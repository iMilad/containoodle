import test from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";

const START = "https://d-0000000000.awsapps.com/start";
const ACCOUNT_ID = "0".repeat(12);
const TEST_HELPER_TOKEN = "A".repeat(43);
const TEST_SSO_IDENTITY = "a".repeat(64);
const TEST_OTHER_SSO_IDENTITY = "b".repeat(64);
const TEST_STALE_REUSE_IDENTITY = "c".repeat(64);
const TEST_SSO_PROFILE = "__containoodle_test_profile__";
const TEST_HELPER_ROLE = "__CONTAINOODLE_TEST_ROLE__";
const TEST_PORTAL_ROLE = "__CONTAINOODLE_TEST_PORTAL_ROLE__";
const TEST_BACKEND_ROLE = "__CONTAINOODLE_TEST_BACKEND_ROLE__";
const TEST_LEGACY_ROLE = "__CONTAINOODLE_TEST_LEGACY_ROLE__";
const TEST_PORTAL_REGION = "xx-test-1";
const TEST_ROLE_DISCOVERY_ORIGIN =
  "https://portal.sso.xx-test-1.amazonaws.com/*";
const TEST_EXTENSION_ORIGIN = "moz-extension://containoodle-test";
const BACKEND_CONSOLE_URL =
  "https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1";
const BACKEND_SIGNIN_URL = (() => {
  const url = new URL("https://signin.aws.amazon.com/federation");
  url.searchParams.set("Action", "login");
  url.searchParams.set("Issuer", "");
  url.searchParams.set(
    "Destination",
    BACKEND_CONSOLE_URL,
  );
  url.searchParams.set("SigninToken", "test-only");
  return url.href;
})();
const SOURCE_TAB = {
  id: 1,
  url: `${START}/#/accounts`,
  cookieStoreId: "firefox-default",
  windowId: 7,
  incognito: false,
};

function matchPatternCovers(ceiling, requested) {
  const parse = (pattern) => {
    const match = /^https:\/\/(\*\.)?([^/]+)\/\*$/.exec(pattern);
    return match && { wildcard: Boolean(match[1]), hostname: match[2] };
  };
  const allowed = parse(ceiling);
  const candidate = parse(requested);
  if (!allowed || !candidate) return ceiling === requested;
  if (!allowed.wildcard) {
    return !candidate.wildcard && candidate.hostname === allowed.hostname;
  }
  return candidate.hostname === allowed.hostname ||
    candidate.hostname.endsWith(`.${allowed.hostname}`);
}

function decodeBase64Url(value) {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hmacHex(token, canonical) {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64Url(token),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(canonical),
  );
  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function authenticatedBackendFetch({
  token = TEST_HELPER_TOKEN,
  authFailure = null,
  identityPayload = { ok: true, identityKey: TEST_SSO_IDENTITY },
  onRequest = () => {},
  responseForRequest = async () => ({ status: 200, payload: {} }),
} = {}) {
  let challengeSequence = 0;
  return async (url, options = {}) => {
    onRequest(String(url), options);
    const requestUrl = new URL(url);
    if (requestUrl.pathname === "/auth/challenge") {
      const challengeBytes = new Uint8Array(32);
      challengeBytes[31] = challengeSequence += 1;
      const challenge = encodeBase64Url(challengeBytes);
      const expiresAt = Date.now() + 30_000;
      const serverProof = authFailure === "server-proof"
        ? "0".repeat(64)
        : await hmacHex(token, [
          "containoodle-server-v1",
          challenge,
          String(expiresAt),
          requestUrl.host,
          TEST_EXTENSION_ORIGIN,
        ].join("\n"));
      return new Response(JSON.stringify({
        version: 1,
        challenge,
        expiresAt,
        serverProof,
      }), { status: 200 });
    }

    const response = requestUrl.pathname === "/sso-identity" && identityPayload
      ? { status: 200, payload: identityPayload }
      : await responseForRequest(
        requestUrl,
        options,
      );
    const {
      status = 200,
      payload = {},
      rawBody,
      responseProofFailure = false,
    } = response;
    const body = rawBody === undefined ? JSON.stringify(payload) : String(rawBody);
    const challenge = new Headers(options.headers).get(
      "X-Containoodle-Challenge",
    );
    const target = `${requestUrl.pathname}${requestUrl.search}`;
    const responseProof = authFailure === "response-proof" || responseProofFailure
      ? "0".repeat(64)
      : await hmacHex(token, [
        "containoodle-response-v1",
        challenge,
        String(status),
        target,
        await sha256Hex(body),
        requestUrl.host,
        TEST_EXTENSION_ORIGIN,
      ].join("\n"));
    return new Response(body, {
      status,
      headers: { "X-Containoodle-Response-Proof": responseProof },
    });
  };
}

function assertNoRawHelperToken(url, options, token = TEST_HELPER_TOKEN) {
  const headers = new Headers(options.headers);
  assert.strictEqual(headers.has("Authorization"), false);
  const rendered = `${url}\n${[...headers].flat().join("\n")}`;
  assert.doesNotMatch(rendered, new RegExp(token));
}

const STORAGE_FIXTURE_NAMES = [
  "portal-v1.0.3.json",
  "backend-v1.0.3.json",
];

function readStorageFixture(name) {
  return JSON.parse(readFileSync(
    new URL(`./fixtures/storage/${name}`, import.meta.url),
    "utf8",
  ));
}

function webExtensionEvent() {
  const listeners = [];
  return {
    listeners,
    addListener(listener) {
      listeners.push(listener);
    },
  };
}

function makeBrowser(initialStorage = null) {
  const storageData = initialStorage === null ? {
    config: {
      mode: "portal",
      portalStartUrl: START,
      backendUrl: "http://127.0.0.1:8421",
      defaultRole: "",
      ssoRegion: TEST_PORTAL_REGION,
    },
    accountsCache: [{ accountId: ACCOUNT_ID, accountName: "backend-prod-data" }],
    accountsCacheSource: "backend",
    backendAuthToken: TEST_HELPER_TOKEN,
    portalPinnedAccounts: [{ accountId: ACCOUNT_ID, accountName: "portal-prod-data" }],
  } : structuredClone(initialStorage);
  const tabs = new Map([[SOURCE_TAB.id, { ...SOURCE_TAB }]]);
  const createdTabs = [];
  const identities = [];
  const identityUpdates = [];
  const tabGroups = new Map();
  const tabGroupUpdates = [];
  const cookieReads = [];
  const cookieWrites = [];
  const cookieRemovals = [];
  const portalCookiesByStore = new Map();
  let cookieReadbackEnabled = true;
  let forceHostOnlyReadback = false;
  let portalCookies = [
    {
      name: "x-amz-sso_authn",
      value: "wrong-first-party-value",
      domain: new URL(START).hostname,
      hostOnly: true,
      path: "/start/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      session: true,
      firstPartyDomain: "example.com",
    },
    {
      name: "x-amz-sso_authn",
      value: "wrong-cross-site-partition",
      domain: ".awsapps.com",
      hostOnly: false,
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      session: true,
      firstPartyDomain: "",
      partitionKey: {
        topLevelSite: new URL(START).origin,
        hasCrossSiteAncestor: true,
      },
    },
    {
      name: "x-amz-sso_authn",
      value: "test-session-value",
      domain: ".awsapps.com",
      hostOnly: false,
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      session: false,
      expirationDate: 2000000000,
      firstPartyDomain: "",
      partitionKey: {
        topLevelSite: new URL(START).origin,
        hasCrossSiteAncestor: false,
      },
    },
  ];
  let nextTabId = 100;
  let nextStoreId = 1;
  let nextGroupId = 1;
  let beforeNextTabCreate = null;
  let registeredScripts = [];
  let portalPermission = true;
  let roleDiscoveryOrigins = ["https://*.amazonaws.com/*"];
  let consoleOrigins = ["https://*.amazon.com/*"];
  const permissionContainsCalls = [];
  let registrationReadGate = null;

  const events = {
    runtimeMessage: webExtensionEvent(),
    runtimeStartup: webExtensionEvent(),
    runtimeInstalled: webExtensionEvent(),
    tabsCreated: webExtensionEvent(),
    tabsUpdated: webExtensionEvent(),
    tabsRemoved: webExtensionEvent(),
    tabGroupsUpdated: webExtensionEvent(),
    storageChanged: webExtensionEvent(),
    permissionsAdded: webExtensionEvent(),
    permissionsRemoved: webExtensionEvent(),
  };

  function storageGet(keys) {
    if (keys === null) return { ...storageData };
    if (typeof keys === "string") {
      return Object.hasOwn(storageData, keys) ? { [keys]: storageData[keys] } : {};
    }
    if (Array.isArray(keys)) {
      return Object.fromEntries(keys.filter((key) => Object.hasOwn(storageData, key)).map(
        (key) => [key, storageData[key]]
      ));
    }
    return Object.fromEntries(Object.entries(keys).map(
      ([key, fallback]) => [key, Object.hasOwn(storageData, key) ? storageData[key] : fallback]
    ));
  }

  function normalizedDomain(domain) {
    return String(domain || "").toLowerCase().replace(/^\./, "");
  }

  function pathMatches(cookiePath, requestPath) {
    if (cookiePath === requestPath) return true;
    if (!requestPath.startsWith(cookiePath)) return false;
    return cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/";
  }

  function partitionMatches(cookie, requestedPartition) {
    const actual = cookie.partitionKey && cookie.partitionKey.topLevelSite;
    if (requestedPartition === undefined) return actual === undefined;
    if (!requestedPartition.topLevelSite) return true;
    if (actual !== requestedPartition.topLevelSite) return false;
    return (
      requestedPartition.hasCrossSiteAncestor === undefined ||
      requestedPartition.hasCrossSiteAncestor ===
        cookie.partitionKey.hasCrossSiteAncestor
    );
  }

  function cookieMatches(cookie, details) {
    if (details.name && cookie.name !== details.name) return false;
    if (
      details.firstPartyDomain !== undefined &&
      details.firstPartyDomain !== null &&
      cookie.firstPartyDomain !== details.firstPartyDomain
    ) return false;
    if (!partitionMatches(cookie, details.partitionKey)) return false;
    if (!details.url) return true;
    const url = new URL(details.url);
    const domain = normalizedDomain(cookie.domain);
    if (
      cookie.hostOnly
        ? url.hostname !== domain
        : url.hostname !== domain && !url.hostname.endsWith(`.${domain}`)
    ) return false;
    if (cookie.secure && url.protocol !== "https:") return false;
    return pathMatches(cookie.path, url.pathname);
  }

  function cookiesForStore(storeId) {
    return storeId === "firefox-default"
      ? portalCookies
      : (portalCookiesByStore.get(storeId) || []);
  }

  function matchingCookies(details) {
    const storeId = details.storeId || "firefox-default";
    if (storeId !== "firefox-default" && !cookieReadbackEnabled) return [];
    return cookiesForStore(storeId).filter(
      (cookie) => cookieMatches(cookie, details)
    ).sort((left, right) => right.path.length - left.path.length);
  }

  function sameCookieIdentity(left, right) {
    return (
      left.name === right.name &&
      normalizedDomain(left.domain) === normalizedDomain(right.domain) &&
      left.hostOnly === right.hostOnly &&
      left.path === right.path &&
      (left.firstPartyDomain || "") === (right.firstPartyDomain || "") &&
      (left.partitionKey && left.partitionKey.topLevelSite) ===
        (right.partitionKey && right.partitionKey.topLevelSite) &&
      (left.partitionKey && left.partitionKey.hasCrossSiteAncestor) ===
        (right.partitionKey && right.partitionKey.hasCrossSiteAncestor)
    );
  }

  const browser = {
    storage: {
      local: {
        async get(keys) {
          return storageGet(keys);
        },
        async set(values) {
          Object.assign(storageData, values);
        },
        async remove(keys) {
          for (const key of Array.isArray(keys) ? keys : [keys]) delete storageData[key];
        },
      },
      onChanged: events.storageChanged,
    },
    contextualIdentities: {
      async query(query) {
        return query && query.name
          ? identities.filter((identity) => identity.name === query.name)
          : [...identities];
      },
      async create(properties) {
        const identity = {
          ...properties,
          cookieStoreId: `firefox-container-${nextStoreId++}`,
        };
        identities.push(identity);
        return identity;
      },
      async get(storeId) {
        const identity = identities.find((item) => item.cookieStoreId === storeId);
        if (!identity) throw new Error("missing identity");
        return identity;
      },
      async update(storeId, properties) {
        const identity = identities.find((item) => item.cookieStoreId === storeId);
        if (!identity) throw new Error("missing identity");
        Object.assign(identity, properties);
        identityUpdates.push({ storeId, ...properties });
        return identity;
      },
    },
    permissions: {
      async contains({ origins = [] }) {
        permissionContainsCalls.push([...origins]);
        return origins.length > 0 && origins.every((origin) => {
          if (origin.includes("awsapps.com")) return portalPermission;
          if (origin.includes("amazonaws.com")) {
            return roleDiscoveryOrigins.some((granted) =>
              matchPatternCovers(granted, origin)
            );
          }
          if (origin.includes("amazon.com")) {
            return consoleOrigins.some((granted) =>
              matchPatternCovers(granted, origin)
            );
          }
          return false;
        });
      },
      onAdded: events.permissionsAdded,
      onRemoved: events.permissionsRemoved,
    },
    cookies: {
      async get(details) {
        cookieReads.push({ method: "get", ...details });
        return matchingCookies(details)[0] || null;
      },
      async getAll(details) {
        cookieReads.push({ method: "getAll", ...details });
        return matchingCookies(details);
      },
      async set(details) {
        cookieWrites.push(details);
        if (details.name !== "x-amz-sso_authn") return details;
        const parsedUrl = new URL(details.url);
        const storedCookie = {
          name: details.name,
          value: details.value,
          domain: forceHostOnlyReadback
            ? normalizedDomain(details.domain || parsedUrl.hostname)
            : (details.domain || parsedUrl.hostname),
          hostOnly: forceHostOnlyReadback || !details.domain,
          path: details.path || parsedUrl.pathname,
          secure: Boolean(details.secure),
          httpOnly: Boolean(details.httpOnly),
          sameSite: details.sameSite,
          session: typeof details.expirationDate !== "number",
          ...(typeof details.expirationDate === "number"
            ? { expirationDate: details.expirationDate }
            : {}),
          ...(typeof details.firstPartyDomain === "string"
            ? { firstPartyDomain: details.firstPartyDomain }
            : { firstPartyDomain: "" }),
          ...(details.partitionKey ? { partitionKey: { ...details.partitionKey } } : {}),
        };
        const existing = portalCookiesByStore.get(details.storeId) || [];
        portalCookiesByStore.set(details.storeId, [
          ...existing.filter((cookie) => !sameCookieIdentity(cookie, storedCookie)),
          storedCookie,
        ]);
        return storedCookie;
      },
      async remove(details) {
        cookieRemovals.push(details);
        const existing = portalCookiesByStore.get(details.storeId) || [];
        const match = existing.filter((cookie) => cookieMatches(cookie, details))
          .sort((left, right) => right.path.length - left.path.length)[0];
        if (!match) return null;
        portalCookiesByStore.set(
          details.storeId,
          existing.filter((cookie) => cookie !== match)
        );
        return details;
      },
    },
    tabs: {
      async query(query = {}) {
        return [...tabs.values()].filter(
          (tab) => query.groupId === undefined || tab.groupId === query.groupId
        );
      },
      async get(tabId) {
        const tab = tabs.get(tabId);
        if (!tab) throw new Error("missing tab");
        return { ...tab };
      },
      async create(properties) {
        if (beforeNextTabCreate) {
          const callback = beforeNextTabCreate;
          beforeNextTabCreate = null;
          await callback(properties);
        }
        const tab = {
          id: nextTabId++,
          windowId: properties.windowId ?? 1,
          ...properties,
        };
        tabs.set(tab.id, tab);
        createdTabs.push(tab);
        return { ...tab };
      },
      async update(tabId, properties) {
        const tab = tabs.get(tabId);
        if (!tab) throw new Error("missing tab");
        Object.assign(tab, properties);
        return { ...tab };
      },
      async remove(tabId) {
        tabs.delete(tabId);
      },
      async group({ groupId, tabIds }) {
        const ids = Array.isArray(tabIds) ? tabIds : [tabIds];
        if (groupId === undefined) {
          const firstTab = tabs.get(ids[0]);
          if (!firstTab) throw new Error("missing tab");
          groupId = nextGroupId++;
          tabGroups.set(groupId, {
            id: groupId,
            windowId: firstTab.windowId,
            title: "",
            color: "grey",
          });
        } else if (!tabGroups.has(groupId)) {
          throw new Error("missing tab group");
        }
        for (const tabId of ids) {
          const tab = tabs.get(tabId);
          if (!tab) throw new Error("missing tab");
          tab.groupId = groupId;
        }
        return groupId;
      },
      async sendMessage() {},
      onCreated: events.tabsCreated,
      onUpdated: events.tabsUpdated,
      onRemoved: events.tabsRemoved,
    },
    tabGroups: {
      onUpdated: events.tabGroupsUpdated,
      async query() {
        return [...tabGroups.values()].map((group) => ({ ...group }));
      },
      async update(groupId, properties) {
        const group = tabGroups.get(groupId);
        if (!group) throw new Error("missing tab group");
        Object.assign(group, properties);
        tabGroupUpdates.push({ groupId, ...properties });
        for (const listener of events.tabGroupsUpdated.listeners) {
          await listener({ ...group });
        }
        return { ...group };
      },
    },
    windows: {
      async update() {},
    },
    scripting: {
      async getRegisteredContentScripts({ ids } = {}) {
        if (registrationReadGate) {
          const gate = registrationReadGate;
          registrationReadGate = null;
          await gate.promise;
        }
        return ids
          ? registeredScripts.filter((script) => ids.includes(script.id))
          : registeredScripts;
      },
      async unregisterContentScripts({ ids } = {}) {
        registeredScripts = ids
          ? registeredScripts.filter((script) => !ids.includes(script.id))
          : [];
      },
      async registerContentScripts(scripts) {
        registeredScripts = scripts;
      },
      async executeScript() {},
    },
    runtime: {
      onMessage: events.runtimeMessage,
      onStartup: events.runtimeStartup,
      onInstalled: events.runtimeInstalled,
    },
  };

  return {
    browser,
    events,
    storageData,
    tabs,
    createdTabs,
    identities,
    identityUpdates,
    tabGroups,
    tabGroupUpdates,
    cookieReads,
    cookieWrites,
    cookieRemovals,
    permissionContainsCalls,
    setPortalCookie(value) {
      portalCookies = value === null
        ? []
        : Array.isArray(value) ? value : [value];
    },
    setCookieReadbackEnabled(value) {
      cookieReadbackEnabled = value;
    },
    setForceHostOnlyReadback(value) {
      forceHostOnlyReadback = value;
    },
    addTargetPortalCookie(storeId, cookie) {
      portalCookiesByStore.set(storeId, [
        ...(portalCookiesByStore.get(storeId) || []),
        cookie,
      ]);
    },
    setPortalPermission(value) {
      portalPermission = value;
    },
    setRoleDiscoveryPermission(value) {
      roleDiscoveryOrigins = value ? ["https://*.amazonaws.com/*"] : [];
    },
    setRoleDiscoveryOrigins(origins) {
      roleDiscoveryOrigins = [...origins];
    },
    setConsolePermission(value) {
      consoleOrigins = value ? ["https://*.amazon.com/*"] : [];
    },
    setConsoleOrigins(origins) {
      consoleOrigins = [...origins];
    },
    getRegisteredScripts() {
      return registeredScripts;
    },
    setRegisteredScripts(scripts) {
      registeredScripts = scripts;
    },
    pauseNextRegistrationRead() {
      let release;
      const promise = new Promise((resolve) => {
        release = resolve;
      });
      registrationReadGate = { promise };
      return release;
    },
    beforeNextTabCreate(callback) {
      beforeNextTabCreate = callback;
    },
  };
}

let backgroundImportNonce = 0;

async function loadBackground(fixture) {
  globalThis.browser = fixture.browser;
  globalThis.location = { origin: TEST_EXTENSION_ORIGIN };
  globalThis.fetch = async () => {
    throw new Error("unexpected fetch");
  };
  await import(
    `../firefox-extension/background.js?group-naming=${++backgroundImportNonce}`
  );
  await new Promise((resolve) => setTimeout(resolve, 0));
  return fixture.events.runtimeMessage.listeners[0];
}

function portalShortcut(accountId = ACCOUNT_ID) {
  return (
    `${START}/#/console?account_id=${accountId}` +
    "&role_name=ReadOnlyAccess"
  );
}

async function handoffPortalAccount(onMessage, accountName, accountId = ACCOUNT_ID) {
  return onMessage(
    {
      type: "portal-shortcut-click",
      url: portalShortcut(accountId),
      disposition: "new-tab",
      accountName,
    },
    { tab: SOURCE_TAB }
  );
}

function groupForAccount(
  fixture,
  accountId = ACCOUNT_ID,
  windowId = SOURCE_TAB.windowId
) {
  const groupId = fixture.storageData[
    `tabGroups/${accountId}/${windowId}`
  ];
  assert.ok(Number.isInteger(groupId), `missing group for ${accountId}`);
  return fixture.tabGroups.get(groupId);
}

async function waitFor(check) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.ok(check(), "timed out waiting for background work");
}

async function completeTabNavigation(
  fixture,
  tabId,
  url,
  overrides = {},
) {
  const tab = fixture.tabs.get(tabId);
  assert.ok(tab, `missing test tab ${tabId}`);
  Object.assign(tab, overrides, { url, status: "complete" });
  for (const listener of fixture.events.tabsUpdated.listeners) {
    listener(
      tabId,
      { url, status: "complete" },
      { ...tab },
    );
  }
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

async function removeTabWithEvent(fixture, tabId) {
  fixture.tabs.delete(tabId);
  for (const listener of fixture.events.tabsRemoved.listeners) {
    listener(tabId, { isWindowClosing: false });
  }
  await new Promise((resolve) => setImmediate(resolve));
}

async function launchFreshBackendForBinding({
  existingBinding = TEST_OTHER_SSO_IDENTITY,
} = {}) {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendSsoProfile = TEST_SSO_PROFILE;
  fixture.storageData.backendSsoIdentityKey = TEST_SSO_IDENTITY;
  fixture.storageData.accountsCache[0].role = TEST_HELPER_ROLE;
  if (existingBinding !== undefined) {
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] =
      existingBinding;
  }
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest() {
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${
            encodeURIComponent(BACKEND_SIGNIN_URL)
          }`,
        },
      };
    },
  });
  const result = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    mode: "backend",
  }, {});
  assert.strictEqual(result.ok, true);
  return { fixture, onMessage, requests, result };
}

async function fireBackgroundLifecycle(event, details) {
  const results = event.listeners.map((listener) => {
    try {
      return Promise.resolve(listener(details));
    } catch (error) {
      return Promise.reject(error);
    }
  });
  const settlements = await Promise.allSettled(results);
  // Detached listeners use only immediately resolving mocks in this harness.
  // Cross both timer/check phases so their promise chains settle before the
  // shared global browser is replaced by the next sequential fixture case.
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setImmediate(resolve));
  const rejection = settlements.find((result) => result.status === "rejected");
  if (rejection) throw rejection.reason;
}

test("open portal focuses an exact default-store portal tab", async () => {
  const fixture = makeBrowser();
  const windowUpdates = [];
  fixture.tabs.get(SOURCE_TAB.id).active = false;
  fixture.browser.windows.update = async (windowId, properties) => {
    windowUpdates.push({ windowId, ...properties });
  };
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await onMessage({ type: "open-portal", mode: "portal" }, {}),
    { ok: true }
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).active, true);
  assert.deepStrictEqual(windowUpdates, [{
    windowId: SOURCE_TAB.windowId,
    focused: true,
  }]);
});

test("open portal ignores account-container copies and creates an active default-store tab", async () => {
  const fixture = makeBrowser();
  fixture.tabs.get(SOURCE_TAB.id).url = "about:blank";
  fixture.tabs.set(2, {
    id: 2,
    url: `${START}/#/accounts`,
    cookieStoreId: "firefox-container-portal-copy",
    windowId: SOURCE_TAB.windowId,
    incognito: false,
    active: false,
  });
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await onMessage({ type: "open-portal", mode: "portal" }, {}),
    { ok: true }
  );
  assert.strictEqual(fixture.createdTabs.length, 1);
  assert.deepStrictEqual(
    {
      url: fixture.createdTabs[0].url,
      active: fixture.createdTabs[0].active,
      cookieStoreId: fixture.createdTabs[0].cookieStoreId,
    },
    {
      url: START,
      active: true,
      cookieStoreId: "firefox-default",
    }
  );
  assert.strictEqual(fixture.tabs.get(2).active, false);
});

test("open portal cancels if the mode changes while tabs are being inspected", async () => {
  const fixture = makeBrowser();
  fixture.tabs.get(SOURCE_TAB.id).active = false;
  const windowUpdates = [];
  fixture.browser.windows.update = async (windowId, properties) => {
    windowUpdates.push({ windowId, ...properties });
  };
  const onMessage = await loadBackground(fixture);

  const originalQuery = fixture.browser.tabs.query;
  let releaseQuery;
  let markQueryStarted;
  const queryGate = new Promise((resolve) => { releaseQuery = resolve; });
  const queryStarted = new Promise((resolve) => { markQueryStarted = resolve; });
  fixture.browser.tabs.query = async (...args) => {
    markQueryStarted();
    await queryGate;
    return originalQuery(...args);
  };

  const opening = onMessage({ type: "open-portal", mode: "portal" }, {});
  await queryStarted;
  const oldConfig = fixture.storageData.config;
  const newConfig = { ...oldConfig, mode: "backend" };
  fixture.storageData.config = newConfig;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
  }
  releaseQuery();

  assert.deepStrictEqual(await opening, {
    ok: false,
    cancelled: true,
    error: "Connection mode changed — try again",
  });
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).active, false);
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.deepStrictEqual(windowUpdates, []);
});

test("open portal cancels if the configured portal changes while tabs are being inspected", async () => {
  const fixture = makeBrowser();
  fixture.tabs.get(SOURCE_TAB.id).active = false;
  const onMessage = await loadBackground(fixture);

  const originalQuery = fixture.browser.tabs.query;
  let releaseQuery;
  let markQueryStarted;
  const queryGate = new Promise((resolve) => { releaseQuery = resolve; });
  const queryStarted = new Promise((resolve) => { markQueryStarted = resolve; });
  fixture.browser.tabs.query = async (...args) => {
    markQueryStarted();
    await queryGate;
    return originalQuery(...args);
  };

  const opening = onMessage({ type: "open-portal", mode: "portal" }, {});
  await queryStarted;
  fixture.storageData.config = {
    ...fixture.storageData.config,
    portalStartUrl: "https://d-1111111111.awsapps.com/start",
  };
  releaseQuery();

  assert.deepStrictEqual(await opening, {
    ok: false,
    cancelled: true,
    error: "Connection mode changed — try again",
  });
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).active, false);
  assert.strictEqual(fixture.createdTabs.length, 0);
});

test("backend pins are normalized, serialized, and isolated from account data", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendPinnedAccountIds = [
    "invalid",
    ACCOUNT_ID,
    ACCOUNT_ID,
  ];
  fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`] = "BackendRole";
  const onMessage = await loadBackground(fixture);
  const accountsBefore = structuredClone(fixture.storageData.accountsCache);
  const portalPinsBefore = structuredClone(fixture.storageData.portalPinnedAccounts);
  const roleBefore = fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`];
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };

  const thirdAccountId = "345678901234";
  const fourthAccountId = "456789012345";
  assert.deepStrictEqual(
    await Promise.all([
      onMessage({
        type: "set-backend-pin",
        mode: "backend",
        accountId: thirdAccountId,
        pinned: true,
      }, {}),
      onMessage({
        type: "set-backend-pin",
        mode: "backend",
        accountId: fourthAccountId,
        pinned: true,
      }, {}),
    ]),
    [
      { ok: true, pinned: true },
      { ok: true, pinned: true },
    ]
  );
  assert.deepStrictEqual(fixture.storageData.backendPinnedAccountIds, [
    ACCOUNT_ID,
    thirdAccountId,
    fourthAccountId,
  ]);

  assert.deepStrictEqual(
    await onMessage({
      type: "set-backend-pin",
      mode: "backend",
      accountId: ACCOUNT_ID,
      pinned: false,
    }, {}),
    { ok: true, pinned: false }
  );
  assert.deepStrictEqual(fixture.storageData.backendPinnedAccountIds, [
    thirdAccountId,
    fourthAccountId,
  ]);
  assert.deepStrictEqual(
    await onMessage({
      type: "set-backend-pin",
      mode: "backend",
      accountId: "not-an-account",
      pinned: true,
    }, {}),
    { ok: false, error: "Invalid backend account" }
  );

  assert.deepStrictEqual(fixture.storageData.accountsCache, accountsBefore);
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, portalPinsBefore);
  assert.strictEqual(
    fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`],
    roleBefore
  );
  assert.strictEqual(fetchCalls, 0);
});

test("backend pin updates cancel before writing after a mode switch", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendPinnedAccountIds = [ACCOUNT_ID];
  const onMessage = await loadBackground(fixture);
  let switched = false;
  const originalGet = fixture.browser.storage.local.get;
  fixture.browser.storage.local.get = async (keys) => {
    const stored = await originalGet(keys);
    if (keys === "backendPinnedAccountIds" && !switched) {
      switched = true;
      const oldConfig = fixture.storageData.config;
      const newConfig = { ...oldConfig, mode: "portal" };
      fixture.storageData.config = newConfig;
      for (const listener of fixture.events.storageChanged.listeners) {
        listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
      }
    }
    return stored;
  };
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };

  assert.deepStrictEqual(
    await onMessage({
      type: "set-backend-pin",
      mode: "backend",
      accountId: ACCOUNT_ID,
      pinned: false,
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    }
  );
  assert.deepStrictEqual(fixture.storageData.backendPinnedAccountIds, [ACCOUNT_ID]);
  assert.strictEqual(fetchCalls, 0);
});

test("backend pin actions are inert in portal mode", async () => {
  const fixture = makeBrowser();
  fixture.storageData.backendPinnedAccountIds = [ACCOUNT_ID];
  const onMessage = await loadBackground(fixture);
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };

  assert.deepStrictEqual(
    await onMessage({
      type: "set-backend-pin",
      mode: "backend",
      accountId: ACCOUNT_ID,
      pinned: true,
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    }
  );
  assert.deepStrictEqual(fixture.storageData.backendPinnedAccountIds, [ACCOUNT_ID]);
  assert.strictEqual(fetchCalls, 0);
});

test("portal account-name replacement changes only the automatic group title", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-dev-(.+)$",
    groupNameReplacement: "$1",
  });
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-dev-data"),
    { ok: true }
  );

  assert.strictEqual(groupForAccount(fixture).title, "data");
  assert.strictEqual(fixture.identities[0].name, "corp-dev-data");
  assert.strictEqual(fixture.identities[0].color, "green");
  assert.strictEqual(groupForAccount(fixture).color, "green");
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    undefined,
    "an automatic update must not be persisted as a manual title"
  );

  const group = groupForAccount(fixture);
  group.collapsed = true;
  for (const listener of fixture.events.tabGroupsUpdated.listeners) {
    await listener({ ...group });
  }
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    undefined,
    "collapse/color events with an unchanged title are not manual renames"
  );

  group.title = "Pinned by user";
  for (const listener of fixture.events.tabGroupsUpdated.listeners) {
    await listener({ ...group });
  }
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    "Pinned by user"
  );

  const oldConfig = fixture.storageData.config;
  const newConfig = { ...oldConfig, groupNameReplacement: "AWS-$1" };
  fixture.storageData.config = newConfig;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
  }
  await waitFor(() => groupForAccount(fixture).title === "Pinned by user");
  assert.strictEqual(groupForAccount(fixture).title, "Pinned by user");
});

test("automatic group naming keeps the original portal name on fallback cases", async (t) => {
  const cases = [
    {
      name: "no pattern configured",
      pattern: "",
      replacement: "ignored",
    },
    {
      name: "pattern does not match",
      pattern: "^other-",
      replacement: "renamed-",
    },
    {
      name: "replacement produces an empty title",
      pattern: "^.*$",
      replacement: "",
    },
  ];

  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const fixture = makeBrowser();
      fixture.storageData.portalPinnedAccounts = [];
      Object.assign(fixture.storageData.config, {
        groupNamePattern: entry.pattern,
        groupNameReplacement: entry.replacement,
      });
      const onMessage = await loadBackground(fixture);

      assert.deepStrictEqual(
        await handoffPortalAccount(onMessage, "corp-qa-payments"),
        { ok: true }
      );
      assert.strictEqual(groupForAccount(fixture).title, "corp-qa-payments");
      assert.strictEqual(fixture.identities[0].name, "corp-qa-payments");
    });
  }
});

test("persisted manual group title overrides automatic account-name replacement", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] = "My pinned AWS title";
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-prod-(.+)$",
    groupNameReplacement: "$1",
  });
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-prod-billing"),
    { ok: true }
  );

  assert.strictEqual(groupForAccount(fixture).title, "My pinned AWS title");
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    "My pinned AWS title"
  );
  assert.strictEqual(fixture.identities[0].name, "corp-prod-billing");
});

test("naming config changes retitle known automatic groups from portal pin fallback", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-(?:dev|qa)-(.+)$",
    groupNameReplacement: "$1",
  });
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-dev-payments"),
    { ok: true }
  );
  assert.strictEqual(groupForAccount(fixture).title, "payments");
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "corp-dev-payments"
  );

  // Simulate a portal group created before v1.0.5 remembered original names.
  // Portal pins remain the mode-owned source for automatic retitling.
  delete fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`];
  fixture.storageData.portalPinnedAccounts = [
    { accountId: ACCOUNT_ID, accountName: "corp-dev-payments" },
  ];

  const oldConfig = fixture.storageData.config;
  const newConfig = {
    ...oldConfig,
    groupNameReplacement: "AWS-$1",
  };
  fixture.storageData.config = newConfig;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
  }

  await waitFor(() => groupForAccount(fixture).title === "AWS-payments");
  assert.strictEqual(groupForAccount(fixture).title, "AWS-payments");
});

test("naming config changes preserve persisted manual group titles", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] = "Pinned QA title";
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-(?:dev|qa)-(.+)$",
    groupNameReplacement: "$1",
  });
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-qa-audit"),
    { ok: true }
  );
  assert.strictEqual(groupForAccount(fixture).title, "Pinned QA title");
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "corp-qa-audit"
  );

  let manualTitleChecks = 0;
  const originalGet = fixture.browser.storage.local.get;
  fixture.browser.storage.local.get = async (keys) => {
    const stored = await originalGet(keys);
    if (keys === `tabGroupTitle/${ACCOUNT_ID}`) manualTitleChecks += 1;
    return stored;
  };
  const oldConfig = fixture.storageData.config;
  const newConfig = {
    ...oldConfig,
    groupNameReplacement: "AWS-$1",
  };
  fixture.storageData.config = newConfig;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
  }

  await waitFor(() => manualTitleChecks > 0);
  assert.strictEqual(groupForAccount(fixture).title, "Pinned QA title");
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    "Pinned QA title"
  );
});

test("a naming change during portal launch wins over the launch config snapshot", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-dev-(.+)$",
    groupNameReplacement: "old-$1",
  });
  const onMessage = await loadBackground(fixture);

  fixture.beforeNextTabCreate(async () => {
    const oldConfig = fixture.storageData.config;
    const newConfig = { ...oldConfig, groupNameReplacement: "new-$1" };
    fixture.storageData.config = newConfig;
    for (const listener of fixture.events.storageChanged.listeners) {
      listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
    }
    await Promise.resolve();
  });

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-dev-payments"),
    { ok: true }
  );
  assert.strictEqual(groupForAccount(fixture).title, "new-payments");
});

test("portal mode never resolves a backend-cached account", async () => {
  const fixture = makeBrowser();
  fixture.storageData.accountsCache = [
    { accountId: ACCOUNT_ID, accountName: "backend-prod-only" },
  ];
  fixture.storageData.accountsCacheSource = "backend";
  fixture.storageData.portalPinnedAccounts = [];
  const onMessage = await loadBackground(fixture);
  assert.deepStrictEqual(fixture.storageData.accountsCache, [
    { accountId: ACCOUNT_ID, accountName: "backend-prod-only" },
  ]);
  assert.strictEqual(fixture.storageData.accountsCacheSource, "backend");

  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("unreachable");
  };

  assert.deepStrictEqual(
    await onMessage({ type: "launch", accountId: ACCOUNT_ID }, {}),
    { ok: false, error: "Account not found — pin it from the sidebar first" },
    "portal mode must not resolve a backend-cached account"
  );
  assert.strictEqual(fetchCalls, 0, "portal mode must not probe the backend");
  assert.strictEqual(fixture.storageData.backendAuthToken, TEST_HELPER_TOKEN);
});

test("backend mode ignores portal sources and stale portal actions", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.accountsCache = [];
  fixture.storageData.accountsCacheSource = "backend";
  fixture.storageData.portalPinnedAccounts = [
    {
      accountId: ACCOUNT_ID,
      accountName: "portal-dev-only",
      role: TEST_PORTAL_ROLE,
    },
  ];
  fixture.storageData[`roleChoice/${ACCOUNT_ID}`] = TEST_LEGACY_ROLE;
  fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`] = TEST_BACKEND_ROLE;
  const onMessage = await loadBackground(fixture);

  let fetchCalls = 0;
  let backendRequestOptions = null;
  globalThis.fetch = async (_url, options) => {
    fetchCalls += 1;
    backendRequestOptions = options;
    throw new Error("unreachable");
  };

  assert.deepStrictEqual(
    await onMessage({ type: "launch", accountId: ACCOUNT_ID }, {}),
    { ok: false, error: "Account not found — check the backend account list" },
    "backend mode must not resolve a portal pin"
  );
  assert.strictEqual(fetchCalls, 1);
  assertNoRawHelperToken(
    "http://127.0.0.1:8421/auth/challenge",
    backendRequestOptions,
  );
  assert.deepStrictEqual(
    await onMessage({ type: "open-portal" }, {}),
    { ok: false, error: "Portal mode is not active" },
    "a stale portal action must be inert in backend mode"
  );
  assert.deepStrictEqual(
    await onMessage({
      type: "set-portal-pin",
      mode: "portal",
      pinned: true,
      account: {
        accountId: ACCOUNT_ID,
        accountName: "must-not-be-pinned",
      },
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    }
  );
  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_PORTAL_ROLE,
      mode: "portal",
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    }
  );
  assert.deepStrictEqual(
    await onMessage({
      type: "discover-roles",
      accountId: ACCOUNT_ID,
      mode: "portal",
    }, {}),
    { ok: false, error: "Connection mode changed — try again" }
  );
  assert.strictEqual(fixture.createdTabs.length, 0);

  fixture.storageData.config = { ...fixture.storageData.config, mode: "portal" };
  fixture.storageData.portalPinnedAccounts = [
    { accountId: ACCOUNT_ID, accountName: "portal-dev-owned" },
  ];
  fixture.storageData[`portalRoleChoice/${ACCOUNT_ID}`] = TEST_PORTAL_ROLE;
  assert.deepStrictEqual(
    await onMessage({ type: "launch", accountId: ACCOUNT_ID }, {}),
    {
      ok: true,
      account: "portal-dev-owned",
      tabId: fixture.createdTabs[0].id,
    }
  );
  assert.ok(fixture.createdTabs[0].url.includes(`role_name=${TEST_PORTAL_ROLE}`));
  assert.strictEqual(
    fixture.createdTabs[0].url.includes(TEST_LEGACY_ROLE),
    false,
    "legacy shared roleChoice must not participate at runtime"
  );
  assert.strictEqual(
    fixture.createdTabs[0].url.includes(TEST_BACKEND_ROLE),
    false,
    "backend remembered roles must not participate in portal mode"
  );
  assert.strictEqual(fetchCalls, 1);
});

test("backend launches fail closed before helper or container work without a token", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  delete fixture.storageData.backendAuthToken;
  const onMessage = await loadBackground(fixture);
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_HELPER_ROLE,
      mode: "backend",
    }, {}),
    {
      ok: false,
      needsOptions: true,
      error: "Local helper access token is missing or invalid",
    }
  );
  assert.strictEqual(fetchCalls, 0);
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.identities.length, 0);
});

test("backend role discovery authenticates the helper request", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest() {
      return { payload: { ok: true, roles: [TEST_HELPER_ROLE] } };
    },
  });

  assert.deepStrictEqual(
    await onMessage({
      type: "discover-roles",
      accountId: ACCOUNT_ID,
      mode: "backend",
    }, {}),
    { ok: true, roles: [TEST_HELPER_ROLE] }
  );
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    ["/auth/challenge", "/sso-identity", "/auth/challenge", "/roles"],
  );
  const identityRequest = new URL(requests[1].url);
  const rolesRequest = new URL(requests[3].url);
  assert.strictEqual(identityRequest.searchParams.has("profile"), false);
  assert.strictEqual(rolesRequest.searchParams.get("identity"), TEST_SSO_IDENTITY);
  assert.strictEqual(fixture.storageData.backendSsoIdentityKey, TEST_SSO_IDENTITY);
  for (const request of requests) {
    assertNoRawHelperToken(request.url, request.options);
  }
});

test("backend profile launches scope helper requests, roles, and reuse metadata to one identity", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendSsoProfile = TEST_SSO_PROFILE;
  fixture.storageData.backendSsoIdentityKey = TEST_OTHER_SSO_IDENTITY;
  fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`] = TEST_LEGACY_ROLE;
  fixture.storageData[
    `backendRoleChoice/${TEST_OTHER_SSO_IDENTITY}/${ACCOUNT_ID}`
  ] = "__CONTAINOODLE_TEST_OTHER_IDENTITY_ROLE__";
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest(url) {
      if (url.pathname === "/roles") {
        return { payload: { ok: true, roles: [TEST_HELPER_ROLE] } };
      }
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${
            encodeURIComponent(BACKEND_SIGNIN_URL)
          }`,
        },
      };
    },
  });

  const result = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    mode: "backend",
  }, {});

  assert.strictEqual(result.ok, true);
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/roles",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  for (const request of requests) assertNoRawHelperToken(request.url, request.options);
  for (const index of [1, 3, 5]) {
    assert.strictEqual(
      new URL(requests[index].url).searchParams.get("profile"),
      TEST_SSO_PROFILE,
    );
  }
  for (const index of [3, 5]) {
    assert.strictEqual(
      new URL(requests[index].url).searchParams.get("identity"),
      TEST_SSO_IDENTITY,
    );
  }
  assert.strictEqual(
    new URL(requests[5].url).searchParams.get("role"),
    TEST_HELPER_ROLE,
  );
  assert.strictEqual(
    fixture.storageData[
      `backendRoleChoice/${TEST_SSO_IDENTITY}/${ACCOUNT_ID}`
    ],
    TEST_HELPER_ROLE,
  );
  assert.strictEqual(
    fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`],
    TEST_LEGACY_ROLE,
  );
  assert.strictEqual(
    fixture.storageData[
      `backendRoleChoice/${TEST_OTHER_SSO_IDENTITY}/${ACCOUNT_ID}`
    ],
    "__CONTAINOODLE_TEST_OTHER_IDENTITY_ROLE__",
  );
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    undefined,
  );
  await completeTabNavigation(
    fixture,
    result.tabId,
    BACKEND_CONSOLE_URL,
  );
  await waitFor(
    () => fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] ===
      TEST_SSO_IDENTITY,
  );
});

test("an unexpected SSO identity response fails before roles, containers, or tabs", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendSsoIdentityKey = TEST_OTHER_SSO_IDENTITY;
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    identityPayload: {
      ok: true,
      identityKey: TEST_SSO_IDENTITY,
      __containoodleTestUnexpectedField: true,
    },
    onRequest(url, options) {
      requests.push({ url, options });
    },
  });

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_HELPER_ROLE,
      mode: "backend",
    }, {}),
    { ok: false, error: "Local helper returned an invalid SSO identity" },
  );
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    ["/auth/challenge", "/sso-identity"],
  );
  assert.strictEqual(
    fixture.storageData.backendSsoIdentityKey,
    TEST_OTHER_SSO_IDENTITY,
  );
  assert.strictEqual(fixture.identities.length, 0);
  assert.strictEqual(fixture.createdTabs.length, 0);
});

test("a live backend session bound to another identity is bypassed and rebound after sign-in", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.accountsCache[0].role = TEST_HELPER_ROLE;
  const storeId = "firefox-container-backend-identity-mismatch";
  fixture.identities.push({
    name: "backend-prod-data",
    cookieStoreId: storeId,
    color: "red",
    icon: "briefcase",
  });
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
  fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
  fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] =
    TEST_OTHER_SSO_IDENTITY;
  fixture.addTargetPortalCookie(storeId, {
    name: "noflush_Region",
    value: "eu-west-1",
    domain: ".console.aws.amazon.com",
    hostOnly: false,
    path: "/",
    secure: true,
  });
  fixture.addTargetPortalCookie(storeId, {
    name: "aws-signer-token_eu-west-1",
    value: "__CONTAINOODLE_TEST_LIVE_SESSION__",
    domain: ".console.aws.amazon.com",
    hostOnly: false,
    path: "/",
    secure: true,
    expirationDate: Math.ceil(Date.now() / 1000) + 3600,
  });
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest() {
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${
            encodeURIComponent(BACKEND_SIGNIN_URL)
          }`,
        },
      };
    },
  });

  const result = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    mode: "backend",
  }, {});

  assert.strictEqual(result.ok, true);
  assert.strictEqual(fixture.cookieReads.length, 0);
  assert.strictEqual(fixture.createdTabs[0].url, BACKEND_SIGNIN_URL);
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_OTHER_SSO_IDENTITY,
  );
  await completeTabNavigation(
    fixture,
    result.tabId,
    BACKEND_CONSOLE_URL,
  );
  await waitFor(
    () => fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] ===
      TEST_SSO_IDENTITY,
  );
});

test("a completed federation error page preserves the old reuse marker", async () => {
  const { fixture, onMessage, requests, result } =
    await launchFreshBackendForBinding();

  await completeTabNavigation(
    fixture,
    result.tabId,
    "https://signin.aws.amazon.com/federation?__containoodle_test_error__=1",
  );
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_OTHER_SSO_IDENTITY,
  );

  const second = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    mode: "backend",
  }, {});
  assert.strictEqual(second.ok, true);
  assert.strictEqual(
    requests.filter((request) =>
      new URL(request.url).pathname === "/generate-url"
    ).length,
    2,
    "an unverified launch must generate a new federation URL next time",
  );
});

test("removing a fresh sign-in tab preserves the old reuse marker", async () => {
  const { fixture, onMessage, requests, result } =
    await launchFreshBackendForBinding();

  await removeTabWithEvent(fixture, result.tabId);
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_OTHER_SSO_IDENTITY,
  );

  const second = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    mode: "backend",
  }, {});
  assert.strictEqual(second.ok, true);
  assert.strictEqual(
    requests.filter((request) =>
      new URL(request.url).pathname === "/generate-url"
    ).length,
    2,
  );
});

test("a timed-out fresh sign-in cannot bind after later console navigation", async () => {
  const nativeSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay, ...args) => nativeSetTimeout(
    callback,
    delay === 120_000 ? 0 : delay,
    ...args,
  );
  let launched;
  try {
    launched = await launchFreshBackendForBinding();
  } finally {
    globalThis.setTimeout = nativeSetTimeout;
  }
  const { fixture, result } = launched;
  await new Promise((resolve) => nativeSetTimeout(resolve, 10));
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_OTHER_SSO_IDENTITY,
  );

  await completeTabNavigation(
    fixture,
    result.tabId,
    BACKEND_CONSOLE_URL,
  );
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_OTHER_SSO_IDENTITY,
  );
});

test("profile replacement after tab creation prevents verified reuse binding", async () => {
  const { fixture, result } = await launchFreshBackendForBinding({
    existingBinding: TEST_STALE_REUSE_IDENTITY,
  });
  fixture.storageData.backendSsoProfile =
    "__containoodle_test_replacement_profile__";
  fixture.storageData.backendSsoIdentityKey = TEST_OTHER_SSO_IDENTITY;

  await completeTabNavigation(
    fixture,
    result.tabId,
    BACKEND_CONSOLE_URL,
  );
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_STALE_REUSE_IDENTITY,
  );
});

test("a console completion in another container preserves the old reuse marker", async () => {
  const { fixture, result } = await launchFreshBackendForBinding();

  await completeTabNavigation(
    fixture,
    result.tabId,
    BACKEND_CONSOLE_URL,
    { cookieStoreId: "firefox-container-__containoodle_test_other__" },
  );
  assert.strictEqual(
    fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`],
    TEST_OTHER_SSO_IDENTITY,
  );
});

test("a profile replacement after identity authentication cancels before live-session reuse", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendSsoProfile = TEST_SSO_PROFILE;
  fixture.storageData.backendSsoIdentityKey = TEST_SSO_IDENTITY;
  const storeId = "firefox-container-backend-profile-race";
  fixture.identities.push({
    name: "backend-prod-data",
    cookieStoreId: storeId,
    color: "red",
    icon: "briefcase",
  });
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
  fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
  fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] =
    TEST_SSO_IDENTITY;
  fixture.addTargetPortalCookie(storeId, {
    name: "noflush_Region",
    value: "eu-west-1",
    domain: ".console.aws.amazon.com",
    hostOnly: false,
    path: "/",
    secure: true,
  });
  const onMessage = await loadBackground(fixture);
  const originalGet = fixture.browser.storage.local.get;
  let replaced = false;
  fixture.browser.storage.local.get = async (keys) => {
    const stored = await originalGet(keys);
    if (keys === `backendContainerIdentity/${ACCOUNT_ID}` && !replaced) {
      replaced = true;
      fixture.storageData.backendSsoProfile =
        "__containoodle_test_replacement_profile__";
      fixture.storageData.backendSsoIdentityKey = TEST_OTHER_SSO_IDENTITY;
    }
    return stored;
  };
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
  });

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      mode: "backend",
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    },
  );
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    ["/auth/challenge", "/sso-identity"],
  );
  assert.strictEqual(fixture.cookieReads.length, 0);
  assert.strictEqual(fixture.createdTabs.length, 0);
});

test("a profile replacement during URL generation cancels before container or tab mutation", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendSsoProfile = TEST_SSO_PROFILE;
  fixture.storageData.backendSsoIdentityKey = TEST_SSO_IDENTITY;
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest(url) {
      assert.strictEqual(url.pathname, "/generate-url");
      fixture.storageData.backendSsoProfile =
        "__containoodle_test_replacement_profile__";
      fixture.storageData.backendSsoIdentityKey = TEST_OTHER_SSO_IDENTITY;
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${
            encodeURIComponent(BACKEND_SIGNIN_URL)
          }`,
        },
      };
    },
  });

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_HELPER_ROLE,
      mode: "backend",
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    },
  );
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  assert.strictEqual(fixture.identities.length, 0);
  assert.strictEqual(fixture.createdTabs.length, 0);
});

test("a helper URL replacement during URL generation cancels before container or tab mutation", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.backendSsoProfile = TEST_SSO_PROFILE;
  fixture.storageData.backendSsoIdentityKey = TEST_SSO_IDENTITY;
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest(url) {
      assert.strictEqual(url.pathname, "/generate-url");
      fixture.storageData.config = {
        ...fixture.storageData.config,
        backendUrl: "http://127.0.0.1:8422",
      };
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${
            encodeURIComponent(BACKEND_SIGNIN_URL)
          }`,
        },
      };
    },
  });

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_HELPER_ROLE,
      mode: "backend",
    }, {}),
    {
      ok: false,
      cancelled: true,
      error: "Connection mode changed — try again",
    },
  );
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  assert.strictEqual(fixture.identities.length, 0);
  assert.strictEqual(fixture.createdTabs.length, 0);
});

test("a helper rejection returns to settings without opening a console tab", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    authFailure: "server-proof",
    onRequest(url, options) {
      requests.push({ url, options });
    },
  });
  const storageBefore = structuredClone(fixture.storageData);
  const cookiesBefore = structuredClone(fixture.cookieWrites);

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_HELPER_ROLE,
      mode: "backend",
    }, {}),
    {
      ok: false,
      needsOptions: true,
      error: "Local helper access token was rejected",
    }
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.identities.length, 0);
  assert.deepStrictEqual(fixture.storageData, storageBefore);
  assert.deepStrictEqual(fixture.cookieWrites, cookiesBefore);
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(new URL(requests[0].url).pathname, "/auth/challenge");
  assertNoRawHelperToken(requests[0].url, requests[0].options);
});

test("a later helper trust failure leaves discovered roles and containers untouched", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest(url) {
      if (url.pathname === "/roles") {
        return { payload: { ok: true, roles: [TEST_HELPER_ROLE] } };
      }
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${
            encodeURIComponent(BACKEND_SIGNIN_URL)
          }`,
        },
        responseProofFailure: true,
      };
    },
  });
  const storageBefore = structuredClone(fixture.storageData);
  const cookiesBefore = structuredClone(fixture.cookieWrites);

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      mode: "backend",
    }, {}),
    {
      ok: false,
      needsOptions: true,
      error: "Local helper access token was rejected",
    },
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.identities.length, 0);
  assert.deepStrictEqual(fixture.storageData, {
    ...storageBefore,
    backendSsoIdentityKey: TEST_SSO_IDENTITY,
  });
  assert.deepStrictEqual(fixture.cookieWrites, cookiesBefore);
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/roles",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  for (const request of requests) {
    assertNoRawHelperToken(request.url, request.options);
  }
});

test("a signed helper 401 is classified before parsing its response body", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      requests.push({ url, options });
    },
    async responseForRequest() {
      return { status: 401, rawBody: "__CONTAINOODLE_TEST_NON_JSON__" };
    },
  });
  const storageBefore = structuredClone(fixture.storageData);
  const cookiesBefore = structuredClone(fixture.cookieWrites);

  assert.deepStrictEqual(
    await onMessage({
      type: "launch",
      accountId: ACCOUNT_ID,
      role: TEST_HELPER_ROLE,
      mode: "backend",
    }, {}),
    {
      ok: false,
      needsOptions: true,
      error: "Local helper access token was rejected",
    },
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.identities.length, 0);
  assert.deepStrictEqual(fixture.storageData, {
    ...storageBefore,
    backendSsoIdentityKey: TEST_SSO_IDENTITY,
  });
  assert.deepStrictEqual(fixture.cookieWrites, cookiesBefore);
  assert.deepStrictEqual(
    requests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  for (const request of requests) {
    assertNoRawHelperToken(request.url, request.options);
  }
});

test("backend session reuse never overrides an explicit role choice", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = {
    ...fixture.storageData.config,
    mode: "backend",
  };
  const storeId = "firefox-container-backend";
  fixture.identities.push({
    name: "backend-prod-data",
    cookieStoreId: storeId,
    color: "red",
    icon: "briefcase",
  });
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
  fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
  fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] =
    TEST_SSO_IDENTITY;
  fixture.addTargetPortalCookie(storeId, {
    name: "noflush_Region",
    value: "eu-west-1",
    domain: ".console.aws.amazon.com",
    hostOnly: false,
    path: "/",
    secure: true,
  });
  fixture.addTargetPortalCookie(storeId, {
    name: "aws-signer-token_eu-west-1",
    value: "live-token",
    domain: ".console.aws.amazon.com",
    hostOnly: false,
    path: "/",
    secure: true,
    expirationDate: Math.ceil(Date.now() / 1000) + 3600,
  });
  const onMessage = await loadBackground(fixture);
  const signinUrl = BACKEND_SIGNIN_URL;
  let backendUrl = null;
  let backendOptions = null;
  const backendRequests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url, options) {
      backendRequests.push({ url, options });
      if (new URL(url).pathname === "/generate-url") {
        backendUrl = url;
        backendOptions = options;
      }
    },
    async responseForRequest() {
      return {
        payload: {
          ok: true,
          containerUrl: `ext+container:name=Containoodle&url=${encodeURIComponent(signinUrl)}`,
        },
      };
    },
  });

  const reused = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    mode: "backend",
  }, {});
  assert.strictEqual(reused.ok, true);
  assert.strictEqual(
    fixture.createdTabs[0].url,
    "https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1"
  );
  assert.deepStrictEqual(
    backendRequests.map((request) => new URL(request.url).pathname),
    ["/auth/challenge", "/sso-identity"],
  );
  const cookieReadCount = fixture.cookieReads.length;
  const explicit = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    role: TEST_HELPER_ROLE,
    mode: "backend",
  }, {});

  assert.strictEqual(explicit.ok, true);
  assert.strictEqual(new URL(backendUrl).searchParams.get("role"), TEST_HELPER_ROLE);
  assert.deepStrictEqual(
    backendRequests.map((request) => new URL(request.url).pathname),
    [
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/sso-identity",
      "/auth/challenge",
      "/generate-url",
    ],
  );
  for (const request of backendRequests) {
    assertNoRawHelperToken(request.url, request.options);
  }
  assert.ok(new Headers(backendOptions.headers).has("X-Containoodle-Request-Proof"));
  assert.strictEqual(fixture.createdTabs[1].url, signinUrl);
  assert.strictEqual(
    fixture.cookieReads.length,
    cookieReadCount,
    "an explicit backend role must bypass the live-session cookie check"
  );
  assert.strictEqual(
    fixture.storageData[
      `backendRoleChoice/${TEST_SSO_IDENTITY}/${ACCOUNT_ID}`
    ],
    TEST_HELPER_ROLE
  );
});

test("legacy and narrow console grants both preserve reuse while absence falls back", async (t) => {
  const cases = [
    {
      name: "legacy broad grant",
      origins: ["https://*.amazon.com/*"],
      reuses: true,
    },
    {
      name: "narrow console grant",
      origins: ["https://*.console.aws.amazon.com/*"],
      reuses: true,
    },
    {
      name: "unrelated AWS sibling grant",
      origins: ["https://signin.aws.amazon.com/*"],
      reuses: false,
    },
    { name: "no console grant", origins: [], reuses: false },
  ];

  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const fixture = makeBrowser();
      fixture.storageData.config = {
        ...fixture.storageData.config,
        mode: "backend",
      };
      fixture.storageData.accountsCache[0].role = TEST_HELPER_ROLE;
      fixture.setConsoleOrigins(entry.origins);
      const storeId = `firefox-container-${entry.name.replaceAll(" ", "-")}`;
      fixture.identities.push({
        name: "backend-prod-data",
        cookieStoreId: storeId,
        color: "red",
        icon: "briefcase",
      });
      fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
      fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
      fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] =
        TEST_SSO_IDENTITY;
      fixture.addTargetPortalCookie(storeId, {
        name: "noflush_Region",
        value: TEST_PORTAL_REGION,
        domain: ".console.aws.amazon.com",
        hostOnly: false,
        path: "/",
        secure: true,
      });
      fixture.addTargetPortalCookie(storeId, {
        name: `aws-signer-token_${TEST_PORTAL_REGION}`,
        value: "__CONTAINOODLE_TEST_LIVE_SESSION__",
        domain: ".console.aws.amazon.com",
        hostOnly: false,
        path: "/",
        secure: true,
        expirationDate: Math.ceil(Date.now() / 1000) + 3600,
      });
      const onMessage = await loadBackground(fixture);
      const requests = [];
      globalThis.fetch = authenticatedBackendFetch({
        onRequest(url, options) {
          requests.push({ url, options });
        },
        async responseForRequest() {
          return {
            payload: {
              ok: true,
              containerUrl: `ext+container:name=Containoodle&url=${
                encodeURIComponent(BACKEND_SIGNIN_URL)
              }`,
            },
          };
        },
      });

      const result = await onMessage({
        type: "launch",
        accountId: ACCOUNT_ID,
        mode: "backend",
      }, {});
      assert.strictEqual(result.ok, true);
      const paths = requests.map((request) => new URL(request.url).pathname);
      assert.strictEqual(paths.includes("/generate-url"), !entry.reuses);
      assert.strictEqual(
        fixture.cookieReads.some((read) => read.name === "noflush_Region"),
        entry.reuses,
      );
      assert.ok(fixture.permissionContainsCalls.some((origins) =>
        origins.length === 1 &&
        origins[0] === "https://*.console.aws.amazon.com/*"
      ));
      assert.ok(fixture.permissionContainsCalls.every((origins) =>
        !origins.includes("https://*.amazon.com/*")
      ));
    });
  }
});

test("a mode switch during backend work cancels the old-mode tab creation", async () => {
  const fixture = makeBrowser();
  const oldConfig = {
    ...fixture.storageData.config,
    mode: "backend",
  };
  fixture.storageData.config = oldConfig;
  const storeId = "firefox-container-backend";
  fixture.identities.push({
    name: "backend-prod-data",
    cookieStoreId: storeId,
    color: "red",
    icon: "briefcase",
  });
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
  fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
  const onMessage = await loadBackground(fixture);

  let resolveBackend;
  let backendRequested = false;
  globalThis.fetch = authenticatedBackendFetch({
    responseForRequest() {
      backendRequested = true;
      return new Promise((resolve) => {
        resolveBackend = resolve;
      });
    },
  });
  const launching = onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    role: TEST_HELPER_ROLE,
    mode: "backend",
  }, {});
  await waitFor(() => backendRequested);

  const newConfig = { ...oldConfig, mode: "portal" };
  fixture.storageData.config = newConfig;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
  }
  resolveBackend({
    payload: {
      ok: true,
      containerUrl: `ext+container:name=Containoodle&url=${
        encodeURIComponent(BACKEND_SIGNIN_URL)
      }`,
    },
  });

  assert.deepStrictEqual(await launching, {
    ok: false,
    cancelled: true,
    error: "Connection mode changed — try again",
  });
  assert.strictEqual(fixture.createdTabs.length, 0);
});

test("successful portal clicks and explicit pinned launches update only the portal pin", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [{
    accountId: ACCOUNT_ID,
    accountName: "old-prod-name",
    role: "OldRole",
    note: "preserved",
  }];
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-dev-payments"),
    { ok: true }
  );
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, [{
    accountId: ACCOUNT_ID,
    accountName: "corp-dev-payments",
    role: "ReadOnlyAccess",
    note: "preserved",
  }]);
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "corp-dev-payments"
  );

  const result = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    role: "PowerUserAccess",
  }, {});
  assert.strictEqual(result.ok, true);
  assert.strictEqual(
    fixture.storageData.portalPinnedAccounts[0].role,
    "PowerUserAccess"
  );
  assert.strictEqual(
    fixture.storageData[`portalRoleChoice/${ACCOUNT_ID}`],
    "PowerUserAccess"
  );
  assert.strictEqual(
    fixture.storageData[`backendRoleChoice/${ACCOUNT_ID}`],
    undefined
  );
  assert.deepStrictEqual(
    await onMessage({
      type: "set-portal-pin",
      mode: "portal",
      pinned: false,
      account: {
        accountId: ACCOUNT_ID,
        accountName: "ignored-name",
      },
    }, {}),
    { ok: true, pinned: false }
  );
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, []);
  assert.deepStrictEqual(
    await onMessage({
      type: "set-portal-pin",
      mode: "portal",
      pinned: true,
      account: {
        accountId: ACCOUNT_ID,
        accountName: "stale-placeholder",
      },
    }, {}),
    { ok: true, pinned: true }
  );
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, [{
    accountId: ACCOUNT_ID,
    accountName: "corp-dev-payments",
    role: "PowerUserAccess",
  }]);
});

test("a proven mapped placeholder is reconciled without adopting a same-name container", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  fixture.identities.push(
    {
      name: `Containoodle ${ACCOUNT_ID}`,
      cookieStoreId: "firefox-container-owned",
      color: "red",
      icon: "briefcase",
    },
    {
      name: "corp-dev-data",
      cookieStoreId: "firefox-container-unrelated",
      color: "blue",
      icon: "fingerprint",
    }
  );
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = "firefox-container-owned";
  fixture.storageData["containerAccount/firefox-container-owned"] = ACCOUNT_ID;
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await handoffPortalAccount(onMessage, "corp-dev-data"),
    { ok: true }
  );
  assert.strictEqual(fixture.identities.length, 2, "no replacement container is created");
  assert.deepStrictEqual(fixture.identities[0], {
    name: "corp-dev-data · Containoodle",
    cookieStoreId: "firefox-container-owned",
    color: "green",
    icon: "briefcase",
  });
  assert.deepStrictEqual(fixture.identityUpdates, [{
    storeId: "firefox-container-owned",
    color: "green",
    name: "corp-dev-data · Containoodle",
  }]);
  assert.strictEqual(
    fixture.createdTabs[0].cookieStoreId,
    "firefox-container-owned"
  );
});

test("v1.0.3 storage fixtures survive install and startup cleanup", async (t) => {
  const lifecycleCases = [
    {
      name: "install",
      eventName: "runtimeInstalled",
      details: { reason: "install" },
    },
    {
      name: "update",
      eventName: "runtimeInstalled",
      details: { reason: "update", previousVersion: "1.0.3" },
    },
    {
      name: "startup",
      eventName: "runtimeStartup",
      details: undefined,
    },
  ];

  for (const fixtureName of STORAGE_FIXTURE_NAMES) {
    for (const lifecycle of lifecycleCases) {
      await t.test(`${fixtureName}: ${lifecycle.name}`, async (t) => {
        const previousBrowser = globalThis.browser;
        const previousFetch = globalThis.fetch;
        t.after(() => {
          globalThis.browser = previousBrowser;
          globalThis.fetch = previousFetch;
        });

        const before = readStorageFixture(fixtureName);
        const transientKeys = Object.keys(before).filter(
          (key) => key.startsWith("tabGroups/"),
        );
        assert.ok(transientKeys.length > 0, "fixture must include transient group IDs");

        const expected = structuredClone(before);
        for (const key of transientKeys) delete expected[key];

        const fixture = makeBrowser(before);
        await loadBackground(fixture);
        assert.deepStrictEqual(
          fixture.storageData,
          before,
          "background import must preserve the complete migrated fixture",
        );

        const event = fixture.events[lifecycle.eventName];
        assert.ok(event.listeners.length > 0, "background lifecycle listener is missing");
        await fireBackgroundLifecycle(event, lifecycle.details);
        assert.deepStrictEqual(
          fixture.storageData,
          expected,
          "lifecycle cleanup must remove only transient group IDs",
        );

        await fireBackgroundLifecycle(event, lifecycle.details);
        assert.deepStrictEqual(
          fixture.storageData,
          expected,
          "repeating lifecycle cleanup must be idempotent",
        );
        assert.deepStrictEqual(fixture.createdTabs, []);
        assert.deepStrictEqual(fixture.identities, []);
        assert.deepStrictEqual(fixture.identityUpdates, []);
        assert.deepStrictEqual(fixture.cookieWrites, []);
        assert.deepStrictEqual(fixture.cookieRemovals, []);
      });
    }
  }
});

test("the stored helper token survives install, update, and startup cleanup", async () => {
  const lifecycleCases = [
    ["runtimeInstalled", { reason: "install" }],
    ["runtimeInstalled", { reason: "update", previousVersion: "1.0.3" }],
    ["runtimeStartup", undefined],
  ];

  for (const [eventName, details] of lifecycleCases) {
    const before = readStorageFixture("backend-v1.0.3.json");
    before.backendAuthToken = TEST_HELPER_TOKEN;
    const fixture = makeBrowser(before);
    await loadBackground(fixture);

    await fireBackgroundLifecycle(fixture.events[eventName], details);
    assert.strictEqual(fixture.storageData.backendAuthToken, TEST_HELPER_TOKEN);

    await fireBackgroundLifecycle(fixture.events[eventName], details);
    assert.strictEqual(fixture.storageData.backendAuthToken, TEST_HELPER_TOKEN);
  }
});

test("legacy automatic titles migrate and reset clears a new manual override", async () => {
  const fixture = makeBrowser();
  delete fixture.storageData.portalPinnedAccounts;
  fixture.storageData.accountsCacheSource = "manual";
  fixture.storageData.accountsCache = [
    { accountId: ACCOUNT_ID, accountName: "corp-dev-payments" },
  ];
  fixture.storageData.accountsCacheAt = 123;
  fixture.storageData[`accountOriginalName/${ACCOUNT_ID}`] = "corp-dev-payments";
  fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] = "corp-dev-payments";
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-(?:dev|qa)-(.+)$",
    groupNameReplacement: "$1",
  });
  const onMessage = await loadBackground(fixture);

  await waitFor(() => fixture.storageData["migration/groupTitlesAutomaticV1"] === true);
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, [
    { accountId: ACCOUNT_ID, accountName: "corp-dev-payments" },
  ]);
  assert.strictEqual(fixture.storageData.accountsCache, undefined);
  assert.strictEqual(fixture.storageData.accountsCacheAt, undefined);
  assert.strictEqual(fixture.storageData.accountsCacheSource, undefined);
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "corp-dev-payments"
  );
  assert.strictEqual(
    fixture.storageData[`accountOriginalName/${ACCOUNT_ID}`],
    undefined,
    "the legacy cross-mode name key is removed"
  );
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    undefined,
    "a known old automatic title is cleared"
  );

  const launchResult = await onMessage({
    type: "launch",
    accountId: ACCOUNT_ID,
    role: TEST_PORTAL_ROLE,
  }, {});
  assert.strictEqual(launchResult.ok, true);
  assert.strictEqual(groupForAccount(fixture, ACCOUNT_ID, 1).title, "payments");

  const group = groupForAccount(fixture, ACCOUNT_ID, 1);
  group.title = "My manual title";
  for (const listener of fixture.events.tabGroupsUpdated.listeners) {
    await listener({ ...group });
  }
  await waitFor(
    () => fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] === "My manual title"
  );

  assert.deepStrictEqual(
    await onMessage({ type: "reset-group-titles" }, {}),
    { ok: true, cleared: 1 }
  );
  assert.strictEqual(fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`], undefined);
  assert.strictEqual(groupForAccount(fixture, ACCOUNT_ID, 1).title, "payments");
});

test("legacy manual titles survive migration and remain resettable", async () => {
  const fixture = makeBrowser();
  delete fixture.storageData.portalPinnedAccounts;
  fixture.storageData.accountsCacheSource = "manual";
  fixture.storageData.accountsCache = [
    { accountId: ACCOUNT_ID, accountName: "corp-qa-audit" },
  ];
  fixture.storageData.accountsCacheAt = 123;
  fixture.storageData[`accountOriginalName/${ACCOUNT_ID}`] = "corp-qa-audit";
  fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] = "Hand-picked title";
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^corp-(?:dev|qa)-(.+)$",
    groupNameReplacement: "$1",
  });
  const onMessage = await loadBackground(fixture);

  await waitFor(() => fixture.storageData["migration/groupTitlesAutomaticV1"] === true);
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, [
    { accountId: ACCOUNT_ID, accountName: "corp-qa-audit" },
  ]);
  assert.strictEqual(fixture.storageData.accountsCache, undefined);
  assert.strictEqual(fixture.storageData.accountsCacheAt, undefined);
  assert.strictEqual(fixture.storageData.accountsCacheSource, undefined);
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "corp-qa-audit"
  );
  assert.strictEqual(
    fixture.storageData[`accountOriginalName/${ACCOUNT_ID}`],
    undefined,
    "the legacy cross-mode name key is removed"
  );
  assert.strictEqual(
    fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`],
    "Hand-picked title",
    "a genuinely different manual title survives migration"
  );

  assert.deepStrictEqual(
    await onMessage({ type: "reset-group-titles" }, {}),
    { ok: true, cleared: 1 }
  );
  assert.strictEqual(fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`], undefined);
});

test("portal click handoff uses no backend and opens the exact shortcut in a container", async () => {
  const fixture = makeBrowser();
  let fetchCalls = 0;
  globalThis.browser = fixture.browser;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };

  await import(`../firefox-extension/background.js?test=${Date.now()}`);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const onMessage = fixture.events.runtimeMessage.listeners[0];
  const destination = "https://console.aws.amazon.com/s3/home";
  const shortcut =
    `${START}/#/console?account_id=${ACCOUNT_ID}` +
    `&role_name=ReadOnlyAccess&destination=${encodeURIComponent(destination)}`;

  // A user-created same-name container must never be adopted for this AWS
  // account; Containoodle owns containers through an explicit account-id mapping.
  fixture.identities.push({
    name: "portal-prod-data",
    cookieStoreId: "firefox-container-manual",
    color: "blue",
    icon: "fingerprint",
  });

  assert.deepStrictEqual(
    fixture.getRegisteredScripts()[0].matches,
    [START, `${START}/`]
  );

  assert.deepStrictEqual(
    await onMessage({ type: "portal-interceptor-state" }, { tab: SOURCE_TAB }),
    { enabled: true }
  );
  assert.deepStrictEqual(
    await onMessage({ type: "portal-readiness" }, {}),
    {
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: true,
      session: true,
      roleDiscoveryAccess: true,
      roleDiscoveryRegion: TEST_PORTAL_REGION,
      roleDiscoveryPermissionOrigin: TEST_ROLE_DISCOVERY_ORIGIN,
      consoleAccess: false,
    }
  );
  assert.strictEqual(fetchCalls, 0);
  fixture.setRoleDiscoveryPermission(false);
  fixture.setConsolePermission(false);
  assert.deepStrictEqual(
    await onMessage({ type: "portal-readiness" }, {}),
    {
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: true,
      session: true,
      roleDiscoveryAccess: false,
      roleDiscoveryRegion: TEST_PORTAL_REGION,
      roleDiscoveryPermissionOrigin: TEST_ROLE_DISCOVERY_ORIGIN,
      consoleAccess: false,
    }
  );
  assert.deepStrictEqual(
    await onMessage({
      type: "discover-roles",
      accountId: ACCOUNT_ID,
      mode: "portal",
    }, {}),
    {
      ok: false,
      needsOptions: true,
      error: "Role choices are not allowed — enable them in Containoodle options",
    }
  );
  // Core portal handoff needs only the exact portal origin. The broad role
  // discovery and console-cookie permissions remain disabled for this launch.
  const result = await onMessage(
    { type: "portal-shortcut-click", url: shortcut, disposition: "new-tab" },
    { tab: SOURCE_TAB }
  );
  assert.deepStrictEqual(result, { ok: true });
  assert.strictEqual(fetchCalls, 0);
  assert.strictEqual(fixture.createdTabs.length, 1);
  assert.strictEqual(fixture.createdTabs[0].url, shortcut);
  assert.strictEqual(fixture.createdTabs[0].cookieStoreId, "firefox-container-1");
  assert.strictEqual(fixture.createdTabs[0].windowId, SOURCE_TAB.windowId);
  assert.strictEqual(fixture.identities[1].name, "portal-prod-data · Containoodle");
  assert.strictEqual(
    fixture.storageData[`accountContainer/${ACCOUNT_ID}`],
    "firefox-container-1"
  );
  assert.strictEqual(
    fixture.storageData["containerAccount/firefox-container-1"],
    ACCOUNT_ID
  );
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).url, SOURCE_TAB.url);
  assert.strictEqual(
    fixture.storageData[`portalRoleChoice/${ACCOUNT_ID}`],
    "ReadOnlyAccess"
  );
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "portal-prod-data"
  );
  assert.strictEqual(
    fixture.cookieReads.some(
      (read) =>
        read.name === "noflush_Region" ||
        String(read.name || "").startsWith("aws-signer-token_")
    ),
    false,
    "portal launches must not inspect AWS console-session cookies"
  );
  assert.strictEqual(
    fixture.cookieWrites.some((cookie) => cookie.name === "awsccc"),
    false,
    "portal launches must not seed the AWS console consent cookie"
  );
  assert.ok(fixture.cookieWrites.some(
    (cookie) =>
      cookie.name === "x-amz-sso_authn" &&
      cookie.storeId === "firefox-container-1"
  ));
  const firstAuthWrite = fixture.cookieWrites.find(
    (cookie) => cookie.name === "x-amz-sso_authn"
  );
  assert.strictEqual(firstAuthWrite.domain, ".awsapps.com");
  assert.strictEqual(firstAuthWrite.path, "/");
  assert.strictEqual(Object.hasOwn(firstAuthWrite, "firstPartyDomain"), false);
  assert.deepStrictEqual(
    firstAuthWrite.partitionKey,
    {
      topLevelSite: new URL(START).origin,
      hasCrossSiteAncestor: false,
    }
  );
  assert.strictEqual(firstAuthWrite.value, "test-session-value");
  assert.ok(fixture.cookieReads.some(
    (read) =>
      read.method === "getAll" &&
      read.name === "x-amz-sso_authn" &&
      read.storeId === "firefox-default" &&
      read.firstPartyDomain === null &&
      read.partitionKey &&
      Object.keys(read.partitionKey).length === 0
  ));

  // Identical later clicks are not suppressed after the first task completes.
  fixture.addTargetPortalCookie("firefox-container-1", {
    name: "x-amz-sso_authn",
    value: "stale-container-value",
    domain: new URL(START).hostname,
    hostOnly: true,
    path: "/start",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    session: true,
    firstPartyDomain: "",
  });
  fixture.setPortalCookie({
    name: "x-amz-sso_authn",
    value: "session-cookie-value",
    domain: new URL(START).hostname,
    hostOnly: true,
    path: "/start",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    session: true,
    firstPartyDomain: "awsapps.com",
  });
  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "new-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: true }
  );
  assert.strictEqual(fixture.createdTabs.length, 2);
  const secondAuthWrite = fixture.cookieWrites.filter(
    (cookie) => cookie.name === "x-amz-sso_authn"
  ).at(-1);
  assert.strictEqual(secondAuthWrite.path, "/start");
  assert.strictEqual(Object.hasOwn(secondAuthWrite, "domain"), false);
  assert.strictEqual(Object.hasOwn(secondAuthWrite, "expirationDate"), false);
  assert.strictEqual(Object.hasOwn(secondAuthWrite, "partitionKey"), false);
  assert.strictEqual(secondAuthWrite.firstPartyDomain, "awsapps.com");
  assert.ok(fixture.cookieRemovals.filter(
    (cookie) =>
      cookie.name === "x-amz-sso_authn" &&
      cookie.storeId === "firefox-container-1"
  ).length >= 2);

  // Switching modes makes the portal machinery inert without probing backend URLs.
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "new-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: false }
  );
  assert.strictEqual(fetchCalls, 0);
  assert.strictEqual(fixture.createdTabs.length, 2);

  // A failed cookie copy creates no destination; the native page remains untouched.
  fixture.storageData.config = { ...fixture.storageData.config, mode: "portal" };
  fixture.setPortalCookie(null);
  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "same-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: false }
  );
  assert.strictEqual(fixture.createdTabs.length, 2);
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).url, SOURCE_TAB.url);

  // The content script's native fallback URL event is consumed once and
  // clears its timer instead of starting another failed handoff.
  fixture.events.tabsUpdated.listeners[0](
    SOURCE_TAB.id,
    { url: shortcut },
    { ...SOURCE_TAB, url: shortcut }
  );
  assert.strictEqual(fixture.createdTabs.length, 2);

  // A failed target=_blank handoff preserves the portal and opens one
  // default-store native fallback tab instead of replacing the portal.
  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "new-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: false, nativeFallback: true }
  );
  assert.strictEqual(fixture.createdTabs.length, 3);
  const nativeFallback = fixture.createdTabs[2];
  assert.strictEqual(nativeFallback.url, shortcut);
  assert.strictEqual(nativeFallback.cookieStoreId, "firefox-default");
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).url, SOURCE_TAB.url);
  fixture.setPortalCookie({
    name: "x-amz-sso_authn",
    value: "test-session-value",
    domain: new URL(START).hostname,
    hostOnly: true,
    path: "/start/",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    session: false,
    expirationDate: 2000000000,
    firstPartyDomain: "",
  });
  // A delayed creation notification for the initial blank page must not
  // clear the exact-tab guard before the target URL notification arrives.
  fixture.events.tabsCreated.listeners[0]({
    ...nativeFallback,
    url: "about:blank",
  });
  fixture.events.tabsUpdated.listeners[0](
    nativeFallback.id,
    { url: shortcut },
    nativeFallback
  );
  // Duplicate URL notifications for that same tab stay consumed, while a
  // later redirect releases the exact-tab guard.
  fixture.events.tabsUpdated.listeners[0](
    nativeFallback.id,
    { url: shortcut },
    nativeFallback
  );
  fixture.events.tabsUpdated.listeners[0](
    nativeFallback.id,
    { url: "https://signin.aws.amazon.com/" },
    { ...nativeFallback, url: "https://signin.aws.amazon.com/" }
  );
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.strictEqual(fixture.createdTabs.length, 3);

  fixture.setPortalPermission(false);
  assert.deepStrictEqual(
    await onMessage({ type: "portal-interceptor-state" }, { tab: SOURCE_TAB }),
    { enabled: false }
  );
  assert.deepStrictEqual(
    await onMessage({ type: "portal-readiness" }, {}),
    {
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: false,
      session: false,
      roleDiscoveryAccess: false,
      roleDiscoveryRegion: null,
      roleDiscoveryPermissionOrigin: null,
      consoleAccess: false,
    }
  );
  fixture.setPortalPermission(true);

  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "new-tab" },
      { tab: { ...SOURCE_TAB, url: "https://example.com/" } }
    ),
    { ok: false }
  );
  assert.strictEqual(fixture.createdTabs.length, 3);

  // The URL-event fallback still launches if AWS redirects before async
  // storage/browser work finishes, but it never overwrites that newer page.
  const redirectedUrl = "https://eu-west-1.console.aws.amazon.com/console/home";
  fixture.tabs.get(SOURCE_TAB.id).url = redirectedUrl;
  fixture.events.tabsUpdated.listeners[0](
    SOURCE_TAB.id,
    { url: shortcut },
    { ...SOURCE_TAB, url: shortcut }
  );
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.strictEqual(fixture.createdTabs.length, 4);
  assert.strictEqual(fixture.tabs.get(SOURCE_TAB.id).url, redirectedUrl);

  // A config change arriving during permission-triggered registration is
  // replayed at the trailing edge instead of being lost to deduplication.
  fixture.storageData.config = { ...fixture.storageData.config, portalStartUrl: "" };
  const releaseRegistrationRead = fixture.pauseNextRegistrationRead();
  fixture.events.permissionsAdded.listeners[0]({});
  await new Promise((resolve) => setTimeout(resolve, 0));
  fixture.storageData.config = {
    ...fixture.storageData.config,
    portalStartUrl: START,
  };
  fixture.events.storageChanged.listeners[0]({ config: {} }, "local");
  releaseRegistrationRead();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepStrictEqual(fixture.getRegisteredScripts()[0].matches, [START, `${START}/`]);
});

test("startup replaces an older portal interceptor registration without duplicate handling", async () => {
  const fixture = makeBrowser();
  fixture.setRegisteredScripts([{
    id: "previous-brand-portal-clicks",
    js: ["portal-interceptor.js"],
    matches: [START, `${START}/`],
    runAt: "document_start",
    persistAcrossSessions: true,
  }]);

  await loadBackground(fixture);
  await waitFor(() => fixture.getRegisteredScripts().length === 1);

  assert.strictEqual(fixture.getRegisteredScripts()[0].id, "containoodle-portal-clicks");
});

test("role readiness queries only the exact regional target with legacy coverage", async () => {
  const fixture = makeBrowser();
  const onMessage = await loadBackground(fixture);
  const cases = [
    { origins: ["https://*.amazonaws.com/*"], access: true },
    { origins: [TEST_ROLE_DISCOVERY_ORIGIN], access: true },
    {
      origins: ["https://portal.sso.yy-test-2.amazonaws.com/*"],
      access: false,
    },
    { origins: [], access: false },
  ];

  for (const entry of cases) {
    fixture.setRoleDiscoveryOrigins(entry.origins);
    fixture.permissionContainsCalls.length = 0;
    const readiness = await onMessage({ type: "portal-readiness" }, {});
    assert.strictEqual(readiness.roleDiscoveryAccess, entry.access);
    assert.strictEqual(
      readiness.roleDiscoveryPermissionOrigin,
      TEST_ROLE_DISCOVERY_ORIGIN,
    );
    assert.ok(fixture.permissionContainsCalls.some(
      (origins) => origins.length === 1 && origins[0] === TEST_ROLE_DISCOVERY_ORIGIN
    ));
    assert.ok(fixture.permissionContainsCalls.every(
      (origins) => !origins.includes("https://*.amazonaws.com/*")
    ));
  }
});

test("portal role discovery calls only the authorized synthetic regional API", async () => {
  const fixture = makeBrowser();
  const onMessage = await loadBackground(fixture);
  const apiOrigin = "https://portal.sso.xx-test-1.amazonaws.com";
  const syntheticAppId = "__CONTAINOODLE_TEST_APP__";
  const allowedCases = [
    ["https://*.amazonaws.com/*"],
    [TEST_ROLE_DISCOVERY_ORIGIN],
  ];

  for (const origins of allowedCases) {
    fixture.setRoleDiscoveryOrigins(origins);
    const fetches = [];
    globalThis.fetch = async (input, options = {}) => {
      const url = new URL(input);
      fetches.push({ url: url.href, options });
      assert.strictEqual(url.origin, apiOrigin);
      if (url.pathname === "/instance/appinstances") {
        return new Response(JSON.stringify({
          result: [{
            id: syntheticAppId,
            searchMetadata: { AccountId: ACCOUNT_ID },
          }],
        }), { status: 200 });
      }
      if (
        url.pathname ===
        `/instance/appinstance/${encodeURIComponent(syntheticAppId)}/profiles`
      ) {
        return new Response(JSON.stringify({
          result: [{ name: TEST_PORTAL_ROLE }],
        }), { status: 200 });
      }
      throw new Error(`Unexpected synthetic portal path: ${url.pathname}`);
    };

    assert.deepStrictEqual(
      await onMessage({
        type: "discover-roles",
        accountId: ACCOUNT_ID,
        mode: "portal",
      }, {}),
      { ok: true, roles: [TEST_PORTAL_ROLE] },
    );
    assert.deepStrictEqual(
      fetches.map(({ url }) => new URL(url).pathname),
      [
        "/instance/appinstances",
        `/instance/appinstance/${encodeURIComponent(syntheticAppId)}/profiles`,
      ],
    );
  }

  for (const origins of [
    ["https://portal.sso.yy-test-2.amazonaws.com/*"],
    [],
  ]) {
    fixture.setRoleDiscoveryOrigins(origins);
    let fetchCount = 0;
    globalThis.fetch = async () => {
      fetchCount += 1;
      throw new Error("regional API must remain unreachable");
    };

    assert.deepStrictEqual(
      await onMessage({
        type: "discover-roles",
        accountId: ACCOUNT_ID,
        mode: "portal",
      }, {}),
      {
        ok: false,
        needsOptions: true,
        error: "Role choices are not allowed — enable them in Containoodle options",
      },
    );
    assert.strictEqual(fetchCount, 0);
  }
});

test("unbound or wrong-portal region caches never become permission targets", async () => {
  for (const cachedOrigin of [undefined, "https://d-9999999999.awsapps.com"]) {
    const fixture = makeBrowser();
    fixture.storageData.config.ssoRegion = "";
    fixture.storageData.portalRegionCache = "yy-test-2";
    if (cachedOrigin) fixture.storageData.portalRegionCacheOrigin = cachedOrigin;
    const onMessage = await loadBackground(fixture);

    const readiness = await onMessage({ type: "portal-readiness" }, {});
    assert.strictEqual(readiness.ok, true);
    assert.strictEqual(readiness.portalAccess, true);
    assert.strictEqual(readiness.session, true);
    assert.strictEqual(readiness.roleDiscoveryAccess, false);
    assert.strictEqual(readiness.roleDiscoveryRegion, null);
    assert.strictEqual(readiness.roleDiscoveryPermissionOrigin, null);
  }
});

test("tab-event fallback reuses a captured portal name for an unpinned account", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`] =
    "corp-dev-payments";
  await loadBackground(fixture);
  const shortcut = portalShortcut();

  fixture.events.tabsUpdated.listeners[0](
    SOURCE_TAB.id,
    { url: shortcut },
    { ...SOURCE_TAB, url: shortcut }
  );
  await waitFor(() => fixture.createdTabs.length === 1);

  assert.strictEqual(fixture.createdTabs[0].url, shortcut);
  assert.strictEqual(fixture.identities[0].name, "corp-dev-payments");
  assert.strictEqual(fixture.identities[0].color, "green");
  assert.strictEqual(groupForAccount(fixture).title, "corp-dev-payments");
  assert.strictEqual(
    fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`],
    "corp-dev-payments"
  );
});

test("portal handoff refuses to navigate when the copied cookie cannot be read back", async () => {
  const fixture = makeBrowser();
  fixture.setCookieReadbackEnabled(false);
  globalThis.browser = fixture.browser;
  globalThis.fetch = async () => {
    throw new Error("unexpected fetch");
  };

  await import(`../firefox-extension/background.js?readback=${Date.now()}`);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const onMessage = fixture.events.runtimeMessage.listeners[0];
  const shortcut =
    `${START}/#/console?account_id=${ACCOUNT_ID}` +
    "&role_name=ReadOnlyAccess";

  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "same-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: false }
  );
  assert.deepStrictEqual(
    await onMessage({ type: "portal-readiness" }, {}),
    {
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: true,
      session: true,
      roleDiscoveryAccess: true,
      roleDiscoveryRegion: TEST_PORTAL_REGION,
      roleDiscoveryPermissionOrigin: TEST_ROLE_DISCOVERY_ORIGIN,
      consoleAccess: false,
    }
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.ok(fixture.cookieWrites.some(
    (cookie) => cookie.name === "x-amz-sso_authn"
  ));

  // Consume the same-tab native fallback guard so the test leaves no timer.
  fixture.events.tabsUpdated.listeners[0](
    SOURCE_TAB.id,
    { url: shortcut },
    { ...SOURCE_TAB, url: shortcut }
  );
});

test("domain-cookie handoff rejects a host-only readback", async () => {
  const fixture = makeBrowser();
  fixture.setForceHostOnlyReadback(true);
  globalThis.browser = fixture.browser;
  globalThis.fetch = async () => {
    throw new Error("unexpected fetch");
  };

  await import(`../firefox-extension/background.js?scope=${Date.now()}`);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const onMessage = fixture.events.runtimeMessage.listeners[0];
  const shortcut =
    `${START}/#/console?account_id=${ACCOUNT_ID}` +
    "&role_name=ReadOnlyAccess";

  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "same-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: false }
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.ok(fixture.cookieWrites.some(
    (cookie) => cookie.domain === ".awsapps.com"
  ));

  fixture.events.tabsUpdated.listeners[0](
    SOURCE_TAB.id,
    { url: shortcut },
    { ...SOURCE_TAB, url: shortcut }
  );
});

test("portal handoff ignores a cross-site-ancestor cookie partition", async () => {
  const fixture = makeBrowser();
  fixture.setPortalCookie({
    name: "x-amz-sso_authn",
    value: "cross-site-only",
    domain: ".awsapps.com",
    hostOnly: false,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    session: true,
    firstPartyDomain: "",
    partitionKey: {
      topLevelSite: new URL(START).origin,
      hasCrossSiteAncestor: true,
    },
  });
  globalThis.browser = fixture.browser;
  globalThis.fetch = async () => {
    throw new Error("unexpected fetch");
  };

  await import(`../firefox-extension/background.js?crosssite=${Date.now()}`);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const onMessage = fixture.events.runtimeMessage.listeners[0];
  const shortcut =
    `${START}/#/console?account_id=${ACCOUNT_ID}` +
    "&role_name=ReadOnlyAccess";

  assert.deepStrictEqual(
    await onMessage(
      { type: "portal-shortcut-click", url: shortcut, disposition: "same-tab" },
      { tab: SOURCE_TAB }
    ),
    { ok: false }
  );
  assert.deepStrictEqual(
    await onMessage({ type: "portal-readiness" }, {}),
    {
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: true,
      session: false,
      roleDiscoveryAccess: true,
      roleDiscoveryRegion: TEST_PORTAL_REGION,
      roleDiscoveryPermissionOrigin: TEST_ROLE_DISCOVERY_ORIGIN,
      consoleAccess: false,
    }
  );
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.cookieWrites.filter(
    (cookie) => cookie.name === "x-amz-sso_authn"
  ).length, 0);

  fixture.events.tabsUpdated.listeners[0](
    SOURCE_TAB.id,
    { url: shortcut },
    { ...SOURCE_TAB, url: shortcut }
  );
});
