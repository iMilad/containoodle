import test from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import {
  ONBOARDING_KEY,
  ONBOARDING_STATES,
} from "../firefox-extension/shared/onboarding.js";

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
        while (tabs.has(nextTabId)) nextTabId += 1;
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

function currentSession(fixture, accountId = ACCOUNT_ID) {
  const storeId = fixture.storageData[`accountContainer/${accountId}`];
  return fixture.storageData[`containerSession/${storeId}`];
}

async function primeVerifiedHelperSession(fixture, onMessage) {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = authenticatedBackendFetch({ responseForRequest: backendSigninResponse });
  try {
    const result = await onMessage({
      type: "launch", accountId: ACCOUNT_ID, mode: "backend", role: TEST_HELPER_ROLE,
    }, {});
    assert.strictEqual(result.ok, true);
    await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
    assert.strictEqual(currentSession(fixture).verified, true);
  } finally {
    globalThis.fetch = previousFetch;
  }
  fixture.createdTabs.length = 0;
  fixture.cookieReads.length = 0;
  fixture.permissionContainsCalls.length = 0;
}

function addLiveConsoleCookies(fixture, storeId) {
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
}

async function changeConnectionMode(fixture, mode) {
  const before = fixture.storageData.config;
  const after = { ...before, mode };
  fixture.storageData.config = after;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: before, newValue: after } }, "local");
  }
  await new Promise((resolve) => setImmediate(resolve));
}

function backendSigninResponse() {
  return { payload: {
    ok: true,
    containerUrl: `ext+container:name=Containoodle&url=${encodeURIComponent(BACKEND_SIGNIN_URL)}`,
  } };
}

function generationRequestCount(requests) {
  return requests.filter((request) => new URL(request.url).pathname === "/generate-url").length;
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

test("connection onboarding lifecycle distinguishes new installs from existing profiles", async (t) => {
  const cases = [
    {
      name: "fresh install",
      initialStorage: {},
      details: { reason: "install" },
      expected: ONBOARDING_STATES.CHOOSE,
    },
    {
      name: "install retaining configuration",
      initialStorage: { config: { mode: "backend" } },
      details: { reason: "install" },
      expected: ONBOARDING_STATES.COMPLETE,
    },
    {
      name: "update without a marker",
      initialStorage: {},
      details: { reason: "update", previousVersion: "1.1.1" },
      expected: ONBOARDING_STATES.COMPLETE,
    },
    {
      name: "invalid stored marker",
      initialStorage: { [ONBOARDING_KEY]: "invalid-test-state" },
      details: { reason: "install" },
      expected: ONBOARDING_STATES.COMPLETE,
    },
  ];

  for (const lifecycle of cases) {
    await t.test(lifecycle.name, async () => {
      const fixture = makeBrowser(lifecycle.initialStorage);
      await loadBackground(fixture);
      const configBefore = structuredClone(fixture.storageData.config);
      const permissionChecksBefore = structuredClone(
        fixture.permissionContainsCalls,
      );
      const originalSet = fixture.browser.storage.local.set;
      let onboardingWrites = 0;
      fixture.browser.storage.local.set = async (values) => {
        if (Object.hasOwn(values, ONBOARDING_KEY)) onboardingWrites += 1;
        return originalSet(values);
      };

      await fireBackgroundLifecycle(
        fixture.events.runtimeInstalled,
        lifecycle.details,
      );

      assert.strictEqual(
        fixture.storageData[ONBOARDING_KEY],
        lifecycle.expected,
      );
      assert.deepStrictEqual(fixture.storageData.config, configBefore);
      assert.deepStrictEqual(
        fixture.permissionContainsCalls,
        permissionChecksBefore,
      );
      assert.deepStrictEqual(fixture.createdTabs, []);
      assert.deepStrictEqual(fixture.cookieWrites, []);
      assert.deepStrictEqual(fixture.cookieRemovals, []);
      assert.strictEqual(onboardingWrites, 1);

      await fireBackgroundLifecycle(
        fixture.events.runtimeInstalled,
        lifecycle.details,
      );
      assert.strictEqual(onboardingWrites, 1, "repeat lifecycle must not rewrite state");
    });
  }
});

test("sidebar onboarding resolution waits for the in-flight install marker", async () => {
  const fixture = makeBrowser({});
  const onMessage = await loadBackground(fixture);
  const lifecycleListener = fixture.events.runtimeInstalled.listeners.find(
    (listener) => listener.name === "beginConnectionOnboarding",
  );
  assert.ok(lifecycleListener, "missing connection onboarding lifecycle listener");

  const originalGet = fixture.browser.storage.local.get;
  let releaseLifecycleRead;
  const lifecycleRead = new Promise((resolve) => {
    releaseLifecycleRead = resolve;
  });
  let delayedLifecycleReads = 0;
  fixture.browser.storage.local.get = async (keys) => {
    if (
      delayedLifecycleReads === 0 &&
      Array.isArray(keys) &&
      keys.length === 2 &&
      keys.includes(ONBOARDING_KEY) &&
      keys.includes("config")
    ) {
      delayedLifecycleReads += 1;
      await lifecycleRead;
    }
    return originalGet(keys);
  };

  const permissionChecksBefore = structuredClone(
    fixture.permissionContainsCalls,
  );
  const initialization = lifecycleListener({ reason: "install" });
  let resolutionSettled = false;
  const resolution = Promise.resolve(onMessage({
    type: "resolve-connection-onboarding",
  }, {})).then((result) => {
    resolutionSettled = true;
    return result;
  });

  await new Promise((resolve) => setImmediate(resolve));
  assert.strictEqual(delayedLifecycleReads, 1);
  assert.strictEqual(resolutionSettled, false);
  assert.strictEqual(Object.hasOwn(fixture.storageData, ONBOARDING_KEY), false);
  assert.deepStrictEqual(
    fixture.permissionContainsCalls,
    permissionChecksBefore,
  );
  assert.deepStrictEqual(fixture.createdTabs, []);
  assert.deepStrictEqual(fixture.cookieWrites, []);
  assert.deepStrictEqual(fixture.cookieRemovals, []);

  releaseLifecycleRead();
  const [resolved] = await Promise.all([resolution, initialization]);
  assert.deepStrictEqual(resolved, { state: ONBOARDING_STATES.CHOOSE });
  assert.strictEqual(
    fixture.storageData[ONBOARDING_KEY],
    ONBOARDING_STATES.CHOOSE,
  );
});

test("sidebar onboarding resolution preserves ordinary missing-marker behavior", async () => {
  const fixture = makeBrowser({});
  const onMessage = await loadBackground(fixture);

  assert.deepStrictEqual(
    await onMessage({ type: "resolve-connection-onboarding" }, {}),
    { state: undefined },
  );
  assert.strictEqual(Object.hasOwn(fixture.storageData, ONBOARDING_KEY), false);
  assert.deepStrictEqual(fixture.permissionContainsCalls, []);
  assert.deepStrictEqual(fixture.createdTabs, []);
  assert.deepStrictEqual(fixture.cookieWrites, []);
  assert.deepStrictEqual(fixture.cookieRemovals, []);
});

test("connection onboarding preserves recognized state and ignores startup", async (t) => {
  for (const state of Object.values(ONBOARDING_STATES)) {
    await t.test(`preserves ${state}`, async () => {
      const fixture = makeBrowser({ [ONBOARDING_KEY]: state });
      await loadBackground(fixture);
      const originalSet = fixture.browser.storage.local.set;
      let onboardingWrites = 0;
      fixture.browser.storage.local.set = async (values) => {
        if (Object.hasOwn(values, ONBOARDING_KEY)) onboardingWrites += 1;
        return originalSet(values);
      };

      await fireBackgroundLifecycle(
        fixture.events.runtimeInstalled,
        { reason: "update", previousVersion: "1.1.1" },
      );

      assert.strictEqual(fixture.storageData[ONBOARDING_KEY], state);
      assert.strictEqual(onboardingWrites, 0);
    });
  }

  await t.test("startup does not initialize missing state", async () => {
    const fixture = makeBrowser({});
    await loadBackground(fixture);
    await fireBackgroundLifecycle(fixture.events.runtimeStartup);
    assert.strictEqual(
      Object.hasOwn(fixture.storageData, ONBOARDING_KEY),
      false,
    );
  });
});

test("connection onboarding storage failure never rejects installation", async () => {
  const fixture = makeBrowser({});
  await loadBackground(fixture);
  const originalSet = fixture.browser.storage.local.set;
  fixture.browser.storage.local.set = async (values) => {
    if (Object.hasOwn(values, ONBOARDING_KEY)) {
      throw new Error("synthetic onboarding storage failure");
    }
    return originalSet(values);
  };

  await fireBackgroundLifecycle(
    fixture.events.runtimeInstalled,
    { reason: "install" },
  );
  assert.strictEqual(Object.hasOwn(fixture.storageData, ONBOARDING_KEY), false);
});

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

test("portal account-name replacement changes automatic labels, not account identity or colors", async () => {
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
  assert.strictEqual(fixture.identities[0].name, "data");
  assert.strictEqual(
    fixture.storageData[`containerOriginalName/${fixture.identities[0].cookieStoreId}`],
    "corp-dev-data",
  );
  assert.strictEqual(fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`], "corp-dev-data");
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
  assert.strictEqual(fixture.identities[0].name, "billing");
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
  await waitFor(() => fixture.identities[0].name === "new-payments");
});

function saveTestNamingRule(fixture, pattern, replacement) {
  const oldConfig = fixture.storageData.config;
  const newConfig = {
    ...oldConfig,
    groupNamePattern: pattern,
    groupNameReplacement: replacement,
  };
  fixture.storageData.config = newConfig;
  for (const listener of fixture.events.storageChanged.listeners) {
    listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
  }
}

async function handoffSyntheticNamedAccount(onMessage, accountName, accountId = ACCOUNT_ID) {
  return onMessage({
    type: "portal-shortcut-click",
    url: `${START}/#/console?account_id=${accountId}&role_name=${TEST_PORTAL_ROLE}`,
    disposition: "new-tab",
    accountName,
  }, { tab: SOURCE_TAB });
}

test("saving and clearing a rule renames existing automatic containers without replacing them", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  const onMessage = await loadBackground(fixture);
  assert.deepStrictEqual(
    await handoffSyntheticNamedAccount(onMessage, "example-prod-payments"), { ok: true },
  );
  const identity = fixture.identities[0];
  const storeId = identity.cookieStoreId;
  const tabId = fixture.createdTabs[0].id;
  const originalStorage = structuredClone(fixture.storageData.portalPinnedAccounts);
  const cookieWriteCount = fixture.cookieWrites.length;
  saveTestNamingRule(fixture, "^example-prod-", "");
  await waitFor(() => identity.name === "payments" && groupForAccount(fixture).title === "payments");
  assert.strictEqual(identity.color, "red", "environment stays based on the original name");
  assert.strictEqual(fixture.storageData[`accountContainer/${ACCOUNT_ID}`], storeId);
  assert.strictEqual(fixture.storageData[`containerAccount/${storeId}`], ACCOUNT_ID);
  assert.strictEqual(fixture.tabs.get(tabId).cookieStoreId, storeId);
  assert.strictEqual(fixture.identities.length, 1);
  assert.strictEqual(fixture.createdTabs.length, 1);
  assert.strictEqual(fixture.cookieWrites.length, cookieWriteCount);
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, originalStorage);

  saveTestNamingRule(fixture, "", "");
  await waitFor(() => identity.name === "example-prod-payments" &&
    groupForAccount(fixture).title === "example-prod-payments");
  assert.strictEqual(fixture.storageData[`containerOriginalName/${storeId}`], "example-prod-payments");
});

test("rules never merge same-label accounts or adopt unrelated Firefox containers", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  Object.assign(fixture.storageData.config, {
    groupNamePattern: "^example-(?:dev|prod)-", groupNameReplacement: "",
  });
  fixture.identities.push({ name: "shared", cookieStoreId: "firefox-container-personal", color: "blue" });
  const unrelatedBefore = structuredClone(fixture.identities[0]);
  const onMessage = await loadBackground(fixture);
  const otherId = "1".repeat(12);
  assert.deepStrictEqual(await handoffSyntheticNamedAccount(onMessage, "example-dev-shared"), { ok: true });
  assert.deepStrictEqual(await handoffSyntheticNamedAccount(onMessage, "example-prod-shared", otherId), { ok: true });
  const firstStore = fixture.storageData[`accountContainer/${ACCOUNT_ID}`];
  const secondStore = fixture.storageData[`accountContainer/${otherId}`];
  assert.notStrictEqual(firstStore, secondStore);
  assert.deepStrictEqual(fixture.identities[0], unrelatedBefore);
  assert.deepStrictEqual(fixture.identities.slice(1).map((identity) => identity.name), [
    "shared · Containoodle", "shared · Containoodle (2)",
  ]);
  assert.strictEqual(fixture.storageData[`containerAccount/${firstStore}`], ACCOUNT_ID);
  assert.strictEqual(fixture.storageData[`containerAccount/${secondStore}`], otherId);
  assert.strictEqual(groupForAccount(fixture).title, "shared");
  assert.strictEqual(groupForAccount(fixture, otherId).title, "shared");
});

test("non-idempotent rules always use raw names across saves and background restart", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  Object.assign(fixture.storageData.config, { groupNamePattern: "^", groupNameReplacement: "Shown: " });
  const onMessage = await loadBackground(fixture);
  await handoffSyntheticNamedAccount(onMessage, "example-dev-data");
  const identity = fixture.identities[0];
  assert.strictEqual(identity.name, "Shown: example-dev-data");
  saveTestNamingRule(fixture, "^", "Label: ");
  await waitFor(() => identity.name === "Label: example-dev-data");
  const restarted = makeBrowser(fixture.storageData);
  restarted.identities.push(structuredClone(identity));
  await loadBackground(restarted);
  assert.strictEqual(restarted.identities[0].name, "Label: example-dev-data");
  assert.strictEqual(restarted.identityUpdates.length, 0);
});

test("manual container names and manual group titles survive a saved rule and later launches", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  const onMessage = await loadBackground(fixture);
  await handoffSyntheticNamedAccount(onMessage, "example-qa-audit");
  fixture.identities[0].name = "My custom container";
  fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] = "My custom tab group";
  saveTestNamingRule(fixture, "^example-qa-", "");
  await handoffSyntheticNamedAccount(onMessage, "example-qa-audit");
  assert.strictEqual(fixture.identities[0].name, "My custom container");
  assert.strictEqual(groupForAccount(fixture).title, "My custom tab group");
  assert.strictEqual(fixture.identities.length, 1);
});

test("a user rename during automatic container-name calculation is not overwritten", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  const onMessage = await loadBackground(fixture);
  await handoffSyntheticNamedAccount(onMessage, "example-dev-data");
  const originalQuery = fixture.browser.contextualIdentities.query;
  let renamed = false;
  fixture.browser.contextualIdentities.query = async (query) => {
    if (query.name === "data" && !renamed) {
      renamed = true;
      fixture.identities[0].name = "User renamed during save";
    }
    return originalQuery(query);
  };
  saveTestNamingRule(fixture, "^example-dev-", "");
  await waitFor(() => renamed);
  await handoffSyntheticNamedAccount(onMessage, "example-dev-data");
  assert.strictEqual(fixture.identities[0].name, "User renamed during save");
});

test("existing helper containers use backend originals on startup without auth or tab-group APIs", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = {
    ...fixture.storageData.config, mode: "backend",
    groupNamePattern: "^example-dev-", groupNameReplacement: "",
  };
  delete fixture.storageData.backendAuthToken;
  fixture.storageData.accountsCache = [{ accountId: ACCOUNT_ID, accountName: "example-dev-data" }];
  fixture.storageData[`portalAccountOriginalName/${ACCOUNT_ID}`] = "portal-prod-must-not-be-used";
  const storeId = "firefox-container-existing-helper";
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
  fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
  fixture.identities.push({ name: "example-dev-data", cookieStoreId: storeId, color: "green" });
  delete fixture.browser.tabs.group;
  delete fixture.browser.tabGroups;
  await loadBackground(fixture);
  await waitFor(() => fixture.identities[0].name === "data");
  assert.strictEqual(fixture.storageData[`containerOriginalName/${storeId}`], "example-dev-data");
  assert.strictEqual(fixture.identities[0].color, "green");
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.cookieWrites.length, 0);
  assert.strictEqual(fixture.identities.length, 1);
});

test("legacy collision names migrate, while custom and unproven mappings stay untouched", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = {
    ...fixture.storageData.config, groupNamePattern: "^example-qa-", groupNameReplacement: "",
  };
  fixture.storageData.portalPinnedAccounts = [];
  const cases = [
    { id: ACCOUNT_ID, store: "firefox-container-legacy", name: "example-qa-data · Containoodle (2)" },
    { id: "1".repeat(12), store: "firefox-container-custom", name: "Custom legacy label" },
    { id: "2".repeat(12), store: "firefox-container-unproven", name: "example-qa-data" },
  ];
  for (const entry of cases) {
    fixture.storageData[`accountContainer/${entry.id}`] = entry.store;
    fixture.storageData[`portalAccountOriginalName/${entry.id}`] = "example-qa-data";
    if (entry.id !== cases[2].id) fixture.storageData[`containerAccount/${entry.store}`] = entry.id;
    fixture.identities.push({ name: entry.name, cookieStoreId: entry.store, color: "yellow" });
  }
  await loadBackground(fixture);
  await waitFor(() => fixture.identities[0].name === "data");
  assert.strictEqual(fixture.identities[1].name, "Custom legacy label");
  assert.strictEqual(fixture.identities[2].name, "example-qa-data");
  assert.strictEqual(fixture.storageData[`containerAccount/${cases[2].store}`], undefined);
});

test("invalid and empty-result rules restore the original container label safely", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  const onMessage = await loadBackground(fixture);
  await handoffSyntheticNamedAccount(onMessage, "example-dev-data");
  saveTestNamingRule(fixture, "^example-dev-", "");
  await waitFor(() => fixture.identities[0].name === "data");
  saveTestNamingRule(fixture, "[", "ignored");
  await waitFor(() => fixture.identities[0].name === "example-dev-data");
  saveTestNamingRule(fixture, "^.*$", "");
  await handoffSyntheticNamedAccount(onMessage, "example-dev-data");
  assert.strictEqual(fixture.identities[0].name, "example-dev-data");
});

test("helper launches format container and group labels while retaining source accounts and request identities", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = {
    ...fixture.storageData.config, mode: "backend",
    groupNamePattern: "^example-prod-", groupNameReplacement: "",
  };
  fixture.storageData.accountsCache = [{
    accountId: ACCOUNT_ID, accountName: "example-prod-helper", role: TEST_HELPER_ROLE,
  }];
  const accountsBefore = structuredClone(fixture.storageData.accountsCache);
  const pinsBefore = structuredClone(fixture.storageData.portalPinnedAccounts);
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url) { requests.push(new URL(url)); },
    async responseForRequest() {
      return { payload: {
        ok: true,
        containerUrl: `ext+container:name=Containoodle&url=${encodeURIComponent(BACKEND_SIGNIN_URL)}`,
      } };
    },
  });
  const result = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(result.ok, true);
  assert.strictEqual(fixture.identities[0].name, "helper");
  assert.strictEqual(fixture.identities[0].color, "red");
  const group = groupForAccount(fixture, ACCOUNT_ID, fixture.createdTabs[0].windowId);
  assert.strictEqual(group.title, "helper");
  assert.strictEqual(group.color, "red");
  const generate = requests.find((url) => url.pathname === "/generate-url");
  assert.ok(generate);
  assert.strictEqual(generate.searchParams.get("account"), ACCOUNT_ID);
  assert.strictEqual(generate.searchParams.get("role"), TEST_HELPER_ROLE);
  assert.deepStrictEqual(fixture.storageData.accountsCache, accountsBefore);
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, pinsBefore);
  const requestCount = requests.length;
  // An active container still has its original name if its helper list is absent.
  fixture.storageData.accountsCache = [];
  saveTestNamingRule(fixture, "^example-prod-", "Renamed: ");
  await waitFor(() => group.title === "Renamed: helper" &&
    fixture.identities[0].name === "Renamed: helper");
  assert.strictEqual(requests.length, requestCount, "cosmetic updates never authenticate or fetch accounts");
});

test("malformed helper cache and response cannot launch or fall back to portal pins", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  fixture.storageData.accountsCache = [
    { accountId: ACCOUNT_ID, accountName: "__CONTAINOODLE_TEST_ACCOUNT__" },
    { accountId: ACCOUNT_ID, accountName: "__CONTAINOODLE_TEST_DUPLICATE__" },
  ];
  const accountsBefore = structuredClone(fixture.storageData.accountsCache);
  const pinsBefore = structuredClone(fixture.storageData.portalPinnedAccounts);
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url) { requests.push(new URL(url).pathname); },
    async responseForRequest(url) {
      assert.strictEqual(url.pathname, "/accounts", "invalid accounts must not request roles or a sign-in URL");
      return { payload: accountsBefore };
    },
  });
  assert.deepStrictEqual(
    await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {}),
    { ok: false, error: "Account not found — check the backend account list" },
  );
  assert.deepStrictEqual(requests, ["/auth/challenge", "/accounts"]);
  assert.strictEqual(fixture.createdTabs.length, 0);
  assert.strictEqual(fixture.identities.length, 0);
  assert.deepStrictEqual(fixture.storageData.accountsCache, accountsBefore);
  assert.deepStrictEqual(fixture.storageData.portalPinnedAccounts, pinsBefore);
});

test("invalid helper cache cannot overwrite trusted automatic names", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = {
    ...fixture.storageData.config, mode: "backend",
    groupNamePattern: "^example-dev-", groupNameReplacement: "",
  };
  fixture.storageData.accountsCache = [{
    accountId: ACCOUNT_ID, accountName: "example-dev-stable", role: TEST_HELPER_ROLE,
  }];
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url) { requests.push(new URL(url).pathname); },
    async responseForRequest() {
      return { payload: {
        ok: true,
        containerUrl: `ext+container:name=Containoodle&url=${encodeURIComponent(BACKEND_SIGNIN_URL)}`,
      } };
    },
  });
  assert.strictEqual((await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {})).ok, true);
  const identity = fixture.identities[0];
  const group = groupForAccount(fixture, ACCOUNT_ID, fixture.createdTabs[0].windowId);
  const requestsBefore = requests.length;
  fixture.storageData.accountsCache = [{
    accountId: ACCOUNT_ID, accountName: "example-dev-invalid-cache", role: 42,
  }];
  const invalidCache = structuredClone(fixture.storageData.accountsCache);
  saveTestNamingRule(fixture, "^example-dev-", "Updated: ");
  await waitFor(() => identity.name === "Updated: stable" && group.title === "Updated: stable");
  assert.strictEqual(fixture.storageData[`containerOriginalName/${identity.cookieStoreId}`], "example-dev-stable");
  assert.deepStrictEqual(fixture.storageData.accountsCache, invalidCache);
  assert.strictEqual(requests.length, requestsBefore);
});

test("invalid helper cache cannot erase a legacy manual group title", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
  delete fixture.storageData["migration/groupTitlesAutomaticV1"];
  fixture.storageData.accountsCache = [{
    accountId: ACCOUNT_ID, accountName: "__CONTAINOODLE_TEST_MANUAL_TITLE__", role: 42,
  }];
  fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`] = "__CONTAINOODLE_TEST_MANUAL_TITLE__";
  await loadBackground(fixture);
  await waitFor(() => fixture.storageData["migration/groupTitlesAutomaticV1"] === true);
  assert.strictEqual(fixture.storageData[`tabGroupTitle/${ACCOUNT_ID}`], "__CONTAINOODLE_TEST_MANUAL_TITLE__");
});

test("a cosmetic container update failure leaves the proven container usable for launch", async () => {
  const fixture = makeBrowser();
  fixture.storageData.portalPinnedAccounts = [];
  const onMessage = await loadBackground(fixture);
  await handoffSyntheticNamedAccount(onMessage, "example-dev-data");
  const storeId = fixture.identities[0].cookieStoreId;
  fixture.browser.contextualIdentities.update = async () => {
    throw new Error("synthetic cosmetic update failure");
  };
  saveTestNamingRule(fixture, "^example-dev-", "");
  assert.deepStrictEqual(await handoffSyntheticNamedAccount(onMessage, "example-dev-data"), { ok: true });
  assert.strictEqual(fixture.identities.length, 1);
  assert.strictEqual(fixture.createdTabs.at(-1).cookieStoreId, storeId);
  assert.strictEqual(fixture.storageData[`accountContainer/${ACCOUNT_ID}`], storeId);
  assert.strictEqual(fixture.identities[0].name, "example-dev-data");
  assert.strictEqual(groupForAccount(fixture).title, "data");
});

test("queued container naming uses the latest mode and preserves a concurrent manual rename", async (t) => {
  for (const manualRename of [false, true]) {
    await t.test(manualRename ? "manual rename" : "automatic name", async () => {
      const fixture = makeBrowser();
      fixture.storageData.config = { ...fixture.storageData.config, mode: "backend" };
      fixture.storageData.accountsCache = [{ accountId: ACCOUNT_ID, accountName: "example-dev-helper" }];
      fixture.storageData.portalPinnedAccounts = [{ accountId: ACCOUNT_ID, accountName: "example-prod-portal" }];
      const storeId = "firefox-container-mode-test";
      fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
      fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
      fixture.identities.push({ name: "example-dev-helper", cookieStoreId: storeId, color: "green" });
      await loadBackground(fixture);
      let release;
      let entered;
      const paused = new Promise((resolve) => { entered = resolve; });
      const gate = new Promise((resolve) => { release = resolve; });
      const originalQuery = fixture.browser.contextualIdentities.query;
      let held = false;
      fixture.browser.contextualIdentities.query = async (query) => {
        if (query.name === "helper" && !held) {
          held = true;
          entered();
          await gate;
        }
        return originalQuery(query);
      };
      saveTestNamingRule(fixture, "^example-(?:dev|prod)-", "");
      await paused;
      const oldConfig = fixture.storageData.config;
      const newConfig = { ...oldConfig, mode: "portal", groupNameReplacement: "Latest: " };
      fixture.storageData.config = newConfig;
      if (manualRename) fixture.identities[0].name = "Concurrent custom label";
      for (const listener of fixture.events.storageChanged.listeners) {
        listener({ config: { oldValue: oldConfig, newValue: newConfig } }, "local");
      }
      release();
      await waitFor(() => fixture.storageData[`containerOriginalName/${storeId}`] === "example-prod-portal");
      assert.strictEqual(fixture.identities[0].name,
        manualRename ? "Concurrent custom label" : "Latest: portal");
      assert.strictEqual(fixture.identities[0].color, "green", "a cosmetic save does not recolor sessions");
      assert.strictEqual(fixture.createdTabs.length, 0);
      assert.strictEqual(fixture.cookieWrites.length, 0);
      assert.strictEqual(fixture.storageData[`accountContainer/${ACCOUNT_ID}`], storeId);
    });
  }
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
    () => currentSession(fixture)?.verified === true,
  );
  assert.strictEqual(currentSession(fixture).identityKey, TEST_SSO_IDENTITY);
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
    () => currentSession(fixture)?.verified === true,
  );
  assert.strictEqual(currentSession(fixture).identityKey, TEST_SSO_IDENTITY);
});

test("a verified helper session is reused on the next ordinary launch", async () => {
  const { fixture, onMessage, requests, result } = await launchFreshBackendForBinding();
  const storeId = fixture.createdTabs[0].cookieStoreId;
  addLiveConsoleCookies(fixture, storeId);
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, true);
  const again = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(again.ok, true);
  assert.strictEqual(generationRequestCount(requests), 1);
  assert.strictEqual(fixture.tabs.get(again.tabId).url, BACKEND_CONSOLE_URL);
});

test("legacy identity-only markers never authorize reuse, even for the current identity", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config.mode = "backend";
  fixture.storageData.accountsCache[0].role = TEST_HELPER_ROLE;
  const storeId = "firefox-container-__containoodle_test_legacy__";
  fixture.identities.push({ cookieStoreId: storeId, name: "__containoodle_test_account__", color: "red" });
  fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
  fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
  fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`] = TEST_SSO_IDENTITY;
  addLiveConsoleCookies(fixture, storeId);
  const onMessage = await loadBackground(fixture);
  const requests = [];
  globalThis.fetch = authenticatedBackendFetch({
    onRequest(url) { requests.push({ url }); },
    responseForRequest: backendSigninResponse,
  });
  const result = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(result.ok, true);
  assert.strictEqual(generationRequestCount(requests), 1);
  assert.strictEqual(fixture.tabs.get(result.tabId).url, BACKEND_SIGNIN_URL);
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.strictEqual(fixture.storageData[`backendContainerIdentity/${ACCOUNT_ID}`], TEST_SSO_IDENTITY);
});

test("a portal session invalidates helper ownership before copying cookies and prevents later reuse", async () => {
  const { fixture, onMessage, requests, result } = await launchFreshBackendForBinding();
  const storeId = fixture.tabs.get(result.tabId).cookieStoreId;
  addLiveConsoleCookies(fixture, storeId);
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  const helperGeneration = currentSession(fixture).generation;
  assert.strictEqual(currentSession(fixture).verified, true);
  const originalSetCookie = fixture.browser.cookies.set;
  let copied = false;
  fixture.browser.cookies.set = async (details) => {
    if (details.name === "x-amz-sso_authn") {
      copied = true;
      assert.strictEqual(currentSession(fixture).verified, false);
      assert.strictEqual(currentSession(fixture).mode, "portal");
      assert.notStrictEqual(currentSession(fixture).generation, helperGeneration);
    }
    return originalSetCookie(details);
  };
  await changeConnectionMode(fixture, "portal");
  const portal = await onMessage({
    type: "launch", accountId: ACCOUNT_ID, role: TEST_PORTAL_ROLE, mode: "portal",
  }, {});
  assert.strictEqual(portal.ok, true);
  assert.strictEqual(copied, true);
  await completeTabNavigation(fixture, portal.tabId, BACKEND_CONSOLE_URL);
  await changeConnectionMode(fixture, "backend");
  const backend = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(backend.ok, true);
  assert.strictEqual(generationRequestCount(requests), 2);
  assert.strictEqual(fixture.tabs.get(backend.tabId).url, BACKEND_SIGNIN_URL);
});

test("an old helper completion after a portal handoff cannot claim the portal session", async () => {
  const { fixture, onMessage, requests, result } = await launchFreshBackendForBinding();
  const storeId = fixture.tabs.get(result.tabId).cookieStoreId;
  addLiveConsoleCookies(fixture, storeId);
  await changeConnectionMode(fixture, "portal");
  const portal = await onMessage({
    type: "launch", accountId: ACCOUNT_ID, role: TEST_PORTAL_ROLE, mode: "portal",
  }, {});
  assert.strictEqual(portal.ok, true);
  await completeTabNavigation(fixture, portal.tabId, BACKEND_CONSOLE_URL);
  await changeConnectionMode(fixture, "backend");
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.strictEqual(currentSession(fixture).mode, "portal");
  const again = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(again.ok, true);
  assert.strictEqual(generationRequestCount(requests), 2);
});

test("overlapping helper and portal sign-ins cannot verify a newer session until older launches settle", async () => {
  const { fixture, onMessage, requests, result: older } = await launchFreshBackendForBinding();
  addLiveConsoleCookies(fixture, fixture.tabs.get(older.tabId).cookieStoreId);
  await changeConnectionMode(fixture, "portal");
  const portal = await onMessage({
    type: "launch", accountId: ACCOUNT_ID, role: TEST_PORTAL_ROLE, mode: "portal",
  }, {});
  assert.strictEqual(portal.ok, true);
  await changeConnectionMode(fixture, "backend");
  const newer = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(newer.ok, true);
  await completeTabNavigation(fixture, newer.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.strictEqual(currentSession(fixture).pending.length, 2);
  await completeTabNavigation(fixture, portal.tabId, BACKEND_CONSOLE_URL);
  await completeTabNavigation(fixture, older.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.deepStrictEqual(currentSession(fixture).pending, []);
  const clean = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(clean.ok, true);
  await completeTabNavigation(fixture, clean.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, true);
  assert.strictEqual(generationRequestCount(requests), 3);
  assert.strictEqual((await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {})).ok, true);
  assert.strictEqual(generationRequestCount(requests), 3);
});

test("portal invalidation serializes after an already in-flight helper verification write", async () => {
  const { fixture, onMessage, result } = await launchFreshBackendForBinding();
  const originalSet = fixture.browser.storage.local.set;
  let releaseWrite;
  const writeGate = new Promise((resolve) => { releaseWrite = resolve; });
  let writeStarted = false;
  fixture.browser.storage.local.set = async (values) => {
    if (Object.entries(values).some(([key, value]) =>
      key.startsWith("containerSession/") && value.verified === true)) {
      writeStarted = true;
      await writeGate;
    }
    return originalSet(values);
  };
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  await waitFor(() => writeStarted);
  await changeConnectionMode(fixture, "portal");
  let copied = false;
  const originalCookieSet = fixture.browser.cookies.set;
  fixture.browser.cookies.set = async (details) => {
    if (details.name === "x-amz-sso_authn") {
      copied = true;
      assert.strictEqual(currentSession(fixture).verified, false);
      assert.strictEqual(currentSession(fixture).mode, "portal");
    }
    return originalCookieSet(details);
  };
  const launchingPortal = onMessage({
    type: "launch", accountId: ACCOUNT_ID, role: TEST_PORTAL_ROLE, mode: "portal",
  }, {});
  await new Promise((resolve) => setImmediate(resolve));
  assert.strictEqual(copied, false, "cookie mutation must wait for the outstanding storage write");
  releaseWrite();
  assert.strictEqual((await launchingPortal).ok, true);
  assert.strictEqual(copied, true);
  assert.strictEqual(currentSession(fixture).verified, false);
  await changeConnectionMode(fixture, "backend");
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).mode, "portal");
  assert.strictEqual(currentSession(fixture).verified, false);
});

test("a loaded portal SPA remains a session transition until its later console navigation", async () => {
  const { fixture, onMessage, result } = await launchFreshBackendForBinding();
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  await changeConnectionMode(fixture, "portal");
  const portal = await onMessage({
    type: "launch", accountId: ACCOUNT_ID, role: TEST_PORTAL_ROLE, mode: "portal",
  }, {});
  assert.strictEqual(portal.ok, true);
  await completeTabNavigation(fixture, portal.tabId, fixture.tabs.get(portal.tabId).url);
  assert.strictEqual(currentSession(fixture).pending.length, 1);
  await changeConnectionMode(fixture, "backend");
  const backend = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(backend.ok, true);
  await completeTabNavigation(fixture, backend.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, false);
  await completeTabNavigation(fixture, portal.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.deepStrictEqual(currentSession(fixture).pending, []);
});

test("same-tab navigation during verification cannot publish or retire stale session ownership", async (t) => {
  for (const phase of ["ownership-read", "verification-write"]) {
    await t.test(phase, async () => {
      const { fixture, onMessage, requests, result } = await launchFreshBackendForBinding();
      addLiveConsoleCookies(fixture, fixture.tabs.get(result.tabId).cookieStoreId);
      let interrupted = false;
      const beginOtherSignin = () => {
        if (interrupted) return;
        interrupted = true;
        const tab = fixture.tabs.get(result.tabId);
        Object.assign(tab, { url: BACKEND_SIGNIN_URL, status: "loading" });
        for (const listener of fixture.events.tabsUpdated.listeners) {
          listener(tab.id, { url: tab.url, status: tab.status }, { ...tab });
        }
      };
      const originalGet = fixture.browser.storage.local.get;
      const originalSet = fixture.browser.storage.local.set;
      fixture.browser.storage.local.get = async (keys) => {
        const value = await originalGet(keys);
        if (phase === "ownership-read" && Array.isArray(keys) &&
          keys.length === 2 && keys[0] === `accountContainer/${ACCOUNT_ID}` &&
          keys[1].startsWith("containerAccount/")) beginOtherSignin();
        return value;
      };
      fixture.browser.storage.local.set = async (values) => {
        if (phase === "verification-write" && Object.entries(values).some(([key, value]) =>
          key.startsWith("containerSession/") && value.verified === true)) {
          beginOtherSignin();
        }
        return originalSet(values);
      };
      await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
      await waitFor(() => interrupted && currentSession(fixture).verified === false);
      assert.strictEqual(fixture.tabs.get(result.tabId).status, "loading");
      assert.strictEqual(currentSession(fixture).pending.length, 1,
        "the re-navigating tab must remain a tracked transition");
      await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(fixture).verified, false,
        "a later sign-in cannot inherit the retired helper verification");
      const again = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
      assert.strictEqual(again.ok, true);
      assert.strictEqual(generationRequestCount(requests), 2);
      assert.strictEqual(fixture.tabs.get(again.tabId).url, BACKEND_SIGNIN_URL);
    });
  }
});

test("session state storage failures prevent untracked sign-ins and clean up blank staging tabs", async (t) => {
  for (const failure of ["invalidation", "tab-record"]) {
    await t.test(failure, async () => {
      const fixture = makeBrowser();
      const onMessage = await loadBackground(fixture);
      const originalSet = fixture.browser.storage.local.set;
      fixture.browser.storage.local.set = async (values) => {
        if (Object.entries(values).some(([key, value]) =>
          key.startsWith("containerSession/") &&
          (failure === "invalidation" || value.pending.length > 0))) {
          throw new Error("__containoodle_test_storage_failure__");
        }
        return originalSet(values);
      };
      const result = await onMessage({
        type: "launch", accountId: ACCOUNT_ID, role: TEST_PORTAL_ROLE, mode: "portal",
      }, {});
      assert.deepStrictEqual(result, {
        ok: false, error: "Could not safely open the account session — try again",
      });
      assert.strictEqual(fixture.createdTabs.length, failure === "invalidation" ? 0 : 1);
      assert.ok(fixture.createdTabs.every((tab) => tab.url === "about:blank"));
      assert.strictEqual(fixture.tabs.size, 1, "only the existing source portal tab remains");
      if (failure === "invalidation") {
        assert.strictEqual(fixture.cookieWrites.length, 0);
        assert.strictEqual(fixture.cookieRemovals.length, 0);
      }
    });
  }
});

test("closing an older pending sign-in allows the newest completed helper session to verify", async () => {
  const { fixture, onMessage, result: older } = await launchFreshBackendForBinding();
  const newer = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(newer.ok, true);
  assert.strictEqual(currentSession(fixture).pending.length, 2);
  await removeTabWithEvent(fixture, older.tabId);
  await completeTabNavigation(fixture, newer.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, true);
  assert.deepStrictEqual(currentSession(fixture).pending, []);
});

test("session-changing navigation is recorded before it starts and cancels on a mode switch", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config.mode = "backend";
  fixture.storageData.accountsCache[0].role = TEST_HELPER_ROLE;
  const onMessage = await loadBackground(fixture);
  globalThis.fetch = authenticatedBackendFetch({ responseForRequest: backendSigninResponse });
  const originalUpdate = fixture.browser.tabs.update;
  fixture.browser.tabs.update = async (tabId, properties) => {
    if (properties.url === BACKEND_SIGNIN_URL) {
      const state = currentSession(fixture);
      assert.strictEqual(state.verified, false);
      assert.ok(state.pending.some((entry) => entry.tabId === tabId));
    }
    return originalUpdate(tabId, properties);
  };
  const first = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(first.ok, true);
  const createdBefore = fixture.createdTabs.length;
  fixture.beforeNextTabCreate(async (properties) => {
    assert.strictEqual(properties.url, "about:blank");
    await changeConnectionMode(fixture, "portal");
  });
  const cancelled = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
  assert.strictEqual(cancelled.cancelled, true);
  assert.strictEqual(fixture.createdTabs.length, createdBefore + 1);
  assert.strictEqual(fixture.createdTabs.at(-1).url, "about:blank");
  assert.strictEqual(fixture.tabs.has(fixture.createdTabs.at(-1).id), false);
});

test("background restart requires a fresh helper generation and cannot verify an earlier unfinished sign-in", async () => {
  for (const verifiedBeforeRestart of [true, false]) {
    const launched = await launchFreshBackendForBinding();
    const storeId = launched.fixture.tabs.get(launched.result.tabId).cookieStoreId;
    if (verifiedBeforeRestart) {
      await completeTabNavigation(launched.fixture, launched.result.tabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(launched.fixture).verified, true);
    }
    const fixture = makeBrowser(launched.fixture.storageData);
    fixture.identities.push(...structuredClone(launched.fixture.identities));
    for (const [id, tab] of launched.fixture.tabs) fixture.tabs.set(id, { ...tab });
    addLiveConsoleCookies(fixture, storeId);
    const onMessage = await loadBackground(fixture);
    const requests = [];
    globalThis.fetch = authenticatedBackendFetch({
      onRequest(url) { requests.push({ url }); },
      responseForRequest: backendSigninResponse,
    });
    if (!verifiedBeforeRestart) {
      await completeTabNavigation(fixture, launched.result.tabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(fixture).verified, false);
    }
    const result = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
    assert.strictEqual(result.ok, true);
    assert.strictEqual(generationRequestCount(requests), 1);
    assert.strictEqual(fixture.tabs.get(result.tabId).url, BACKEND_SIGNIN_URL);
  }
});

test("a failed verification rollback cannot lose an older sign-in fence, including after restart", async (t) => {
  for (const { restart, completedSigninPage } of [
    { restart: false, completedSigninPage: false },
    { restart: false, completedSigninPage: true },
    { restart: true, completedSigninPage: false },
    { restart: true, completedSigninPage: true },
  ]) {
    const label = `${restart ? "background restarted" : "same background"}: ${
      completedSigninPage ? "loaded retryable sign-in page" : "still loading"
    }`;
    await t.test(label, async () => {
      const launched = await launchFreshBackendForBinding();
      let { fixture, onMessage, requests } = launched;
      const oldTabId = launched.result.tabId;
      const storeId = fixture.tabs.get(oldTabId).cookieStoreId;
      const originalSet = fixture.browser.storage.local.set;
      let navigationStarted = false;
      let rollbackFailed = false;
      fixture.browser.storage.local.set = async (values) => {
        const changedState = values[`containerSession/${storeId}`];
        if (changedState?.verified === true && !navigationStarted) {
          navigationStarted = true;
          const tab = fixture.tabs.get(oldTabId);
          Object.assign(tab, { url: BACKEND_SIGNIN_URL, status: "loading" });
          for (const listener of fixture.events.tabsUpdated.listeners) {
            listener(tab.id, { url: tab.url, status: "loading" }, { ...tab });
          }
        } else if (navigationStarted && !rollbackFailed && changedState?.verified === false) {
          rollbackFailed = true;
          throw new Error("__containoodle_test_failed_corrective_write__");
        }
        return originalSet(values);
      };
      await completeTabNavigation(fixture, oldTabId, BACKEND_CONSOLE_URL);
      await waitFor(() => rollbackFailed);
      assert.strictEqual(currentSession(fixture).verified, true,
        "reproduce the failed durable correction, rather than hiding it with a retry");
      assert.deepStrictEqual(currentSession(fixture).pending, []);
      fixture.browser.storage.local.set = originalSet;
      if (completedSigninPage) {
        await completeTabNavigation(fixture, oldTabId, BACKEND_SIGNIN_URL);
        assert.strictEqual(fixture.tabs.get(oldTabId).status, "complete");
        assert.deepStrictEqual(currentSession(fixture).pending, [],
          "exercise runtime recovery after the persisted pending entry was lost");
      }
      if (restart) {
        const previous = fixture;
        fixture = makeBrowser(previous.storageData);
        fixture.identities.push(...structuredClone(previous.identities));
        for (const [id, tab] of previous.tabs) fixture.tabs.set(id, { ...tab });
        onMessage = await loadBackground(fixture);
        requests = [];
        globalThis.fetch = authenticatedBackendFetch({
          onRequest(url) { requests.push({ url }); },
          responseForRequest: backendSigninResponse,
        });
      }
      addLiveConsoleCookies(fixture, storeId);
      const generatedBefore = generationRequestCount(requests);
      const newer = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
      assert.strictEqual(newer.ok, true);
      assert.strictEqual(generationRequestCount(requests), generatedBefore + 1);
      assert.strictEqual(fixture.tabs.get(newer.tabId).url, BACKEND_SIGNIN_URL);
      assert.strictEqual(currentSession(fixture).pending.length, 2,
        "the older unresolved sign-in must be recovered before navigating the newer one");
      await completeTabNavigation(fixture, newer.tabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(fixture).verified, false);
      await completeTabNavigation(fixture, oldTabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(fixture).verified, false);
      assert.deepStrictEqual(currentSession(fixture).pending, []);
      const clean = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
      assert.strictEqual(clean.ok, true);
      await completeTabNavigation(fixture, clean.tabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(fixture).verified, true);
      assert.strictEqual((await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {})).ok, true);
      assert.strictEqual(generationRequestCount(requests), generatedBefore + 2);
    });
  }
});

test("malformed persisted session entries fall back to a normal helper sign-in", async (t) => {
  for (const pending of [[null], ["__containoodle_test_bad_entry__"], [[]], {}]) {
    await t.test(JSON.stringify(pending), async () => {
      const fixture = makeBrowser();
      fixture.storageData.config.mode = "backend";
      fixture.storageData.accountsCache[0].role = TEST_HELPER_ROLE;
      const storeId = "firefox-container-__containoodle_test_malformed__";
      fixture.identities.push({ cookieStoreId: storeId, name: "__containoodle_test_account__", color: "red" });
      fixture.storageData[`accountContainer/${ACCOUNT_ID}`] = storeId;
      fixture.storageData[`containerAccount/${storeId}`] = ACCOUNT_ID;
      fixture.storageData[`containerSession/${storeId}`] = {
        version: 1, generation: "__containoodle_test_invalid_generation__",
        accountId: ACCOUNT_ID, mode: "backend", identityKey: TEST_SSO_IDENTITY,
        verified: true, pending,
      };
      const onMessage = await loadBackground(fixture);
      globalThis.fetch = authenticatedBackendFetch({ responseForRequest: backendSigninResponse });
      const result = await onMessage({ type: "launch", accountId: ACCOUNT_ID, mode: "backend" }, {});
      assert.strictEqual(result.ok, true);
      assert.strictEqual(fixture.tabs.get(result.tabId).url, BACKEND_SIGNIN_URL);
      await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
      assert.strictEqual(currentSession(fixture).verified, true);
    });
  }
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
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.strictEqual(currentSession(fixture).pending.length, 1);
  await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  assert.strictEqual(currentSession(fixture).verified, false,
    "later manual browsing cannot retroactively verify a failed sign-in");

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
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.deepStrictEqual(currentSession(fixture).pending, []);

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
  const { fixture, result } = await launchFreshBackendForBinding();
  const nativeDateNow = Date.now;
  const expiredNow = nativeDateNow() + 120_001;
  Date.now = () => expiredNow;
  try {
    await completeTabNavigation(fixture, result.tabId, BACKEND_CONSOLE_URL);
  } finally {
    Date.now = nativeDateNow;
  }
  assert.strictEqual(currentSession(fixture).verified, false);
  assert.deepStrictEqual(currentSession(fixture).pending, []);
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
  assert.strictEqual(currentSession(fixture).verified, false);
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
  assert.strictEqual(currentSession(fixture).verified, false);
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
  await primeVerifiedHelperSession(fixture, onMessage);
  const originalGet = fixture.browser.storage.local.get;
  let replaced = false;
  fixture.browser.storage.local.get = async (keys) => {
    const stored = await originalGet(keys);
    if (keys === `containerSession/${storeId}` && !replaced) {
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
  await primeVerifiedHelperSession(fixture, onMessage);
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
      await primeVerifiedHelperSession(fixture, onMessage);
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
        if (lifecycle.eventName === "runtimeInstalled") {
          expected[ONBOARDING_KEY] = ONBOARDING_STATES.COMPLETE;
        }

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
          "lifecycle must initialize onboarding and remove only transient group IDs",
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

test("passive portal readiness never performs remote region discovery", async () => {
  const fixture = makeBrowser();
  fixture.storageData.config.ssoRegion = "";
  delete fixture.storageData.portalRegionCache;
  delete fixture.storageData.portalRegionCacheOrigin;
  const onMessage = await loadBackground(fixture);
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return new Response(JSON.stringify({ region: TEST_PORTAL_REGION }), {
      status: 200,
    });
  };

  const passive = await onMessage({
    type: "portal-readiness",
    allowRemoteRegionLookup: false,
  }, {});
  assert.strictEqual(passive.portalAccess, true);
  assert.strictEqual(passive.session, true);
  assert.strictEqual(passive.roleDiscoveryRegion, null);
  assert.strictEqual(passive.roleDiscoveryPermissionOrigin, null);
  assert.strictEqual(fetchCalls, 0);
  assert.strictEqual(fixture.storageData.portalRegionCache, undefined);

  const explicit = await onMessage({ type: "portal-readiness" }, {});
  assert.strictEqual(fetchCalls, 1);
  assert.strictEqual(explicit.roleDiscoveryRegion, TEST_PORTAL_REGION);
  assert.strictEqual(
    explicit.roleDiscoveryPermissionOrigin,
    TEST_ROLE_DISCOVERY_ORIGIN,
  );
  assert.strictEqual(
    fixture.storageData.portalRegionCacheOrigin,
    new URL(START).origin,
  );
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
