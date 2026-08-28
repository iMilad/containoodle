import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  BACKEND_AUTH_TOKEN_KEY,
  BACKEND_SSO_IDENTITY_KEY,
  BACKEND_SSO_PROFILE_KEY,
} from "../firefox-extension/shared/backend.js";
import {
  BACKEND_SESSION_REUSE_ORIGIN,
  LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
  LEGACY_ROLE_DISCOVERY_ORIGIN,
  roleDiscoveryOrigin,
} from "../firefox-extension/shared/permissions.js";

const OPTIONS_MODULE = new URL(
  "../firefox-extension/options/options.js",
  import.meta.url,
);

const SYNTHETIC_REGION = "xx-test-1";
const REPLACEMENT_SYNTHETIC_REGION = "yy-test-2";
const ROLE_DISCOVERY_ORIGINS = [roleDiscoveryOrigin(SYNTHETIC_REGION)];
const REPLACEMENT_ROLE_DISCOVERY_ORIGINS = [
  roleDiscoveryOrigin(REPLACEMENT_SYNTHETIC_REGION),
];
const LEGACY_ROLE_DISCOVERY_ORIGINS = [LEGACY_ROLE_DISCOVERY_ORIGIN];
const CONSOLE_ORIGINS = [BACKEND_SESSION_REUSE_ORIGIN];
const LEGACY_CONSOLE_ORIGINS = [LEGACY_BACKEND_SESSION_REUSE_ORIGIN];
const BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY =
  "backendSessionReuseAutoOfferHandled";
const TEST_EXTENSION_ORIGIN = "moz-extension://containoodle-test";
const SYNTHETIC_HELPER_TOKEN = `__CONTAINOODLE_TEST_${"0".repeat(23)}`;
const REPLACEMENT_SYNTHETIC_HELPER_TOKEN = `__CONTAINOODLE_TEST_${"4".repeat(23)}`;
const SYNTHETIC_PROFILE = "__CONTAINOODLE_TEST_PROFILE__";
const SYNTHETIC_IDENTITY_KEY = "0".repeat(64);
const PREVIOUS_SYNTHETIC_IDENTITY_KEY = "4".repeat(64);

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
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=";
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(bytes) {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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

let importSequence = 0;

const originalGlobals = Object.fromEntries(
  ["document", "browser", "fetch", "location", "window"].map((name) => [
    name,
    {
      exists: Object.prototype.hasOwnProperty.call(globalThis, name),
      value: globalThis[name],
    },
  ]),
);

class FakeElement {
  constructor(id) {
    this.id = id;
    this.value = "";
    this.textContent = "";
    this.className = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.dataset = {};
    this.attributes = new Map();
    this.controls = [];
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name);
  }

  querySelectorAll(selector) {
    if (selector === "button, input, textarea") return this.controls;
    return [];
  }

  async dispatch(type, event = {}) {
    for (const listener of this.listeners.get(type) ?? []) {
      await listener({ target: this, ...event });
    }
  }
}

function createEvent() {
  const listeners = [];
  return {
    get listenerCount() {
      return listeners.length;
    },
    addListener(listener) {
      listeners.push(listener);
    },
    async fire(...args) {
      for (const listener of listeners) await listener(...args);
    },
  };
}

function createDocument() {
  const ids = [
    "mode-backend",
    "mode-portal",
    "backend-panel",
    "portal-panel",
    "open-portal",
    "portal-refresh",
    "backend-url",
    "backend-token",
    "backend-token-status",
    "backend-sso-profile",
    "backend-save",
    "backend-refresh",
    "backend-status",
    "backend-accounts-status",
    "role-discovery-grant",
    "role-discovery-revoke",
    "role-discovery-status",
    "console-grant",
    "console-revoke",
    "console-status",
    "portal-url",
    "portal-save",
    "portal-status",
    "sso-region",
    "role-save",
    "role-settings-status",
    "group-name-pattern",
    "group-name-replacement",
    "group-name-save",
    "group-name-reset",
    "group-name-status",
    "portal-pins-status",
  ];

  const elements = new Map(ids.map((id) => [id, new FakeElement(id)]));
  const backendPanel = elements.get("backend-panel");
  const portalPanel = elements.get("portal-panel");

  elements.get("mode-backend").value = "backend";
  elements.get("mode-portal").value = "portal";

  backendPanel.dataset.modePanel = "backend";
  portalPanel.dataset.modePanel = "portal";
  portalPanel.hidden = true;

  backendPanel.controls = [
    "backend-url",
    "backend-token",
    "backend-sso-profile",
    "backend-save",
    "backend-refresh",
    "console-grant",
    "console-revoke",
  ].map((id) => elements.get(id));
  portalPanel.controls = [
    "open-portal",
    "portal-refresh",
    "portal-url",
    "portal-save",
    "role-discovery-grant",
    "role-discovery-revoke",
    "sso-region",
    "role-save",
  ].map((id) => elements.get(id));

  const document = {
    getElementById(id) {
      return elements.get(id) ?? null;
    },
    querySelectorAll(selector) {
      if (selector === "[data-mode-panel]") {
        return [backendPanel, portalPanel];
      }
      return [];
    },
  };

  return { document, elements };
}

function createFixture({
  config = {},
  granted = [],
  portalSession = true,
  storage = {},
} = {}) {
  const { document, elements } = createDocument();
  const permissionSet = new Set(granted);
  const permissionRequests = [];
  const permissionRemovals = [];
  const permissionCallOrder = [];
  const runtimeMessages = [];
  const fetchCalls = [];
  const storageSetCalls = [];
  const onAdded = createEvent();
  const onRemoved = createEvent();
  const cookiesChanged = createEvent();
  const storageChanged = createEvent();
  const windowEvents = new Map();
  const storageData = {
    config: {
      mode: "backend",
      backendUrl: "http://127.0.0.1:8765",
      portalStartUrl: "",
      ssoRegion: SYNTHETIC_REGION,
      defaultRole: "",
      groupNamePattern: "",
      groupNameReplacement: "",
      ...config,
    },
    [BACKEND_AUTH_TOKEN_KEY]: SYNTHETIC_HELPER_TOKEN,
    [BACKEND_SSO_PROFILE_KEY]: "",
    [BACKEND_SSO_IDENTITY_KEY]: PREVIOUS_SYNTHETIC_IDENTITY_KEY,
    [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: true,
    ...storage,
  };
  let sessionAvailable = portalSession;
  let readinessOverride = null;
  let permissionRequestAllowed = true;
  let permissionRequestError = null;
  let permissionRequestGate = null;
  let materializeCoveredPermissionRequest = true;
  let permissionRemovalFailureOrigin = null;
  let portalReadinessGate = null;
  let configWriteGate = null;
  let failNextStorageWrite = false;
  let failNextConfigWrite = false;
  let deferBackendFetch = false;
  let abortedFetches = 0;
  let resetGroupTitlesResult = { ok: true };
  let backendFetchStatus = 200;
  let backendFetchPayload = [];
  let backendIdentityStatus = 200;
  let backendIdentityPayload = {
    ok: true,
    identityKey: SYNTHETIC_IDENTITY_KEY,
  };
  let backendFetchError = null;
  let backendAuthFailure = null;
  let challengeSequence = 0;
  let helperToken = storageData[BACKEND_AUTH_TOKEN_KEY];

  const hasEffectiveOrigin = (requested) =>
    [...permissionSet].some((grantedOrigin) =>
      matchPatternCovers(grantedOrigin, requested)
    );

  function currentReadiness() {
    if (readinessOverride) return { ...readinessOverride };

    const portalStartUrl = storageData.config.portalStartUrl;
    const configured = Boolean(portalStartUrl);
    const portalOrigin = configured
      ? `${new URL(portalStartUrl).origin}/*`
      : null;
    const portalAccess = Boolean(portalOrigin && permissionSet.has(portalOrigin));
    const roleDiscoveryPermissionOrigin = configured && sessionAvailable
      ? roleDiscoveryOrigin(storageData.config.ssoRegion)
      : null;

    return {
      ok: true,
      mode: storageData.config.mode,
      configured,
      portalAccess,
      session: portalAccess && sessionAvailable,
      roleDiscoveryAccess: Boolean(
        roleDiscoveryPermissionOrigin &&
        hasEffectiveOrigin(roleDiscoveryPermissionOrigin)
      ),
      roleDiscoveryRegion: roleDiscoveryPermissionOrigin
        ? storageData.config.ssoRegion
        : null,
      roleDiscoveryPermissionOrigin,
      consoleAccess: CONSOLE_ORIGINS.every(hasEffectiveOrigin),
    };
  }

  const browser = {
    storage: {
      onChanged: storageChanged,
      local: {
        async get(keys) {
          if (typeof keys === "string") return { [keys]: storageData[keys] };
          if (Array.isArray(keys)) {
            return Object.fromEntries(keys.map((key) => [key, storageData[key]]));
          }
          return { ...storageData };
        },
        async set(values) {
          if (failNextStorageWrite) {
            failNextStorageWrite = false;
            throw new Error("simulated storage write failure");
          }
          if (values.config && configWriteGate) {
            const gate = configWriteGate;
            configWriteGate = null;
            await gate.promise;
          }
          if (values.config && failNextConfigWrite) {
            failNextConfigWrite = false;
            throw new Error("simulated config write failure");
          }
          storageSetCalls.push(structuredClone(values));
          Object.assign(storageData, values);
        },
        async remove(keys) {
          for (const key of Array.isArray(keys) ? keys : [keys]) {
            delete storageData[key];
          }
        },
      },
    },
    permissions: {
      onAdded,
      onRemoved,
      async getAll() {
        permissionCallOrder.push("getAll");
        return { origins: [...permissionSet] };
      },
      async contains({ origins }) {
        return origins.every(hasEffectiveOrigin);
      },
      async request({ origins }) {
        permissionCallOrder.push(`request:${origins.join(",")}`);
        permissionRequests.push([...origins]);
        if (permissionRequestGate) {
          const gate = permissionRequestGate;
          permissionRequestGate = null;
          await gate.promise;
        }
        if (permissionRequestError) {
          const error = permissionRequestError;
          permissionRequestError = null;
          throw error;
        }
        if (!permissionRequestAllowed) return false;
        if (
          materializeCoveredPermissionRequest ||
          !origins.every(hasEffectiveOrigin)
        ) {
          origins.forEach((origin) => permissionSet.add(origin));
        }
        return true;
      },
      async remove({ origins }) {
        permissionCallOrder.push(`remove:${origins.join(",")}`);
        permissionRemovals.push([...origins]);
        if (
          permissionRemovalFailureOrigin &&
          origins.includes(permissionRemovalFailureOrigin)
        ) {
          permissionRemovalFailureOrigin = null;
          throw new Error("simulated permission removal failure");
        }
        origins.forEach((origin) => permissionSet.delete(origin));
        return true;
      },
    },
    runtime: {
      async sendMessage(message) {
        runtimeMessages.push({ ...message });
        if (message.type === "portal-readiness") {
          if (portalReadinessGate) {
            const gate = portalReadinessGate;
            portalReadinessGate = null;
            await gate.promise;
            if (gate.error) throw gate.error;
          }
          return currentReadiness();
        }
        if (message.type === "open-portal") return { ok: true };
        if (message.type === "reset-group-titles") {
          return { ...resetGroupTitlesResult };
        }
        return { ok: true };
      },
    },
    cookies: {
      onChanged: cookiesChanged,
    },
  };

  async function fetch(url, options = {}) {
    const { signal } = options;
    fetchCalls.push({ url: String(url), options: { ...options } });
    if (backendFetchError) throw backendFetchError;
    const requestUrl = new URL(url);
    if (requestUrl.pathname === "/auth/challenge") {
      const challengeBytes = new Uint8Array(32);
      challengeBytes[31] = challengeSequence += 1;
      const challenge = encodeBase64Url(challengeBytes);
      const expiresAt = Date.now() + 30_000;
      const canonical = [
        "containoodle-server-v1",
        challenge,
        String(expiresAt),
        requestUrl.host,
        TEST_EXTENSION_ORIGIN,
      ].join("\n");
      const serverProof = backendAuthFailure === "server-proof"
        ? "0".repeat(64)
        : await hmacHex(helperToken, canonical);
      return new Response(JSON.stringify({
        version: 1,
        challenge,
        expiresAt,
        serverProof,
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (!deferBackendFetch) {
      const isIdentityRequest = requestUrl.pathname === "/sso-identity";
      const responseStatus = isIdentityRequest
        ? backendIdentityStatus
        : backendFetchStatus;
      const responsePayload = isIdentityRequest
        ? backendIdentityPayload
        : backendFetchPayload;
      const body = JSON.stringify(structuredClone(responsePayload));
      const challenge = new Headers(options.headers).get(
        "X-Containoodle-Challenge",
      );
      const target = `${requestUrl.pathname}${requestUrl.search}`;
      const canonical = [
        "containoodle-response-v1",
        challenge,
        String(responseStatus),
        target,
        await sha256Hex(body),
        requestUrl.host,
        TEST_EXTENSION_ORIGIN,
      ].join("\n");
      const responseProof = backendAuthFailure === "response-proof"
        ? "0".repeat(64)
        : await hmacHex(helperToken, canonical);
      return new Response(body, {
        status: responseStatus,
        headers: {
          "Content-Type": "application/json",
          "X-Containoodle-Response-Proof": responseProof,
        },
      });
    }
    return new Promise((resolve, reject) => {
      const abort = () => {
        abortedFetches += 1;
        const error = new Error("aborted");
        error.name = "AbortError";
        reject(error);
      };
      if (signal?.aborted) {
        abort();
        return;
      }
      signal?.addEventListener("abort", abort, { once: true });
      void resolve;
    });
  }

  const fakeWindow = {
    addEventListener(type, listener) {
      const listeners = windowEvents.get(type) ?? [];
      listeners.push(listener);
      windowEvents.set(type, listeners);
    },
    async fire(type) {
      for (const listener of windowEvents.get(type) ?? []) await listener();
    },
  };

  return {
    browser,
    document,
    elements,
    storageData,
    permissionRequests,
    permissionRemovals,
    permissionCallOrder,
    runtimeMessages,
    fetch,
    fetchCalls,
    storageSetCalls,
    fakeWindow,
    cookiesChanged,
    storageChanged,
    onAdded,
    onRemoved,
    setPortalSession(value) {
      sessionAvailable = value;
    },
    setReadiness(value) {
      readinessOverride = value;
    },
    setPermissionRequestAllowed(value) {
      permissionRequestAllowed = value;
    },
    setMaterializeCoveredPermissionRequest(value) {
      materializeCoveredPermissionRequest = value;
    },
    pauseNextPermissionRequest() {
      let release;
      const promise = new Promise((resolve) => { release = resolve; });
      permissionRequestGate = { promise, release };
      return release;
    },
    grantedOrigins() {
      return [...permissionSet];
    },
    failNextPermissionRequest(error = new Error("simulated permission request failure")) {
      permissionRequestError = error;
    },
    failPermissionRemovalFor(origin) {
      permissionRemovalFailureOrigin = origin;
    },
    pauseNextPortalReadiness(
      error = new Error("simulated stale portal readiness failure"),
    ) {
      let release;
      const promise = new Promise((resolve) => { release = resolve; });
      portalReadinessGate = { promise, release, error };
      return release;
    },
    pauseNextConfigWrite() {
      let release;
      const promise = new Promise((resolve) => { release = resolve; });
      configWriteGate = { promise, release };
      return release;
    },
    failFollowingConfigWrite() {
      failNextConfigWrite = true;
    },
    failFollowingStorageWrite() {
      failNextStorageWrite = true;
    },
    setDeferredBackendFetch(value) {
      deferBackendFetch = value;
    },
    setBackendFetchResponse(status, payload = []) {
      backendFetchStatus = status;
      backendFetchPayload = payload;
    },
    setBackendIdentityResponse(status, payload) {
      backendIdentityStatus = status;
      backendIdentityPayload = structuredClone(payload);
    },
    setBackendFetchError(error) {
      backendFetchError = error;
    },
    setBackendAuthFailure(value) {
      backendAuthFailure = value;
    },
    setHelperToken(value) {
      helperToken = value;
    },
    setResetGroupTitlesResult(value) {
      resetGroupTitlesResult = { ...value };
    },
    get abortedFetches() {
      return abortedFetches;
    },
  };
}

async function settle(turns = 20) {
  for (let index = 0; index < turns; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function waitFor(check, message, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.ok(check(), message);
}

async function waitForBackendRequest(fixture) {
  await waitFor(
    () =>
      !fixture.elements.get("backend-save").disabled &&
      !fixture.elements.get("backend-refresh").disabled,
    "backend request did not finish",
  );
}

async function loadOptions(fixture) {
  globalThis.document = fixture.document;
  globalThis.browser = fixture.browser;
  globalThis.fetch = fixture.fetch;
  globalThis.location = { origin: TEST_EXTENSION_ORIGIN };
  globalThis.window = fixture.fakeWindow;
  await import(`${OPTIONS_MODULE.href}?test=${importSequence += 1}`);
  await waitFor(
    () => fixture.onAdded.listenerCount === 1 && fixture.onRemoved.listenerCount === 1,
    "options initialization did not finish",
  );
}

function cleanupGlobals() {
  for (const [name, original] of Object.entries(originalGlobals)) {
    if (original.exists) globalThis[name] = original.value;
    else delete globalThis[name];
  }
}

function protectedFetchCalls(fixture) {
  return fixture.fetchCalls.filter(
    (call) => new URL(call.url).pathname !== "/auth/challenge",
  );
}

function assertNoRawHelperToken(call, ...tokens) {
  const headers = new Headers(call.options.headers);
  assert.equal(headers.has("Authorization"), false);
  const rendered = `${call.url}\n${[...headers].flat().join("\n")}`;
  for (const token of tokens) assert.doesNotMatch(rendered, new RegExp(token));
}

test("renders the active mode, switches live, and guards backend fetches in portal mode", async () => {
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    const backendPanel = fixture.elements.get("backend-panel");
    const portalPanel = fixture.elements.get("portal-panel");
    const backendMode = fixture.elements.get("mode-backend");
    const portalMode = fixture.elements.get("mode-portal");

    assert.equal(backendPanel.hidden, false);
    assert.equal(backendPanel.getAttribute("aria-hidden"), "false");
    assert.equal(portalPanel.hidden, true);
    assert.equal(portalPanel.getAttribute("aria-hidden"), "true");
    assert.equal(fixture.elements.get("portal-save").disabled, true);

    // Hidden portal actions are inert while backend mode is active.
    fixture.elements.get("portal-url").value =
      "https://d-1234567890.awsapps.com/start";
    await fixture.elements.get("portal-save").dispatch("click");
    await fixture.elements.get("open-portal").dispatch("click");
    await settle();
    assert.deepEqual(fixture.permissionRequests, []);
    assert.deepEqual(fixture.runtimeMessages, []);

    backendMode.checked = false;
    portalMode.checked = true;
    await portalMode.dispatch("change");
    await settle();

    assert.equal(fixture.storageData.config.mode, "portal");
    assert.equal(backendPanel.hidden, true);
    assert.equal(portalPanel.hidden, false);
    assert.equal(fixture.elements.get("backend-save").disabled, true);
    assert.equal(fixture.elements.get("portal-save").disabled, false);

    // Invoke a stale backend handler directly: the mode guard must still stop I/O.
    await fixture.elements.get("backend-save").dispatch("click");
    assert.deepEqual(fixture.fetchCalls, []);
  } finally {
    cleanupGlobals();
  }
});

test("portal settings report only portal-pinned accounts", async () => {
  const fixture = createFixture({
    config: { mode: "portal" },
    storage: {
      accountsCache: [
        { accountId: "111111111111", accountName: "backend-only" },
        { accountId: "222222222222", accountName: "also-backend-only" },
      ],
      portalPinnedAccounts: [
        { accountId: "333333333333", accountName: "portal-pinned" },
      ],
    },
  });
  try {
    await loadOptions(fixture);

    assert.equal(
      fixture.elements.get("portal-pins-status").textContent,
      "1 pinned account available in the sidebar",
    );

    fixture.storageData.portalPinnedAccounts.push({
      accountId: "444444444444",
      accountName: "second-pin",
    });
    await fixture.storageChanged.fire(
      { portalPinnedAccounts: { newValue: fixture.storageData.portalPinnedAccounts } },
      "local",
    );
    await settle();

    assert.equal(
      fixture.elements.get("portal-pins-status").textContent,
      "2 pinned accounts available in the sidebar",
    );
  } finally {
    cleanupGlobals();
  }
});

test("open portal identifies the portal mode to the background", async () => {
  const start = "https://d-4444444444.awsapps.com/start";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl: start },
    granted: ["https://d-4444444444.awsapps.com/*"],
  });
  try {
    await loadOptions(fixture);
    await fixture.elements.get("open-portal").dispatch("click");
    await settle();

    assert.deepEqual(
      fixture.runtimeMessages.filter(
        (message) => message.type === "open-portal",
      ),
      [{ type: "open-portal", mode: "portal" }],
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend refresh marks its cache as backend-owned", async () => {
  const fixture = createFixture({
    storage: {
      accountsCacheSource: "manual",
    },
  });
  try {
    await loadOptions(fixture);
    await fixture.elements.get("backend-refresh").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.deepEqual(fixture.storageData.accountsCache, []);
    assert.equal(fixture.storageData.accountsCacheSource, "backend");
    assert.equal(fixture.fetchCalls.length, 2);
    assert.equal(protectedFetchCalls(fixture).length, 1);
    for (const call of fixture.fetchCalls) {
      assertNoRawHelperToken(call, SYNTHETIC_HELPER_TOKEN);
    }
  } finally {
    cleanupGlobals();
  }
});

test("backend save tests a replacement token before storing URL and token", async () => {
  const previousUrl = "http://127.0.0.1:8765";
  const nextUrl = "http://127.0.0.1:8877";
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    fixture.setHelperToken(REPLACEMENT_SYNTHETIC_HELPER_TOKEN);
    fixture.elements.get("backend-url").value = nextUrl;
    fixture.elements.get("backend-token").value = REPLACEMENT_SYNTHETIC_HELPER_TOKEN;
    fixture.elements.get("backend-sso-profile").value = `  ${SYNTHETIC_PROFILE}  `;
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.equal(fixture.fetchCalls.length, 4);
    const protectedCalls = protectedFetchCalls(fixture);
    assert.deepEqual(
      protectedCalls.map((call) => call.url),
      [
        `${nextUrl}/sso-identity?profile=${SYNTHETIC_PROFILE}`,
        `${nextUrl}/accounts`,
      ],
    );
    for (const call of fixture.fetchCalls) {
      assertNoRawHelperToken(
        call,
        SYNTHETIC_HELPER_TOKEN,
        REPLACEMENT_SYNTHETIC_HELPER_TOKEN,
      );
    }
    assert.notEqual(previousUrl, nextUrl);
    assert.equal(fixture.storageData.config.backendUrl, nextUrl);
    assert.equal(
      fixture.storageData[BACKEND_AUTH_TOKEN_KEY],
      REPLACEMENT_SYNTHETIC_HELPER_TOKEN,
    );
    assert.equal(
      fixture.storageData[BACKEND_SSO_PROFILE_KEY],
      SYNTHETIC_PROFILE,
    );
    assert.equal(
      fixture.storageData[BACKEND_SSO_IDENTITY_KEY],
      SYNTHETIC_IDENTITY_KEY,
    );
    const [connectionWrite] = fixture.storageSetCalls.filter(
      (values) => Object.hasOwn(values, BACKEND_SSO_IDENTITY_KEY),
    );
    assert.ok(connectionWrite);
    assert.deepEqual(
      Object.keys(connectionWrite).sort(),
      [
        BACKEND_AUTH_TOKEN_KEY,
        BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY,
        BACKEND_SSO_IDENTITY_KEY,
        BACKEND_SSO_PROFILE_KEY,
        "accountsCache",
        "accountsCacheAt",
        "accountsCacheSource",
        "config",
      ].sort(),
    );
    assert.equal(fixture.elements.get("backend-token").value, "");
    assert.equal(
      fixture.elements.get("backend-sso-profile").value,
      SYNTHETIC_PROFILE,
    );
    assert.equal(
      fixture.elements.get("backend-token").getAttribute("aria-invalid"),
      "false",
    );
    assert.equal(
      fixture.elements.get("backend-token-status").textContent,
      "A helper access token is stored",
    );
    assert.doesNotMatch(
      fixture.elements.get("backend-status").textContent,
      /__CONTAINOODLE_TEST_/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend save can explicitly replace a stored profile with automatic selection", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_SSO_PROFILE_KEY]: SYNTHETIC_PROFILE },
  });
  try {
    await loadOptions(fixture);
    assert.equal(
      fixture.elements.get("backend-sso-profile").value,
      SYNTHETIC_PROFILE,
    );

    fixture.elements.get("backend-sso-profile").value = "   ";
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.deepEqual(
      protectedFetchCalls(fixture).map((call) => call.url),
      [
        "http://127.0.0.1:8765/sso-identity",
        "http://127.0.0.1:8765/accounts",
      ],
    );
    assert.equal(fixture.storageData[BACKEND_SSO_PROFILE_KEY], "");
    assert.equal(
      fixture.storageData[BACKEND_SSO_IDENTITY_KEY],
      SYNTHETIC_IDENTITY_KEY,
    );
    assert.equal(fixture.elements.get("backend-sso-profile").value, "");
  } finally {
    cleanupGlobals();
  }
});

test("backend save rejects an invalid profile locally and preserves saved state", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_SSO_PROFILE_KEY]: SYNTHETIC_PROFILE },
  });
  const before = structuredClone(fixture.storageData);
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    fixture.elements.get("backend-sso-profile").value = `${SYNTHETIC_PROFILE}\n`;
    await fixture.elements.get("backend-save").dispatch("click");

    assert.deepEqual(fixture.fetchCalls, []);
    assert.deepEqual(fixture.storageData, before);
    assert.equal(
      fixture.elements.get("backend-sso-profile").getAttribute("aria-invalid"),
      "true",
    );
    assert.match(
      fixture.elements.get("backend-status").textContent,
      /AWS CLI profile/,
    );
    assert.doesNotMatch(
      fixture.elements.get("backend-status").textContent,
      /__CONTAINOODLE_TEST_PROFILE__/,
    );

    await fixture.elements.get("backend-sso-profile").dispatch("input");
    assert.equal(
      fixture.elements.get("backend-sso-profile").getAttribute("aria-invalid"),
      "false",
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend save accepts only the exact safe SSO identity payload", async () => {
  const malformedPayloads = [
    null,
    [],
    { ok: false, identityKey: SYNTHETIC_IDENTITY_KEY },
    { ok: true, identityKey: "A".repeat(64) },
    { ok: true, identityKey: SYNTHETIC_IDENTITY_KEY, extra: true },
    { identityKey: SYNTHETIC_IDENTITY_KEY },
  ];

  for (const payload of malformedPayloads) {
    const fixture = createFixture({
      storage: {
        [BACKEND_SSO_PROFILE_KEY]: SYNTHETIC_PROFILE,
        accountsCache: [],
        accountsCacheAt: 1,
        accountsCacheSource: "backend",
      },
    });
    const before = structuredClone(fixture.storageData);
    try {
      fixture.setBackendIdentityResponse(200, payload);
      await loadOptions(fixture);
      fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
      await fixture.elements.get("backend-save").dispatch("click");
      await waitForBackendRequest(fixture);

      assert.deepEqual(fixture.storageData, before);
      assert.deepEqual(
        protectedFetchCalls(fixture).map((call) => call.url),
        [
          `http://127.0.0.1:8877/sso-identity?profile=${SYNTHETIC_PROFILE}`,
        ],
      );
      assert.equal(
        fixture.elements.get("backend-status").textContent,
        "Local helper returned an unexpected response",
      );
    } finally {
      cleanupGlobals();
    }
  }
});

test("backend save shows only a simple actionable SSO identity error", async () => {
  const actionableError =
    "Multiple valid SSO sessions are available; enter an AWS CLI profile";
  const fixture = createFixture({
    storage: { [BACKEND_SSO_PROFILE_KEY]: SYNTHETIC_PROFILE },
  });
  const before = structuredClone(fixture.storageData);
  fixture.setBackendIdentityResponse(409, { error: actionableError });
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.deepEqual(fixture.storageData, before);
    assert.equal(
      fixture.elements.get("backend-status").textContent,
      actionableError,
    );
    assert.deepEqual(
      protectedFetchCalls(fixture).map((call) => call.url),
      [
        `http://127.0.0.1:8877/sso-identity?profile=${SYNTHETIC_PROFILE}`,
      ],
    );
  } finally {
    cleanupGlobals();
  }

  const malformed = createFixture();
  malformed.setBackendIdentityResponse(409, {
    error: "synthetic line one\nsynthetic line two",
    extra: true,
  });
  try {
    await loadOptions(malformed);
    await malformed.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(malformed);

    assert.equal(
      malformed.elements.get("backend-status").textContent,
      "Local helper returned HTTP 409",
    );
  } finally {
    cleanupGlobals();
  }
});

test("an accounts failure after identity authentication preserves every saved connection value", async () => {
  const previousAccounts = [{
    accountId: "000000000000",
    accountName: "__CONTAINOODLE_TEST_ACCOUNT__",
  }];
  const fixture = createFixture({
    storage: {
      [BACKEND_SSO_PROFILE_KEY]: SYNTHETIC_PROFILE,
      accountsCache: previousAccounts,
      accountsCacheAt: 1,
      accountsCacheSource: "backend",
    },
  });
  const before = structuredClone(fixture.storageData);
  fixture.setBackendFetchResponse(503, { error: "__CONTAINOODLE_TEST_ERROR__" });
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    fixture.elements.get("backend-sso-profile").value = "";
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.deepEqual(fixture.storageData, before);
    assert.deepEqual(
      protectedFetchCalls(fixture).map((call) => call.url),
      [
        "http://127.0.0.1:8877/sso-identity",
        "http://127.0.0.1:8877/accounts",
      ],
    );
    assert.equal(
      fixture.elements.get("backend-status").textContent,
      "Local helper returned HTTP 503",
    );
    assert.doesNotMatch(
      fixture.elements.get("backend-status").textContent,
      /__CONTAINOODLE_TEST_/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend setup reports a stored token without copying it into the page", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_SSO_PROFILE_KEY]: SYNTHETIC_PROFILE },
  });
  try {
    await loadOptions(fixture);

    assert.equal(fixture.elements.get("backend-token").value, "");
    assert.equal(
      fixture.elements.get("backend-sso-profile").value,
      SYNTHETIC_PROFILE,
    );
    assert.equal(
      fixture.elements.get("backend-token-status").textContent,
      "A helper access token is stored",
    );
    assert.equal(
      [...fixture.elements.values()].some((element) =>
        element.textContent.includes(SYNTHETIC_HELPER_TOKEN)
      ),
      false,
    );

    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);
    assert.equal(protectedFetchCalls(fixture).length, 2);
    for (const call of fixture.fetchCalls) {
      assertNoRawHelperToken(call, SYNTHETIC_HELPER_TOKEN);
    }
  } finally {
    cleanupGlobals();
  }
});

test("first backend Save & test offers session reuse synchronously without blocking helper setup", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: undefined },
  });
  fixture.setPermissionRequestAllowed(false);
  try {
    await loadOptions(fixture);

    await fixture.elements.get("backend-save").dispatch("click");
    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);
    assert.equal(
      fixture.storageData[BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY],
      true,
    );

    await waitForBackendRequest(fixture);
    assert.match(
      fixture.elements.get("backend-status").textContent,
      /Connected to local helper/,
    );
    assert.match(
      fixture.elements.get("console-status").textContent,
      /declined/,
    );

    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);
    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);
  } finally {
    cleanupGlobals();
  }
});

test("session reuse auto-offer errors and marker write failures do not block helper setup or reprompt", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: undefined },
  });
  fixture.failFollowingStorageWrite();
  fixture.failNextPermissionRequest();
  let persistedStorage;
  try {
    await loadOptions(fixture);

    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);
    assert.equal(
      fixture.storageData[BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY],
      true,
    );
    assert.match(
      fixture.elements.get("backend-status").textContent,
      /Connected to local helper/,
    );
    assert.match(
      fixture.elements.get("console-status").textContent,
      /simulated permission request failure/,
    );

    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);
    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);
    persistedStorage = structuredClone(fixture.storageData);
  } finally {
    cleanupGlobals();
  }

  const reloaded = createFixture({ storage: persistedStorage });
  try {
    await loadOptions(reloaded);
    await reloaded.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(reloaded);

    assert.deepEqual(reloaded.permissionRequests, []);
    assert.match(
      reloaded.elements.get("backend-status").textContent,
      /Connected to local helper/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("accepted session reuse is not auto-offered again after revoke, while manual Allow can re-request", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: undefined },
  });
  try {
    await loadOptions(fixture);

    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);
    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);
    assert.match(fixture.elements.get("console-status").textContent, /Enabled/);

    await fixture.elements.get("console-revoke").dispatch("click");
    await settle();
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);
    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);

    await fixture.elements.get("console-grant").dispatch("click");
    await settle();
    assert.deepEqual(fixture.permissionRequests, [
      CONSOLE_ORIGINS,
      CONSOLE_ORIGINS,
    ]);
  } finally {
    cleanupGlobals();
  }
});

test("a remembered auto-offer decision survives reload and an existing grant records the marker", async () => {
  const remembered = createFixture();
  try {
    await loadOptions(remembered);
    await remembered.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(remembered);
    assert.deepEqual(remembered.permissionRequests, []);
  } finally {
    cleanupGlobals();
  }

  const alreadyGranted = createFixture({
    granted: CONSOLE_ORIGINS,
    storage: { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: undefined },
  });
  try {
    await loadOptions(alreadyGranted);
    assert.equal(
      alreadyGranted.storageData[BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY],
      true,
    );
    await alreadyGranted.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(alreadyGranted);
    assert.deepEqual(alreadyGranted.permissionRequests, []);
  } finally {
    cleanupGlobals();
  }
});

test("explicit legacy migration requests first, then removes broad access after literal proof", async () => {
  const fixture = createFixture({ granted: LEGACY_CONSOLE_ORIGINS });
  try {
    await loadOptions(fixture);
    assert.match(
      fixture.elements.get("console-status").textContent,
      /older broad access/,
    );
    assert.equal(fixture.elements.get("console-grant").textContent, "Tighten access");

    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("console-grant").dispatch("click");
    await waitFor(() => fixture.permissionRemovals.length === 1);

    assert.equal(
      fixture.permissionCallOrder[0],
      `request:${BACKEND_SESSION_REUSE_ORIGIN}`,
    );
    assert.deepEqual(fixture.permissionRequests, [CONSOLE_ORIGINS]);
    assert.deepEqual(fixture.permissionRemovals, [LEGACY_CONSOLE_ORIGINS]);
    assert.deepEqual(fixture.grantedOrigins(), CONSOLE_ORIGINS);
  } finally {
    cleanupGlobals();
  }
});

test("a covered request that stays broad preserves the working legacy grant", async () => {
  const fixture = createFixture({ granted: LEGACY_CONSOLE_ORIGINS });
  fixture.setMaterializeCoveredPermissionRequest(false);
  try {
    await loadOptions(fixture);
    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("console-grant").dispatch("click");
    await waitFor(() => /kept the older broad grant/.test(
      fixture.elements.get("console-status").textContent,
    ));

    assert.equal(
      fixture.permissionCallOrder[0],
      `request:${BACKEND_SESSION_REUSE_ORIGIN}`,
    );
    assert.deepEqual(fixture.permissionRemovals, []);
    assert.deepEqual(fixture.grantedOrigins(), LEGACY_CONSOLE_ORIGINS);
  } finally {
    cleanupGlobals();
  }
});

test("finish tightening removes a legacy grant without another prompt", async () => {
  const fixture = createFixture({
    granted: [...LEGACY_CONSOLE_ORIGINS, ...CONSOLE_ORIGINS],
  });
  try {
    await loadOptions(fixture);
    assert.equal(
      fixture.elements.get("console-grant").textContent,
      "Finish tightening",
    );
    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("console-grant").dispatch("click");
    await waitFor(() => fixture.permissionRemovals.length === 1);
    await waitFor(() => /repeated backend launches/.test(
      fixture.elements.get("console-status").textContent,
    ));

    assert.equal(fixture.permissionRequests.length, 0);
    assert.equal(fixture.permissionCallOrder[0], "getAll");
    assert.deepEqual(fixture.permissionRemovals, [LEGACY_CONSOLE_ORIGINS]);
    assert.deepEqual(fixture.grantedOrigins(), CONSOLE_ORIGINS);
  } finally {
    cleanupGlobals();
  }
});

test("a failed tightening cleanup preserves both working grants and reports the failure", async () => {
  const fixture = createFixture({
    granted: [...LEGACY_CONSOLE_ORIGINS, ...CONSOLE_ORIGINS],
  });
  fixture.failPermissionRemovalFor(LEGACY_BACKEND_SESSION_REUSE_ORIGIN);
  try {
    await loadOptions(fixture);
    await fixture.elements.get("console-grant").dispatch("click");
    await waitFor(() => /simulated permission removal failure/.test(
      fixture.elements.get("console-status").textContent,
    ));

    assert.deepEqual(
      fixture.grantedOrigins(),
      [...LEGACY_CONSOLE_ORIGINS, ...CONSOLE_ORIGINS],
    );
    assert.equal(
      fixture.elements.get("console-grant").textContent,
      "Finish tightening",
    );
  } finally {
    cleanupGlobals();
  }
});

test("a mode change rolls back only a newly accepted narrow grant", async () => {
  const fixture = createFixture();
  const releaseRequest = fixture.pauseNextPermissionRequest();
  try {
    await loadOptions(fixture);
    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("console-grant").dispatch("click");
    assert.equal(
      fixture.permissionCallOrder[0],
      `request:${BACKEND_SESSION_REUSE_ORIGIN}`,
    );

    const portalMode = fixture.elements.get("mode-portal");
    portalMode.checked = true;
    await portalMode.dispatch("change");
    await waitFor(() => fixture.storageData.config.mode === "portal");
    releaseRequest();
    await waitFor(() => fixture.permissionRemovals.length === 1);

    assert.deepEqual(fixture.permissionRemovals, [CONSOLE_ORIGINS]);
    assert.deepEqual(fixture.grantedOrigins(), []);
  } finally {
    cleanupGlobals();
  }
});

test("startup inspects but never migrates permissions", async () => {
  const fixture = createFixture({
    granted: [...LEGACY_CONSOLE_ORIGINS, ...CONSOLE_ORIGINS],
  });
  try {
    await loadOptions(fixture);
    assert.deepEqual(fixture.permissionRequests, []);
    assert.deepEqual(fixture.permissionRemovals, []);
    assert.deepEqual(
      fixture.grantedOrigins(),
      [...LEGACY_CONSOLE_ORIGINS, ...CONSOLE_ORIGINS],
    );
  } finally {
    cleanupGlobals();
  }
});

test("a stale backend Save & test click in portal mode cannot consume or trigger the auto-offer", async () => {
  const fixture = createFixture({
    config: { mode: "portal" },
    storage: { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: undefined },
  });
  try {
    await loadOptions(fixture);
    await fixture.elements.get("backend-save").dispatch("click");

    assert.deepEqual(fixture.permissionRequests, []);
    assert.equal(
      fixture.storageData[BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY],
      undefined,
    );
    assert.deepEqual(fixture.fetchCalls, []);
  } finally {
    cleanupGlobals();
  }
});

test("backend save with a rejected token preserves the working URL and token", async () => {
  const previousUrl = "http://127.0.0.1:8765";
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    fixture.elements.get("backend-token").value = REPLACEMENT_SYNTHETIC_HELPER_TOKEN;
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.equal(fixture.storageData.config.backendUrl, previousUrl);
    assert.equal(
      fixture.storageData[BACKEND_AUTH_TOKEN_KEY],
      SYNTHETIC_HELPER_TOKEN,
    );
    assert.equal(
      fixture.elements.get("backend-token-status").textContent,
      "The helper access token was rejected",
    );
    assert.equal(
      fixture.elements.get("backend-status").textContent,
      "Helper authentication failed",
    );
    assert.equal(
      fixture.elements.get("backend-token").getAttribute("aria-invalid"),
      "true",
    );
    assert.equal(fixture.fetchCalls.length, 1);
    assert.equal(new URL(fixture.fetchCalls[0].url).pathname, "/auth/challenge");
    assertNoRawHelperToken(
      fixture.fetchCalls[0],
      SYNTHETIC_HELPER_TOKEN,
      REPLACEMENT_SYNTHETIC_HELPER_TOKEN,
    );
    assert.doesNotMatch(
      fixture.elements.get("backend-status").textContent,
      /__CONTAINOODLE_TEST_/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend save rejects a malformed draft token before any request", async () => {
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    fixture.elements.get("backend-token").value = "__SYNTHETIC_INVALID_TOKEN__";
    await fixture.elements.get("backend-save").dispatch("click");

    assert.deepEqual(fixture.fetchCalls, []);
    assert.equal(fixture.storageData.config.backendUrl, "http://127.0.0.1:8765");
    assert.equal(
      fixture.storageData[BACKEND_AUTH_TOKEN_KEY],
      SYNTHETIC_HELPER_TOKEN,
    );
    assert.equal(
      fixture.elements.get("backend-token-status").textContent,
      "The helper access token is invalid",
    );
    assert.equal(
      fixture.elements.get("backend-token").getAttribute("aria-invalid"),
      "true",
    );
    await fixture.elements.get("backend-token").dispatch("input");
    assert.equal(
      fixture.elements.get("backend-token").getAttribute("aria-invalid"),
      "false",
    );
    assert.doesNotMatch(
      fixture.elements.get("backend-status").textContent,
      /__SYNTHETIC_INVALID_TOKEN__|__CONTAINOODLE_TEST_/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend save with an unreachable helper preserves the working settings", async () => {
  const fixture = createFixture();
  fixture.setBackendFetchError(new TypeError("synthetic network failure"));
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    fixture.elements.get("backend-token").value = REPLACEMENT_SYNTHETIC_HELPER_TOKEN;
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.equal(fixture.storageData.config.backendUrl, "http://127.0.0.1:8765");
    assert.equal(
      fixture.storageData[BACKEND_AUTH_TOKEN_KEY],
      SYNTHETIC_HELPER_TOKEN,
    );
    assert.equal(
      fixture.elements.get("backend-status").textContent,
      "Local helper is unreachable",
    );
    assert.doesNotMatch(
      fixture.elements.get("backend-status").textContent,
      /synthetic network failure|__CONTAINOODLE_TEST_/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend save preserves working settings when local storage rejects the commit", async () => {
  const fixture = createFixture();
  fixture.failFollowingConfigWrite();
  try {
    await loadOptions(fixture);
    fixture.setHelperToken(REPLACEMENT_SYNTHETIC_HELPER_TOKEN);
    fixture.elements.get("backend-url").value = "http://127.0.0.1:8877";
    fixture.elements.get("backend-token").value = REPLACEMENT_SYNTHETIC_HELPER_TOKEN;
    await fixture.elements.get("backend-save").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.equal(fixture.storageData.config.backendUrl, "http://127.0.0.1:8765");
    assert.equal(
      fixture.storageData[BACKEND_AUTH_TOKEN_KEY],
      SYNTHETIC_HELPER_TOKEN,
    );
    assert.equal(
      fixture.elements.get("backend-status").textContent,
      "Helper connected, but settings could not be saved",
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend refresh requires a stored token and never uses the draft field", async () => {
  const fixture = createFixture({
    storage: { [BACKEND_AUTH_TOKEN_KEY]: undefined },
  });
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-token").value = REPLACEMENT_SYNTHETIC_HELPER_TOKEN;
    await fixture.elements.get("backend-refresh").dispatch("click");
    await waitForBackendRequest(fixture);

    assert.deepEqual(fixture.fetchCalls, []);
    assert.equal(
      fixture.elements.get("backend-status").textContent,
      "Helper access token required",
    );
    assert.equal(fixture.storageData[BACKEND_AUTH_TOKEN_KEY], undefined);
  } finally {
    cleanupGlobals();
  }
});

test("portal mode never uses the stored helper token or calls the helper", async () => {
  const fixture = createFixture({ config: { mode: "portal" } });
  try {
    await loadOptions(fixture);

    assert.equal(fixture.elements.get("backend-token").value, "");
    await fixture.elements.get("backend-save").dispatch("click");
    await fixture.elements.get("backend-refresh").dispatch("click");
    assert.deepEqual(fixture.fetchCalls, []);
    assert.equal(
      fixture.storageData[BACKEND_AUTH_TOKEN_KEY],
      SYNTHETIC_HELPER_TOKEN,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend settings reject remote helper addresses without saving or fetching", async () => {
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    fixture.elements.get("backend-url").value = "https://example.invalid";
    await fixture.elements.get("backend-save").dispatch("click");

    assert.equal(
      fixture.storageData.config.backendUrl,
      "http://127.0.0.1:8765",
    );
    assert.deepEqual(fixture.fetchCalls, []);
    assert.match(
      fixture.elements.get("backend-status").textContent,
      /127\.0\.0\.1/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("portal core access requests only the normalized portal host", async () => {
  const fixture = createFixture({
    config: { mode: "portal" },
    storage: {
      portalRegionCache: "yy-test-2",
      portalRegionCacheOrigin: "https://d-9999999999.awsapps.com",
    },
  });
  try {
    await loadOptions(fixture);
    const portalUrl = fixture.elements.get("portal-url");
    portalUrl.value = "https://d-1234567890.awsapps.com/start/";
    await fixture.elements.get("portal-save").dispatch("click");
    await settle();

    assert.deepEqual(fixture.permissionRequests, [
      ["https://d-1234567890.awsapps.com/*"],
    ]);
    assert.equal(
      fixture.storageData.config.portalStartUrl,
      "https://d-1234567890.awsapps.com/start",
    );
    assert.equal(fixture.storageData.portalRegionCache, undefined);
    assert.equal(fixture.storageData.portalRegionCacheOrigin, undefined);
    assert.equal(
      fixture.permissionRequests[0].includes(ROLE_DISCOVERY_ORIGINS[0]),
      false,
    );
    assert.equal(
      fixture.permissionRequests[0].includes(CONSOLE_ORIGINS[0]),
      false,
    );
    assert.match(fixture.elements.get("portal-status").textContent, /source session detected/);
  } finally {
    cleanupGlobals();
  }
});

test("declined portal replacement preserves the existing portal configuration", async () => {
  const previous = "https://d-1111111111.awsapps.com/start";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl: previous },
    granted: ["https://d-1111111111.awsapps.com/*"],
  });
  fixture.setPermissionRequestAllowed(false);
  try {
    await loadOptions(fixture);
    fixture.elements.get("portal-url").value =
      "https://d-2222222222.awsapps.com/start";
    await fixture.elements.get("portal-save").dispatch("click");
    await settle();

    assert.equal(fixture.storageData.config.portalStartUrl, previous);
    assert.equal(fixture.elements.get("portal-url").value, previous);
    assert.deepEqual(fixture.permissionRequests, [
      ["https://d-2222222222.awsapps.com/*"],
    ]);
    assert.deepEqual(fixture.permissionRemovals, []);
    assert.match(
      fixture.elements.get("portal-status").textContent,
      /existing portal is unchanged/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("a first portal decline leaves no saved URL and reports that clearly", async () => {
  const fixture = createFixture({ config: { mode: "portal" } });
  fixture.setPermissionRequestAllowed(false);
  try {
    await loadOptions(fixture);
    fixture.elements.get("portal-url").value =
      "https://d-3333333333.awsapps.com/start";
    await fixture.elements.get("portal-save").dispatch("click");
    await settle();

    assert.equal(fixture.storageData.config.portalStartUrl, "");
    assert.equal(fixture.elements.get("portal-url").value, "");
    assert.match(
      fixture.elements.get("portal-status").textContent,
      /portal URL was not saved/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("portal replacement removes only the old origin and preserves pre-existing grants on rollback", async () => {
  const previous = "https://d-1111111111.awsapps.com/start";
  const previousOrigin = "https://d-1111111111.awsapps.com/*";
  const next = "https://d-2222222222.awsapps.com/start";
  const nextOrigin = "https://d-2222222222.awsapps.com/*";

  const success = createFixture({
    config: { mode: "portal", portalStartUrl: previous },
    granted: [previousOrigin],
  });
  try {
    await loadOptions(success);
    success.elements.get("portal-url").value = next;
    await success.elements.get("portal-save").dispatch("click");
    await settle();

    assert.equal(success.storageData.config.portalStartUrl, next);
    assert.deepEqual(success.permissionRemovals, [[previousOrigin]]);
  } finally {
    cleanupGlobals();
  }

  const removalFailure = createFixture({
    config: { mode: "portal", portalStartUrl: previous },
    granted: [previousOrigin],
  });
  try {
    await loadOptions(removalFailure);
    removalFailure.failPermissionRemovalFor(previousOrigin);
    removalFailure.elements.get("portal-url").value = next;
    await removalFailure.elements.get("portal-save").dispatch("click");
    await settle();

    assert.equal(removalFailure.storageData.config.portalStartUrl, previous);
    assert.equal(removalFailure.elements.get("portal-url").value, previous);
    assert.deepEqual(removalFailure.permissionRemovals, [
      [previousOrigin],
      [nextOrigin],
    ]);
    assert.match(
      removalFailure.elements.get("portal-status").textContent,
      /Could not save portal access/,
    );
  } finally {
    cleanupGlobals();
  }

  const rollback = createFixture({
    config: { mode: "portal", portalStartUrl: previous },
    granted: [previousOrigin, nextOrigin],
  });
  try {
    await loadOptions(rollback);
    rollback.failFollowingConfigWrite();
    rollback.elements.get("portal-url").value = next;
    await rollback.elements.get("portal-save").dispatch("click");
    await settle();

    assert.equal(rollback.storageData.config.portalStartUrl, previous);
    assert.equal(rollback.elements.get("portal-url").value, previous);
    assert.deepEqual(rollback.permissionRemovals, []);
    assert.match(rollback.elements.get("portal-status").textContent, /Could not save portal access/);
  } finally {
    cleanupGlobals();
  }
});

test("switching to portal cancels pending and in-flight backend work", async () => {
  const pendingSave = createFixture();
  try {
    await loadOptions(pendingSave);
    pendingSave.setDeferredBackendFetch(true);
    await pendingSave.elements.get("backend-save").dispatch("click");
    await waitFor(
      () => pendingSave.fetchCalls.length === 2,
      "backend save did not start its protected request",
    );
    assert.equal(pendingSave.fetchCalls.length, 2);

    const portalMode = pendingSave.elements.get("mode-portal");
    portalMode.checked = true;
    await portalMode.dispatch("change");
    await waitFor(
      () =>
        pendingSave.storageData.config.mode === "portal" &&
        pendingSave.abortedFetches === 1,
      "portal switch did not cancel the backend save",
    );

    assert.equal(pendingSave.storageData.config.mode, "portal");
    assert.equal(pendingSave.abortedFetches, 1);
    assert.equal(
      pendingSave.storageData[BACKEND_AUTH_TOKEN_KEY],
      SYNTHETIC_HELPER_TOKEN,
    );
  } finally {
    cleanupGlobals();
  }

  const inFlight = createFixture();
  try {
    await loadOptions(inFlight);
    inFlight.setDeferredBackendFetch(true);
    await inFlight.elements.get("backend-refresh").dispatch("click");
    await waitFor(
      () => inFlight.fetchCalls.length === 2,
      "backend refresh did not start its protected request",
    );
    assert.equal(inFlight.fetchCalls.length, 2);

    const portalMode = inFlight.elements.get("mode-portal");
    portalMode.checked = true;
    await portalMode.dispatch("change");
    await waitFor(
      () =>
        inFlight.storageData.config.mode === "portal" &&
        inFlight.abortedFetches === 1,
      "portal switch did not cancel the backend refresh",
    );

    assert.equal(inFlight.abortedFetches, 1);
    assert.equal(inFlight.storageData.config.mode, "portal");
    assert.equal(inFlight.storageData.accountsCache, undefined);
  } finally {
    cleanupGlobals();
  }
});

test("manual, cookie, and focus events refresh portal readiness", async () => {
  const start = "https://d-4444444444.awsapps.com/start";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl: start },
    granted: ["https://d-4444444444.awsapps.com/*"],
  });
  try {
    await loadOptions(fixture);
    const readinessCount = () => fixture.runtimeMessages.filter(
      (message) => message.type === "portal-readiness",
    ).length;
    let before = readinessCount();

    await fixture.elements.get("portal-refresh").dispatch("click");
    await settle();
    assert.equal(readinessCount(), before + 1);
    before = readinessCount();

    await fixture.cookiesChanged.fire({
      cookie: {
        name: "x-amz-sso_authn",
        storeId: "firefox-default",
      },
    });
    await settle();
    assert.equal(readinessCount(), before + 1);
    before = readinessCount();

    await fixture.fakeWindow.fire("focus");
    await settle();
    assert.equal(readinessCount(), before + 1);
  } finally {
    cleanupGlobals();
  }
});

test("a superseded readiness failure cannot overwrite the newest portal status", async () => {
  const portalStartUrl = "https://d-0000000000.awsapps.com/start";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl },
    granted: ["https://d-0000000000.awsapps.com/*"],
  });
  try {
    await loadOptions(fixture);
    const releaseStaleReadiness = fixture.pauseNextPortalReadiness();
    const readinessCount = () => fixture.runtimeMessages.filter(
      ({ type }) => type === "portal-readiness",
    ).length;
    const before = readinessCount();

    await fixture.elements.get("portal-refresh").dispatch("click");
    await waitFor(() => readinessCount() === before + 1);
    await fixture.elements.get("portal-refresh").dispatch("click");
    await waitFor(() => readinessCount() === before + 2);
    await waitFor(() => /source session detected/.test(
      fixture.elements.get("portal-status").textContent,
    ));

    releaseStaleReadiness();
    await settle();
    assert.match(
      fixture.elements.get("portal-status").textContent,
      /source session detected/,
    );
    assert.doesNotMatch(
      fixture.elements.get("portal-status").textContent,
      /stale portal readiness failure/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("role permission is never requested without a validated cached target", async () => {
  const fixture = createFixture({ config: { mode: "portal", ssoRegion: "" } });
  try {
    await loadOptions(fixture);
    await fixture.elements.get("role-discovery-grant").dispatch("click");
    await settle();
    assert.deepEqual(fixture.permissionRequests, []);
    assert.match(
      fixture.elements.get("role-discovery-status").textContent,
      /Sign in and refresh readiness/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("a stale regional role grant remains explicitly revocable without a current target", async () => {
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl: "", ssoRegion: "" },
    granted: REPLACEMENT_ROLE_DISCOVERY_ORIGINS,
  });
  try {
    await loadOptions(fixture);
    assert.equal(fixture.elements.get("role-discovery-revoke").disabled, false);
    assert.match(
      fixture.elements.get("role-discovery-status").textContent,
      /Existing role access is still granted/,
    );

    await fixture.elements.get("role-discovery-revoke").dispatch("click");
    await waitFor(() => fixture.permissionRemovals.length === 1);
    await settle();

    assert.deepEqual(
      fixture.permissionRemovals,
      [REPLACEMENT_ROLE_DISCOVERY_ORIGINS],
    );
    assert.deepEqual(fixture.grantedOrigins(), []);
  } finally {
    cleanupGlobals();
  }
});

test("role choices and session reuse permissions are isolated to their modes", async () => {
  const portalStartUrl = "https://d-0000000000.awsapps.com/start";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl },
    granted: ["https://d-0000000000.awsapps.com/*"],
  });
  try {
    await loadOptions(fixture);
    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("role-discovery-grant").dispatch("click");
    await settle();
    assert.equal(
      fixture.permissionCallOrder[0],
      `request:${ROLE_DISCOVERY_ORIGINS[0]}`,
    );
    await fixture.elements.get("role-discovery-revoke").dispatch("click");
    await settle();

    // A stale or scripted click cannot activate the hidden backend permission.
    await fixture.elements.get("console-grant").dispatch("click");
    await settle();
    assert.deepEqual(fixture.permissionRequests, [ROLE_DISCOVERY_ORIGINS]);

    fixture.elements.get("mode-portal").checked = false;
    fixture.elements.get("mode-backend").checked = true;
    await fixture.elements.get("mode-backend").dispatch("change");
    await settle();

    // The portal-only control is equally inert in backend mode.
    await fixture.elements.get("role-discovery-grant").dispatch("click");
    await settle();
    assert.deepEqual(fixture.permissionRequests, [ROLE_DISCOVERY_ORIGINS]);

    await fixture.elements.get("console-grant").dispatch("click");
    await settle();
    await fixture.elements.get("console-revoke").dispatch("click");
    await settle();

    assert.deepEqual(fixture.permissionRequests, [
      ROLE_DISCOVERY_ORIGINS,
      CONSOLE_ORIGINS,
    ]);
    assert.deepEqual(fixture.permissionRemovals, [
      ROLE_DISCOVERY_ORIGINS,
      CONSOLE_ORIGINS,
    ]);
  } finally {
    cleanupGlobals();
  }
});

test("explicit role migration requests the cached regional target before removing broad access", async () => {
  const portalStartUrl = "https://d-0000000000.awsapps.com/start";
  const portalOrigin = "https://d-0000000000.awsapps.com/*";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl },
    granted: [portalOrigin, ...LEGACY_ROLE_DISCOVERY_ORIGINS],
  });
  try {
    await loadOptions(fixture);
    assert.match(
      fixture.elements.get("role-discovery-status").textContent,
      /older broad access/,
    );

    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("role-discovery-grant").dispatch("click");
    await waitFor(() => fixture.permissionRemovals.length === 1);

    assert.equal(
      fixture.permissionCallOrder[0],
      `request:${ROLE_DISCOVERY_ORIGINS[0]}`,
    );
    assert.deepEqual(fixture.permissionRequests, [ROLE_DISCOVERY_ORIGINS]);
    assert.deepEqual(fixture.permissionRemovals, [LEGACY_ROLE_DISCOVERY_ORIGINS]);
    assert.deepEqual(
      fixture.grantedOrigins().sort(),
      [portalOrigin, ...ROLE_DISCOVERY_ORIGINS].sort(),
    );
  } finally {
    cleanupGlobals();
  }
});

test("a mode change rolls back a newly accepted regional role grant", async () => {
  const portalStartUrl = "https://d-0000000000.awsapps.com/start";
  const portalOrigin = "https://d-0000000000.awsapps.com/*";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl },
    granted: [portalOrigin],
  });
  const releaseRequest = fixture.pauseNextPermissionRequest();
  try {
    await loadOptions(fixture);
    fixture.permissionCallOrder.length = 0;
    await fixture.elements.get("role-discovery-grant").dispatch("click");
    assert.equal(
      fixture.permissionCallOrder[0],
      `request:${ROLE_DISCOVERY_ORIGINS[0]}`,
    );

    const backendMode = fixture.elements.get("mode-backend");
    backendMode.checked = true;
    await backendMode.dispatch("change");
    await waitFor(() => fixture.storageData.config.mode === "backend");
    releaseRequest();
    await waitFor(() => fixture.permissionRemovals.length === 1);

    assert.deepEqual(fixture.permissionRemovals, [ROLE_DISCOVERY_ORIGINS]);
    assert.deepEqual(fixture.grantedOrigins(), [portalOrigin]);
  } finally {
    cleanupGlobals();
  }
});

test("a same-mode region change cancels an older role grant without touching current access", async () => {
  const portalStartUrl = "https://d-0000000000.awsapps.com/start";
  const portalOrigin = "https://d-0000000000.awsapps.com/*";
  const fixture = createFixture({
    config: { mode: "portal", portalStartUrl },
    granted: [
      portalOrigin,
      ...LEGACY_ROLE_DISCOVERY_ORIGINS,
      ...REPLACEMENT_ROLE_DISCOVERY_ORIGINS,
    ],
  });
  const releaseRequest = fixture.pauseNextPermissionRequest();
  try {
    await loadOptions(fixture);
    await fixture.elements.get("role-discovery-grant").dispatch("click");
    assert.deepEqual(fixture.permissionRequests, [ROLE_DISCOVERY_ORIGINS]);

    fixture.elements.get("sso-region").value = REPLACEMENT_SYNTHETIC_REGION;
    await fixture.elements.get("role-save").dispatch("click");
    await waitFor(
      () => fixture.storageData.config.ssoRegion === REPLACEMENT_SYNTHETIC_REGION,
    );

    releaseRequest();
    await waitFor(() => fixture.permissionRemovals.length === 1);

    assert.deepEqual(fixture.permissionRemovals, [ROLE_DISCOVERY_ORIGINS]);
    assert.deepEqual(
      fixture.grantedOrigins().sort(),
      [
        portalOrigin,
        ...LEGACY_ROLE_DISCOVERY_ORIGINS,
        ...REPLACEMENT_ROLE_DISCOVERY_ORIGINS,
      ].sort(),
    );
  } finally {
    cleanupGlobals();
  }
});

test("portal readiness renders unconfigured, permission, session, and ready states", async () => {
  const fixture = createFixture({ config: { mode: "portal" } });
  fixture.setReadiness({
    ok: true,
    mode: "portal",
    configured: false,
    portalAccess: false,
    session: false,
    roleDiscoveryAccess: false,
    consoleAccess: false,
  });
  try {
    await loadOptions(fixture);
    const status = fixture.elements.get("portal-status");
    assert.equal(status.textContent, "Portal URL not configured");

    fixture.setReadiness({
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: false,
      session: false,
      roleDiscoveryAccess: false,
      consoleAccess: false,
    });
    await fixture.onAdded.fire({ origins: [] });
    await settle();
    assert.equal(
      status.textContent,
      "Portal URL saved · portal permission not granted",
    );

    fixture.setReadiness({
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: true,
      session: false,
      roleDiscoveryAccess: false,
      consoleAccess: false,
    });
    await fixture.onAdded.fire({ origins: [] });
    await settle();
    assert.equal(status.textContent, "Portal access granted · sign in required");

    fixture.setReadiness({
      ok: true,
      mode: "portal",
      configured: true,
      portalAccess: true,
      session: true,
      roleDiscoveryAccess: true,
      consoleAccess: true,
    });
    await fixture.onAdded.fire({ origins: [] });
    await settle();
    assert.equal(
      status.textContent,
      "Portal access and source session detected · each launch verifies its container copy",
    );
    assert.equal(status.className, "status ok");
  } finally {
    cleanupGlobals();
  }
});

test("loads saved tab-group naming options", async () => {
  const fixture = createFixture({
    config: {
      groupNamePattern: "^([^-]+)-.*$",
      groupNameReplacement: "$1",
    },
  });
  try {
    await loadOptions(fixture);

    assert.equal(
      fixture.elements.get("group-name-pattern").value,
      "^([^-]+)-.*$",
    );
    assert.equal(
      fixture.elements.get("group-name-replacement").value,
      "$1",
    );
  } finally {
    cleanupGlobals();
  }
});

test("saves a valid tab-group naming rule", async () => {
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    fixture.elements.get("group-name-pattern").value = "^(.+?)-(dev|prod)$";
    fixture.elements.get("group-name-replacement").value = "$1 [$2]";

    await fixture.elements.get("group-name-save").dispatch("click");
    await settle();

    assert.equal(
      fixture.storageData.config.groupNamePattern,
      "^(.+?)-(dev|prod)$",
    );
    assert.equal(
      fixture.storageData.config.groupNameReplacement,
      "$1 [$2]",
    );
    assert.equal(
      fixture.elements.get("group-name-status").textContent,
      "Tab group naming saved",
    );
    assert.equal(
      fixture.elements.get("group-name-status").className,
      "status ok",
    );
  } finally {
    cleanupGlobals();
  }
});

test("resets existing tab-group titles to automatic naming through the background", async () => {
  const fixture = createFixture();
  try {
    await loadOptions(fixture);
    await fixture.elements.get("group-name-reset").dispatch("click");
    await settle();

    assert.deepEqual(
      fixture.runtimeMessages.filter(
        (message) => message.type === "reset-group-titles",
      ),
      [{ type: "reset-group-titles" }],
    );
    assert.equal(
      fixture.elements.get("group-name-status").textContent,
      "Existing tab group titles reset to automatic naming",
    );
    assert.equal(
      fixture.elements.get("group-name-status").className,
      "status ok",
    );
  } finally {
    cleanupGlobals();
  }
});

test("reports a failed automatic-title reset", async () => {
  const fixture = createFixture();
  fixture.setResetGroupTitlesResult({
    ok: false,
    error: "Could not update one group",
  });
  try {
    await loadOptions(fixture);
    await fixture.elements.get("group-name-reset").dispatch("click");
    await settle();

    assert.equal(
      fixture.elements.get("group-name-status").textContent,
      "Could not update one group",
    );
    assert.equal(
      fixture.elements.get("group-name-status").className,
      "status error",
    );
  } finally {
    cleanupGlobals();
  }
});

test("rejects an invalid tab-group name regex without overwriting config", async () => {
  const existing = {
    groupNamePattern: "^([^-]+)-.*$",
    groupNameReplacement: "$1",
  };
  const fixture = createFixture({ config: existing });
  try {
    await loadOptions(fixture);
    fixture.elements.get("group-name-pattern").value = "([";
    fixture.elements.get("group-name-replacement").value = "invalid";

    await fixture.elements.get("group-name-save").dispatch("click");
    await settle();

    assert.equal(
      fixture.storageData.config.groupNamePattern,
      existing.groupNamePattern,
    );
    assert.equal(
      fixture.storageData.config.groupNameReplacement,
      existing.groupNameReplacement,
    );
    assert.match(
      fixture.elements.get("group-name-status").textContent,
      /Invalid name regex/,
    );
    assert.equal(
      fixture.elements.get("group-name-status").className,
      "status error",
    );
  } finally {
    cleanupGlobals();
  }
});

test("allows an empty tab-group pattern to disable name transformation", async () => {
  const fixture = createFixture({
    config: {
      groupNamePattern: "^([^-]+)-.*$",
      groupNameReplacement: "$1",
    },
  });
  try {
    await loadOptions(fixture);
    fixture.elements.get("group-name-pattern").value = "";
    fixture.elements.get("group-name-replacement").value = "unused";

    await fixture.elements.get("group-name-save").dispatch("click");
    await settle();

    assert.equal(fixture.storageData.config.groupNamePattern, "");
    assert.equal(
      fixture.elements.get("group-name-status").textContent,
      "Tab group naming saved",
    );
    assert.equal(
      fixture.elements.get("group-name-status").className,
      "status ok",
    );
  } finally {
    cleanupGlobals();
  }
});

test("options markup separates portal pins from backend session reuse", async () => {
  const html = await readFile(
    new URL("../firefox-extension/options/options.html", import.meta.url),
    "utf8",
  );
  const backendPanel = html.match(
    /<section\s+id="backend-panel"[\s\S]*?<\/section>/,
  );
  const portalPanel = html.match(
    /<section\s+id="portal-panel"[\s\S]*?<\/section>/,
  );

  assert.ok(backendPanel, "backend panel must remain present");
  assert.ok(portalPanel, "portal panel must remain present");
  assert.match(backendPanel[0], /id="console-permissions"/);
  assert.match(
    backendPanel[0],
    /type="password"[\s\S]*?id="backend-token"|id="backend-token"[\s\S]*?type="password"/,
  );
  assert.ok(
    backendPanel[0].indexOf('id="backend-url"') <
      backendPanel[0].indexOf('id="backend-token"') &&
      backendPanel[0].indexOf('id="backend-token"') <
      backendPanel[0].indexOf('id="backend-sso-profile"') &&
      backendPanel[0].indexOf('id="backend-sso-profile"') <
      backendPanel[0].indexOf('id="backend-save"'),
    "keyboard order must be helper URL, helper token, profile, then Save & test",
  );
  assert.doesNotMatch(backendPanel[0], /id="backend-token"[^>]*\svalue=/);
  assert.match(backendPanel[0], /id="backend-sso-profile"/);
  assert.match(backendPanel[0], /placeholder="__CONTAINOODLE_TEST_PROFILE__"/);
  assert.doesNotMatch(portalPanel[0], /id="console-permissions"/);
  assert.doesNotMatch(portalPanel[0], /id="backend-token"/);
  assert.match(portalPanel[0], /id="portal-pins-status"/);
  assert.doesNotMatch(html, /id="accounts-json"/);
  assert.doesNotMatch(html, /id="accounts-save"/);
  assert.doesNotMatch(html, /id="default-role"/);
  assert.match(html, /id="group-name-reset"/);
});
