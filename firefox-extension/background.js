/* ═══════════════════════════════════════════════════════════════════
   Containoodle — Background (event page)

   Owns launching in both modes so tab-grouping and container logic
   live in one place:
     backend mode → GET <backendUrl>/generate-url, open signin URL
     portal  mode → copy the portal session cookie (x-amz-sso_authn)
                    from the default store into the account's
                    container, then open the federation deep link
   Either way the tab lands in the account's container and tab group.
   ═══════════════════════════════════════════════════════════════════ */

import { accountEnv } from "./sidebar/env.js";
import {
  consoleDeepLink,
  portalCookieUrl,
  portalOriginPattern,
  whoAmIUrl,
  portalApiBase,
  unwrapResult,
  findAccountInstance,
  parsePortalConsoleDeepLink,
  isConfiguredPortalPage,
  canRemovePortalShortcutTab,
  planPortalTabHandoff,
} from "./shared/portal.js";
import { automaticGroupTitle } from "./shared/group-naming.js";
import {
  BACKEND_AUTH_TOKEN_KEY,
  BACKEND_SSO_IDENTITY_KEY,
  BACKEND_SSO_PROFILE_KEY,
  DEFAULT_BACKEND_URL,
  backendFetch,
  isBackendAuthenticationError,
  normalizeBackendSsoIdentityKey,
  normalizeBackendSsoProfile,
  normalizeBackendToken,
  safeBackendUrl,
  validateBackendSigninUrl,
} from "./shared/backend.js";

const DEFAULT_CONFIG = {
  mode: "backend",
  backendUrl: DEFAULT_BACKEND_URL,
  portalStartUrl: "",
  ssoRegion: "",
  groupNamePattern: "",
  groupNameReplacement: "",
};

const ENV_CONTAINER_COLOR = { prod: "red", qa: "yellow", dev: "green", test: "toolbar" };
const ENV_GROUP_COLOR = { prod: "red", qa: "yellow", dev: "green", test: "grey" };
const REGION_RE = /^[a-z]{2}-[a-z]+-\d$/;
const PORTAL_API_ORIGINS = ["https://*.amazonaws.com/*"];
const CONSOLE_ORIGINS = ["https://*.amazon.com/*"];
let storageMigrationPromise = null;
let connectionModeRevision = 0;

function ensureStorageMigration() {
  if (!storageMigrationPromise) {
    storageMigrationPromise = migrateLegacyStorage().catch(() => {
      storageMigrationPromise = null;
      return null;
    });
  }
  return storageMigrationPromise;
}

/* Deduplicate concurrent async calls that share a key (double-click
   on launch must not create two containers / two tab groups). */
function synchronize(fn) {
  const pending = new Map();
  return (key, ...args) => {
    let p = pending.get(key);
    if (!p) {
      p = fn(key, ...args).finally(() => pending.delete(key));
      pending.set(key, p);
    }
    return p;
  };
}

async function getConfig() {
  const { config } = await browser.storage.local.get("config");
  const merged = { ...DEFAULT_CONFIG, ...(config || {}) };
  merged.backendUrl = safeBackendUrl(merged.backendUrl);
  return merged;
}

async function getBackendAccounts() {
  const { accountsCache } = await browser.storage.local.get("accountsCache");
  return Array.isArray(accountsCache) ? accountsCache : [];
}

async function getBackendAuthToken() {
  const stored = await browser.storage.local.get(BACKEND_AUTH_TOKEN_KEY);
  try {
    return normalizeBackendToken(stored[BACKEND_AUTH_TOKEN_KEY]);
  } catch {
    const err = new Error("Local helper access token is missing or invalid");
    err.needsOptions = true;
    throw err;
  }
}

function backendAuthRejectedError() {
  const err = new Error("Local helper access token was rejected");
  err.needsOptions = true;
  return err;
}

function rethrowBackendAuthenticationError(err) {
  if (isBackendAuthenticationError(err)) throw backendAuthRejectedError();
  throw err;
}

function backendIdentityChangedError() {
  const err = new Error("Backend identity changed — try again");
  err.cancelled = true;
  return err;
}

function backendIdentityUrl(config, profile) {
  const url = new URL("/sso-identity", `${config.backendUrl}/`);
  if (profile) url.searchParams.set("profile", profile);
  return url.href;
}

function backendIdentityQuery(identity) {
  const query = new URLSearchParams();
  if (identity.profile) query.set("profile", identity.profile);
  query.set("identity", identity.identityKey);
  return query;
}

/* Authenticate the helper-selected SSO identity before any operation that
   can consume or reuse an AWS session. The returned key is opaque to the
   extension and scopes backend-only role/reuse state. */
async function authenticateBackendIdentity(config) {
  const stored = await browser.storage.local.get([
    BACKEND_AUTH_TOKEN_KEY,
    BACKEND_SSO_PROFILE_KEY,
    BACKEND_SSO_IDENTITY_KEY,
  ]);
  let token;
  let profile;
  try {
    token = normalizeBackendToken(stored[BACKEND_AUTH_TOKEN_KEY]);
  } catch {
    const missing = new Error("Local helper access token is missing or invalid");
    missing.needsOptions = true;
    throw missing;
  }
  try {
    profile = normalizeBackendSsoProfile(stored[BACKEND_SSO_PROFILE_KEY]);
  } catch (err) {
    const invalidProfile = new Error(err.message || "AWS CLI profile is invalid");
    invalidProfile.needsOptions = true;
    throw invalidProfile;
  }

  let res;
  try {
    res = await backendFetch(backendIdentityUrl(config, profile), token);
  } catch (err) {
    rethrowBackendAuthenticationError(err);
  }
  if (res.status === 401) throw backendAuthRejectedError();

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`Backend error (HTTP ${res.status})`);
  }
  if (!res.ok) {
    throw new Error(data?.error || `Backend error (HTTP ${res.status})`);
  }
  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    Object.keys(data).sort().join("\n") !== "identityKey\nok" ||
    data.ok !== true
  ) {
    throw new Error("Local helper returned an invalid SSO identity");
  }

  let identityKey;
  try {
    identityKey = normalizeBackendSsoIdentityKey(data.identityKey);
  } catch {
    throw new Error("Local helper returned an invalid SSO identity");
  }

  // Do not publish a response that belongs to credentials or a profile that
  // changed while the authenticated request was in flight.
  const latest = await browser.storage.local.get([
    "config",
    BACKEND_AUTH_TOKEN_KEY,
    BACKEND_SSO_PROFILE_KEY,
  ]);
  let latestToken;
  let latestProfile;
  try {
    latestToken = normalizeBackendToken(latest[BACKEND_AUTH_TOKEN_KEY]);
    latestProfile = normalizeBackendSsoProfile(latest[BACKEND_SSO_PROFILE_KEY]);
  } catch {
    throw backendIdentityChangedError();
  }
  const latestConfig = {
    ...DEFAULT_CONFIG,
    ...(latest.config || {}),
  };
  latestConfig.backendUrl = safeBackendUrl(latestConfig.backendUrl);
  if (
    latestConfig.mode !== "backend" ||
    latestConfig.backendUrl !== config.backendUrl ||
    latestToken !== token ||
    latestProfile !== profile
  ) {
    throw backendIdentityChangedError();
  }

  let previousIdentity = null;
  try {
    previousIdentity = normalizeBackendSsoIdentityKey(
      stored[BACKEND_SSO_IDENTITY_KEY]
    );
  } catch {
    // Missing/legacy state is replaced only after a trusted response.
  }
  if (previousIdentity !== identityKey) {
    await browser.storage.local.set({
      [BACKEND_SSO_IDENTITY_KEY]: identityKey,
    });
  }
  return {
    backendUrl: config.backendUrl,
    profile,
    identityKey,
    token,
  };
}

async function backendIdentityIsCurrent(identity) {
  const stored = await browser.storage.local.get([
    "config",
    BACKEND_AUTH_TOKEN_KEY,
    BACKEND_SSO_PROFILE_KEY,
    BACKEND_SSO_IDENTITY_KEY,
  ]);
  try {
    const config = {
      ...DEFAULT_CONFIG,
      ...(stored.config || {}),
    };
    config.backendUrl = safeBackendUrl(config.backendUrl);
    return (
      config.mode === "backend" &&
      config.backendUrl === identity.backendUrl &&
      normalizeBackendToken(stored[BACKEND_AUTH_TOKEN_KEY]) === identity.token &&
      normalizeBackendSsoProfile(stored[BACKEND_SSO_PROFILE_KEY]) === identity.profile &&
      normalizeBackendSsoIdentityKey(stored[BACKEND_SSO_IDENTITY_KEY]) ===
        identity.identityKey
    );
  } catch {
    return false;
  }
}

async function getPortalPinnedAccounts() {
  const { portalPinnedAccounts } = await browser.storage.local.get("portalPinnedAccounts");
  return Array.isArray(portalPinnedAccounts) ? portalPinnedAccounts : [];
}

async function getPortalHandoffAccounts() {
  const all = await browser.storage.local.get(null);
  const accounts = Array.isArray(all.portalPinnedAccounts)
    ? all.portalPinnedAccounts.filter((account) => account && typeof account === "object")
    : [];
  const knownIds = new Set(accounts.map((account) => String(account.accountId)));
  for (const [key, value] of Object.entries(all)) {
    const match = /^portalAccountOriginalName\/(\d{12})$/.exec(key);
    if (!match || knownIds.has(match[1]) || typeof value !== "string" || !value.trim()) {
      continue;
    }
    accounts.push({ accountId: match[1], accountName: value });
    knownIds.add(match[1]);
  }
  return accounts;
}

async function getStoredAccounts(config) {
  return config.mode === "portal"
    ? getPortalPinnedAccounts()
    : getBackendAccounts();
}

/* Register a document-start click interceptor only on the exact portal
   origin/path the user granted. It catches the user gesture before the
   portal can open an ordinary console tab; tabs events remain a fallback
   for portal implementations that do not expose a normal link. */
const PORTAL_INTERCEPTOR_ID = "containoodle-portal-clicks";

async function syncPortalInterceptorOnce() {
  const config = await getConfig();
  const allRegistered = await browser.scripting.getRegisteredContentScripts();
  const portalRegistrations = allRegistered.filter(
    (script) =>
      Array.isArray(script.js) &&
      script.js.includes("portal-interceptor.js")
  );
  const staleIds = portalRegistrations
    .filter((script) => script.id !== PORTAL_INTERCEPTOR_ID)
    .map((script) => script.id);
  if (staleIds.length > 0) {
    await browser.scripting.unregisterContentScripts({ ids: staleIds });
  }
  const registered = portalRegistrations.filter(
    (script) => script.id === PORTAL_INTERCEPTOR_ID
  );
  let shouldRegister = false;
  if (
    config.mode === "portal" &&
    config.portalStartUrl &&
    isConfiguredPortalPage(config.portalStartUrl, config.portalStartUrl)
  ) {
    shouldRegister = await browser.permissions.contains({
      origins: [portalOriginPattern(config.portalStartUrl)],
    });
  }
  if (!shouldRegister) {
    if (registered.length > 0) {
      await browser.scripting.unregisterContentScripts({ ids: [PORTAL_INTERCEPTOR_ID] });
    }
    return;
  }

  const start = new URL(config.portalStartUrl);
  const path = start.pathname.replace(/\/+$/, "") || "/";
  const matches = path === "/"
    ? [`${start.origin}/`]
    : [`${start.origin}${path}`, `${start.origin}${path}/`];
  const current = registered[0];
  const upToDate = Boolean(
    current &&
    Array.isArray(current.matches) &&
    current.matches.length === matches.length &&
    current.matches.every((value, index) => value === matches[index])
  );
  if (!upToDate) {
    if (registered.length > 0) {
      await browser.scripting.unregisterContentScripts({ ids: [PORTAL_INTERCEPTOR_ID] });
    }
    await browser.scripting.registerContentScripts([
      {
        id: PORTAL_INTERCEPTOR_ID,
        js: ["portal-interceptor.js"],
        matches,
        runAt: "document_start",
        persistAcrossSessions: true,
      },
    ]);
  }

  // Registration affects future navigations. Inject once into already-open
  // default-store portal tabs so switching mode works without a reload.
  const tabs = await browser.tabs.query({});
  await Promise.allSettled(tabs.filter(
    (tab) =>
      Number.isInteger(tab.id) &&
      !tab.incognito &&
      tab.cookieStoreId === "firefox-default" &&
      isConfiguredPortalPage(tab.url, config.portalStartUrl)
  ).map((tab) => browser.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["portal-interceptor.js"],
  })));
}

let portalInterceptorSyncPromise = null;
let portalInterceptorSyncDirty = false;

function refreshPortalInterceptor() {
  portalInterceptorSyncDirty = true;
  if (portalInterceptorSyncPromise) return portalInterceptorSyncPromise;
  portalInterceptorSyncPromise = (async () => {
    do {
      portalInterceptorSyncDirty = false;
      try {
        await syncPortalInterceptorOnce();
      } catch {
        // A later config/permission event retries registration.
      }
    } while (portalInterceptorSyncDirty);
  })().finally(() => {
    portalInterceptorSyncPromise = null;
    if (portalInterceptorSyncDirty) void refreshPortalInterceptor();
  });
  return portalInterceptorSyncPromise;
}

/* ─── Containers ─────────────────────────────────────────────────── */

let containerMutationQueue = Promise.resolve();

function serializeContainerMutation(operation) {
  const result = containerMutationQueue.then(operation, operation);
  containerMutationQueue = result.catch(() => {});
  return result;
}

function isPlaceholderContainerName(name, accountId) {
  const escapedId = String(accountId).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `^(?:Containoodle|AWS) ${escapedId}(?: \\(\\d+\\)| · Containoodle(?: \\(\\d+\\))?)?$`
  ).test(String(name || ""));
}

async function availableOwnedContainerName(name, mappedStoreId = null) {
  const exactMatches = await browser.contextualIdentities.query({ name });
  if (exactMatches.every((identity) => identity.cookieStoreId === mappedStoreId)) {
    return name;
  }

  const base = `${name} · Containoodle`;
  let candidate = base;
  let suffix = 2;
  while (
    (await browser.contextualIdentities.query({ name: candidate }))
      .some((identity) => identity.cookieStoreId !== mappedStoreId)
  ) {
    candidate = `${base} (${suffix++})`;
  }
  return candidate;
}

async function reconcileMappedContainer(identity, accountId, name, env) {
  const expectedColor = ENV_CONTAINER_COLOR[env] || "orange";
  const properties = {};
  if (identity.color !== expectedColor) properties.color = expectedColor;
  if (
    name &&
    identity.name !== name &&
    isPlaceholderContainerName(identity.name, accountId)
  ) {
    properties.name = await availableOwnedContainerName(name, identity.cookieStoreId);
  }
  if (Object.keys(properties).length === 0) return identity;
  return browser.contextualIdentities.update(identity.cookieStoreId, properties);
}

/* Read-only lookup used before a backend helper round-trip. A stale or rejected
   helper credential must not create/repair containers or storage mappings. */
async function getMappedContainer(accountId) {
  const mappingKey = `accountContainer/${accountId}`;
  const { [mappingKey]: mappedStoreId } = await browser.storage.local.get(mappingKey);
  if (typeof mappedStoreId !== "string") return null;
  try {
    return await browser.contextualIdentities.get(mappedStoreId);
  } catch {
    return null;
  }
}

const findOrCreateContainer = synchronize(async (accountId, name, env, mode) => {
  return serializeContainerMutation(async () => {
    const mappingKey = `accountContainer/${accountId}`;
    const { [mappingKey]: mappedStoreId } = await browser.storage.local.get(mappingKey);
    if (typeof mappedStoreId === "string") {
      let identity;
      try {
        identity = await browser.contextualIdentities.get(mappedStoreId);
      } catch {
        await browser.storage.local.remove([
          mappingKey,
          `containerAccount/${mappedStoreId}`,
        ]);
      }
      if (identity) {
        await browser.storage.local.set({
          [`containerAccount/${mappedStoreId}`]: accountId,
        });
        try {
          return await reconcileMappedContainer(identity, accountId, name, env);
        } catch {
          // A cosmetic update must not invalidate a proven account mapping.
          return identity;
        }
      }
    }

    // Never adopt an unrelated Firefox container solely because its display
    // name matches. The account-id mapping, not the label, owns identity.
    const containerName = await availableOwnedContainerName(name);

    const identity = await browser.contextualIdentities.create({
      name: containerName,
      color: ENV_CONTAINER_COLOR[env] || "orange",
      icon: "briefcase",
    });
    await browser.storage.local.set({
      [mappingKey]: identity.cookieStoreId,
      [`containerAccount/${identity.cookieStoreId}`]: accountId,
    });
    if (mode === "backend") await seedConsentCookie(identity.cookieStoreId);
    return identity;
  });
});

/* Pre-seed the AWS console cookie-consent cookie (non-essential
   declined) so fresh containers never show the cookie banner.
   Needs the *.amazon.com host permission; silently skipped without. */
async function seedConsentCookie(storeId) {
  try {
    if (!(await browser.permissions.contains({ origins: CONSOLE_ORIGINS }))) return;
    await browser.cookies.set({
      name: "awsccc",
      value: btoa(JSON.stringify({ e: 1, p: 1, f: 1, a: 0, i: crypto.randomUUID(), v: "1" })),
      url: "https://global.console.aws.amazon.com",
      domain: ".aws.amazon.com",
      secure: true,
      httpOnly: false,
      sameSite: "lax",
      expirationDate: Math.trunc(Date.now() / 1000) + 3600 * 24 * 365 * 10,
      storeId,
    });
  } catch {
    // cosmetic only — never block a launch on it
  }
}

/* If the container already has a live console session, reuse it and
   skip federation entirely (no backend round-trip, no portal hop).
   Region comes from the console's own cookies; requires the
   *.amazon.com host permission, otherwise cookies.getAll returns
   nothing and we fall through to a normal launch. */
async function liveConsoleRegion(storeId) {
  try {
    const regionCookies = await browser.cookies.getAll({ name: "noflush_Region", storeId });
    if (regionCookies.length === 0) return null;
    const region = regionCookies[0].value;
    if (!REGION_RE.test(region)) return null;
    const tokens = await browser.cookies.getAll({ name: `aws-signer-token_${region}`, storeId });
    const now = Math.ceil(Date.now() / 1000);
    if (tokens.length > 0 && tokens[0].expirationDate !== undefined && tokens[0].expirationDate > now) {
      return region;
    }
  } catch {
    // fall through to a normal launch
  }
  return null;
}

/* ─── Portal mode ────────────────────────────────────────────────── */

const PORTAL_AUTH_COOKIE = "x-amz-sso_authn";

/* Firefox can qualify cookies by both first-party domain and storage
   partition. getAll() with these wildcards lets us find the cookie that
   belongs to the visible top-level portal even when FPI is enabled. */
async function listPortalAuthCookies(url, storeId) {
  const details = {
    url,
    name: PORTAL_AUTH_COOKIE,
    storeId,
    firstPartyDomain: null,
    partitionKey: {},
  };
  try {
    return await browser.cookies.getAll(details);
  } catch {
    // Compatibility fallback for Firefox versions/profiles that reject one
    // of the wildcard fields. The extension's minimum version supports the
    // explicit store selector.
    const cookie = await browser.cookies.get({
      url,
      name: PORTAL_AUTH_COOKIE,
      storeId,
    });
    return cookie ? [cookie] : [];
  }
}

function selectPortalAuthCookie(cookies, portalUrl) {
  if (!Array.isArray(cookies) || cookies.length === 0) return null;
  const portal = new URL(portalUrl);
  const appliesToPortalHost = (rawHost) => {
    const host = String(rawHost || "").toLowerCase().replace(/^\./, "");
    return !host || portal.hostname === host || portal.hostname.endsWith(`.${host}`);
  };
  const firstPartyCandidates = cookies.filter(
    (cookie) => appliesToPortalHost(cookie.firstPartyDomain)
  );
  if (firstPartyCandidates.length === 0) return null;

  // A top-level portal normally uses unpartitioned storage. If Firefox did
  // partition it, accept only a partition whose schemeful site applies to
  // this portal rather than falling back to another site's cookie jar.
  const unpartitioned = firstPartyCandidates.find(
    (cookie) => !(cookie.partitionKey && cookie.partitionKey.topLevelSite)
  );
  if (unpartitioned) return unpartitioned;
  return firstPartyCandidates.find((cookie) => {
    if (cookie.partitionKey.hasCrossSiteAncestor === true) return false;
    try {
      const topLevelSite = new URL(cookie.partitionKey.topLevelSite);
      return (
        topLevelSite.protocol === portal.protocol &&
        appliesToPortalHost(topLevelSite.hostname)
      );
    } catch {
      return false;
    }
  }) || null;
}

function cookieIsolationDetails(cookie) {
  const details = {};
  if (
    cookie.partitionKey &&
    typeof cookie.partitionKey.topLevelSite === "string"
  ) {
    details.partitionKey = { topLevelSite: cookie.partitionKey.topLevelSite };
    if (typeof cookie.partitionKey.hasCrossSiteAncestor === "boolean") {
      details.partitionKey.hasCrossSiteAncestor = cookie.partitionKey.hasCrossSiteAncestor;
    }
  } else if (typeof cookie.firstPartyDomain === "string") {
    details.firstPartyDomain = cookie.firstPartyDomain;
  }
  return details;
}

function portalCookieRemovalUrl(portalUrl, cookie) {
  const url = new URL(portalUrl);
  if (typeof cookie.path === "string" && cookie.path.startsWith("/")) {
    url.pathname = cookie.path;
  }
  url.search = "";
  url.hash = "";
  return url.href;
}

function copiedPortalCookieMatches(candidate, source) {
  if (!candidate || candidate.value !== source.value) return false;
  if (typeof source.path === "string" && candidate.path !== source.path) return false;
  if (source.hostOnly === true && candidate.hostOnly !== true) return false;
  if (
    source.hostOnly === false && (
      candidate.hostOnly !== false ||
      String(candidate.domain || "").replace(/^\./, "") !==
        String(source.domain || "").replace(/^\./, "")
    )
  ) return false;
  const sourcePartition = source.partitionKey && source.partitionKey.topLevelSite;
  const candidatePartition = candidate.partitionKey && candidate.partitionKey.topLevelSite;
  if (sourcePartition !== candidatePartition) return false;
  if (sourcePartition) {
    return (
      source.partitionKey.hasCrossSiteAncestor ===
      candidate.partitionKey.hasCrossSiteAncestor
    );
  }
  if (
    typeof source.firstPartyDomain === "string" &&
    candidate.firstPartyDomain !== source.firstPartyDomain
  ) return false;
  return true;
}

/* Readiness metadata for extension UI. This deliberately returns only
   booleans, never the portal cookie value. Session detection shares the
   same FPI/partition selection as launch so Options cannot report a cookie
   jar that the handoff would reject. */
async function portalReadiness() {
  const config = await getConfig();
  const result = {
    ok: true,
    mode: config.mode,
    configured: Boolean(config.portalStartUrl),
    portalAccess: false,
    session: false,
    roleDiscoveryAccess: false,
    consoleAccess: false,
  };

  try {
    if (config.mode !== "portal") {
      result.consoleAccess = await browser.permissions.contains({
        origins: CONSOLE_ORIGINS,
      });
      return result;
    }
    result.roleDiscoveryAccess = await browser.permissions.contains({
      origins: PORTAL_API_ORIGINS,
    });
    if (!result.configured) return result;

    result.portalAccess = await browser.permissions.contains({
      origins: [portalOriginPattern(config.portalStartUrl)],
    });
    if (!result.portalAccess) return result;

    const url = portalCookieUrl(config.portalStartUrl);
    result.session = Boolean(selectPortalAuthCookie(
      await listPortalAuthCookies(url, "firefox-default"),
      url
    ));
    return result;
  } catch (err) {
    return {
      ...result,
      ok: false,
      error: (err && err.message) || "Could not inspect portal readiness",
    };
  }
}

/* Copy the portal session cookie from the explicit default store into
   the account container with its real scope/isolation metadata, then read
   it back before navigation. Stale variants are removed only from this
   target container. */
async function copyPortalCookie(startUrl, storeId) {
  const url = portalCookieUrl(startUrl);
  const sourceCookies = await listPortalAuthCookies(url, "firefox-default");
  const cookie = selectPortalAuthCookie(sourceCookies, url);
  if (!cookie) return false;

  const targetCookies = await listPortalAuthCookies(url, storeId);
  await Promise.all(targetCookies.map((targetCookie) => browser.cookies.remove({
    url: portalCookieRemovalUrl(url, targetCookie),
    name: PORTAL_AUTH_COOKIE,
    storeId,
    ...cookieIsolationDetails(targetCookie),
  })));

  const details = {
    name: cookie.name,
    value: cookie.value,
    url,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    storeId,
    ...cookieIsolationDetails(cookie),
  };
  if (typeof cookie.path === "string") details.path = cookie.path;
  if (cookie.hostOnly === false && typeof cookie.domain === "string") {
    details.domain = cookie.domain;
  }
  if (typeof cookie.expirationDate === "number") {
    details.expirationDate = cookie.expirationDate;
  }
  await browser.cookies.set(details);

  const copiedCookies = await listPortalAuthCookies(url, storeId);
  return (
    copiedCookies.some((candidate) => copiedPortalCookieMatches(candidate, cookie)) &&
    copiedCookies.every((candidate) => candidate.value === cookie.value)
  );
}

/* ─── Role discovery ─────────────────────────────────────────────
   Roles are resolved per click: pinned role in the active mode's account
   source → that mode's remembered pick → live discovery. A
   single discovered role launches immediately; several are sent
   back to the sidebar as a picker. Portal mode has no invisible
   cross-mode fallback; backend mode can leave resolution to the helper. */

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return res.json();
}

async function fetchBackendJson(url, opts, trustedToken = null) {
  const token = trustedToken || await getBackendAuthToken();
  let res;
  try {
    res = await backendFetch(url, token, opts);
  } catch (err) {
    rethrowBackendAuthenticationError(err);
  }
  if (res.status === 401) throw backendAuthRejectedError();
  if (!res.ok) throw new Error(`HTTP ${res.status} from local helper`);
  return res.json();
}

/* SSO region: explicit config wins, then cached detection, then
   the portal's whoAmI endpoint. */
async function portalRegion(config) {
  if (config.ssoRegion && REGION_RE.test(config.ssoRegion)) return config.ssoRegion;
  const { portalRegionCache } = await browser.storage.local.get("portalRegionCache");
  if (portalRegionCache && REGION_RE.test(portalRegionCache)) return portalRegionCache;
  const data = await fetchJson(whoAmIUrl(config.portalStartUrl), { credentials: "include" });
  const region = data.region || data.awsRegion || (data.instance && data.instance.region);
  if (!region || !REGION_RE.test(region)) {
    throw new Error("Could not detect the SSO region — set it in Containoodle options");
  }
  await browser.storage.local.set({ portalRegionCache: region });
  return region;
}

/* The portal SPA authenticates with the x-amz-sso_authn cookie value
   passed as a bearer header — same session the cookie copy uses. */
async function portalDiscoverRoles(config, account) {
  if (!(await browser.permissions.contains({ origins: PORTAL_API_ORIGINS }))) {
    const err = new Error(
      "Role choices are not allowed — enable them in Containoodle options"
    );
    err.needsOptions = true;
    throw err;
  }
  let cookie;
  try {
    const url = portalCookieUrl(config.portalStartUrl);
    cookie = selectPortalAuthCookie(
      await listPortalAuthCookies(url, "firefox-default"),
      url
    );
  } catch {
    const err = new Error("Portal access not granted");
    err.needsOptions = true;
    throw err;
  }
  if (!cookie) {
    const err = new Error("No portal session");
    err.needsLogin = true;
    throw err;
  }
  const api = portalApiBase(await portalRegion(config));
  const headers = { "x-amz-sso_bearer_token": cookie.value };
  const instances = unwrapResult(await fetchJson(`${api}/instance/appinstances`, { headers }));
  const app = findAccountInstance(instances, account.accountId);
  if (!app || !app.id) throw new Error("Account not visible in the portal");
  const profiles = unwrapResult(
    await fetchJson(`${api}/instance/appinstance/${encodeURIComponent(app.id)}/profiles`, { headers })
  );
  return profiles.map((p) => p && p.name).filter(Boolean);
}

/* Backend variant — GET /roles (server runs aws sso
   list-account-roles). Old servers 404 here; caller falls back. */
async function backendDiscoverRoles(config, account, backendIdentity) {
  const query = backendIdentityQuery(backendIdentity);
  query.set("account", account.accountId);
  const data = await fetchBackendJson(
    `${config.backendUrl}/roles?${query}`,
    undefined,
    backendIdentity.token
  );
  if (!data.ok || !Array.isArray(data.roles)) throw new Error(data.error || "Bad /roles response");
  return data.roles;
}

async function discoverRolesFor(config, account, backendIdentity = null) {
  return config.mode === "portal"
    ? portalDiscoverRoles(config, account)
    : backendDiscoverRoles(config, account, backendIdentity);
}

function rememberedRoleKey(mode, accountId, backendIdentity = null) {
  if (mode === "portal") return `portalRoleChoice/${accountId}`;
  if (!backendIdentity) throw new Error("Backend identity is required");
  return `backendRoleChoice/${backendIdentity.identityKey}/${accountId}`;
}

async function rememberRole(config, accountId, role, backendIdentity = null) {
  await browser.storage.local.set({
    [rememberedRoleKey(config.mode, accountId, backendIdentity)]: role,
  });
}

/* Resolution order: explicit pick → pinned → mode-specific remembered
   pick → discovery (1 role: use it; several: throw chooseRole) → null.
   Backend mode lets the server resolve null; portal mode reports it. */
async function resolveRole(config, account, explicitRole, options = {}) {
  if (explicitRole) return explicitRole;
  if (account.role) return account.role;
  const key = rememberedRoleKey(
    config.mode,
    account.accountId,
    options.backendIdentity
  );
  const { [key]: remembered } = await browser.storage.local.get(key);
  if (remembered) return remembered;

  let roles = null;
  try {
    roles = await discoverRolesFor(config, account, options.backendIdentity);
  } catch (err) {
    if (err && (err.needsLogin || err.needsOptions)) throw err;
    roles = null; // discovery unavailable — fall through to defaults
  }
  if (roles && roles.length === 1) {
    if (typeof options.onDiscoveredRole === "function") {
      options.onDiscoveredRole(roles[0]);
    } else {
      await rememberRole(
        config,
        account.accountId,
        roles[0],
        options.backendIdentity
      );
    }
    return roles[0];
  }
  if (roles && roles.length > 1) {
    const err = new Error("Multiple roles available");
    err.chooseRole = roles;
    throw err;
  }
  return null;
}

/* Sidebar "change role" chip → always show the live list. */
async function discoverRoles(accountId, expectedMode) {
  const config = await getConfig();
  if (expectedMode && config.mode !== expectedMode) {
    return { ok: false, error: "Connection mode changed — try again" };
  }
  let account;
  try {
    account = await resolveAccount(accountId, config);
  } catch (err) {
    if (err && err.needsOptions) {
      return { ok: false, needsOptions: true, error: err.message };
    }
    return { ok: false, error: err.message || "Account lookup failed" };
  }
  if (!account) {
    return {
      ok: false,
      error: config.mode === "portal"
        ? "Account not found — pin it from the sidebar first"
        : "Account not found — check the backend account list",
    };
  }
  try {
    const backendIdentity = config.mode === "backend"
      ? await authenticateBackendIdentity(config)
      : null;
    const roles = await discoverRolesFor(config, account, backendIdentity);
    if (
      backendIdentity &&
      !(await backendIdentityIsCurrent(backendIdentity))
    ) {
      throw backendIdentityChangedError();
    }
    if (!roles || roles.length === 0) return { ok: false, error: "No roles found for this account" };
    return { ok: true, roles };
  } catch (err) {
    if (err && err.needsLogin) return { ok: false, needsLogin: true, error: "No portal session" };
    if (err && err.needsOptions) return { ok: false, needsOptions: true, error: err.message };
    return { ok: false, error: err.message || "Role discovery failed" };
  }
}

/* Focus an existing portal tab (outside any container) or open one,
   so the user can sign in. A stale portal action must not cross a
   connection-mode or configured-portal change while tabs.query runs. */
async function openPortal(expectedMode) {
  const config = await getConfig();
  const openModeRevision = connectionModeRevision;
  const cancelled = () => ({
    ok: false,
    cancelled: true,
    error: "Connection mode changed — try again",
  });
  if (expectedMode && config.mode !== expectedMode) return cancelled();
  if (config.mode !== "portal") {
    return { ok: false, error: "Portal mode is not active" };
  }
  if (!config.portalStartUrl) return { ok: false, error: "Portal URL not configured" };
  const portalStartUrl = config.portalStartUrl;
  const tabs = await browser.tabs.query({});
  const latestConfig = await getConfig();
  if (
    openModeRevision !== connectionModeRevision ||
    latestConfig.mode !== "portal" ||
    (expectedMode && latestConfig.mode !== expectedMode) ||
    latestConfig.portalStartUrl !== portalStartUrl
  ) {
    return cancelled();
  }
  const existing = tabs.find(
    (t) =>
      !t.incognito &&
      t.cookieStoreId === "firefox-default" &&
      isConfiguredPortalPage(t.url, portalStartUrl)
  );
  if (existing) {
    await browser.tabs.update(existing.id, { active: true });
    await browser.windows.update(existing.windowId, { focused: true });
  } else {
    await browser.tabs.create({
      url: portalStartUrl,
      active: true,
      cookieStoreId: "firefox-default",
    });
  }
  return { ok: true };
}

/* ─── Backend mode ───────────────────────────────────────────────── */

const BACKEND_REUSE_BIND_TIMEOUT_MS = 120_000;
const pendingBackendReuseBindings = new Map();

function clearPendingBackendReuseBinding(tabId) {
  const pending = pendingBackendReuseBindings.get(tabId);
  if (!pending) return null;
  pendingBackendReuseBindings.delete(tabId);
  clearTimeout(pending.timer);
  return pending;
}

function isAwsConsoleUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const hostname = url.hostname.toLowerCase();
  return (
    url.protocol === "https:" &&
    !url.username &&
    !url.password &&
    !url.port &&
    (
      hostname === "console.aws.amazon.com" ||
      hostname.endsWith(".console.aws.amazon.com")
    )
  );
}

async function verifyPendingBackendReuseBinding(tabId) {
  const candidate = pendingBackendReuseBindings.get(tabId);
  if (!candidate) return;

  let tab;
  try {
    tab = await browser.tabs.get(tabId);
  } catch {
    clearPendingBackendReuseBinding(tabId);
    return;
  }
  if (tab.status !== "complete") return;

  // A completed non-console navigation is a failed federation attempt. Take
  // this exact pending launch once so later browsing cannot retroactively bind
  // it as a reusable session.
  const pending = clearPendingBackendReuseBinding(tabId);
  if (
    !pending ||
    tab.cookieStoreId !== pending.cookieStoreId ||
    !isAwsConsoleUrl(tab.url)
  ) return;

  const mappingKey = `accountContainer/${pending.accountId}`;
  const ownerKey = `containerAccount/${pending.cookieStoreId}`;
  try {
    if (!(await backendIdentityIsCurrent(pending.backendIdentity))) return;
    const config = await getConfig();
    if (config.mode !== "backend") return;
    const stored = await browser.storage.local.get([mappingKey, ownerKey]);
    if (
      stored[mappingKey] !== pending.cookieStoreId ||
      stored[ownerKey] !== pending.accountId
    ) return;
    if (!(await backendIdentityIsCurrent(pending.backendIdentity))) return;
    if ((await getConfig()).mode !== "backend") return;
    await browser.storage.local.set({
      [`backendContainerIdentity/${pending.accountId}`]:
        pending.backendIdentity.identityKey,
    });
  } catch {
    // Verification is deliberately fail-closed. The previous marker remains.
  }
}

function scheduleBackendReuseBinding(tab, accountId, backendIdentity) {
  if (!Number.isInteger(tab.id) || typeof tab.cookieStoreId !== "string") return;
  clearPendingBackendReuseBinding(tab.id);
  const pending = {
    accountId,
    cookieStoreId: tab.cookieStoreId,
    backendIdentity,
    timer: null,
  };
  pending.timer = setTimeout(() => {
    if (pendingBackendReuseBindings.get(tab.id) === pending) {
      clearPendingBackendReuseBinding(tab.id);
    }
  }, BACKEND_REUSE_BIND_TIMEOUT_MS);
  pending.timer?.unref?.();
  pendingBackendReuseBindings.set(tab.id, pending);

  // The redirect may complete before tabs.create() resolves or before the
  // listener observes its update. Inspect the exact created tab once now too.
  void verifyPendingBackendReuseBinding(tab.id);
}

async function backendSigninUrl(backendUrl, account, role, backendIdentity) {
  const query = backendIdentityQuery(backendIdentity);
  query.set("account", account.accountId);
  if (role) query.set("role", role);
  let res;
  try {
    res = await backendFetch(
      `${backendUrl}/generate-url?${query}`,
      backendIdentity.token
    );
  } catch (err) {
    rethrowBackendAuthenticationError(err);
  }
  if (res.status === 401) throw backendAuthRejectedError();
  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`Backend error (HTTP ${res.status})`);
  }
  if (!res.ok || !data.ok) throw new Error(data.error || `Backend error (HTTP ${res.status})`);
  const urlParam = data.containerUrl.split("&url=")[1];
  if (!urlParam) throw new Error("Malformed container URL from backend");
  return validateBackendSigninUrl(decodeURIComponent(urlParam));
}

/* ─── Launch ─────────────────────────────────────────────────────── */

let portalPinMutationQueue = Promise.resolve();
let backendPinMutationQueue = Promise.resolve();

function serializePortalPinMutation(operation) {
  const result = portalPinMutationQueue.then(operation, operation);
  portalPinMutationQueue = result.catch(() => {});
  return result;
}

function serializeBackendPinMutation(operation) {
  const result = backendPinMutationQueue.then(operation, operation);
  backendPinMutationQueue = result.catch(() => {});
  return result;
}

function normalizedBackendPinnedAccountIds(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.flatMap((entry) => {
    const accountId = String(entry ?? "").trim();
    return /^\d{12}$/.test(accountId) ? [accountId] : [];
  }))];
}

async function setBackendPin(accountId, shouldPin, expectedMode) {
  return serializeBackendPinMutation(async () => {
    const config = await getConfig();
    if (
      config.mode !== "backend" ||
      (expectedMode && config.mode !== expectedMode)
    ) {
      return {
        ok: false,
        cancelled: true,
        error: "Connection mode changed — try again",
      };
    }

    const normalizedAccountId = String(accountId ?? "").trim();
    if (!/^\d{12}$/.test(normalizedAccountId)) {
      return { ok: false, error: "Invalid backend account" };
    }

    const { backendPinnedAccountIds } = await browser.storage.local.get(
      "backendPinnedAccountIds"
    );
    const existing = normalizedBackendPinnedAccountIds(backendPinnedAccountIds);
    const next = shouldPin
      ? existing.includes(normalizedAccountId)
        ? existing
        : [...existing, normalizedAccountId]
      : existing.filter((entry) => entry !== normalizedAccountId);

    const latestConfig = await getConfig();
    if (
      latestConfig.mode !== "backend" ||
      (expectedMode && latestConfig.mode !== expectedMode)
    ) {
      return {
        ok: false,
        cancelled: true,
        error: "Connection mode changed — try again",
      };
    }

    await browser.storage.local.set({ backendPinnedAccountIds: next });
    return { ok: true, pinned: Boolean(shouldPin) };
  });
}

function normalizedPortalPin(account, fallbackName) {
  if (!account || typeof account !== "object") return null;
  const accountId = String(account.accountId || "").trim();
  const accountName = String(fallbackName || account.accountName || "").trim();
  if (
    !/^\d{12}$/.test(accountId) ||
    !accountName ||
    accountName.length > 256 ||
    /[\u0000-\u001f\u007f]/.test(accountName)
  ) return null;
  const pin = { accountId, accountName };
  const role = typeof account.role === "string" ? account.role.trim() : "";
  if (role && /^[\w+=,.@-]{1,64}$/.test(role)) pin.role = role;
  return pin;
}

async function setPortalPin(account, shouldPin, expectedMode) {
  return serializePortalPinMutation(async () => {
    const config = await getConfig();
    if (
      config.mode !== "portal" ||
      (expectedMode && config.mode !== expectedMode)
    ) {
      return {
        ok: false,
        cancelled: true,
        error: "Connection mode changed — try again",
      };
    }

    const candidate = normalizedPortalPin(account);
    if (!candidate) return { ok: false, error: "Invalid portal account" };
    const nameKey = `portalAccountOriginalName/${candidate.accountId}`;
    const roleKey = `portalRoleChoice/${candidate.accountId}`;
    const stored = await browser.storage.local.get([
      "portalPinnedAccounts",
      nameKey,
      roleKey,
    ]);
    const existing = Array.isArray(stored.portalPinnedAccounts)
      ? stored.portalPinnedAccounts
      : [];
    const next = existing.filter(
      (entry) => String(entry && entry.accountId) !== candidate.accountId
    );

    if (shouldPin) {
      const storedName = typeof stored[nameKey] === "string"
        ? stored[nameKey].trim()
        : "";
      const storedRole = typeof stored[roleKey] === "string"
        ? stored[roleKey].trim()
        : "";
      next.push({
        ...candidate,
        accountName: storedName || candidate.accountName,
        ...(storedRole ? { role: storedRole } : {}),
      });
    }
    const latestConfig = await getConfig();
    if (
      latestConfig.mode !== "portal" ||
      (expectedMode && latestConfig.mode !== expectedMode)
    ) {
      return {
        ok: false,
        cancelled: true,
        error: "Connection mode changed — try again",
      };
    }
    await browser.storage.local.set({ portalPinnedAccounts: next });
    return { ok: true, pinned: Boolean(shouldPin) };
  });
}

async function persistSuccessfulPortalLaunch(account, role, updatePinned) {
  return serializePortalPinMutation(async () => {
    const values = {
      [`portalAccountOriginalName/${account.accountId}`]: account.accountName,
    };
    if (role) values[`portalRoleChoice/${account.accountId}`] = role;

    if (updatePinned) {
      const pinned = await getPortalPinnedAccounts();
      let changed = false;
      const nextPinned = pinned.map((entry) => {
        if (String(entry && entry.accountId) !== String(account.accountId)) return entry;
        const updated = {
          ...entry,
          accountId: account.accountId,
          accountName: account.accountName,
          ...(role ? { role } : {}),
        };
        if (JSON.stringify(updated) !== JSON.stringify(entry)) changed = true;
        return updated;
      });
      if (changed) values.portalPinnedAccounts = nextPinned;
    }

    await browser.storage.local.set(values);
  });
}

async function resolveAccount(accountId, config) {
  await ensureStorageMigration();
  const stored = await getStoredAccounts(config);
  const hit = stored.find((a) => a.accountId === accountId);
  if (hit) return hit;
  if (config.mode === "backend") {
    // Cache may not be primed yet — ask the backend directly.
    try {
      const token = await getBackendAuthToken();
      let res;
      try {
        res = await backendFetch(`${config.backendUrl}/accounts`, token);
      } catch (err) {
        rethrowBackendAuthenticationError(err);
      }
      if (res.status === 401) throw backendAuthRejectedError();
      const data = await res.json();
      if (Array.isArray(data)) return data.find((a) => a.accountId === accountId);
    } catch (err) {
      if (err && err.needsOptions) throw err;
      return undefined;
    }
  }
  return undefined;
}

/* Name the exact missing precondition instead of failing obscurely
   mid-launch. Returns null when the mode is ready to go. */
async function preflight(config) {
  if (config.mode === "portal") {
    if (!config.portalStartUrl) {
      return { ok: false, needsOptions: true, error: "Portal mode is on but no portal URL is saved" };
    }
    const granted = await browser.permissions.contains({
      origins: [portalOriginPattern(config.portalStartUrl)],
    });
    if (!granted) {
      return { ok: false, needsOptions: true, error: "Portal access not granted" };
    }
  }
  return null;
}

async function launch(accountId, explicitRole, options = {}) {
  await ensureStorageMigration();
  const config = await getConfig();
  const launchMode = config.mode;
  const launchModeRevision = connectionModeRevision;
  const modeIsCurrent = async () => (
    launchModeRevision === connectionModeRevision &&
    (await getConfig()).mode === launchMode
  );
  const cancelled = () => ({
    ok: false,
    cancelled: true,
    error: "Connection mode changed — try again",
  });
  if (options.expectedMode && config.mode !== options.expectedMode) {
    return cancelled();
  }
  const blocked = await preflight(config);
  if (blocked) return blocked;

  let portalLaunch = null;
  if (options.portalLaunchUrl) {
    if (config.mode !== "portal") {
      return { ok: false, error: "Portal launch ignored because portal mode is off" };
    }
    portalLaunch = parsePortalConsoleDeepLink(
      options.portalLaunchUrl,
      config.portalStartUrl
    );
    if (
      !portalLaunch ||
      portalLaunch.accountId !== accountId ||
      portalLaunch.roleName !== explicitRole
    ) {
      return { ok: false, error: "Invalid portal console launch" };
    }
  }

  let account;
  try {
    account = options.account || await resolveAccount(accountId, config);
  } catch (err) {
    if (err && err.needsOptions) {
      return { ok: false, needsOptions: true, error: err.message };
    }
    return { ok: false, error: err.message || "Account lookup failed" };
  }
  if (!account) {
    return {
      ok: false,
      error: config.mode === "portal"
        ? "Account not found — pin it from the sidebar first"
        : "Account not found — check the backend account list",
    };
  }

  if (!(await modeIsCurrent())) return cancelled();
  const env = accountEnv(account.accountName);
  let container;
  let url;
  let resolvedRole = null;
  let backendIdentity = null;
  let freshBackendSignin = false;

  if (config.mode === "backend") {
    try {
      backendIdentity = await authenticateBackendIdentity(config);
    } catch (err) {
      if (err && err.cancelled) return cancelled();
      if (err && err.needsOptions) {
        return { ok: false, needsOptions: true, error: err.message };
      }
      if (err instanceof TypeError) {
        return {
          ok: false,
          needsOptions: true,
          error: `Backend unreachable at ${config.backendUrl} — is server.py running? Or switch to portal mode`,
        };
      }
      return { ok: false, error: err.message || "Backend identity error" };
    }
    if (
      !(await modeIsCurrent()) ||
      !(await backendIdentityIsCurrent(backendIdentity))
    ) return cancelled();

    // A live console session is reusable only when it was created for this
    // authenticated SSO identity. Legacy/unscoped metadata is preserved but
    // deliberately ignored.
    const reuseKey = `backendContainerIdentity/${account.accountId}`;
    const { [reuseKey]: boundIdentity } = await browser.storage.local.get(
      reuseKey
    );
    const reusableContainer = !explicitRole && boundIdentity === backendIdentity.identityKey
      ? await getMappedContainer(account.accountId)
      : null;
    if (!(await backendIdentityIsCurrent(backendIdentity))) return cancelled();
    const liveRegion = reusableContainer
      ? await liveConsoleRegion(reusableContainer.cookieStoreId)
      : null;
    if (!(await backendIdentityIsCurrent(backendIdentity))) return cancelled();
    if (liveRegion) {
      if (!(await modeIsCurrent())) return cancelled();
      container = await findOrCreateContainer(
        account.accountId,
        account.accountName,
        env,
        config.mode
      );
      if (!(await modeIsCurrent())) return cancelled();
      url = `https://${liveRegion}.console.aws.amazon.com/console/home?region=${liveRegion}`;
    } else {
      let role;
      let discoveredRole = null;
      try {
        role = await resolveRole(config, account, explicitRole, {
          backendIdentity,
          onDiscoveredRole(value) {
            discoveredRole = value;
          },
        });
      } catch (err) {
        if (err.needsOptions) {
          return { ok: false, needsOptions: true, error: err.message };
        }
        if (err.chooseRole) return { ok: false, chooseRole: err.chooseRole };
        return { ok: false, error: err.message || "Role resolution failed" };
      }
      resolvedRole = role;
      try {
        if (
          !(await modeIsCurrent()) ||
          !(await backendIdentityIsCurrent(backendIdentity))
        ) return cancelled();
        // role may be null — the server then resolves it from
        // accounts.json / CONTAINOODLE_DEFAULT_ROLE as before.
        url = await backendSigninUrl(
          config.backendUrl,
          account,
          role,
          backendIdentity
        );
        freshBackendSignin = true;
      } catch (err) {
        if (err && err.needsOptions) {
          return { ok: false, needsOptions: true, error: err.message };
        }
        if (err instanceof TypeError) {
          // fetch network failure — server not running or wrong URL
          return {
            ok: false,
            needsOptions: true,
            error: `Backend unreachable at ${config.backendUrl} — is server.py running? Or switch to portal mode`,
          };
        }
        return { ok: false, error: err.message || "Backend error" };
      }
      if (
        !(await modeIsCurrent()) ||
        !(await backendIdentityIsCurrent(backendIdentity))
      ) return cancelled();
      if (discoveredRole) {
        try {
          await rememberRole(
            config,
            account.accountId,
            discoveredRole,
            backendIdentity
          );
        } catch (err) {
          return { ok: false, error: err.message || "Role resolution failed" };
        }
        if (
          !(await modeIsCurrent()) ||
          !(await backendIdentityIsCurrent(backendIdentity))
        ) return cancelled();
      }
      container = await findOrCreateContainer(
        account.accountId,
        account.accountName,
        env,
        config.mode
      );
    }
  } else {
    container = await findOrCreateContainer(
      account.accountId,
      account.accountName,
      env,
      config.mode
    );
    if (!(await modeIsCurrent())) return cancelled();

    // A portal click is an explicit role choice. Never let a possibly
    // different live session in the container override that handoff.
    let role = portalLaunch && portalLaunch.roleName;
    if (!role) {
      try {
        role = await resolveRole(config, account, explicitRole);
      } catch (err) {
        if (err.needsLogin) return { ok: false, needsLogin: true, error: "No portal session" };
        if (err.needsOptions) {
          return { ok: false, needsOptions: true, error: err.message };
        }
        if (err.chooseRole) return { ok: false, chooseRole: err.chooseRole };
        return { ok: false, error: err.message || "Role resolution failed" };
      }
    }
    resolvedRole = role;

    if (!role) {
      return {
        ok: false,
        error: `No role for ${account.accountName} — sign in to the portal so roles can be discovered, or choose a role for its pinned shortcut`,
      };
    }
    let hasSession;
    try {
      if (!(await modeIsCurrent())) return cancelled();
      hasSession = await copyPortalCookie(config.portalStartUrl, container.cookieStoreId);
    } catch {
      return { ok: false, needsOptions: true, error: "Portal access not granted" };
    }
    if (!hasSession) {
      return { ok: false, needsLogin: true, error: "No portal session" };
    }
    // A portal-click handoff keeps the portal's complete shortcut URL,
    // including an optional destination. Sidebar launches build one.
    url = portalLaunch
      ? portalLaunch.url
      : consoleDeepLink(config.portalStartUrl, account.accountId, role);
  }

  if (
    !(await modeIsCurrent()) ||
    (
      config.mode === "backend" &&
      !(await backendIdentityIsCurrent(backendIdentity))
    )
  ) return cancelled();
  const createProperties = { url, cookieStoreId: container.cookieStoreId };
  if (Number.isInteger(options.windowId)) createProperties.windowId = options.windowId;
  const tab = await browser.tabs.create(createProperties);
  if (config.mode === "backend" && freshBackendSignin) {
    scheduleBackendReuseBinding(tab, account.accountId, backendIdentity);
  }
  await addToGroup(tab, account, env);
  try {
    if (config.mode === "portal") {
      await persistSuccessfulPortalLaunch(
        account,
        resolvedRole,
        Boolean(portalLaunch || explicitRole)
      );
    } else {
      const identityStillCurrent = await backendIdentityIsCurrent(
        backendIdentity
      );
      if (identityStillCurrent) {
        const successfulState = {};
        if (explicitRole && resolvedRole) {
          successfulState[
            rememberedRoleKey(
              config.mode,
              account.accountId,
              backendIdentity
            )
          ] = resolvedRole;
        }
        if (Object.keys(successfulState).length > 0) {
          await browser.storage.local.set(successfulState);
        }
      }
    }
  } catch {
    // Launch history and pinned-shortcut updates must never fail a
    // completed console launch.
  }
  return { ok: true, account: account.accountName, tabId: tab.id };
}

/* ─── Tab groups ─────────────────────────────────────────────────── */

const supportsGroups =
  typeof browser.tabs.group === "function" && typeof browser.tabGroups === "object";

const createGroup = synchronize(async (groupKey, tabId) => {
  const groupId = await browser.tabs.group({ tabIds: tabId });
  await browser.storage.local.set({ [`tabGroups/${groupKey}`]: groupId });
  return groupId;
});

let groupNamingMutationQueue = Promise.resolve();

function serializeGroupNamingMutation(operation) {
  const result = groupNamingMutationQueue.then(operation, operation);
  groupNamingMutationQueue = result.catch(() => {});
  return result;
}

async function addToGroup(tab, account, env) {
  if (!supportsGroups || tab.id === undefined) return;
  try {
    // Firefox groups belong to one window, so cache one group per
    // account/window rather than trying to reuse a group cross-window.
    const groupKey = `${account.accountId}/${tab.windowId}`;
    const key = `tabGroups/${groupKey}`;
    const titleKey = `tabGroupTitle/${account.accountId}`;
    const {
      [key]: cachedGroupId,
      [titleKey]: savedTitle,
    } = await browser.storage.local.get([key, titleKey]);
    let groupId = null;
    if (typeof cachedGroupId === "number") {
      try {
        await browser.tabs.group({ groupId: cachedGroupId, tabIds: tab.id });
        groupId = cachedGroupId;
      } catch {
        // group was closed — create a fresh one below
      }
    }
    if (groupId === null) {
      groupId = await createGroup(groupKey, tab.id);
      // Concurrent first launches share createGroup's promise. Explicitly
      // add this caller's tab too so the second tab is not left ungrouped.
      await browser.tabs.group({ groupId, tabIds: tab.id });
    }
    await serializeGroupNamingMutation(async () => {
      const latestConfig = await getConfig();
      const generatedTitle = automaticGroupTitle(
        account.accountName,
        latestConfig.groupNamePattern,
        latestConfig.groupNameReplacement
      );
      const pendingManualWrite = manualGroupTitleWrites.get(groupId);
      if (pendingManualWrite) await pendingManualWrite.catch(() => {});
      const { [titleKey]: latestSavedTitle } = await browser.storage.local.get(titleKey);
      const manualTitle = typeof latestSavedTitle === "string"
        ? latestSavedTitle
        : savedTitle;
      const color = ENV_GROUP_COLOR[env];
      if (typeof manualTitle === "string" && manualTitle) {
        await setGroupProps(groupId, manualTitle, color);
      } else {
        await setGroupProps(groupId, generatedTitle || account.accountName, color);
        await restoreConcurrentManualTitle(groupId, account.accountId, color);
      }
    });
  } catch {
    // grouping is a convenience — never fail the launch over it
  }
}

/* Setting the title ourselves fires tabGroups.onUpdated; the
   expected-update tokens stop that echo from being written back as a
   user rename while still allowing a real rename during an update. */
const manualGroupTitleRevision = new Map();
const manualGroupTitleWrites = new Map();
const knownGroupTitles = new Map();

const setGroupProps = (() => {
  const expectedUpdates = new Map();

  const forgetExpected = (groupId, token) => {
    const tokens = expectedUpdates.get(groupId) || [];
    const remaining = tokens.filter((candidate) => candidate !== token);
    if (remaining.length > 0) expectedUpdates.set(groupId, remaining);
    else expectedUpdates.delete(groupId);
  };

  const consumeExpected = (groupId, title) => {
    const tokens = expectedUpdates.get(groupId) || [];
    const token = tokens.find((candidate) => candidate.title === title);
    if (!token) return false;
    forgetExpected(groupId, token);
    return true;
  };

  if (supportsGroups) {
    browser.tabGroups.onUpdated.addListener(async (group) => {
      if (!group.title) return;
      if (consumeExpected(group.id, group.title)) {
        knownGroupTitles.set(group.id, group.title);
        return;
      }
      const previousTitle = knownGroupTitles.get(group.id);
      knownGroupTitles.set(group.id, group.title);
      if (previousTitle === undefined || previousTitle === group.title) return;
      manualGroupTitleRevision.set(
        group.id,
        (manualGroupTitleRevision.get(group.id) || 0) + 1
      );
      const previousWrite = manualGroupTitleWrites.get(group.id) || Promise.resolve();
      const write = previousWrite.catch(() => {}).then(async () => {
        const tabs = await browser.tabs.query({ groupId: group.id });
        if (tabs.length === 0 || tabs[0].cookieStoreId === undefined) return;
        const ownerKey = `containerAccount/${tabs[0].cookieStoreId}`;
        const { [ownerKey]: mappedAccountId } = await browser.storage.local.get(ownerKey);
        if (!mappedAccountId) return;
        await browser.storage.local.set({ [`tabGroupTitle/${mappedAccountId}`]: group.title });
      });
      manualGroupTitleWrites.set(group.id, write);
      try {
        await write;
      } catch {
        // container may be gone; nothing to persist
      } finally {
        if (manualGroupTitleWrites.get(group.id) === write) {
          manualGroupTitleWrites.delete(group.id);
        }
      }
    });
  }
  return async (groupId, title, color) => {
    const token = { title };
    const previousTitle = knownGroupTitles.get(groupId);
    expectedUpdates.set(groupId, [...(expectedUpdates.get(groupId) || []), token]);
    try {
      const props = { title };
      if (color) props.color = color;
      await browser.tabGroups.update(groupId, props);
      knownGroupTitles.set(groupId, title);
    } catch (err) {
      forgetExpected(groupId, token);
      if (knownGroupTitles.get(groupId) === title) {
        if (previousTitle === undefined) knownGroupTitles.delete(groupId);
        else knownGroupTitles.set(groupId, previousTitle);
      }
      throw err;
    } finally {
      // Firefox normally emits onUpdated before update() settles. Retain the
      // token through the current turn for profiles where delivery is later.
      setTimeout(() => forgetExpected(groupId, token), 0);
    }
  };
})();

async function seedKnownGroupTitles() {
  if (!supportsGroups || typeof browser.tabGroups.query !== "function") return;
  try {
    const groups = await browser.tabGroups.query({});
    for (const group of groups) {
      if (Number.isInteger(group.id) && typeof group.title === "string") {
        if (!knownGroupTitles.has(group.id)) {
          knownGroupTitles.set(group.id, group.title);
        }
      }
    }
  } catch {
    // The first Containoodle update for an unknown group seeds it defensively.
  }
}

async function restoreConcurrentManualTitle(groupId, accountId, color) {
  const pendingManualWrite = manualGroupTitleWrites.get(groupId);
  if (pendingManualWrite) await pendingManualWrite.catch(() => {});
  const titleKey = `tabGroupTitle/${accountId}`;
  const { [titleKey]: manualTitle } = await browser.storage.local.get(titleKey);
  if (typeof manualTitle === "string" && manualTitle) {
    await setGroupProps(groupId, manualTitle, color);
  }
}

async function refreshAutomaticGroupTitles(config) {
  if (!supportsGroups) return;
  try {
    const all = await browser.storage.local.get(null);
    const storedAccounts = config.mode === "portal"
      ? all.portalPinnedAccounts
      : all.accountsCache;
    const cachedNames = new Map(
      (Array.isArray(storedAccounts) ? storedAccounts : [])
        .filter((account) => account && typeof account.accountName === "string")
        .map((account) => [String(account.accountId), account.accountName])
    );
    await Promise.allSettled(Object.entries(all).map(async ([key, groupId]) => {
      const match = /^tabGroups\/(\d{12})\/.+/.exec(key);
      if (!match || typeof groupId !== "number") return;
      const accountId = match[1];
      const originalName = config.mode === "portal"
        ? all[`portalAccountOriginalName/${accountId}`] || cachedNames.get(accountId)
        : cachedNames.get(accountId);
      if (typeof originalName !== "string" || !originalName.trim()) return;
      const revision = manualGroupTitleRevision.get(groupId) || 0;
      const pendingManualWrite = manualGroupTitleWrites.get(groupId);
      if (pendingManualWrite) await pendingManualWrite.catch(() => {});
      const titleKey = `tabGroupTitle/${accountId}`;
      const { [titleKey]: manualTitle } = await browser.storage.local.get(titleKey);
      if (
        typeof manualTitle === "string" ||
        revision !== (manualGroupTitleRevision.get(groupId) || 0) ||
        manualGroupTitleWrites.has(groupId)
      ) return;
      const color = ENV_GROUP_COLOR[accountEnv(originalName)];
      await setGroupProps(
        groupId,
        automaticGroupTitle(
          originalName,
          config.groupNamePattern,
          config.groupNameReplacement
        ) || originalName,
        color
      );
      await restoreConcurrentManualTitle(groupId, accountId, color);
    }));
  } catch {
    // A naming preference must never interfere with launching or startup.
  }
}

function queueAutomaticGroupTitleRefresh(config) {
  return serializeGroupNamingMutation(() => refreshAutomaticGroupTitles(config));
}

/* One-way storage cleanup for builds that used accountsCache for both
   connection modes and mistook v1.0.4's generated group title for a manual
   rename. Only an explicitly manual legacy cache moves to portal pins; a
   backend cache stays backend-only. */
async function migrateLegacyStorage() {
  const all = await browser.storage.local.get(null);
  const values = {};
  const remove = [];
  const config = { ...DEFAULT_CONFIG, ...(all.config || {}) };

  let migratedPortalPins = Array.isArray(all.portalPinnedAccounts)
    ? all.portalPinnedAccounts
    : null;
  if (all.accountsCacheSource === "manual") {
    const legacyManualAccounts = Array.isArray(all.accountsCache) ? all.accountsCache : [];
    if (!migratedPortalPins) {
      migratedPortalPins = legacyManualAccounts;
      values.portalPinnedAccounts = migratedPortalPins;
    } else {
      const pinnedIds = new Set(
        migratedPortalPins.map((account) => String(account && account.accountId))
      );
      const missingLegacyAccounts = legacyManualAccounts.filter(
        (account) => !pinnedIds.has(String(account && account.accountId))
      );
      if (missingLegacyAccounts.length > 0) {
        migratedPortalPins = [...migratedPortalPins, ...missingLegacyAccounts];
        values.portalPinnedAccounts = migratedPortalPins;
      }
    }
    remove.push("accountsCache", "accountsCacheAt", "accountsCacheSource");
  }

  for (const [key, value] of Object.entries(all)) {
    const match = /^accountOriginalName\/(\d{12})$/.exec(key);
    if (!match) continue;
    if (
      config.mode === "portal" &&
      typeof value === "string" &&
      value.trim() &&
      typeof all[`portalAccountOriginalName/${match[1]}`] !== "string"
    ) {
      values[`portalAccountOriginalName/${match[1]}`] = value;
    }
    remove.push(key);
  }

  let clearedTitles = 0;
  const migrateGroupTitles = all["migration/groupTitlesAutomaticV1"] !== true;
  if (migrateGroupTitles) {
    const activeAccounts = config.mode === "portal"
      ? (migratedPortalPins || [])
      : (
          all.accountsCacheSource !== "manual" && Array.isArray(all.accountsCache)
            ? all.accountsCache
            : []
        );
    const knownOriginalNames = new Map();
    const rememberOriginal = (accountId, accountName) => {
      if (!/^\d{12}$/.test(String(accountId))) return;
      if (typeof accountName !== "string" || !accountName.trim()) return;
      const names = knownOriginalNames.get(String(accountId)) || new Set();
      names.add(accountName);
      knownOriginalNames.set(String(accountId), names);
    };

    for (const account of activeAccounts) {
      if (account) rememberOriginal(account.accountId, account.accountName);
    }
    if (config.mode === "portal") {
      for (const [key, value] of Object.entries(all)) {
        let match = /^portalAccountOriginalName\/(\d{12})$/.exec(key);
        if (match) rememberOriginal(match[1], value);
        match = /^accountOriginalName\/(\d{12})$/.exec(key);
        if (match) rememberOriginal(match[1], value);
      }
    }
    for (const [key, value] of Object.entries(all)) {
      const match = /^tabGroupTitle\/(\d{12})$/.exec(key);
      if (
        match &&
        typeof value === "string" &&
        knownOriginalNames.get(match[1])?.has(value)
      ) {
        remove.push(key);
        clearedTitles += 1;
      }
    }
  }

  if (Object.keys(values).length > 0) await browser.storage.local.set(values);
  if (remove.length > 0) await browser.storage.local.remove([...new Set(remove)]);
  if (migrateGroupTitles) {
    await browser.storage.local.set({ "migration/groupTitlesAutomaticV1": true });
  }
  return { clearedTitles };
}

async function resetGroupTitles() {
  try {
    await ensureStorageMigration();
    await Promise.allSettled([...manualGroupTitleWrites.values()]);
    const all = await browser.storage.local.get(null);
    const keys = Object.keys(all).filter((key) => /^tabGroupTitle\/\d{12}$/.test(key));
    if (keys.length > 0) await browser.storage.local.remove(keys);
    await queueAutomaticGroupTitleRefresh(await getConfig());
    return { ok: true, cleared: keys.length };
  } catch (err) {
    return {
      ok: false,
      error: (err && err.message) || "Could not reset tab-group titles",
    };
  }
}

/* Group IDs do not survive a browser restart — drop stale entries. */
async function cleanupStaleGroups() {
  try {
    const all = await browser.storage.local.get(null);
    const stale = Object.keys(all).filter((k) => k.startsWith("tabGroups/"));
    if (stale.length > 0) await browser.storage.local.remove(stale);
  } catch {
    // best effort
  }
}

browser.runtime.onStartup.addListener(cleanupStaleGroups);
browser.runtime.onInstalled.addListener(cleanupStaleGroups);
browser.runtime.onStartup.addListener(seedKnownGroupTitles);
browser.runtime.onInstalled.addListener(seedKnownGroupTitles);
void seedKnownGroupTitles();

/* ─── Portal-click handoff ──────────────────────────────────────────
   In portal mode a narrowly scoped content script intercepts a validated
   account/role link before the portal opens an ordinary tab. URL events
   are retained as a non-destructive fallback for other portal behavior. */

const portalHandoffPending = new Set();
const portalNativeFallbacks = new Map();
const portalNewTabFallbacks = new Map();

function sameUrl(left, right) {
  try {
    return new URL(left).href === new URL(right).href;
  } catch {
    return left === right;
  }
}

function isMatchingPortalSource(tab, plan, portalStartUrl) {
  if (!tab || tab.incognito || tab.cookieStoreId !== "firefox-default") return false;
  const parsed = parsePortalConsoleDeepLink(tab.url, portalStartUrl);
  return Boolean(parsed && parsed.url === plan.sourceUrl);
}

async function isDisposablePortalChild(tab, portalStartUrl) {
  if (!Number.isInteger(tab.openerTabId) || tab.openerTabId === tab.id) return false;
  try {
    const opener = await browser.tabs.get(tab.openerTabId);
    return canRemovePortalShortcutTab(tab, opener, portalStartUrl);
  } catch {
    return false;
  }
}

async function getTab(tabId) {
  try {
    return await browser.tabs.get(tabId);
  } catch {
    return null;
  }
}

function guardNativeFallback(tabId, sourceUrl) {
  const guard = { url: sourceUrl };
  portalNativeFallbacks.set(tabId, guard);
  guard.timer = setTimeout(() => {
    if (portalNativeFallbacks.get(tabId) === guard) portalNativeFallbacks.delete(tabId);
  }, 10000);
  return guard;
}

function clearNativeFallback(tabId) {
  const guard = portalNativeFallbacks.get(tabId);
  if (guard && guard.timer) clearTimeout(guard.timer);
  portalNativeFallbacks.delete(tabId);
}

function guardNewTabFallback(tabId, sourceUrl) {
  const guard = { tabId, url: sourceUrl };
  portalNewTabFallbacks.set(tabId, guard);
  guard.timer = setTimeout(() => {
    if (portalNewTabFallbacks.get(tabId) === guard) {
      portalNewTabFallbacks.delete(tabId);
    }
  }, 10000);
  return guard;
}

function clearNewTabFallback(guard) {
  if (guard && guard.timer) clearTimeout(guard.timer);
  if (guard) portalNewTabFallbacks.delete(guard.tabId);
}

function consumeNewTabFallback(tab, candidateUrl) {
  if (
    !tab ||
    !Number.isInteger(tab.id) ||
    tab.incognito ||
    tab.cookieStoreId !== "firefox-default"
  ) return false;
  const guard = portalNewTabFallbacks.get(tab.id);
  if (!guard) return false;
  // A delayed creation notification can report the initial blank page after
  // tabs.create() has resolved and the exact-tab guard is installed.
  if (candidateUrl === "about:blank") return true;
  if (sameUrl(candidateUrl, guard.url)) return true;
  clearNewTabFallback(guard);
  return false;
}

async function openNewTabFallback(windowId, sourceUrl) {
  let tab = null;
  let guard = null;
  try {
    // Create first, then bind the guard to this exact tab before navigating.
    // This prevents another same-URL tab in the window from stealing it.
    tab = await browser.tabs.create({
      url: "about:blank",
      cookieStoreId: "firefox-default",
      windowId,
    });
    if (!Number.isInteger(tab.id)) throw new Error("Fallback tab has no id");
    guard = guardNewTabFallback(tab.id, sourceUrl);
    await browser.tabs.update(tab.id, { url: sourceUrl });
    return true;
  } catch {
    clearNewTabFallback(guard);
    if (tab && Number.isInteger(tab.id)) {
      try { await browser.tabs.remove(tab.id); } catch {}
    }
    return false;
  }
}

const launchPortalShortcut = synchronize(async (_key, plan, windowId) => {
  return launch(plan.accountId, plan.roleName, {
    account: plan.account,
    portalLaunchUrl: plan.sourceUrl,
    windowId,
  });
});

async function maybeHandoffPortalTab(tab, candidateUrl) {
  if (!tab || !Number.isInteger(tab.id) || !candidateUrl) return;
  if (portalHandoffPending.has(tab.id)) return;

  try {
    await ensureStorageMigration();
    const config = await getConfig();
    if (config.mode !== "portal") return;
    const plan = planPortalTabHandoff({
      mode: config.mode,
      portalStartUrl: config.portalStartUrl,
      accounts: await getPortalHandoffAccounts(),
      tab: { ...tab, url: candidateUrl },
    });

    if (plan.kind !== "handoff") return;
    if (portalHandoffPending.has(tab.id)) return;

    portalHandoffPending.add(tab.id);
    try {
      const disposeSource = await isDisposablePortalChild(tab, config.portalStartUrl);
      const launchKey = `${plan.windowId}:${plan.sourceUrl}`;
      const result = await launchPortalShortcut(launchKey, plan, plan.windowId);
      if (!result.ok) return;

      // Only mutate the source if it is still the exact shortcut. A proven
      // portal-created child is disposable; otherwise retain a portal tab.
      // If AWS already redirected it, leave the native tab untouched.
      try {
        const current = await getTab(plan.tabId);
        if (!isMatchingPortalSource(current, plan, config.portalStartUrl)) return;
        if (disposeSource) {
          await browser.tabs.remove(plan.tabId);
        } else {
          await browser.tabs.update(plan.tabId, { url: config.portalStartUrl });
        }
      } catch {
        // The user may already have closed or moved the source tab.
      }
    } finally {
      portalHandoffPending.delete(tab.id);
    }
  } catch {
    // Native portal navigation is the fallback for every handoff failure.
  }
}

async function portalInterceptorState(tab) {
  if (!tab || tab.incognito || tab.cookieStoreId !== "firefox-default") {
    return { enabled: false };
  }
  const config = await getConfig();
  let granted = false;
  if (
    config.mode === "portal" &&
    config.portalStartUrl &&
    isConfiguredPortalPage(tab.url, config.portalStartUrl)
  ) {
    granted = await browser.permissions.contains({
      origins: [portalOriginPattern(config.portalStartUrl)],
    });
  }
  return {
    enabled: Boolean(granted),
  };
}

async function notifyPortalInterceptorState() {
  try {
    const config = await getConfig();
    if (!config.portalStartUrl) return;
    const tabs = await browser.tabs.query({});
    await Promise.allSettled(tabs.filter(
      (tab) =>
        Number.isInteger(tab.id) &&
        !tab.incognito &&
        tab.cookieStoreId === "firefox-default" &&
        isConfiguredPortalPage(tab.url, config.portalStartUrl)
    ).map((tab) => browser.tabs.sendMessage(tab.id, {
      type: "portal-interceptor-refresh",
    })));
  } catch {
    // Existing pages can refresh state on their next config change/reload.
  }
}

const handoffPortalClick = synchronize(async (
  _key,
  sourceTab,
  candidateUrl,
  disposition,
  accountName
) => {
  if (!sourceTab || !Number.isInteger(sourceTab.id)) return { ok: false };
  await ensureStorageMigration();
  const config = await getConfig();
  if (
    config.mode !== "portal" ||
    sourceTab.incognito ||
    sourceTab.cookieStoreId !== "firefox-default" ||
    !isConfiguredPortalPage(sourceTab.url, config.portalStartUrl)
  ) return { ok: false };

  const plan = planPortalTabHandoff({
    mode: config.mode,
    portalStartUrl: config.portalStartUrl,
    accounts: await getPortalHandoffAccounts(),
    tab: { ...sourceTab, url: candidateUrl },
    portalAccountName: accountName,
  });
  if (plan.kind !== "handoff") return { ok: false };

  const current = await getTab(sourceTab.id);
  if (
    !current ||
    current.incognito ||
    current.cookieStoreId !== "firefox-default" ||
    !isConfiguredPortalPage(current.url, config.portalStartUrl)
  ) return { ok: false };

  const opensNewTab = disposition === "new-tab";
  const fallbackGuard = opensNewTab
    ? null
    : guardNativeFallback(sourceTab.id, plan.sourceUrl);
  const launchKey = `${current.windowId}:${plan.sourceUrl}`;
  let result;
  try {
    result = await launchPortalShortcut(launchKey, plan, current.windowId);
  } catch {
    result = { ok: false };
  }
  if (result.ok && fallbackGuard && portalNativeFallbacks.get(sourceTab.id) === fallbackGuard) {
    clearNativeFallback(sourceTab.id);
  }
  if (result.ok) return { ok: true };
  if (result.cancelled) {
    if (fallbackGuard && portalNativeFallbacks.get(sourceTab.id) === fallbackGuard) {
      clearNativeFallback(sourceTab.id);
    }
    return { ok: false, cancelled: true };
  }
  const nativeFallback = opensNewTab
    ? await openNewTabFallback(current.windowId, plan.sourceUrl)
    : false;
  return nativeFallback ? { ok: false, nativeFallback: true } : { ok: false };
});

browser.tabs.onCreated.addListener((tab) => {
  if (tab.url && consumeNewTabFallback(tab, tab.url)) return;
  if (tab.url) void maybeHandoffPortalTab(tab, tab.url);
});

browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (pendingBackendReuseBindings.has(tabId)) {
    void verifyPendingBackendReuseBinding(tabId);
  }
  if (!changeInfo.url) return;
  if (consumeNewTabFallback({ ...tab, id: tabId }, changeInfo.url)) return;
  const nativeFallback = portalNativeFallbacks.get(tabId);
  if (nativeFallback && sameUrl(nativeFallback.url, changeInfo.url)) {
    clearNativeFallback(tabId);
    return;
  }
  if (nativeFallback) {
    clearNativeFallback(tabId);
  }
  void maybeHandoffPortalTab({ ...tab, id: tabId }, changeInfo.url);
});

browser.tabs.onRemoved.addListener((tabId) => {
  clearPendingBackendReuseBinding(tabId);
  portalHandoffPending.delete(tabId);
  clearNativeFallback(tabId);
  clearNewTabFallback(portalNewTabFallbacks.get(tabId));
});

/* ─── Messages ───────────────────────────────────────────────────── */

browser.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === "launch") {
    return launch(msg.accountId, msg.role, { expectedMode: msg.mode });
  }
  if (msg && msg.type === "discover-roles") {
    return discoverRoles(msg.accountId, msg.mode);
  }
  if (msg && msg.type === "set-portal-pin") {
    return setPortalPin(msg.account, msg.pinned, msg.mode);
  }
  if (msg && msg.type === "set-backend-pin") {
    return setBackendPin(msg.accountId, msg.pinned, msg.mode);
  }
  if (msg && msg.type === "open-portal") return openPortal(msg.mode);
  if (msg && msg.type === "portal-readiness") return portalReadiness();
  if (msg && msg.type === "reset-group-titles") return resetGroupTitles();
  if (msg && msg.type === "portal-interceptor-state") {
    return portalInterceptorState(sender && sender.tab);
  }
  if (msg && msg.type === "portal-shortcut-click") {
    const tab = sender && sender.tab;
    const key = String(tab && tab.id);
    return handoffPortalClick(key, tab, msg.url, msg.disposition, msg.accountName);
  }
  return false;
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.config) return;
  const oldMode = changes.config.oldValue?.mode;
  const newMode = changes.config.newValue?.mode;
  if (oldMode !== newMode) connectionModeRevision += 1;
  void refreshPortalInterceptor();
  const before = { ...DEFAULT_CONFIG, ...(changes.config.oldValue || {}) };
  const after = { ...DEFAULT_CONFIG, ...(changes.config.newValue || {}) };
  if (
    before.groupNamePattern !== after.groupNamePattern ||
    before.groupNameReplacement !== after.groupNameReplacement
  ) {
    void queueAutomaticGroupTitleRefresh(after);
  }
});
browser.permissions.onAdded.addListener(() => {
  void refreshPortalInterceptor();
  void notifyPortalInterceptorState();
});
browser.permissions.onRemoved.addListener(() => {
  void refreshPortalInterceptor();
  void notifyPortalInterceptorState();
});
browser.runtime.onStartup.addListener(() => { void refreshPortalInterceptor(); });
browser.runtime.onInstalled.addListener(() => { void refreshPortalInterceptor(); });

async function migrateAndRefreshGroupTitles() {
  const result = await ensureStorageMigration();
  if (result && result.clearedTitles > 0) {
    await queueAutomaticGroupTitleRefresh(await getConfig());
  }
}

browser.runtime.onStartup.addListener(() => { void migrateAndRefreshGroupTitles(); });
browser.runtime.onInstalled.addListener(() => { void migrateAndRefreshGroupTitles(); });
void migrateAndRefreshGroupTitles();
void refreshPortalInterceptor();
