/* Containoodle Options
 *
 * The selected connection mode owns the visible setup panel. Portal mode never
 * probes the local helper; backend mode never probes the AWS portal. Portal
 * role-choice access and backend session-reuse access stay inside their
 * respective mode panels.
 */

import { normalizeStartUrl, portalOriginPattern } from "../shared/portal.js";
import { REGION_RE } from "../shared/accounts.js";
import { validateGroupNameRule } from "../shared/group-naming.js";
import {
  BACKEND_AUTH_TOKEN_KEY,
  DEFAULT_BACKEND_URL,
  backendFetch,
  isBackendAuthenticationError,
  normalizeBackendToken,
  normalizeBackendUrl,
  safeBackendUrl,
} from "../shared/backend.js";

const DEFAULT_CONFIG = {
  mode: "backend",
  backendUrl: DEFAULT_BACKEND_URL,
  portalStartUrl: "",
  ssoRegion: "",
  groupNamePattern: "",
  groupNameReplacement: "",
};

const PORTAL_API_ORIGINS = ["https://*.amazonaws.com/*"];
const CONSOLE_ORIGINS = ["https://*.amazon.com/*"];
const BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY =
  "backendSessionReuseAutoOfferHandled";

const el = (id) => document.getElementById(id);

let config = { ...DEFAULT_CONFIG };
let configSaveQueue = Promise.resolve();
let backendRequestController = null;
let backendSessionReuseAutoOfferHandled = false;
let consolePermissionGranted = false;

function setStatus(id, message, ok) {
  const node = el(id);
  node.textContent = message;
  node.className = `status ${ok === undefined ? "" : ok ? "ok" : "error"}`;
}

function setBackendTokenInvalid(invalid) {
  el("backend-token").setAttribute("aria-invalid", String(Boolean(invalid)));
}

function saveConfig(patch) {
  const operation = async () => {
    const nextConfig = { ...config, ...patch };
    await browser.storage.local.set({ config: nextConfig });
    config = nextConfig;
  };
  const result = configSaveQueue.then(operation, operation);
  configSaveQueue = result.catch(() => {});
  return result;
}

function setPermissionButtons(grantId, revokeId, granted) {
  el(grantId).disabled = granted;
  el(revokeId).disabled = !granted;
}

function renderMode() {
  el("mode-backend").checked = config.mode === "backend";
  el("mode-portal").checked = config.mode === "portal";

  for (const panel of document.querySelectorAll("[data-mode-panel]")) {
    const active = panel.dataset.modePanel === config.mode;
    panel.hidden = !active;
    panel.setAttribute("aria-hidden", String(!active));
    for (const control of panel.querySelectorAll("button, input, textarea")) {
      control.disabled = !active;
    }
  }

  if (config.mode === "portal") {
    el("open-portal").disabled = !config.portalStartUrl;
  }
}

function bindMode() {
  for (const id of ["mode-backend", "mode-portal"]) {
    el(id).addEventListener("change", async (event) => {
      if (!event.target.checked) return;
      if (event.target.value === "portal" && backendRequestController) {
        backendRequestController.abort();
      }
      await saveConfig({ mode: event.target.value });
      renderMode();
      if (config.mode === "portal") {
        await Promise.all([refreshPortalPinsStatus(), refreshPortalReadiness()]);
      } else {
        await Promise.all([
          refreshBackendCacheStatus(),
          refreshBackendTokenStatus(),
          refreshConsoleStatus(),
        ]);
      }
    });
  }
}

function backendInputUrl() {
  return normalizeBackendUrl(el("backend-url").value);
}

function formatCacheSummary({ accountsCache, accountsCacheAt }) {
  const count = Array.isArray(accountsCache) ? accountsCache.length : 0;
  if (count === 0) return "No accounts cached";

  const parts = [`${count} account${count === 1 ? "" : "s"} cached`];
  parts.push("from local helper");
  if (Number.isFinite(accountsCacheAt)) {
    parts.push(`updated ${new Date(accountsCacheAt).toLocaleString()}`);
  }
  return parts.join(" · ");
}

async function readAccountsState() {
  return browser.storage.local.get([
    "accountsCache",
    "accountsCacheAt",
  ]);
}

async function refreshBackendCacheStatus() {
  setStatus("backend-accounts-status", formatCacheSummary(await readAccountsState()));
}

async function readStoredBackendToken() {
  const stored = await browser.storage.local.get(BACKEND_AUTH_TOKEN_KEY);
  const value = stored[BACKEND_AUTH_TOKEN_KEY];
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    return normalizeBackendToken(value);
  } catch {
    return null;
  }
}

async function refreshBackendTokenStatus() {
  if (config.mode !== "backend") return;
  let token = null;
  try {
    token = await readStoredBackendToken();
  } catch {
    // A generic status keeps storage failures from exposing stored values.
  }
  setStatus(
    "backend-token-status",
    token
      ? "A helper access token is stored"
      : "No helper access token is stored",
    token ? true : undefined
  );
  setBackendTokenInvalid(false);
}

async function tokenForBackendRequest({ allowEnteredToken }) {
  const entered = allowEnteredToken ? el("backend-token").value : "";
  if (entered.trim()) {
    try {
      return normalizeBackendToken(entered);
    } catch {
      setBackendTokenInvalid(true);
      setStatus("backend-token-status", "The helper access token is invalid", false);
      setStatus("backend-status", "Enter the 43-character token from server.py --show-token", false);
      return null;
    }
  }

  let stored = null;
  try {
    stored = await readStoredBackendToken();
  } catch {
    // Report the same missing-token state without exposing storage details.
  }
  if (!stored) {
    setBackendTokenInvalid(true);
    setStatus("backend-token-status", "No helper access token is stored", false);
    setStatus("backend-status", "Helper access token required", false);
    return null;
  }
  return stored;
}

function backendAccountState(accounts) {
  return {
    accountsCache: accounts,
    accountsCacheAt: Date.now(),
    accountsCacheSource: "backend",
  };
}

function commitBackendConnection(url, token, accounts) {
  const operation = async () => {
    if (config.mode !== "backend") return false;
    const nextConfig = { ...config, backendUrl: url };
    await browser.storage.local.set({
      config: nextConfig,
      [BACKEND_AUTH_TOKEN_KEY]: token,
      ...backendAccountState(accounts),
      ...(backendSessionReuseAutoOfferHandled
        ? { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: true }
        : {}),
    });
    config = nextConfig;
    return true;
  };
  const result = configSaveQueue.then(operation, operation);
  configSaveQueue = result.catch(() => {});
  return result;
}

async function refreshBackendAccounts({ saveUrl }) {
  // This guard is the Options-page half of the no-backend Portal contract.
  if (config.mode !== "backend") return;

  let url;
  try {
    url = saveUrl ? backendInputUrl() : normalizeBackendUrl(config.backendUrl);
  } catch (err) {
    setStatus("backend-status", err.message, false);
    return;
  }
  if (backendRequestController) backendRequestController.abort();
  const controller = new AbortController();
  backendRequestController = controller;

  const buttons = [el("backend-save"), el("backend-refresh")];
  for (const button of buttons) button.disabled = true;
  setStatus("backend-status", saveUrl ? "Testing local helper…" : "Refreshing accounts…");
  try {
    const token = await tokenForBackendRequest({ allowEnteredToken: saveUrl });
    if (!token) return;
    if (controller.signal.aborted || config.mode !== "backend") return;

    const response = await backendFetch(`${url}/accounts`, token, {
      signal: controller.signal,
    });
    if (response.status === 401) {
      setBackendTokenInvalid(true);
      setStatus("backend-token-status", "The helper access token was rejected", false);
      setStatus("backend-status", "Authentication failed", false);
      return;
    }
    if (response.status === 403) {
      setStatus("backend-status", "The local helper rejected this request", false);
      return;
    }
    if (!response.ok) {
      setStatus("backend-status", `Local helper returned HTTP ${response.status}`, false);
      return;
    }

    let accounts;
    try {
      accounts = await response.json();
    } catch {
      setStatus("backend-status", "Local helper returned an unexpected response", false);
      return;
    }
    if (!Array.isArray(accounts)) {
      setStatus("backend-status", "Local helper returned an unexpected response", false);
      return;
    }
    if (controller.signal.aborted || config.mode !== "backend") return;
    setBackendTokenInvalid(false);

    if (saveUrl) {
      let committed;
      try {
        committed = await commitBackendConnection(url, token, accounts);
      } catch {
        setStatus("backend-status", "Helper connected, but settings could not be saved", false);
        return;
      }
      if (!committed) return;
      el("backend-url").value = url;
      el("backend-token").value = "";
      await refreshBackendTokenStatus();
    } else {
      try {
        await browser.storage.local.set(backendAccountState(accounts));
      } catch {
        setStatus("backend-status", "Helper connected, but the account cache could not be updated", false);
        return;
      }
    }
    setStatus("backend-status", `Connected to local helper · ${accounts.length} accounts refreshed`, true);
    await refreshBackendCacheStatus();
  } catch (err) {
    if (err && err.name === "AbortError") return;
    if (isBackendAuthenticationError(err)) {
      setBackendTokenInvalid(true);
      setStatus("backend-token-status", "The helper access token was rejected", false);
      setStatus("backend-status", "Helper authentication failed", false);
      return;
    }
    setStatus("backend-status", "Local helper is unreachable", false);
  } finally {
    if (backendRequestController === controller) {
      backendRequestController = null;
      for (const button of buttons) button.disabled = config.mode !== "backend";
    }
  }
}

function bindBackend() {
  el("backend-url").value = config.backendUrl;
  // A stored authentication value is deliberately never copied into the DOM.
  el("backend-token").value = "";
  setBackendTokenInvalid(false);
  el("backend-token").addEventListener("input", () => {
    setBackendTokenInvalid(false);
  });
  el("backend-save").addEventListener("click", () => {
    if (config.mode !== "backend") return;
    beginBackendSessionReuseAutoOffer();
    void refreshBackendAccounts({ saveUrl: true });
  });
  el("backend-refresh").addEventListener("click", () => {
    void refreshBackendAccounts({ saveUrl: false });
  });
}

function renderRoleDiscoveryStatus(granted) {
  setPermissionButtons("role-discovery-grant", "role-discovery-revoke", granted);
  setStatus(
    "role-discovery-status",
    granted
      ? "Allowed — Containoodle can load role choices for pinned accounts"
      : "Not allowed — pinning and normal portal clicks still work",
    granted || undefined
  );
}

function renderConsoleStatus(granted) {
  setPermissionButtons("console-grant", "console-revoke", granted);
  setStatus(
    "console-status",
    granted
      ? "Enabled — repeated backend launches can reuse a signed-in session"
      : "Disabled — normal backend launches still work",
    granted || undefined
  );
}

function markBackendSessionReuseAutoOfferHandled() {
  if (backendSessionReuseAutoOfferHandled) return;
  backendSessionReuseAutoOfferHandled = true;
  try {
    void browser.storage.local.set({
      [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: true,
    }).catch(() => {});
  } catch {
    // The in-memory marker still prevents another prompt on this page.
  }
}

function beginBackendSessionReuseAutoOffer() {
  if (
    config.mode !== "backend" ||
    backendSessionReuseAutoOfferHandled ||
    consolePermissionGranted
  ) {
    return;
  }

  // Mark first, then invoke request directly in the click handler's call stack
  // so Firefox recognizes the user gesture. This optional prompt must never
  // delay or determine the helper connection result.
  markBackendSessionReuseAutoOfferHandled();
  let request;
  try {
    request = browser.permissions.request({ origins: CONSOLE_ORIGINS });
  } catch (err) {
    setStatus(
      "console-status",
      err.message || "Could not request session reuse permission",
      false,
    );
    return;
  }

  void Promise.resolve(request).then((granted) => {
    consolePermissionGranted = Boolean(granted);
    if (config.mode === "backend") renderConsoleStatus(consolePermissionGranted);
  }).catch((err) => {
    if (config.mode === "backend") {
      setStatus(
        "console-status",
        err.message || "Could not request session reuse permission",
        false,
      );
    }
  });
}

async function refreshConsoleStatus() {
  try {
    const granted = await browser.permissions.contains({ origins: CONSOLE_ORIGINS });
    consolePermissionGranted = granted;
    if (granted) markBackendSessionReuseAutoOfferHandled();
    renderConsoleStatus(granted);
  } catch (err) {
    setStatus("console-status", err.message || "Could not inspect console permission", false);
  }
}

async function refreshPortalReadiness() {
  if (config.mode !== "portal") return;

  el("open-portal").disabled = !config.portalStartUrl;
  try {
    const ready = await browser.runtime.sendMessage({ type: "portal-readiness" });
    if (!ready || !ready.ok) {
      throw new Error((ready && ready.error) || "Could not inspect portal readiness");
    }

    renderRoleDiscoveryStatus(ready.roleDiscoveryAccess);

    if (!ready.configured) {
      setStatus("portal-status", "Portal URL not configured");
    } else if (!ready.portalAccess) {
      setStatus("portal-status", "Portal URL saved · portal permission not granted", false);
    } else if (!ready.session) {
      setStatus("portal-status", "Portal access granted · sign in required", false);
    } else {
      setStatus(
        "portal-status",
        "Portal access and source session detected · each launch verifies its container copy",
        true
      );
    }
  } catch (err) {
    setStatus("portal-status", err.message || "Could not inspect portal readiness", false);
  }
}

async function savePortal() {
  if (config.mode !== "portal") return;

  let normalized;
  try {
    normalized = normalizeStartUrl(el("portal-url").value);
  } catch (err) {
    setStatus("portal-status", err.message, false);
    return;
  }

  const previousStartUrl = config.portalStartUrl;
  const previousPattern = previousStartUrl
    ? portalOriginPattern(previousStartUrl)
    : null;
  const nextPattern = portalOriginPattern(normalized);

  try {
    // Start both calls before awaiting so the permission request remains in the
    // button's user gesture while rollback can still distinguish an existing
    // grant from one added by this operation.
    const existingAccess = browser.permissions.contains({ origins: [nextPattern] });
    const requestingAccess = browser.permissions.request({ origins: [nextPattern] });
    const [hadNextAccess, granted] = await Promise.all([existingAccess, requestingAccess]);
    if (!granted) {
      el("portal-url").value = previousStartUrl;
      setStatus(
        "portal-status",
        previousStartUrl
          ? "Permission was declined · the existing portal is unchanged"
          : "Permission was declined · portal URL was not saved",
        false
      );
      return;
    }

    try {
      if (normalized !== previousStartUrl) {
        await saveConfig({ portalStartUrl: normalized });
        if (previousPattern && previousPattern !== nextPattern) {
          await browser.permissions.remove({ origins: [previousPattern] });
        }
      }
    } catch (err) {
      if (config.portalStartUrl === normalized && previousStartUrl !== normalized) {
        await saveConfig({ portalStartUrl: previousStartUrl }).catch(() => {});
      }
      if (!hadNextAccess && nextPattern !== previousPattern) {
        await browser.permissions.remove({ origins: [nextPattern] }).catch(() => {});
      }
      el("portal-url").value = previousStartUrl;
      throw new Error(`Could not save portal access: ${err.message}`);
    }
    el("portal-url").value = normalized;
    el("open-portal").disabled = false;
    await refreshPortalReadiness();
  } catch (err) {
    setStatus("portal-status", err.message, false);
  }
}

async function openPortal() {
  if (config.mode !== "portal") return;

  try {
    const result = await browser.runtime.sendMessage({
      type: "open-portal",
      mode: "portal",
    });
    if (!result || !result.ok) {
      throw new Error((result && result.error) || "Could not open portal");
    }
  } catch (err) {
    setStatus("portal-status", err.message || "Could not open portal", false);
  }
}

async function updatePermission({ origins, grant, statusId }) {
  try {
    const changed = grant
      ? await browser.permissions.request({ origins })
      : await browser.permissions.remove({ origins });
    if (grant && !changed) {
      setStatus(statusId, "Permission was declined", false);
      return;
    }
  } catch (err) {
    setStatus(statusId, err.message || "Permission change failed", false);
    return;
  }

  if (config.mode === "portal") {
    await refreshPortalReadiness();
  } else {
    await refreshConsoleStatus();
  }
}

function bindPortal() {
  el("portal-url").value = config.portalStartUrl;
  el("sso-region").value = config.ssoRegion;

  el("portal-save").addEventListener("click", () => { void savePortal(); });
  el("open-portal").addEventListener("click", () => { void openPortal(); });
  el("portal-refresh").addEventListener("click", () => { void refreshPortalReadiness(); });

  el("role-discovery-grant").addEventListener("click", () => {
    if (config.mode !== "portal") return;
    void updatePermission({
      origins: PORTAL_API_ORIGINS,
      grant: true,
      statusId: "role-discovery-status",
    });
  });
  el("role-discovery-revoke").addEventListener("click", () => {
    if (config.mode !== "portal") return;
    void updatePermission({
      origins: PORTAL_API_ORIGINS,
      grant: false,
      statusId: "role-discovery-status",
    });
  });

  el("role-save").addEventListener("click", async () => {
    if (config.mode !== "portal") return;
    const ssoRegion = el("sso-region").value.trim();
    if (ssoRegion && !REGION_RE.test(ssoRegion)) {
      setStatus("role-settings-status", "Invalid SSO region (expected e.g. eu-west-1)", false);
      return;
    }
    await saveConfig({ ssoRegion });
    await browser.storage.local.remove("portalRegionCache");
    setStatus("role-settings-status", "SSO region override saved", true);
  });
}

function bindConsole() {
  el("console-grant").addEventListener("click", () => {
    if (config.mode !== "backend") return;
    void updatePermission({
      origins: CONSOLE_ORIGINS,
      grant: true,
      statusId: "console-status",
    });
  });
  el("console-revoke").addEventListener("click", () => {
    if (config.mode !== "backend") return;
    void updatePermission({
      origins: CONSOLE_ORIGINS,
      grant: false,
      statusId: "console-status",
    });
  });
}

function bindGroupNaming() {
  el("group-name-pattern").value = config.groupNamePattern;
  el("group-name-replacement").value = config.groupNameReplacement;

  el("group-name-save").addEventListener("click", async () => {
    const pattern = el("group-name-pattern").value;
    const replacement = el("group-name-replacement").value;
    try {
      validateGroupNameRule(pattern, replacement);
      await saveConfig({
        groupNamePattern: pattern,
        groupNameReplacement: replacement,
      });
      setStatus("group-name-status", "Tab group naming saved", true);
    } catch (err) {
      setStatus(
        "group-name-status",
        err.message || "Could not save tab group naming",
        false
      );
    }
  });

  el("group-name-reset").addEventListener("click", async () => {
    try {
      const result = await browser.runtime.sendMessage({ type: "reset-group-titles" });
      if (!result || !result.ok) {
        throw new Error((result && result.error) || "Could not reset tab group titles");
      }
      setStatus("group-name-status", "Existing tab group titles reset to automatic naming", true);
    } catch (err) {
      setStatus(
        "group-name-status",
        err.message || "Could not reset tab group titles",
        false
      );
    }
  });
}

async function refreshPortalPinsStatus() {
  const { portalPinnedAccounts } = await browser.storage.local.get("portalPinnedAccounts");
  const accounts = Array.isArray(portalPinnedAccounts) ? portalPinnedAccounts : [];
  setStatus(
    "portal-pins-status",
    accounts.length === 0
      ? "No accounts pinned yet — open one from the portal, then pin it in the sidebar"
      : `${accounts.length} pinned account${accounts.length === 1 ? "" : "s"} available in the sidebar`
  );
}

async function refreshPermissionStatuses() {
  if (config.mode === "portal") {
    await refreshPortalReadiness();
  } else {
    await refreshConsoleStatus();
  }
}

async function init() {
  const storedState = await browser.storage.local.get([
    "config",
    BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY,
  ]);
  const stored = storedState.config;
  config = { ...DEFAULT_CONFIG, ...(stored || {}) };
  config.backendUrl = safeBackendUrl(config.backendUrl);
  backendSessionReuseAutoOfferHandled =
    storedState[BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY] === true;

  try {
    consolePermissionGranted = await browser.permissions.contains({
      origins: CONSOLE_ORIGINS,
    });
    if (consolePermissionGranted) markBackendSessionReuseAutoOfferHandled();
  } catch {
    // The normal status refresh below reports permission inspection failures.
  }

  bindMode();
  bindBackend();
  bindPortal();
  bindConsole();
  bindGroupNaming();
  renderMode();

  if (config.mode === "portal") {
    await Promise.all([refreshPortalPinsStatus(), refreshPortalReadiness()]);
  } else {
    await Promise.all([
      refreshBackendCacheStatus(),
      refreshBackendTokenStatus(),
      refreshConsoleStatus(),
    ]);
  }

  browser.permissions.onAdded.addListener(() => { void refreshPermissionStatuses(); });
  browser.permissions.onRemoved.addListener(() => { void refreshPermissionStatuses(); });
  if (browser.storage?.onChanged?.addListener) {
    browser.storage.onChanged.addListener((changes, areaName) => {
      if (
        config.mode === "portal" &&
        areaName === "local" &&
        Object.prototype.hasOwnProperty.call(changes, "portalPinnedAccounts")
      ) {
        void refreshPortalPinsStatus();
      }
    });
  }
  if (browser.cookies?.onChanged?.addListener) {
    browser.cookies.onChanged.addListener((change) => {
      if (
        config.mode === "portal" &&
        change.cookie &&
        change.cookie.name === "x-amz-sso_authn" &&
        change.cookie.storeId === "firefox-default"
      ) {
        void refreshPortalReadiness();
      }
    });
  }
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("focus", () => { void refreshPermissionStatuses(); });
  }
}

void init();
