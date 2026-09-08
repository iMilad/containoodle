/* Containoodle Options
 *
 * The selected connection mode owns the visible setup panel. Portal mode never
 * probes the local helper; backend mode never probes the AWS portal. Portal
 * role-choice access and backend session-reuse access stay inside their
 * respective mode panels.
 */

import { normalizeStartUrl, portalOriginPattern } from "../shared/portal.js";
import { message as t, localizeDocument } from "../shared/i18n.js";
import { REGION_RE, safeAccountsError, validateAccounts } from "../shared/accounts.js";
import { validateGroupNameRule } from "../shared/group-naming.js";
import {
  BACKEND_AUTH_TOKEN_KEY,
  BACKEND_SSO_IDENTITY_KEY,
  BACKEND_SSO_PROFILE_KEY,
  DEFAULT_BACKEND_URL,
  backendFetch,
  isBackendAuthenticationError,
  isBackendTimeoutError,
  normalizeBackendSsoIdentityKey,
  normalizeBackendSsoProfile,
  normalizeBackendToken,
  normalizeBackendUrl,
  safeBackendUrl,
} from "../shared/backend.js";
import {
  backendSessionReuseOriginsForRevoke,
  beginExplicitPermissionTransaction,
  classifyBackendSessionReusePermission,
  classifyRoleDiscoveryPermission,
  roleDiscoveryOrigin,
  roleDiscoveryOriginsForRevoke,
  settleExplicitPermissionTransaction,
} from "../shared/permissions.js";
import {
  ONBOARDING_KEY,
  ONBOARDING_STATES,
  isOnboardingPending,
  normalizeOnboardingState,
  onboardingStateForMode,
} from "../shared/onboarding.js";

const DEFAULT_CONFIG = {
  mode: "backend",
  backendUrl: DEFAULT_BACKEND_URL,
  portalStartUrl: "",
  ssoRegion: "",
  groupNamePattern: "",
  groupNameReplacement: "",
};

const BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY =
  "backendSessionReuseAutoOfferHandled";

const el = (id) => document.getElementById(id);

let config = { ...DEFAULT_CONFIG };
let configSaveQueue = Promise.resolve();
let backendRequestController = null;
let backendSsoProfile = "";
let backendSessionReuseAutoOfferHandled = false;
let consolePermissionGranted = false;
// Connection saves and onboarding completion need their own revision. Optional
// permission discovery can legitimately change while one of those saves is in
// flight (for example when the requested portal grant fires permissions.onAdded).
let connectionContextRevision = 0;
// Advances whenever the active mode or a mode-specific permission target
// changes, so an older prompt cannot clean up grants for the new context.
let permissionModeRevision = 0;
let backendSessionReuseClassification = null;
let roleDiscoveryRegion = null;
let roleDiscoveryPermissionTarget = null;
let roleDiscoveryClassification = null;
let lastValidatedRoleDiscoveryPermissionTarget = null;
let portalReadinessSequence = 0;
let onboardingState = null;
let onboardingDismissedForPage = false;
let portalCorePermissionOperations = 0;

function setStatus(id, message, ok) {
  const node = el(id);
  node.textContent = message;
  node.className = `status ${ok === undefined ? "" : ok ? "ok" : "error"}`;
}

function setBackendTokenInvalid(invalid) {
  el("backend-token").setAttribute("aria-invalid", String(Boolean(invalid)));
}

function setBackendSsoProfileInvalid(invalid) {
  el("backend-sso-profile").setAttribute(
    "aria-invalid",
    String(Boolean(invalid)),
  );
}

function saveConfig(
  patch,
  { nextOnboardingState, expectedContext } = {},
) {
  const operation = async () => {
    if (expectedContext) {
      if (!localConnectionContextMatches(expectedContext)) return false;
      if (!await persistedConnectionContextMatches(expectedContext)) return false;
      if (!localConnectionContextMatches(expectedContext)) return false;
    }
    const nextConfig = { ...config, ...patch };
    const values = { config: nextConfig };
    if (nextOnboardingState !== undefined) {
      values[ONBOARDING_KEY] = nextOnboardingState;
    }
    await browser.storage.local.set(values);
    config = nextConfig;
    if (nextOnboardingState !== undefined) {
      onboardingState = normalizeOnboardingState(nextOnboardingState);
    }
    return true;
  };
  const result = configSaveQueue.then(operation, operation);
  configSaveQueue = result.catch(() => {});
  return result;
}

function onboardingIsChoosing() {
  return onboardingState === ONBOARDING_STATES.CHOOSE;
}

function activeModeIs(mode) {
  return !onboardingIsChoosing() && config.mode === mode;
}

function configsMatch(left, right) {
  if (
    !left || typeof left !== "object" || Array.isArray(left) ||
    !right || typeof right !== "object" || Array.isArray(right)
  ) {
    return false;
  }
  const effectiveLeft = { ...DEFAULT_CONFIG, ...left };
  const effectiveRight = { ...DEFAULT_CONFIG, ...right };
  const leftKeys = Object.keys(effectiveLeft);
  const rightKeys = Object.keys(effectiveRight);
  return leftKeys.length === rightKeys.length && leftKeys.every(
    (key) => Object.prototype.hasOwnProperty.call(effectiveRight, key) &&
      effectiveLeft[key] === effectiveRight[key],
  );
}

async function persistedConnectionContextMatches({
  expectedConfig,
  expectedOnboardingState,
}) {
  const stored = await browser.storage.local.get(["config", ONBOARDING_KEY]);
  return configsMatch(stored.config, expectedConfig) &&
    normalizeOnboardingState(stored[ONBOARDING_KEY]) ===
      expectedOnboardingState;
}

function localConnectionContextMatches({
  expectedConfig,
  expectedOnboardingState,
  expectedConnectionRevision,
}) {
  return connectionContextRevision === expectedConnectionRevision &&
    configsMatch(config, expectedConfig) &&
    onboardingState === expectedOnboardingState;
}

function captureConnectionContext() {
  return {
    expectedConfig: { ...config },
    expectedOnboardingState: onboardingState,
    expectedConnectionRevision: connectionContextRevision,
  };
}

function renderOnboarding() {
  const panel = el("onboarding");
  const active = isOnboardingPending(onboardingState) &&
    !onboardingDismissedForPage;
  panel.hidden = !active;
  panel.setAttribute("aria-hidden", String(!active));
  if (!active) return;

  const descriptions = {
    [ONBOARDING_STATES.CHOOSE]:
      t("ui_choose_local_aws_cli_helper_or_aws_access_portal", "Choose Local AWS CLI helper or AWS access portal below. Containoodle will then show only the setup you need."),
    [ONBOARDING_STATES.BACKEND]:
      t("ui_local_helper_is_selected_start_server_py_enter_its", "Local helper is selected. Start server.py, enter its URL and access token, then choose Save & test."),
    [ONBOARDING_STATES.PORTAL]:
      t("ui_aws_access_portal_is_selected_enter_its_start_url", "AWS access portal is selected. Enter its start URL, grant that exact site access, then sign in and refresh readiness."),
  };
  el("onboarding-description").textContent = descriptions[onboardingState] || "";
}

function invalidateRoleDiscoveryTarget() {
  roleDiscoveryRegion = null;
  roleDiscoveryPermissionTarget = null;
  roleDiscoveryClassification = null;
}

function replaceRoleDiscoveryPermissionContext(target) {
  const normalizedTarget = typeof target === "string" ? target : null;
  if (normalizedTarget !== lastValidatedRoleDiscoveryPermissionTarget) {
    permissionModeRevision += 1;
    lastValidatedRoleDiscoveryPermissionTarget = normalizedTarget;
  }
}

function resetRoleDiscoveryPermissionContext() {
  permissionModeRevision += 1;
  portalReadinessSequence += 1;
  lastValidatedRoleDiscoveryPermissionTarget = null;
  invalidateRoleDiscoveryTarget();
}

function renderMode() {
  const choosing = onboardingIsChoosing();
  el("mode-backend").checked = !choosing && config.mode === "backend";
  el("mode-portal").checked = !choosing && config.mode === "portal";

  for (const panel of document.querySelectorAll("[data-mode-panel]")) {
    const active = !choosing && panel.dataset.modePanel === config.mode;
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

function bindOnboarding() {
  el("onboarding-continue").addEventListener("click", () => {
    onboardingDismissedForPage = true;
    renderOnboarding();
    el(config.mode === "portal" ? "mode-portal" : "mode-backend").focus();
  });
}

function bindMode() {
  for (const id of ["mode-backend", "mode-portal"]) {
    el(id).addEventListener("change", async (event) => {
      if (!event.target.checked) return;
      connectionContextRevision += 1;
      resetRoleDiscoveryPermissionContext();
      if (event.target.value === "portal" && backendRequestController) {
        backendRequestController.abort();
      }
      const nextState = isOnboardingPending(onboardingState)
        ? onboardingStateForMode(event.target.value)
        : undefined;
      try {
        await saveConfig(
          { mode: event.target.value },
          { nextOnboardingState: nextState },
        );
      } catch {
        renderMode();
        renderOnboarding();
        if (isOnboardingPending(onboardingState)) {
          setStatus("onboarding-status", t("ui_could_not_save_the_connection_method", "Could not save the connection method"), false);
        }
        return;
      }
      setStatus("onboarding-status", "");
      renderMode();
      renderOnboarding();
      if (config.mode === "portal") {
        await Promise.all([
          refreshPortalPinsStatus(),
          refreshPortalReadinessAutomatically(),
        ]);
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

function backendInputSsoProfile() {
  return normalizeBackendSsoProfile(el("backend-sso-profile").value);
}

function formatCacheSummary({ accountsCache, accountsCacheAt }) {
  const accounts = validateAccounts(accountsCache).accounts;
  const count = accounts ? accounts.length : 0;
  if (count === 0) return t("ui_no_accounts_cached", "No accounts cached");

  const summary = count === 1
    ? t("ui_one_account_cached", "$1 account cached · from local helper", [count])
    : t("ui_many_accounts_cached", "$1 accounts cached · from local helper", [count]);
  return Number.isFinite(accountsCacheAt)
    ? t("ui_cache_updated", "$1 · updated $2", [summary, new Date(accountsCacheAt).toLocaleString()])
    : summary;
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
      ? t("ui_a_helper_access_token_is_stored", "A helper access token is stored")
      : t("ui_no_helper_access_token_is_stored", "No helper access token is stored"),
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
      setStatus("backend-token-status", t("ui_the_helper_access_token_is_invalid", "The helper access token is invalid"), false);
      setStatus("backend-status", t("ui_enter_the_43_character_token_from_server_py_show", "Enter the 43-character token from server.py --show-token"), false);
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
    setStatus("backend-token-status", t("ui_no_helper_access_token_is_stored", "No helper access token is stored"), false);
    setStatus("backend-status", t("ui_helper_access_token_required", "Helper access token required"), false);
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

async function backendErrorMessage(response, { accountsOnly = false } = {}) {
  const fallback = t("ui_local_helper_returned_http_value", "Local helper returned HTTP $1", [response.status]);
  let payload;
  try {
    payload = await response.json();
  } catch {
    return fallback;
  }
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    Object.keys(payload).join("\n") !== "error" ||
    typeof payload.error !== "string" ||
    !payload.error ||
    payload.error.length > 256 ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(payload.error)
  ) {
    return fallback;
  }
  return accountsOnly ? safeAccountsError(payload) || fallback : payload.error;
}

function commitBackendConnection(
  url,
  token,
  profile,
  identityKey,
  accounts,
  requestContext,
) {
  const operation = async () => {
    if (
      config.mode !== "backend" ||
      !localConnectionContextMatches(requestContext)
    ) {
      return false;
    }
    const completesOnboarding =
      requestContext.expectedOnboardingState === ONBOARDING_STATES.BACKEND;
    if (
      completesOnboarding &&
      !await persistedConnectionContextMatches(requestContext)
    ) {
      return false;
    }
    if (!localConnectionContextMatches(requestContext)) return false;

    const nextConfig = { ...config, backendUrl: url };
    await browser.storage.local.set({
      config: nextConfig,
      [BACKEND_AUTH_TOKEN_KEY]: token,
      [BACKEND_SSO_PROFILE_KEY]: profile,
      [BACKEND_SSO_IDENTITY_KEY]: identityKey,
      ...backendAccountState(accounts),
      ...(backendSessionReuseAutoOfferHandled
        ? { [BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY]: true }
        : {}),
      ...(completesOnboarding
        ? { [ONBOARDING_KEY]: ONBOARDING_STATES.COMPLETE }
        : {}),
    });
    config = nextConfig;
    backendSsoProfile = profile;
    if (completesOnboarding) {
      onboardingState = ONBOARDING_STATES.COMPLETE;
    }
    return true;
  };
  const result = configSaveQueue.then(operation, operation);
  configSaveQueue = result.catch(() => {});
  return result;
}

async function refreshBackendAccounts({ saveUrl }) {
  // This guard is the Options-page half of the no-backend Portal contract.
  if (!activeModeIs("backend")) return;
  const requestContext = captureConnectionContext();

  let url;
  let profile = null;
  try {
    url = saveUrl ? backendInputUrl() : normalizeBackendUrl(config.backendUrl);
  } catch (err) {
    setStatus("backend-status", err.message, false);
    return;
  }
  if (saveUrl) {
    try {
      profile = backendInputSsoProfile();
      setBackendSsoProfileInvalid(false);
    } catch (err) {
      setBackendSsoProfileInvalid(true);
      setStatus("backend-status", err.message, false);
      return;
    }
  }
  if (backendRequestController) backendRequestController.abort();
  const controller = new AbortController();
  backendRequestController = controller;

  const buttons = [el("backend-save"), el("backend-refresh")];
  for (const button of buttons) button.disabled = true;
  setStatus("backend-status", saveUrl ? t("ui_testing_local_helper", "Testing local helper…") : t("ui_refreshing_accounts", "Refreshing accounts…"));
  try {
    const token = await tokenForBackendRequest({ allowEnteredToken: saveUrl });
    if (!token) return;
    if (controller.signal.aborted || config.mode !== "backend") return;

    let identityKey = null;
    if (saveUrl) {
      const identityUrl = new URL(`${url}/sso-identity`);
      if (profile) identityUrl.searchParams.set("profile", profile);
      const identityResponse = await backendFetch(identityUrl.href, token, {
        signal: controller.signal,
      });
      if (identityResponse.status === 401) {
        setBackendTokenInvalid(true);
        setStatus("backend-token-status", t("ui_the_helper_access_token_was_rejected", "The helper access token was rejected"), false);
        setStatus(
          "backend-status",
          await backendErrorMessage(identityResponse),
          false,
        );
        return;
      }
      if (!identityResponse.ok) {
        setStatus(
          "backend-status",
          await backendErrorMessage(identityResponse),
          false,
        );
        return;
      }

      let identity;
      try {
        identity = await identityResponse.json();
        if (
          !identity ||
          typeof identity !== "object" ||
          Array.isArray(identity) ||
          Object.keys(identity).sort().join("\n") !== "identityKey\nok" ||
          identity.ok !== true
        ) {
          throw new Error("invalid identity response");
        }
        identityKey = normalizeBackendSsoIdentityKey(identity.identityKey);
      } catch {
        setStatus("backend-status", t("ui_local_helper_returned_an_unexpected_response", "Local helper returned an unexpected response"), false);
        return;
      }
      if (controller.signal.aborted || config.mode !== "backend") return;
    }

    const response = await backendFetch(`${url}/accounts`, token, {
      signal: controller.signal,
    });
    if (response.status === 401) {
      setBackendTokenInvalid(true);
      setStatus("backend-token-status", t("ui_the_helper_access_token_was_rejected", "The helper access token was rejected"), false);
      setStatus("backend-status", t("ui_authentication_failed", "Authentication failed"), false);
      return;
    }
    if (response.status === 403) {
      setStatus("backend-status", t("ui_the_local_helper_rejected_this_request", "The local helper rejected this request"), false);
      return;
    }
    if (!response.ok) {
      setStatus("backend-status", await backendErrorMessage(response, { accountsOnly: true }), false);
      return;
    }

    let accounts;
    try {
      accounts = await response.json();
    } catch {
      setStatus("backend-status", t("ui_local_helper_returned_an_unexpected_response", "Local helper returned an unexpected response"), false);
      return;
    }
    if (validateAccounts(accounts).errors.length) {
      setStatus("backend-status", t("ui_local_helper_returned_an_unexpected_response", "Local helper returned an unexpected response"), false);
      return;
    }
    if (controller.signal.aborted || config.mode !== "backend") return;
    setBackendTokenInvalid(false);

    if (saveUrl) {
      let committed;
      try {
        committed = await commitBackendConnection(
          url,
          token,
          profile,
          identityKey,
          accounts,
          requestContext,
        );
      } catch {
        setStatus("backend-status", t("ui_helper_connected_but_settings_could_not_be_saved", "Helper connected, but settings could not be saved"), false);
        return;
      }
      if (!committed) {
        if (localConnectionContextMatches(requestContext)) {
          setStatus(
            "backend-status",
            t("ui_connection_settings_changed_elsewhere_review_them_and_try_again", "Connection settings changed elsewhere · review them and try again"),
            false,
          );
        }
        return;
      }
      renderOnboarding();
      el("backend-url").value = url;
      el("backend-token").value = "";
      el("backend-sso-profile").value = profile;
      await refreshBackendTokenStatus();
    } else {
      try {
        await browser.storage.local.set(backendAccountState(accounts));
      } catch {
        setStatus("backend-status", t("ui_helper_connected_but_the_account_cache_could_not_be", "Helper connected, but the account cache could not be updated"), false);
        return;
      }
    }
    setStatus("backend-status", t("ui_connected_to_local_helper_value_accounts_refreshed", "Connected to local helper · $1 accounts refreshed", [accounts.length]), true);
    await refreshBackendCacheStatus();
  } catch (err) {
    if (err && err.name === "AbortError") return;
    if (isBackendTimeoutError(err)) {
      setStatus("backend-status", t("ui_local_helper_timed_out_check_server_py_and_try_again", "Local helper timed out. Check server.py and try again."), false);
      return;
    }
    if (isBackendAuthenticationError(err)) {
      setBackendTokenInvalid(true);
      setStatus("backend-token-status", t("ui_the_helper_access_token_was_rejected", "The helper access token was rejected"), false);
      setStatus("backend-status", t("ui_helper_authentication_failed", "Helper authentication failed"), false);
      return;
    }
    setStatus("backend-status", t("ui_local_helper_is_unreachable", "Local helper is unreachable"), false);
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
  el("backend-sso-profile").value = backendSsoProfile;
  setBackendTokenInvalid(false);
  setBackendSsoProfileInvalid(false);
  el("backend-token").addEventListener("input", () => {
    setBackendTokenInvalid(false);
  });
  el("backend-sso-profile").addEventListener("input", () => {
    setBackendSsoProfileInvalid(false);
  });
  el("backend-save").addEventListener("click", () => {
    if (!activeModeIs("backend")) return;
    beginBackendSessionReuseAutoOffer();
    void refreshBackendAccounts({ saveUrl: true });
  });
  el("backend-refresh").addEventListener("click", () => {
    void refreshBackendAccounts({ saveUrl: false });
  });
}

function hasManagedGrant(classification) {
  return Boolean(
    classification && (
      classification.targetGranted ||
      classification.legacyGranted ||
      classification.staleOrigins.length > 0
    )
  );
}

function renderRoleDiscoveryStatus(
  classification,
  { managedWithoutTarget = false, portalSession = false } = {},
) {
  const targetReady = Boolean(roleDiscoveryPermissionTarget && classification);
  const grant = el("role-discovery-grant");
  const revoke = el("role-discovery-revoke");
  const cleanupPending = Boolean(classification && classification.cleanupPending);
  const legacyOnly = Boolean(
    classification && classification.legacyGranted && !classification.targetGranted
  );
  grant.textContent = cleanupPending
    ? t("ui_finish_tightening", "Finish tightening")
    : legacyOnly
      ? t("ui_tighten_access", "Tighten access")
      : t("ui_allow_role_choices", "Allow role choices");
  grant.disabled = !targetReady || Boolean(
    classification.targetGranted && !cleanupPending
  );
  revoke.disabled = !(hasManagedGrant(classification) || managedWithoutTarget);

  if (!targetReady) {
    setStatus(
      "role-discovery-status",
      managedWithoutTarget
        ? portalSession
          ? t("ui_a_previously_granted_role_access_permission_is_still_stored", "A previously granted role-access permission is still stored · set the SSO region below to tighten it, or revoke it now")
          : t("ui_existing_role_access_is_still_granted_sign_in_and", "Existing role access is still granted · sign in and refresh to tighten it, or revoke it now")
        : portalSession
          ? t("ui_portal_session_detected_but_the_sso_region_could_not", "Portal session detected, but the SSO region could not be detected · set it under Advanced: SSO region override")
          : t("ui_sign_in_and_refresh_readiness_before_allowing_role_choices", "Sign in and refresh readiness before allowing role choices"),
      managedWithoutTarget || undefined,
    );
  } else if (cleanupPending) {
    setStatus(
      "role-discovery-status",
      t("ui_allowed_finish_tightening_to_remove_older_broad_access", "Allowed · finish tightening to remove older broad access"),
      true,
    );
  } else if (legacyOnly) {
    setStatus(
      "role-discovery-status",
      t("ui_allowed_with_older_broad_access_tighten_it_without_affecting", "Allowed with older broad access · tighten it without affecting portal clicks"),
      true,
    );
  } else {
    setStatus(
      "role-discovery-status",
      classification.effectiveGranted
        ? t("ui_allowed_containoodle_can_load_role_choices_for_pinned_accounts", "Allowed — Containoodle can load role choices for favorites")
        : t("ui_not_allowed_pinning_and_normal_portal_clicks_still_work", "Not allowed — pinning and normal portal clicks still work"),
      classification.effectiveGranted || undefined,
    );
  }
}

function renderConsoleStatus(classification) {
  const grant = el("console-grant");
  const revoke = el("console-revoke");
  const cleanupPending = Boolean(classification && classification.cleanupPending);
  const legacyOnly = Boolean(
    classification && classification.legacyGranted && !classification.targetGranted
  );
  grant.textContent = cleanupPending
    ? t("ui_finish_tightening", "Finish tightening")
    : legacyOnly
      ? t("ui_tighten_access", "Tighten access")
      : t("ui_allow_session_reuse", "Allow session reuse");
  grant.disabled = !classification || Boolean(
    classification.targetGranted && !cleanupPending
  );
  revoke.disabled = !hasManagedGrant(classification);

  if (cleanupPending) {
    setStatus(
      "console-status",
      t("ui_enabled_finish_tightening_to_remove_older_broad_access", "Enabled · finish tightening to remove older broad access"),
      true,
    );
  } else if (legacyOnly) {
    setStatus(
      "console-status",
      t("ui_enabled_with_older_broad_access_tighten_it_without_blocking", "Enabled with older broad access · tighten it without blocking normal launches"),
      true,
    );
  } else {
    setStatus(
      "console-status",
      classification && classification.effectiveGranted
        ? t("ui_enabled_repeated_backend_launches_can_reuse_a_signed_in", "Enabled — repeated backend launches can reuse a signed-in session")
        : t("ui_disabled_normal_backend_launches_still_work", "Disabled — normal backend launches still work"),
      classification && classification.effectiveGranted || undefined,
    );
  }
}

async function grantedPermissionOrigins() {
  const granted = await browser.permissions.getAll();
  return Array.isArray(granted && granted.origins) ? granted.origins : [];
}

function beginPermissionGrant({ feature, mode, classification, classify, statusId }) {
  let transaction;
  try {
    transaction = beginExplicitPermissionTransaction({
      trigger: "user-action",
      feature,
      mode,
      modeRevision: permissionModeRevision,
      classification,
    });
  } catch (err) {
    setStatus(statusId, err.message || t("ui_permission_change_failed", "Permission change failed"), false);
    return;
  }

  // This call must remain in the direct click-handler stack. Do not await an
  // inventory, storage read, or message before starting the Firefox prompt.
  let request = null;
  try {
    if (transaction.requestOrigins.length > 0) {
      request = browser.permissions.request({
        origins: transaction.requestOrigins,
      });
    }
  } catch (err) {
    setStatus(statusId, err.message || t("ui_permission_change_failed", "Permission change failed"), false);
    return;
  }

  void finishPermissionGrant({
    transaction,
    request,
    classify,
    statusId,
  });
}

async function finishPermissionGrant({ transaction, request, classify, statusId }) {
  let requestOutcome = "not-needed";
  let requestError = null;
  if (request) {
    try {
      requestOutcome = await request ? "accepted" : "declined";
    } catch (err) {
      requestOutcome = "error";
      requestError = err;
    }
  }

  let decision;
  try {
    const classification = classify(await grantedPermissionOrigins());
    decision = settleExplicitPermissionTransaction(transaction, {
      requestOutcome,
      currentMode: config.mode,
      currentModeRevision: permissionModeRevision,
      classification,
    });
    if (decision.removeOrigins.length > 0) {
      await browser.permissions.remove({ origins: decision.removeOrigins });
    }
  } catch (err) {
    const message = err.message || t("ui_permission_change_failed", "Permission change failed");
    await refreshPermissionStatuses();
    if (
      config.mode === transaction.expectedMode &&
      permissionModeRevision === transaction.expectedModeRevision
    ) {
      setStatus(statusId, message, false);
    }
    return;
  }

  await refreshPermissionStatuses();
  if (
    config.mode !== transaction.expectedMode ||
    permissionModeRevision !== transaction.expectedModeRevision
  ) return;
  if (decision.state === "declined") {
    setStatus(statusId, t("ui_permission_was_declined", "Permission was declined"), false);
  } else if (decision.state === "request-error") {
    setStatus(
      statusId,
      requestError && requestError.message || t("ui_permission_request_failed", "Permission request failed"),
      false,
    );
  } else if (decision.state === "target-not-literal") {
    setStatus(
      statusId,
      t("ui_firefox_kept_the_older_broad_grant_revoke_then_allow", "Firefox kept the older broad grant · revoke, then allow again to finish tightening"),
      true,
    );
  }
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
    !activeModeIs("backend") ||
    backendSessionReuseAutoOfferHandled ||
    consolePermissionGranted ||
    !backendSessionReuseClassification
  ) {
    return;
  }

  // Mark first, then invoke request directly in the click handler's call stack
  // so Firefox recognizes the user gesture. This optional prompt must never
  // delay or determine the helper connection result.
  markBackendSessionReuseAutoOfferHandled();
  beginPermissionGrant({
    feature: "backend-session-reuse",
    mode: "backend",
    classification: backendSessionReuseClassification,
    classify: classifyBackendSessionReusePermission,
    statusId: "console-status",
  });
}

async function refreshConsoleStatus() {
  try {
    const classification = classifyBackendSessionReusePermission(
      await grantedPermissionOrigins(),
    );
    backendSessionReuseClassification = classification;
    consolePermissionGranted = classification.effectiveGranted;
    if (consolePermissionGranted) markBackendSessionReuseAutoOfferHandled();
    renderConsoleStatus(classification);
  } catch (err) {
    setStatus("console-status", err.message || t("ui_could_not_inspect_console_permission", "Could not inspect console permission"), false);
  }
}

async function completePortalOnboarding({
  ready,
  grantedOrigins,
  sequence,
  portalStartUrl,
  requestContext,
}) {
  if (
    onboardingState !== ONBOARDING_STATES.PORTAL ||
    !ready.configured ||
    !ready.portalAccess ||
    !ready.session ||
    ready.mode !== "portal"
  ) {
    return false;
  }

  let exactOrigin;
  try {
    exactOrigin = portalOriginPattern(portalStartUrl);
  } catch {
    return false;
  }
  if (!grantedOrigins.includes(exactOrigin)) return false;

  const operation = async () => {
    if (
      !localConnectionContextMatches(requestContext) ||
      onboardingState !== ONBOARDING_STATES.PORTAL ||
      config.mode !== "portal" ||
      config.portalStartUrl !== portalStartUrl ||
      portalReadinessSequence !== sequence
    ) {
      return false;
    }
    if (!await persistedConnectionContextMatches(requestContext)) return false;
    if (
      !localConnectionContextMatches(requestContext) ||
      portalReadinessSequence !== sequence
    ) {
      return false;
    }
    await browser.storage.local.set({
      [ONBOARDING_KEY]: ONBOARDING_STATES.COMPLETE,
    });
    onboardingState = ONBOARDING_STATES.COMPLETE;
    return true;
  };
  const result = configSaveQueue.then(operation, operation);
  configSaveQueue = result.catch(() => {});
  try {
    const completed = await result;
    if (completed) {
      renderOnboarding();
    }
    return completed;
  } catch {
    if (
      onboardingState === ONBOARDING_STATES.PORTAL &&
      config.mode === "portal" &&
      portalReadinessSequence === sequence
    ) {
      setStatus("onboarding-status", t("ui_connection_is_ready_but_setup_status_could_not_be", "Connection is ready, but setup status could not be saved"), false);
    }
    return false;
  }
}

async function refreshPortalReadiness({ allowRemoteRegionLookup = true } = {}) {
  if (config.mode !== "portal") return;

  const sequence = ++portalReadinessSequence;
  const readinessRevision = permissionModeRevision;
  invalidateRoleDiscoveryTarget();
  el("open-portal").disabled = !config.portalStartUrl;
  try {
    const ready = await browser.runtime.sendMessage({
      type: "portal-readiness",
      ...(allowRemoteRegionLookup ? {} : { allowRemoteRegionLookup: false }),
    });
    if (!ready || !ready.ok) {
      throw new Error((ready && ready.error) || t("ui_could_not_inspect_portal_readiness", "Could not inspect portal readiness"));
    }
    if (
      config.mode !== "portal" ||
      permissionModeRevision !== readinessRevision ||
      portalReadinessSequence !== sequence
    ) {
      return;
    }

    const grantedOrigins = await grantedPermissionOrigins();
    let validTarget = null;
    if (
      typeof ready.roleDiscoveryRegion === "string" &&
      typeof ready.roleDiscoveryPermissionOrigin === "string"
    ) {
      try {
        const expected = roleDiscoveryOrigin(ready.roleDiscoveryRegion);
        if (expected === ready.roleDiscoveryPermissionOrigin) {
          validTarget = expected;
        }
      } catch {
        validTarget = null;
      }
    }
    if (
      config.mode !== "portal" ||
      permissionModeRevision !== readinessRevision ||
      portalReadinessSequence !== sequence
    ) {
      return;
    }
    replaceRoleDiscoveryPermissionContext(validTarget);
    if (validTarget) {
      roleDiscoveryRegion = ready.roleDiscoveryRegion;
      roleDiscoveryPermissionTarget = validTarget;
      roleDiscoveryClassification = classifyRoleDiscoveryPermission(
        grantedOrigins,
        roleDiscoveryRegion,
      );
      renderRoleDiscoveryStatus(roleDiscoveryClassification);
    } else {
      renderRoleDiscoveryStatus(null, {
        managedWithoutTarget:
          roleDiscoveryOriginsForRevoke(grantedOrigins).length > 0,
        portalSession: Boolean(ready.session),
      });
    }

    if (!ready.configured) {
      setStatus("portal-status", t("ui_portal_url_not_configured", "Portal URL not configured"));
    } else if (!ready.portalAccess) {
      setStatus("portal-status", t("ui_portal_url_saved_portal_permission_not_granted", "Portal URL saved · portal permission not granted"), false);
    } else if (!ready.session) {
      setStatus("portal-status", t("ui_portal_access_granted_sign_in_required", "Portal access granted · sign in required"), false);
    } else {
      setStatus(
        "portal-status",
        t("ui_portal_access_and_source_session_detected_each_launch_verifies", "Portal access and source session detected · each launch verifies its container copy"),
        true
      );
    }
    await completePortalOnboarding({
      ready,
      grantedOrigins,
      sequence,
      portalStartUrl: config.portalStartUrl,
      requestContext: captureConnectionContext(),
    });
  } catch (err) {
    if (
      config.mode === "portal" &&
      permissionModeRevision === readinessRevision &&
      portalReadinessSequence === sequence
    ) {
      replaceRoleDiscoveryPermissionContext(null);
      setStatus(
        "portal-status",
        err.message || t("ui_could_not_inspect_portal_readiness", "Could not inspect portal readiness"),
        false,
      );
    }
  }
}

function refreshPortalReadinessAutomatically() {
  return refreshPortalReadiness({
    allowRemoteRegionLookup: !isOnboardingPending(onboardingState),
  });
}

async function savePortal() {
  if (config.mode !== "portal") return;
  const requestContext = captureConnectionContext();

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

  portalCorePermissionOperations += 1;
  try {
    // Start both calls before awaiting so the permission request remains in the
    // button's user gesture while rollback can still distinguish an existing
    // grant from one added by this operation.
    const existingAccess = browser.permissions.contains({ origins: [nextPattern] });
    const requestingAccess = browser.permissions.request({ origins: [nextPattern] });
    const [hadNextAccess, granted] = await Promise.all([existingAccess, requestingAccess]);
    let contextStillCurrent = localConnectionContextMatches(requestContext);
    try {
      if (contextStillCurrent) {
        contextStillCurrent = await persistedConnectionContextMatches(requestContext);
      }
    } catch (err) {
      if (granted && !hadNextAccess) {
        await browser.permissions.remove({ origins: [nextPattern] }).catch(() => {});
      }
      throw err;
    }
    if (!contextStillCurrent) {
      if (granted && !hadNextAccess) {
        await browser.permissions.remove({ origins: [nextPattern] }).catch(() => {});
      }
      return;
    }
    if (!granted) {
      el("portal-url").value = previousStartUrl;
      setStatus(
        "portal-status",
        previousStartUrl
          ? t("ui_permission_was_declined_the_existing_portal_is_unchanged", "Permission was declined · the existing portal is unchanged")
          : t("ui_permission_was_declined_portal_url_was_not_saved", "Permission was declined · portal URL was not saved"),
        false
      );
      return;
    }

    try {
      if (normalized !== previousStartUrl) {
        const saved = await saveConfig(
          { portalStartUrl: normalized },
          { expectedContext: requestContext },
        );
        if (!saved) {
          if (!hadNextAccess) {
            await browser.permissions.remove({ origins: [nextPattern] }).catch(() => {});
          }
          return;
        }
        connectionContextRevision += 1;
        resetRoleDiscoveryPermissionContext();
        await browser.storage.local.remove([
          "portalRegionCache",
          "portalRegionCacheOrigin",
        ]);
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
      throw new Error(t("ui_could_not_save_portal_access_value", "Could not save portal access: $1", [err.message]));
    }
    el("portal-url").value = normalized;
    el("open-portal").disabled = false;
    await refreshPortalReadiness();
  } catch (err) {
    setStatus("portal-status", err.message, false);
  } finally {
    portalCorePermissionOperations -= 1;
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
      throw new Error((result && result.error) || t("ui_could_not_open_portal", "Could not open portal"));
    }
  } catch (err) {
    setStatus("portal-status", err.message || t("ui_could_not_open_portal", "Could not open portal"), false);
  }
}

async function revokeManagedPermission({ mode, originsForRevoke, statusId }) {
  const revision = permissionModeRevision;
  try {
    const origins = originsForRevoke(await grantedPermissionOrigins());
    if (config.mode !== mode || permissionModeRevision !== revision) return;
    if (origins.length > 0) {
      await browser.permissions.remove({ origins });
    }
  } catch (err) {
    setStatus(statusId, err.message || t("ui_permission_change_failed", "Permission change failed"), false);
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
    const region = roleDiscoveryRegion;
    const classification = roleDiscoveryClassification;
    if (!roleDiscoveryPermissionTarget || !region || !classification) {
      setStatus(
        "role-discovery-status",
        t("ui_sign_in_and_refresh_readiness_before_allowing_role_choices", "Sign in and refresh readiness before allowing role choices"),
        false,
      );
      return;
    }
    beginPermissionGrant({
      feature: "role-discovery",
      mode: "portal",
      classification,
      classify: (origins) => classifyRoleDiscoveryPermission(
        origins,
        region,
      ),
      statusId: "role-discovery-status",
    });
  });
  el("role-discovery-revoke").addEventListener("click", () => {
    if (config.mode !== "portal") return;
    void revokeManagedPermission({
      mode: "portal",
      originsForRevoke: roleDiscoveryOriginsForRevoke,
      statusId: "role-discovery-status",
    });
  });

  el("role-save").addEventListener("click", async () => {
    if (config.mode !== "portal") return;
    const ssoRegion = el("sso-region").value.trim();
    if (ssoRegion && !REGION_RE.test(ssoRegion)) {
      setStatus("role-settings-status", t("ui_invalid_sso_region_expected_e_g_eu_west_1", "Invalid SSO region (expected e.g. eu-west-1)"), false);
      return;
    }
    connectionContextRevision += 1;
    resetRoleDiscoveryPermissionContext();
    await saveConfig({ ssoRegion });
    await browser.storage.local.remove([
      "portalRegionCache",
      "portalRegionCacheOrigin",
    ]);
    await refreshPortalReadiness();
    setStatus("role-settings-status", t("ui_sso_region_override_saved", "SSO region override saved"), true);
  });
}

function bindConsole() {
  el("console-grant").addEventListener("click", () => {
    if (!activeModeIs("backend")) return;
    if (!backendSessionReuseClassification) return;
    beginPermissionGrant({
      feature: "backend-session-reuse",
      mode: "backend",
      classification: backendSessionReuseClassification,
      classify: classifyBackendSessionReusePermission,
      statusId: "console-status",
    });
  });
  el("console-revoke").addEventListener("click", () => {
    if (!activeModeIs("backend")) return;
    void revokeManagedPermission({
      mode: "backend",
      originsForRevoke: backendSessionReuseOriginsForRevoke,
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
      setStatus("group-name-status", t("ui_account_display_naming_saved", "Account display naming saved"), true);
    } catch (err) {
      setStatus(
        "group-name-status",
        err.message || t("ui_could_not_save_account_display_naming", "Could not save account display naming"),
        false
      );
    }
  });

  el("group-name-reset").addEventListener("click", async () => {
    try {
      const result = await browser.runtime.sendMessage({ type: "reset-group-titles" });
      if (!result || !result.ok) {
        throw new Error((result && result.error) || t("ui_could_not_reset_tab_group_titles", "Could not reset tab group titles"));
      }
      setStatus("group-name-status", t("ui_existing_tab_group_titles_reset_to_automatic_naming", "Existing tab group titles reset to automatic naming"), true);
    } catch (err) {
      setStatus(
        "group-name-status",
        err.message || t("ui_could_not_reset_tab_group_titles", "Could not reset tab group titles"),
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
      ? t("ui_no_accounts_pinned_yet_open_one_from_the_portal", "No favorites yet — open an account from the portal, then choose ☆ in the sidebar")
      : accounts.length === 1
        ? t("ui_one_pinned_account", "$1 favorite available in the sidebar", [accounts.length])
        : t("ui_many_pinned_accounts", "$1 favorites available in the sidebar", [accounts.length])
  );
}

async function refreshPermissionStatuses() {
  if (onboardingIsChoosing()) return;
  if (config.mode === "portal") {
    await refreshPortalReadinessAutomatically();
  } else {
    await refreshConsoleStatus();
  }
}

function applyStoredConnectionChanges(changes) {
  const hasConfig = Object.prototype.hasOwnProperty.call(changes, "config");
  const hasOnboarding = Object.prototype.hasOwnProperty.call(
    changes,
    ONBOARDING_KEY,
  );
  if (!hasConfig && !hasOnboarding) return;

  const previousConfig = config;
  const previousOnboardingState = onboardingState;
  const previousMode = config.mode;
  const wasChoosing = onboardingIsChoosing();
  let nextConfig = config;
  if (hasConfig) {
    const storedConfig = changes.config.newValue;
    nextConfig = {
      ...DEFAULT_CONFIG,
      ...(storedConfig && typeof storedConfig === "object" &&
          !Array.isArray(storedConfig)
        ? storedConfig
        : {}),
    };
    nextConfig.backendUrl = safeBackendUrl(nextConfig.backendUrl);
  }
  let nextOnboardingState = onboardingState;
  if (hasOnboarding) {
    nextOnboardingState = normalizeOnboardingState(
      changes[ONBOARDING_KEY].newValue,
    );
  }

  const activeConnectionMode = (candidateConfig, candidateOnboardingState) => {
    if (candidateOnboardingState === ONBOARDING_STATES.CHOOSE) return null;
    if (
      candidateOnboardingState === ONBOARDING_STATES.BACKEND ||
      candidateOnboardingState === ONBOARDING_STATES.PORTAL
    ) {
      return candidateOnboardingState;
    }
    return candidateConfig.mode;
  };
  const previousActiveMode = activeConnectionMode(
    previousConfig,
    previousOnboardingState,
  );
  const nextActiveMode = activeConnectionMode(nextConfig, nextOnboardingState);
  const configChanged = !configsMatch(previousConfig, nextConfig);
  const onboardingChanged = previousOnboardingState !== nextOnboardingState;
  const permissionContextChanged =
    previousActiveMode !== nextActiveMode ||
    (
      nextActiveMode === "portal" &&
      (
        previousConfig.portalStartUrl !== nextConfig.portalStartUrl ||
        previousConfig.ssoRegion !== nextConfig.ssoRegion
      )
    );

  if (configChanged || onboardingChanged) connectionContextRevision += 1;
  if (permissionContextChanged) resetRoleDiscoveryPermissionContext();
  if (
    backendRequestController &&
    (
      nextActiveMode !== "backend" ||
      previousConfig.backendUrl !== nextConfig.backendUrl
    )
  ) {
    backendRequestController.abort();
  }

  config = nextConfig;
  onboardingState = nextOnboardingState;
  el("open-portal").disabled = !config.portalStartUrl;

  renderOnboarding();
  if (config.mode !== previousMode || onboardingIsChoosing() !== wasChoosing) {
    renderMode();
  }
}

async function init() {
  const storedState = await browser.storage.local.get([
    "config",
    BACKEND_SSO_PROFILE_KEY,
    BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY,
    ONBOARDING_KEY,
  ]);
  const stored = storedState.config;
  config = { ...DEFAULT_CONFIG, ...(stored || {}) };
  config.backendUrl = safeBackendUrl(config.backendUrl);
  try {
    backendSsoProfile = normalizeBackendSsoProfile(
      storedState[BACKEND_SSO_PROFILE_KEY],
    );
  } catch {
    backendSsoProfile = "";
  }
  backendSessionReuseAutoOfferHandled =
    storedState[BACKEND_SESSION_REUSE_AUTO_OFFER_HANDLED_KEY] === true;
  onboardingState = normalizeOnboardingState(storedState[ONBOARDING_KEY]);

  bindOnboarding();
  bindMode();
  bindBackend();
  bindPortal();
  bindConsole();
  bindGroupNaming();
  renderOnboarding();
  renderMode();

  if (browser.storage?.onChanged?.addListener) {
    browser.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== "local") return;
      applyStoredConnectionChanges(changes);
      if (
        config.mode === "portal" &&
        Object.prototype.hasOwnProperty.call(changes, "portalPinnedAccounts")
      ) {
        void refreshPortalPinsStatus();
      }
    });
  }

  if (onboardingIsChoosing()) {
    // A new install has no active connection method until the user chooses one.
  } else if (config.mode === "portal") {
    await Promise.all([
      refreshPortalPinsStatus(),
      refreshPortalReadinessAutomatically(),
    ]);
  } else {
    await Promise.all([
      refreshBackendCacheStatus(),
      refreshBackendTokenStatus(),
      refreshConsoleStatus(),
    ]);
  }

  const refreshAfterPermissionChange = () => {
    if (portalCorePermissionOperations > 0) return;
    void refreshPermissionStatuses();
  };
  browser.permissions.onAdded.addListener(refreshAfterPermissionChange);
  browser.permissions.onRemoved.addListener(refreshAfterPermissionChange);
  if (browser.cookies?.onChanged?.addListener) {
    browser.cookies.onChanged.addListener((change) => {
      if (
        config.mode === "portal" &&
        change.cookie &&
        change.cookie.name === "x-amz-sso_authn" &&
        change.cookie.storeId === "firefox-default"
      ) {
        void refreshPortalReadinessAutomatically();
      }
    });
  }
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("focus", () => { void refreshPermissionStatuses(); });
  }
}

localizeDocument();
void init();
