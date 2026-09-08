/* ═══════════════════════════════════════════════════════════════════
   Containoodle Sidebar — Main Logic

   Every AWS account runs in its own container. Tracks Firefox container tabs,
   enriches with AWS
   account metadata from the selected connection mode, and launches
   accounts via the background script.
   ═══════════════════════════════════════════════════════════════════ */

import { accountEnv } from "./env.js";
import { safeAccountsError, validateAccounts } from "../shared/accounts.js";
import { message as t, localizeDocument } from "../shared/i18n.js";
import { automaticAccountName } from "../shared/group-naming.js";
import { createFaviconLoader, faviconSourceForTab } from "../shared/service-icons.js";

const loadFavicon = createFaviconLoader();
import {
  BACKEND_AUTH_TOKEN_KEY,
  BACKEND_SSO_IDENTITY_KEY,
  BACKEND_SSO_PROFILE_KEY,
  DEFAULT_BACKEND_URL,
  backendFetch,
  isBackendAuthenticationError,
  isBackendTimeoutError,
  normalizeBackendSsoIdentityKey,
  normalizeBackendToken,
  safeBackendUrl,
} from "../shared/backend.js";
import {
  ONBOARDING_KEY,
  ONBOARDING_STATES,
  isOnboardingPending,
} from "../shared/onboarding.js";

const DEFAULT_CONFIG = {
  mode: "backend",
  backendUrl: DEFAULT_BACKEND_URL,
  portalStartUrl: "",
};

const RESOLVE_CONNECTION_ONBOARDING = "resolve-connection-onboarding";

// Display labels for the env classes returned by accountEnv() (env.js)
const ENV_LABEL = { prod: "PROD", qa: "QA", dev: "DEV", test: "TEST" };

// ── State ────────────────────────────────────────────────────
let config = { ...DEFAULT_CONFIG };
let accounts = [];
let backendOnline = false;
let usingCache = false;
let backendAuthProblem = null;
let backendAccountsProblem = null;
let searchActiveQuery = "";
let searchPinnedQuery = "";
let searchAllQuery = "";
let sectionCollapsed = { active: false, pinned: false, all: true };
let renderDebounceTimer = null;
let lastActiveTabId = null;
let refreshGeneration = 0;
let modeRevision = 0;
let backendRequestController = null;
let onboardingResolved = false;
let onboardingPending = false;
// Tab ids Firefox reported removed — tabs.query() can still return a
// closing tab briefly after onRemoved, leaving ghosts in Active
const removedTabIds = new Set();
// accountId → backend-only remembered role for the current SSO identity
let rememberedRoles = {};
// accountId → last role handed off from the AWS portal (display only)
let portalRoles = {};
// accountId → portal-only name captured from the AWS Access Portal handoff
let portalAccountOriginalNames = {};
// Backend pins are IDs only; account names and roles stay backend-owned.
let backendPinnedAccountIds = new Set();
// Explicit Containoodle ownership; display names are labels, not identity.
let accountContainers = {};
let containerAccounts = {};
// cookieStoreId → unmodified source name for a managed container. A container
// label may already be formatted, so never treat it as an original name.
let containerOriginalNames = {};
let containerOriginalNamesRevision = 0;
const containerOriginalNameRevisions = new Map();
// accountId → roles list currently offered as an inline picker
const rolePicks = new Map();

// ── DOM refs ─────────────────────────────────────────────────
const listEl       = document.getElementById("account-list");
const loadingState = document.getElementById("loading-state");
const statusDot    = document.getElementById("status-dot");
const statusText   = document.getElementById("status-text");
const refreshBtn   = document.getElementById("refresh-btn");
const optionsBtn   = document.getElementById("options-btn");
const notification = document.getElementById("notification");
const announcement = document.getElementById("sidebar-announcement");
const portalToolbar = document.getElementById("portal-toolbar");
const openPortalBtn = document.getElementById("open-portal-btn");
const portalToolbarHint = document.getElementById("portal-toolbar-hint");
const onboardingCard = document.getElementById("onboarding-card");
const onboardingHeading = document.getElementById("onboarding-heading");
const onboardingDescription = document.getElementById("onboarding-description");
const onboardingOpenSetup = document.getElementById("onboarding-open-setup");

// ── Notification ─────────────────────────────────────────────
let notifyTimer = null;
function notify(message, type = "info", onClick = null) {
  const hadFocus = notification.contains(document.activeElement);
  notification.textContent = "";
  notification.className = type;
  if (onClick) {
    const action = document.createElement("button");
    action.type = "button";
    action.className = "notification-action";
    action.textContent = message;
    action.addEventListener("click", onClick);
    notification.appendChild(action);
    if (hadFocus) action.focus();
  } else {
    notification.textContent = message;
    if (hadFocus) refreshBtn.focus();
  }
  notification.hidden = false;
  announcement.textContent = message;
  clearTimeout(notifyTimer);
  // Recovery actions stay available until the next result or refresh. A
  // timed disappearance would strand keyboard and screen-reader users.
  if (!onClick) notifyTimer = setTimeout(() => { notification.hidden = true; }, 4000);
}

const ONBOARDING_COPY = Object.freeze({
  [ONBOARDING_STATES.CHOOSE]: {
    heading: t("ui_set_up_containoodle", "Set up Containoodle"),
    description: t("ui_choose_how_containoodle_should_open_aws_console_sessions", "Choose how Containoodle should open AWS console sessions."),
  },
  [ONBOARDING_STATES.BACKEND]: {
    heading: t("ui_finish_helper_setup", "Finish helper setup"),
    description: t("ui_connect_and_test_the_local_aws_cli_helper_before", "Connect and test the local AWS CLI helper before opening accounts."),
  },
  [ONBOARDING_STATES.PORTAL]: {
    heading: t("ui_finish_portal_setup", "Finish portal setup"),
    description: t("ui_add_your_aws_access_portal_and_confirm_it_is", "Add your AWS access portal and confirm it is ready before opening accounts."),
  },
});

function showOnboarding(state) {
  const copy = ONBOARDING_COPY[state] || ONBOARDING_COPY[ONBOARDING_STATES.CHOOSE];
  onboardingPending = true;
  if (backendRequestController) backendRequestController.abort();
  rolePicks.clear();

  onboardingHeading.textContent = copy.heading;
  onboardingDescription.textContent = copy.description;
  onboardingCard.dataset.state = state;
  onboardingCard.hidden = false;
  portalToolbar.hidden = true;
  listEl.hidden = true;
  loadingState.classList.remove("visible");
  loadingState.hidden = true;
  refreshBtn.hidden = true;
  notification.hidden = true;
  statusDot.className = "dot setup";
  statusText.classList.add("setup");
  statusText.textContent = t("ui_setup_required", "Setup required");
}

function hideOnboarding() {
  onboardingPending = false;
  onboardingCard.hidden = true;
  delete onboardingCard.dataset.state;
  listEl.hidden = false;
  loadingState.hidden = false;
  refreshBtn.hidden = false;
  statusText.classList.remove("setup");
}

async function readOnboardingState() {
  try {
    const stored = await browser.storage.local.get(ONBOARDING_KEY);
    if (Object.prototype.hasOwnProperty.call(stored, ONBOARDING_KEY)) {
      return stored[ONBOARDING_KEY];
    }

    // The install sidebar can load while the background's asynchronous
    // lifecycle write is still pending. Wait only in that ambiguous missing
    // state; ordinary startups receive an immediate missing response and keep
    // the established behavior.
    const resolved = await browser.runtime.sendMessage({
      type: RESOLVE_CONNECTION_ONBOARDING,
    });
    return resolved && resolved.state;
  } catch {
    // A missing or unreadable marker must preserve the established sidebar.
    return null;
  }
}

// ── Config + accounts ────────────────────────────────────────
async function readConfig() {
  try {
    const { config: stored } = await browser.storage.local.get("config");
    const merged = { ...DEFAULT_CONFIG, ...(stored || {}) };
    merged.backendUrl = safeBackendUrl(merged.backendUrl);
    return merged;
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

async function readAccountsCache() {
  try {
    const { accountsCache } = await browser.storage.local.get("accountsCache");
    return validateAccounts(accountsCache).errors.length ? [] : accountsCache;
  } catch {
    return [];
  }
}

function normalizePortalPins(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const accountId = String(entry.accountId || "").trim();
    const accountName = String(entry.accountName || "").trim();
    if (!/^\d{12}$/.test(accountId) || !accountName) return [];
    const account = { accountId, accountName };
    const role = typeof entry.role === "string" ? entry.role.trim() : "";
    if (role) account.role = role;
    return [account];
  });
}

function normalizeBackendPinnedIds(value) {
  if (!Array.isArray(value)) return new Set();
  return new Set(
    value
      .map((accountId) => String(accountId || "").trim())
      .filter((accountId) => /^\d{12}$/.test(accountId))
  );
}

async function readStoredMetadata(activeMode) {
  const next = {
    rememberedRoles: {},
    portalRoles: {},
    portalAccountOriginalNames: {},
    backendPinnedAccountIds: new Set(),
    accountContainers: {},
    containerAccounts: {},
    containerOriginalNames: {},
  };
  try {
    const all = await browser.storage.local.get(null);
    let backendRolePrefix = null;
    if (activeMode === "backend") {
      try {
        const identityKey = normalizeBackendSsoIdentityKey(
          all[BACKEND_SSO_IDENTITY_KEY]
        );
        backendRolePrefix = `backendRoleChoice/${identityKey}/`;
      } catch {
        // No trusted identity means legacy/unscoped backend roles stay hidden.
      }
    }
    for (const [key, value] of Object.entries(all)) {
      if (
        backendRolePrefix &&
        key.startsWith(backendRolePrefix) &&
        /^\d{12}$/.test(key.slice(backendRolePrefix.length))
      ) {
        next.rememberedRoles[key.slice(backendRolePrefix.length)] = value;
      } else if (activeMode === "portal" && key.startsWith("portalRoleChoice/")) {
        next.portalRoles[key.slice("portalRoleChoice/".length)] = value;
      } else if (
        activeMode === "portal" &&
        key.startsWith("portalAccountOriginalName/") &&
        typeof value === "string"
      ) {
        next.portalAccountOriginalNames[
          key.slice("portalAccountOriginalName/".length)
        ] = value;
      } else if (activeMode === "backend" && key === "backendPinnedAccountIds") {
        next.backendPinnedAccountIds = normalizeBackendPinnedIds(value);
      } else if (key.startsWith("accountContainer/") && typeof value === "string") {
        next.accountContainers[key.slice("accountContainer/".length)] = value;
      } else if (key.startsWith("containerAccount/") && typeof value === "string") {
        next.containerAccounts[key.slice("containerAccount/".length)] = value;
      } else if (key.startsWith("containerOriginalName/") && typeof value === "string") {
        next.containerOriginalNames[key.slice("containerOriginalName/".length)] = value;
      }
    }
  } catch {
    // Empty metadata keeps the sidebar usable if storage is unavailable.
  }
  return next;
}

async function readAccounts(activeConfig) {
  if (activeConfig.mode === "backend") {
    if (backendRequestController) backendRequestController.abort();
    const controller = new AbortController();
    backendRequestController = controller;
    try {
      const stored = await browser.storage.local.get(BACKEND_AUTH_TOKEN_KEY);
      let token;
      try {
        token = normalizeBackendToken(stored[BACKEND_AUTH_TOKEN_KEY]);
      } catch {
        const err = new Error(t("ui_local_helper_access_token_is_missing_or_invalid", "Local helper access token is missing or invalid"));
        err.backendAuthProblem = "required";
        throw err;
      }
      const res = await backendFetch(
        `${activeConfig.backendUrl}/accounts`,
        token,
        { signal: controller.signal }
      );
      if (res.status === 401) {
        const err = new Error(t("ui_local_helper_access_token_was_rejected", "Local helper access token was rejected"));
        err.backendAuthProblem = "rejected";
        throw err;
      }
      if (!res.ok) {
        const err = new Error();
        try {
          err.backendAccountsProblem = safeAccountsError(await res.json());
        } catch {
          // A malformed error response is not user-facing diagnostic text.
        }
        throw err;
      }
      const data = await res.json();
      if (validateAccounts(data).errors.length) {
        const err = new Error();
        err.backendAccountsProblem = t("ui_local_helper_returned_an_unexpected_response", "Local helper returned an unexpected response");
        throw err;
      }
      const cached = await readAccountsCache();
      return {
        accounts: data,
        backendOnline: true,
        usingCache: false,
        backendAuthProblem: null,
        backendAccountsProblem: null,
        cacheChanged: JSON.stringify(cached) !== JSON.stringify(data),
      };
    } catch (err) {
      const cached = await readAccountsCache();
      const authProblem = isBackendAuthenticationError(err)
        ? "rejected"
        : err && (
          err.backendAuthProblem === "required" ||
          err.backendAuthProblem === "rejected"
        ) ? err.backendAuthProblem : null;
      return {
        accounts: cached,
        backendOnline: false,
        usingCache: cached.length > 0,
        backendAuthProblem: authProblem,
        backendAccountsProblem: isBackendTimeoutError(err)
          ? t("ui_local_helper_timed_out_check_server_py_and_try_again", "Local helper timed out. Check server.py and try again.")
          : err?.backendAccountsProblem || null,
        cacheChanged: false,
      };
    } finally {
      if (backendRequestController === controller) {
        backendRequestController = null;
      }
    }
  }

  const { portalPinnedAccounts } = await browser.storage.local.get(
    "portalPinnedAccounts"
  );
  return {
    accounts: normalizePortalPins(portalPinnedAccounts),
    backendOnline: false,
    usingCache: false,
    backendAuthProblem: null,
    cacheChanged: false,
  };
}

function updateStatus() {
  statusText.title = config.mode === "backend" ? backendAccountsProblem || "" : "";
  if (config.mode === "portal") {
    const ready = Boolean(config.portalStartUrl);
    statusDot.className = `dot ${ready ? "online" : "offline"}`;
    if (!ready) {
      statusText.textContent = t("ui_portal_not_configured", "Portal · not configured");
    } else if (accounts.length === 0) {
      statusText.textContent = t("ui_portal_ready", "Portal · ready");
    } else {
      statusText.textContent = t("ui_portal_value_pinned", "Portal · $1 favorites", [accounts.length]);
    }
    return;
  }
  statusDot.className = `dot ${backendOnline ? "online" : "offline"}`;
  if (backendAuthProblem === "required") {
    statusText.textContent = t("ui_helper_access_token_required", "Helper access token required");
  } else if (backendAuthProblem === "rejected") {
    statusText.textContent = t("ui_helper_access_token_rejected", "Helper access token rejected");
  } else if (backendOnline) {
    statusText.textContent = t("ui_connected_value_accounts", "Connected · $1 accounts", [accounts.length]);
  } else {
    statusText.textContent = usingCache
      ? t("ui_offline_value_cached", "Offline · $1 cached", [accounts.length])
      : t("ui_containoodle_offline", "Containoodle offline");
  }
}

function updatePortalToolbar() {
  const portalMode = config.mode === "portal";
  const configured = portalMode && Boolean(
    typeof config.portalStartUrl === "string" && config.portalStartUrl.trim()
  );
  portalToolbar.hidden = !portalMode;
  openPortalBtn.disabled = !configured;
  openPortalBtn.title = configured
    ? t("ui_focus_the_aws_access_portal_tab_or_open_it", "Focus the AWS Access Portal tab, or open it")
    : t("ui_set_the_aws_access_portal_url_in_containoodle_options", "Set the AWS Access Portal URL in Containoodle Options first");
  openPortalBtn.setAttribute("aria-disabled", String(!configured));
  portalToolbarHint.hidden = configured;
}

// ── Build cookie-store → container/tabs map ──────────────────
async function getContainerTabMap() {
  const containers = await browser.contextualIdentities.query({});
  const allTabs = (await browser.tabs.query({})).filter(
    (t) => !removedTabIds.has(t.id)
  );

  const result = new Map();
  for (const c of containers) {
    result.set(c.cookieStoreId, { container: c, tabs: [] });
  }

  for (const tab of allTabs) {
    const entry = result.get(tab.cookieStoreId);
    if (entry) entry.tabs.push(tab);
  }
  return result;
}

// ── Debounced render (for event-driven calls) ────────────────
function scheduleRender() {
  if (!onboardingResolved || onboardingPending) return;
  clearTimeout(renderDebounceTimer);
  renderDebounceTimer = setTimeout(render, 50);
}

// ── Render ───────────────────────────────────────────────────
function displayAccountName(originalName) {
  return automaticAccountName(
    originalName,
    config.groupNamePattern,
    config.groupNameReplacement,
  );
}

function keyedControl(element, key) {
  element.dataset.focusKey = key;
  return element;
}

function listControls() {
  return [...listEl.querySelectorAll("[data-focus-key]")];
}

function captureListFocus() {
  const focused = document.activeElement;
  if (!focused || !listEl.contains(focused)) return null;
  return {
    key: focused.dataset.focusKey,
    accountKey: focused.closest(".account-item")?.dataset.accountKey,
    sectionKey: focused.closest(".section")?.dataset.sectionKey,
    index: listControls().indexOf(focused),
    start: focused.selectionStart,
    end: focused.selectionEnd,
    direction: focused.selectionDirection,
  };
}

function restoreListFocus(saved) {
  if (!saved) return;
  const controls = listControls().filter((control) => !control.disabled);
  const restored = controls.find((control) => control.dataset.focusKey === saved.key)
    || (saved.accountKey && controls.find((control) =>
      control.closest(".account-item")?.dataset.accountKey === saved.accountKey))
    || controls.find((control) => control.dataset.focusKey === `section:${saved.sectionKey}`)
    || controls[Math.min(Math.max(saved.index, 0), controls.length - 1)]
    || refreshBtn;
  restored.focus({ preventScroll: true });
  if (restored.dataset.focusKey === saved.key && typeof saved.start === "number") {
    restored.setSelectionRange(saved.start, saved.end, saved.direction);
  }
}

async function renderWithRoleFocus(accountId, origin) {
  const focusKey = origin?.dataset.focusKey;
  await render();
  // Discovery is asynchronous: only move into the picker if the user is
  // still on the control that requested it, not after they tab elsewhere.
  if (!focusKey || document.activeElement?.dataset.focusKey !== focusKey) return;
  const firstRole = listControls().find((control) =>
    control.dataset.focusKey === `role:${accountId}:0`);
  firstRole?.focus({ preventScroll: true });
}

function dismissRolePicker(accountId, accountKey) {
  const focused = document.activeElement;
  const shouldReturn = focused?.closest(".role-picker")
    ?.closest(".account-item")?.dataset.accountKey === accountKey;
  rolePicks.delete(accountId);
  void render().then(() => {
    if (!shouldReturn) return;
    // render() already returned focus within the account. Do not steal it
    // if the user moved elsewhere while Firefox supplied the latest tabs.
    if (document.activeElement?.closest(".account-item")?.dataset.accountKey !== accountKey) return;
    const controls = listControls();
    const origin = controls.find((control) => control.dataset.focusKey === `choose-role:${accountKey}`)
      || controls.find((control) => control.dataset.focusKey === `launch:${accountKey}`);
    origin?.focus({ preventScroll: true });
  });
}

async function render(expectedGeneration = refreshGeneration) {
  if (!onboardingResolved || onboardingPending) return;
  const containerMap = await getContainerTabMap();
  if (expectedGeneration !== refreshGeneration) return;
  const portalMode = config.mode === "portal";
  const modePinnedIds = portalMode
    ? new Set(accounts.map((account) => String(account.accountId)))
    : backendPinnedAccountIds;

  // Merge accounts with container/tab data
  const items = accounts.map((acc) => {
    const mappedStoreId = accountContainers[acc.accountId];
    const cd = mappedStoreId ? containerMap.get(mappedStoreId) : null;
    const isPinned = modePinnedIds.has(String(acc.accountId));
    const originalName = (portalMode && portalAccountOriginalNames[acc.accountId]) ||
      acc.accountName;
    return {
      account: acc,
      originalName,
      displayName: displayAccountName(originalName),
      container: cd ? cd.container : null,
      tabs: cd ? cd.tabs : [],
      isPinned,
      pinAvailable: true,
      portalPinnedShortcut: portalMode && isPinned,
    };
  });

  // Also show active containers not already represented by an explicit
  // account-id/cookie-store mapping. Display names are never ownership.
  const includedStoreIds = new Set(items.flatMap(
    (item) => item.container ? [item.container.cookieStoreId] : []
  ));
  for (const cd of containerMap.values()) {
    const name = cd.container.name;
    if (includedStoreIds.has(cd.container.cookieStoreId)) continue;
    const mappedAccountId = containerAccounts[cd.container.cookieStoreId];
    if (cd.tabs.length > 0) {
      const portalName = portalMode && mappedAccountId
        ? portalAccountOriginalNames[mappedAccountId]
        : null;
      const storedOriginal = mappedAccountId
        ? containerOriginalNames[cd.container.cookieStoreId]
        : null;
      const originalName = portalName || storedOriginal;
      items.push({
        account: {
          accountId: mappedAccountId || "—",
          accountName: originalName || name,
          role: "—",
        },
        originalName: originalName || name,
        // Missing source metadata is not permission to apply the rule twice
        // to a formatted label, or to rename an unrelated Firefox container.
        displayName: originalName ? displayAccountName(originalName) : name,
        container: cd.container,
        tabs: cd.tabs,
        isPinned: portalMode && modePinnedIds.has(String(mappedAccountId)),
        // Portal handoffs may create a real active account before it is
        // pinned. A backend container missing from the helper/cache is only
        // a synthetic display row and must not become a backend account.
        pinAvailable: portalMode && /^\d{12}$/.test(String(mappedAccountId || "")),
        portalPinnedShortcut:
          portalMode && modePinnedIds.has(String(mappedAccountId)),
      });
    }
  }

  // Each account belongs to exactly one section. A pinned active account
  // remains in Active; it moves to Favorites after its final tab closes.
  const activeItems = items.filter((i) => i.tabs.length > 0);
  const inactiveItems = items.filter((i) => i.tabs.length === 0);
  const pinnedItems = inactiveItems.filter((i) => i.isPinned);
  const otherItems = inactiveItems.filter((i) => !i.isPinned);

  function filterItems(source, query) {
    return query
      ? source.filter(
        (i) =>
          i.account.accountName.toLowerCase().includes(query) ||
          i.originalName.toLowerCase().includes(query) ||
          i.displayName.toLowerCase().includes(query) ||
          String(i.account.accountId).includes(query)
      )
      : source;
  }

  // Filter each section independently.
  const aq = searchActiveQuery.trim().toLowerCase();
  const pq = searchPinnedQuery.trim().toLowerCase();
  const allq = searchAllQuery.trim().toLowerCase();
  const filteredActive = filterItems(activeItems, aq);
  const filteredPinned = filterItems(pinnedItems, pq);
  const filteredOther = filterItems(otherItems, allq);

  // Sort by the label the user actually sees, without changing source data.
  filteredActive.sort((a, b) =>
    a.displayName.localeCompare(b.displayName)
  );
  filteredPinned.sort((a, b) =>
    a.displayName.localeCompare(b.displayName)
  );
  filteredOther.sort((a, b) =>
    a.displayName.localeCompare(b.displayName)
  );

  // Get currently active tab for highlighting
  const [activeTab] = await browser.tabs.query({
    active: true,
    currentWindow: true,
  });
  if (expectedGeneration !== refreshGeneration) return;
  const activeTabId = activeTab ? activeTab.id : null;

  // Render
  // Snapshot immediately before replacing the DOM, after asynchronous work
  // has finished, so a newer user focus or caret position wins.
  const savedFocus = captureListFocus();
  listEl.textContent = "";
  loadingState.classList.remove("visible");

  // Active section
  if (activeItems.length > 0) {
    const sec = createSection("active", t("ui_active_value", "Active ($1)", [filteredActive.length]));
    if (!sectionCollapsed.active) {
      sec.appendChild(createSearchInput("active", searchActiveQuery, t("ui_filter_active", "Filter active…")));
      for (const item of filteredActive) {
        sec.appendChild(createAccountEl(item, activeTabId));
      }
      if (filteredActive.length === 0 && aq) {
        sec.appendChild(createInlineEmpty());
      }
    }
    listEl.appendChild(sec);
  }

  if (pinnedItems.length > 0) {
    const secPinned = createSection(
      "pinned",
      t("ui_pinned_accounts_value", "Favorites ($1)", [filteredPinned.length])
    );
    if (!sectionCollapsed.pinned) {
      secPinned.appendChild(
        createSearchInput("pinned", searchPinnedQuery, t("ui_filter_pinned_accounts", "Filter favorites…"))
      );
      for (const item of filteredPinned) {
        secPinned.appendChild(createAccountEl(item, activeTabId));
      }
      if (filteredPinned.length === 0 && pq) {
        secPinned.appendChild(createInlineEmpty());
      }
    }
    listEl.appendChild(secPinned);
  }

  // Portal mode has no general account source: its inactive accounts are
  // necessarily pins. Backend mode keeps all remaining helper accounts here.
  if (!portalMode && otherItems.length > 0) {
    const secAll = createSection(
      "all",
      t("ui_other_accounts_value", "Other accounts ($1)", [filteredOther.length])
    );
    if (!sectionCollapsed.all) {
      secAll.appendChild(
        createSearchInput("all", searchAllQuery, t("ui_filter_other_accounts", "Filter other accounts…"))
      );
      for (const item of filteredOther) {
        secAll.appendChild(createAccountEl(item, activeTabId));
      }
      if (filteredOther.length === 0 && allq) {
        secAll.appendChild(createInlineEmpty());
      }
    }
    listEl.appendChild(secAll);
  }

  restoreListFocus(savedFocus);

  // Keep the active tab findable: scroll to it when it changes
  // (not on every render, so it doesn't fight manual scrolling).
  // Only commit state once the element is actually rendered, so the
  // scroll survives collapsed/filtered sections until it can happen.
  if (activeTabId !== lastActiveTabId) {
    const activeEl = listEl.querySelector(".tab-item.is-active");
    if (activeEl) {
      activeEl.scrollIntoView({ block: "nearest" });
      lastActiveTabId = activeTabId;
    } else {
      lastActiveTabId = null;
    }
  }
}

function sectionHeader(text, sectionKey) {
  const el = keyedControl(document.createElement("button"), `section:${sectionKey}`);
  el.type = "button";
  el.className = "section-header";
  el.setAttribute("aria-label", text);
  el.setAttribute("aria-expanded", String(!sectionCollapsed[sectionKey]));
  const symbol = document.createElement("span");
  symbol.className = "section-symbol";
  symbol.setAttribute("aria-hidden", "true");
  symbol.textContent = sectionKey === "active" ? "●" : sectionKey === "pinned" ? "★" : "▤";
  el.appendChild(symbol);
  const heading = document.createElement("span");
  heading.className = "section-heading";
  const label = document.createElement("span");
  label.className = "section-label";
  label.textContent = text;
  heading.appendChild(label);
  if (sectionKey === "active" || sectionKey === "pinned") {
    const description = document.createElement("span");
    description.className = "section-description";
    description.id = `section-description-${sectionKey}`;
    description.textContent = sectionKey === "active"
      ? t("ui_open_tabs_now", "Open tabs now")
      : t("ui_saved_shortcuts_no_open_tabs", "Saved shortcuts · no open tabs");
    heading.appendChild(description);
    el.setAttribute("aria-describedby", description.id);
  }
  el.appendChild(heading);
  const chevron = document.createElement("span");
  chevron.className = `section-chevron${sectionCollapsed[sectionKey] ? "" : " open"}`;
  chevron.setAttribute("aria-hidden", "true");
  chevron.textContent = "▶";
  el.appendChild(chevron);
  el.addEventListener("click", () => {
    sectionCollapsed[sectionKey] = !sectionCollapsed[sectionKey];
    render();
  });
  return el;
}

function createSection(sectionKey, title) {
  const wrapper = document.createElement("div");
  wrapper.className = `section section-${sectionKey}`;
  wrapper.dataset.sectionKey = sectionKey;
  wrapper.appendChild(sectionHeader(title, sectionKey));
  return wrapper;
}

function createSearchInput(section, value, placeholder) {
  const wrapper = document.createElement("div");
  wrapper.className = "section-search";
  const input = keyedControl(document.createElement("input"), `search:${section}`);
  input.type = "text";
  input.className = "section-search-input";
  input.placeholder = placeholder;
  input.setAttribute("aria-label", placeholder);
  input.value = value;
  input.autocomplete = "off";
  input.spellcheck = false;
  input.addEventListener("input", () => {
    if (section === "active") {
      searchActiveQuery = input.value;
    } else if (section === "pinned") {
      searchPinnedQuery = input.value;
    } else {
      searchAllQuery = input.value;
    }
    render();
  });
  input.dataset.section = section;
  wrapper.appendChild(input);
  return wrapper;
}

function createInlineEmpty() {
  const el = document.createElement("div");
  el.className = "inline-empty";
  el.textContent = t("ui_no_matches", "No matches");
  return el;
}

// ── Account element ──────────────────────────────────────────
function createAccountEl({
  account,
  originalName,
  displayName,
  container,
  tabs,
  isPinned = false,
  pinAvailable = false,
  portalPinnedShortcut = false,
}, activeTabId) {
  const isActive = tabs.length > 0;
  // Synthetic container-only rows ("—") aren't AWS accounts — no env
  const env = account.accountId !== "—" ? accountEnv(originalName) : null;
  const div = document.createElement("div");
  div.className = `account-item${isActive ? " active" : ""}${env ? ` env-${env}` : ""}`;
  const accountKey = `${config.mode}:${account.accountId === "—" ? container.cookieStoreId : account.accountId}`;
  div.dataset.accountKey = accountKey;

  // Header row
  const header = document.createElement("div");
  header.className = "account-header";

  const dot = document.createElement("span");
  dot.className = "aws-dot";
  if (!env && container) {
    // No env match → fall back to the Firefox container color
    dot.style.background = containerCssColor(container.color);
  }

  const info = document.createElement("div");
  info.className = "account-info";

  const nameRow = document.createElement("div");
  nameRow.className = "account-name-row";
  if (env) {
    const badge = document.createElement("span");
    badge.className = `env-badge env-badge-${env}`;
    badge.textContent = ENV_LABEL[env];
    nameRow.appendChild(badge);
  }
  const nameEl = document.createElement("span");
  nameEl.className = "account-name";
  nameEl.textContent = displayName;
  nameRow.appendChild(nameEl);

  const idEl = document.createElement("div");
  idEl.className = "account-id";
  idEl.textContent = account.accountId;

  // Role chip: a portal pin can be changed through live discovery; a backend
  // role declared by the helper remains static.
  // Accounts with neither resolve automatically on first launch.
  if (account.accountId !== "—") {
    const pinned = account.role && account.role !== "—" ? account.role : null;
    const remembered = rememberedRoles[account.accountId];
    const portalRole = config.mode === "portal" ? portalRoles[account.accountId] : null;
    if (pinned) {
      const portalPinRole = config.mode === "portal" && portalPinnedShortcut;
      const chip = document.createElement(portalPinRole ? "button" : "span");
      chip.className = "role-chip pinned";
      chip.textContent = pinned;
      chip.title = portalPinRole
        ? t("ui_pinned_role_click_to_change", "Pinned role — click to change")
        : t("ui_role_pinned_in_the_accounts_list", "Role pinned in the accounts list");
      if (portalPinRole) {
        keyedControl(chip, `choose-role:${accountKey}`);
        chip.type = "button";
        chip.setAttribute("aria-label", t("ui_change_role_for_value_current_value", "Change role for $1; current role $2", [displayName, pinned]));
        chip.setAttribute("aria-expanded", String(rolePicks.has(account.accountId)));
        chip.classList.add("changeable");
        chip.addEventListener("click", (e) => {
          e.stopPropagation();
          openRolePicker(account);
        });
      }
      idEl.appendChild(chip);
    } else if (portalRole) {
      const chip = document.createElement("span");
      chip.className = "role-chip pinned";
      chip.textContent = portalRole;
      chip.title = t("ui_last_role_selected_in_the_aws_portal", "Last role selected in the AWS portal");
      idEl.appendChild(chip);
    } else if (config.mode === "backend" && remembered) {
      const chip = document.createElement("button");
      chip.className = "role-chip";
      chip.textContent = remembered;
      chip.title = t("ui_remembered_backend_role_click_to_change", "Remembered backend role — click to change");
      keyedControl(chip, `choose-role:${accountKey}`);
      chip.type = "button";
      chip.setAttribute("aria-label", t("ui_change_role_for_value_current_value", "Change role for $1; current role $2", [displayName, remembered]));
      chip.setAttribute("aria-expanded", String(rolePicks.has(account.accountId)));
      chip.addEventListener("click", (e) => {
        e.stopPropagation();
        openRolePicker(account);
      });
      idEl.appendChild(chip);
    }
  }

  info.appendChild(nameRow);
  info.appendChild(idEl);

  header.appendChild(dot);
  header.appendChild(info);

  if (pinAvailable && account.accountId !== "—") {
    const pinBtn = keyedControl(document.createElement("button"), `pin:${accountKey}`);
    pinBtn.className = `pin-btn${isPinned ? " is-pinned" : ""}`;
    pinBtn.type = "button";
    pinBtn.textContent = isPinned ? "★" : "☆";
    pinBtn.title = isPinned
      ? t("ui_unpin_account", "Remove from favorites")
      : t("ui_pin_account", "Add to favorites");
    pinBtn.setAttribute(
      "aria-label",
      isPinned
        ? t("ui_unpin_value", "Remove $1 from favorites", [displayName])
        : t("ui_pin_value", "Add $1 to favorites", [displayName])
    );
    pinBtn.setAttribute("aria-pressed", String(isPinned));
    pinBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (pinBtn.getAttribute("aria-disabled") === "true") return;
      // Keep the focused control in the tab order while its request is
      // pending; aria-disabled plus this guard prevents a duplicate request.
      pinBtn.setAttribute("aria-disabled", "true");
      try {
        await setAccountPinned(account, !isPinned);
      } finally {
        pinBtn.setAttribute("aria-disabled", "false");
      }
    });
    header.appendChild(pinBtn);
  }

  if (isActive) {
    // Tab count badge
    const badge = document.createElement("span");
    badge.className = "tab-count";
    badge.textContent = tabs.length;
    header.appendChild(badge);

    // Close-all button
    const closeAll = keyedControl(document.createElement("button"), `close-all:${accountKey}`);
    closeAll.type = "button";
    closeAll.className = "close-all-btn";
    closeAll.title = t("ui_close_all_tabs", "Close all tabs");
    closeAll.textContent = "✕";
    closeAll.setAttribute("aria-label", t("ui_close_all_tabs_for_value", "Close all tabs for $1", [displayName]));
    closeAll.addEventListener("click", async (e) => {
      e.stopPropagation();
      tabs.forEach((t) => removedTabIds.add(t.id));
      await Promise.allSettled(tabs.map((t) => browser.tabs.remove(t.id)));
      render();
    });
    header.appendChild(closeAll);
  } else if (account.accountId !== "—") {
    // Launch button — always present so a misconfigured setup fails
    // loudly (the background reports exactly what's missing) instead
    // of rendering an inert row.
    const btn = keyedControl(document.createElement("button"), `launch:${accountKey}`);
    btn.type = "button";
    btn.className = "launch-btn";
    btn.title = t("ui_launch_in_container", "Launch in container");
    btn.textContent = "▶";
    btn.setAttribute("aria-label", t("ui_launch_value_in_container", "Launch $1 in its container", [displayName]));
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      launchAccount(account, btn);
    });
    header.appendChild(btn);
  }

  // Clicking inactive header also launches
  if (!isActive && account.accountId !== "—") {
    header.addEventListener("click", () => {
      const btn = header.querySelector(".launch-btn");
      if (btn) launchAccount(account, btn);
    });
  }

  div.appendChild(header);

  // Inline role picker (after a multi-role discovery)
  if (rolePicks.has(account.accountId)) {
    const picker = document.createElement("div");
    picker.className = "role-picker";
    picker.setAttribute("role", "group");
    picker.setAttribute("aria-label", t("ui_choose_role_for_value", "Choose a role for $1", [displayName]));
    picker.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      dismissRolePicker(account.accountId, accountKey);
    });
    for (const [index, role] of rolePicks.get(account.accountId).entries()) {
      const option = keyedControl(document.createElement("button"), `role:${account.accountId}:${index}`);
      option.type = "button";
      option.className = "role-option";
      option.textContent = role;
      option.addEventListener("click", (e) => {
        e.stopPropagation();
        dismissRolePicker(account.accountId, accountKey);
        launchAccount(account, header.querySelector(".launch-btn"), role);
      });
      picker.appendChild(option);
    }
    const dismiss = keyedControl(document.createElement("button"), `dismiss-role:${accountKey}`);
    dismiss.type = "button";
    dismiss.className = "role-option dismiss";
    dismiss.textContent = "✕";
    dismiss.title = t("ui_dismiss", "Dismiss");
    dismiss.setAttribute("aria-label", t("ui_dismiss_role_choices_for_value", "Dismiss role choices for $1", [displayName]));
    dismiss.addEventListener("click", (e) => {
      e.stopPropagation();
      dismissRolePicker(account.accountId, accountKey);
    });
    picker.appendChild(dismiss);
    div.appendChild(picker);
  }

  // Tab list
  if (isActive) {
    const tabListEl = document.createElement("div");
    tabListEl.className = "tab-list";
    for (const tab of tabs) {
      tabListEl.appendChild(createTabEl(tab, activeTabId));
    }
    div.appendChild(tabListEl);
  }

  return div;
}

// ── Tab element ──────────────────────────────────────────────
function createTabEl(tab, activeTabId) {
  const el = document.createElement("div");
  el.className = `tab-item${tab.id === activeTabId ? " is-active" : ""}`;
  const switchButton = keyedControl(document.createElement("button"), `tab:${tab.id}`);
  switchButton.type = "button";
  switchButton.className = "tab-switch";
  switchButton.setAttribute("aria-label", t("ui_switch_to_tab_value", "Switch to tab: $1", [tab.title || t("ui_loading", "Loading…")]));
  if (tab.id === activeTabId) switchButton.setAttribute("aria-current", "true");
  switchButton.addEventListener("click", () => switchToTab(tab.id));

  switchButton.appendChild(createTabFavicon(tab));

  // Title
  const title = document.createElement("span");
  title.className = "tab-title";
  title.textContent = tab.title || t("ui_loading", "Loading…");
  switchButton.appendChild(title);
  el.appendChild(switchButton);

  // Close button
  const closeBtn = keyedControl(document.createElement("button"), `close-tab:${tab.id}`);
  closeBtn.type = "button";
  closeBtn.className = "tab-close";
  closeBtn.title = t("ui_close_tab", "Close tab");
  closeBtn.textContent = "×";
  closeBtn.setAttribute("aria-label", t("ui_close_tab_value", "Close tab: $1", [tab.title || t("ui_loading", "Loading…")]));
  closeBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    removedTabIds.add(tab.id);
    try { await browser.tabs.remove(tab.id); } catch {}
    render();
  });
  el.appendChild(closeBtn);

  return el;
}

function createTabFavicon(tab) {
  const span = document.createElement("span");
  span.className = "tab-favicon tab-favicon-slot is-fallback";
  span.setAttribute("aria-hidden", "true");
  function showImage(src) {
    if (!src) return;
    const img = document.createElement("img");
    img.alt = "";
    img.className = "tab-favicon-image";
    img.decoding = "async";
    img.onload = () => span.classList.remove("is-fallback");
    img.onerror = () => {
      span.textContent = "";
      span.classList.add("is-fallback");
    };
    // Embedded data or a browser-local image, never a remote <img> request.
    img.src = src;
    span.appendChild(img);
  }
  const source = faviconSourceForTab(tab);
  if (source?.remote) void loadFavicon(tab).then(showImage);
  else if (source) showImage(source.url);
  return span;
}

// ── Mode-specific pins ───────────────────────────────────────
async function setAccountPinned(account, shouldPin) {
  const requestedMode = config.mode;
  const requestedRevision = modeRevision;
  if (!["backend", "portal"].includes(requestedMode)) return;

  try {
    const result = await browser.runtime.sendMessage(
      requestedMode === "portal"
        ? {
            type: "set-portal-pin",
            mode: requestedMode,
            pinned: shouldPin,
            account: {
              accountId: account.accountId,
              accountName:
                portalAccountOriginalNames[account.accountId] || account.accountName,
            },
          }
        : {
            type: "set-backend-pin",
            mode: requestedMode,
            pinned: shouldPin,
            accountId: account.accountId,
          }
    );
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode ||
      (result && result.cancelled)
    ) return;
    if (!result || !result.ok) {
      throw new Error((result && result.error) || t("ui_pin_update_failed", "Favorite update failed"));
    }
    notify(
      shouldPin
        ? t("ui_pinned_value", "Added $1 to favorites", [account.accountName])
        : t("ui_unpinned_value", "Removed $1 from favorites", [account.accountName]),
      "success"
    );
    if (requestedMode === "portal") {
      await fullRefresh();
    } else {
      const { backendPinnedAccountIds: stored } =
        await browser.storage.local.get("backendPinnedAccountIds");
      if (
        requestedRevision !== modeRevision ||
        requestedMode !== config.mode
      ) return;
      backendPinnedAccountIds = normalizeBackendPinnedIds(stored);
      await render();
    }
  } catch (err) {
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode
    ) return;
    notify(t("ui_could_not_update_pin_value", "Could not update favorite: $1", [err.message]), "error");
    await render();
  }
}

function openOptionsAction() {
  browser.runtime.openOptionsPage().catch(() => {});
  notification.hidden = true;
}

// ── AWS Access Portal shortcut ───────────────────────────────
async function openPortalAction() {
  const requestedMode = config.mode;
  const requestedRevision = modeRevision;
  if (requestedMode !== "portal") return;
  if (
    typeof config.portalStartUrl !== "string" ||
    !config.portalStartUrl.trim()
  ) {
    notify(
      t("ui_set_the_aws_access_portal_url_in_options_first", "Set the AWS Access Portal URL in Options first"),
      "error",
      openOptionsAction
    );
    return;
  }

  openPortalBtn.disabled = true;
  openPortalBtn.classList.add("loading");
  notify(t("ui_opening_aws_portal", "Opening AWS Portal…"), "info");
  try {
    const result = await browser.runtime.sendMessage({
      type: "open-portal",
      mode: requestedMode,
    });
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode ||
      (result && result.cancelled)
    ) return;
    if (result && result.ok) {
      notify(t("ui_aws_portal_ready", "AWS Portal ready"), "success");
    } else {
      notify(
        t("ui_value_click_here_to_open_settings", "$1 — click here to open settings", [(result && result.error) || t("ui_could_not_open_aws_portal", "Could not open AWS Portal")]),
        "error",
        openOptionsAction
      );
    }
  } catch (err) {
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode
    ) return;
    notify(t("ui_could_not_open_aws_portal_value", "Could not open AWS Portal: $1", [err.message]), "error");
  } finally {
    openPortalBtn.classList.remove("loading");
    if (
      requestedRevision === modeRevision &&
      requestedMode === config.mode
    ) {
      updatePortalToolbar();
    }
  }
}

function signInAction() {
  void openPortalAction();
}

openPortalBtn.addEventListener("click", () => {
  void openPortalAction();
});

// ── Launch account (delegated to the background script) ──────
async function launchAccount(account, btn, role) {
  const requestedMode = config.mode;
  const requestedRevision = modeRevision;
  const origin = document.activeElement;
  if (btn) {
    btn.classList.add("loading");
    btn.textContent = "↻";
  }
  notify(t("ui_opening_value", "Opening $1…", [account.accountName]), "info");

  try {
    const resp = await browser.runtime.sendMessage({
      type: "launch",
      accountId: account.accountId,
      role,
      mode: requestedMode,
    });
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode
    ) return;
    if (resp && resp.ok) {
      notify(t("ui_opened_value", "Opened $1", [resp.account]), "success");
    } else if (resp && resp.needsLogin) {
      notify(t("ui_no_portal_session_click_here_to_sign_in", "No portal session — click here to sign in"), "error", signInAction);
    } else if (resp && resp.needsOptions) {
      notify(t("ui_value_click_here_to_open_settings", "$1 — click here to open settings", [resp.error]), "error", openOptionsAction);
    } else if (resp && resp.chooseRole) {
      rolePicks.set(account.accountId, resp.chooseRole);
      notify(t("ui_value_pick_a_role", "$1: pick a role", [account.accountName]), "info");
      await renderWithRoleFocus(account.accountId, origin);
    } else {
      notify(t("ui_failed_value", "Failed: $1", [(resp && resp.error) || t("ui_no_response", "no response")]), "error");
    }
  } catch (err) {
    notify(t("ui_failed_value", "Failed: $1", [err.message]), "error");
  } finally {
    if (btn) {
      btn.classList.remove("loading");
      btn.textContent = "▶";
    }
  }
}

// ── Role picker (chip click → live role list) ────────────────
async function openRolePicker(account) {
  const requestedMode = config.mode;
  const requestedRevision = modeRevision;
  const origin = document.activeElement;
  notify(t("ui_loading_roles_for_value", "Loading roles for $1…", [account.accountName]), "info");
  try {
    const resp = await browser.runtime.sendMessage({
      type: "discover-roles",
      accountId: account.accountId,
      mode: requestedMode,
    });
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode
    ) return;
    if (resp && resp.ok) {
      rolePicks.set(account.accountId, resp.roles);
      notification.hidden = true;
      await renderWithRoleFocus(account.accountId, origin);
    } else if (resp && resp.needsLogin) {
      notify(t("ui_no_portal_session_click_here_to_sign_in", "No portal session — click here to sign in"), "error", signInAction);
    } else if (resp && resp.needsOptions) {
      notify(t("ui_value_click_here_to_open_settings", "$1 — click here to open settings", [resp.error]), "error", openOptionsAction);
    } else {
      notify(t("ui_failed_value", "Failed: $1", [(resp && resp.error) || t("ui_no_response", "no response")]), "error");
    }
  } catch (err) {
    notify(t("ui_failed_value", "Failed: $1", [err.message]), "error");
  }
}

// ── Switch to tab ────────────────────────────────────────────
async function switchToTab(tabId) {
  try {
    const tab = await browser.tabs.get(tabId);
    await browser.tabs.update(tabId, { active: true });
    await browser.windows.update(tab.windowId, { focused: true });
  } catch {
    // Tab may have been closed
  }
}

// ── Container color → CSS color ──────────────────────────────
function containerCssColor(name) {
  const map = {
    blue: "#37adff", turquoise: "#00c79a", green: "#51cd00",
    yellow: "#ffcb00", orange: "#ff9f00", red: "#ff613d",
    pink: "#ff4bda", purple: "#af51f5", toolbar: "#7c7c7d",
  };
  return map[name] || "#ff9900";
}

// ── Footer buttons ───────────────────────────────────────────
onboardingOpenSetup.addEventListener("click", openOptionsAction);

refreshBtn.addEventListener("click", async () => {
  refreshBtn.classList.add("spinning");
  await fullRefresh();
  setTimeout(() => refreshBtn.classList.remove("spinning"), 600);
});

optionsBtn.addEventListener("click", () => {
  browser.runtime.openOptionsPage().catch(() => {});
});

// ── Tab + container event listeners ──────────────────────────
browser.tabs.onRemoved.addListener((tabId) => {
  removedTabIds.add(tabId);
  scheduleRender();
});
browser.tabs.onCreated.addListener(scheduleRender);
browser.tabs.onActivated.addListener(scheduleRender);
browser.tabs.onUpdated.addListener((_id, changeInfo) => {
  if (changeInfo.title || changeInfo.url || Object.hasOwn(changeInfo, "favIconUrl") || changeInfo.status === "complete") scheduleRender();
});
browser.contextualIdentities.onCreated.addListener(scheduleRender);
browser.contextualIdentities.onRemoved.addListener(scheduleRender);
browser.contextualIdentities.onUpdated.addListener(scheduleRender);

// Mode, backend-cache, portal-pin, and mapping changes reflect live.
browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  const keys = Object.keys(changes);
  const originalNameKeys = keys.filter((key) => key.startsWith("containerOriginalName/"));
  if (originalNameKeys.length > 0) containerOriginalNamesRevision += 1;
  for (const key of originalNameKeys) {
    const storeId = key.slice("containerOriginalName/".length);
    const value = changes[key].newValue;
    containerOriginalNameRevisions.set(storeId, containerOriginalNamesRevision);
    if (typeof value === "string") containerOriginalNames[storeId] = value;
    else delete containerOriginalNames[storeId];
  }
  if (changes[ONBOARDING_KEY]) {
    onboardingResolved = true;
    if (isOnboardingPending(changes[ONBOARDING_KEY].newValue)) {
      onboardingPending = true;
      if (backendRequestController) backendRequestController.abort();
    }
    void fullRefresh();
    return;
  }
  if (changes.config) {
    const oldMode = changes.config.oldValue?.mode;
    const newMode = changes.config.newValue?.mode;
    if (oldMode !== newMode) {
      modeRevision += 1;
      rolePicks.clear();
      searchActiveQuery = "";
      searchPinnedQuery = "";
      searchAllQuery = "";
      if (newMode === "portal" && backendRequestController) {
        backendRequestController.abort();
      }
    }
  }
  if (
    keys.includes("config") ||
    (config.mode === "backend" && keys.includes(BACKEND_AUTH_TOKEN_KEY)) ||
    (config.mode === "backend" && keys.includes(BACKEND_SSO_PROFILE_KEY)) ||
    (config.mode === "backend" && keys.includes(BACKEND_SSO_IDENTITY_KEY)) ||
    (config.mode === "backend" && keys.includes("accountsCache")) ||
    (config.mode === "portal" && keys.includes("portalPinnedAccounts"))
  ) {
    fullRefresh();
  } else if (
    config.mode === "backend" &&
    keys.includes("backendPinnedAccountIds")
  ) {
    backendPinnedAccountIds = normalizeBackendPinnedIds(
      changes.backendPinnedAccountIds.newValue
    );
    scheduleRender();
  } else if (keys.some((k) =>
    (config.mode === "backend" && k.startsWith("backendRoleChoice/")) ||
    (config.mode === "portal" && k.startsWith("portalRoleChoice/")) ||
    k.startsWith("portalAccountOriginalName/") ||
    k.startsWith("accountContainer/") ||
    k.startsWith("containerAccount/")
  )) {
    fullRefresh();
  } else if (originalNameKeys.length > 0) {
    // Bulk label updates carry only raw source metadata. Refresh the visible
    // rows without reloading accounts or contacting the local helper again.
    scheduleRender();
  }
});

// ── Full refresh (config + accounts + tabs) ──────────────────
async function fullRefresh() {
  const generation = ++refreshGeneration;
  loadingState.classList.add("visible");
  const nextOnboardingState = await readOnboardingState();
  if (generation !== refreshGeneration) return;
  onboardingResolved = true;
  if (isOnboardingPending(nextOnboardingState)) {
    showOnboarding(nextOnboardingState);
    return;
  }

  hideOnboarding();
  const nextConfig = await readConfig();
  if (generation !== refreshGeneration) return;
  if (nextConfig.mode === "portal" && backendRequestController) {
    backendRequestController.abort();
  }

  const originalNamesRevision = containerOriginalNamesRevision;
  const [nextAccounts, nextMetadata] = await Promise.all([
    readAccounts(nextConfig),
    readStoredMetadata(nextConfig.mode),
  ]);
  if (generation !== refreshGeneration) return;

  // A helper response may finish after this refresh snapshotted metadata.
  // Keep newer source-only updates (including removals) without another fetch.
  for (const [storeId, revision] of containerOriginalNameRevisions) {
    if (revision <= originalNamesRevision) continue;
    if (Object.prototype.hasOwnProperty.call(containerOriginalNames, storeId)) {
      nextMetadata.containerOriginalNames[storeId] = containerOriginalNames[storeId];
    } else {
      delete nextMetadata.containerOriginalNames[storeId];
    }
  }

  config = nextConfig;
  accounts = nextAccounts.accounts;
  backendOnline = nextAccounts.backendOnline;
  usingCache = nextAccounts.usingCache;
  backendAuthProblem = nextAccounts.backendAuthProblem;
  const previousAccountsProblem = backendAccountsProblem;
  backendAccountsProblem = nextAccounts.backendAccountsProblem || null;
  rememberedRoles = nextMetadata.rememberedRoles;
  portalRoles = nextMetadata.portalRoles;
  portalAccountOriginalNames = nextMetadata.portalAccountOriginalNames;
  backendPinnedAccountIds = nextMetadata.backendPinnedAccountIds;
  accountContainers = nextMetadata.accountContainers;
  containerAccounts = nextMetadata.containerAccounts;
  containerOriginalNames = nextMetadata.containerOriginalNames;
  updateStatus();
  updatePortalToolbar();
  if (backendAccountsProblem && backendAccountsProblem !== previousAccountsProblem) {
    notify(backendAccountsProblem, "error", () => browser.runtime.openOptionsPage());
  }

  if (nextAccounts.cacheChanged) {
    browser.storage.local.set({
      accountsCache: accounts,
      accountsCacheAt: Date.now(),
      accountsCacheSource: "backend",
    }).catch(() => {});
  }

  await render(generation);
  if (generation === refreshGeneration) {
    loadingState.classList.remove("visible");
  }
}

// ── Init ─────────────────────────────────────────────────────
localizeDocument();
// Never let cosmetics break init (e.g. stale cached HTML after update)
try {
  const versionEl = document.getElementById("brand-version");
  if (versionEl) {
    versionEl.textContent = `v${browser.runtime.getManifest().version}`;
  }
} catch {}
fullRefresh();
