/* ═══════════════════════════════════════════════════════════════════
   Containoodle Sidebar — Main Logic

   Every AWS account runs in its own container. Tracks Firefox container tabs,
   enriches with AWS
   account metadata from the selected connection mode, and launches
   accounts via the background script.
   ═══════════════════════════════════════════════════════════════════ */

import { accountEnv } from "./env.js";
import {
  BACKEND_AUTH_TOKEN_KEY,
  BACKEND_SSO_IDENTITY_KEY,
  BACKEND_SSO_PROFILE_KEY,
  DEFAULT_BACKEND_URL,
  backendFetch,
  isBackendAuthenticationError,
  normalizeBackendSsoIdentityKey,
  normalizeBackendToken,
  safeBackendUrl,
} from "../shared/backend.js";

const DEFAULT_CONFIG = {
  mode: "backend",
  backendUrl: DEFAULT_BACKEND_URL,
  portalStartUrl: "",
};

// Display labels for the env classes returned by accountEnv() (env.js)
const ENV_LABEL = { prod: "PROD", qa: "QA", dev: "DEV", test: "TEST" };

// ── State ────────────────────────────────────────────────────
let config = { ...DEFAULT_CONFIG };
let accounts = [];
let backendOnline = false;
let usingCache = false;
let backendAuthProblem = null;
let searchActiveQuery = "";
let searchPinnedQuery = "";
let searchAllQuery = "";
let pendingFocusSection = null;
let sectionCollapsed = { active: false, pinned: false, all: true };
let renderDebounceTimer = null;
let lastActiveTabId = null;
let refreshGeneration = 0;
let modeRevision = 0;
let backendRequestController = null;
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
const portalToolbar = document.getElementById("portal-toolbar");
const openPortalBtn = document.getElementById("open-portal-btn");
const portalToolbarHint = document.getElementById("portal-toolbar-hint");

// ── Notification ─────────────────────────────────────────────
let notifyTimer = null;
function notify(message, type = "info", onClick = null) {
  notification.textContent = message;
  notification.className = type + (onClick ? " clickable" : "");
  notification.hidden = false;
  notification.onclick = onClick;
  clearTimeout(notifyTimer);
  notifyTimer = setTimeout(() => { notification.hidden = true; }, onClick ? 10000 : 4000);
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
    return Array.isArray(accountsCache) ? accountsCache : [];
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
        const err = new Error("Local helper access token is missing or invalid");
        err.backendAuthProblem = "required";
        throw err;
      }
      const res = await backendFetch(
        `${activeConfig.backendUrl}/accounts`,
        token,
        { signal: controller.signal }
      );
      if (res.status === 401) {
        const err = new Error("Local helper access token was rejected");
        err.backendAuthProblem = "rejected";
        throw err;
      }
      if (!res.ok) throw new Error();
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error();
      const cached = await readAccountsCache();
      return {
        accounts: data,
        backendOnline: true,
        usingCache: false,
        backendAuthProblem: null,
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
  if (config.mode === "portal") {
    const ready = Boolean(config.portalStartUrl);
    statusDot.className = `dot ${ready ? "online" : "offline"}`;
    if (!ready) {
      statusText.textContent = "Portal · not configured";
    } else if (accounts.length === 0) {
      statusText.textContent = "Portal · ready";
    } else {
      statusText.textContent = `Portal · ${accounts.length} pinned`;
    }
    return;
  }
  statusDot.className = `dot ${backendOnline ? "online" : "offline"}`;
  if (backendAuthProblem === "required") {
    statusText.textContent = "Helper access token required";
  } else if (backendAuthProblem === "rejected") {
    statusText.textContent = "Helper access token rejected";
  } else if (backendOnline) {
    statusText.textContent = `Connected · ${accounts.length} accounts`;
  } else {
    statusText.textContent = usingCache
      ? `Offline · ${accounts.length} cached`
      : "Containoodle offline";
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
    ? "Focus the AWS Access Portal tab, or open it"
    : "Set the AWS Access Portal URL in Containoodle Options first";
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
  clearTimeout(renderDebounceTimer);
  renderDebounceTimer = setTimeout(render, 50);
}

// ── Render ───────────────────────────────────────────────────
async function render(expectedGeneration = refreshGeneration) {
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
    return {
      account: acc,
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
      items.push({
        account: {
          accountId: mappedAccountId || "—",
          accountName: portalName || name,
          role: "—",
        },
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
  // remains in Active; it moves to Pinned accounts after its final tab closes.
  const activeItems = items.filter((i) => i.tabs.length > 0);
  const inactiveItems = items.filter((i) => i.tabs.length === 0);
  const pinnedItems = inactiveItems.filter((i) => i.isPinned);
  const otherItems = inactiveItems.filter((i) => !i.isPinned);

  function filterItems(source, query) {
    return query
      ? source.filter(
        (i) =>
          i.account.accountName.toLowerCase().includes(query) ||
          String(i.account.accountId).includes(query)
      )
      : source;
  }

  // Filter each section independently.
  const aq = searchActiveQuery;
  const pq = searchPinnedQuery;
  const allq = searchAllQuery;
  const filteredActive = filterItems(activeItems, aq);
  const filteredPinned = filterItems(pinnedItems, pq);
  const filteredOther = filterItems(otherItems, allq);

  // Sort each alphabetically
  filteredActive.sort((a, b) =>
    a.account.accountName.localeCompare(b.account.accountName)
  );
  filteredPinned.sort((a, b) =>
    a.account.accountName.localeCompare(b.account.accountName)
  );
  filteredOther.sort((a, b) =>
    a.account.accountName.localeCompare(b.account.accountName)
  );

  // Get currently active tab for highlighting
  const [activeTab] = await browser.tabs.query({
    active: true,
    currentWindow: true,
  });
  if (expectedGeneration !== refreshGeneration) return;
  const activeTabId = activeTab ? activeTab.id : null;

  // Render
  listEl.textContent = "";
  loadingState.classList.remove("visible");

  // Active section
  if (activeItems.length > 0) {
    const sec = createSection("active", `Active (${filteredActive.length})`);
    if (!sectionCollapsed.active) {
      sec.appendChild(createSearchInput("active", searchActiveQuery, "Filter active…"));
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
      `Pinned accounts (${filteredPinned.length})`
    );
    if (!sectionCollapsed.pinned) {
      secPinned.appendChild(
        createSearchInput("pinned", searchPinnedQuery, "Filter pinned accounts…")
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
      `Other accounts (${filteredOther.length})`
    );
    if (!sectionCollapsed.all) {
      secAll.appendChild(
        createSearchInput("all", searchAllQuery, "Filter other accounts…")
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

  // Restore focus to search input after DOM rebuild
  if (pendingFocusSection) {
    const restored = listEl.querySelector(
      `.section-search-input[data-section="${pendingFocusSection}"]`
    );
    if (restored) {
      restored.focus();
      restored.selectionStart = restored.selectionEnd = restored.value.length;
    }
    pendingFocusSection = null;
  }

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
  const el = document.createElement("div");
  el.className = "section-header";
  const chevron = document.createElement("span");
  chevron.className = `section-chevron${sectionCollapsed[sectionKey] ? "" : " open"}`;
  chevron.textContent = "▶";
  el.appendChild(chevron);
  el.appendChild(document.createTextNode(` ${text}`));
  el.addEventListener("click", () => {
    sectionCollapsed[sectionKey] = !sectionCollapsed[sectionKey];
    render();
  });
  return el;
}

function createSection(sectionKey, title) {
  const wrapper = document.createElement("div");
  wrapper.className = `section section-${sectionKey}`;
  wrapper.appendChild(sectionHeader(title, sectionKey));
  return wrapper;
}

function createSearchInput(section, value, placeholder) {
  const wrapper = document.createElement("div");
  wrapper.className = "section-search";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "section-search-input";
  input.placeholder = placeholder;
  input.value = value;
  input.autocomplete = "off";
  input.spellcheck = false;
  input.addEventListener("input", () => {
    if (section === "active") {
      searchActiveQuery = input.value.trim().toLowerCase();
    } else if (section === "pinned") {
      searchPinnedQuery = input.value.trim().toLowerCase();
    } else {
      searchAllQuery = input.value.trim().toLowerCase();
    }
    pendingFocusSection = section;
    render();
  });
  input.dataset.section = section;
  wrapper.appendChild(input);
  return wrapper;
}

function createInlineEmpty() {
  const el = document.createElement("div");
  el.className = "inline-empty";
  el.textContent = "No matches";
  return el;
}

// ── Account element ──────────────────────────────────────────
function createAccountEl({
  account,
  container,
  tabs,
  isPinned = false,
  pinAvailable = false,
  portalPinnedShortcut = false,
}, activeTabId) {
  const isActive = tabs.length > 0;
  // Synthetic container-only rows ("—") aren't AWS accounts — no env
  const env = account.accountId !== "—" ? accountEnv(account.accountName) : null;
  const div = document.createElement("div");
  div.className = `account-item${isActive ? " active" : ""}${env ? ` env-${env}` : ""}`;

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
  nameEl.textContent = account.accountName;
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
        ? "Pinned role — click to change"
        : "Role pinned in the accounts list";
      if (portalPinRole) {
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
      chip.title = "Last role selected in the AWS portal";
      idEl.appendChild(chip);
    } else if (config.mode === "backend" && remembered) {
      const chip = document.createElement("button");
      chip.className = "role-chip";
      chip.textContent = remembered;
      chip.title = "Remembered backend role — click to change";
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
    const pinBtn = document.createElement("button");
    pinBtn.className = `pin-btn${isPinned ? " is-pinned" : ""}`;
    pinBtn.type = "button";
    pinBtn.textContent = isPinned ? "★" : "☆";
    pinBtn.title = isPinned
      ? "Unpin account"
      : "Pin account";
    pinBtn.setAttribute(
      "aria-label",
      isPinned
        ? `Unpin ${account.accountName}`
        : `Pin ${account.accountName}`
    );
    pinBtn.setAttribute("aria-pressed", String(isPinned));
    pinBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      pinBtn.disabled = true;
      await setAccountPinned(account, !isPinned);
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
    const closeAll = document.createElement("button");
    closeAll.className = "close-all-btn";
    closeAll.title = "Close all tabs";
    closeAll.textContent = "✕";
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
    const btn = document.createElement("button");
    btn.className = "launch-btn";
    btn.title = "Launch in container";
    btn.textContent = "▶";
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
    for (const role of rolePicks.get(account.accountId)) {
      const option = document.createElement("button");
      option.className = "role-option";
      option.textContent = role;
      option.addEventListener("click", (e) => {
        e.stopPropagation();
        rolePicks.delete(account.accountId);
        launchAccount(account, header.querySelector(".launch-btn"), role);
      });
      picker.appendChild(option);
    }
    const dismiss = document.createElement("button");
    dismiss.className = "role-option dismiss";
    dismiss.textContent = "✕";
    dismiss.title = "Dismiss";
    dismiss.addEventListener("click", (e) => {
      e.stopPropagation();
      rolePicks.delete(account.accountId);
      render();
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

  // Favicon
  if (
    typeof tab.favIconUrl === "string" &&
    (
      tab.favIconUrl.startsWith("moz-extension://") ||
      /^data:image\/(?:png|jpe?g|gif|webp|x-icon|vnd\.microsoft\.icon);base64,/i
        .test(tab.favIconUrl)
    )
  ) {
    const img = document.createElement("img");
    img.className = "tab-favicon";
    img.src = tab.favIconUrl;
    img.onerror = () => {
      img.replaceWith(faviconPlaceholder());
    };
    el.appendChild(img);
  } else {
    el.appendChild(faviconPlaceholder());
  }

  // Title
  const title = document.createElement("span");
  title.className = "tab-title";
  title.textContent = tab.title || "Loading…";
  el.appendChild(title);

  // Close button
  const closeBtn = document.createElement("button");
  closeBtn.className = "tab-close";
  closeBtn.title = "Close tab";
  closeBtn.textContent = "×";
  closeBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    removedTabIds.add(tab.id);
    try { await browser.tabs.remove(tab.id); } catch {}
    render();
  });
  el.appendChild(closeBtn);

  // Click → switch to tab
  el.addEventListener("click", () => switchToTab(tab.id));

  return el;
}

function faviconPlaceholder() {
  const span = document.createElement("span");
  span.className = "tab-favicon-placeholder";
  span.textContent = "📄";
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
      throw new Error((result && result.error) || "Pin update failed");
    }
    notify(
      shouldPin
        ? `Pinned ${account.accountName}`
        : `Unpinned ${account.accountName}`,
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
    notify(`Could not update pin: ${err.message}`, "error");
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
      "Set the AWS Access Portal URL in Options first",
      "error",
      openOptionsAction
    );
    return;
  }

  openPortalBtn.disabled = true;
  openPortalBtn.classList.add("loading");
  notify("Opening AWS Portal…", "info");
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
      notify("AWS Portal ready", "success");
    } else {
      notify(
        `${(result && result.error) || "Could not open AWS Portal"} — click here to open settings`,
        "error",
        openOptionsAction
      );
    }
  } catch (err) {
    if (
      requestedRevision !== modeRevision ||
      requestedMode !== config.mode
    ) return;
    notify(`Could not open AWS Portal: ${err.message}`, "error");
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
  if (btn) {
    btn.classList.add("loading");
    btn.textContent = "↻";
  }
  notify(`Opening ${account.accountName}…`, "info");

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
      notify(`Opened ${resp.account}`, "success");
    } else if (resp && resp.needsLogin) {
      notify("No portal session — click here to sign in", "error", signInAction);
    } else if (resp && resp.needsOptions) {
      notify(`${resp.error} — click here to open settings`, "error", openOptionsAction);
    } else if (resp && resp.chooseRole) {
      rolePicks.set(account.accountId, resp.chooseRole);
      notify(`${account.accountName}: pick a role`, "info");
      render();
    } else {
      notify(`Failed: ${(resp && resp.error) || "no response"}`, "error");
    }
  } catch (err) {
    notify(`Failed: ${err.message}`, "error");
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
  notify(`Loading roles for ${account.accountName}…`, "info");
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
      render();
    } else if (resp && resp.needsLogin) {
      notify("No portal session — click here to sign in", "error", signInAction);
    } else if (resp && resp.needsOptions) {
      notify(`${resp.error} — click here to open settings`, "error", openOptionsAction);
    } else {
      notify(`Failed: ${(resp && resp.error) || "no response"}`, "error");
    }
  } catch (err) {
    notify(`Failed: ${err.message}`, "error");
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
  if (changeInfo.title || changeInfo.status === "complete") scheduleRender();
});
browser.contextualIdentities.onCreated.addListener(scheduleRender);
browser.contextualIdentities.onRemoved.addListener(scheduleRender);
browser.contextualIdentities.onUpdated.addListener(scheduleRender);

// Mode, backend-cache, portal-pin, and mapping changes reflect live.
browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  const keys = Object.keys(changes);
  if (changes.config) {
    const oldMode = changes.config.oldValue?.mode;
    const newMode = changes.config.newValue?.mode;
    if (oldMode !== newMode) {
      modeRevision += 1;
      rolePicks.clear();
      searchActiveQuery = "";
      searchPinnedQuery = "";
      searchAllQuery = "";
      pendingFocusSection = null;
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
  }
});

// ── Full refresh (config + accounts + tabs) ──────────────────
async function fullRefresh() {
  const generation = ++refreshGeneration;
  loadingState.classList.add("visible");
  const nextConfig = await readConfig();
  if (generation !== refreshGeneration) return;
  if (nextConfig.mode === "portal" && backendRequestController) {
    backendRequestController.abort();
  }

  const [nextAccounts, nextMetadata] = await Promise.all([
    readAccounts(nextConfig),
    readStoredMetadata(nextConfig.mode),
  ]);
  if (generation !== refreshGeneration) return;

  config = nextConfig;
  accounts = nextAccounts.accounts;
  backendOnline = nextAccounts.backendOnline;
  usingCache = nextAccounts.usingCache;
  backendAuthProblem = nextAccounts.backendAuthProblem;
  rememberedRoles = nextMetadata.rememberedRoles;
  portalRoles = nextMetadata.portalRoles;
  portalAccountOriginalNames = nextMetadata.portalAccountOriginalNames;
  backendPinnedAccountIds = nextMetadata.backendPinnedAccountIds;
  accountContainers = nextMetadata.accountContainers;
  containerAccounts = nextMetadata.containerAccounts;
  updateStatus();
  updatePortalToolbar();

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
// Never let cosmetics break init (e.g. stale cached HTML after update)
try {
  const versionEl = document.getElementById("brand-version");
  if (versionEl) {
    versionEl.textContent = `v${browser.runtime.getManifest().version}`;
  }
} catch {}
fullRefresh();
