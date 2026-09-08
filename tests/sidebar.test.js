import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  ONBOARDING_KEY,
  ONBOARDING_STATES,
} from "../firefox-extension/shared/onboarding.js";

const TEST_EXTENSION_ORIGIN = "moz-extension://containoodle-test";
const TEST_HELPER_TOKEN = "A".repeat(43);
const TEST_HELPER_ROLE = "__CONTAINOODLE_TEST_ROLE__";
const TEST_SSO_IDENTITY = "a".repeat(64);
const TEST_OTHER_SSO_IDENTITY = "b".repeat(64);

function focusedControl(fixture, key) {
  return fixture.ids.get("account-list").querySelectorAll("[data-focus-key]")
    .find((control) => control.dataset.focusKey === key);
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

class ClassList {
  constructor(element) {
    this.element = element;
  }

  values() {
    return this.element.className.split(/\s+/).filter(Boolean);
  }

  add(...names) {
    this.element.className = [...new Set([...this.values(), ...names])].join(" ");
  }

  remove(...names) {
    this.element.className = this.values()
      .filter((name) => !names.includes(name))
      .join(" ");
  }

  contains(name) {
    return this.values().includes(name);
  }
}

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.className = "";
    this.classList = new ClassList(this);
    this.dataset = {};
    this.style = {};
    this.attributes = {};
    this.listeners = {};
    this.value = "";
    this.hidden = false;
    this.disabled = false;
    this._textContent = "";
  }

  set textContent(value) {
    if (this.ownerDocument && this.ownerDocument.activeElement !== this &&
        this.contains(this.ownerDocument.activeElement)) {
      this.ownerDocument.activeElement = this.ownerDocument.body;
    }
    this._textContent = String(value);
    for (const child of this.children) child.parentNode = null;
    this.children = [];
  }

  get textContent() {
    return this._textContent + this.children.map((child) => child.textContent).join("");
  }

  appendChild(child) {
    child.parentNode = this;
    child.ownerDocument = this.ownerDocument;
    this.children.push(child);
    return child;
  }

  addEventListener(type, listener) {
    (this.listeners[type] ||= []).push(listener);
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes[name];
  }

  matches(selector) {
    const attribute = selector.match(/^\[([a-z-]+)(?:="([^"]*)")?\]$/);
    if (attribute) {
      const name = attribute[1];
      const value = name.startsWith("data-")
        ? this.dataset[name.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase())]
        : this.getAttribute(name);
      return value !== undefined && (attribute[2] === undefined || attribute[2] === value);
    }
    if (selector.startsWith(".")) {
      return selector
        .slice(1)
        .split(".")
        .every((name) => this.classList.contains(name));
    }
    return this.tagName === selector.toUpperCase();
  }

  querySelector(selector) {
    if (this.matches(selector)) return this;
    for (const child of this.children) {
      const found = child.querySelector && child.querySelector(selector);
      if (found) return found;
    }
    return null;
  }

  querySelectorAll(selector) {
    return this.children.flatMap((child) => [
      ...(child.matches?.(selector) ? [child] : []),
      ...(child.querySelectorAll?.(selector) || []),
    ]);
  }

  closest(selector) {
    return this.matches(selector) ? this : this.parentNode?.closest(selector) || null;
  }

  contains(node) {
    return Boolean(node && (node === this || this.children.some((child) => child.contains(node))));
  }

  focus() {
    if (this.ownerDocument) this.ownerDocument.activeElement = this;
  }

  setSelectionRange(start, end, direction = "none") {
    this.selectionStart = start;
    this.selectionEnd = end;
    this.selectionDirection = direction;
  }
  scrollIntoView() {}
}

function extensionEvent() {
  const listeners = [];
  return {
    listeners,
    addListener(listener) {
      listeners.push(listener);
    },
  };
}

function storageGet(storageData, keys) {
  if (keys === null) return { ...storageData };
  if (typeof keys === "string") {
    return Object.hasOwn(storageData, keys) ? { [keys]: storageData[keys] } : {};
  }
  return Object.fromEntries(
    keys
      .filter((key) => Object.hasOwn(storageData, key))
      .map((key) => [key, storageData[key]])
  );
}

const originalGlobals = Object.fromEntries(
  ["browser", "document", "fetch", "location", "setTimeout"].map((name) => [
    name,
    {
      exists: Object.prototype.hasOwnProperty.call(globalThis, name),
      value: globalThis[name],
    },
  ])
);

let importSequence = 0;
let scheduledTimers = new Set();

function createSidebarFixture({
  i18n,
  storage = {},
  includeDefaultStorage = true,
  containers = [],
  tabs = [],
  sendMessageImpl = null,
  fetchImpl = async () => {
    throw new Error("Unexpected backend request");
  },
} = {}) {
  const defaultStorage = {
    config: {
      mode: "portal",
      portalStartUrl: "https://example.awsapps.com/start",
    },
    portalPinnedAccounts: [],
    backendPinnedAccountIds: [],
    backendAuthToken: TEST_HELPER_TOKEN,
  };
  const storageData = includeDefaultStorage
    ? { ...defaultStorage, ...storage }
    : { ...storage };
  const sentMessages = [];
  const storageGetCalls = [];
  const tabUpdates = [];
  const tabRemovals = [];
  const windowUpdates = [];
  let containerQueryCalls = 0;
  let tabQueryCalls = 0;
  let openOptionsCalls = 0;
  const storageChanged = extensionEvent();
  const ids = new Map([
    ["account-list", new Element()],
    ["loading-state", new Element()],
    ["status-dot", new Element()],
    ["status-text", new Element()],
    ["refresh-btn", new Element("button")],
    ["options-btn", new Element("button")],
    ["notification", new Element()],
    ["sidebar-announcement", new Element()],
    ["brand-version", new Element()],
    ["portal-toolbar", new Element()],
    ["open-portal-btn", new Element("button")],
    ["portal-toolbar-hint", new Element()],
    ["onboarding-card", new Element("section")],
    ["onboarding-heading", new Element("h1")],
    ["onboarding-description", new Element("p")],
    ["onboarding-open-setup", new Element("button")],
  ]);
  ids.get("onboarding-card").hidden = true;
  const document = {
    createElementNS: (_namespace, tagName) => new Element(tagName),
    getElementById(id) {
      return ids.get(id) || null;
    },
    createElement(tagName) {
      const element = new Element(tagName);
      element.ownerDocument = document;
      return element;
    },
    createTextNode(text) {
      const node = new Element("#text");
      node.textContent = text;
      return node;
    },
  };
  document.body = document.createElement("body");
  document.activeElement = document.body;
  for (const element of ids.values()) {
    element.ownerDocument = document;
    document.body.appendChild(element);
  }
  const browser = {
    i18n,
    storage: {
      local: {
        async get(keys) {
          storageGetCalls.push(
            Array.isArray(keys) ? [...keys] : keys,
          );
          return storageGet(storageData, keys);
        },
        async set(values) {
          const changes = {};
          for (const [key, value] of Object.entries(values)) {
            changes[key] = { oldValue: storageData[key], newValue: value };
            storageData[key] = value;
          }
          for (const listener of storageChanged.listeners) {
            listener(changes, "local");
          }
        },
        async remove(keys) {
          const changes = {};
          for (const key of typeof keys === "string" ? [keys] : keys) {
            if (!Object.hasOwn(storageData, key)) continue;
            changes[key] = { oldValue: storageData[key] };
            delete storageData[key];
          }
          for (const listener of storageChanged.listeners) {
            listener(changes, "local");
          }
        },
      },
      onChanged: storageChanged,
    },
    contextualIdentities: {
      async query() {
        containerQueryCalls += 1;
        return containers.map((container) => ({ ...container }));
      },
      onCreated: extensionEvent(),
      onRemoved: extensionEvent(),
      onUpdated: extensionEvent(),
    },
    tabs: {
      async get(id) {
        const tab = tabs.find((entry) => entry.id === id);
        if (!tab) throw new Error("Synthetic tab no longer exists");
        return { ...tab };
      },
      async update(id, changes) {
        tabUpdates.push({ id, changes });
        Object.assign(tabs.find((tab) => tab.id === id), changes);
      },
      async remove(id) {
        tabRemovals.push(id);
        const index = tabs.findIndex((tab) => tab.id === id);
        if (index >= 0) tabs.splice(index, 1);
      },
      async query(query) {
        tabQueryCalls += 1;
        const matches = query && query.active
          ? tabs.filter((tab) => tab.active)
          : tabs;
        return matches.map((tab) => ({ ...tab }));
      },
      onRemoved: extensionEvent(),
      onCreated: extensionEvent(),
      onActivated: extensionEvent(),
      onUpdated: extensionEvent(),
    },
    runtime: {
      getManifest() {
        return { version: "test" };
      },
      async openOptionsPage() {
        openOptionsCalls += 1;
      },
      async sendMessage(message) {
        sentMessages.push(message);
        if (sendMessageImpl) {
          return sendMessageImpl(message, {
            storageData,
            storageChanged,
          });
        }
        if (message.type === "set-portal-pin") {
          const previous = Array.isArray(storageData.portalPinnedAccounts)
            ? storageData.portalPinnedAccounts
            : [];
          const next = previous.filter(
            (pin) => pin.accountId !== message.account.accountId
          );
          if (message.pinned) {
            const role = storageData[
              `portalRoleChoice/${message.account.accountId}`
            ];
            next.push({
              ...message.account,
              ...(typeof role === "string" && role ? { role } : {}),
            });
          }
          storageData.portalPinnedAccounts = next;
          for (const listener of storageChanged.listeners) {
            listener({
              portalPinnedAccounts: {
                oldValue: previous,
                newValue: next,
              },
            }, "local");
          }
          return { ok: true, pinned: Boolean(message.pinned) };
        }
        if (message.type === "set-backend-pin") {
          const previous = Array.isArray(storageData.backendPinnedAccountIds)
            ? storageData.backendPinnedAccountIds
            : [];
          const accountId = String(message.accountId);
          const next = previous.filter((entry) => String(entry) !== accountId);
          if (message.pinned) next.push(accountId);
          storageData.backendPinnedAccountIds = next;
          for (const listener of storageChanged.listeners) {
            listener({
              backendPinnedAccountIds: {
                oldValue: previous,
                newValue: next,
              },
            }, "local");
          }
          return { ok: true, pinned: Boolean(message.pinned) };
        }
        if (message.type === "open-portal") return { ok: true };
        return { ok: true };
      },
    },
    windows: {
      async update(id, changes) { windowUpdates.push({ id, changes }); },
    },
  };

  return {
    browser,
    document,
    fetch: fetchImpl,
    ids,
    storageData,
    storageChanged,
    sentMessages,
    tabUpdates,
    tabRemovals,
    windowUpdates,
    storageGetCalls,
    get containerQueryCalls() {
      return containerQueryCalls;
    },
    get tabQueryCalls() {
      return tabQueryCalls;
    },
    get openOptionsCalls() {
      return openOptionsCalls;
    },
  };
}

async function loadSidebar(fixture, { waitForInitialRefresh = true, helperTimeoutMs } = {}) {
  const nativeSetTimeout = originalGlobals.setTimeout.value;
  const fixtureTimers = new Set();
  scheduledTimers = fixtureTimers;
  globalThis.setTimeout = (callback, delay, ...args) => {
    const timer = nativeSetTimeout((...callbackArgs) => {
      fixtureTimers.delete(timer);
      callback(...callbackArgs);
    }, helperTimeoutMs && delay === 60_000 ? helperTimeoutMs : delay, ...args);
    fixtureTimers.add(timer);
    timer.unref?.();
    return timer;
  };
  globalThis.document = fixture.document;
  globalThis.browser = fixture.browser;
  globalThis.fetch = fixture.fetch;
  globalThis.location = { origin: TEST_EXTENSION_ORIGIN };
  await import(
    `../firefox-extension/sidebar/sidebar.js?test=${importSequence += 1}`
  );
  if (waitForInitialRefresh) {
    await waitFor(
      () => !fixture.ids.get("loading-state").classList.contains("visible"),
      "sidebar initial refresh did not finish",
    );
  } else {
    await settle();
  }
}

async function settle(turns = 5) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function waitFor(check, message) {
  const nativeSetTimeout = originalGlobals.setTimeout.value;
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => nativeSetTimeout(resolve, 5));
  }
  assert.ok(check(), message);
}

function cleanupGlobals() {
  for (const timer of scheduledTimers) clearTimeout(timer);
  scheduledTimers.clear();
  for (const [name, original] of Object.entries(originalGlobals)) {
    if (original.exists) globalThis[name] = original.value;
    else delete globalThis[name];
  }
}

function backendResponse(
  payload,
  onRequest = () => {},
  { status = 200, token = TEST_HELPER_TOKEN, authFailure = null } = {},
) {
  let challengeSequence = 0;
  return async (url, options = {}) => {
    onRequest(url, options);
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

    const body = JSON.stringify(await payload);
    const challenge = new Headers(options.headers).get(
      "X-Containoodle-Challenge",
    );
    const target = `${requestUrl.pathname}${requestUrl.search}`;
    const responseProof = authFailure === "response-proof"
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
  assert.equal(headers.has("Authorization"), false);
  const rendered = `${url}\n${[...headers].flat().join("\n")}`;
  assert.doesNotMatch(rendered, new RegExp(token));
}

test("section buttons preserve keyboard focus and the search caret across live refreshes", async () => {
  const fixture = createSidebarFixture({
    storage: {
      config: { mode: "backend" },
      accountsCache: [{ accountId: "000000000000", accountName: "__CONTAINOODLE_TEST_ACCOUNT__" }],
    },
  });
  try {
    await loadSidebar(fixture);
    const toggle = focusedControl(fixture, "section:all");
    assert.equal(toggle.tagName, "BUTTON");
    assert.equal(toggle.type, "button");
    assert.equal(toggle.getAttribute("aria-expanded"), "false");
    assert.equal(toggle.querySelector(".section-chevron").getAttribute("aria-hidden"), "true");
    toggle.focus();
    toggle.listeners.click[0]();
    await settle();
    const expanded = focusedControl(fixture, "section:all");
    assert.equal(expanded.getAttribute("aria-expanded"), "true");
    assert.equal(fixture.document.activeElement, expanded);

    const search = focusedControl(fixture, "search:all");
    assert.equal(search.getAttribute("aria-label"), "Filter other accounts…");
    search.focus();
    search.value = "  ConTaInOodle  ";
    search.setSelectionRange(4, 7, "backward");
    search.listeners.input[0]();
    await settle();
    const replacement = focusedControl(fixture, "search:all");
    assert.equal(fixture.document.activeElement, replacement);
    assert.equal(replacement.value, "  ConTaInOodle  ");
    assert.deepEqual([replacement.selectionStart, replacement.selectionEnd, replacement.selectionDirection], [4, 7, "backward"]);
    assert.match(fixture.ids.get("account-list").textContent, /__CONTAINOODLE_TEST_ACCOUNT__/);

    fixture.browser.tabs.onUpdated.listeners[0](1, { title: "__CONTAINOODLE_TEST_TAB__" });
    await waitFor(() => focusedControl(fixture, "search:all") !== replacement, "event-driven render did not finish");
    assert.equal(fixture.document.activeElement, focusedControl(fixture, "search:all"));
    assert.equal(fixture.document.activeElement.selectionStart, 4);
    fixture.ids.get("options-btn").focus();
    const previous = focusedControl(fixture, "section:all");
    fixture.browser.tabs.onActivated.listeners[0]();
    await waitFor(() => focusedControl(fixture, "section:all") !== previous, "second render did not finish");
    assert.equal(fixture.document.activeElement, fixture.ids.get("options-btn"), "updates must not steal focus from the footer");
  } finally {
    cleanupGlobals();
  }
});

test("Active and Favorites have distinct named sections without migrating or duplicating saved accounts", async () => {
  const active = { accountId: "000000000000", accountName: "__CONTAINOODLE_TEST_OPEN_ACCOUNT__" };
  const favorite = { accountId: "000000000001", accountName: "__CONTAINOODLE_TEST_FAVORITE_ACCOUNT__" };
  const other = { accountId: "000000000002", accountName: "__CONTAINOODLE_TEST_OTHER_ACCOUNT__" };
  const storeId = "firefox-container-synthetic-favorites";
  for (const mode of ["backend", "portal"]) {
    const fixture = createSidebarFixture({
      storage: {
        config: { mode, portalStartUrl: "https://example.awsapps.com/start" },
        [ONBOARDING_KEY]: ONBOARDING_STATES.COMPLETE,
        accountsCache: [active, favorite, other],
        backendPinnedAccountIds: [active.accountId, favorite.accountId],
        portalPinnedAccounts: [active, favorite],
        [`accountContainer/${active.accountId}`]: storeId,
        [`containerAccount/${storeId}`]: active.accountId,
      },
      containers: [{ cookieStoreId: storeId, name: active.accountName, color: "green" }],
      tabs: [{ id: 7, cookieStoreId: storeId, active: true, windowId: 1, title: "__CONTAINOODLE_TEST_OPEN_TAB__" }],
      fetchImpl: mode === "backend" ? backendResponse([active, favorite, other]) : undefined,
    });
    try {
      await loadSidebar(fixture);
      const list = fixture.ids.get("account-list");
      const opened = list.querySelector(".section-active");
      const saved = list.querySelector(".section-pinned");
      assert.equal(opened.querySelector(".section-label").textContent, "Active (1)");
      assert.equal(saved.querySelector(".section-label").textContent, "Favorites (1)");
      assert.equal(opened.querySelector(".section-description").textContent, "Open tabs now");
      assert.equal(saved.querySelector(".section-description").textContent, "Saved shortcuts · no open tabs");
      for (const section of [opened, saved]) {
        const button = section.querySelector(".section-header");
        assert.equal(button.tagName, "BUTTON");
        assert.equal(button.getAttribute("aria-describedby"), section.querySelector(".section-description").id);
        assert.equal(section.querySelector(".section-symbol").getAttribute("aria-hidden"), "true");
      }
      assert.equal(opened.querySelector(".section-symbol").textContent, "●");
      assert.equal(saved.querySelector(".section-symbol").textContent, "★");
      assert.equal(list.querySelectorAll(".account-name").filter(n => n.textContent === active.accountName).length, 1);
      assert.equal(saved.querySelector(".account-name").textContent, favorite.accountName);
      assert.equal(focusedControl(fixture, "search:pinned").placeholder, "Filter favorites…");
      assert.equal(focusedControl(fixture, `pin:${mode}:${favorite.accountId}`).title, "Remove from favorites");
      assert.equal(Boolean(list.querySelector(".section-all")), mode === "backend");
      const toggle = focusedControl(fixture, "section:pinned");
      toggle.focus();
      toggle.listeners.click[0]();
      await settle();
      assert.equal(focusedControl(fixture, "section:pinned").getAttribute("aria-expanded"), "false");
      assert.equal(fixture.document.activeElement, focusedControl(fixture, "section:pinned"));
      assert.equal(focusedControl(fixture, "search:pinned"), undefined);
      assert.deepEqual(fixture.storageData.backendPinnedAccountIds, [active.accountId, favorite.accountId]);
      assert.deepEqual(fixture.storageData.portalPinnedAccounts, [active, favorite]);
    } finally { cleanupGlobals(); }
  }
});

test("tab switching and closing are separately named native actions with surviving focus", async () => {
  const accountId = "000000000000";
  const storeId = "firefox-container-synthetic-keyboard";
  const fixture = createSidebarFixture({
    storage: {
      portalPinnedAccounts: [{ accountId, accountName: "__CONTAINOODLE_TEST_ACCOUNT__" }],
      [`accountContainer/${accountId}`]: storeId,
      [`containerAccount/${storeId}`]: accountId,
    },
    containers: [{ cookieStoreId: storeId, name: "__CONTAINOODLE_TEST_ACCOUNT__", color: "blue" }],
    tabs: [
      { id: 7, cookieStoreId: storeId, active: true, windowId: 1, title: "__CONTAINOODLE_TEST_TAB_ONE__" },
      { id: 8, cookieStoreId: storeId, active: false, windowId: 1, title: "__CONTAINOODLE_TEST_TAB_TWO__" },
    ],
  });
  try {
    await loadSidebar(fixture);
    const switcher = focusedControl(fixture, "tab:7");
    const close = focusedControl(fixture, "close-tab:7");
    assert.equal(switcher.tagName, "BUTTON");
    assert.equal(close.tagName, "BUTTON");
    assert.equal(switcher.parentNode, close.parentNode);
    assert.equal(switcher.querySelectorAll("button").length, 0, "switch action has no nested button");
    assert.equal(switcher.getAttribute("aria-current"), "true");
    assert.equal(switcher.getAttribute("aria-label"), "Switch to tab: __CONTAINOODLE_TEST_TAB_ONE__");
    assert.equal(close.getAttribute("aria-label"), "Close tab: __CONTAINOODLE_TEST_TAB_ONE__");
    switcher.focus();
    await switcher.listeners.click[0]();
    assert.deepEqual(fixture.tabUpdates, [{ id: 7, changes: { active: true } }]);
    assert.deepEqual(fixture.windowUpdates, [{ id: 1, changes: { focused: true } }]);
    fixture.browser.tabs.onUpdated.listeners[0](7, { title: "__CONTAINOODLE_TEST_TAB_ONE__" });
    await waitFor(() => focusedControl(fixture, "tab:7") !== switcher, "updated tab row did not render");
    assert.equal(fixture.document.activeElement, focusedControl(fixture, "tab:7"));
    const activeClose = focusedControl(fixture, "close-tab:7");
    activeClose.focus();
    await activeClose.listeners.click[0]({ stopPropagation() {} });
    await settle();
    assert.deepEqual(fixture.tabRemovals, [7]);
    assert.equal(focusedControl(fixture, "tab:7"), undefined);
    assert.equal(fixture.tabUpdates.length, 1, "closing a tab must not switch to it");
    assert.ok(fixture.ids.get("account-list").contains(fixture.document.activeElement), "closing the focused row retains a visible focus target");
  } finally {
    cleanupGlobals();
  }
});

test("role choices receive focus, support Escape and return to their launch or change-role control", async () => {
  const accountId = "000000000000";
  for (const pinnedRole of [undefined, "__CONTAINOODLE_TEST_ROLE_ONE__"]) {
    const fixture = createSidebarFixture({
      storage: { portalPinnedAccounts: [{ accountId, accountName: "__CONTAINOODLE_TEST_ACCOUNT__", ...(pinnedRole ? { role: pinnedRole } : {}) }] },
      sendMessageImpl: async (message) => message.type === "discover-roles"
        ? { ok: true, roles: ["__CONTAINOODLE_TEST_ROLE_ONE__", "__CONTAINOODLE_TEST_ROLE_TWO__"] }
        : { chooseRole: ["__CONTAINOODLE_TEST_ROLE_ONE__", "__CONTAINOODLE_TEST_ROLE_TWO__"] },
    });
    try {
      await loadSidebar(fixture);
      const originKey = `${pinnedRole ? "choose-role" : "launch"}:portal:${accountId}`;
      const origin = focusedControl(fixture, originKey);
      origin.focus();
      origin.listeners.click[0]({ stopPropagation() {} });
      await settle(10);
      const firstRole = focusedControl(fixture, `role:${accountId}:0`);
      assert.equal(fixture.document.activeElement, firstRole);
      assert.equal(firstRole.type, "button");
      const picker = firstRole.closest(".role-picker");
      assert.equal(picker.getAttribute("role"), "group");
      assert.equal(picker.getAttribute("aria-label"), "Choose a role for __CONTAINOODLE_TEST_ACCOUNT__");
      let prevented = false;
      picker.listeners.keydown[0]({ key: "Escape", preventDefault() { prevented = true; }, stopPropagation() {} });
      await settle(10);
      assert.equal(prevented, true);
      assert.equal(fixture.ids.get("account-list").querySelector(".role-picker"), null);
      assert.equal(fixture.document.activeElement, focusedControl(fixture, originKey));
      assert.equal(fixture.sentMessages.filter((message) => message.role).length, 0, "dismissing never launches a role");
    } finally {
      cleanupGlobals();
    }
  }
});

test("late role discovery does not steal focus after a user moves to another control", async () => {
  const accountId = "000000000000";
  let resolveRoles;
  const fixture = createSidebarFixture({
    storage: { portalPinnedAccounts: [{ accountId, accountName: "__CONTAINOODLE_TEST_ACCOUNT__", role: TEST_HELPER_ROLE }] },
    sendMessageImpl: (message) => message.type === "discover-roles"
      ? new Promise((resolve) => { resolveRoles = resolve; }) : { ok: true },
  });
  try {
    await loadSidebar(fixture);
    const origin = focusedControl(fixture, `choose-role:portal:${accountId}`);
    origin.focus();
    origin.listeners.click[0]({ stopPropagation() {} });
    fixture.ids.get("options-btn").focus();
    resolveRoles({ ok: true, roles: [TEST_HELPER_ROLE] });
    await settle(10);
    assert.ok(focusedControl(fixture, `role:${accountId}:0`));
    assert.equal(fixture.document.activeElement, fixture.ids.get("options-btn"));
  } finally {
    cleanupGlobals();
  }
});

test("helper timeout leaves cached accounts intact and offers an announced keyboard recovery action", async () => {
  const account = { accountId: "000000000000", accountName: "__CONTAINOODLE_TEST_ACCOUNT__" };
  const fixture = createSidebarFixture({
    storage: { config: { mode: "backend" }, accountsCache: [account], accountsCacheAt: 1 },
    fetchImpl: () => new Promise(() => {}),
  });
  try {
    await loadSidebar(fixture, { helperTimeoutMs: 5 });
    assert.equal(fixture.ids.get("status-text").textContent, "Offline · 1 cached");
    assert.deepEqual(fixture.storageData.accountsCache, [account]);
    assert.equal(fixture.storageData.accountsCacheAt, 1);
    const message = "Local helper timed out. Check server.py and try again.";
    assert.equal(fixture.ids.get("status-text").title, message);
    assert.equal(fixture.ids.get("sidebar-announcement").textContent, message);
    const action = fixture.ids.get("notification").querySelector(".notification-action");
    assert.equal(action.tagName, "BUTTON");
    assert.equal(action.textContent, message);
    action.focus();
    await action.listeners.click[0]();
    assert.equal(fixture.openOptionsCalls, 1);
    const html = await readFile(new URL("../firefox-extension/sidebar/sidebar.html", import.meta.url), "utf8");
    assert.match(html, /id="sidebar-announcement"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
    assert.match(html, /id="status-text"[^>]*role="status"/);
  } finally {
    cleanupGlobals();
  }
});

test("sidebar onboarding markup has a labelled native setup action", async () => {
  const html = await readFile(
    new URL("../firefox-extension/sidebar/sidebar.html", import.meta.url),
    "utf8",
  );
  const card = html.match(
    /<section\s+id="onboarding-card"[\s\S]*?<\/section>/,
  );

  assert.ok(card, "onboarding card must remain a semantic section");
  assert.match(card[0], /aria-labelledby="onboarding-heading"/);
  assert.match(card[0], /aria-describedby="onboarding-description"/);
  assert.match(
    card[0],
    /<button[\s\S]*?type="button"[\s\S]*?id="onboarding-open-setup"/,
  );
  assert.match(card[0], />Open setup<\/button>/);
});

test("first-install sidebar waits for lifecycle onboarding before legacy reads", async () => {
  let releaseOnboarding;
  const onboardingReady = new Promise((resolve) => {
    releaseOnboarding = resolve;
  });
  let backendFetchCalls = 0;
  const fixture = createSidebarFixture({
    includeDefaultStorage: false,
    fetchImpl: async () => {
      backendFetchCalls += 1;
      throw new Error("first-install onboarding must not contact the helper");
    },
    sendMessageImpl: async (message) => {
      assert.deepEqual(message, { type: "resolve-connection-onboarding" });
      return { state: await onboardingReady };
    },
  });

  try {
    await loadSidebar(fixture, { waitForInitialRefresh: false });

    assert.equal(fixture.ids.get("onboarding-card").hidden, true);
    assert.equal(
      fixture.ids.get("loading-state").classList.contains("visible"),
      true,
    );
    assert.deepEqual(fixture.storageGetCalls, [ONBOARDING_KEY]);
    assert.deepEqual(fixture.sentMessages, [
      { type: "resolve-connection-onboarding" },
    ]);
    assert.equal(backendFetchCalls, 0);
    assert.equal(fixture.containerQueryCalls, 0);
    assert.equal(fixture.tabQueryCalls, 0);

    releaseOnboarding(ONBOARDING_STATES.CHOOSE);
    await waitFor(
      () => !fixture.ids.get("onboarding-card").hidden,
      "sidebar did not show onboarding after lifecycle initialization",
    );

    assert.equal(
      fixture.ids.get("onboarding-card").dataset.state,
      ONBOARDING_STATES.CHOOSE,
    );
    assert.deepEqual(fixture.storageGetCalls, [ONBOARDING_KEY]);
    assert.equal(backendFetchCalls, 0);
    assert.equal(fixture.containerQueryCalls, 0);
    assert.equal(fixture.tabQueryCalls, 0);
  } finally {
    cleanupGlobals();
  }
});

test("pending onboarding shows only the accessible setup path", async () => {
  const cases = [
    {
      state: ONBOARDING_STATES.CHOOSE,
      heading: "Set up Containoodle",
      description: "Choose how Containoodle should open AWS console sessions.",
    },
    {
      state: ONBOARDING_STATES.BACKEND,
      heading: "Finish helper setup",
      description: "Connect and test the local AWS CLI helper before opening accounts.",
    },
    {
      state: ONBOARDING_STATES.PORTAL,
      heading: "Finish portal setup",
      description: "Add your AWS access portal and confirm it is ready before opening accounts.",
    },
  ];

  for (const { state, heading, description } of cases) {
    let backendFetchCalls = 0;
    const fixture = createSidebarFixture({
      storage: {
        [ONBOARDING_KEY]: state,
        config: {
          mode: "backend",
          backendUrl: "http://127.0.0.1:8421",
          portalStartUrl: "https://d-0000000000.awsapps.com/start",
        },
      },
      containers: [{
        cookieStoreId: "firefox-container-synthetic",
        name: "__CONTAINOODLE_TEST_ACCOUNT__",
        color: "blue",
      }],
      tabs: [{
        id: 1,
        cookieStoreId: "firefox-container-synthetic",
        active: true,
        windowId: 1,
        title: "Synthetic console",
      }],
      fetchImpl: async () => {
        backendFetchCalls += 1;
        throw new Error("onboarding must not contact the helper");
      },
      sendMessageImpl: async () => {
        throw new Error("onboarding must not send runtime messages");
      },
    });

    try {
      await loadSidebar(fixture);

      const card = fixture.ids.get("onboarding-card");
      assert.equal(card.hidden, false);
      assert.equal(card.dataset.state, state);
      assert.equal(fixture.ids.get("onboarding-heading").textContent, heading);
      assert.equal(
        fixture.ids.get("onboarding-description").textContent,
        description,
      );
      assert.equal(fixture.ids.get("account-list").hidden, true);
      assert.equal(fixture.ids.get("loading-state").hidden, true);
      assert.equal(
        fixture.ids.get("loading-state").classList.contains("visible"),
        false,
      );
      assert.equal(fixture.ids.get("portal-toolbar").hidden, true);
      assert.equal(fixture.ids.get("refresh-btn").hidden, true);
      assert.equal(fixture.ids.get("status-text").textContent, "Setup required");
      assert.equal(fixture.ids.get("status-text").classList.contains("setup"), true);
      assert.equal(fixture.ids.get("status-dot").className, "dot setup");

      assert.equal(backendFetchCalls, 0);
      assert.deepEqual(fixture.sentMessages, []);
      assert.equal(fixture.containerQueryCalls, 0);
      assert.equal(fixture.tabQueryCalls, 0);
      assert.deepEqual(fixture.storageGetCalls, [ONBOARDING_KEY]);

      await fixture.ids.get("onboarding-open-setup").listeners.click[0]();
      await settle();
      assert.equal(fixture.openOptionsCalls, 1);
      assert.equal(backendFetchCalls, 0);
      assert.deepEqual(fixture.sentMessages, []);
      assert.equal(fixture.containerQueryCalls, 0);
      assert.equal(fixture.tabQueryCalls, 0);
    } finally {
      cleanupGlobals();
    }
  }
});

test("completing onboarding resumes the existing sidebar refresh", async () => {
  const fixture = createSidebarFixture({
    storage: {
      [ONBOARDING_KEY]: ONBOARDING_STATES.CHOOSE,
    },
  });

  try {
    await loadSidebar(fixture);
    assert.equal(fixture.ids.get("onboarding-card").hidden, false);
    assert.equal(fixture.containerQueryCalls, 0);
    assert.equal(fixture.tabQueryCalls, 0);

    await fixture.browser.storage.local.set({
      [ONBOARDING_KEY]: ONBOARDING_STATES.COMPLETE,
    });
    await waitFor(
      () => fixture.ids.get("status-text").textContent === "Portal · ready",
      "normal sidebar refresh did not resume after onboarding",
    );

    assert.equal(fixture.ids.get("onboarding-card").hidden, true);
    assert.equal(fixture.ids.get("account-list").hidden, false);
    assert.equal(fixture.ids.get("loading-state").hidden, false);
    assert.equal(fixture.ids.get("portal-toolbar").hidden, false);
    assert.equal(fixture.ids.get("refresh-btn").hidden, false);
    assert.equal(fixture.ids.get("status-text").classList.contains("setup"), false);
    assert.equal(fixture.containerQueryCalls, 1);
    assert.equal(fixture.tabQueryCalls, 2);
    assert.deepEqual(fixture.sentMessages, []);
  } finally {
    cleanupGlobals();
  }
});

test("missing, invalid, and complete onboarding markers preserve sidebar behavior", async () => {
  const cases = [
    { label: "missing", state: undefined },
    { label: "invalid", state: "__CONTAINOODLE_TEST_INVALID_STATE__" },
    { label: "complete", state: ONBOARDING_STATES.COMPLETE },
  ];

  for (const { label, state } of cases) {
    const fixture = createSidebarFixture({
      storage: state === undefined ? {} : { [ONBOARDING_KEY]: state },
    });

    try {
      await loadSidebar(fixture);
      assert.equal(
        fixture.ids.get("onboarding-card").hidden,
        true,
        `${label} marker must not show onboarding`,
      );
      assert.equal(fixture.ids.get("account-list").hidden, false);
      assert.equal(fixture.ids.get("portal-toolbar").hidden, false);
      assert.equal(fixture.ids.get("status-text").textContent, "Portal · ready");
      assert.equal(fixture.containerQueryCalls, 1);
      assert.equal(fixture.tabQueryCalls, 2);
      assert.deepEqual(
        fixture.sentMessages,
        state === undefined
          ? [{ type: "resolve-connection-onboarding" }]
          : [],
      );
    } finally {
      cleanupGlobals();
    }
  }
});

test("backend account refresh authenticates while portal mode never calls the helper", async () => {
  const requests = [];
  const backend = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "https://d-0000000000.awsapps.com/start",
      },
    },
    fetchImpl: backendResponse([], (url, options) => {
      requests.push({ url: String(url), options });
    }),
  });

  try {
    await loadSidebar(backend);
    assert.equal(requests.length, 2);
    assert.deepEqual(
      requests.map((request) => new URL(request.url).pathname),
      ["/auth/challenge", "/accounts"],
    );
    for (const request of requests) {
      assertNoRawHelperToken(request.url, request.options);
    }
  } finally {
    cleanupGlobals();
  }

  let portalHelperCalls = 0;
  const portal = createSidebarFixture({
    fetchImpl: async () => {
      portalHelperCalls += 1;
      throw new Error("unexpected helper call");
    },
  });
  try {
    await loadSidebar(portal);
    assert.equal(portalHelperCalls, 0);
    assert.equal(portal.storageData.backendAuthToken, TEST_HELPER_TOKEN);
  } finally {
    cleanupGlobals();
  }
});

test("sidebar localizes dynamic labels but never account names or identities", async () => {
  const account = { accountId: "000000000001", accountName: "__CONTAINOODLE_TEST_ACCOUNT__" };
  const calls = [];
  const fixture = createSidebarFixture({
    storage: { config: { mode: "backend", backendUrl: "http://127.0.0.1:8421" } },
    fetchImpl: backendResponse([account]),
    i18n: {
      getMessage(key, values) {
        calls.push({ key, values });
        if (key === "ui_connected_value_accounts") return `TEST-CONNECTED ${values[0]}`;
        return "";
      },
    },
  });
  try {
    await loadSidebar(fixture);
    assert.equal(fixture.ids.get("status-text").textContent, "TEST-CONNECTED 1");
    assert.deepEqual(fixture.storageData.accountsCache, [account]);
    assert.ok(calls.some(({ values }) => values[0] === "1"));
    assert.ok(calls.every(({ key }) => key !== account.accountName && key !== account.accountId));
  } finally {
    cleanupGlobals();
  }
});

test("signed malformed helper lists use only a valid saved cache and never overwrite it", async () => {
  const valid = { accountId: "000000000001", accountName: "__CONTAINOODLE_TEST_ACCOUNT__" };
  for (const payload of [[null], [{ ...valid, accountName: 7 }], [valid, { ...valid }]]) {
    const fixture = createSidebarFixture({
      storage: {
        config: { mode: "backend", backendUrl: "http://127.0.0.1:8421" },
        accountsCache: [valid],
        accountsCacheAt: 1,
      },
      fetchImpl: backendResponse(payload),
    });
    try {
      await loadSidebar(fixture);
      assert.equal(fixture.ids.get("status-text").textContent, "Offline · 1 cached");
      assert.deepEqual(fixture.storageData.accountsCache, [valid]);
      assert.equal(fixture.storageData.accountsCacheAt, 1);
    } finally {
      cleanupGlobals();
    }
  }
});

test("sidebar account-file guidance is safe, actionable and preserves cached accounts", async () => {
  const valid = { accountId: "000000000001", accountName: "__CONTAINOODLE_TEST_ACCOUNT__" };
  for (const [error, expected] of [
    ["accounts.json entry 1: duplicate accountId", "accounts.json entry 1: duplicate accountId"],
    ["__CONTAINOODLE_TEST_PRIVATE_ERROR__", ""],
  ]) {
    const fixture = createSidebarFixture({
      storage: {
        config: { mode: "backend", backendUrl: "http://127.0.0.1:8421" },
        accountsCache: [valid],
      },
      fetchImpl: backendResponse({ error }, () => {}, { status: 500 }),
    });
    try {
      await loadSidebar(fixture);
      assert.equal(fixture.ids.get("status-text").textContent, "Offline · 1 cached");
      assert.equal(fixture.ids.get("status-text").title, expected);
      assert.equal(fixture.ids.get("notification").textContent, expected);
      assert.deepEqual(fixture.storageData.accountsCache, [valid]);
      if (expected) {
        await fixture.ids.get("notification").querySelector(".notification-action").listeners.click[0]();
        assert.equal(fixture.openOptionsCalls, 1);
      }
    } finally {
      cleanupGlobals();
    }
  }
});

test("corrupt legacy account caches do not crash offline rendering or get rewritten", async () => {
  const malformedCache = [null, { accountId: "000000000001", accountName: 7 }];
  const fixture = createSidebarFixture({
    storage: {
      config: { mode: "backend", backendUrl: "http://127.0.0.1:8421" },
      accountsCache: malformedCache,
      accountsCacheAt: 1,
    },
  });
  try {
    await loadSidebar(fixture);
    assert.equal(fixture.ids.get("status-text").textContent, "Containoodle offline");
    assert.deepEqual(fixture.storageData.accountsCache, malformedCache);
    assert.equal(fixture.storageData.accountsCacheAt, 1);
    assert.ok(!fixture.ids.get("loading-state").classList.contains("visible"));
  } finally {
    cleanupGlobals();
  }
});

test("backend account refresh fails closed with clear token status", async () => {
  let fetchCalls = 0;
  const missing = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "",
      },
      backendAuthToken: undefined,
    },
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("unexpected fetch");
    },
  });

  try {
    await loadSidebar(missing);
    assert.strictEqual(fetchCalls, 0);
    assert.strictEqual(
      missing.ids.get("status-text").textContent,
      "Helper access token required"
    );
  } finally {
    cleanupGlobals();
  }

  const rejectedRequests = [];
  const rejected = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "",
      },
    },
    fetchImpl: backendResponse([], (url, options) => {
      rejectedRequests.push({ url: String(url), options });
    }, { authFailure: "server-proof" }),
  });

  try {
    await loadSidebar(rejected);
    assert.strictEqual(
      rejected.ids.get("status-text").textContent,
      "Helper access token rejected"
    );
    assert.equal(rejectedRequests.length, 1);
    assertNoRawHelperToken(
      rejectedRequests[0].url,
      rejectedRequests[0].options,
    );
  } finally {
    cleanupGlobals();
  }
});

function accountRow(root, accountName) {
  const pending = [root];
  while (pending.length > 0) {
    const candidate = pending.shift();
    if (
      candidate.classList?.contains("account-item") &&
      candidate.querySelector(".account-name")?.textContent === accountName
    ) {
      return candidate;
    }
    pending.push(...(candidate.children || []));
  }
  return null;
}

function countText(haystack, needle) {
  return haystack.split(needle).length - 1;
}

function accountNames(root) {
  const names = [];
  const pending = [root];
  while (pending.length > 0) {
    const candidate = pending.shift();
    if (candidate.classList?.contains("account-name")) {
      names.push(candidate.textContent);
    }
    pending.push(...(candidate.children || []));
  }
  return names;
}

async function filterSection(fixture, section, query) {
  const input = fixture.ids.get("account-list")
    .querySelector(`.section-${section}`)
    .querySelector(".section-search-input");
  input.value = query;
  input.listeners.input[0]();
  await settle();
}

test("backend name rules format every account section without changing source data or environment", async () => {
  const activeId = "000000000000";
  const pinnedId = "111111111111";
  const alphaId = "222222222222";
  const zuluId = "333333333333";
  const storeId = "firefox-container-synthetic-names";
  const backendAccounts = [
    { accountId: activeId, accountName: "__CONTAINOODLE_TEST_ACCOUNT__-DEV-active" },
    {
      accountId: pinnedId,
      accountName: "__CONTAINOODLE_TEST_ACCOUNT__-QA-pinned",
      role: TEST_HELPER_ROLE,
    },
    { accountId: zuluId, accountName: "__CONTAINOODLE_TEST_ACCOUNT__-DEV-zulu" },
    { accountId: alphaId, accountName: "__CONTAINOODLE_TEST_ACCOUNT__-PROD-alpha" },
  ];
  const originalAccounts = structuredClone(backendAccounts);
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        groupNamePattern: "^__CONTAINOODLE_TEST_ACCOUNT__-(PROD|QA|DEV)-(.*)$",
        groupNameReplacement: "short-$2",
      },
      backendPinnedAccountIds: [pinnedId],
      [`accountContainer/${activeId}`]: storeId,
      [`containerAccount/${storeId}`]: activeId,
      [`containerOriginalName/${storeId}`]: "__CONTAINOODLE_TEST_STALE_SOURCE__",
      [`portalAccountOriginalName/${activeId}`]: "__CONTAINOODLE_TEST_PORTAL_SOURCE__",
    },
    containers: [{ cookieStoreId: storeId, name: "short-active", color: "red" }],
    tabs: [{ id: 1, cookieStoreId: storeId, active: true, title: "Synthetic console" }],
    fetchImpl: backendResponse(backendAccounts),
  });

  try {
    await loadSidebar(fixture);
    const list = fixture.ids.get("account-list");
    list.querySelector(".section-all").querySelector(".section-header")
      .listeners.click[0]();
    await settle();

    assert.deepEqual(accountNames(list.querySelector(".section-active")), ["short-active"]);
    assert.deepEqual(accountNames(list.querySelector(".section-pinned")), ["short-pinned"]);
    assert.deepEqual(accountNames(list.querySelector(".section-all")), ["short-alpha", "short-zulu"]);
    for (const [label, env] of [
      ["short-active", "dev"], ["short-pinned", "qa"],
      ["short-alpha", "prod"], ["short-zulu", "dev"],
    ]) {
      const row = accountRow(list, label);
      assert.equal(row.classList.contains(`env-${env}`), true);
      assert.equal(row.querySelector(".env-badge").textContent, env.toUpperCase());
    }
    const pinnedRow = accountRow(list, "short-pinned");
    assert.equal(pinnedRow.querySelector(".role-chip").textContent, TEST_HELPER_ROLE);
    assert.equal(pinnedRow.querySelector(".pin-btn").getAttribute("aria-label"), "Remove short-pinned from favorites");
    assert.match(pinnedRow.querySelector(".account-id").textContent, new RegExp(pinnedId));
    assert.equal(accountRow(list, "short-active").querySelector(".tab-count").textContent, "1");

    // A replacement-only search and the unmodified AWS source name both work.
    await filterSection(fixture, "all", "short-alpha");
    assert.deepEqual(accountNames(list.querySelector(".section-all")), ["short-alpha"]);
    await filterSection(fixture, "all", "__containoodle_test_account__-dev-zulu");
    assert.deepEqual(accountNames(list.querySelector(".section-all")), ["short-zulu"]);
    await filterSection(fixture, "all", alphaId);
    assert.deepEqual(accountNames(list.querySelector(".section-all")), ["short-alpha"]);
    await filterSection(fixture, "all", "");

    await accountRow(list, "short-alpha").querySelector(".pin-btn")
      .listeners.click[0]({ stopPropagation() {} });
    accountRow(list, "short-pinned").querySelector(".launch-btn")
      .listeners.click[0]({ stopPropagation() {} });
    await settle();
    assert.deepEqual(fixture.sentMessages.filter((message) =>
      ["set-backend-pin", "launch"].includes(message.type)
    ), [
      { type: "set-backend-pin", mode: "backend", pinned: true, accountId: alphaId },
      { type: "launch", accountId: pinnedId, role: undefined, mode: "backend" },
    ]);
    assert.deepEqual(backendAccounts, originalAccounts);
    assert.deepEqual(fixture.storageData.accountsCache, originalAccounts);
    assert.equal(fixture.storageData[`accountContainer/${activeId}`], storeId);
    assert.equal(fixture.storageData[`containerAccount/${storeId}`], activeId);
  } finally {
    cleanupGlobals();
  }
});

test("portal name rules format active and pinned accounts using portal originals", async () => {
  const activeId = "000000000000";
  const pinnedId = "111111111111";
  const secondPinnedId = "222222222222";
  const storeId = "firefox-container-synthetic-portal-names";
  const rawActiveName = "__CONTAINOODLE_TEST_ACCOUNT__-DEV-active";
  const rawPinnedName = "__CONTAINOODLE_TEST_ACCOUNT__-QA-alpha";
  const originalPins = [
    {
      accountId: secondPinnedId,
      accountName: "__CONTAINOODLE_TEST_ACCOUNT__-DEV-zulu",
    },
    {
      accountId: pinnedId,
      accountName: "__CONTAINOODLE_TEST_OLDER_PIN_NAME__",
      role: TEST_HELPER_ROLE,
    },
  ];
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "portal",
        portalStartUrl: "https://d-0000000000.awsapps.com/start",
        groupNamePattern: "^__CONTAINOODLE_TEST_ACCOUNT__-(PROD|QA|DEV)-(.*)$",
        groupNameReplacement: "short-$2",
      },
      portalPinnedAccounts: structuredClone(originalPins),
      accountsCache: [{ accountId: activeId, accountName: "__CONTAINOODLE_TEST_BACKEND_ONLY__" }],
      [`portalAccountOriginalName/${activeId}`]: rawActiveName,
      [`portalAccountOriginalName/${pinnedId}`]: rawPinnedName,
      [`portalRoleChoice/${activeId}`]: TEST_HELPER_ROLE,
      [`accountContainer/${activeId}`]: storeId,
      [`containerAccount/${storeId}`]: activeId,
      [`containerOriginalName/${storeId}`]: "__CONTAINOODLE_TEST_STALE_SOURCE__",
    },
    containers: [{ cookieStoreId: storeId, name: "short-active", color: "red" }],
    tabs: [{ id: 1, cookieStoreId: storeId, active: true, title: "Synthetic console" }],
  });

  try {
    await loadSidebar(fixture);
    const list = fixture.ids.get("account-list");
    assert.deepEqual(accountNames(list.querySelector(".section-active")), ["short-active"]);
    assert.deepEqual(accountNames(list.querySelector(".section-pinned")), ["short-alpha", "short-zulu"]);
    assert.equal(list.querySelector(".section-all"), null);
    assert.equal(accountRow(list, "short-active").querySelector(".env-badge").textContent, "DEV");
    assert.equal(accountRow(list, "short-alpha").querySelector(".env-badge").textContent, "QA");
    assert.equal(accountRow(list, "short-alpha").querySelector(".role-chip").textContent, TEST_HELPER_ROLE);
    assert.doesNotMatch(list.textContent, /__CONTAINOODLE_TEST_(BACKEND_ONLY|STALE_SOURCE)__/);
    assert.equal(fixture.storageGetCalls.includes("accountsCache"), false);

    await filterSection(fixture, "pinned", "short-alpha");
    assert.deepEqual(accountNames(list.querySelector(".section-pinned")), ["short-alpha"]);
    await filterSection(fixture, "pinned", rawPinnedName);
    assert.deepEqual(accountNames(list.querySelector(".section-pinned")), ["short-alpha"]);
    await filterSection(fixture, "pinned", "__containoodle_test_older_pin_name__");
    assert.deepEqual(accountNames(list.querySelector(".section-pinned")), ["short-alpha"]);
    await filterSection(fixture, "active", "short-active");
    assert.deepEqual(accountNames(list.querySelector(".section-active")), ["short-active"]);
    await filterSection(fixture, "active", rawActiveName);
    assert.deepEqual(accountNames(list.querySelector(".section-active")), ["short-active"]);

    await accountRow(list, "short-active").querySelector(".pin-btn")
      .listeners.click[0]({ stopPropagation() {} });
    assert.deepEqual(fixture.sentMessages.find((message) => message.type === "set-portal-pin"), {
      type: "set-portal-pin",
      mode: "portal",
      pinned: true,
      account: { accountId: activeId, accountName: rawActiveName },
    });
    assert.deepEqual(fixture.storageData.portalPinnedAccounts, [
      ...originalPins,
      { accountId: activeId, accountName: rawActiveName, role: TEST_HELPER_ROLE },
    ]);
    assert.equal(fixture.storageData[`portalAccountOriginalName/${activeId}`], rawActiveName);
    assert.equal(fixture.storageData[`accountContainer/${activeId}`], storeId);
    assert.equal(fixture.storageData[`containerAccount/${storeId}`], activeId);
  } finally {
    cleanupGlobals();
  }
});

test("name-rule config changes and invalid or cleared rules refresh sidebar labels from originals", async () => {
  for (const mode of ["backend", "portal"]) {
    const accountId = "000000000000";
    const accountName = "__CONTAINOODLE_TEST_ACCOUNT__-DEV-source";
    const sourceAccounts = [{ accountId, accountName }];
    const fixture = createSidebarFixture({
      storage: {
        config: {
          mode,
          backendUrl: "http://127.0.0.1:8421",
          portalStartUrl: "https://d-0000000000.awsapps.com/start",
          groupNamePattern: "^",
          groupNameReplacement: "first-",
        },
        backendPinnedAccountIds: [accountId],
        portalPinnedAccounts: structuredClone(sourceAccounts),
      },
      fetchImpl: mode === "backend" ? backendResponse(sourceAccounts) : undefined,
    });

    try {
      await loadSidebar(fixture);
      const list = fixture.ids.get("account-list");
      assert.deepEqual(accountNames(list), [`first-${accountName}`]);
      for (const [pattern, replacement, expected] of [
        ["^", "second-", `second-${accountName}`],
        ["", "second-", accountName],
        ["[", "invalid-", accountName],
        ["(a+)+$", "unsafe-", accountName],
        ["^.*$", "", accountName],
      ]) {
        await fixture.browser.storage.local.set({
          config: {
            ...fixture.storageData.config,
            groupNamePattern: pattern,
            groupNameReplacement: replacement,
          },
        });
        await waitFor(
          () => !fixture.ids.get("loading-state").classList.contains("visible"),
          `${mode} name-rule refresh did not finish`,
        );
        assert.deepEqual(accountNames(list), [expected]);
        assert.equal(list.querySelector(".env-badge").textContent, "DEV");
      }
      assert.deepEqual(fixture.storageData.portalPinnedAccounts, sourceAccounts);
      if (mode === "backend") assert.deepEqual(fixture.storageData.accountsCache, sourceAccounts);
    } finally {
      cleanupGlobals();
    }
  }
});

test("managed active-only rows use saved originals once and leave unrelated containers untouched", async () => {
  for (const mode of ["backend", "portal"]) {
    let helperRequestCount = 0;
    const knownId = "000000000000";
    const unknownId = "111111111111";
    const knownStoreId = "firefox-container-synthetic-known";
    const unknownStoreId = "firefox-container-synthetic-unknown";
    const unrelatedStoreId = "firefox-container-synthetic-unrelated";
    const originalName = "__CONTAINOODLE_TEST_ACCOUNT__-QA-source";
    const formattedName = `short-${originalName}`;
    const unrelatedName = "__CONTAINOODLE_TEST_PERSONAL_CONTAINER__";
    const containers = [
      { cookieStoreId: knownStoreId, name: formattedName, color: "red" },
      { cookieStoreId: unknownStoreId, name: "short-__CONTAINOODLE_TEST_UNKNOWN__", color: "purple" },
      { cookieStoreId: unrelatedStoreId, name: unrelatedName, color: "blue" },
    ];
    const fixture = createSidebarFixture({
      storage: {
        config: {
          mode,
          backendUrl: "http://127.0.0.1:8421",
          portalStartUrl: "https://d-0000000000.awsapps.com/start",
          groupNamePattern: "^",
          groupNameReplacement: "short-",
        },
        [`accountContainer/${knownId}`]: knownStoreId,
        [`containerAccount/${knownStoreId}`]: knownId,
        [`containerOriginalName/${knownStoreId}`]: originalName,
        [`accountContainer/${unknownId}`]: unknownStoreId,
        [`containerAccount/${unknownStoreId}`]: unknownId,
        // A stale metadata entry alone does not make this personal container managed.
        [`containerOriginalName/${unrelatedStoreId}`]: "__CONTAINOODLE_TEST_STALE_SOURCE__",
      },
      containers,
      tabs: containers.map((container, index) => ({
        id: index + 1,
        cookieStoreId: container.cookieStoreId,
        active: index === 0,
        title: "Synthetic tab",
      })),
      fetchImpl: mode === "backend"
        ? backendResponse([], () => { helperRequestCount += 1; })
        : undefined,
    });

    try {
      await loadSidebar(fixture);
      const list = fixture.ids.get("account-list");
      const knownRow = accountRow(list, formattedName);
      assert.ok(knownRow);
      assert.equal(knownRow.querySelector(".env-badge").textContent, "QA");
      assert.ok(accountRow(list, "short-__CONTAINOODLE_TEST_UNKNOWN__"));
      const unrelatedRow = accountRow(list, unrelatedName);
      assert.ok(unrelatedRow);
      assert.equal(unrelatedRow.querySelector(".env-badge"), null);
      assert.equal(unrelatedRow.querySelector(".aws-dot").style.background, "#37adff");
      assert.equal(unrelatedRow.querySelector(".pin-btn"), null);
      assert.doesNotMatch(list.textContent, /short-short-|__CONTAINOODLE_TEST_STALE_SOURCE__/);
      if (mode === "backend") assert.equal(knownRow.querySelector(".pin-btn"), null);

      const revisedOriginal = "__CONTAINOODLE_TEST_ACCOUNT__-DEV-updated";
      const requestsBeforeMetadataChange = helperRequestCount;
      await fixture.browser.storage.local.set({
        [`containerOriginalName/${knownStoreId}`]: revisedOriginal,
      });
      await waitFor(
        () => Boolean(accountRow(list, `short-${revisedOriginal}`)),
        `${mode} sidebar did not refresh saved container source metadata`,
      );
      assert.equal(accountRow(list, `short-${revisedOriginal}`).querySelector(".env-badge").textContent, "DEV");
      assert.equal(helperRequestCount, requestsBeforeMetadataChange);
      assert.equal(containers[0].name, formattedName);
      assert.equal(containers[2].name, unrelatedName);

      await fixture.browser.storage.local.remove(`containerOriginalName/${knownStoreId}`);
      await waitFor(
        () => Boolean(accountRow(list, formattedName)),
        `${mode} sidebar retained a deleted container source name`,
      );
      assert.equal(accountRow(list, `short-${revisedOriginal}`), null);
      assert.equal(helperRequestCount, requestsBeforeMetadataChange);
      assert.doesNotMatch(list.textContent, /short-short-/);

      // Config and source changes in the same event still use the established
      // full refresh, with the new original available to the rendered rows.
      await fixture.browser.storage.local.set({
        config: { ...fixture.storageData.config, groupNameReplacement: "next-" },
        [`containerOriginalName/${knownStoreId}`]: revisedOriginal,
      });
      await waitFor(
        () => Boolean(accountRow(list, `next-${revisedOriginal}`)),
        `${mode} sidebar lost source metadata in a mixed config update`,
      );
      if (mode === "backend") {
        assert.ok(helperRequestCount > requestsBeforeMetadataChange);
      } else {
        assert.equal(helperRequestCount, 0);
      }
    } finally {
      cleanupGlobals();
    }
  }
});

test("deferred helper refresh preserves newer container source updates and deletions", async () => {
  const changedStoreId = "firefox-container-synthetic-source-update";
  const removedStoreId = "firefox-container-synthetic-source-delete";
  const originalName = "__CONTAINOODLE_TEST_ACCOUNT__-QA-before";
  const revisedOriginal = "__CONTAINOODLE_TEST_ACCOUNT__-DEV-after";
  const removedFallback = "short-__CONTAINOODLE_TEST_CONTAINER_FALLBACK__";
  let deferRefresh = false;
  let accountRequestPending = false;
  let helperRequests = 0;
  let releaseAccounts;
  const pendingAccounts = new Promise((resolve) => { releaseAccounts = resolve; });
  const recordRequest = (url) => {
    helperRequests += 1;
    if (deferRefresh && new URL(url).pathname === "/accounts") {
      accountRequestPending = true;
    }
  };
  const immediateResponse = backendResponse([], recordRequest);
  const deferredResponse = backendResponse(pendingAccounts, recordRequest);
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        groupNamePattern: "^",
        groupNameReplacement: "short-",
      },
      [`accountContainer/000000000000`]: changedStoreId,
      [`containerAccount/${changedStoreId}`]: "000000000000",
      [`containerOriginalName/${changedStoreId}`]: originalName,
      [`accountContainer/111111111111`]: removedStoreId,
      [`containerAccount/${removedStoreId}`]: "111111111111",
      [`containerOriginalName/${removedStoreId}`]: "__CONTAINOODLE_TEST_REMOVED_SOURCE__",
    },
    containers: [
      { cookieStoreId: changedStoreId, name: `short-${originalName}`, color: "red" },
      { cookieStoreId: removedStoreId, name: removedFallback, color: "red" },
    ],
    tabs: [changedStoreId, removedStoreId].map((cookieStoreId, index) => ({
      id: index + 1,
      cookieStoreId,
      active: index === 0,
      title: "Synthetic console",
    })),
    fetchImpl: (url, options) => (deferRefresh ? deferredResponse : immediateResponse)(url, options),
  });

  try {
    await loadSidebar(fixture);
    const list = fixture.ids.get("account-list");
    assert.ok(accountRow(list, `short-${originalName}`));
    assert.ok(accountRow(list, "short-__CONTAINOODLE_TEST_REMOVED_SOURCE__"));

    deferRefresh = true;
    const refresh = fixture.ids.get("refresh-btn").listeners.click[0]();
    await waitFor(() => accountRequestPending, "helper refresh did not wait for its account payload");
    const requestsBeforeSourceEvents = helperRequests;
    await fixture.browser.storage.local.set({
      [`containerOriginalName/${changedStoreId}`]: revisedOriginal,
    });
    await fixture.browser.storage.local.remove(`containerOriginalName/${removedStoreId}`);
    await waitFor(
      () => Boolean(accountRow(list, `short-${revisedOriginal}`)) &&
        Boolean(accountRow(list, removedFallback)),
      "new source metadata did not render while helper refresh was pending",
    );

    releaseAccounts([]);
    await refresh;
    await settle();
    assert.ok(accountRow(list, `short-${revisedOriginal}`));
    assert.equal(accountRow(list, `short-${originalName}`), null);
    assert.ok(accountRow(list, removedFallback));
    assert.equal(accountRow(list, "short-__CONTAINOODLE_TEST_REMOVED_SOURCE__"), null);
    assert.equal(accountRow(list, `short-${revisedOriginal}`).querySelector(".env-badge").textContent, "DEV");
    assert.equal(helperRequests, requestsBeforeSourceEvents);
    assert.equal(fixture.storageData[`containerOriginalName/${changedStoreId}`], revisedOriginal);
    assert.equal(Object.hasOwn(fixture.storageData, `containerOriginalName/${removedStoreId}`), false);
  } finally {
    releaseAccounts([]);
    cleanupGlobals();
  }
});

test("portal sidebar uses captured names and pins without reading backend accounts", async () => {
  const accountId = "123456789012";
  const storeId = "firefox-container-1";
  const fixture = createSidebarFixture({
    storage: {
      accountsCache: [{
        accountId: "999999999999",
        accountName: "backend-prod-must-not-leak",
      }],
      backendPinnedAccountIds: [accountId],
      [`portalAccountOriginalName/${accountId}`]: "Payments DEV",
      [`accountContainer/${accountId}`]: storeId,
      [`containerAccount/${storeId}`]: accountId,
      [`portalRoleChoice/${accountId}`]: "Developer",
    },
    containers: [{
      cookieStoreId: storeId,
      name: `Containoodle ${accountId}`,
      color: "red",
    }],
    tabs: [{
      id: 7,
      cookieStoreId: storeId,
      active: true,
      windowId: 1,
      title: "AWS Console",
    }],
  });

  try {
    await loadSidebar(fixture);

    const list = fixture.ids.get("account-list");
    assert.equal(list.querySelector(".account-name").textContent, "Payments DEV");
    assert.equal(list.querySelector(".env-badge").textContent, "DEV");
    assert.equal(list.querySelector(".section-all"), null);
    assert.doesNotMatch(list.textContent, /backend-prod-must-not-leak/);

    const pin = list.querySelector(".pin-btn");
    assert.equal(pin.getAttribute("aria-pressed"), "false");
    await pin.listeners.click[0]({ stopPropagation() {} });
    assert.deepEqual(fixture.storageData.portalPinnedAccounts, [{
      accountId,
      accountName: "Payments DEV",
      role: "Developer",
    }]);

    const unpin = list.querySelector(".pin-btn");
    assert.equal(unpin.getAttribute("aria-pressed"), "true");
    await unpin.listeners.click[0]({ stopPropagation() {} });
    assert.deepEqual(fixture.storageData.portalPinnedAccounts, []);
    assert.equal(list.querySelector(".account-name").textContent, "Payments DEV");
  } finally {
    cleanupGlobals();
  }
});

test("sidebar does not load arbitrary remote tab favicons", async () => {
  const accountId = "123456789012";
  const storeId = "firefox-container-1";
  const fixture = createSidebarFixture({
    storage: {
      portalPinnedAccounts: [{
        accountId,
        accountName: "Test account",
      }],
      [`accountContainer/${accountId}`]: storeId,
      [`containerAccount/${storeId}`]: accountId,
    },
    containers: [{
      cookieStoreId: storeId,
      name: "Test account",
      color: "green",
    }],
    tabs: [{
      id: 7,
      cookieStoreId: storeId,
      active: true,
      windowId: 1,
      title: "Console",
      favIconUrl: "https://example.invalid/favicon.ico",
    }],
  });

  try {
    await loadSidebar(fixture);
    const list = fixture.ids.get("account-list");
    assert.equal(list.querySelector("img"), null);
    assert.ok(list.querySelector(".tab-favicon.is-fallback"));
  } finally {
    cleanupGlobals();
  }
});

test("both sidebar modes prefer actual PNG/SVG favicons, including an anonymous original AWS image", async () => {
  const accountId = "000000000000";
  const storeId = "firefox-container-synthetic-icons";
  const account = { accountId, accountName: "__CONTAINOODLE_TEST_ICON_ACCOUNT__" };
  const services = ["sagemaker", "s3", "systems-manager", "lambda", "inspector"];
  const embedded = "data:image/png;base64,iVBORw0KGgo=";
  const originalSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="6"/></svg>';
  for (const mode of ["portal", "backend"]) {
    const remote = `https://assets.console.awsstatic.com/synthetic/${mode}.svg`;
    const iconCalls = [];
    const helperFetch = backendResponse([account]);
    const tabs = services.map((service, index) => ({
      id: index + 7, cookieStoreId: storeId, active: index === 0, windowId: 1,
      title: `__CONTAINOODLE_TEST_${service.toUpperCase()}__`,
      url: `https://eu-west-1.console.aws.amazon.com/${service}/home`,
      favIconUrl: index === 4 ? remote : embedded,
    }));
    const fixture = createSidebarFixture({
      storage: {
        config: { mode, portalStartUrl: "https://example.awsapps.com/start" },
        [ONBOARDING_KEY]: ONBOARDING_STATES.COMPLETE,
        portalPinnedAccounts: [account], accountsCache: [account],
        [`accountContainer/${accountId}`]: storeId,
        [`containerAccount/${storeId}`]: accountId,
      },
      containers: [{ cookieStoreId: storeId, name: account.accountName, color: "green" }],
      tabs,
      fetchImpl: (url, options) => {
        if (url === remote) {
          iconCalls.push(options);
          return Promise.resolve(new Response(originalSvg, { headers: { "content-type": "image/svg+xml" } }));
        }
        if (mode === "backend") return helperFetch(url, options);
        throw new Error("Unexpected synthetic portal request");
      },
    });
    try {
      await loadSidebar(fixture);
      const list = fixture.ids.get("account-list");
      await waitFor(() => list.querySelectorAll("img").length === 5, "Original remote image must finish loading");
      assert.equal(list.querySelectorAll("svg").length, 0, "SVG page data is never inserted into DOM");
      assert.deepEqual(list.querySelectorAll("img").map(img => img.src), [embedded, embedded, embedded, embedded,
        "data:image/svg+xml;base64," + btoa(originalSvg)]);
      assert.equal(iconCalls.length, 1);
      assert.equal(iconCalls[0].credentials, "omit");
      assert.equal(iconCalls[0].redirect, "error");
      assert.equal(iconCalls[0].referrerPolicy, "no-referrer");
      for (const icon of list.querySelectorAll(".tab-favicon")) assert.equal(icon.getAttribute("aria-hidden"), "true");
      const before = fixture.tabQueryCalls;
      tabs[0].url = "https://console.aws.amazon.com/ec2/home";
      tabs[0].favIconUrl = "data:image/svg+xml," + encodeURIComponent(originalSvg);
      fixture.browser.tabs.onUpdated.listeners[0](7, { url: tabs[0].url });
      await waitFor(() => fixture.tabQueryCalls > before, "URL-only changes must refresh favicons");
      await waitFor(() => list.querySelector("img").src === tabs[0].favIconUrl,
        "Navigation must update the actual favicon even when the title is unchanged");
      const slot = list.querySelector(".tab-favicon");
      slot.querySelector("img").onload();
      assert.equal(slot.classList.contains("is-fallback"), false);
      slot.querySelector("img").onerror();
      assert.equal(slot.querySelector("img"), null);
      assert.equal(slot.classList.contains("is-fallback"), true);
      const afterUrl = fixture.tabQueryCalls;
      tabs[0].favIconUrl = "";
      fixture.browser.tabs.onUpdated.listeners[0](7, { favIconUrl: "" });
      await waitFor(() => fixture.tabQueryCalls > afterUrl, "favicon-only changes must refresh embedded icons");
      await waitFor(() => list.querySelector(".tab-favicon").querySelector("img") === null, "Empty favicon must clear the previous image");
      const tabSwitch = list.querySelector(".tab-switch");
      await tabSwitch.listeners.click[0]();
      assert.deepEqual(fixture.tabUpdates, [{ id: 7, changes: { active: true } }]);
      await list.querySelector(".tab-close").listeners.click[0]({ stopPropagation() {} });
      assert.deepEqual(fixture.tabRemovals, [7]);
      // Closing schedules a render without awaiting it; let that render finish
      // before removing this test's global browser/document fixture.
      await settle();
    } finally { cleanupGlobals(); }
  }
});

test("embedded favicons still work on non-AWS tabs and spoofed titles do not select a service", async () => {
  const fixture = createSidebarFixture({
    storage: { [ONBOARDING_KEY]: ONBOARDING_STATES.COMPLETE },
    containers: [{ cookieStoreId: "firefox-container-synthetic-icons", name: "__CONTAINOODLE_TEST__", color: "green" }],
    tabs: [{
      id: 7, cookieStoreId: "firefox-container-synthetic-icons", active: true, windowId: 1,
      title: "S3 buckets | Lambda | Amazon SageMaker", url: "https://example.invalid/",
      favIconUrl: "data:image/png;base64,iVBORw0KGgo=",
    }],
  });
  try {
    await loadSidebar(fixture);
    const list = fixture.ids.get("account-list");
    assert.equal(list.querySelector(".tab-service-icon"), null);
    assert.equal(list.querySelector("img").src, "data:image/png;base64,iVBORw0KGgo=");
  } finally { cleanupGlobals(); }
});

test("portal rows never display a backend-only remembered role", async () => {
  const accountId = "123456789012";
  const storeId = "firefox-container-1";
  const fixture = createSidebarFixture({
    storage: {
      portalPinnedAccounts: [{
        accountId,
        accountName: "Payments DEV",
      }],
      [`backendRoleChoice/${accountId}`]: "BackendOnlyRole",
      [`accountContainer/${accountId}`]: storeId,
      [`containerAccount/${storeId}`]: accountId,
    },
    containers: [{
      cookieStoreId: storeId,
      name: "Payments DEV",
      color: "green",
    }],
    tabs: [{
      id: 7,
      cookieStoreId: storeId,
      active: true,
      windowId: 1,
      title: "AWS Console",
    }],
  });

  try {
    await loadSidebar(fixture);

    const list = fixture.ids.get("account-list");
    assert.equal(list.querySelector(".account-name").textContent, "Payments DEV");
    assert.equal(list.querySelector(".role-chip"), null);
    assert.doesNotMatch(list.textContent, /BackendOnlyRole/);
  } finally {
    cleanupGlobals();
  }
});

test("backend rows display remembered roles only for the current SSO identity", async () => {
  const accountId = "000000000000";
  const accounts = [{
    accountId,
    accountName: "__CONTAINOODLE_TEST_ACCOUNT__",
  }];
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "",
      },
      backendSsoProfile: "__containoodle_test_profile__",
      backendSsoIdentityKey: TEST_SSO_IDENTITY,
      backendPinnedAccountIds: [accountId],
      [`backendRoleChoice/${accountId}`]:
        "__CONTAINOODLE_TEST_LEGACY_ROLE__",
      [`backendRoleChoice/${TEST_SSO_IDENTITY}/${accountId}`]:
        TEST_HELPER_ROLE,
      [`backendRoleChoice/${TEST_OTHER_SSO_IDENTITY}/${accountId}`]:
        "__CONTAINOODLE_TEST_OTHER_IDENTITY_ROLE__",
    },
    fetchImpl: backendResponse(accounts),
  });

  try {
    await loadSidebar(fixture);
    let chip = fixture.ids.get("account-list").querySelector(".role-chip");
    assert.ok(chip);
    assert.strictEqual(chip.textContent, TEST_HELPER_ROLE);

    await fixture.browser.storage.local.set({
      backendSsoProfile: "__containoodle_test_other_profile__",
      backendSsoIdentityKey: TEST_OTHER_SSO_IDENTITY,
    });
    await waitFor(
      () => fixture.ids.get("account-list").querySelector(".role-chip")
        ?.textContent === "__CONTAINOODLE_TEST_OTHER_IDENTITY_ROLE__",
      "sidebar did not switch to the replacement identity's role",
    );
    chip = fixture.ids.get("account-list").querySelector(".role-chip");
    assert.strictEqual(
      chip.textContent,
      "__CONTAINOODLE_TEST_OTHER_IDENTITY_ROLE__",
    );
    assert.doesNotMatch(
      fixture.ids.get("account-list").textContent,
      /__CONTAINOODLE_TEST_LEGACY_ROLE__/,
    );
  } finally {
    cleanupGlobals();
  }
});

test("backend pins partition active, pinned, and other accounts without crossing portal pins", async () => {
  const activeId = "111111111111";
  const pinnedId = "222222222222";
  const newlyPinnedId = "333333333333";
  const otherId = "444444444444";
  const storeId = "firefox-container-backend-active";
  const backendAccounts = [
    { accountId: activeId, accountName: "Active DEV" },
    { accountId: pinnedId, accountName: "Pinned QA", role: "ReadOnly" },
    { accountId: newlyPinnedId, accountName: "New PROD" },
    { accountId: otherId, accountName: "Other TEST" },
  ];
  let fetchCount = 0;
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "https://example.awsapps.com/start",
      },
      backendPinnedAccountIds: [activeId, pinnedId],
      portalPinnedAccounts: [{
        accountId: otherId,
        accountName: "Portal-only pin",
        role: "PortalRole",
      }],
      [`accountContainer/${activeId}`]: storeId,
      [`containerAccount/${storeId}`]: activeId,
    },
    containers: [{
      cookieStoreId: storeId,
      name: "Active DEV",
      color: "green",
    }],
    tabs: [{
      id: 7,
      cookieStoreId: storeId,
      active: true,
      windowId: 1,
      title: "AWS Console",
    }],
    fetchImpl: backendResponse(backendAccounts, () => {
      fetchCount += 1;
    }),
  });

  try {
    await loadSidebar(fixture);

    const list = fixture.ids.get("account-list");
    const activeSection = list.querySelector(".section-active");
    const pinnedSection = list.querySelector(".section-pinned");
    const otherSection = list.querySelector(".section-all");
    assert.match(activeSection.textContent, /Active DEV/);
    assert.doesNotMatch(activeSection.textContent, /Pinned QA/);
    assert.match(pinnedSection.textContent, /Pinned QA/);
    assert.doesNotMatch(pinnedSection.textContent, /Active DEV/);
    assert.match(otherSection.textContent, /Other accounts \(2\)/);
    assert.equal(countText(list.textContent, "Active DEV"), 1);
    assert.equal(countText(list.textContent, "Pinned QA"), 1);
    assert.equal(
      accountRow(activeSection, "Active DEV")
        .querySelector(".pin-btn")
        .getAttribute("aria-pressed"),
      "true"
    );

    // "Other accounts" starts collapsed; opening it exposes backend rows
    // with empty stars. A portal pin with the same ID must not fill one.
    otherSection.querySelector(".section-header").listeners.click[0]();
    await settle();
    const otherRow = accountRow(list, "Other TEST");
    assert.equal(
      otherRow.querySelector(".pin-btn").getAttribute("aria-pressed"),
      "false"
    );

    const newRow = accountRow(list, "New PROD");
    const fetchCountBeforePin = fetchCount;
    await newRow.querySelector(".pin-btn").listeners.click[0]({
      stopPropagation() {},
    });
    assert.deepEqual(
      new Set(fixture.storageData.backendPinnedAccountIds),
      new Set([activeId, pinnedId, newlyPinnedId])
    );
    assert.deepEqual(fixture.storageData.portalPinnedAccounts, [{
      accountId: otherId,
      accountName: "Portal-only pin",
      role: "PortalRole",
    }]);
    assert.equal(
      fetchCount,
      fetchCountBeforePin,
      "pinning must not refresh or call the helper"
    );
    assert.match(
      fixture.ids.get("account-list").querySelector(".section-pinned").textContent,
      /New PROD/
    );
    assert.equal(countText(fixture.ids.get("account-list").textContent, "New PROD"), 1);

    const pinnedRow = accountRow(fixture.ids.get("account-list"), "Pinned QA");
    await pinnedRow.querySelector(".pin-btn").listeners.click[0]({
      stopPropagation() {},
    });
    assert.deepEqual(
      new Set(fixture.storageData.backendPinnedAccountIds),
      new Set([activeId, newlyPinnedId])
    );
    assert.equal(fetchCount, fetchCountBeforePin);
    assert.match(
      fixture.ids.get("account-list").querySelector(".section-all").textContent,
      /Pinned QA/
    );

    const pinMessages = fixture.sentMessages.filter(
      (message) => message.type === "set-backend-pin"
    );
    assert.deepEqual(pinMessages, [
      {
        type: "set-backend-pin",
        mode: "backend",
        pinned: true,
        accountId: newlyPinnedId,
      },
      {
        type: "set-backend-pin",
        mode: "backend",
        pinned: false,
        accountId: pinnedId,
      },
    ]);
  } finally {
    cleanupGlobals();
  }
});

test("backend synthetic container-only rows cannot be pinned", async () => {
  const accountId = "123456789012";
  const storeId = "firefox-container-orphan";
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "https://example.awsapps.com/start",
      },
      backendPinnedAccountIds: [accountId],
      portalPinnedAccounts: [{
        accountId,
        accountName: "Portal DEV",
      }],
      [`accountContainer/${accountId}`]: storeId,
      [`containerAccount/${storeId}`]: accountId,
    },
    containers: [{
      cookieStoreId: storeId,
      name: "Backend container only",
      color: "blue",
    }],
    tabs: [{
      id: 8,
      cookieStoreId: storeId,
      active: true,
      windowId: 1,
      title: "AWS Console",
    }],
    fetchImpl: backendResponse([]),
  });

  try {
    await loadSidebar(fixture);
    const row = accountRow(
      fixture.ids.get("account-list"),
      "Backend container only"
    );
    assert.ok(row);
    assert.equal(row.querySelector(".pin-btn"), null);
  } finally {
    cleanupGlobals();
  }
});

test("portal launcher is portal-only and focuses or opens through the background", async () => {
  const portal = createSidebarFixture();
  try {
    await loadSidebar(portal);
    const toolbar = portal.ids.get("portal-toolbar");
    const button = portal.ids.get("open-portal-btn");
    const hint = portal.ids.get("portal-toolbar-hint");
    assert.equal(toolbar.hidden, false);
    assert.equal(button.disabled, false);
    assert.equal(hint.hidden, true);

    button.listeners.click[0]();
    await settle();
    assert.deepEqual(
      portal.sentMessages.filter((message) => message.type === "open-portal"),
      [{ type: "open-portal", mode: "portal" }]
    );
    assert.equal(portal.ids.get("notification").textContent, "AWS Portal ready");
  } finally {
    cleanupGlobals();
  }

  const missingUrl = createSidebarFixture({
    storage: {
      config: {
        mode: "portal",
        portalStartUrl: "",
      },
    },
  });
  try {
    await loadSidebar(missingUrl);
    const button = missingUrl.ids.get("open-portal-btn");
    assert.equal(missingUrl.ids.get("portal-toolbar").hidden, false);
    assert.equal(button.disabled, true);
    assert.equal(missingUrl.ids.get("portal-toolbar-hint").hidden, false);
    assert.match(button.title, /Set the AWS Access Portal URL/);

    // The disabled control cannot be clicked by a user; invoking its handler
    // directly still proves it performs no background action.
    button.listeners.click[0]();
    await settle();
    assert.equal(
      missingUrl.sentMessages.some((message) => message.type === "open-portal"),
      false
    );
    assert.match(
      missingUrl.ids.get("notification").textContent,
      /Set the AWS Access Portal URL/
    );
  } finally {
    cleanupGlobals();
  }

  const backend = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "https://example.awsapps.com/start",
      },
    },
    fetchImpl: backendResponse([]),
  });
  try {
    await loadSidebar(backend);
    assert.equal(backend.ids.get("portal-toolbar").hidden, true);
  } finally {
    cleanupGlobals();
  }
});

test("a backend pin reply arriving after a portal switch is ignored", async () => {
  const backendId = "123456789012";
  const portalId = "999999999999";
  let resolvePin;
  const pendingPin = new Promise((resolve) => {
    resolvePin = resolve;
  });
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "https://example.awsapps.com/start",
      },
      portalPinnedAccounts: [{
        accountId: portalId,
        accountName: "Portal DEV",
      }],
    },
    fetchImpl: backendResponse([{
      accountId: backendId,
      accountName: "Backend PROD",
    }]),
    sendMessageImpl(message) {
      if (message.type === "set-backend-pin") return pendingPin;
      return { ok: true };
    },
  });

  try {
    await loadSidebar(fixture);
    const list = fixture.ids.get("account-list");
    list.querySelector(".section-all")
      .querySelector(".section-header")
      .listeners.click[0]();
    await settle();
    const pinReply = accountRow(list, "Backend PROD")
      .querySelector(".pin-btn")
      .listeners.click[0]({ stopPropagation() {} });

    await fixture.browser.storage.local.set({
      config: {
        ...fixture.storageData.config,
        mode: "portal",
      },
    });
    await waitFor(
      () => fixture.ids.get("account-list").textContent.includes("Portal DEV"),
      "portal mode did not render"
    );

    resolvePin({ ok: true, pinned: true });
    await pinReply;
    await settle();

    assert.match(fixture.ids.get("account-list").textContent, /Portal DEV/);
    assert.doesNotMatch(fixture.ids.get("account-list").textContent, /Backend PROD/);
    assert.doesNotMatch(
      fixture.ids.get("notification").textContent,
      /Pinned Backend PROD/
    );
    assert.deepEqual(fixture.storageData.backendPinnedAccountIds, []);
  } finally {
    cleanupGlobals();
  }
});

test("a deferred backend response cannot replace portal accounts after a mode switch", async () => {
  const accountId = "0".repeat(12);
  const storeId = "firefox-container-1";
  let resolveBackend;
  let backendSignal;
  let backendRequested = false;
  const backendPayload = new Promise((resolve) => {
    resolveBackend = resolve;
  });
  const fixture = createSidebarFixture({
    storage: {
      config: {
        mode: "backend",
        backendUrl: "http://127.0.0.1:8421",
        portalStartUrl: "https://example.awsapps.com/start",
      },
      portalPinnedAccounts: [{
        accountId,
        accountName: "Portal DEV",
        role: TEST_HELPER_ROLE,
      }],
      [`accountContainer/${accountId}`]: storeId,
      [`containerAccount/${storeId}`]: accountId,
    },
    containers: [{
      cookieStoreId: storeId,
      name: "Portal DEV",
      color: "green",
    }],
    tabs: [{
      id: 7,
      cookieStoreId: storeId,
      active: true,
      windowId: 1,
      title: "AWS Console",
    }],
    fetchImpl: backendResponse(backendPayload, (url, options) => {
      if (new URL(url).pathname === "/auth/challenge") return;
      backendRequested = true;
      backendSignal = options.signal;
      // The signed mock deliberately ignores abort while awaiting its payload,
      // so the refresh generation must still reject the stale verified result.
    }),
  });

  try {
    await loadSidebar(fixture, { waitForInitialRefresh: false });
    await waitFor(() => backendRequested, "sidebar did not start its backend request");

    await fixture.browser.storage.local.set({
      config: {
        ...fixture.storageData.config,
        mode: "portal",
      },
    });
    await waitFor(
      () => fixture.ids.get("account-list").textContent.includes("Portal DEV"),
      "portal accounts did not render after the mode switch"
    );
    assert.equal(backendSignal.aborted, true);

    resolveBackend([{
      accountId,
      accountName: "Backend PROD",
      role: TEST_HELPER_ROLE,
    }]);
    await settle(10);

    const list = fixture.ids.get("account-list");
    assert.match(list.textContent, /Portal DEV/);
    assert.doesNotMatch(list.textContent, /Backend PROD/);
    assert.match(fixture.ids.get("status-text").textContent, /^Portal/);
  } finally {
    cleanupGlobals();
  }
});
