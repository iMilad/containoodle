import test from "node:test";
import assert from "node:assert/strict";

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
    this._textContent = String(value);
    this.children = [];
  }

  get textContent() {
    return this._textContent + this.children.map((child) => child.textContent).join("");
  }

  appendChild(child) {
    child.parentNode = this;
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
    if (selector.startsWith(".")) {
      return selector
        .slice(1)
        .split(".")
        .every((name) => this.classList.contains(name));
    }
    return false;
  }

  querySelector(selector) {
    if (this.matches(selector)) return this;
    for (const child of this.children) {
      const found = child.querySelector && child.querySelector(selector);
      if (found) return found;
    }
    return null;
  }

  focus() {}
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
  ["browser", "document", "fetch", "setTimeout"].map((name) => [
    name,
    {
      exists: Object.prototype.hasOwnProperty.call(globalThis, name),
      value: globalThis[name],
    },
  ])
);

let importSequence = 0;

function createSidebarFixture({
  storage = {},
  containers = [],
  tabs = [],
  sendMessageImpl = null,
  fetchImpl = async () => {
    throw new Error("Unexpected backend request");
  },
} = {}) {
  const storageData = {
    config: {
      mode: "portal",
      portalStartUrl: "https://example.awsapps.com/start",
    },
    portalPinnedAccounts: [],
    backendPinnedAccountIds: [],
    ...storage,
  };
  const sentMessages = [];
  const storageChanged = extensionEvent();
  const ids = new Map([
    ["account-list", new Element()],
    ["loading-state", new Element()],
    ["status-dot", new Element()],
    ["status-text", new Element()],
    ["refresh-btn", new Element("button")],
    ["options-btn", new Element("button")],
    ["notification", new Element()],
    ["brand-version", new Element()],
    ["portal-toolbar", new Element()],
    ["open-portal-btn", new Element("button")],
    ["portal-toolbar-hint", new Element()],
  ]);
  const document = {
    getElementById(id) {
      return ids.get(id) || null;
    },
    createElement(tagName) {
      return new Element(tagName);
    },
    createTextNode(text) {
      const node = new Element("#text");
      node.textContent = text;
      return node;
    },
  };
  const browser = {
    storage: {
      local: {
        async get(keys) {
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
      },
      onChanged: storageChanged,
    },
    contextualIdentities: {
      async query() {
        return containers.map((container) => ({ ...container }));
      },
      onCreated: extensionEvent(),
      onRemoved: extensionEvent(),
      onUpdated: extensionEvent(),
    },
    tabs: {
      async query(query) {
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
      openOptionsPage: async () => {},
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
    windows: { update: async () => {} },
  };

  return {
    browser,
    document,
    fetch: fetchImpl,
    ids,
    storageData,
    storageChanged,
    sentMessages,
  };
}

async function loadSidebar(fixture) {
  const nativeSetTimeout = originalGlobals.setTimeout.value;
  globalThis.setTimeout = (...args) => {
    const timer = nativeSetTimeout(...args);
    timer.unref?.();
    return timer;
  };
  globalThis.document = fixture.document;
  globalThis.browser = fixture.browser;
  globalThis.fetch = fixture.fetch;
  await import(
    `../firefox-extension/sidebar/sidebar.js?test=${importSequence += 1}`
  );
  await settle();
}

async function settle(turns = 5) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function waitFor(check, message) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (check()) return;
    await settle(1);
  }
  assert.ok(check(), message);
}

function cleanupGlobals() {
  for (const [name, original] of Object.entries(originalGlobals)) {
    if (original.exists) globalThis[name] = original.value;
    else delete globalThis[name];
  }
}

function backendResponse(accounts, onRequest = () => {}) {
  return async () => {
    onRequest();
    return {
      ok: true,
      async json() {
        return accounts;
      },
    };
  };
}

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

test("sidebar does not load remote tab favicons", async () => {
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
    assert.equal(list.querySelector(".tab-favicon"), null);
    assert.ok(list.querySelector(".tab-favicon-placeholder"));
  } finally {
    cleanupGlobals();
  }
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
  const accountId = "123456789012";
  const storeId = "firefox-container-1";
  let resolveBackend;
  let backendSignal;
  let backendRequested = false;
  const backendResponse = new Promise((resolve) => {
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
        role: "PortalRole",
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
    fetchImpl(_url, options = {}) {
      backendRequested = true;
      backendSignal = options.signal;
      // Deliberately ignore abort so this simulates a transport that resolves
      // late; the refresh generation must still reject the stale result.
      return backendResponse;
    },
  });

  try {
    await loadSidebar(fixture);
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

    resolveBackend({
      ok: true,
      async json() {
        return [{
          accountId,
          accountName: "Backend PROD",
          role: "BackendRole",
        }];
      },
    });
    await settle(10);

    const list = fixture.ids.get("account-list");
    assert.match(list.textContent, /Portal DEV/);
    assert.doesNotMatch(list.textContent, /Backend PROD/);
    assert.match(fixture.ids.get("status-text").textContent, /^Portal/);
  } finally {
    cleanupGlobals();
  }
});
