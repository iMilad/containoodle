// Optional real-DOM keyboard check. Uses an isolated headless browser and only
// synthetic browser APIs/data; it never opens Firefox or authenticates to AWS.
// node tests/sidebar-browser-smoke.mjs --playwright=/path/to/playwright/index.mjs --browser=/path/to/chromium
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, extname, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: {
  playwright: { type: "string" },
  browser: { type: "string" },
} });
const { chromium } = await import(values.playwright
  ? pathToFileURL(resolve(values.playwright)).href : "playwright");
const extensionRoot = fileURLToPath(new URL("../firefox-extension/", import.meta.url));
const types = { ".html": "text/html", ".css": "text/css", ".js": "application/javascript", ".png": "image/png" };
const server = createServer(async (request, response) => {
  try {
    const path = resolve(extensionRoot, `.${new URL(request.url, "http://localhost").pathname}`);
    if (!path.startsWith(`${extensionRoot.replace(/\/$/, "")}${sep}`) || !types[extname(path)]) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "Content-Type": types[extname(path)] }).end(await readFile(path));
  } catch {
    response.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await chromium.launch({ headless: true, ...(values.browser ? { executablePath: values.browser } : {}) });
  const context = await browser.newContext({ viewport: { width: 320, height: 820 } });
  await context.route("**/*", (route) => route.request().url().startsWith(`${origin}/`)
    ? route.continue() : route.abort());
  await context.addInitScript(() => {
    const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); }, emit(...args) { this.listeners.forEach((fn) => fn(...args)); } });
    const accountId = "000000000000";
    const otherId = "111111111111";
    const storeId = "firefox-container-synthetic-smoke";
    const account = { accountId, accountName: "__CONTAINOODLE_TEST_ACTIVE_ACCOUNT__" };
    const other = { accountId: otherId, accountName: "__CONTAINOODLE_TEST_OTHER_ACCOUNT__" };
    const roles = ["__CONTAINOODLE_TEST_ROLE_ONE__", "__CONTAINOODLE_TEST_ROLE_TWO__"];
    const state = {
      config: { mode: "backend" }, "onboarding/connectionV1": "complete",
      accountsCache: [account, other], backendPinnedAccountIds: [], portalPinnedAccounts: [],
      [`accountContainer/${accountId}`]: storeId, [`containerAccount/${storeId}`]: accountId,
    };
    const storageEvent = event();
    const tabs = [
      { id: 7, windowId: 1, active: true, cookieStoreId: storeId, title: "__CONTAINOODLE_TEST_TAB_ONE__" },
      { id: 8, windowId: 1, active: false, cookieStoreId: storeId, title: "__CONTAINOODLE_TEST_TAB_TWO__" },
    ];
    const results = { tabUpdates: [], tabRemovals: [], windows: [], messages: [], options: 0 };
    window.browser = {
      storage: {
        local: {
          async get(keys) { return keys === null ? { ...state } : Object.fromEntries((typeof keys === "string" ? [keys] : keys).filter((key) => Object.hasOwn(state, key)).map((key) => [key, state[key]])); },
          async set(values) { const changes = {}; for (const [key, newValue] of Object.entries(values)) { changes[key] = { oldValue: state[key], newValue }; state[key] = newValue; } storageEvent.emit(changes, "local"); },
        },
        onChanged: storageEvent,
      },
      contextualIdentities: { query: async () => [{ cookieStoreId: storeId, name: account.accountName, color: "blue" }], onCreated: event(), onRemoved: event(), onUpdated: event() },
      tabs: {
        query: async (query) => tabs.filter((tab) => !query?.active || tab.active).map((tab) => ({ ...tab })),
        get: async (id) => ({ ...tabs.find((tab) => tab.id === id) }),
        update: async (id, changes) => { results.tabUpdates.push({ id, changes }); },
        remove: async (id) => { results.tabRemovals.push(id); tabs.splice(tabs.findIndex((tab) => tab.id === id), 1); },
        onRemoved: event(), onCreated: event(), onActivated: event(), onUpdated: event(),
      },
      runtime: {
        getManifest: () => ({ version: "1.2.0-synthetic-smoke" }),
        openOptionsPage: async () => { results.options += 1; },
        sendMessage: async (message) => {
          results.messages.push(message);
          if (message.type === "launch") return message.role ? { ok: true, account: other.accountName } : { chooseRole: roles };
          if (message.type === "discover-roles") return { ok: true, roles };
          if (message.type === "set-backend-pin") {
            await window.browser.storage.local.set({ backendPinnedAccountIds: message.pinned ? [otherId] : [] });
            return { ok: true };
          }
          if (message.type === "open-portal") return { error: "__CONTAINOODLE_TEST_SETUP_REQUIRED__" };
          return { ok: true };
        },
      },
      windows: { update: async (id, changes) => { results.windows.push({ id, changes }); } },
    };
    window.fetch = () => { throw new Error("Unexpected network request from synthetic sidebar"); };
    window.sidebarSmoke = { results, other, emitRefresh: () => window.browser.tabs.onActivated.emit() };
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${origin}/sidebar/sidebar.html`);
  const control = (key) => page.locator(`[data-focus-key="${key}"]`);
  const focusedKey = () => page.evaluate(() => document.activeElement.dataset.focusKey);
  const waitFocus = (key) => page.waitForFunction((expected) => document.activeElement.dataset.focusKey === expected, key);
  await control("section:all").waitFor();
  assert.equal(await control("section:all").getAttribute("aria-expanded"), "false");
  await control("section:all").focus();
  await page.keyboard.press("Space");
  await page.waitForFunction(() => document.querySelector('[data-focus-key="section:all"]').getAttribute("aria-expanded") === "true");
  assert.equal(await focusedKey(), "section:all");
  await page.keyboard.press("Tab");
  assert.equal(await focusedKey(), "search:all");
  await control("search:all").fill(" AcCount ");
  await control("search:all").evaluate((input) => input.setSelectionRange(3, 5, "backward"));
  await page.evaluate(() => { document.activeElement.dataset.oldNode = "true"; window.sidebarSmoke.emitRefresh(); });
  await page.waitForFunction(() => !document.querySelector('[data-old-node="true"]'));
  assert.deepEqual(await page.evaluate(() => [document.activeElement.value, document.activeElement.selectionStart, document.activeElement.selectionEnd, document.activeElement.selectionDirection]), [" AcCount ", 3, 5, "backward"]);
  await control("search:all").fill("");

  const pinKey = "pin:backend:111111111111";
  await control(pinKey).focus();
  await page.keyboard.press("Space");
  await page.waitForFunction(() => document.querySelector('[data-focus-key="pin:backend:111111111111"]').getAttribute("aria-pressed") === "true");
  assert.equal(await focusedKey(), pinKey);

  const launchKey = "launch:backend:111111111111";
  await control(launchKey).focus();
  await page.waitForFunction(() => getComputedStyle(document.activeElement).opacity === "1");
  await page.keyboard.press("Enter");
  await waitFocus("role:111111111111:0");
  await page.keyboard.press("Tab");
  assert.equal(await focusedKey(), "role:111111111111:1");
  await page.keyboard.press("Escape");
  await waitFocus(launchKey);
  assert.equal(await page.locator(".role-picker").count(), 0);
  await page.keyboard.press("Enter");
  await waitFocus("role:111111111111:0");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.sidebarSmoke.results.messages.some((message) => message.role === "__CONTAINOODLE_TEST_ROLE_ONE__"));

  await control("tab:7").focus();
  await page.waitForFunction(() => getComputedStyle(document.querySelector('[data-focus-key="close-tab:7"]')).opacity === "1");
  assert.equal(await control("tab:7").locator("button").count(), 0);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.sidebarSmoke.results.tabUpdates.length === 1);
  await control("close-tab:7").focus();
  await page.keyboard.press("Space");
  await page.waitForFunction(() => !document.querySelector('[data-focus-key="tab:7"]'));
  assert.equal(await page.evaluate(() => document.querySelector("#account-list").contains(document.activeElement)), true);
  assert.deepEqual(await page.evaluate(() => window.sidebarSmoke.results.tabRemovals), [7]);

  await page.evaluate(() => window.browser.storage.local.set({ config: { mode: "portal", portalStartUrl: "https://example.awsapps.com/start" }, portalPinnedAccounts: [window.sidebarSmoke.other] }));
  await page.locator("#open-portal-btn").waitFor({ state: "visible" });
  await page.locator("#open-portal-btn").focus();
  await page.keyboard.press("Enter");
  const recovery = page.locator(".notification-action");
  await recovery.waitFor();
  assert.equal(await recovery.evaluate((button) => button.tagName), "BUTTON");
  assert.match(await page.locator("#sidebar-announcement").textContent(), /__CONTAINOODLE_TEST_SETUP_REQUIRED__/);
  await recovery.focus();
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.sidebarSmoke.results.options === 1);

  assert.equal(await page.locator("button button").count(), 0);
  assert.equal(await page.locator('[role="status"][aria-live="polite"]').count(), 2);
  const muted = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--text-muted").trim());
  const luminance = (hex) => {
    const channels = hex.slice(1).match(/../g).map((value) => parseInt(value, 16) / 255).map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return channels.reduce((total, value, index) => total + value * [0.2126, 0.7152, 0.0722][index], 0);
  };
  const minimumContrast = Math.min(...["#0a0e17", "#111827", "#161f33", "#1c2844"].map((background) => (luminance(muted) + 0.05) / (luminance(background) + 0.05)));
  assert.ok(minimumContrast >= 4.5, `Muted text contrast is ${minimumContrast.toFixed(2)}:1`);
  assert.deepEqual(errors, []);
  const output = await mkdtemp(resolve(tmpdir(), "containoodle-sidebar-smoke-"));
  await page.screenshot({ path: resolve(output, "sidebar-320px.png"), fullPage: true });
  console.log(JSON.stringify({ passed: true, keyboard: "section, search, pin, role selection, Escape, tab switch/close, recovery", minimumMutedTextContrast: minimumContrast.toFixed(2), screenshot: resolve(output, "sidebar-320px.png") }));
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
