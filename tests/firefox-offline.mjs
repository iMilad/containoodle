// Actual Firefox, temporary extension/profile, real WebExtension APIs.
// No AWS login. Locked rejecting proxy + verified browser request gate.
// Firefox's own native sandbox remains enabled; no outer OS sandbox is used.
// Optional standalone smoke; NOT part of npm test and does not publish.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer as httpServer } from "node:http";
import net from "node:net";
import { mkdtemp, mkdir, lstat, realpath, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({ options: {
  firefox: { type: "string", default: "/Applications/Firefox.app/Contents/MacOS/firefox" },
  xpi: { type: "string" },
  probe: { type: "boolean", default: false },
  "skip-slow": { type: "boolean", default: false },
} });
const ADDON_ID = "{7da5f34e-08f0-4e4e-be7f-7b9b66ab7f60}";
const ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf";
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

class Marionette {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.nextId = 0;
    this.pending = new Map();
    this.hello = new Promise((resolve, reject) => { this.onHello = resolve; this.failHello = reject; });
    socket.on("data", data => {
      this.buffer = Buffer.concat([this.buffer, data]);
      for (;;) {
        const colon = this.buffer.indexOf(58);
        if (colon < 0) break;
        const length = Number(this.buffer.subarray(0, colon).toString());
        if (!Number.isSafeInteger(length) || length < 0 || length > 32 * 1024 * 1024) {
          socket.destroy(new Error("Invalid Marionette frame")); return;
        }
        if (this.buffer.length < colon + 1 + length) break;
        const message = JSON.parse(this.buffer.subarray(colon + 1, colon + 1 + length));
        this.buffer = this.buffer.subarray(colon + 1 + length);
        if (!Array.isArray(message)) { this.onHello(message); continue; }
        const pending = this.pending.get(message[1]);
        if (!pending) continue;
        clearTimeout(pending.timer);
        this.pending.delete(message[1]);
        if (message[2]) pending.reject(new Error(`${message[2].error}: ${message[2].message}`));
        else pending.resolve(message[3]);
      }
    });
    socket.on("error", error => this.fail(error));
    socket.on("close", () => this.fail(new Error("Marionette connection closed")));
  }
  fail(error) {
    this.failHello(error);
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    this.pending.clear();
  }
  send(name, params = {}, timeout = 20000) {
    const id = ++this.nextId;
    const bytes = Buffer.from(JSON.stringify([0, id, name, params]));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`Timed out: ${name}`)); }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(Buffer.concat([Buffer.from(`${bytes.length}:`), bytes]));
    });
  }
  async script(script, args = []) {
    const result = await this.send("WebDriver:ExecuteScript", { script, args, newSandbox: false });
    return result?.value;
  }
  async asyncScript(script, args = [], timeout = 20000) {
    const result = await this.send("WebDriver:ExecuteAsyncScript", { script, args, newSandbox: false }, timeout);
    const value = result?.value;
    if (value?.__fixtureError) throw new Error(value.__fixtureError);
    return value;
  }
  async evaluate(expression, args = [], timeout = 20000) {
    return this.asyncScript(`const done = arguments[arguments.length-1];
      Promise.resolve().then(async () => (${expression})).then(done,
        error => done({__fixtureError: String(error.message || error)}));`, args, timeout);
  }
  context(value) { return this.send("Marionette:SetContext", { value }); }
  async click(selector) {
    for (let attempt = 0; ; attempt++) {
      const el = await this.send("WebDriver:FindElement", { using: "css selector", value: selector });
      try { return await this.send("WebDriver:ElementClick", { id: (el.value ?? el)[ELEMENT_KEY] }); }
      catch (error) { if (attempt >= 2 || !error.message.startsWith("stale element reference:")) throw error; await delay(100); }
    }
  }
  async keys(text) {
    for (let attempt = 0; ; attempt++) {
      const el = await this.send("WebDriver:GetActiveElement");
      try { return await this.send("WebDriver:ElementSendKeys", { id: (el.value ?? el)[ELEMENT_KEY], text }); }
      catch (error) { if (attempt >= 2 || !error.message.startsWith("stale element reference:")) throw error; await delay(100); }
    }
  }
  async fill(selector, text) {
    const el = await this.send("WebDriver:FindElement", { using: "css selector", value: selector });
    const id = (el.value ?? el)[ELEMENT_KEY];
    await this.send("WebDriver:ElementClear", { id });
    await this.send("WebDriver:ElementSendKeys", { id, text });
  }
  async waitFor(expression, timeout = 15000) {
    const deadline = Date.now() + timeout;
    let last;
    do {
      last = await this.script(`return (${expression});`);
      if (last) return last;
      await delay(100);
    } while (Date.now() < deadline);
    throw new Error(`Wait failed: ${expression}; last=${JSON.stringify(last)}`);
  }
}

async function listen(server) {
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return server.address().port;
}
async function connect(port, child) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (child.exitCode !== null) throw new Error(`Firefox exited with ${child.exitCode}`);
    try {
      const socket = await new Promise((resolve, reject) => {
        const socket = net.connect({ host: "127.0.0.1", port });
        socket.once("error", reject); socket.once("connect", () => { socket.removeListener("error", reject); resolve(socket); });
      });
      const client = new Marionette(socket);
      let greetingTimer;
      try {
        await Promise.race([client.hello, new Promise((_, reject) => {
          greetingTimer = setTimeout(() => { socket.destroy(); reject(new Error("Marionette greeting timeout")); }, 3000);
        })]);
      } finally { clearTimeout(greetingTimer); }
      return client;
    } catch { await delay(200); }
  }
  throw new Error("Disposable Firefox did not open its automation port");
}
async function stopChild(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([new Promise(resolve => child.once("exit", resolve)), delay(5000)]);
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise(resolve => child.once("exit", resolve));
    child.kill("SIGKILL");
    await Promise.race([exited, delay(5000)]);
    assert.ok(child.exitCode !== null || child.signalCode !== null, "Owned browser must exit before profile cleanup");
  }
}

async function startHelper() {
  const child = spawn("python3", [join(root, "tests/firefox_synthetic_helper.py")], { stdio: ["ignore", "pipe", "pipe"] });
  const ready = await new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => { child.kill("SIGTERM"); reject(new Error("Synthetic helper handshake timeout")); }, 10000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); reject(new Error(`Synthetic helper exited: ${code}`)); });
    child.stdout.on("data", chunk => {
      output += chunk;
      if (output.includes("\n")) {
        clearTimeout(timer);
        try { resolve(JSON.parse(output.split("\n")[0])); }
        catch { child.kill("SIGTERM"); reject(new Error("Invalid synthetic helper handshake")); }
      }
    });
    child.stderr.on("data", () => {});
  });
  assert.equal(ready.synthetic, true);
  assert.match(ready.url, /^http:\/\/127\.0\.0\.1:\d+$/);
  return { child, ...ready, async control(command) {
    const response = await fetch(ready.url + ready.controlPath, { method: "POST", headers: {
      "Content-Type": "application/json", [ready.controlHeader]: ready.controlToken,
    }, body: JSON.stringify(command), signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
    return response.json();
  } };
}

async function main() {
  assert.equal(process.platform, "darwin", "This installed Firefox smoke currently targets macOS");
  const installPath = values.xpi ? resolve(values.xpi) : join(root, "firefox-extension");
  const artifactHash = values.xpi ? createHash("sha256").update(await readFile(installPath)).digest("hex") : null;
  const workspace = await mkdtemp(join(tmpdir(), "containoodle-firefox-offline-"));
  const profile = join(workspace, "profile");
  await mkdir(profile);
  const reportDir = join(root, "artifacts", `firefox-offline-${new Date().toISOString().replace(/[:.]/g, "-")}`);
  await mkdir(reportDir, { recursive: true });
  const profileMetadata = async () => Promise.all([
    "/Users/mk/Library/Application Support/Firefox/profiles.ini",
    "/Users/mk/Library/Application Support/Firefox/installs.ini",
  ].map(async path => {
    try { const stat = await lstat(path); return { path, size: stat.size, mtimeMs: stat.mtimeMs, ino: stat.ino }; }
    catch (error) { if (error.code === "ENOENT") return { path, absent: true }; throw error; }
  }));
  const originalMetadata = await profileMetadata();
  const results = { mode: values.probe ? "probe" : "offline-suite", slowCheckSkipped: values["skip-slow"], browser: null, addon: null, artifact: artifactHash ? { path: installPath, sha256: artifactHash } : null, install: `temporary ${artifactHash ? "XPI" : "source-directory"} install in headless Firefox; not signed upgrade acceptance`, checks: [], network: { protection: "locked rejecting proxy and browser channel gate; not OS isolation", blockedHosts: [] } };
  const record = (name, detail = {}) => { results.checks.push({ ...detail, name, passed: true }); console.log(`PASS ${name}`); };
  const hosts = new Set();
  const proxy = httpServer((req, res) => {
    try { hosts.add(new URL(req.url).hostname); } catch { hosts.add("invalid-target"); }
    res.writeHead(502, { "Content-Type": "text/plain" }).end("Synthetic offline test: external network blocked");
  });
  proxy.on("connect", (req, socket) => {
    hosts.add(req.url.split(":")[0]);
    socket.end("HTTP/1.1 403 Offline test network guard\r\nContent-Length: 0\r\n\r\n");
  });
  const proxyPort = await listen(proxy);
  const reservation = net.createServer();
  const marionettePort = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  const prefs = {
    "marionette.port": marionettePort,
    "remote.prefs.recommended": false,
    "browser.shell.checkDefaultBrowser": false,
    "browser.startup.page": 0,
    "browser.startup.homepage": "about:blank",
    "browser.startup.homepage_override.mstone": "ignore",
    "browser.newtabpage.enabled": false,
    "browser.aboutwelcome.enabled": false,
    "browser.discovery.enabled": false,
    "browser.region.network.url": "",
    "browser.region.update.enabled": false,
    "browser.translations.enable": false,
    "browser.tabs.groups.enabled": true,
    "datareporting.policy.dataSubmissionEnabled": false,
    "datareporting.healthreport.uploadEnabled": false,
    "datareporting.usage.uploadEnabled": false,
    "toolkit.telemetry.enabled": false,
    "toolkit.telemetry.server": "data:,",
    "toolkit.telemetry.reportingpolicy.firstRun": false,
    "app.normandy.enabled": false,
    "app.shield.optoutstudies.enabled": false,
    "extensions.update.enabled": false,
    "extensions.systemAddon.update.enabled": false,
    "extensions.getAddons.cache.enabled": false,
    "extensions.getAddons.showPane": false,
    "services.settings.server": "data:,",
    "security.remote_settings.intermediates.enabled": false,
    "network.proxy.type": 1,
    "network.proxy.http": "127.0.0.1", "network.proxy.http_port": proxyPort,
    "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": proxyPort,
    "network.proxy.no_proxies_on": "localhost,127.0.0.1",
    "network.proxy.failover_direct": false,
    "network.trr.mode": 5,
    "network.dns.disablePrefetch": true,
    "network.prefetch-next": false,
    "network.http.speculative-parallel-limit": 0,
    "network.captive-portal-service.enabled": false,
    "network.connectivity-service.enabled": false,
    "media.peerconnection.enabled": false,
    "dom.push.connection.enabled": false,
    "geo.enabled": false,
    "signon.rememberSignons": false,
    "termsofuse.bypassNotification": true,
  };
  await writeFile(join(profile, "user.js"), Object.entries(prefs).map(([k,v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join("\n"));
  // Deliberately no signature/content-sandbox relaxation and no HOME override.
  // sandbox-exec cannot be nested with Firefox's own macOS content sandbox.
  // All product testing is gated on the browser-channel blocker below instead.
  let firefox;
  let client;
  let helper;
  let logs = "";
  let failure;
  try {
    helper = await startHelper();
    firefox = spawn(values.firefox, [
      "-headless", "-no-remote", "-profile", profile, "-marionette", "--remote-allow-system-access", "about:blank"], {
      stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, MOZ_CRASHREPORTER_DISABLE: "1" },
    });
    let spawnError;
    firefox.once("error", error => { spawnError = error; });
    firefox.stdout.on("data", chunk => { logs = (logs + chunk).slice(-12000); });
    firefox.stderr.on("data", chunk => { logs = (logs + chunk).slice(-12000); });
    client = await connect(marionettePort, firefox);
    if (spawnError) throw spawnError;
    const session = await client.send("WebDriver:NewSession", { capabilities: { alwaysMatch: {
      acceptInsecureCerts: false, pageLoadStrategy: "eager",
    } } });
    const capabilities = session.capabilities ?? session.value?.capabilities;
    assert.equal(capabilities["moz:profile"], profile);
    results.browser = { name: capabilities.browserName, version: capabilities.browserVersion };
    record("genuine Firefox with an isolated unregistered profile", results.browser);
    await client.send("WebDriver:SetTimeouts", { script: 20000, pageLoad: 20000, implicit: 0 });
    await client.context("chrome");
    const profileDirs = await client.script("return ['ProfD','ProfLD'].map(key => Services.dirsvc.get(key, Ci.nsIFile).path);");
    const ownedPath = await realpath(workspace);
    for (const path of profileDirs) assert.ok((await realpath(path)).startsWith(ownedPath + "/"), "Both profile and cache must stay in our owned test directory");
    await client.script(`
      window.__containoodleOfflineGate = {
        blocked: [],
        observe(subject) {
          const channel = subject.QueryInterface(Ci.nsIHttpChannel);
          if (channel.URI.prePath === ${JSON.stringify(helper.url)}) return;
          this.blocked.push(channel.URI.host);
          channel.cancel(Cr.NS_ERROR_OFFLINE);
        }
      };
      Services.obs.addObserver(window.__containoodleOfflineGate, 'http-on-modify-request');
      for (const name of ${JSON.stringify(Object.keys(prefs).filter(name => name.startsWith("network.") || name === "media.peerconnection.enabled"))}) Services.prefs.lockPref(name);
      return true;
    `);
    let deniedHits = 0;
    const deniedServer = httpServer((_req, res) => { deniedHits++; res.writeHead(500).end("Unexpected fixture access"); });
    const deniedPort = await listen(deniedServer);
    try {
      const blocked = await client.evaluate(`Promise.all([
        fetch('https://containoodle-offline-check.invalid/'),
        fetch('http://127.0.0.1:${deniedPort}/')
      ].map(request => request.then(() => false, () => true)))`);
      assert.deepEqual(blocked, [true, true]);
      const logged = await client.script("return window.__containoodleOfflineGate.blocked;");
      assert.ok(logged.includes("containoodle-offline-check.invalid"));
      assert.ok(logged.includes("127.0.0.1"));
      assert.equal(deniedHits, 0, "Disallowed local listener must not receive requests");
      const local = await client.evaluate(`fetch(${JSON.stringify(helper.url + "/auth/challenge")}).then(r => r.status)`);
      assert.equal(local, 200);
      record("network gate rejects external and non-fixture loopback requests; synthetic helper stays reachable");
    } finally { deniedServer.closeAllConnections(); await new Promise(resolve => deniedServer.close(resolve)); }
    await client.context("content");
    await client.send("Addon:Install", { path: installPath, temporary: true });
    await client.context("chrome");
    const extensionOrigin = await client.script(`return WebExtensionPolicy.getByID(${JSON.stringify(ADDON_ID)}).getURL("");`);
    record("temporary unsigned extension installed without disabling signature enforcement");
    await client.context("content");
    await client.send("WebDriver:Navigate", { url: `${extensionOrigin}options/options.html` });
    results.addon = await client.evaluate("browser.runtime.getManifest().version");
    assert.equal(results.addon, "1.2.0");
    assert.equal(await client.evaluate("browser.runtime.getManifest().name"), "Containoodle — AWS Console Containers");
    const state = await client.evaluate("browser.storage.local.get(null)");
    assert.equal(state["onboarding/connectionV1"], "choose");
    record("fresh first-run onboarding uses real Firefox extension storage");
    if (!values.probe) {
      const optionsUrl = `${extensionOrigin}options/options.html`;
      const sidebarUrl = `${extensionOrigin}sidebar/sidebar.html`;
      const handleResult = await client.send("WebDriver:GetWindowHandle");
      const mainHandle = handleResult.value ?? handleResult;
      const mainWindow = async () => { await client.context("content"); await client.send("WebDriver:SwitchToWindow", { handle: mainHandle }); };
      const go = async url => { await mainWindow(); await client.send("WebDriver:Navigate", { url }); };
      const getState = () => client.evaluate("browser.storage.local.get(null)");
      const origins = () => client.evaluate("browser.permissions.getAll().then(p => p.origins.sort())");
      const poll = async (fn, predicate, timeout = 15000) => {
        const end = Date.now() + timeout;
        let last;
        do { last = await fn(); if (predicate(last)) return last; await delay(150); } while (Date.now() < end);
        throw new Error("Timed out waiting for native browser state");
      };
      const screenshot = async name => {
        const result = await client.send("WebDriver:TakeScreenshot", { full: true });
        await writeFile(join(reportDir, `${name}.png`), Buffer.from(result.value ?? result, "base64"));
      };
      const permission = async allow => {
        await client.context("chrome");
        await client.waitFor("document.getElementById('addon-webext-permissions-notification') && !document.getElementById('addon-webext-permissions-notification').hidden && PopupNotifications.panel.state === 'open'");
        // Honor Firefox's anti-clickjacking delay rather than weakening it.
        const clickDelay = await client.script("return Services.prefs.getIntPref('security.notification_enable_delay', 500);");
        await delay(Math.max(1000, clickDelay + 250));
        const promptState = await client.script(`const n = document.getElementById('addon-webext-permissions-notification'); const b=n.${allow ? "button" : "secondaryButton"}; const r=b.getBoundingClientRect(); return {state:PopupNotifications.panel.state,hidden:n.hidden,tag:b.localName,x:r.x,y:r.y,width:r.width,height:r.height};`);
        const element = await client.script(`const n = document.getElementById('addon-webext-permissions-notification'); const button = n.${allow ? "button" : "secondaryButton"}; return button.shadowRoot?.querySelector('button') || button;`);
        if (!element?.[ELEMENT_KEY]) {
          console.log("PROMPT SHAPE", JSON.stringify(await client.script("const n=document.getElementById('addon-webext-permissions-notification'); return {html:n.outerHTML.slice(0,4000),button:!!n.button,secondary:!!n.secondaryButton};")));
          throw new Error("Cannot find native Firefox permission button");
        }
        if (promptState.tag === "moz-button") {
          // Firefox 156 uses shadow-DOM HTML buttons in a native popup;
          // Marionette's element-scroll check cannot target that widget.
          // Use real keyboard activation, not a permission-API shortcut.
          const focused = await client.script(`window.focus(); const n=document.getElementById('addon-webext-permissions-notification'); const host=n.${allow ? "button" : "secondaryButton"}; host.buttonEl.focus(); return host.shadowRoot.activeElement === host.buttonEl;`);
          assert.equal(focused, true);
          await client.send("WebDriver:PerformActions", { actions: [{ type: "key", id: "native-permission-keyboard", actions: [
            { type: "keyDown", value: "\uE007" }, { type: "keyUp", value: "\uE007" },
          ] }] });
          await client.send("WebDriver:ReleaseActions");
        } else await client.send("WebDriver:ElementClick", { id: element[ELEMENT_KEY] });
        await client.waitFor("PopupNotifications.panel.state === 'closed'");
        await client.context("content");
      };
      const before = await helper.control({ action: "status" });
      await client.click("#mode-backend");
      await client.waitFor("document.getElementById('backend-save') && !document.getElementById('backend-save').disabled");
      assert.deepEqual((await helper.control({ action: "status" })).counts, before.counts);
      assert.deepEqual(await origins(), []);
      record("choosing helper setup does not request permissions or contact a helper");
      await client.fill("#backend-url", helper.url);
      await client.fill("#backend-token", helper.helperToken);
      await client.click("#backend-save");
      await permission(false);
      await client.waitFor("document.getElementById('backend-status').textContent.includes('Connected to local helper')");
      assert.equal(await client.script("return document.getElementById('backend-token').value;"), "");
      let saved = await getState();
      assert.equal(saved["onboarding/connectionV1"], "complete");
      assert.equal(saved.accountsCache.length, 2);
      assert.equal(saved.backendAuthToken, helper.helperToken);
      assert.equal(saved.backendSessionReuseAutoOfferHandled, true);
      assert.deepEqual(await origins(), []);
      record("native permission denial does not block real HMAC helper setup; token is not redisplayed");
      await client.click("#backend-save");
      await client.waitFor("document.getElementById('backend-status').textContent.includes('Connected to local helper')");
      await client.context("chrome");
      assert.notEqual(await client.script("return PopupNotifications.panel.state;"), "open");
      await client.context("content");
      record("saved helper token works and first-run permission offer is not repeated");
      await client.script("document.getElementById('console-permissions').open = true;");
      await client.click("#console-grant");
      await permission(true);
      await client.waitFor("document.getElementById('console-revoke').disabled === false");
      assert.deepEqual(await origins(), ["https://*.console.aws.amazon.com/*"]);
      await client.click("#console-revoke");
      await client.waitFor("document.getElementById('console-revoke').disabled === true");
      assert.deepEqual(await origins(), []);
      assert.equal((await getState()).accountsCache.length, 2);
      record("native session-reuse permission grant and revoke remain console-only and preserve accounts");
      await go(sidebarUrl);
      await client.waitFor("document.getElementById('status-text').textContent.includes('Connected')");
      await client.click('[data-focus-key="section:all"]');
      await client.waitFor("document.querySelector('[data-focus-key=\"search:all\"]')");
      record("real Firefox sidebar loads synthetic helper accounts");
      const alpha = helper.accounts[0].accountId;
      const beta = helper.accounts[1].accountId;
      const key = value => `[data-focus-key="${value}"]`;
      await client.click(key(`pin:backend:${alpha}`));
      await client.waitFor(`document.querySelector('${key(`pin:backend:${alpha}`)}').getAttribute('aria-pressed') === 'true'`);
      await client.keys(" ");
      await client.waitFor(`document.querySelector('${key(`pin:backend:${alpha}`)}').getAttribute('aria-pressed') === 'false'`);
      await client.keys("\uE007");
      await client.waitFor(`document.querySelector('${key(`pin:backend:${alpha}`)}').getAttribute('aria-pressed') === 'true'`);
      await go(sidebarUrl);
      await client.waitFor(`document.querySelector('${key(`pin:backend:${alpha}`)}')?.getAttribute('aria-pressed') === 'true'`);
      record("native keyboard Space and Enter toggle a pin; pin survives page reload");
      const search = key("search:all");
      if (!(await client.script(`return !!document.querySelector('${search}');`))) await client.click(key("section:all"));
      await client.fill(search, "BETA");
      await client.waitFor(`document.querySelector('.section-all ${key(`launch:backend:${beta}`)}') && !document.querySelector('.section-all ${key(`launch:backend:${alpha}`)}')`);
      await client.keys("\uE003"); // Backspace; real keyboard input, not a synthetic DOM event.
      const focusBefore = await client.script("const n=document.activeElement; return {key:n.dataset.focusKey,start:n.selectionStart,value:n.value};");
      await client.evaluate("browser.tabs.create({url:'about:blank', active:false}).then(async tab => {await browser.tabs.remove(tab.id); return true;})");
      await delay(400);
      const focusAfter = await client.script("const n=document.activeElement; return {key:n.dataset.focusKey,start:n.selectionStart,value:n.value};");
      assert.deepEqual(focusAfter, focusBefore);
      await client.fill(search, "");
      record("account filtering and keyboard focus/caret survive real Firefox tab-event refreshes");

      // Recheck the HTTP gate immediately before allowing AWS-shaped fake launch URLs.
      await client.context("chrome");
      assert.equal(await client.evaluate("fetch('https://containoodle-offline-check.invalid/').then(() => false, () => true)"), true);
      assert.equal(await client.script("return Services.prefs.prefIsLocked('network.proxy.type') && !!window.__containoodleOfflineGate;"), true);
      await client.context("content");
      await helper.control({ action: "configure", mode: "good", allowSyntheticLaunches: true, networkBlocked: true });
      await client.click(key(`launch:backend:${beta}`));
      await client.waitFor(`document.querySelector('${key(`role:${beta}:0`)}')`);
      await client.keys("\uE00C"); // Escape dismisses the inline role picker.
      await client.waitFor(`!document.querySelector('${key(`role:${beta}:0`)}')`);
      await client.click(key(`launch:backend:${beta}`));
      await client.waitFor(`document.querySelector('${key(`role:${beta}:0`)}')`);
      await client.keys("\uE007");
      await delay(500);
      await mainWindow();
      saved = await poll(getState, value => typeof value[`accountContainer/${beta}`] === "string");
      const betaStore = saved[`accountContainer/${beta}`];
      await client.waitFor(`document.querySelector('${key(`launch:backend:${alpha}`)}')`);
      await client.click(key(`launch:backend:${alpha}`));
      await delay(500);
      await mainWindow();
      saved = await poll(getState, value => typeof value[`accountContainer/${alpha}`] === "string");
      const alphaStore = saved[`accountContainer/${alpha}`];
      assert.notEqual(alphaStore, betaStore);
      const organized = await poll(() => client.evaluate("Promise.all([browser.tabs.query({}), browser.tabGroups.query({}), browser.contextualIdentities.query({})])"),
        ([tabs, groups]) => [alphaStore, betaStore].every(store => tabs.some(tab => tab.cookieStoreId === store && groups.some(group => group.id === tab.groupId))));
      assert.ok(organized[2].some(container => container.cookieStoreId === alphaStore));
      assert.ok(organized[2].some(container => container.cookieStoreId === betaStore));
      record("native role picker Escape/Enter and synthetic launches create separate real Firefox containers and tab groups", { liveAwsVerified: false });

      await go(optionsUrl);
      await client.fill("#group-name-pattern", "^__CONTAINOODLE_TEST_ACCOUNT_");
      await client.fill("#group-name-replacement", "Test ");
      await client.click("#group-name-save");
      await client.waitFor("document.getElementById('group-name-status').textContent.includes('naming saved')");
      await poll(() => client.evaluate("browser.contextualIdentities.query({})"), containers =>
        containers.some(c => c.cookieStoreId === alphaStore && c.name === "Test ALPHA__") && containers.some(c => c.cookieStoreId === betaStore && c.name === "Test BETA__"));
      await poll(() => client.evaluate("browser.tabGroups.query({})"), groups => groups.some(g => g.title === "Test ALPHA__") && groups.some(g => g.title === "Test BETA__"));
      // Actual page-provided favicons, from loopback-only synthetic pages.
      // SVG scripts/external images are traps: Firefox must not execute/load
      // them when displaying a favicon as a passive <img>.
      await go(helper.url + "/__fixture/favicon-page");
      assert.equal(await client.script("return document.cookie.includes('__CONTAINOODLE_TEST_FAVICON__=fixture');"), true);
      await go(optionsUrl);
      const iconServices = ["sagemaker", "s3", "systems-manager", "lambda", "inspector"];
      const iconTabs = await client.evaluate(`Promise.all(${JSON.stringify(iconServices)}.map(service => browser.tabs.create({
        url:${JSON.stringify(helper.url + "/__fixture/favicon-page?service=")}+service,
        cookieStoreId:${JSON.stringify(alphaStore)}, active:false,
      }))).then(tabs=>tabs.map(tab=>tab.id))`);
      await go(sidebarUrl);
      await client.waitFor("[...document.querySelectorAll('.account-name')].some(n => n.textContent === 'Test ALPHA__')");
      await client.waitFor("document.querySelectorAll('.tab-favicon-slot:not(.is-fallback) img').length === 5");
      assert.equal(await client.script("return [...document.querySelectorAll('.tab-favicon-image')].every(n=>n.naturalWidth===16 && n.src.startsWith('data:image/') && n.parentElement.getAttribute('aria-hidden')==='true');"), true);
      assert.equal(await client.script("return document.querySelectorAll('.tab-favicon-slot svg, .tab-favicon-slot script').length;"), 0);
      record("five actual Firefox page-provided SVG favicons display as passive images, not custom service drawings", { liveAwsVerified: false });
      const remoteFavicon = await client.evaluate(`(async () => {
        const {createFaviconLoader} = await import('../shared/service-icons.js');
        // Substitute only transport destination: the production validator,
        // request flags, byte limit, data conversion and cache run unchanged.
        let calls=0;
        const load=createFaviconLoader({fetchImpl:(_url,options)=>{
          calls++; return fetch(${JSON.stringify(helper.url + "/__fixture/favicon.svg")}, options);
        }});
        const tab={url:'https://eu-west-1.console.aws.amazon.com/s3/home',
          favIconUrl:'https://assets.console.awsstatic.com/synthetic/favicon.svg'};
        const [first,second]=await Promise.all([load(tab),load(tab)]);
        const img=new Image(); img.src=first;
        await img.decode();
        return {calls, same:first===second, embedded:first.startsWith('data:image/svg+xml;base64,'), width:img.naturalWidth};
      })()`);
      assert.deepEqual(remoteFavicon, {calls:1,same:true,embedded:true,width:16});
      const iconCounts = (await helper.control({action:"status"})).counts;
      assert.equal(iconCounts.faviconCookieReceived || 0, 0);
      assert.equal(iconCounts.faviconReferrerReceived || 0, 0);
      assert.equal(iconCounts["GET /__fixture/forbidden-svg-resource"] || 0, 0);
      record("production favicon loader uses anonymous CORS without cookies/referrers; SVG scripts/resources stay disabled", { transport: "synthetic loopback substitution; no AWS image request" });
      await screenshot("sidebar-renamed-accounts");
      await client.context("chrome");
      const docked = await client.evaluate(`(async () => {
        const entry = window.SidebarController.getExtensions().find(e => e.extensionId === ${JSON.stringify(ADDON_ID)});
        if (!entry) throw new Error('Native extension sidebar was not registered');
        await window.SidebarController.show(entry.commandID);
        return {open:window.SidebarController.isOpen, correct:window.SidebarController.currentID === entry.commandID};
      })()`);
      assert.deepEqual(docked, { open: true, correct: true });
      await client.waitFor(`window.SidebarController.browser.contentDocument?.getElementById('webext-panels-browser')?.currentURI.spec === ${JSON.stringify(sidebarUrl)}`);
      await delay(700);
      await screenshot("native-docked-sidebar");
      const sidebarScript = script => client.evaluate(`(async () => {
        const inner = SidebarController.browser.contentDocument.getElementById('webext-panels-browser');
        const actor = inner.browsingContext.currentWindowGlobal.getActor('MarionetteCommands');
        return await actor.executeScript(${JSON.stringify(script)}, [],
          {timeout:5000,sandboxName:null,newSandbox:false,file:'containoodle-offline-test',line:0,async:false});
      })()`);
      const sidebarMetrics = () => sidebarScript(`return {
        width:innerWidth, clientWidth:document.documentElement.clientWidth, scrollWidth:document.documentElement.scrollWidth,
        accounts:document.querySelectorAll('.account-item').length,
        serviceIcons:document.querySelectorAll('.tab-favicon-slot:not(.is-fallback) img').length,
        roleOptions:document.querySelectorAll('.role-option').length,
        nameWidths:[...document.querySelectorAll('.account-name')].map(n=>n.getBoundingClientRect().width),
        clippedButtons:[...document.querySelectorAll('button, .role-chip, .tab-favicon, .section-label, .section-description, .brand-subtitle')].filter(n=>{
          const r=n.getBoundingClientRect(); return r.width>0 && (r.left<0 || r.right>innerWidth+1);
        }).map(n=>n.dataset.focusKey || n.id || n.className)
      };`);
      const normalMetrics = await sidebarMetrics();
      assert.ok(normalMetrics.width > 0 && normalMetrics.accounts === 2);
      assert.equal(normalMetrics.serviceIcons, 5);
      assert.ok(normalMetrics.scrollWidth <= normalMetrics.clientWidth + 1);
      await client.script("SidebarController.browser.contentDocument.getElementById('webext-panels-browser').fullZoom = 2;");
      await delay(400);
      const zoomMetrics = await sidebarMetrics();
      assert.ok(zoomMetrics.accounts === 2 && zoomMetrics.width < normalMetrics.width);
      assert.equal(zoomMetrics.serviceIcons, 5);
      assert.ok(zoomMetrics.scrollWidth <= zoomMetrics.clientWidth + 1);
      await screenshot("native-docked-sidebar-200-percent");
      // Activate the real docked UI handler for layout coverage only. The earlier
      // role-picker interaction uses native WebDriver keyboard input separately.
      await sidebarScript(`document.querySelector('${key(`choose-role:backend:${beta}`)}').click(); return true;`);
      const pickerZoomMetrics = await poll(sidebarMetrics, metrics => metrics.roleOptions === 3);
      await screenshot("native-docked-role-picker-200-percent");
      await client.script("SidebarController.browser.contentDocument.getElementById('webext-panels-browser').fullZoom = 1;");
      await delay(300);
      const pickerNormalMetrics = await sidebarMetrics();
      await screenshot("native-docked-role-picker");
      await sidebarScript(`document.querySelector('${key(`dismiss-role:backend:${beta}`)}').click(); return true;`);
      await client.context("content");
      await client.click(key(`pin:backend:${beta}`));
      await client.waitFor(`document.querySelector('${key(`pin:backend:${beta}`)}').getAttribute('aria-pressed') === 'true'`);
      await client.evaluate(`browser.tabs.query({cookieStoreId:${JSON.stringify(betaStore)}}).then(tabs=>browser.tabs.remove([
        ...tabs.map(tab=>tab.id), ...${JSON.stringify(iconTabs)}
      ]))`);
      await client.context("chrome");
      const sectionState = () => sidebarScript(`return {
        subtitle:document.querySelector('.brand-subtitle')?.textContent,
        subtitleBelowName:document.querySelector('.brand-subtitle').getBoundingClientRect().top >= document.querySelector('.brand-name-row').getBoundingClientRect().bottom,
        sections:[...document.querySelectorAll('.section')].map(n=>({key:n.dataset.sectionKey,
          label:n.querySelector('.section-label').textContent,
          description:n.querySelector('.section-description')?.textContent,
          symbol:n.querySelector('.section-symbol').textContent,
          accounts:n.querySelectorAll('.account-item').length}))
      };`);
      const sections = await poll(sectionState, value=>value.sections.some(n=>n.key==='pinned' && n.accounts===1));
      assert.equal(sections.subtitle, "AWS Console Containers");
      assert.equal(sections.subtitleBelowName, true);
      assert.deepEqual(sections.sections, [
        {key:"active",label:"Active (1)",description:"Open tabs now",symbol:"●",accounts:1},
        {key:"pinned",label:"Favorites (1)",description:"Saved shortcuts · no open tabs",symbol:"★",accounts:1},
      ]);
      const favoritesNormalMetrics = await sidebarMetrics();
      assert.equal(favoritesNormalMetrics.roleOptions, 0);
      await screenshot("native-docked-active-favorites");
      await client.script("SidebarController.browser.contentDocument.getElementById('webext-panels-browser').fullZoom = 2;");
      await delay(400);
      const favoritesZoomMetrics = await sidebarMetrics();
      await screenshot("native-docked-active-favorites-200-percent");
      await client.script("SidebarController.browser.contentDocument.getElementById('webext-panels-browser').fullZoom = 1;");
      results.sidebarSections = sections;
      record("subtitle and distinct Active/Favorites sections preserve saved shortcuts when their tabs close");
      // Root overflow is intentionally hidden by the UI, so scrollWidth alone
      // is NOT sufficient evidence that labels and controls remain usable.
      results.sidebarLayout = { normalMetrics, zoomMetrics, pickerNormalMetrics, pickerZoomMetrics, favoritesNormalMetrics, favoritesZoomMetrics };
      if (Object.values(results.sidebarLayout).some(metrics => metrics.scrollWidth > metrics.clientWidth + 1 || metrics.nameWidths.some(width => width < 1) || metrics.clippedButtons.length)) {
        results.findings ??= [];
        results.findings.push({ severity: "moderate", area: "narrow-sidebar-zoom", description: "An account label collapsed or a button extended outside the sidebar at normal or 200-percent zoom.", screenshot: "native-docked-sidebar-200-percent.png" });
        console.log("FINDING narrow sidebar loses account-label/control space; not a visual acceptance pass");
      }
      record("actual docked sidebar geometry and screenshots captured at normal and 200-percent zoom", { visualAcceptance: !(results.findings?.length) });
      await client.evaluate("window.SidebarController.hide()");
      await client.context("content");
      record("the extension opens in Firefox's actual docked sidebar", { screenshot: "native-docked-sidebar.png" });
      record("name regex updates native container names, native group titles, active accounts and pinned sidebar labels");
      await client.evaluate(`browser.contextualIdentities.update(${JSON.stringify(alphaStore)}, {name:'__CONTAINOODLE_TEST_MANUAL_CONTAINER__'})`);
      const alphaTab = await client.evaluate(`browser.tabs.query({cookieStoreId:${JSON.stringify(alphaStore)}}).then(tabs => tabs[0])`);
      await client.evaluate(`browser.tabGroups.update(${alphaTab.groupId}, {title:'__CONTAINOODLE_TEST_MANUAL_GROUP__'})`);
      await poll(getState, state => state[`tabGroupTitle/${alpha}`] === "__CONTAINOODLE_TEST_MANUAL_GROUP__");
      await go(optionsUrl);
      await client.fill("#group-name-replacement", "Demo ");
      await client.click("#group-name-save");
      await poll(() => client.evaluate("browser.contextualIdentities.query({})"), containers => containers.some(c => c.cookieStoreId === betaStore && c.name === "Demo BETA__"));
      const renamedContainers = await client.evaluate("browser.contextualIdentities.query({})");
      assert.equal(renamedContainers.find(c => c.cookieStoreId === alphaStore).name, "__CONTAINOODLE_TEST_MANUAL_CONTAINER__");
      const renamedGroups = await client.evaluate("browser.tabGroups.query({})");
      assert.equal(renamedGroups.find(g => g.id === alphaTab.groupId).title, "__CONTAINOODLE_TEST_MANUAL_GROUP__");
      record("changing the naming rule preserves manually renamed real containers and tab groups");

      const baseline = await getState();
      const assertPreserved = async () => {
        const current = await getState();
        for (const name of ["backendUrl", "backendAuthToken", "accountsCache"]) assert.deepEqual(current[name], baseline[name], `${name} must survive a failed helper check`);
        assert.equal(await client.script("return document.getElementById('backend-save').disabled;"), false);
      };
      await client.fill("#backend-token", "A".repeat(43));
      await client.click("#backend-save");
      await client.waitFor("!document.getElementById('backend-save').disabled && /authentication failed/i.test(document.getElementById('backend-status').textContent)");
      await assertPreserved();
      await client.fill("#backend-token", "");
      record("wrong synthetic helper token fails closed without replacing saved settings or cached accounts");
      for (const mode of ["bad-schema", "bad-json", "bad-proof", "unavailable", "disconnect"]) {
        await helper.control({ action: "configure", mode });
        await client.click("#backend-refresh");
        await client.waitFor("!document.getElementById('backend-save').disabled && !/Refreshing|Connected/.test(document.getElementById('backend-status').textContent)");
        const message = await client.script("return document.getElementById('backend-status').textContent;");
        assert.ok(message.trim());
        await assertPreserved();
        await helper.control({ action: "configure", mode: "good" });
        await client.click("#backend-refresh");
        await client.waitFor("!document.getElementById('backend-save').disabled && document.getElementById('backend-status').textContent.includes('Connected')");
        record(`helper ${mode} error preserves cache/settings and a subsequent real Firefox retry recovers`, { message });
      }
      if (!values["skip-slow"]) {
        await helper.control({ action: "configure", mode: "accounts-body-delay", delaySeconds: 65 });
        const started = Date.now();
        await client.click("#backend-refresh");
        console.log("RUNNING actual 60-second response-body timeout check (no mocked browser clock)");
        await client.waitFor("!document.getElementById('backend-save').disabled && /timed out/i.test(document.getElementById('backend-status').textContent)", 70000);
        const elapsedMs = Date.now() - started;
        assert.ok(elapsedMs >= 59000 && elapsedMs < 70000);
        await assertPreserved();
        await helper.control({ action: "configure", mode: "good" });
        await client.click("#backend-refresh");
        await client.waitFor("!document.getElementById('backend-save').disabled && document.getElementById('backend-status').textContent.includes('Connected')");
        record("real 60-second body-read deadline releases controls, preserves cache and allows successful retry", { elapsedMs });
      }
      await screenshot("helper-connected");
      await client.click("#mode-portal");
      await client.fill("#portal-url", "https://example.awsapps.com/start");
      await client.click("#portal-save");
      await permission(true);
      await poll(origins, list => list.includes("https://example.awsapps.com/*"));
      assert.deepEqual(await origins(), ["https://example.awsapps.com/*"]);
      record("portal setup requests only its synthetic exact origin through Firefox's native prompt", { livePortalVerified: false });
      await client.script("document.getElementById('portal-sidebar-settings').open = true; document.getElementById('portal-region-settings').open = true;");
      await client.fill("#sso-region", "eu-west-1");
      await client.click("#role-save");
      await client.waitFor("document.getElementById('role-discovery-grant').disabled === false");
      await client.click("#role-discovery-grant");
      await permission(true);
      await poll(origins, list => list.includes("https://portal.sso.eu-west-1.amazonaws.com/*"));
      assert.deepEqual(await origins(), ["https://example.awsapps.com/*", "https://portal.sso.eu-west-1.amazonaws.com/*"]);
      await client.click("#role-discovery-revoke");
      await poll(origins, list => list.length === 1);
      assert.deepEqual(await origins(), ["https://example.awsapps.com/*"]);
      record("native role-choice permission is limited to the explicit synthetic SSO region; revoking preserves portal-origin access", { liveRoleDiscoveryVerified: false });
      await screenshot("portal-no-session");
      await client.click("#mode-backend");
      await go(optionsUrl);
      assert.equal(await client.script("return document.getElementById('backend-token').value;"), "");
      assert.equal((await getState()).backendAuthToken, helper.helperToken);
      await client.click("#backend-save");
      await client.waitFor("!document.getElementById('backend-save').disabled && document.getElementById('backend-status').textContent.includes('Connected')");
      await go(sidebarUrl);
      await client.waitFor(`document.querySelector('${key(`pin:backend:${alpha}`)}')?.getAttribute('aria-pressed') === 'true'`);
      record("portal/helper switching and Options reload preserve saved helper pairing, account cache and helper pin");
      await client.context("chrome");
      results.network.cancelledHosts = [...new Set(await client.script("return window.__containoodleOfflineGate.blocked;"))].sort();
      assert.ok(results.network.cancelledHosts.some(host => host.endsWith("signin.aws.amazon.com")), "Synthetic AWS-shaped launch must have reached and been cancelled by the network gate");
      await client.context("content");
    }
    results.network.blockedHosts = [...hosts].sort();
  } catch (error) {
    failure = error;
    console.error("FIREFOX TEST FAILURE:", error.message);
    console.error("Disposable Firefox diagnostic tail:", logs.slice(-5000));
    results.failure = error.message;
    try {
      const shot = await client?.send("WebDriver:TakeScreenshot", { full: true });
      if (shot) await writeFile(join(reportDir, "failure.png"), Buffer.from(shot.value ?? shot, "base64"));
    } catch { /* A failed/disconnected browser may not supply a screenshot. */ }
  } finally {
    if (client) {
      try { await client.send("Marionette:Quit", { flags: ["eAttemptQuit"] }, 5000); } catch { /* Our child is stopped below. */ }
      client.socket.destroy();
    }
    try { await stopChild(firefox); }
    finally {
      try { await stopChild(helper?.child); }
      finally {
        proxy.closeAllConnections();
        await new Promise(resolve => proxy.close(resolve));
      }
    }
    // Only this mkdtemp-created test directory is removed; no saved user profile.
    await rm(workspace, { recursive: true, force: true });
  }
  assert.deepEqual(await profileMetadata(), originalMetadata, "Saved Firefox profile registration metadata must remain unchanged");
  if (artifactHash) assert.equal(createHash("sha256").update(await readFile(installPath)).digest("hex"), artifactHash, "Tested XPI bytes must remain unchanged throughout the run");
  record("owned Firefox and helper stopped, disposable profile removed, saved profile registrations unchanged");
  results.automationCompleted = !failure;
  results.passed = !failure && !results.findings?.length;
  await writeFile(join(reportDir, "report.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify({ reportDir, ...results }));
  if (failure) throw failure;
  if (results.findings?.length) process.exitCode = 1;
}

await main();
