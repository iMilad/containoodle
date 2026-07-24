import test from "node:test";
import assert from "node:assert";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const SOURCE = readFileSync(
  new URL("../firefox-extension/portal-interceptor.js", import.meta.url),
  "utf8"
);
const START = "https://d-0000000000.awsapps.com/start";
const SHORTCUT = `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`;
const SECOND_SHORTCUT = `${START}/#/console?account_id=210987654321&role_name=AdministratorAccess`;

function makeEvent(anchor, composedPath = [anchor]) {
  return {
    isTrusted: true,
    defaultPrevented: false,
    button: 0,
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    prevented: false,
    stopped: false,
    composedPath: () => composedPath,
    preventDefault() {
      this.prevented = true;
    },
    stopImmediatePropagation() {
      this.stopped = true;
    },
  };
}

function makeAnchor(target = "", href = SHORTCUT) {
  return {
    tagName: "A",
    href,
    hasAttribute: () => false,
    getAttribute: (name) => (name === "target" ? target : null),
    closest: () => null,
  };
}

function makePortalRoleClick(accountName, target = "", href = SHORTCUT) {
  const anchor = makeAnchor(target, href);
  const accountCell = {
    tagName: "DIV",
    dataset: { testid: "account-list-cell" },
    innerText: accountName,
    textContent: accountName,
  };
  const accountRow = {
    tagName: "TR",
    dataset: {},
    previousElementSibling: null,
    querySelector(selector) {
      return selector.includes("account-list-cell") ? accountCell : null;
    },
  };
  const unrelatedRow = {
    tagName: "TR",
    dataset: {},
    previousElementSibling: accountRow,
    querySelector: () => null,
  };
  const roleRow = {
    tagName: "TR",
    dataset: { selectionItem: "item" },
    previousElementSibling: unrelatedRow,
    querySelector: () => null,
  };
  anchor.closest = (selector) => selector.includes("tr") ? roleRow : null;

  return {
    anchor,
    composedPath: [anchor, roleRow],
  };
}

async function makeFixture(shortcutResponse) {
  const windowListeners = {};
  const runtimeListeners = [];
  const shortcutMessages = [];
  const assigned = [];
  const opened = [];
  let enabled = true;
  let response = shortcutResponse;

  const context = {
    URL,
    URLSearchParams,
    location: {
      href: `${START}/#/accounts`,
      origin: new URL(START).origin,
      pathname: "/start/",
      assign(url) {
        assigned.push(url);
      },
    },
    window: {
      addEventListener(type, listener) {
        windowListeners[type] = listener;
      },
      open(url, target, features) {
        opened.push({ url, target, features });
        return {};
      },
    },
    browser: {
      runtime: {
        async sendMessage(message) {
          if (message.type === "portal-interceptor-state") return { enabled };
          shortcutMessages.push(message);
          return typeof response === "function" ? response(message) : response;
        },
        onMessage: {
          addListener(listener) {
            runtimeListeners.push(listener);
          },
        },
      },
      storage: {
        onChanged: { addListener() {} },
      },
    },
  };
  vm.runInNewContext(SOURCE, context);
  await new Promise((resolve) => setTimeout(resolve, 0));

  return {
    assigned,
    opened,
    runtimeListeners,
    shortcutMessages,
    windowListeners,
    setEnabled(value) {
      enabled = value;
    },
    setResponse(value) {
      response = value;
    },
  };
}

test("target=_blank failure uses the background-created native fallback", async () => {
  const fixture = await makeFixture({ ok: false, nativeFallback: true });
  const event = makeEvent(makeAnchor("_blank"));
  fixture.windowListeners.click(event);
  await Promise.resolve();

  assert.strictEqual(event.prevented, true);
  assert.strictEqual(event.stopped, true);
  assert.strictEqual(fixture.shortcutMessages.length, 1);
  assert.strictEqual(fixture.shortcutMessages[0].disposition, "new-tab");
  assert.deepStrictEqual(fixture.assigned, []);
});

test("a mode-cancelled handoff does not resume native portal navigation", async () => {
  const fixture = await makeFixture({ ok: false, cancelled: true });
  const event = makeEvent(makeAnchor("_self"));
  fixture.windowListeners.click(event);
  await Promise.resolve();

  assert.strictEqual(event.prevented, true);
  assert.deepStrictEqual(fixture.assigned, []);
  assert.deepStrictEqual(fixture.opened, []);
});

test("same-tab failure resumes the original shortcut in the portal tab", async () => {
  const fixture = await makeFixture({ ok: false });
  const event = makeEvent(makeAnchor("_self"));
  fixture.windowListeners.click(event);
  await Promise.resolve();

  assert.strictEqual(fixture.shortcutMessages[0].disposition, "same-tab");
  assert.deepStrictEqual(fixture.assigned, [SHORTCUT]);
});

test("a rejected new-tab handoff preserves the portal and resumes in a new tab", async () => {
  const fixture = await makeFixture(() => Promise.reject(new Error("background unavailable")));
  const event = makeEvent(makeAnchor("_blank"));
  fixture.windowListeners.click(event);
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.deepStrictEqual(fixture.assigned, []);
  assert.deepStrictEqual(fixture.opened, [
    { url: SHORTCUT, target: "_blank", features: "noopener" },
  ]);
});

test("portal handoff includes the original account name from the clicked role rows", async () => {
  const fixture = await makeFixture({ ok: true });
  const click = makePortalRoleClick("  Finance.Prod-0007  ", "_blank");
  const event = makeEvent(click.anchor, click.composedPath);

  fixture.windowListeners.click(event);
  await Promise.resolve();

  assert.strictEqual(event.prevented, true);
  assert.strictEqual(fixture.shortcutMessages.length, 1);
  assert.strictEqual(
    fixture.shortcutMessages[0].accountName,
    "Finance.Prod-0007"
  );
});

test("an invalid nearest account cell never falls through to a previous account", async () => {
  const fixture = await makeFixture({ ok: true });
  const anchor = makeAnchor("_blank");
  const previousCell = {
    innerText: "previous-account",
    textContent: "previous-account",
  };
  const previousAccountRow = {
    previousElementSibling: null,
    querySelector: () => previousCell,
  };
  const invalidCell = {
    innerText: "wrong\naccount",
    textContent: "wrong\naccount",
  };
  const nearestAccountRow = {
    previousElementSibling: previousAccountRow,
    querySelector: () => invalidCell,
  };
  const roleRow = {
    previousElementSibling: nearestAccountRow,
    querySelector: () => null,
  };
  anchor.closest = () => roleRow;

  fixture.windowListeners.click(makeEvent(anchor, [anchor, roleRow]));
  await Promise.resolve();

  assert.strictEqual(fixture.shortcutMessages.length, 1);
  assert.strictEqual(fixture.shortcutMessages[0].accountName, undefined);
});

test("portal handoff safely omits the account name when its row cannot be found", async () => {
  const fixture = await makeFixture({ ok: true });
  const anchor = makeAnchor("_blank");
  const event = makeEvent(anchor);

  fixture.windowListeners.click(event);
  await Promise.resolve();

  assert.strictEqual(event.prevented, true);
  assert.strictEqual(event.stopped, true);
  assert.strictEqual(fixture.shortcutMessages.length, 1);
  assert.strictEqual(fixture.shortcutMessages[0].accountName, undefined);
});

test("the interceptor serializes rapid clicks and disables after permission refresh", async () => {
  let resolveHandoff;
  const pending = new Promise((resolve) => {
    resolveHandoff = resolve;
  });
  const fixture = await makeFixture(() => pending);
  const first = makeEvent(makeAnchor("_blank"));
  const second = makeEvent(makeAnchor("_blank"));
  fixture.windowListeners.click(first);
  fixture.windowListeners.click(second);
  assert.strictEqual(fixture.shortcutMessages.length, 1);
  assert.strictEqual(second.prevented, true);

  resolveHandoff({ ok: true });
  await new Promise((resolve) => setTimeout(resolve, 0));
  fixture.setEnabled(false);
  fixture.runtimeListeners[0]({ type: "portal-interceptor-refresh" });
  await new Promise((resolve) => setTimeout(resolve, 0));

  const afterRevoke = makeEvent(makeAnchor("_blank"));
  fixture.windowListeners.click(afterRevoke);
  assert.strictEqual(afterRevoke.prevented, false);
  assert.strictEqual(fixture.shortcutMessages.length, 1);
});

test("a distinct rapid click is queued rather than discarded", async () => {
  let resolveFirst;
  const firstResponse = new Promise((resolve) => {
    resolveFirst = resolve;
  });
  const fixture = await makeFixture(() => firstResponse);
  const first = makeEvent(makeAnchor("_blank", SHORTCUT));
  const second = makeEvent(makeAnchor("_blank", SECOND_SHORTCUT));

  fixture.windowListeners.click(first);
  fixture.windowListeners.click(second);
  assert.strictEqual(fixture.shortcutMessages.length, 1);
  assert.strictEqual(second.prevented, true);

  fixture.setResponse({ ok: true });
  resolveFirst({ ok: true });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.strictEqual(fixture.shortcutMessages.length, 2);
  assert.strictEqual(fixture.shortcutMessages[1].url, SECOND_SHORTCUT);
});

test("the same shortcut with a different target disposition is not deduplicated", async () => {
  let resolveFirst;
  const firstResponse = new Promise((resolve) => {
    resolveFirst = resolve;
  });
  const fixture = await makeFixture(() => firstResponse);

  fixture.windowListeners.click(makeEvent(makeAnchor("_blank", SHORTCUT)));
  fixture.windowListeners.click(makeEvent(makeAnchor("_self", SHORTCUT)));
  assert.strictEqual(fixture.shortcutMessages.length, 1);

  fixture.setResponse({ ok: true });
  resolveFirst({ ok: true });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.strictEqual(fixture.shortcutMessages.length, 2);
  assert.strictEqual(fixture.shortcutMessages[1].disposition, "same-tab");
});
