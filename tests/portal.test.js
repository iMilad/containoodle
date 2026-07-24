import test from "node:test";
import assert from "node:assert";
import {
  normalizeStartUrl,
  consoleDeepLink,
  portalCookieUrl,
  portalOriginPattern,
  whoAmIUrl,
  portalApiBase,
  unwrapResult,
  findAccountInstance,
  isConfiguredPortalPage,
  canRemovePortalShortcutTab,
  parsePortalConsoleDeepLink,
  planPortalTabHandoff,
} from "../firefox-extension/shared/portal.js";

const START = "https://d-0000000000.awsapps.com/start";

test("normalizeStartUrl accepts common input shapes", () => {
  const cases = [
    ["https://d-0000000000.awsapps.com/start", START],
    ["https://d-0000000000.awsapps.com/start/", START],
    ["https://d-0000000000.awsapps.com/start///", START],
    ["d-0000000000.awsapps.com/start", START],
    ["  d-0000000000.awsapps.com/start  ", START],
    ["d-0000000000.awsapps.com", START],
    ["https://d-0000000000.awsapps.com", START],
  ];
  for (const [input, want] of cases) {
    assert.strictEqual(normalizeStartUrl(input), want, `normalizeStartUrl(${JSON.stringify(input)})`);
  }
});

test("normalizeStartUrl rejects bad input", () => {
  assert.throws(() => normalizeStartUrl(""), /empty/);
  assert.throws(() => normalizeStartUrl("   "), /empty/);
  assert.throws(() => normalizeStartUrl(undefined), /empty/);
  assert.throws(() => normalizeStartUrl("http://d-0000000000.awsapps.com/start"), /https/);
  assert.throws(() => normalizeStartUrl("https://"), /valid URL/);
  assert.throws(() => normalizeStartUrl("https://example.com/start"), /awsapps/);
  assert.throws(
    () => normalizeStartUrl("https://user@d-0000000000.awsapps.com/start"),
    /credentials/
  );
  assert.throws(
    () => normalizeStartUrl("https://d-0000000000.awsapps.com:8443/start"),
    /awsapps/
  );
});

test("consoleDeepLink builds and encodes the federation link", () => {
  assert.strictEqual(
    consoleDeepLink(START, "123456789012", "ReadOnlyAccess"),
    `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`
  );
  // Role names may contain +=,.@- which must survive encoding
  const link = consoleDeepLink(START, "123456789012", "My+Role=x,y.z@corp-1");
  assert.ok(link.includes("role_name=My%2BRole%3Dx%2Cy.z%40corp-1"), link);
});

test("parsePortalConsoleDeepLink recognizes and preserves a portal shortcut", () => {
  const url =
    `${START}/#/console?account_id=123456789012` +
    `&role_name=ReadOnlyAccess` +
    `&destination=${encodeURIComponent("https://console.aws.amazon.com/s3/home")}`;
  assert.deepStrictEqual(parsePortalConsoleDeepLink(url, START), {
    accountId: "123456789012",
    roleName: "ReadOnlyAccess",
    url,
  });
});

test("parsePortalConsoleDeepLink decodes valid roles and tolerates extra parameters", () => {
  const url =
    `${START}/#/console/?destination=x` +
    `&role_name=My%2BRole%3Dx%2Cy.z%40corp-1` +
    `&account_id=123456789012&future=value`;
  const parsed = parsePortalConsoleDeepLink(url, `${START}/`);
  assert.strictEqual(parsed.accountId, "123456789012");
  assert.strictEqual(parsed.roleName, "My+Role=x,y.z@corp-1");
  assert.strictEqual(parsed.url, url);
});

test("parsePortalConsoleDeepLink rejects other origins, paths, and routes", () => {
  const query = "account_id=123456789012&role_name=ReadOnlyAccess";
  const rejected = [
    `https://d-1111111111.awsapps.com/start/#/console?${query}`,
    `https://user@d-0000000000.awsapps.com/start/#/console?${query}`,
    `https://d-0000000000.awsapps.com/other/#/console?${query}`,
    `${START}/#/accounts?${query}`,
    `${START}/#/console-extra?${query}`,
    `${START}/?${query}`,
    "not a url",
  ];
  for (const url of rejected) {
    assert.strictEqual(parsePortalConsoleDeepLink(url, START), null, url);
  }
});

test("parsePortalConsoleDeepLink rejects missing, duplicate, or invalid identity fields", () => {
  const rejected = [
    `${START}/#/console?role_name=ReadOnlyAccess`,
    `${START}/#/console?account_id=123456789012`,
    `${START}/#/console?account_id=123&role_name=ReadOnlyAccess`,
    `${START}/#/console?account_id=123456789012&account_id=210987654321&role_name=ReadOnlyAccess`,
    `${START}/#/console?account_id=123456789012&role_name=One&role_name=Two`,
    `${START}/#/console?account_id=123456789012&role_name=unescaped+space`,
  ];
  for (const url of rejected) {
    assert.strictEqual(parsePortalConsoleDeepLink(url, START), null, url);
  }
});

test("isConfiguredPortalPage accepts only the configured AWS portal page", () => {
  assert.strictEqual(isConfiguredPortalPage(`${START}/#/`, START), true);
  assert.strictEqual(isConfiguredPortalPage(`${START}/#/accounts`, `${START}/`), true);
  assert.strictEqual(
    isConfiguredPortalPage("https://d-1111111111.awsapps.com/start/#/", START),
    false
  );
  assert.strictEqual(
    isConfiguredPortalPage("https://d-0000000000.awsapps.com/other/#/", START),
    false
  );
  assert.strictEqual(
    isConfiguredPortalPage("https://user@d-0000000000.awsapps.com/start/#/", START),
    false
  );
});

test("only a default-store child with the configured portal as opener is disposable", () => {
  const child = {
    id: 42,
    openerTabId: 41,
    cookieStoreId: "firefox-default",
  };
  const portalOpener = {
    id: 41,
    url: `${START}/#/accounts`,
    cookieStoreId: "firefox-default",
  };
  assert.strictEqual(canRemovePortalShortcutTab(child, portalOpener, START), true);

  assert.strictEqual(
    canRemovePortalShortcutTab({ ...child, pinned: true }, portalOpener, START),
    false
  );

  // A newly opened main portal tab has no proven opener and must be retained.
  assert.strictEqual(
    canRemovePortalShortcutTab({ ...child, openerTabId: undefined }, null, START),
    false
  );
  // An old tab can have an unrelated historical opener; that is not proof.
  assert.strictEqual(
    canRemovePortalShortcutTab(
      child,
      { ...portalOpener, url: "https://example.com/" },
      START
    ),
    false
  );
  assert.strictEqual(
    canRemovePortalShortcutTab(
      child,
      { ...portalOpener, cookieStoreId: "firefox-container-1" },
      START
    ),
    false
  );
});

test("planPortalTabHandoff maps a portal launch to its cached account", () => {
  const sourceUrl = `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`;
  const plan = planPortalTabHandoff({
    mode: "portal",
    portalStartUrl: START,
    accounts: [{ accountId: "123456789012", accountName: "prod-data" }],
    tab: {
      id: 42,
      url: sourceUrl,
      cookieStoreId: "firefox-default",
      windowId: 7,
      index: 3,
      openerTabId: 41,
    },
  });
  assert.strictEqual(plan.kind, "handoff");
  assert.strictEqual(plan.account.accountName, "prod-data");
  assert.strictEqual(plan.roleName, "ReadOnlyAccess");
  assert.strictEqual(plan.windowId, 7);
  assert.strictEqual(plan.openerTabId, 41);
});

test("planPortalTabHandoff works without an accounts list using an ID container", () => {
  const plan = planPortalTabHandoff({
    mode: "portal",
    portalStartUrl: START,
    accounts: [],
    tab: {
      id: 42,
      url: `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`,
      cookieStoreId: "firefox-default",
    },
  });
  assert.strictEqual(plan.kind, "handoff");
  assert.deepStrictEqual(plan.account, {
    accountId: "123456789012",
    accountName: "AWS 123456789012",
  });
});

test("planPortalTabHandoff avoids duplicate friendly-name container collisions", () => {
  const plan = planPortalTabHandoff({
    mode: "portal",
    portalStartUrl: START,
    accounts: [
      { accountId: "123456789012", accountName: "prod" },
      { accountId: "210987654321", accountName: "prod" },
    ],
    tab: {
      id: 42,
      url: `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`,
      cookieStoreId: "firefox-default",
    },
  });
  assert.strictEqual(plan.kind, "handoff");
  assert.deepStrictEqual(plan.account, {
    accountId: "123456789012",
    accountName: "AWS 123456789012",
  });
});

test("planPortalTabHandoff preserves the cached account name exactly", () => {
  const plan = planPortalTabHandoff({
    mode: "portal",
    portalStartUrl: START,
    accounts: [{ accountId: "123456789012", accountName: " prod-data " }],
    tab: {
      id: 42,
      url: `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`,
      cookieStoreId: "firefox-default",
    },
  });
  assert.strictEqual(plan.account.accountName, " prod-data ");
});

test("planPortalTabHandoff rejects malformed clicked account names", () => {
  const tab = {
    id: 42,
    url: `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`,
    cookieStoreId: "firefox-default",
  };
  for (const portalAccountName of [
    "   ",
    "wrong\naccount",
    "x".repeat(257),
    123,
    { name: "forged" },
  ]) {
    const plan = planPortalTabHandoff({
      mode: "portal",
      portalStartUrl: START,
      accounts: [{ accountId: "123456789012", accountName: "prod-data" }],
      portalAccountName,
      tab,
    });
    assert.strictEqual(plan.kind, "handoff");
    assert.strictEqual(plan.account.accountId, "123456789012");
    assert.strictEqual(plan.account.accountName, "prod-data");
  }

  const withoutCache = planPortalTabHandoff({
    mode: "portal",
    portalStartUrl: START,
    accounts: [],
    portalAccountName: "bad\tname",
    tab,
  });
  assert.strictEqual(withoutCache.account.accountId, "123456789012");
  assert.strictEqual(withoutCache.account.accountName, "AWS 123456789012");
});

test("planPortalTabHandoff ignores backend, private, and every non-default store", () => {
  const tab = {
    id: 42,
    url: `${START}/#/console?account_id=123456789012&role_name=ReadOnlyAccess`,
    cookieStoreId: "firefox-default",
  };
  assert.strictEqual(
    planPortalTabHandoff({ mode: "backend", portalStartUrl: START, tab }).reason,
    "mode"
  );
  assert.strictEqual(
    planPortalTabHandoff({
      mode: "portal",
      portalStartUrl: START,
      tab: { ...tab, incognito: true },
    }).reason,
    "private-store"
  );
  assert.strictEqual(
    planPortalTabHandoff({
      mode: "portal",
      portalStartUrl: START,
      tab: { ...tab, cookieStoreId: "firefox-container-1" },
    }).reason,
    "store"
  );
  for (const cookieStoreId of [undefined, "firefox-private", "unknown-store"]) {
    assert.strictEqual(
      planPortalTabHandoff({
        mode: "portal",
        portalStartUrl: START,
        tab: { ...tab, cookieStoreId },
      }).reason,
      "store"
    );
  }
});

test("portalCookieUrl matches the portal session cookie scope", () => {
  assert.strictEqual(portalCookieUrl(START), `${START}/`);
  assert.strictEqual(portalCookieUrl("d-0000000000.awsapps.com"), `${START}/`);
});

test("portalOriginPattern is a valid host match pattern", () => {
  assert.strictEqual(
    portalOriginPattern(START),
    "https://d-0000000000.awsapps.com/*"
  );
});

test("whoAmIUrl targets the portal origin, not the /start path", () => {
  assert.strictEqual(whoAmIUrl(START), "https://d-0000000000.awsapps.com/token/whoAmI");
  assert.strictEqual(whoAmIUrl("d-0000000000.awsapps.com"), "https://d-0000000000.awsapps.com/token/whoAmI");
});

test("portalApiBase builds the regional API host and rejects junk", () => {
  assert.strictEqual(portalApiBase("eu-west-1"), "https://portal.sso.eu-west-1.amazonaws.com");
  assert.throws(() => portalApiBase("narnia"), /Invalid SSO region/);
  assert.throws(() => portalApiBase("evil.example.com/"), /Invalid SSO region/);
});

test("unwrapResult tolerates both raw arrays and {result:[...]}", () => {
  assert.deepStrictEqual(unwrapResult([1, 2]), [1, 2]);
  assert.deepStrictEqual(unwrapResult({ result: [3] }), [3]);
  assert.deepStrictEqual(unwrapResult({ nope: true }), []);
  assert.deepStrictEqual(unwrapResult(null), []);
});

test("findAccountInstance matches on searchMetadata.AccountId", () => {
  const instances = [
    { id: "ins-1", searchMetadata: { AccountId: "111111111111" } },
    { id: "ins-2", searchMetadata: { AccountId: "222222222222" } },
    { id: "ins-broken" },
  ];
  assert.strictEqual(findAccountInstance(instances, "222222222222").id, "ins-2");
  assert.strictEqual(findAccountInstance(instances, "999999999999"), undefined);
});
