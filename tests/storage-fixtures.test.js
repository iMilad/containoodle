import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { parseAccounts } from "../firefox-extension/shared/accounts.js";
import { validateGroupNameRule } from "../firefox-extension/shared/group-naming.js";

const FIXTURE_NAMES = [
  "portal-v1.0.3.json",
  "backend-v1.0.3.json",
];
const CONFIG_KEYS = [
  "backendUrl",
  "groupNamePattern",
  "groupNameReplacement",
  "mode",
  "portalStartUrl",
  "ssoRegion",
];
const SHARED_ACCOUNT_ID = "123456789012";
const PORTAL_ONLY_ACCOUNT_ID = "210987654321";
const HELPER_ONLY_ACCOUNT_ID = "345678901234";
const EXPECTED_BACKEND_ROLES = {
  [SHARED_ACCOUNT_ID]: "BackendOnlyRole",
  [HELPER_ONLY_ACCOUNT_ID]: "DeveloperAccess",
};
const EXPECTED_PORTAL_ROLES = {
  [SHARED_ACCOUNT_ID]: "ReadOnlyAccess",
  [PORTAL_ONLY_ACCOUNT_ID]: "AuditAccess",
};
const SESSION_MATERIAL_RE = new RegExp([
  "access[_-]?token",
  "refresh[_-]?token",
  "id[_-]?token",
  "signin[_-]?token",
  "session[_-]?(?:id|key|token)",
  "access[_-]?key(?:[_-]?id)?",
  "secret[_-]?(?:access[_-]?)?key",
  "client[_-]?secret",
  "authorization",
  "credential",
  "private[_-]?key",
  "x-amz-sso_authn",
  "BEGIN [A-Z ]*PRIVATE KEY",
  "signin\\.aws\\.amazon\\.com/federation",
  "[?&]Action=login",
].join("|"), "i");

function readFixture(name) {
  return JSON.parse(readFileSync(
    new URL(`./fixtures/storage/${name}`, import.meta.url),
    "utf8",
  ));
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function accountById(accounts, accountId) {
  return accounts.find((account) => account.accountId === accountId);
}

function namespaceIds(fixture, prefix) {
  return Object.keys(fixture)
    .filter((key) => key.startsWith(prefix))
    .map((key) => key.slice(prefix.length))
    .sort();
}

test("v1.0.3 storage fixtures enforce the upgrade contract", () => {
  const fixtures = Object.fromEntries(
    FIXTURE_NAMES.map((name) => [name, readFixture(name)]),
  );

  for (const [name, fixture] of Object.entries(fixtures)) {
    assert.deepStrictEqual(
      Object.keys(fixture.config).sort(),
      CONFIG_KEYS,
      `${name} must contain the complete six-field config`,
    );
    assert.strictEqual(fixture.config.backendUrl, "http://127.0.0.1:8421");
    assert.strictEqual(
      fixture.config.portalStartUrl,
      "https://d-0000000000.awsapps.com/start",
    );
    assert.strictEqual(fixture.config.ssoRegion, "eu-west-1");
    assert.deepStrictEqual(
      validateGroupNameRule(
        fixture.config.groupNamePattern,
        fixture.config.groupNameReplacement,
      ),
      {
        pattern: fixture.config.groupNamePattern,
        replacement: fixture.config.groupNameReplacement,
      },
    );

    for (const accountList of [fixture.accountsCache, fixture.portalPinnedAccounts]) {
      const { accounts, errors } = parseAccounts(JSON.stringify(accountList));
      assert.deepStrictEqual(errors, [], `${name} contains invalid account data`);
      assert.deepStrictEqual(accounts, accountList);
    }

    const backendAccountIds = fixture.accountsCache
      .map((account) => account.accountId)
      .sort();
    const portalAccountIds = fixture.portalPinnedAccounts
      .map((account) => account.accountId)
      .sort();
    assert.deepStrictEqual(
      backendAccountIds,
      [SHARED_ACCOUNT_ID, HELPER_ONLY_ACCOUNT_ID].sort(),
    );
    assert.deepStrictEqual(
      portalAccountIds,
      [SHARED_ACCOUNT_ID, PORTAL_ONLY_ACCOUNT_ID].sort(),
    );
    assert.strictEqual(fixture.accountsCacheSource, "backend");
    assert.strictEqual(fixture.accountsCacheAt, 1767225600000);
    assert.deepStrictEqual([...fixture.backendPinnedAccountIds].sort(), backendAccountIds);
    assert.strictEqual(fixture.portalRegionCache, fixture.config.ssoRegion);
    assert.deepStrictEqual(
      namespaceIds(fixture, "backendRoleChoice/"),
      backendAccountIds,
    );
    assert.deepStrictEqual(
      namespaceIds(fixture, "portalRoleChoice/"),
      portalAccountIds,
    );
    assert.deepStrictEqual(
      namespaceIds(fixture, "portalAccountOriginalName/"),
      portalAccountIds,
    );

    for (const [accountId, role] of Object.entries(EXPECTED_BACKEND_ROLES)) {
      assert.strictEqual(fixture[`backendRoleChoice/${accountId}`], role);
    }
    for (const [accountId, role] of Object.entries(EXPECTED_PORTAL_ROLES)) {
      const account = accountById(fixture.portalPinnedAccounts, accountId);
      assert.strictEqual(fixture[`portalRoleChoice/${accountId}`], role);
      assert.strictEqual(account.role, role);
      assert.strictEqual(
        fixture[`portalAccountOriginalName/${accountId}`],
        account.accountName,
      );
    }

    const accountIds = new Set([
      ...fixture.accountsCache.map((account) => account.accountId),
      ...fixture.portalPinnedAccounts.map((account) => account.accountId),
    ]);
    assert.deepStrictEqual(
      [...accountIds].sort(),
      [SHARED_ACCOUNT_ID, PORTAL_ONLY_ACCOUNT_ID, HELPER_ONLY_ACCOUNT_ID].sort(),
    );
    assert.strictEqual(
      namespaceIds(fixture, "accountContainer/").length,
      accountIds.size,
      `${name} contains an extra forward container mapping`,
    );
    assert.strictEqual(
      namespaceIds(fixture, "containerAccount/").length,
      accountIds.size,
      `${name} contains an extra reverse container mapping`,
    );
    const mappedStoreIds = new Set();
    for (const accountId of accountIds) {
      const storeId = fixture[`accountContainer/${accountId}`];
      assert.ok(storeId, `${name} lacks a container mapping for ${accountId}`);
      mappedStoreIds.add(storeId);
      assert.strictEqual(fixture[`containerAccount/${storeId}`], accountId);
    }
    assert.strictEqual(
      mappedStoreIds.size,
      accountIds.size,
      `${name} container mappings must be one-to-one`,
    );
    for (const storeId of namespaceIds(fixture, "containerAccount/")) {
      const accountId = fixture[`containerAccount/${storeId}`];
      assert.ok(accountIds.has(accountId), `${name} has an orphan reverse mapping`);
      assert.strictEqual(fixture[`accountContainer/${accountId}`], storeId);
    }

    assert.strictEqual(fixture["tabGroupTitle/123456789012"], "Payments - manual");
    assert.strictEqual(fixture["migration/groupTitlesAutomaticV1"], true);
    assert.strictEqual(fixture["roleChoice/123456789012"], "LegacySharedRole");
    assert.ok(
      Object.entries(fixture).some(
        ([key, value]) => key.startsWith("tabGroups/") && Number.isInteger(value),
      ),
      `${name} must include transient group IDs`,
    );
    assert.doesNotMatch(
      JSON.stringify(fixture),
      SESSION_MATERIAL_RE,
      `${name} must not contain common session or credential markers`,
    );
  }

  const portal = fixtures["portal-v1.0.3.json"];
  const backend = fixtures["backend-v1.0.3.json"];
  assert.strictEqual(portal.config.mode, "portal");
  assert.strictEqual(backend.config.mode, "backend");
  assert.notStrictEqual(
    accountById(portal.portalPinnedAccounts, SHARED_ACCOUNT_ID).accountName,
    accountById(backend.accountsCache, SHARED_ACCOUNT_ID).accountName,
  );
  assert.notStrictEqual(
    portal[`portalRoleChoice/${SHARED_ACCOUNT_ID}`],
    backend[`backendRoleChoice/${SHARED_ACCOUNT_ID}`],
  );

  const normalizedPortal = structuredClone(portal);
  const normalizedBackend = structuredClone(backend);
  normalizedPortal.config.mode = "normalized";
  normalizedBackend.config.mode = "normalized";
  assert.deepStrictEqual(
    canonicalize(normalizedPortal),
    canonicalize(normalizedBackend),
    "portal and backend fixtures must differ only by config.mode",
  );
});
