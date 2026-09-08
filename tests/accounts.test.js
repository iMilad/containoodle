import test from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { parseAccounts, safeAccountsError, validateAccounts } from "../firefox-extension/shared/accounts.js";

const VALID = JSON.stringify([
  { accountId: "0".repeat(12), accountName: "example-prod-data", role: "__CONTAINOODLE_TEST_ROLE__", region: "xx-test-1" },
  { accountId: "1".repeat(12), accountName: "example-dev-tools" },
]);

test("only known value-free account-file diagnostics are displayable", () => {
  const allowed = [
    "accounts.json not found",
    "accounts.json is invalid",
    "accounts.json could not be read",
    "accounts.json must contain an array of accounts",
    "accounts.json entry 1 must be an object",
    "accounts.json entry 2: accountId must be a 12-digit string",
    "accounts.json entry 3: accountName must be a nonempty string",
    "accounts.json entry 4: accountName is too long or contains control characters",
    "accounts.json entry 5: accountName contains invalid Unicode",
    "accounts.json entry 6: invalid role",
    "accounts.json entry 7: invalid region",
    "accounts.json entry 8: duplicate accountId",
  ];
  for (const error of allowed) assert.equal(safeAccountsError({ error }), error);
  for (const payload of [
    null, [], { error: 7 }, { error: allowed[0], extra: true },
    { error: "__CONTAINOODLE_TEST_PRIVATE_ERROR__" },
    { error: "accounts.json entry 000000000001: invalid role" },
    { error: "accounts.json entry 1: invalid role __CONTAINOODLE_TEST_ROLE__" },
    { error: "accounts.json entry 1: invalid role\n" },
    { error: "accounts.json is invalid at /synthetic/private/path" },
    { error: "accounts.json entry 0 must be an object" },
  ]) assert.equal(safeAccountsError(payload), null);
});

test("parseAccounts accepts a valid document", () => {
  const { accounts, errors } = parseAccounts(VALID);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(accounts.length, 2);
  assert.strictEqual(accounts[0].accountName, "example-prod-data");
});

test("parseAccounts rejects malformed JSON", () => {
  const { accounts, errors } = parseAccounts("[{");
  assert.strictEqual(accounts, null);
  assert.match(errors[0], /Invalid JSON/);
});

test("sparse cached arrays are rejected without mutation", () => {
  const cache = new Array(2);
  cache[1] = { accountId: "0".repeat(12), accountName: "__CONTAINOODLE_TEST_ACCOUNT__" };
  assert.deepStrictEqual(validateAccounts(cache), {
    accounts: null, errors: ["Entry 1: must be an object"],
  });
  assert.strictEqual(0 in cache, false);
  assert.strictEqual(cache.length, 2);
});

test("parseAccounts rejects non-array top level", () => {
  const { accounts, errors } = parseAccounts(JSON.stringify({ accountId: "0".repeat(12) }));
  assert.strictEqual(accounts, null);
  assert.match(errors[0], /array/);
});

test("parseAccounts reports per-entry problems", () => {
  const doc = JSON.stringify([
    { accountId: "123", accountName: "short-id" },
    { accountId: "0".repeat(12) },
    { accountId: "1".repeat(12), accountName: "bad-role", role: "__INVALID TEST ROLE__" },
    { accountId: "2".repeat(12), accountName: "bad-region", region: "invalid-region" },
    "not-an-object",
  ]);
  const { accounts, errors } = parseAccounts(doc);
  assert.strictEqual(accounts, null);
  assert.strictEqual(errors.length, 5);
  assert.match(errors[0], /12-digit/);
  assert.match(errors[1], /accountName/);
  assert.match(errors[2], /role/);
  assert.match(errors[3], /region/);
  assert.match(errors[4], /object/);
});

test("parseAccounts allows optional role and region to be absent", () => {
  const { accounts, errors } = parseAccounts(
    JSON.stringify([{ accountId: "0".repeat(12), accountName: "example-qa-x" }])
  );
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(accounts[0].role, undefined);
});

test("account validation matches shared synthetic schema fixtures", async (t) => {
  const fixtures = JSON.parse(readFileSync(new URL("./fixtures/accounts-validation.json", import.meta.url)));
  for (const entry of fixtures) {
    await t.test(entry.name, () => {
      const result = parseAccounts(JSON.stringify(entry.document));
      assert.strictEqual(result.errors.length === 0, entry.valid);
      if (entry.valid) assert.deepStrictEqual(result.accounts, entry.document);
      else assert.strictEqual(result.accounts, null);
    });
  }
});

test("account names are bounded by Unicode characters and do not leak into errors", () => {
  const account = { accountId: "0".repeat(12), accountName: "🧪".repeat(256) };
  assert.deepStrictEqual(parseAccounts(JSON.stringify([account])).errors, []);
  account.accountName += "🧪";
  const result = parseAccounts(JSON.stringify([account]));
  assert.strictEqual(result.accounts, null);
  assert.strictEqual(result.errors.some((error) => error.includes("🧪")), false);
  const malformed = parseAccounts('{"__CONTAINOODLE_PRIVATE_TEST_VALUE__": bad-json}');
  assert.deepStrictEqual(malformed.errors, ["Invalid JSON account document"]);
});
