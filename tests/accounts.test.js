import test from "node:test";
import assert from "node:assert";
import { parseAccounts } from "../firefox-extension/shared/accounts.js";

const VALID = JSON.stringify([
  { accountId: "123456789012", accountName: "prod-data", role: "AdministratorAccess", region: "eu-west-1" },
  { accountId: "210987654321", accountName: "dev-tools" },
]);

test("parseAccounts accepts a valid document", () => {
  const { accounts, errors } = parseAccounts(VALID);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(accounts.length, 2);
  assert.strictEqual(accounts[0].accountName, "prod-data");
});

test("parseAccounts rejects malformed JSON", () => {
  const { accounts, errors } = parseAccounts("[{");
  assert.strictEqual(accounts, null);
  assert.match(errors[0], /Invalid JSON/);
});

test("parseAccounts rejects non-array top level", () => {
  const { accounts, errors } = parseAccounts('{"accountId": "123456789012"}');
  assert.strictEqual(accounts, null);
  assert.match(errors[0], /array/);
});

test("parseAccounts reports per-entry problems", () => {
  const doc = JSON.stringify([
    { accountId: "123", accountName: "short-id" },
    { accountId: "123456789012" },
    { accountId: "123456789012", accountName: "bad-role", role: "no spaces allowed" },
    { accountId: "123456789012", accountName: "bad-region", region: "narnia" },
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
    JSON.stringify([{ accountId: "999999999999", accountName: "qa-x" }])
  );
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(accounts[0].role, undefined);
});
