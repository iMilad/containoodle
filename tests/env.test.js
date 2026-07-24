import test from "node:test";
import assert from "node:assert";
import { accountEnv } from "../firefox-extension/sidebar/env.js";

// [account name, expected environment]
const CASES = [
  // prod
  ["billing-prod", "prod"],
  ["EKSProd", "prod"],
  ["PRODBilling", "prod"],
  ["Production-Analytics", "prod"],
  ["DevOps-Prod", "prod"],
  // qa
  ["data-qa-eu", "qa"],
  ["MyQAAccount", "qa"],
  ["QA", "qa"],
  // dev
  ["my-dev-account", "dev"],
  ["dev1", "dev"],
  ["VPNDev", "dev"],
  ["development-tools", "dev"],
  // test / eval -> grey
  ["test-analytics", "test"],
  ["Eval2", "test"],
  ["TestingGround", "test"],
  ["eval-sandbox", "test"],
  // non/pre-prod are NOT production -> grey
  ["Payments-NonProd", "test"],
  ["nonprod", "test"],
  ["PreProd", "test"],
  ["preprod-x", "test"],
  // devops is a role, not an env; unknown -> prod (fail-safe)
  ["DevOps", "prod"],
  ["product-catalog", "prod"],
  ["shared-services", "prod"],
  ["random-account", "prod"],
  ["", "prod"],
  // precedence
  ["dev-test", "dev"],
  ["test-prod", "prod"],
];

test("accountEnv classifies every fixture correctly", () => {
  for (const [name, want] of CASES) {
    assert.strictEqual(accountEnv(name), want, `accountEnv(${JSON.stringify(name)})`);
  }
});

test("accountEnv never throws on odd input", () => {
  for (const input of [undefined, null, 12345, "—", "   "]) {
    assert.doesNotThrow(() => accountEnv(input));
  }
});
