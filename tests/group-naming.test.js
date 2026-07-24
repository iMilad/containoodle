import test from "node:test";
import assert from "node:assert/strict";

import {
  automaticGroupTitle,
  validateGroupNameRule,
} from "../firefox-extension/shared/group-naming.js";

test("automaticGroupTitle applies captures and preserves all documented fallbacks", () => {
  assert.equal(
    automaticGroupTitle("corp-dev-payments", "^corp-(?:dev|prod)-(.+)$", "$1"),
    "payments"
  );
  assert.equal(automaticGroupTitle("corp-dev-payments", "", "$1"), "corp-dev-payments");
  assert.equal(
    automaticGroupTitle("corp-dev-payments", "^other-(.+)$", "$1"),
    "corp-dev-payments"
  );
  assert.equal(
    automaticGroupTitle("corp-dev-payments", "^.*$", ""),
    "corp-dev-payments"
  );
  assert.equal(
    automaticGroupTitle("account", "^(.+)$", "$1".repeat(100)),
    "account"
  );
});

test("name-rule validation rejects backtracking-prone regex constructs", () => {
  for (const pattern of [
    "^(a+)+$",
    "^(a|aa)+$",
    "^(?=a).+$",
    "^(a+)\\1$",
    "^(.+)-(.+)-(.+)$",
    "^(a|aa)(a|aa)(a|aa)(a|aa)(a|aa)$",
  ]) {
    assert.throws(
      () => validateGroupNameRule(pattern, "$1"),
      /Unsafe name regex/
    );
  }
});

test("name-rule validation enforces pattern, replacement, and repetition limits", () => {
  assert.throws(
    () => validateGroupNameRule("a".repeat(257), ""),
    /pattern must be at most 256/
  );
  assert.throws(
    () => validateGroupNameRule("^a$", "x".repeat(257)),
    /replacement: must be at most 256/
  );
  assert.throws(
    () => validateGroupNameRule("^a{257}$", "a"),
    /repetition bounds must not exceed 256/
  );
});

test("runtime naming safely ignores invalid or manually injected unsafe rules", () => {
  assert.equal(automaticGroupTitle("account", "([", "$1"), "account");
  assert.equal(automaticGroupTitle(`${"a".repeat(64)}!`, "^(a+)+$", "$1"), `${"a".repeat(64)}!`);
  assert.equal(automaticGroupTitle("account", "^(.+)$", "x".repeat(257)), "account");
});
