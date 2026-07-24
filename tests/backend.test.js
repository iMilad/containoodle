import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_BACKEND_URL,
  normalizeBackendUrl,
  safeBackendUrl,
  validateBackendSigninUrl,
} from "../firefox-extension/shared/backend.js";

test("local helper URLs are restricted to explicit 127.0.0.1 ports", () => {
  assert.equal(normalizeBackendUrl("http://127.0.0.1:8421/"), DEFAULT_BACKEND_URL);
  assert.equal(normalizeBackendUrl(" http://127.0.0.1:8765 "), "http://127.0.0.1:8765");

  for (const value of [
    "http://localhost:8421",
    "http://127.0.0.1",
    "https://127.0.0.1:8421",
    "http://127.0.0.1:8421/path",
    "http://127.0.0.1:8421?next=https://example.invalid",
    "http://user@127.0.0.1:8421",
    "https://example.invalid",
  ]) {
    assert.throws(() => normalizeBackendUrl(value), /127\.0\.0\.1/);
  }
});

test("unsafe stored helper URLs fall back without making them usable", () => {
  assert.equal(safeBackendUrl("https://example.invalid"), DEFAULT_BACKEND_URL);
});

test("helper sign-in URLs must stay on the expected AWS federation endpoint", () => {
  const destination =
    "https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1";
  const valid = new URL("https://signin.aws.amazon.com/federation");
  valid.searchParams.set("Action", "login");
  valid.searchParams.set("Issuer", "");
  valid.searchParams.set("Destination", destination);
  valid.searchParams.set("SigninToken", "synthetic-test-token");

  assert.equal(validateBackendSigninUrl(valid.href), valid.href);

  const external = new URL(valid);
  external.hostname = "example.invalid";
  assert.throws(
    () => validateBackendSigninUrl(external.href),
    /unexpected sign-in destination/,
  );

  const badDestination = new URL(valid);
  badDestination.searchParams.set("Destination", "https://example.invalid/");
  assert.throws(
    () => validateBackendSigninUrl(badDestination.href),
    /unexpected sign-in destination/,
  );
});
