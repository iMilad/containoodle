import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { syncAmoPrivacy, ADDON_GUID } from "../scripts/sync-amo-privacy.mjs";

const policy = "Synthetic Containoodle privacy policy. ".repeat(5);
const issuer = "__CONTAINOODLE_TEST_ISSUER__";
const secret = "__CONTAINOODLE_TEST_SECRET_NOT_REAL__";
const response = body => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });

test("AMO policy sync authenticates only the exact listing and PATCHes only its privacy text", async () => {
  const calls = [];
  let counter = 0;
  const result = await syncAmoPrivacy({ policy, issuer, secret, now: () => 1800000000000,
    nonce: () => "synthetic-" + ++counter, fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return response(options.method === "GET" ? { guid: ADDON_GUID, slug: "containoodle" } : { privacy_policy: { "en-US": policy } });
    } });
  assert.deepEqual(result, { updated: true });
  assert.deepEqual(calls.map(c => [c.url, c.options.method]), [
    ["https://addons.mozilla.org/api/v5/addons/addon/3046053/", "GET"],
    ["https://addons.mozilla.org/api/v5/addons/addon/3046053/eula_policy/", "PATCH"],
  ]);
  assert.deepEqual(JSON.parse(calls[1].options.body), { privacy_policy: { "en-US": policy } });
  for (const { options } of calls) {
    assert.equal(options.redirect, "error");
    assert.ok(options.signal instanceof AbortSignal);
    const [header, payload, signature] = options.headers.Authorization.slice(4).split(".");
    assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "HS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(payload, "base64url"));
    assert.equal(claims.iss, issuer);
    assert.equal(claims.exp - claims.iat, 60);
    assert.equal(signature, createHmac("sha256", secret).update(header + "." + payload).digest("base64url"));
  }
  assert.notEqual(calls[0].options.headers.Authorization, calls[1].options.headers.Authorization);
});

test("AMO policy sync fails before writing to an unexpected add-on", async () => {
  let calls = 0;
  await assert.rejects(syncAmoPrivacy({ policy, issuer, secret, fetchImpl: async () => {
    calls++;
    return response({ guid: "synthetic-other-guid", slug: "other-addon" });
  } }), /target does not match/);
  assert.equal(calls, 1);
});

test("AMO policy sync never echoes network/credential data and requires confirmation", async () => {
  for (const fetchImpl of [
    async () => { throw new Error(secret); },
    async () => new Response(secret, { status: 403 }),
    async (_url, options) => response(options.method === "GET" ? { guid: ADDON_GUID, slug: "containoodle" } : {}),
  ]) {
    await assert.rejects(syncAmoPrivacy({ policy, issuer, secret, fetchImpl }), error =>
      !error.message.includes(secret) && /failed|confirm/.test(error.message));
  }
});

test("invalid policy or missing signing configuration never contacts AMO", async () => {
  for (const values of [{ policy: "" }, { issuer: "" }, { secret: "" }]) {
    await assert.rejects(syncAmoPrivacy({ policy, issuer, secret, ...values,
      fetchImpl: () => assert.fail("Must not contact AMO") }), /requires/);
  }
});
