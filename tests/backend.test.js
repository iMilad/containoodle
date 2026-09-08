import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import test from "node:test";

import {
  BACKEND_AUTH_TOKEN_KEY,
  BACKEND_SSO_IDENTITY_KEY,
  BACKEND_SSO_PROFILE_KEY,
  BACKEND_REQUEST_TIMEOUT_MS,
  DEFAULT_BACKEND_URL,
  backendFetch,
  isBackendAuthenticationError,
  isBackendTimeoutError,
  normalizeBackendSsoIdentityKey,
  normalizeBackendSsoProfile,
  normalizeBackendUrl,
  normalizeBackendToken,
  safeBackendUrl,
  validateBackendSigninUrl,
} from "../firefox-extension/shared/backend.js";

const TEST_ACCOUNT_ID = "0".repeat(12);
const TEST_ROLE = "__CONTAINOODLE_TEST_ROLE__";
const TEST_PROFILE = "__CONTAINOODLE_TEST_PROFILE__";
const TEST_IDENTITY_KEY = "0".repeat(64);

function testBase64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const TEST_TOKEN = testBase64Url(Uint8Array.from([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
]));
const TEST_OTHER_TOKEN = testBase64Url(Uint8Array.from([
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
]));
const TEST_URLSAFE_TOKEN = testBase64Url(Uint8Array.from([
  0x0b, 0x30, 0x55, 0x7a, 0x9f, 0xc4, 0xe9, 0x0e,
  0x33, 0x58, 0x7d, 0xa2, 0xc7, 0xec, 0x11, 0x36,
  0x5b, 0x80, 0xa5, 0xca, 0xef, 0x14, 0x39, 0x5e,
  0x83, 0xa8, 0xcd, 0xf2, 0x17, 0x3c, 0x61, 0x86,
]));
const TEST_CHALLENGE = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
const TEST_NOW = 2_000_000_000_000;
const TEST_EXPIRES_AT = TEST_NOW + 30_000;
const TEST_HOST = "127.0.0.1:8421";
const TEST_ORIGIN = "moz-extension://containoodle-test-origin";
const TEST_TARGET = (
  `/generate-url?account=${TEST_ACCOUNT_ID}` +
  `&role=${encodeURIComponent(TEST_ROLE)}`
);
const TEST_REQUEST_URL = `${DEFAULT_BACKEND_URL}${TEST_TARGET}`;
const TEST_BODY = '{"ok":true}';

// Shared with the Python protocol tests. These are deliberately hard-coded so
// a matching mistake in the JS helper functions cannot make this vector pass.
const KNOWN_SERVER_PROOF =
  "3a65edaffa3b75c35fd50b08cd767f2f230d26731b84b0d63436da4c9cf3fd93";
const KNOWN_REQUEST_PROOF =
  "c6782764d40751c6e26ea3ec9a5555b54e93471075a619106739f5e9a236ed65";
const KNOWN_RESPONSE_PROOF =
  "cf971959cbc2a14a3c224a20f3f55f248b4012672121b78155b70153d08d6a7a";

function hmacProof(parts, token = TEST_TOKEN) {
  return createHmac("sha256", Buffer.from(token, "base64url"))
    .update(parts.join("\n"), "utf8")
    .digest("hex");
}

function serverProof({
  challenge = TEST_CHALLENGE,
  expiresAt = TEST_EXPIRES_AT,
  host = TEST_HOST,
  origin = TEST_ORIGIN,
  token = TEST_TOKEN,
} = {}) {
  return hmacProof([
    "containoodle-server-v1",
    challenge,
    String(expiresAt),
    host,
    origin,
  ], token);
}

function requestProof({
  challenge = TEST_CHALLENGE,
  target = TEST_TARGET,
  host = TEST_HOST,
  origin = TEST_ORIGIN,
  token = TEST_TOKEN,
} = {}) {
  return hmacProof([
    "containoodle-request-v1",
    challenge,
    "GET",
    target,
    host,
    origin,
  ], token);
}

function responseProof({
  challenge = TEST_CHALLENGE,
  status = 200,
  target = TEST_TARGET,
  body = TEST_BODY,
  host = TEST_HOST,
  origin = TEST_ORIGIN,
  token = TEST_TOKEN,
} = {}) {
  const bodyDigest = createHash("sha256").update(body).digest("hex");
  return hmacProof([
    "containoodle-response-v1",
    challenge,
    String(status),
    target,
    bodyDigest,
    host,
    origin,
  ], token);
}

function validChallenge(overrides = {}) {
  const payload = {
    version: 1,
    challenge: TEST_CHALLENGE,
    expiresAt: TEST_EXPIRES_AT,
    ...overrides,
  };
  if (!("serverProof" in overrides)) {
    payload.serverProof = serverProof(payload);
  }
  return payload;
}

function challengeResponse(payload = validChallenge(), status = 200) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function signedProtectedResponse({
  body = TEST_BODY,
  status = 200,
  proof = responseProof({ body, status }),
} = {}) {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (proof != null) headers.set("X-Containoodle-Response-Proof", proof);
  return new Response(body, { status, headers });
}

async function withBackendRuntime(mockFetch, operation, {
  now = TEST_NOW,
  origin = TEST_ORIGIN,
} = {}) {
  const previousFetch = globalThis.fetch;
  const previousLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  const previousNow = Date.now;
  globalThis.fetch = mockFetch;
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { origin },
  });
  Date.now = () => now;
  try {
    return await operation();
  } finally {
    globalThis.fetch = previousFetch;
    Date.now = previousNow;
    if (previousLocation) {
      Object.defineProperty(globalThis, "location", previousLocation);
    } else {
      delete globalThis.location;
    }
  }
}

function assertAuthenticationError(error) {
  assert.ok(isBackendAuthenticationError(error));
  assert.equal(error.name, "BackendAuthenticationError");
  assert.doesNotMatch(error.message, new RegExp(TEST_TOKEN));
  assert.doesNotMatch(error.message, new RegExp(TEST_OTHER_TOKEN));
  return true;
}

function assertNoRawToken(call, ...tokens) {
  const [url, options] = call;
  const values = [String(url)];
  if (options.headers) {
    for (const [name, value] of new Headers(options.headers)) {
      values.push(name, value);
    }
  }
  for (const token of tokens) {
    for (const value of values) assert.doesNotMatch(value, new RegExp(token));
  }
}

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

test("helper tokens use a separate key and canonical 256-bit base64url", () => {
  assert.equal(BACKEND_AUTH_TOKEN_KEY, "backendAuthToken");
  assert.equal(normalizeBackendToken(`  ${TEST_TOKEN}\n`), TEST_TOKEN);
  assert.equal(normalizeBackendToken(TEST_URLSAFE_TOKEN), TEST_URLSAFE_TOKEN);
  assert.match(TEST_URLSAFE_TOKEN, /-/);
  assert.match(TEST_URLSAFE_TOKEN, /_/);

  for (const value of [
    undefined,
    null,
    "",
    "A".repeat(42),
    `${TEST_TOKEN} with-space`,
    `${TEST_TOKEN}.with-punctuation`,
    "A".repeat(44),
    `${TEST_TOKEN.slice(0, -1)}9`,
  ]) {
    let error;
    assert.throws(() => normalizeBackendToken(value), (caught) => {
      error = caught;
      return /authentication token is missing or invalid/.test(caught.message);
    });
    assert.ok(isBackendAuthenticationError(error));
  }
});

test("helper SSO profile and identity storage values are strictly normalized", () => {
  assert.equal(BACKEND_SSO_PROFILE_KEY, "backendSsoProfile");
  assert.equal(BACKEND_SSO_IDENTITY_KEY, "backendSsoIdentityKey");
  assert.equal(normalizeBackendSsoProfile(undefined), "");
  assert.equal(normalizeBackendSsoProfile(null), "");
  assert.equal(normalizeBackendSsoProfile("   "), "");
  assert.equal(
    normalizeBackendSsoProfile(`  ${TEST_PROFILE}  `),
    TEST_PROFILE,
  );
  assert.equal(normalizeBackendSsoProfile("x".repeat(128)), "x".repeat(128));
  assert.equal(normalizeBackendSsoIdentityKey(TEST_IDENTITY_KEY), TEST_IDENTITY_KEY);

  for (const value of [
    false,
    0,
    {},
    `${TEST_PROFILE}\n`,
    `${TEST_PROFILE}\u0000`,
    "x".repeat(129),
  ]) {
    assert.throws(() => normalizeBackendSsoProfile(value), /AWS CLI profile/);
  }

  for (const value of [
    undefined,
    null,
    "",
    "0".repeat(63),
    "0".repeat(65),
    "A".repeat(64),
    `${TEST_IDENTITY_KEY} `,
  ]) {
    assert.throws(
      () => normalizeBackendSsoIdentityKey(value),
      /invalid SSO identity/,
    );
  }
});

test("mutual HMAC exchange matches the shared v1 vector without sending the token", async () => {
  assert.equal(serverProof(), KNOWN_SERVER_PROOF);
  assert.equal(requestProof(), KNOWN_REQUEST_PROOF);
  assert.equal(responseProof(), KNOWN_RESPONSE_PROOF);

  const controller = new AbortController();
  const calls = [];
  const originalHeaders = { Accept: "application/json" };
  const originalOptions = {
    signal: controller.signal,
    headers: originalHeaders,
    redirect: "follow",
    cache: "reload",
    credentials: "include",
  };

  const result = await withBackendRuntime(async (...args) => {
    calls.push(args);
    if (calls.length === 1) {
      return challengeResponse({
        version: 1,
        challenge: TEST_CHALLENGE,
        expiresAt: TEST_EXPIRES_AT,
        serverProof: KNOWN_SERVER_PROOF,
      });
    }
    return signedProtectedResponse({ proof: KNOWN_RESPONSE_PROOF });
  }, () => backendFetch(TEST_REQUEST_URL, TEST_TOKEN, originalOptions));

  assert.equal(calls.length, 2);
  const [challengeUrl, challengeOptions] = calls[0];
  assert.equal(challengeUrl, `${DEFAULT_BACKEND_URL}/auth/challenge`);
  assert.equal(challengeOptions.method, "GET");
  assert.ok(challengeOptions.signal instanceof AbortSignal);
  assert.equal(challengeOptions.signal.aborted, false);
  assert.equal(challengeOptions.redirect, "error");
  assert.equal(challengeOptions.cache, "no-store");
  assert.equal(challengeOptions.credentials, "omit");
  assert.equal(challengeOptions.mode, "cors");
  assert.equal(Object.hasOwn(challengeOptions, "headers"), false);

  const [requestUrl, requestOptions] = calls[1];
  assert.equal(requestUrl, TEST_REQUEST_URL);
  assert.equal(requestOptions.method, "GET");
  assert.equal(requestOptions.signal, challengeOptions.signal);
  assert.equal(requestOptions.redirect, "error");
  assert.equal(requestOptions.cache, "no-store");
  assert.equal(requestOptions.credentials, "omit");
  assert.equal(requestOptions.mode, "cors");
  assert.equal(requestOptions.headers.get("Accept"), "application/json");
  assert.equal(
    requestOptions.headers.get("X-Containoodle-Challenge"),
    TEST_CHALLENGE,
  );
  assert.equal(
    requestOptions.headers.get("X-Containoodle-Request-Proof"),
    KNOWN_REQUEST_PROOF,
  );
  assert.equal(requestOptions.headers.has("Authorization"), false);
  assertNoRawToken(calls[0], TEST_TOKEN);
  assertNoRawToken(calls[1], TEST_TOKEN);
  assert.deepEqual(originalHeaders, { Accept: "application/json" });
  assert.equal(originalOptions.redirect, "follow");

  assert.equal(result.status, 200);
  assert.equal(await result.text(), TEST_BODY);
  assert.equal(
    result.headers.get("X-Containoodle-Response-Proof"),
    KNOWN_RESPONSE_PROOF,
  );
});

test("all protected routes use a fresh challenge and exact target proof", async () => {
  const urls = [
    `${DEFAULT_BACKEND_URL}/accounts`,
    `${DEFAULT_BACKEND_URL}/sso-identity`,
    `${DEFAULT_BACKEND_URL}/sso-identity?profile=${TEST_PROFILE}`,
    (
      `${DEFAULT_BACKEND_URL}/roles?account=${TEST_ACCOUNT_ID}` +
      `&profile=${TEST_PROFILE}&identity=${TEST_IDENTITY_KEY}`
    ),
    (
      `${TEST_REQUEST_URL}&profile=${TEST_PROFILE}` +
      `&identity=${TEST_IDENTITY_KEY}`
    ),
  ];
  const calls = [];

  await withBackendRuntime(async (...args) => {
    calls.push(args);
    const [url, options] = args;
    if (String(url).endsWith("/auth/challenge")) return challengeResponse();

    const parsed = new URL(url);
    const target = `${parsed.pathname}${parsed.search}`;
    assert.equal(
      options.headers.get("X-Containoodle-Request-Proof"),
      requestProof({ target }),
    );
    return signedProtectedResponse({
      proof: responseProof({ target }),
    });
  }, async () => {
    for (const url of urls) {
      const response = await backendFetch(url, TEST_TOKEN);
      assert.equal(await response.text(), TEST_BODY);
    }
  });

  assert.equal(calls.length, urls.length * 2);
});

test("malformed, stale, and fake challenges fail before the protected GET", async () => {
  const stale = validChallenge({ expiresAt: TEST_NOW });
  stale.serverProof = serverProof(stale);
  const farFuture = validChallenge({ expiresAt: TEST_NOW + 35_001 });
  farFuture.serverProof = serverProof(farFuture);
  const extraField = { ...validChallenge(), unexpected: true };
  const noncanonicalChallenge = `${TEST_CHALLENGE.slice(0, -1)}9`;

  const cases = [
    challengeResponse("{not-json"),
    challengeResponse({ ...validChallenge(), version: "1" }),
    challengeResponse(extraField),
    challengeResponse({
      ...validChallenge(),
      challenge: noncanonicalChallenge,
      serverProof: serverProof({ challenge: noncanonicalChallenge }),
    }),
    challengeResponse(stale),
    challengeResponse(farFuture),
    challengeResponse({ ...validChallenge(), serverProof: "0".repeat(64) }),
    challengeResponse({
      ...validChallenge(),
      serverProof: KNOWN_SERVER_PROOF.toUpperCase(),
    }),
    challengeResponse(validChallenge(), 404),
  ];

  for (const response of cases) {
    const calls = [];
    await withBackendRuntime(async (...args) => {
      calls.push(args);
      return response.clone();
    }, async () => {
      await assert.rejects(
        backendFetch(TEST_REQUEST_URL, TEST_TOKEN),
        assertAuthenticationError,
      );
    });
    assert.equal(calls.length, 1);
  }
});

test("a valid challenge signed by another key never reaches the protected route", async () => {
  const calls = [];
  await withBackendRuntime(async (...args) => {
    calls.push(args);
    return challengeResponse();
  }, async () => {
    await assert.rejects(
      backendFetch(TEST_REQUEST_URL, TEST_OTHER_TOKEN),
      assertAuthenticationError,
    );
  });

  assert.equal(calls.length, 1);
  assertNoRawToken(calls[0], TEST_TOKEN, TEST_OTHER_TOKEN);
});

test("missing and tampered response proofs are authentication failures", async () => {
  const cases = [
    signedProtectedResponse({ proof: null }),
    signedProtectedResponse({ proof: "0".repeat(64) }),
    signedProtectedResponse({
      body: '{"ok":false}',
      proof: responseProof({ body: TEST_BODY }),
    }),
    signedProtectedResponse({
      status: 500,
      proof: responseProof({ status: 200 }),
    }),
    signedProtectedResponse({
      proof: responseProof({ target: "/accounts" }),
    }),
    signedProtectedResponse({
      proof: responseProof({ host: "127.0.0.1:8765" }),
    }),
  ];

  for (const protectedResponse of cases) {
    const calls = [];
    await withBackendRuntime(async (...args) => {
      calls.push(args);
      return calls.length === 1
        ? challengeResponse()
        : protectedResponse.clone();
    }, async () => {
      await assert.rejects(
        backendFetch(TEST_REQUEST_URL, TEST_TOKEN),
        assertAuthenticationError,
      );
    });
    assert.equal(calls.length, 2);
  }
});

test("a correctly signed application error is returned for caller handling", async () => {
  const body = '{"error":"synthetic helper failure"}';
  const status = 503;
  const calls = [];

  const result = await withBackendRuntime(async (...args) => {
    calls.push(args);
    return calls.length === 1
      ? challengeResponse()
      : signedProtectedResponse({ body, status });
  }, () => backendFetch(TEST_REQUEST_URL, TEST_TOKEN));

  assert.equal(calls.length, 2);
  assert.equal(result.status, status);
  assert.equal(result.ok, false);
  assert.equal(await result.text(), body);
});

test("server proof binds the challenge to expiry, port, and extension origin", async () => {
  const cases = [
    validChallenge({
      serverProof: serverProof({ expiresAt: TEST_EXPIRES_AT + 1 }),
    }),
    validChallenge({
      serverProof: serverProof({ host: "127.0.0.1:8765" }),
    }),
    validChallenge({
      serverProof: serverProof({ origin: "moz-extension://other-test-origin" }),
    }),
    validChallenge({
      serverProof: serverProof({ challenge: TEST_OTHER_TOKEN }),
    }),
  ];

  for (const payload of cases) {
    const calls = [];
    await withBackendRuntime(async (...args) => {
      calls.push(args);
      return challengeResponse(payload);
    }, async () => {
      await assert.rejects(
        backendFetch(TEST_REQUEST_URL, TEST_TOKEN),
        assertAuthenticationError,
      );
    });
    assert.equal(calls.length, 1);
  }
});

test("caller cancellation propagates and prevents a later protected request", async () => {
  const controller = new AbortController();
  const calls = [];

  await withBackendRuntime(async (...args) => {
    calls.push(args);
    const [, options] = args;
    assert.ok(options.signal instanceof AbortSignal);
    if (calls.length === 1) {
      controller.abort();
      return challengeResponse();
    }
    throw options.signal.reason;
  }, async () => {
    await assert.rejects(
      backendFetch(TEST_REQUEST_URL, TEST_TOKEN, {
        signal: controller.signal,
      }),
      (error) => {
        assert.equal(error.name, "AbortError");
        assert.equal(isBackendAuthenticationError(error), false);
        return true;
      },
    );
  });

  assert.equal(calls.length, 1);
});

test("already cancelled requests do not contact the helper", async () => {
  const controller = new AbortController();
  controller.abort();
  await withBackendRuntime(() => assert.fail("cancelled request reached fetch"), async () => {
    await assert.rejects(backendFetch(TEST_REQUEST_URL, TEST_TOKEN, {
      signal: controller.signal,
    }), { name: "AbortError" });
  });
});

test("the deadline covers stalled challenge and protected response bodies", async t => {
  for (const phase of ["challenge-fetch", "challenge-body", "protected-fetch", "protected-body"]) {
    await t.test(phase, async t => {
      t.mock.timers.enable({ apis: ["setTimeout"] });
      let release;
      const stalled = new Promise(resolve => { release = resolve; });
      let reached;
      const atStall = new Promise(resolve => { reached = resolve; });
      const requests = [];
      let requestSignal;
      await withBackendRuntime(async (url, options) => {
        requestSignal = options.signal;
        requests.push(url);
        const response = requests.length === 1 ? challengeResponse() : signedProtectedResponse();
        const current = requests.length === 1 ? "challenge" : "protected";
        if (phase === `${current}-fetch`) {
          reached();
          await stalled;
        } else if (phase === `${current}-body`) {
          const method = current === "challenge" ? "text" : "arrayBuffer";
          const read = response[method].bind(response);
          response[method] = async () => { reached(); await stalled; return read(); };
        }
        return response;
      }, async () => {
        const pending = backendFetch(TEST_REQUEST_URL, TEST_TOKEN);
        const rejection = assert.rejects(pending, error => {
          assert.ok(isBackendTimeoutError(error));
          assert.equal(isBackendAuthenticationError(error), false);
          assert.doesNotMatch(error.message, new RegExp(TEST_TOKEN));
          return true;
        });
        await atStall;
        t.mock.timers.tick(BACKEND_REQUEST_TIMEOUT_MS);
        await rejection;
        assert.equal(requestSignal.aborted, true);
        const countAtDeadline = requests.length;
        release();
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(requests.length, countAtDeadline, "late work must not send another request");
      });
    });
  }
});

test("a completed exchange cancels its timer and detaches caller cancellation", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const caller = new AbortController();
  const signals = [];
  await withBackendRuntime(async (_url, options) => {
    signals.push(options.signal);
    return signals.length === 1 ? challengeResponse() : signedProtectedResponse();
  }, async () => {
    const result = await backendFetch(TEST_REQUEST_URL, TEST_TOKEN, { signal: caller.signal });
    assert.equal(await result.text(), TEST_BODY);
    assert.equal(signals[0], signals[1]);
    t.mock.timers.tick(BACKEND_REQUEST_TIMEOUT_MS);
    caller.abort();
    assert.equal(signals[0].aborted, false);
  });
});

test("unsafe inputs and caller-controlled security headers reject synchronously", async () => {
  const calls = [];
  await withBackendRuntime(async (...args) => {
    calls.push(args);
    return challengeResponse();
  }, async () => {
    const unsafeUrls = [
      "http://localhost:8421/accounts",
      "http://127.1:8421/accounts",
      "https://127.0.0.1:8421/accounts",
      "http://127.0.0.1/accounts",
      "http://user@127.0.0.1:8421/accounts",
      "http://127.0.0.1:8421/accounts#fragment",
      "http://127.0.0.1:8421/",
      "http://127.0.0.1:8421/accounts/",
      "http://127.0.0.1:8421/static/app.js",
      `http://127.0.0.1:8421/accounts?account=${TEST_ACCOUNT_ID}`,
      "http://127.0.0.1:8421/roles?unknown=value",
      (
        `http://127.0.0.1:8421/roles?account=${TEST_ACCOUNT_ID}` +
        `&account=${TEST_ACCOUNT_ID}`
      ),
      `${DEFAULT_BACKEND_URL}/roles?account=${TEST_TOKEN}`,
      `${DEFAULT_BACKEND_URL}/sso-identity?unknown=value`,
      `${DEFAULT_BACKEND_URL}/sso-identity?profile=`,
      `${DEFAULT_BACKEND_URL}/sso-identity?profile=%20${TEST_PROFILE}`,
      `${DEFAULT_BACKEND_URL}/sso-identity?profile=${TEST_PROFILE}%0A`,
      `${DEFAULT_BACKEND_URL}/sso-identity?profile=${"x".repeat(129)}`,
      `${DEFAULT_BACKEND_URL}/roles?identity=${"A".repeat(64)}`,
      `${DEFAULT_BACKEND_URL}/generate-url?identity=${"0".repeat(63)}`,
    ];
    for (const url of unsafeUrls) {
      assert.throws(
        () => backendFetch(url, TEST_TOKEN),
        /Invalid local helper request/,
      );
    }

    const unsafeOptions = [
      { method: "POST" },
      { body: "synthetic-body" },
      { headers: { Authorization: `Bearer ${TEST_OTHER_TOKEN}` } },
      { headers: { Cookie: `helper=${TEST_OTHER_TOKEN}` } },
      { headers: { "Proxy-Authorization": TEST_OTHER_TOKEN } },
      { headers: { Host: TEST_HOST } },
      { headers: { Origin: TEST_ORIGIN } },
      { headers: { "X-Containoodle-Challenge": TEST_CHALLENGE } },
      { headers: { "X-Containoodle-Request-Proof": "0".repeat(64) } },
      { headers: { "X-Containoodle-Response-Proof": "0".repeat(64) } },
      { headers: { "X-Synthetic-Test": TEST_TOKEN } },
    ];
    for (const options of unsafeOptions) {
      assert.throws(
        () => backendFetch(TEST_REQUEST_URL, TEST_TOKEN, options),
        /Invalid local helper request/,
      );
    }

    assert.throws(
      () => backendFetch(TEST_REQUEST_URL, "short-synthetic-token"),
      assertAuthenticationError,
    );
  });

  assert.deepEqual(calls, []);
});

test("non-extension origins reject synchronously before challenge fetch", async () => {
  for (const origin of [
    "null",
    "https://example.invalid",
    "moz-extension://",
    "moz-extension://containoodle_test_origin",
    "moz-extension://containoodle-test-origin/path",
  ]) {
    const calls = [];
    await withBackendRuntime(async (...args) => {
      calls.push(args);
      return challengeResponse();
    }, async () => {
      assert.throws(
        () => backendFetch(TEST_REQUEST_URL, TEST_TOKEN),
        /Invalid local helper request/,
      );
    }, { origin });
    assert.deepEqual(calls, []);
  }
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
