export const DEFAULT_BACKEND_URL = "http://127.0.0.1:8421";
export const BACKEND_AUTH_TOKEN_KEY = "backendAuthToken";

const BASE64URL_32_RE = /^[A-Za-z0-9_-]{43}$/;
const BACKEND_PROOF_RE = /^[0-9a-f]{64}$/;
const EXTENSION_ORIGIN_RE = /^moz-extension:\/\/[A-Za-z0-9-]+$/;
const CHALLENGE_MAX_FUTURE_MS = 35_000;
const BACKEND_REQUEST_PATHS = new Map([
  ["/accounts", new Set()],
  ["/roles", new Set(["account"])],
  ["/generate-url", new Set(["account", "role"])],
]);
const CALLER_FORBIDDEN_HEADERS = [
  "Authorization",
  "Cookie",
  "Host",
  "Origin",
  "Proxy-Authorization",
  "X-Containoodle-Challenge",
  "X-Containoodle-Request-Proof",
  "X-Containoodle-Response-Proof",
];
const CHALLENGE_FIELDS = ["challenge", "expiresAt", "serverProof", "version"];
const UTF8 = new TextEncoder();

class BackendAuthenticationError extends Error {
  constructor(message = "Local helper authentication or trust verification failed") {
    super(message);
    this.name = "BackendAuthenticationError";
  }
}

function invalidBackendRequest() {
  return new Error("Invalid local helper request");
}

function invalidBackendToken() {
  return new BackendAuthenticationError(
    "Local helper authentication token is missing or invalid",
  );
}

function backendAuthenticationFailure() {
  return new BackendAuthenticationError();
}

export function isBackendAuthenticationError(error) {
  return error instanceof BackendAuthenticationError;
}

function decodeCanonicalBase64Url32(value, invalid) {
  if (typeof value !== "string" || !BASE64URL_32_RE.test(value)) throw invalid();

  let binary;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = globalThis.atob(`${base64}=`);
  } catch {
    throw invalid();
  }
  if (binary.length !== 32) throw invalid();

  const canonical = globalThis.btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  if (canonical !== value) throw invalid();

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function normalizedBackendToken(value) {
  if (typeof value !== "string") throw invalidBackendToken();
  const token = value.trim();
  const keyBytes = decodeCanonicalBase64Url32(token, invalidBackendToken);
  return { token, keyBytes };
}

export function normalizeBackendUrl(value) {
  const candidate = String(value ?? "").trim() || DEFAULT_BACKEND_URL;
  let url;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error("Helper URL must be http://127.0.0.1:<port>");
  }

  if (
    url.protocol !== "http:" ||
    url.hostname !== "127.0.0.1" ||
    !url.port ||
    url.username ||
    url.password ||
    (url.pathname !== "" && url.pathname !== "/") ||
    url.search ||
    url.hash
  ) {
    throw new Error("Helper URL must be http://127.0.0.1:<port>");
  }

  return `http://127.0.0.1:${url.port}`;
}

export function safeBackendUrl(value) {
  try {
    return normalizeBackendUrl(value);
  } catch {
    return DEFAULT_BACKEND_URL;
  }
}

export function normalizeBackendToken(value) {
  return normalizedBackendToken(value).token;
}

function validateBackendRequestUrl(value, token) {
  if (typeof value !== "string" || value !== value.trim()) {
    throw invalidBackendRequest();
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw invalidBackendRequest();
  }

  const exactOrigin = url.port
    ? `http://127.0.0.1:${url.port}`
    : "";
  if (
    !exactOrigin ||
    url.origin !== exactOrigin ||
    url.href !== value ||
    url.username ||
    url.password ||
    url.hash ||
    value.includes(token)
  ) {
    throw invalidBackendRequest();
  }

  const allowedQueryKeys = BACKEND_REQUEST_PATHS.get(url.pathname);
  if (!allowedQueryKeys) throw invalidBackendRequest();

  const seenQueryKeys = new Set();
  for (const [key, queryValue] of url.searchParams) {
    if (
      !allowedQueryKeys.has(key) ||
      seenQueryKeys.has(key) ||
      queryValue.includes(token)
    ) {
      throw invalidBackendRequest();
    }
    seenQueryKeys.add(key);
  }

  return {
    href: url.href,
    host: url.host,
    origin: url.origin,
    target: `${url.pathname}${url.search}`,
  };
}

function extensionOrigin() {
  let origin;
  try {
    origin = globalThis.location.origin;
  } catch {
    throw invalidBackendRequest();
  }
  if (typeof origin !== "string" || !EXTENSION_ORIGIN_RE.test(origin)) {
    throw invalidBackendRequest();
  }
  return origin;
}

function validateBackendOptions(options, token) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw invalidBackendRequest();
  }
  if (options.body != null) throw invalidBackendRequest();

  try {
    if (options.method && String(options.method).toUpperCase() !== "GET") {
      throw invalidBackendRequest();
    }
  } catch {
    throw invalidBackendRequest();
  }

  let headers;
  try {
    headers = new Headers(options.headers);
  } catch {
    throw invalidBackendRequest();
  }
  if (CALLER_FORBIDDEN_HEADERS.some((header) => headers.has(header))) {
    throw invalidBackendRequest();
  }
  for (const [name, value] of headers) {
    if (name.includes(token) || value.includes(token)) {
      throw invalidBackendRequest();
    }
  }

  return { headers, signal: options.signal };
}

function validateChallengePayload(payload, now) {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    Object.keys(payload).sort().join("\n") !== CHALLENGE_FIELDS.join("\n") ||
    payload.version !== 1 ||
    !Number.isSafeInteger(payload.expiresAt) ||
    payload.expiresAt <= now ||
    payload.expiresAt > now + CHALLENGE_MAX_FUTURE_MS ||
    typeof payload.serverProof !== "string" ||
    !BACKEND_PROOF_RE.test(payload.serverProof)
  ) {
    throw backendAuthenticationFailure();
  }

  decodeCanonicalBase64Url32(payload.challenge, backendAuthenticationFailure);
  return payload;
}

function canonical(fields) {
  return UTF8.encode(fields.join("\n"));
}

function hexToBytes(value) {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function importHmacKey(keyBytes) {
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
  } catch {
    throw backendAuthenticationFailure();
  }
}

async function hmacHex(key, value) {
  try {
    const signature = await globalThis.crypto.subtle.sign("HMAC", key, value);
    return bytesToHex(new Uint8Array(signature));
  } catch {
    throw backendAuthenticationFailure();
  }
}

async function verifyHmacHex(key, value, proof) {
  if (!BACKEND_PROOF_RE.test(proof)) return false;
  try {
    return await globalThis.crypto.subtle.verify(
      "HMAC",
      key,
      hexToBytes(proof),
      value,
    );
  } catch {
    throw backendAuthenticationFailure();
  }
}

async function sha256Hex(value) {
  try {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", value);
    return bytesToHex(new Uint8Array(digest));
  } catch {
    throw backendAuthenticationFailure();
  }
}

async function parseChallengeResponse(response) {
  if (!response || response.status !== 200 || typeof response.text !== "function") {
    throw backendAuthenticationFailure();
  }

  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw backendAuthenticationFailure();
  }
  return validateChallengePayload(payload, Date.now());
}

async function authenticatedBackendFetch(request, keyBytes, origin, callerOptions) {
  const challengeResponse = await globalThis.fetch(
    `${request.origin}/auth/challenge`,
    {
      method: "GET",
      signal: callerOptions.signal,
      redirect: "error",
      cache: "no-store",
      credentials: "omit",
      mode: "cors",
    },
  );
  const challenge = await parseChallengeResponse(challengeResponse);
  const key = await importHmacKey(keyBytes);

  const serverCanonical = canonical([
    "containoodle-server-v1",
    challenge.challenge,
    String(challenge.expiresAt),
    request.host,
    origin,
  ]);
  if (!(await verifyHmacHex(key, serverCanonical, challenge.serverProof))) {
    throw backendAuthenticationFailure();
  }
  if (challenge.expiresAt <= Date.now()) {
    throw backendAuthenticationFailure();
  }

  const requestCanonical = canonical([
    "containoodle-request-v1",
    challenge.challenge,
    "GET",
    request.target,
    request.host,
    origin,
  ]);
  const headers = new Headers(callerOptions.headers);
  headers.set("X-Containoodle-Challenge", challenge.challenge);
  headers.set("X-Containoodle-Request-Proof", await hmacHex(key, requestCanonical));

  const protectedResponse = await globalThis.fetch(request.href, {
    method: "GET",
    signal: callerOptions.signal,
    headers,
    redirect: "error",
    cache: "no-store",
    credentials: "omit",
    mode: "cors",
  });
  if (
    !protectedResponse ||
    !Number.isInteger(protectedResponse.status) ||
    protectedResponse.status < 200 ||
    protectedResponse.status > 599 ||
    typeof protectedResponse.arrayBuffer !== "function" ||
    !protectedResponse.headers ||
    typeof protectedResponse.headers.get !== "function"
  ) {
    throw backendAuthenticationFailure();
  }

  const bodyBytes = new Uint8Array(await protectedResponse.arrayBuffer());
  const bodyDigest = await sha256Hex(bodyBytes);
  const responseCanonical = canonical([
    "containoodle-response-v1",
    challenge.challenge,
    String(protectedResponse.status),
    request.target,
    bodyDigest,
    request.host,
    origin,
  ]);
  const responseProof = protectedResponse.headers.get(
    "X-Containoodle-Response-Proof",
  );
  if (!(await verifyHmacHex(key, responseCanonical, responseProof || ""))) {
    throw backendAuthenticationFailure();
  }

  const nullBodyStatus = [204, 205, 304].includes(protectedResponse.status);
  try {
    return new Response(nullBodyStatus ? null : bodyBytes, {
      status: protectedResponse.status,
      statusText: protectedResponse.statusText,
      headers: protectedResponse.headers,
    });
  } catch {
    throw backendAuthenticationFailure();
  }
}

export function backendFetch(url, token, options = {}) {
  const normalized = normalizedBackendToken(token);
  const request = validateBackendRequestUrl(url, normalized.token);
  const origin = extensionOrigin();
  const callerOptions = validateBackendOptions(options, normalized.token);
  return authenticatedBackendFetch(
    request,
    normalized.keyBytes,
    origin,
    callerOptions,
  );
}

export function validateBackendSigninUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Local helper returned an invalid sign-in URL");
  }

  let destination;
  try {
    destination = new URL(url.searchParams.get("Destination") || "");
  } catch {
    throw new Error("Local helper returned an invalid sign-in URL");
  }

  if (
    url.origin !== "https://signin.aws.amazon.com" ||
    url.pathname !== "/federation" ||
    url.searchParams.get("Action") !== "login" ||
    !url.searchParams.get("SigninToken") ||
    destination.protocol !== "https:" ||
    !destination.hostname.endsWith(".console.aws.amazon.com")
  ) {
    throw new Error("Local helper returned an unexpected sign-in destination");
  }

  return url.href;
}
