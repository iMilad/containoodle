export const DEFAULT_BACKEND_URL = "http://127.0.0.1:8421";

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
