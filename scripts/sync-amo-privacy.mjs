// Release-only metadata update. Never print keys, JWTs, response bodies or headers.
import { createHmac, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const ADDON_GUID = "{7da5f34e-08f0-4e4e-be7f-7b9b66ab7f60}";
const API = "https://addons.mozilla.org/api/v5/addons/addon/3046053/";

export async function syncAmoPrivacy({ policy, issuer, secret, fetchImpl = fetch,
  now = Date.now, nonce = randomUUID }) {
  if (typeof policy !== "string" || policy.length < 100 || policy.length > 64 * 1024 ||
      typeof issuer !== "string" || !issuer || typeof secret !== "string" || !secret) {
    throw new Error("AMO privacy sync requires the release policy and configured signing credentials");
  }
  async function request(url, method, body) {
    const issued = Math.floor(now() / 1000);
    const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");
    const unsigned = encode({ alg: "HS256", typ: "JWT" }) + "." +
      encode({ iss: issuer, jti: nonce(), iat: issued, exp: issued + 60 });
    const token = unsigned + "." + createHmac("sha256", secret).update(unsigned).digest("base64url");
    try {
      const response = await fetchImpl(url, {
        method, redirect: "error", signal: AbortSignal.timeout(30_000),
        headers: { Authorization: "JWT " + token, Accept: "application/json",
          "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      return await response.json();
    } catch {
      // Do not echo server/library errors which could contain request material.
      throw new Error("AMO privacy sync request failed; no credentials or response details logged");
    }
  }
  const addon = await request(API, "GET");
  if (addon.guid !== ADDON_GUID || addon.slug !== "containoodle") {
    throw new Error("AMO privacy sync target does not match Containoodle");
  }
  // PATCH only the policy: no EULA, listing name, authors, releases or permissions.
  const result = await request(API + "eula_policy/", "PATCH", {
    privacy_policy: { "en-US": policy },
  });
  if (typeof result.privacy_policy?.["en-US"] !== "string" || !result.privacy_policy["en-US"]) {
    throw new Error("AMO did not confirm the updated privacy policy");
  }
  return { updated: true };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const manifest = JSON.parse(await readFile(join(root, "firefox-extension/manifest.json"), "utf8"));
    if (process.argv.slice(2).join(" ") !== "--publish" || process.env.GITHUB_REF_TYPE !== "tag" ||
        process.env.GITHUB_REF_NAME !== "v" + manifest.version ||
        manifest.browser_specific_settings?.gecko?.id !== ADDON_GUID) {
      throw new Error("AMO privacy publishing is restricted to an explicit matching release tag");
    }
    await syncAmoPrivacy({ policy: await readFile(join(root, "PRIVACY.md"), "utf8"),
      issuer: process.env.AMO_JWT_ISSUER, secret: process.env.AMO_JWT_SECRET });
    console.log("AMO privacy policy updated from the tagged PRIVACY.md.");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
