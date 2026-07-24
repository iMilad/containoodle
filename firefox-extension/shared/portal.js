/* ═══════════════════════════════════════════════════════════════════
   Orbiting Turnip — AWS access portal URL helpers.

   Pure, no browser APIs. ES module shared by the background script,
   the options page and Node unit tests.

   The portal start URL is user-configured (e.g.
   https://d-xxxxxxxxxx.awsapps.com/start) and lives only in
   browser.storage — never in the repo or the manifest.
   ═══════════════════════════════════════════════════════════════════ */

import { ACCOUNT_ID_RE, ROLE_RE } from "./accounts.js";

/** Normalize a user-entered portal start URL.
 *  Accepts with/without scheme and trailing slashes; returns
 *  "https://<host>/start"-style base with no trailing slash.
 *  Throws with a user-readable message on invalid input. */
export function normalizeStartUrl(input) {
  let s = String(input ?? "").trim();
  if (!s) throw new Error("Portal start URL is empty");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error("Portal start URL is not a valid URL");
  }
  if (u.protocol !== "https:") throw new Error("Portal start URL must use https");
  if (u.username || u.password) throw new Error("Portal start URL must not contain credentials");
  if (!u.hostname.endsWith(".awsapps.com") || u.port) {
    throw new Error("Portal start URL must be an awsapps.com access portal");
  }
  let path = u.pathname.replace(/\/+$/, "");
  if (path === "") path = "/start";
  return `${u.origin}${path}`;
}

/** Federation deep link that opens one account/role from the portal. */
export function consoleDeepLink(startUrl, accountId, roleName) {
  const base = normalizeStartUrl(startUrl);
  return (
    `${base}/#/console` +
    `?account_id=${encodeURIComponent(accountId)}` +
    `&role_name=${encodeURIComponent(roleName)}`
  );
}

function normalizedPath(url) {
  return url.pathname.replace(/\/+$/, "") || "/";
}

/** Whether a URL belongs to the exact configured AWS portal page.
 *  The fragment may be any portal SPA route. */
export function isConfiguredPortalPage(rawUrl, configuredStartUrl) {
  try {
    const candidate = new URL(String(rawUrl ?? ""));
    const configured = new URL(normalizeStartUrl(configuredStartUrl));
    return (
      candidate.protocol === "https:" &&
      !candidate.username &&
      !candidate.password &&
      candidate.hostname.endsWith(".awsapps.com") &&
      candidate.origin === configured.origin &&
      normalizedPath(candidate) === normalizedPath(configured)
    );
  } catch {
    return false;
  }
}

/** Whether a shortcut tab is a portal-created child that can be removed.
 *  Tabs without a proven portal opener are retained after handoff. */
export function canRemovePortalShortcutTab(tab, opener, configuredStartUrl) {
  return Boolean(
    tab &&
    !tab.incognito &&
    !tab.pinned &&
    tab.cookieStoreId === "firefox-default" &&
    Number.isInteger(tab.openerTabId) &&
    tab.openerTabId !== tab.id &&
    opener &&
    opener.id === tab.openerTabId &&
    !opener.incognito &&
    opener.cookieStoreId === "firefox-default" &&
    isConfiguredPortalPage(opener.url, configuredStartUrl)
  );
}

/** Parse an AWS access-portal console shortcut opened by the portal.
 *
 *  AWS puts account_id and role_name in the fragment query, not the
 *  normal URL query:
 *    https://<portal>/start/#/console?account_id=...&role_name=...
 *
 *  The candidate must belong to the exact configured portal origin and
 *  path. Returns null for anything that is not a valid console shortcut
 *  so this is safe to use as a tabs event filter. */
export function parsePortalConsoleDeepLink(rawUrl, configuredStartUrl) {
  try {
    const candidate = new URL(String(rawUrl ?? ""));
    if (!isConfiguredPortalPage(candidate.href, configuredStartUrl)) return null;

    const fragment = candidate.hash.startsWith("#") ? candidate.hash.slice(1) : "";
    const queryAt = fragment.indexOf("?");
    if (queryAt < 0) return null;
    const route = fragment.slice(0, queryAt).replace(/\/+$/, "");
    if (route !== "/console") return null;

    const params = new URLSearchParams(fragment.slice(queryAt + 1));
    const accountIds = params.getAll("account_id");
    const roleNames = params.getAll("role_name");
    if (accountIds.length !== 1 || roleNames.length !== 1) return null;

    const accountId = accountIds[0];
    const roleName = roleNames[0];
    if (!ACCOUNT_ID_RE.test(accountId) || !ROLE_RE.test(roleName)) return null;

    return { accountId, roleName, url: candidate.href };
  } catch {
    return null;
  }
}

/** Build a browser-free decision for an observed tab URL. */
export function planPortalTabHandoff({
  mode,
  portalStartUrl,
  accounts,
  tab,
  portalAccountName,
}) {
  const ignore = (reason) => ({ kind: "ignore", reason });
  if (mode !== "portal") return ignore("mode");
  if (!portalStartUrl) return ignore("portal-url");
  if (!tab || !Number.isInteger(tab.id) || !tab.url) return ignore("tab");
  if (tab.incognito) return ignore("private-store");
  if (tab.cookieStoreId !== "firefox-default") return ignore("store");

  const parsed = parsePortalConsoleDeepLink(tab.url, portalStartUrl);
  if (!parsed) return ignore("url");

  const matches = Array.isArray(accounts)
    ? accounts.filter((account) => String(account && account.accountId) === parsed.accountId)
    : [];
  const cached = matches.length === 1 ? matches[0] : null;
  const cachedName = cached &&
    typeof cached.accountName === "string" &&
    cached.accountName.trim()
    ? cached.accountName
    : "";
  const clickedName = typeof portalAccountName === "string"
    ? portalAccountName.trim()
    : "";
  const validClickedName = Boolean(
    clickedName &&
    clickedName.length <= 256 &&
    !/[\u0000-\u001f\u007f]/.test(clickedName)
  );
  const nameIsUnique = cachedName && accounts.filter(
    (account) =>
      account &&
      typeof account.accountName === "string" &&
      account.accountName === cachedName
  ).length === 1;
  const account = validClickedName
    ? { ...(cached || {}), accountId: parsed.accountId, accountName: clickedName }
    : nameIsUnique
      ? { ...cached, accountId: parsed.accountId, accountName: cachedName }
      : { accountId: parsed.accountId, accountName: `AWS ${parsed.accountId}` };

  return {
    kind: "handoff",
    tabId: tab.id,
    sourceUrl: parsed.url,
    account,
    accountId: parsed.accountId,
    roleName: parsed.roleName,
    windowId: tab.windowId,
    openerTabId: tab.openerTabId,
  };
}

/** URL the x-amz-sso_authn session cookie is scoped to. */
export function portalCookieUrl(startUrl) {
  return normalizeStartUrl(startUrl) + "/";
}

/** Host match pattern for a runtime permissions.request(). */
export function portalOriginPattern(startUrl) {
  return new URL(normalizeStartUrl(startUrl)).origin + "/*";
}

/* ─── Role discovery (portal internal API) ────────────────────────
   The portal SPA authenticates its API calls with the value of the
   x-amz-sso_authn cookie passed as the x-amz-sso_bearer_token
   header. whoAmI (on the portal origin) reveals the SSO region. */

/** Endpoint that identifies the signed-in portal user + SSO region. */
export function whoAmIUrl(startUrl) {
  return new URL(normalizeStartUrl(startUrl)).origin + "/token/whoAmI";
}

/** Base URL of the SSO portal API for a given SSO region. */
export function portalApiBase(region) {
  if (!/^[a-z]{2}-[a-z]+-\d$/.test(String(region))) {
    throw new Error(`Invalid SSO region: ${region}`);
  }
  return `https://portal.sso.${region}.amazonaws.com`;
}

/** Portal API responses are usually { result: [...] }; tolerate both. */
export function unwrapResult(json) {
  if (Array.isArray(json)) return json;
  if (json && Array.isArray(json.result)) return json.result;
  return [];
}

/** Find the app instance for a 12-digit account id in an
 *  /instance/appinstances response. */
export function findAccountInstance(appinstances, accountId) {
  return appinstances.find(
    (a) => a && a.searchMetadata && a.searchMetadata.AccountId === accountId
  );
}
