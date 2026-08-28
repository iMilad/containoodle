import { portalApiBase } from "./portal.js";

// These broad origins are the currently granted legacy capabilities. Keep them
// explicit while Phase 5 characterizes and migrates existing Firefox profiles.
export const LEGACY_ROLE_DISCOVERY_ORIGIN = "https://*.amazonaws.com/*";
export const LEGACY_BACKEND_SESSION_REUSE_ORIGIN = "https://*.amazon.com/*";

// This is the conservative console replacement: it still covers every
// aws.amazon.com host, but no unrelated amazon.com site. Runtime code does not
// request it until the real-Firefox cookie gate has passed.
export const BACKEND_SESSION_REUSE_ORIGIN = "https://*.aws.amazon.com/*";

function literalOriginSet(origins) {
  if (!Array.isArray(origins)) return new Set();
  return new Set(origins.filter((origin) => typeof origin === "string"));
}

function scopeState(targetGranted, legacyGranted, staleOrigins) {
  if (targetGranted && legacyGranted) return "target-and-legacy";
  if (targetGranted) return "target";
  if (legacyGranted) return "legacy";
  if (staleOrigins.length > 0) return "stale-only";
  return "missing";
}

function isManagedRoleDiscoveryOrigin(origin) {
  if (typeof origin !== "string" || !origin.endsWith("/*")) return false;
  try {
    const url = new URL(origin.slice(0, -2));
    const prefix = "portal.sso.";
    const suffix = ".amazonaws.com";
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      !url.hostname.startsWith(prefix) ||
      !url.hostname.endsWith(suffix)
    ) {
      return false;
    }
    const region = url.hostname.slice(prefix.length, -suffix.length);
    return roleDiscoveryOrigin(region) === origin;
  } catch {
    return false;
  }
}

function classifyManagedPermission({
  grantedOrigins,
  targetOrigin,
  legacyOrigins,
  isManagedTarget,
}) {
  const literalOrigins = literalOriginSet(grantedOrigins);
  const targetGranted = literalOrigins.has(targetOrigin);
  const grantedLegacyOrigins = legacyOrigins
    .filter((origin) => literalOrigins.has(origin))
    .sort();
  const staleOrigins = [...literalOrigins]
    .filter((origin) => origin !== targetOrigin && isManagedTarget(origin))
    .sort();
  const legacyGranted = grantedLegacyOrigins.length > 0;

  // A covering wildcard can make permissions.contains(target) return true
  // without storing targetOrigin. Only a literal target from getAll() permits
  // removal of a legacy or stale grant. These arrays are advisory candidates;
  // runtime code must re-inventory permissions around every user action.
  return {
    state: scopeState(targetGranted, legacyGranted, staleOrigins),
    targetOrigin,
    targetGranted,
    legacyGranted,
    effectiveGranted: targetGranted || legacyGranted,
    cleanupPending:
      targetGranted && (grantedLegacyOrigins.length > 0 || staleOrigins.length > 0),
    staleOrigins,
    requestCandidateOrigins: targetGranted ? [] : [targetOrigin],
    removalCandidateOrigins: targetGranted
      ? [...new Set([...grantedLegacyOrigins, ...staleOrigins])].sort()
      : [],
  };
}

export function roleDiscoveryOrigin(region) {
  return `${portalApiBase(region)}/*`;
}

export function classifyRoleDiscoveryPermission(grantedOrigins, region) {
  const targetOrigin = roleDiscoveryOrigin(region);
  return classifyManagedPermission({
    grantedOrigins,
    targetOrigin,
    legacyOrigins: [LEGACY_ROLE_DISCOVERY_ORIGIN],
    isManagedTarget: isManagedRoleDiscoveryOrigin,
  });
}

export function classifyBackendSessionReusePermission(grantedOrigins) {
  return classifyManagedPermission({
    grantedOrigins,
    targetOrigin: BACKEND_SESSION_REUSE_ORIGIN,
    legacyOrigins: [LEGACY_BACKEND_SESSION_REUSE_ORIGIN],
    isManagedTarget: (origin) => origin === BACKEND_SESSION_REUSE_ORIGIN,
  });
}

export function roleDiscoveryOriginsForRevoke(grantedOrigins) {
  return [...literalOriginSet(grantedOrigins)]
    .filter((origin) =>
      origin === LEGACY_ROLE_DISCOVERY_ORIGIN ||
      isManagedRoleDiscoveryOrigin(origin)
    )
    .sort();
}

export function backendSessionReuseOriginsForRevoke(grantedOrigins) {
  return [...literalOriginSet(grantedOrigins)]
    .filter((origin) =>
      origin === LEGACY_BACKEND_SESSION_REUSE_ORIGIN ||
      origin === BACKEND_SESSION_REUSE_ORIGIN
    )
    .sort();
}
