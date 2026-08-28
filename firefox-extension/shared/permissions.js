import { portalApiBase } from "./portal.js";

// These broad origins are the currently granted legacy capabilities. Keep them
// explicit while Phase 5 characterizes and migrates existing Firefox profiles.
export const LEGACY_ROLE_DISCOVERY_ORIGIN = "https://*.amazonaws.com/*";
export const LEGACY_BACKEND_SESSION_REUSE_ORIGIN = "https://*.amazon.com/*";

// This covers the global and regional AWS Console hosts used by backend
// session reuse, but excludes sibling aws.amazon.com services. Its production
// cookie operations passed the isolated Firefox 149 and 155 scope gate.
export const BACKEND_SESSION_REUSE_ORIGIN =
  "https://*.console.aws.amazon.com/*";

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

const FEATURE_MODE = Object.freeze({
  "role-discovery": "portal",
  "backend-session-reuse": "backend",
});

/** Start only an explicit user-action transaction. Callers must invoke
 * permissions.request() from the same synchronous click-handler stack. */
export function beginExplicitPermissionTransaction({
  trigger,
  feature,
  mode,
  modeRevision,
  classification,
}) {
  if (trigger !== "user-action") {
    throw new Error("Permission changes require an explicit user action");
  }
  if (FEATURE_MODE[feature] !== mode) {
    throw new Error("Permission feature does not belong to the active mode");
  }
  if (!Number.isSafeInteger(modeRevision) || modeRevision < 0) {
    throw new Error("Invalid permission mode revision");
  }
  if (
    !classification ||
    typeof classification.targetOrigin !== "string" ||
    typeof classification.targetGranted !== "boolean"
  ) {
    throw new Error("Invalid permission classification");
  }
  return {
    feature,
    expectedMode: mode,
    expectedModeRevision: modeRevision,
    targetOrigin: classification.targetOrigin,
    targetWasLiteral: classification.targetGranted,
    requestOrigins: classification.targetGranted
      ? []
      : [classification.targetOrigin],
  };
}

/** Decide cleanup only from a fresh post-request permission inventory. */
export function settleExplicitPermissionTransaction(transaction, {
  requestOutcome,
  currentMode,
  currentModeRevision,
  classification,
}) {
  const noRemoval = (state) => ({ state, removeOrigins: [] });
  if (!transaction || !classification) {
    throw new Error("Invalid permission transaction");
  }
  if (classification.targetOrigin !== transaction.targetOrigin) {
    throw new Error("Permission target changed during the transaction");
  }
  if (requestOutcome === "declined") return noRemoval("declined");
  if (requestOutcome === "error") return noRemoval("request-error");
  if (!new Set(["accepted", "not-needed"]).has(requestOutcome)) {
    throw new Error("Invalid permission request outcome");
  }

  if (
    currentMode !== transaction.expectedMode ||
    currentModeRevision !== transaction.expectedModeRevision
  ) {
    return {
      state: "cancelled",
      removeOrigins:
        requestOutcome === "accepted" &&
        !transaction.targetWasLiteral &&
        classification.targetGranted
          ? [transaction.targetOrigin]
          : [],
    };
  }
  if (!classification.targetGranted) {
    return noRemoval("target-not-literal");
  }
  if (classification.removalCandidateOrigins.length > 0) {
    return {
      state: "cleanup-ready",
      removeOrigins: [...classification.removalCandidateOrigins],
    };
  }
  return noRemoval("enabled");
}
