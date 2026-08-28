import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  BACKEND_SESSION_REUSE_ORIGIN,
  LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
  LEGACY_ROLE_DISCOVERY_ORIGIN,
  backendSessionReuseOriginsForRevoke,
  classifyBackendSessionReusePermission,
  classifyRoleDiscoveryPermission,
  roleDiscoveryOrigin,
  roleDiscoveryOriginsForRevoke,
} from "../firefox-extension/shared/permissions.js";

const SYNTHETIC_REGION = "xx-test-1";
const PREVIOUS_SYNTHETIC_REGION = "yy-test-2";
const ROLE_ORIGIN =
  "https://portal.sso.xx-test-1.amazonaws.com/*";
const PREVIOUS_ROLE_ORIGIN =
  "https://portal.sso.yy-test-2.amazonaws.com/*";
const UNRELATED_ORIGIN = "https://unrelated.invalid/*";

function matchPatternCovers(ceiling, requested) {
  const parse = (pattern) => {
    const match = /^https:\/\/(\*\.)?([^/]+)\/\*$/.exec(pattern);
    return match && { wildcard: Boolean(match[1]), hostname: match[2] };
  };
  const allowed = parse(ceiling);
  const candidate = parse(requested);
  if (!allowed || !candidate) return false;
  if (!allowed.wildcard) {
    return !candidate.wildcard && candidate.hostname === allowed.hostname;
  }
  return candidate.hostname === allowed.hostname ||
    candidate.hostname.endsWith(`.${allowed.hostname}`);
}

const expectedClassification = ({
  state,
  targetOrigin,
  targetGranted = false,
  legacyGranted = false,
  effectiveGranted = targetGranted || legacyGranted,
  cleanupPending = false,
  staleOrigins = [],
  requestCandidateOrigins = targetGranted ? [] : [targetOrigin],
  removalCandidateOrigins = [],
}) => ({
  state,
  targetOrigin,
  targetGranted,
  legacyGranted,
  effectiveGranted,
  cleanupPending,
  staleOrigins,
  requestCandidateOrigins,
  removalCandidateOrigins,
});

test("role discovery targets one validated synthetic regional API origin", () => {
  assert.equal(roleDiscoveryOrigin(SYNTHETIC_REGION), ROLE_ORIGIN);
  assert.throws(() => roleDiscoveryOrigin("__CONTAINOODLE_TEST_REGION__"));
  assert.throws(() => roleDiscoveryOrigin("xx-test-1.invalid"));
});

test("fresh role discovery classifies only the exact regional request candidate", () => {
  assert.deepEqual(classifyRoleDiscoveryPermission([], SYNTHETIC_REGION), expectedClassification({
    state: "missing",
    targetOrigin: ROLE_ORIGIN,
  }));
});

test("a broad role grant never counts as a literal narrow grant", () => {
  assert.deepEqual(
    classifyRoleDiscoveryPermission(
      [LEGACY_ROLE_DISCOVERY_ORIGIN],
      SYNTHETIC_REGION,
    ),
    expectedClassification({
      state: "legacy",
      targetOrigin: ROLE_ORIGIN,
      legacyGranted: true,
      effectiveGranted: true,
    }),
  );
});

test("role migration removes legacy and stale grants only after literal target proof", () => {
  assert.deepEqual(
    classifyRoleDiscoveryPermission(
      [
        UNRELATED_ORIGIN,
        PREVIOUS_ROLE_ORIGIN,
        LEGACY_ROLE_DISCOVERY_ORIGIN,
        ROLE_ORIGIN,
        ROLE_ORIGIN,
      ],
      SYNTHETIC_REGION,
    ),
    expectedClassification({
      state: "target-and-legacy",
      targetOrigin: ROLE_ORIGIN,
      targetGranted: true,
      legacyGranted: true,
      cleanupPending: true,
      staleOrigins: [PREVIOUS_ROLE_ORIGIN],
      removalCandidateOrigins: [
        LEGACY_ROLE_DISCOVERY_ORIGIN,
        PREVIOUS_ROLE_ORIGIN,
      ],
    }),
  );
});

test("a stale regional grant is preserved until the replacement is literal", () => {
  const classification = classifyRoleDiscoveryPermission(
    [PREVIOUS_ROLE_ORIGIN],
    SYNTHETIC_REGION,
  );
  assert.equal(classification.state, "stale-only");
  assert.equal(classification.effectiveGranted, false);
  assert.deepEqual(classification.staleOrigins, [PREVIOUS_ROLE_ORIGIN]);
  assert.deepEqual(classification.requestCandidateOrigins, [ROLE_ORIGIN]);
  assert.deepEqual(classification.removalCandidateOrigins, []);
});

test("backend reuse narrows only to the conservative AWS-owned subtree", () => {
  assert.equal(BACKEND_SESSION_REUSE_ORIGIN, "https://*.aws.amazon.com/*");
  assert.deepEqual(
    classifyBackendSessionReusePermission([]),
    expectedClassification({
      state: "missing",
      targetOrigin: BACKEND_SESSION_REUSE_ORIGIN,
    }),
  );
});

test("a broad console grant is preserved until Firefox lists the narrow grant", () => {
  const legacy = classifyBackendSessionReusePermission([
    LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
  ]);
  assert.equal(legacy.state, "legacy");
  assert.equal(legacy.effectiveGranted, true);
  assert.deepEqual(legacy.requestCandidateOrigins, [BACKEND_SESSION_REUSE_ORIGIN]);
  assert.deepEqual(legacy.removalCandidateOrigins, []);

  const proven = classifyBackendSessionReusePermission([
    LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
    BACKEND_SESSION_REUSE_ORIGIN,
  ]);
  assert.equal(proven.state, "target-and-legacy");
  assert.equal(proven.cleanupPending, true);
  assert.deepEqual(proven.requestCandidateOrigins, []);
  assert.deepEqual(proven.removalCandidateOrigins, [
    LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
  ]);
});

test("literal target-only grants are complete and need no cleanup", () => {
  const role = classifyRoleDiscoveryPermission([ROLE_ORIGIN], SYNTHETIC_REGION);
  const reuse = classifyBackendSessionReusePermission([
    BACKEND_SESSION_REUSE_ORIGIN,
  ]);
  for (const classification of [role, reuse]) {
    assert.equal(classification.state, "target");
    assert.equal(classification.targetGranted, true);
    assert.equal(classification.effectiveGranted, true);
    assert.equal(classification.cleanupPending, false);
    assert.deepEqual(classification.requestCandidateOrigins, []);
    assert.deepEqual(classification.removalCandidateOrigins, []);
  }
});

test("legacy plus stale access removes nothing without literal target proof", () => {
  const origins = [LEGACY_ROLE_DISCOVERY_ORIGIN, PREVIOUS_ROLE_ORIGIN];
  const snapshot = [...origins];
  const classification = classifyRoleDiscoveryPermission(origins, SYNTHETIC_REGION);
  assert.equal(classification.state, "legacy");
  assert.equal(classification.effectiveGranted, true);
  assert.deepEqual(classification.staleOrigins, [PREVIOUS_ROLE_ORIGIN]);
  assert.deepEqual(classification.removalCandidateOrigins, []);
  assert.deepEqual(origins, snapshot);
});

test("a covered request is still pending until getAll lists its target literally", () => {
  const afterRequest = classifyRoleDiscoveryPermission(
    [LEGACY_ROLE_DISCOVERY_ORIGIN],
    SYNTHETIC_REGION,
  );
  assert.equal(afterRequest.targetGranted, false);
  assert.deepEqual(afterRequest.requestCandidateOrigins, [ROLE_ORIGIN]);
  assert.deepEqual(afterRequest.removalCandidateOrigins, []);
});

test("revoke plans touch only recognized Containoodle-managed origins", () => {
  assert.deepEqual(
    roleDiscoveryOriginsForRevoke([
      null,
      UNRELATED_ORIGIN,
      PREVIOUS_ROLE_ORIGIN,
      LEGACY_ROLE_DISCOVERY_ORIGIN,
      ROLE_ORIGIN,
    ]),
    [LEGACY_ROLE_DISCOVERY_ORIGIN, ROLE_ORIGIN, PREVIOUS_ROLE_ORIGIN],
  );
  assert.deepEqual(
    backendSessionReuseOriginsForRevoke([
      undefined,
      UNRELATED_ORIGIN,
      BACKEND_SESSION_REUSE_ORIGIN,
      LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
      BACKEND_SESSION_REUSE_ORIGIN,
    ]),
    [LEGACY_BACKEND_SESSION_REUSE_ORIGIN, BACKEND_SESSION_REUSE_ORIGIN],
  );
  assert.deepEqual(roleDiscoveryOriginsForRevoke(null), []);
  assert.deepEqual(backendSessionReuseOriginsForRevoke({}), []);
});

test("malformed permission snapshots fail closed as no literal grants", () => {
  assert.equal(
    classifyRoleDiscoveryPermission(null, SYNTHETIC_REGION).targetGranted,
    false,
  );
  assert.equal(classifyBackendSessionReusePermission({}).targetGranted, false);
});

test("the synthetic previous region remains valid but distinct", () => {
  assert.equal(
    roleDiscoveryOrigin(PREVIOUS_SYNTHETIC_REGION),
    PREVIOUS_ROLE_ORIGIN,
  );
});

test("managed regional classification round-trips through the canonical validator", () => {
  const valid = roleDiscoveryOriginsForRevoke([ROLE_ORIGIN]);
  const malformed = roleDiscoveryOriginsForRevoke([
    "https://portal.sso.xx-test-1.amazonaws.com.invalid/*",
    "https://portal.sso.xx-test-1.amazonaws.com/path/*",
    "http://portal.sso.xx-test-1.amazonaws.com/*",
  ]);
  assert.deepEqual(valid, [ROLE_ORIGIN]);
  assert.deepEqual(malformed, []);
});

test("the Phase 5A manifest retains legacy ceilings that cover all candidates", async () => {
  const manifest = JSON.parse(
    await readFile(
      new URL("../firefox-extension/manifest.json", import.meta.url),
      "utf8",
    ),
  );
  assert.ok(manifest.optional_host_permissions.includes(LEGACY_ROLE_DISCOVERY_ORIGIN));
  assert.ok(
    manifest.optional_host_permissions.includes(
      LEGACY_BACKEND_SESSION_REUSE_ORIGIN,
    ),
  );

  const candidates = [
    classifyRoleDiscoveryPermission([], SYNTHETIC_REGION)
      .requestCandidateOrigins[0],
    classifyBackendSessionReusePermission([]).requestCandidateOrigins[0],
  ];
  for (const candidate of candidates) {
    assert.ok(
      manifest.optional_host_permissions.some((ceiling) =>
        matchPatternCovers(ceiling, candidate)
      ),
      `${candidate} must remain requestable from the Phase 5A manifest`,
    );
  }
});
