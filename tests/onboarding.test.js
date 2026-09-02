import assert from "node:assert/strict";
import test from "node:test";

import {
  ONBOARDING_STATES,
  isOnboardingPending,
  normalizeOnboardingState,
  onboardingMode,
  onboardingStateForLifecycle,
  onboardingStateForMode,
} from "../firefox-extension/shared/onboarding.js";

test("onboarding recognizes only the versioned connection states", () => {
  for (const state of Object.values(ONBOARDING_STATES)) {
    assert.equal(normalizeOnboardingState(state), state);
  }
  for (const value of [undefined, null, "", "future", 1, {}]) {
    assert.equal(normalizeOnboardingState(value), null);
  }

  assert.equal(isOnboardingPending(ONBOARDING_STATES.CHOOSE), true);
  assert.equal(isOnboardingPending(ONBOARDING_STATES.BACKEND), true);
  assert.equal(isOnboardingPending(ONBOARDING_STATES.PORTAL), true);
  assert.equal(isOnboardingPending(ONBOARDING_STATES.COMPLETE), false);
  assert.equal(isOnboardingPending(undefined), false);
});

test("onboarding mode mapping never invents a runtime mode", () => {
  assert.equal(onboardingMode(ONBOARDING_STATES.CHOOSE), null);
  assert.equal(onboardingMode(ONBOARDING_STATES.BACKEND), "backend");
  assert.equal(onboardingMode(ONBOARDING_STATES.PORTAL), "portal");
  assert.equal(onboardingMode(ONBOARDING_STATES.COMPLETE), null);
  assert.equal(onboardingMode("unexpected"), null);

  assert.equal(onboardingStateForMode("backend"), ONBOARDING_STATES.BACKEND);
  assert.equal(onboardingStateForMode("portal"), ONBOARDING_STATES.PORTAL);
  assert.equal(onboardingStateForMode("unexpected"), null);
});

test("fresh installs start onboarding while existing installs are grandfathered", () => {
  assert.equal(
    onboardingStateForLifecycle({
      reason: "install",
      storedState: undefined,
      hasConfig: false,
    }),
    ONBOARDING_STATES.CHOOSE,
  );
  assert.equal(
    onboardingStateForLifecycle({
      reason: "install",
      storedState: undefined,
      hasConfig: true,
    }),
    ONBOARDING_STATES.COMPLETE,
  );
  assert.equal(
    onboardingStateForLifecycle({
      reason: "update",
      storedState: undefined,
      hasConfig: false,
    }),
    ONBOARDING_STATES.COMPLETE,
  );
});

test("lifecycle handling preserves known state and fails closed on invalid state", () => {
  for (const state of Object.values(ONBOARDING_STATES)) {
    assert.equal(
      onboardingStateForLifecycle({
        reason: "update",
        storedState: state,
        hasConfig: true,
      }),
      null,
    );
  }
  assert.equal(
    onboardingStateForLifecycle({
      reason: "install",
      storedState: "unexpected",
      hasConfig: false,
    }),
    ONBOARDING_STATES.COMPLETE,
  );
  assert.equal(
    onboardingStateForLifecycle({
      reason: "browser_update",
      storedState: undefined,
      hasConfig: false,
    }),
    null,
  );
});
