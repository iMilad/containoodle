export const ONBOARDING_KEY = "onboarding/connectionV1";

export const ONBOARDING_STATES = Object.freeze({
  CHOOSE: "choose",
  BACKEND: "backend",
  PORTAL: "portal",
  COMPLETE: "complete",
});

const RECOGNIZED_STATES = new Set(Object.values(ONBOARDING_STATES));
const PENDING_STATES = new Set([
  ONBOARDING_STATES.CHOOSE,
  ONBOARDING_STATES.BACKEND,
  ONBOARDING_STATES.PORTAL,
]);

export function normalizeOnboardingState(value) {
  return RECOGNIZED_STATES.has(value) ? value : null;
}

export function isOnboardingPending(value) {
  return PENDING_STATES.has(normalizeOnboardingState(value));
}

export function onboardingMode(value) {
  const state = normalizeOnboardingState(value);
  return state === ONBOARDING_STATES.BACKEND ||
    state === ONBOARDING_STATES.PORTAL
    ? state
    : null;
}

export function onboardingStateForMode(mode) {
  if (mode === "backend") return ONBOARDING_STATES.BACKEND;
  if (mode === "portal") return ONBOARDING_STATES.PORTAL;
  return null;
}

/*
 * Missing state is meaningful only during an install/update lifecycle event.
 * The UI treats missing or invalid state as complete so an existing profile is
 * never surprised by onboarding merely because it predates this marker.
 */
export function onboardingStateForLifecycle({
  reason,
  storedState,
  hasConfig,
}) {
  if (normalizeOnboardingState(storedState)) return null;
  if (storedState !== undefined) return ONBOARDING_STATES.COMPLETE;
  if (reason === "install" && !hasConfig) return ONBOARDING_STATES.CHOOSE;
  if (reason === "install" || reason === "update") {
    return ONBOARDING_STATES.COMPLETE;
  }
  return null;
}
