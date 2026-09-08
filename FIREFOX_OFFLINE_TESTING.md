# Actual Firefox offline acceptance — 2026-09-08

## Current: original page favicons

The final favicon candidate passes **412 JavaScript tests**, extension lint with
zero errors/warnings/notices, and **29 check groups each** in actual Firefox
155.0.1 and Developer Edition 156.0. Both browser runs used the exact frozen XPI
and skipped the unchanged helper's slow deadline case; its earlier evidence is
recorded below. The helper source and all packaged files except the favicon
module and sidebar JS/CSS are byte-for-byte unchanged from the previous package.

Frozen artifact: `artifacts/acceptance-1.2.0-449492d64c86/containoodle-1.2.0.xpi`.
SHA-256: `449492d64c861808176530c981702fe86b6c7c8d878a37205631ed9b0d14e5a7`.
Reports and screenshots:

- `artifacts/firefox-offline-2026-09-08T11-59-07-458Z/` — Firefox 155.0.1.
- `artifacts/firefox-offline-2026-09-08T11-59-05-648Z/` — Developer Edition 156.0.

Five loopback-only pages provide SVG favicons through Firefox's actual tab API.
The sidebar displays those original images, with no custom service drawings.
They fit at 216/108 CSS pixels and normal/200% zoom. A separate production-loader
test substitutes the transport destination with the synthetic loopback server:
real CORS fetch sends no cookies or referrer, deduplicates the image request and
decodes the returned image. SVG script/external-resource traps are never invoked.
Unit tests cover rejected URLs, redirects/CORS failures, stalled/oversized bodies,
cache expiry and the bound on pending requests. No SVG is inserted into the DOM.
Final normal-zoom screenshots were visually inspected; no clipping was found.

This is not proof that every live AWS favicon allows anonymous CORS requests.
The user still needs to compare icons with their own AWS tabs; refusal/missing
images deliberately produces a neutral placeholder. No AWS login, AWS request,
real credentials, saved profile changes, publication or nomination occurred.

## Previous subtitle/Favorites candidate evidence

Status: the subtitle/Favorites 1.2.0 XPI passed in Firefox **155.0.1** (28 check groups) and
Firefox Developer Edition **156.0** (29 groups, including the real timeout).
**The previously reported narrow-sidebar layout issue is resolved.** This is not a complete
Firefox/AWS release acceptance or a recommendation-badge approval.

## What was exercised

These runs used the installed Firefox binaries in headless mode, fresh unregistered
temporary profiles, the exact frozen extension XPI, and real Firefox WebExtension
APIs. The docked native sidebar was opened and photographed as well as exercising
the sidebar document in a tab. Browser APIs were not mocked.

The test helper preserves production HTTP routing, host/origin checks and mutual
HMAC authentication, but replaces AWS identity/account/role data and federation
generation with unmistakably synthetic fixtures. It cannot exercise real AWS SSO
cache selection or account-file parsing. Those paths retain separate unit tests.

| Area | Observed result |
| --- | --- |
| Installation and onboarding | Temporary installation works without relaxing signature enforcement. Fresh setup does not make unsolicited helper calls or permission grants. Successful helper setup completes onboarding. |
| Helper authentication | Real Firefox exchanges authenticate with the synthetic Python helper. The saved token works on subsequent checks and is not redisplayed. Wrong tokens and invalid response proofs fail closed. |
| Native permission prompts | Denying the initial console permission does not prevent setup. Explicit console-only grant/revoke works. Portal grants are exact-origin; optional role grants are exact-region. Revoking a role grant preserves portal access. |
| Accounts and keyboard | Synthetic accounts load; mouse, Space and Enter toggle pins; pins survive page reload. Filtering and caret/focus survive real tab events. Escape dismisses the role picker; Enter selects a role. |
| Containers and groups | Synthetic launches create distinct actual Firefox containers and account tab groups. Their AWS-shaped navigation is cancelled. This does **not** prove authenticated AWS session isolation. |
| Naming and persistence | The regex changes active/pinned labels, automatic container names and group titles. Manual names remain unchanged. Portal/helper switching and Options reload retain helper pairing, cache and pins. |
| Failure recovery | Malformed schema/JSON, bad proof, signed service errors and a simulated transport disconnect preserve saved settings/cache. A subsequent valid refresh recovers. |
| Real deadline | Developer Edition 156 aborts a deliberately delayed response body after 60.784 seconds, releases the controls and retries successfully. No browser clock is mocked. The duplicate slow case is skipped on regular Firefox. |
| Native sidebar layout | Account labels, long role chips, the open inline role picker and footer buttons fit at both 216 and 108 CSS pixels (200% zoom). Each individual button/chip and account-name width is measured; details below. |
| Service icons | Five real tabs with synthetic AWS console URLs render distinct bundled SageMaker, S3, Systems Manager, Lambda and Inspector pictograms, without remote image elements. The network gate blocks their page navigation; the error-page titles in screenshots are expected in this offline test. Icons fit at normal and 200% zoom. |
| Subtitle and Favorites | The small purpose subtitle sits below the brand. Distinct symbols/descriptions identify Active and Favorites; saving an active account and closing its tabs moves it to Favorites without duplication or losing its star. The outlined Favorites card and its controls fit at normal and 200% zoom. |

The subtitle/Favorites candidate reran **408 JavaScript tests** on Node 24.14.1 and **114 Python
tests** on Python 3.14.4. The unchanged helper also passed Python 3.12.13 during
the preceding pre-test closure. Python's
synthetic loopback test used authorized execution outside the tool's socket
restriction. Python 3.10 was tested in the historical September 5 run, not this
run; its hosted CI matrix remains a separate release gate.

## Resolved finding: narrow-sidebar content and controls were clipped

The September 5 run found a long role-choice button outside the 216 CSS-pixel
viewport. At 200% zoom (108 CSS pixels), account-name widths were zero and
close-all, role-choice and refresh controls extended outside the viewport.

The September 8 CSS-only correction lets narrow account headers and footers
wrap, reserves usable account-label space, and constrains long role chips and
role-option buttons. Normal-width rows keep their arrangement. No account,
role, permission, storage or session logic was changed in this correction.

Root `scrollWidth === clientWidth` is not sufficient here: the page intentionally
hides overflow. The final harness measures individual account labels and buttons
and reports a finding instead of declaring the visual test passed. Headless
chrome screenshots also appear to omit part of the remote-frame zoom transform;
layout measurements are independently confirmed by native DOM geometry, not
inferred from that image alone. Screenshots at normal zoom were also inspected.

Both subtitle/Favorites Firefox runs measure account-name widths of **119.68–131.68 CSS pixels**
at normal zoom and **46.5–58.5 CSS pixels** at 200%, with zero out-of-viewport buttons,
role chips, section labels/descriptions or brand subtitles. The same assertions pass with all three inline role-picker
controls present. Native role-picker keyboard behavior is tested separately;
the docked layout-only check activates its real DOM click handler.

Frozen artifact: `artifacts/acceptance-1.2.0-ea34e47c0e75/containoodle-1.2.0.xpi`.
SHA-256: `ea34e47c0e7534076fe6387eea8ee310e15b26c4f19d8d0e841ff6d921f0b5c4`.
The harness records and verifies this digest before and after each run and checks
the installed name/version. This supersedes earlier 1.2.0 build hashes.

## Safety and evidence

- No AWS sign-in, real AWS configuration/cache/helper-token reads, or live AWS
  requests. The normal local helper was not contacted.
- A rejecting HTTP/HTTPS proxy starts before Firefox. A verified browser channel
  gate allows only the ephemeral synthetic helper origin before installation.
  External and unrelated loopback requests are tested as blocked. This is
  browser HTTP(S) containment, **not** a claim of operating-system-wide isolation.
- Both profile and cache directories are checked to be inside the owned temporary
  directory. Saved Firefox profile-registration files are checked by metadata
  only and remain unchanged. No default-profile/signature preference was changed.
- Owned Firefox/helper processes are stopped and their temporary directories
  removed. Screenshots and reports contain only synthetic data.
- Previous subtitle/Favorites evidence: `artifacts/firefox-offline-2026-09-08T11-33-17-443Z/`
  (Firefox 155.0.1) and `artifacts/firefox-offline-2026-09-08T11-33-21-765Z/`
  (Developer Edition 156, including the slow deadline). Each has `report.json`
  and screenshots; both report `automationCompleted: true` and `passed: true`.
  The `native-docked-active-favorites.png` screenshot shows the new sections.
- The previous icon candidate's passing evidence remains at
  `artifacts/firefox-offline-2026-09-08T11-19-53-387Z/` and
  `artifacts/firefox-offline-2026-09-08T11-19-58-099Z/`; it predates the subtitle
  and Favorites styling/copy. The first UI package run at
  `artifacts/firefox-offline-2026-09-08T11-31-53-854Z/` passed before the final
  harness closed its role picker for the cleaner Favorites screenshot.
- The earlier pre-icon candidate's passing reports remain at
  `artifacts/firefox-offline-2026-09-08T10-27-06-389Z/` and
  `artifacts/firefox-offline-2026-09-08T10-27-02-360Z/`; they do not test the icons.
- Historical failing-layout evidence remains at
  `artifacts/firefox-offline-2026-09-05T06-56-10-850Z/` and
  `artifacts/firefox-offline-2026-09-05T06-56-16-095Z/`; it is not a current open
  finding. An initial September 8 regular-Firefox launch exited before connection;
  cleanup passed, and subsequent source and final XPI runs passed. That startup
  attempt is not counted as a completed test.

## Repeat without AWS

From this repository, with Node 24+, Python 3.10+ and the installed macOS Firefox:

```sh
node tests/firefox-offline.mjs --xpi artifacts/acceptance-1.2.0-449492d64c86/containoodle-1.2.0.xpi --skip-slow
node tests/firefox-offline.mjs --xpi artifacts/acceptance-1.2.0-449492d64c86/containoodle-1.2.0.xpi --firefox='/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox' --skip-slow
```

The harness is standalone and is not added to `npm test`. It requests no package
installation, signed installation, Git operation or publication. It creates its
own profiles; do not point it at a saved profile. It exits nonzero when assertions
fail **or** a measured layout finding exists. Without `--xpi` it installs source
instead, which is not evidence for a frozen package. `--probe` only checks
isolation, installation and initial state; it is not the full suite.

## Still needs live/distribution acceptance

The unchecked manual checklist in `TESTING_1.2.0.md` remains authoritative for:

- Real helper launch into the intended AWS account/role, SSO-profile selection,
  authenticated session reuse, and actual helper process restart/recovery.
- Real portal login/handoff, cookie-copy verification, pinned launch and live
  role discovery on the other laptop.
- Two authenticated AWS sessions remaining separate; cross-mode/account/role
  transitions never silently reusing the wrong identity.
- Signed same-ID upgrade and Firefox-restart persistence. A temporary
  XPI installation cannot establish those distribution properties.

No real AWS manual item has been marked passed, and nothing was published or
submitted to Mozilla.
