# Containoodle 1.2.0

## Highlights

- Guided first-run setup for AWS Access Portal or the optional local AWS CLI helper.
- Account-name rules now apply consistently to sidebar labels, automatic Firefox
  container names and tab-group titles; manual names remain unchanged.
- A clearer sidebar: AWS Console Containers subtitle, distinct Active/Favorites
  sections, original page favicons and improved narrow-width/keyboard behavior.
- Stronger helper validation, bounded requests and safer recovery from connection
  failures, with additional safeguards around session reuse and SSO identity changes.
- Expanded regression coverage and reproducible release packaging. English is the
  only shipped language; UI messages are prepared for future translation.

## Updating

Install normal signed updates through the
[Firefox Add-ons listing](https://addons.mozilla.org/firefox/addon/containoodle/).
AMO review and availability are separate from the GitHub release.

Local-helper users should update `server.py` from this release and restart it.
Keep your existing helper token and selected AWS CLI profile; no re-pairing or
token rotation is required solely for this update. Portal users do not need the
Python helper. Existing saved settings, favorites and containers are retained.

Favicons use the original image reported by Firefox. Eligible remote AWS images
are fetched without cookies/referrers or redirects; blocked/unavailable images
get a neutral placeholder. No new browser permission was added. See the updated
[privacy policy](PRIVACY.md) for the limited anonymous image requests.

The unsigned GitHub XPI is for temporary testing via `about:debugging` in an
isolated test profile, not normal installation. Do not change your main profile
or Firefox signature settings to install it.

## Validation and scope

The maintainer reported a successful test and authorized release on 2026-09-08.
Local release gates passed 416 JavaScript and 114 Python tests, extension lint
with zero findings, and byte-for-byte reproducible packaging. The accepted local
XPI SHA-256 is `449492d64c861808176530c981702fe86b6c7c8d878a37205631ed9b0d14e5a7`.
Actual Firefox 155.0.1 and Developer Edition 156 each passed 29 synthetic/offline
check groups. This is not an independent assertion that every live AWS workflow
or signed in-place update has been verified.

Release automation also publishes the tagged privacy disclosure to the existing
AMO listing. Its four additional synthetic tests do not change the accepted XPI.

The full dependency audit retains two explicitly contained build-only upstream
advisories, expiring 2026-10-05. These dependencies are not shipped in the XPI;
see [TOOLING_SECURITY.md](TOOLING_SECURITY.md). No claim of security certification
or Mozilla Recommended status is made.
