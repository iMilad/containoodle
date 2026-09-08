# Containoodle — reviewer guide

Version: 1.2.0, accepted by the maintainer for release on 2026-09-08. This guide
is not evidence of AMO approval or Recommended status. The frozen package and acceptance scope
are in [TESTING_1.2.0.md](TESTING_1.2.0.md); current native Firefox evidence is in
[FIREFOX_OFFLINE_TESTING.md](FIREFOX_OFFLINE_TESTING.md). Older phase records in
[QA_BASELINE.md](QA_BASELINE.md) are historical, not extra current development work.

## Purpose and scope

Containoodle helps people who work with several AWS accounts keep console tabs in
visibly named Firefox containers and groups. Its primary mode hands off a role
chosen in the user's AWS access portal; it needs no local helper or AWS CLI.
An optional Python helper supports locally authenticated AWS CLI SSO workflows.

Account-name rules affect sidebar labels and automatically managed container/group
names, not account identity, role selection, or user-supplied custom names. Account
ownership is keyed by account ID and Firefox cookie-store ID, never display name.

The sidebar labels saved shortcuts **Favorites** (formerly **Pinned accounts**).
They are separate from **Active**, which means accounts with open tabs, not proof
of a live authenticated AWS session. Symbols, explanatory text and separate card
styling distinguish them without relying only on colour. Related Options/action
copy uses the same name; storage keys and message APIs still use their existing
pin identifiers, with no data migration, new permission or behavioral change.

## Source and repeatable checks

Use Node.js 24 LTS, Python 3.10 or newer, and `zip`/`unzip`:

```sh
npm ci --ignore-scripts
npm run audit:dependencies
npm run build-for-amo
```

The commands audit build/runtime dependencies, run JavaScript and isolated Python
tests, lint the extension, and build `artifacts/containoodle-1.2.0.xpi`. They do not
sign, upload, or publish. Tests use synthetic identities, isolated filesystem
fixtures, mocked AWS/HTTP calls, and one ephemeral loopback concurrency test; they
do not require a real AWS login, helper token, or browser profile. Registry access
is required for the dependency audit. The XPI contains only the explicit 21-file
allowlist; independently staged archives must match byte-for-byte and by hash.

Readable JavaScript is shipped directly; there is no minification, downloaded
runtime code, telemetry, or hosted Containoodle service. The optional `server.py`
is separate from the XPI. See [TOOLING_SECURITY.md](TOOLING_SECURITY.md) for the
known unpatched build-parser advisories and scoped, expiring containment.

Sidebar icons use Firefox's reported `favIconUrl`, not custom service drawings.
`shared/service-icons.js` accepts embedded image data (including SVG, rendered
only as passive `<img>` content) and browser-local extension icons. Remote icons
require an actual AWS console/Studio tab, HTTPS on an AWS console or `awsstatic.com`
host, a static image path and no query, credentials or nondefault port. Fetch
uses `credentials: omit`, `referrerPolicy: no-referrer`, `redirect: error` and CORS.
Responses are limited to image MIME types, 64 KiB streamed bytes and five seconds;
the memory-only cache holds at most 64 entries with five-minute success/30-second
failure expiry. Missing, blocked and invalid images fall back without affecting
tab actions. There is no authenticated retry, third-party favicon service, remote
SVG DOM insertion, new host permission, dependency, or manifest-image/parser
allowance. URL classification is decorative, never account/session authorization.
The privacy policy discloses the limited anonymous AWS image requests.

## Security and permissions to review

- Core portal access is requested only for the configured exact portal origin.
  Broad optional host declarations provide the manifest's allowable ceiling and
  legacy compatibility, not an automatic runtime grant.
- Pinned-account role discovery is separate and optional: one regional portal API
  origin. Helper reuse is separate and optional: console-cookie hosts. Declining
  either does not block the main launch path. Legacy broad permissions only
  migrate after explicit user action; passive loading never grants access.
- Container APIs isolate cookie jars; tab/group APIs organize account tabs;
  storage retains settings, pins, validated account metadata, and helper pairing
  material locally. Scripting is scoped to the configured portal handoff.
- Portal mode copies a powerful SSO cookie into the account container. That
  credential can reach all accounts the SSO user is entitled to, not only the
  account being displayed. Its scope and expiry are preserved, and the copy is
  checked before navigation. This accepted trade-off is documented, not hidden.
- Protected helper routes require challenge-bound HMAC request and response proofs. The
  secret is never transmitted over loopback. SSO selection rejects ambiguous
  identities and keeps the SSO region distinct from the console destination.
  This does not defend against malware with the same OS user's file access.
- Helper session reuse requires verified per-container generation ownership.
  Portal transitions and overlapping unfinished sign-ins invalidate or fence
  reuse. Verification authority is limited to the current background lifetime;
  a background restart triggers fresh federation and recovers unresolved tabs.
  Timeouts fail closed and preserve the last valid connection/cache.

See [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md) for retention, disclosures,
limitations, and private vulnerability reporting. Installation data-category
disclosures describe data handled locally; they are not a telemetry claim.

## Interactive review

Use an isolated Firefox test profile and [TESTING_1.2.0.md](TESTING_1.2.0.md). Do not
change the default/main profile or relax signature settings. Portal testing needs
an authorized non-production AWS SSO environment; helper testing additionally
needs its local CLI setup. The offline tests cannot demonstrate AWS's live portal
DOM or browser cookie behavior. If reviewers require access, arrange a dedicated,
least-privileged review environment privately through the submission process;
never put credentials, live URLs, IDs, or role names in public artifacts.

Keyboard checks should include collapsed account sections, tab switching and
closing, role choices, focus during account refresh, and notification actions.
The English catalog is translation-ready, but English is the only shipped locale;
do not describe it as a multilingual release or a completed accessibility audit.

## Release and nomination gates

The maintainer reported a successful test and authorized release on 2026-09-08.
User acceptance, hosted CI, reviewed commit/merge, and the
signed in-place update check remain distinct from local automated checks. Do not
mark deferred checks as passed. Resolve account/role/session or state-loss failures
before publishing. After the accepted version is available on AMO, verify its
listing and use the prepared [nomination draft](MOZILLA_NOMINATION.md).

Mozilla's [Recommended criteria](https://extensionworkshop.com/documentation/publish/recommended-extensions/)
include exceptional functionality, safety, user experience, international
relevance, and active maintenance. Containoodle has a specialized professional
audience and no measured adoption evidence yet. Curated selection remains
Mozilla's decision; test counts alone cannot establish eligibility.
