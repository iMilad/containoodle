# Containoodle v1.0.3 compatibility baseline

Captured on 2026-08-19 before compatibility or hardening work. This is the
rollback and upgrade reference for the next release; it does not claim that the
live checks below have been run.

Phase 0 made no extension, helper, manifest, permission, workflow, or packaging
change. No Firefox profile, local helper, AWS session, Git history, GitHub
release, or AMO listing was modified or contacted while recording this
baseline.

## Frozen release identity

| Item | Baseline |
|---|---|
| Version | `1.0.3` in the manifest, package, and package lock |
| Git tag | Annotated tag `v1.0.3` |
| Commit | `d5ae978fc1f421130181ff6181c688ee1e6b9378` |
| Tree | `8d1af653725d9cc407de10a245e65ebda6cd85e1` |
| XPI | `artifacts/containoodle-1.0.3.xpi`, 65,020 bytes |
| XPI SHA-256 | `15c1ffe6a489498156417e0c94c0759ca3f644b744d8919ef864cd80b9410af2` |

The ignored local XPI passed its ZIP integrity check. Its 16 entries all
matched the extension source byte-for-byte:

```text
background.js
icons/icon-48.png
icons/icon-96.png
manifest.json
options/options.css
options/options.html
options/options.js
portal-interceptor.js
shared/accounts.js
shared/backend.js
shared/group-naming.js
shared/portal.js
sidebar/env.js
sidebar/sidebar.css
sidebar/sidebar.html
sidebar/sidebar.js
```

A fresh build from a temporary `git archive v1.0.3` produced the same hash and
was byte-identical to the local XPI. The build script uses an explicit file
order, normalizes timestamps and file modes, and enforces the list above. Exact
reproducibility was verified with the current local Node/Info-ZIP toolchain; it
was not tested across platforms. The GitHub Release and AMO copies were not
downloaded for a live comparison.

## Automated baseline

These checks passed against the frozen v1.0.3 tracked source:

- `npm test`: 100 JavaScript tests and 3 Python tests passed.
- `npm run lint:ext`: 0 errors, 0 notices, and 0 warnings.
- Node.js: `v22.22.3`.
- Python: `3.14.4` was selected explicitly for the full baseline run because
  the supported range is 3.10 or newer; the Python suite was also repeated
  successfully with `3.11.15` after the Phase 0 files were added.

The JavaScript suite runs production modules against synthetic browser and DOM
fixtures; it is not a real-Firefox end-to-end test. At the frozen v1.0.3
baseline, the three Python tests cover only SSO token-expiry handling. Later
phases expand that characterization without replacing the manual Firefox and
non-production AWS gates below.

Phase 1 adds both complete v1.0.3 storage fixtures to `npm test`. The tests prove
that importing the background preserves the full migrated snapshot and that
install/update or startup removes only transient `tabGroups/*` entries,
including when the lifecycle event is repeated. These are synthetic storage
and WebExtension-event checks whose mocked browser APIs resolve immediately;
they are not proof of a same-ID Firefox update or delayed real-browser work.

Phase 2 expands the current Python suite from the frozen three-test baseline to
41 deterministic helper tests. They characterize SSO cache selection and
expiry, exact AWS CLI contracts and failure handling, federation URL encoding,
account lookup, CORS/JSON transport, and every HTTP route without starting the
server. AWS subprocesses, federation requests, home-directory paths, and socket
I/O remain mocked; this is not a live AWS or helper integration test.
Valid JSON with a malformed account schema remains a later input-hardening gap,
not behavior that Phase 2 freezes as acceptable.

Phase 3 is an intentional strict local-helper protocol change. The candidate
uses synchronized manifest, package, and package-lock version `1.1.0`; the
frozen table above remains the `1.0.3` rollback reference. The candidate
creates a persistent 256-bit helper access token outside the checkout and
requires a fresh proof derived from it on `/accounts`, `/roles`, and
`/generate-url` before account files, the AWS CLI cache, subprocesses, or
federation code are reached. The extension
stores its copy under the separate `backendAuthToken` key but never transmits the
saved value. Each logical request verifies a signed, short-lived helper challenge,
sends a single-use HMAC proof bound to the exact request target, loopback Host, and
Firefox-extension Origin, then verifies a proof over the exact response bytes and
status before parsing them. OPTIONS remains unauthenticated because CORS preflight
cannot carry the request proof, but it requires the exact helper Host and a
Firefox-extension Origin. These are mocked protocol tests, not a real-Firefox CORS
or socket test. The Phase 3 candidate suite currently reports 143 JavaScript
tests and 72 Python tests; the Python protocol tests remain socket-free and run
with filesystem, subprocess, AWS, federation, and home-directory access isolated.

The frozen v1.0.3 state has no helper access token. Phase 3 deliberately fails
every helper request and new helper-generated session closed until the token is
entered and successfully tested; there is no legacy unauthenticated helper
fallback. A mapped, still-signed-in Firefox container may continue through the
separately granted session-reuse path because that path does not call the helper.
The old extension/new helper and new extension/old helper combinations are
intentionally incompatible, so both pieces must be updated together. Portal mode
remains usable: portal-specific paths must not look up the helper token by its
storage key, call the helper, or attach that token to any request.

Phase 4 replaces filesystem-recency SSO selection with one deterministic,
backend-only identity contract. An optional AWS CLI profile resolves either the
modern `sso_session` cache namespace or the legacy inline `sso_start_url`
namespace; the helper reads the exact corresponding token and never falls back
to another identity. With no profile, compatibility remains only when exactly
one distinct usable cached login exists. Multiple identities, malformed cache
metadata, an expired or near-expiry token, or a changed opaque identity key fail
before AWS CLI or federation work. The helper honors `AWS_CONFIG_FILE` and never
moves, rewrites, or deletes AWS CLI cache files.

The extension stores the profile alias and opaque token-bound identity key under
separate backend-only keys. Remembered backend roles are scoped to that key. A
live container is reusable only after the exact helper-generated federation tab
finishes on an AWS Console page in the expected container and the helper URL,
token, profile, identity, and account/container mappings still match. A failed,
removed, timed-out, or stale navigation leaves the previous reuse marker intact.
Portal mode, permissions, `accounts.json`, pins, and the six shared `config`
fields are unchanged.

The Phase 4 candidate suite reports 161 JavaScript tests and 91 Python tests,
clean extension lint, and a successful deterministic XPI build. These remain
mocked safety/contract checks; live profile selection and completed-console reuse
still require the sequential non-production smoke gate below.

Phase 5 tightens the two optional AWS host grants at runtime. Portal role
discovery now requests only the exact detected or configured regional target,
`https://portal.sso.<region>.amazonaws.com/*`. Backend session reuse now requests
`https://*.console.aws.amazon.com/*`, excluding sibling `aws.amazon.com`
services. The transitional manifest still declares the legacy broad optional-host
ceilings so an existing installation can migrate; declaring an optional ceiling
does not grant it. Runtime authorization uses only the narrow feature target.

Existing `https://*.amazonaws.com/*` and `https://*.amazon.com/*` grants remain
effective during migration. Phase 5 never changes them on startup, extension
update, Options load, or a normal mode switch. A legacy grant is removed only
as part of the user's corresponding **Allow**/**Tighten access** migration after
a fresh literal-permission inventory proves Firefox stored the narrow replacement.
The explicit **Revoke** action instead removes that feature's recognized grants
directly. If Firefox treats the broad grant as coverage and does not add the
narrow literal, Containoodle preserves the broad grant and tells the user to
choose **Revoke**, then **Allow** again.

A synthetic Firefox permission-scope gate passed in fresh temporary profiles on
Firefox Release 149.0 and Firefox Developer Edition 155.0. With only
`https://*.console.aws.amazon.com/*`, the production-shaped AWS Console cookie
operations needed for reuse succeeded, including the parent-domain consent
cookie, while a synthetic sibling `aws.amazon.com` service remained denied. The
negative control denied every AWS cookie operation; the legacy broad grant also
allowed the sibling, demonstrating why it is broader. The harness used only
synthetic cookies and containers, made no AWS navigation or login, and used no
account or role data. This gate verifies the tested Firefox versions' permission
and cookie behavior; it is not evidence for Firefox 142 through 148. Real AWS
portal and helper smoke testing remains deferred to the manual non-production
acceptance gate below.

## Stored-state compatibility contract

Unless a future change has an explicit, tested migration, an in-place upgrade
must preserve:

- all six `config` fields and the active connection mode;
- backend cache data, backend pins, and `backendRoleChoice/*` values;
- portal pins, captured portal names, `portalRoleChoice/*` values, and the
  cached portal region;
- both directions of every account/container mapping;
- manually saved `tabGroupTitle/*` values;
- migration markers, `backendSessionReuseAutoOfferHandled` once set, and
  unrelated extension-local keys; and
- exact-origin, role-discovery, and session-reuse permission grants held by
  Firefox.

After Phase 3 setup, `backendAuthToken` is also stable local state. It must survive
startup and extension updates, but its real value must be redacted entirely from QA
snapshots, logs, screenshots, issues, and test fixtures.
`backendSessionReuseAutoOfferHandled` records only that the one-time permission
offer was handled; Firefox's optional host permission remains the authoritative
session-reuse enabled state.

After Phase 4 setup, `backendSsoProfile` and `backendSsoIdentityKey` are also
stable local state. The profile is only a local AWS CLI alias; the identity key
is an opaque HMAC value and must not be decoded or treated as AWS metadata.
Identity-scoped `backendRoleChoice/<identityKey>/*` and
`backendContainerIdentity/*` values must survive startup and updates. Older
unscoped backend-role values are preserved but ignored while a trusted identity
key is active.

Phase 5 binds `portalRegionCache` to the exact saved portal origin with
`portalRegionCacheOrigin`. An older unbound or wrong-origin cache is ignored and
redetected rather than trusted as a permission target. This safe invalidation
must not alter portal pins, roles, or the saved portal URL.

`tabGroups/<accountId>/<windowId>` is the deliberate exception: the numeric
Firefox group IDs are transient and v1.0.3 removes these storage entries on
install/update and startup. It preserves the visible Firefox group and the
manual `tabGroupTitle/*`, but it does not rediscover that open group before the
next launch. Avoiding a duplicate and rejoining the open group is therefore a
stricter candidate requirement and a known v1.0.3 gap, not frozen baseline
behavior.

The synthetic raw-storage snapshots are:

- [`tests/fixtures/storage/portal-v1.0.3.json`](tests/fixtures/storage/portal-v1.0.3.json)
- [`tests/fixtures/storage/backend-v1.0.3.json`](tests/fixtures/storage/backend-v1.0.3.json)

Each fixture deliberately retains state owned by the inactive mode. This makes
cross-mode loss or leakage visible during an upgrade. All identities, URLs,
roles, container IDs, window IDs, and group IDs are synthetic. Cookies, access
tokens, credentials, and session URLs are not storage fixtures and must never be
captured.

## Manual upgrade checklist

Status: **not executed during Phase 0**. Establish the mode-specific smoke
baseline on v1.0.3, then repeat it after a real in-place candidate update. The
upgrade-only checks are explicitly identified below.

### Safety and preparation

- [ ] Use Firefox 142 or newer, a dedicated closed-and-cloned test profile, and
  non-production AWS accounts.
- [ ] Never uninstall between baseline and candidate; uninstalling removes
  extension-local storage. Use a fresh copy of the closed baseline profile for
  every retry or rollback.
- [ ] Use a signed candidate or a permanent unsigned install in Firefox
  Developer Edition/Nightly. Keep the manifest's Gecko ID unchanged, use a
  higher version, and verify Firefox performs an update. A temporary add-on or
  remove/reinstall cycle cannot prove restart or storage preservation.
- [ ] Prepare one account available through both modes with different roles,
  one portal-only pinned account, and one helper-only pinned account.
- [ ] Enable the exact portal origin, the exact regional role-discovery target,
  and the console-only backend session-reuse target in the test profile.
- [ ] Make a second profile clone with the exact portal origin retained but
  both optional host grants revoked. The candidate must preserve both
  granted and revoked states during update and startup without an unexpected
  permission prompt.
- [ ] Keep one upgrade clone with the legacy broad role-discovery and
  session-reuse grants so the explicit Phase 5 tightening flow can be tested.
- [ ] Prepare two fresh candidate profiles with no console permission and no
  `backendSessionReuseAutoOfferHandled` key: one for accepting the one-time
  backend offer and one for declining it.
- [ ] Keep mapped containers and tabs open. Create one automatic group title
  and one manually renamed group, and save a group-name rule.
- [ ] Record a sanitized storage snapshot with `backendAuthToken` omitted,
  `browser.permissions.getAll()`,
  container names/counts, open account tabs, and visible group titles. Do not
  export cookies, helper tokens, or session URLs.
- [ ] Stop or stub the helper before the before/after storage comparison so a
  cache refresh cannot be mistaken for an upgrade mutation. Start it only for
  the helper smoke gate.

### Offline gate

- [ ] Confirm the baseline tag, commit, manifest/package versions, extension
  ID, XPI file list, size, and hash against the table above.
- [ ] Run `npm test` with Python 3.10 or newer and run `npm run lint:ext`.
- [ ] Build twice from clean temporary exports and compare the two XPI hashes
  and file lists.
- [ ] Confirm `npm test` loads both complete storage fixtures, enforces their
  distinct three-account, mode-owned topology, and preserves the full state on
  background import.
- [ ] Confirm update and startup remove only `tabGroups/*`, preserve every
  other key, and remain idempotent when repeated.
- [ ] Treat the Phase 2 Python result as mocked helper characterization, not a
  live AWS, federation-endpoint, or socket-level integration result.
- [ ] Confirm the Phase 3 tests reject missing, malformed, duplicate, expired,
  replayed, and target/Host/Origin-mismatched challenges or proofs with the same
  generic 401 before filesystem/AWS work. Confirm altered or unsigned response
  bytes/status are rejected before JSON parsing or browser action.
- [ ] Confirm every extension helper call uses the central authenticated fetch
  path, while portal-mode tests perform no helper-token lookup or helper request.
- [ ] Confirm the Phase 4 tests resolve modern, legacy, default, and
  `AWS_CONFIG_FILE`-overridden profiles from synthetic files; reject ambiguous,
  malformed, expiring, mismatched, and changed identities before AWS work; and
  never modify the synthetic cache files.
- [ ] Confirm helper URL/profile/identity races cancel before browser mutation,
  remembered backend roles are identity-scoped, and reuse binding occurs only
  after the exact new sign-in tab completes on an AWS Console URL.
- [ ] Confirm the Phase 5 permission tests distinguish literal grants from
  wildcard coverage, request the exact feature target synchronously from the
  user's click, preserve a broad grant when Firefox stores no narrow literal,
  and roll back only a newly added narrow grant after a stale mode or target-context
  revision.

### In-place upgrade hard gate

- [ ] Perform the same-ID, higher-version update without closing the existing
  account tabs first.
- [ ] Confirm the version changes while active mode and stable storage values
  remain unchanged. In the granted clone, all three grants must remain; in the
  revoked clone, both optional grants must remain absent during update and
  startup without a prompt. No permission may change unless the tester accepts
  a Firefox permission request.
- [ ] On a frozen v1.0.3 backend profile, attempt a helper-required launch with
  no reusable mapped live session. Confirm the candidate clearly reports that a
  helper access token is required and makes no helper request or console tab
  before setup. This one new missing-key state is intentional.
- [ ] After the storage comparison, use `server.py --show-token`, save and test
  the token once, and confirm subsequent update/startup cycles preserve it
  without placing it back into the password field.
- [ ] In the granted upgrade clone, the first backend **Save & test** must retain
  the existing legacy session-reuse grant without showing a redundant prompt and must
  record `backendSessionReuseAutoOfferHandled` as `true`.
- [ ] In the revoked upgrade clone, if
  `backendSessionReuseAutoOfferHandled` is absent, the first backend **Save &
  test** must present the expected one-time offer. Decline it and confirm the
  permission stays absent, the marker becomes `true`, and later **Save & test**
  operations do not prompt again. This user-triggered offer is not an
  update/startup permission mutation.
- [ ] Without clicking a permission control, open Options, restart Firefox,
  update the extension, and switch modes in both directions. The literal
  permission inventory must remain unchanged and no prompt may appear.
- [ ] In the legacy-grant clone, choose the backend and role-discovery
  **Tighten access** actions separately. If Firefox stores the requested narrow
  literal, confirm only that feature's recognized legacy broad grant is removed.
  If Firefox reports coverage but leaves only the broad literal, confirm the
  broad grant is preserved and the status instructs **Revoke**, then **Allow**
  again. Declining or an API error must remove nothing.
- [ ] Confirm existing tabs remain in their original containers and no
  duplicate same-name container appears.
- [ ] Confirm backend and portal pins, account names, and remembered roles stay
  separate.
- [ ] Confirm the manual group title remains unchanged.
- [ ] Launch another tab for an account whose group stayed open. It must join
  the existing visible group; a second group for that account is a failure.
- [ ] Restart Firefox and repeat the container/group reuse check.
- [ ] Compare sanitized before/after snapshots. Permit only a documented and
  tested migration, removal of transient `tabGroups/*`, and expected volatile
  cache timestamps.

The open-group check is especially important. v1.0.3 clears stored
`tabGroups/*` mappings on `runtime.onInstalled` even though Firefox may keep the
visible group, then creates a new group on the next launch because it has no
rediscovery path. The no-duplicate check is deliberately stricter than the
v1.0.3 baseline and is expected to require a later implementation change.

### Fresh-profile one-time session-reuse offer gate

- [ ] In both fresh profiles, confirm `https://*.console.aws.amazon.com/*` is not granted
  and `backendSessionReuseAutoOfferHandled` is absent before backend setup.
- [ ] Choose the first backend **Save & test** in the acceptance profile. The
  Firefox request for `https://*.console.aws.amazon.com/*` must begin directly from that
  click, without waiting for the helper result. Accept it, complete a valid
  helper test, and confirm the permission is present, session reuse is enabled,
  and `backendSessionReuseAutoOfferHandled` is `true`.
- [ ] Repeat **Save & test** and restart Firefox. The accepted profile must stay
  enabled without another prompt.
- [ ] Choose the first backend **Save & test** in the decline profile, decline
  the Firefox request, and confirm the helper URL, token, and
  account cache are still saved successfully. The console permission must remain
  absent and `backendSessionReuseAutoOfferHandled` must be `true`.
- [ ] Repeat **Save & test**, refresh accounts, launch through the helper, and
  restart Firefox. Normal helper mode must remain functional and the automatic
  permission prompt must not return.
- [ ] Choose **Allow session reuse** in the declined profile, accept Firefox's
  request, and confirm reuse becomes enabled. Then choose **Revoke**, confirm the
  permission is absent, and verify later **Save & test** operations do
  not automatically prompt again. The manual **Allow session reuse** control must
  remain available.

### Portal-mode smoke gate

- [ ] Confirm the saved portal URL, exact-origin permission, active mode, and
  readiness status survive the upgrade.
- [ ] Close every normal default-container tab for the configured portal. Use
  **AWS Portal**, record the new tab, then use it again and verify that exact
  tab is focused rather than another tab being opened.
- [ ] Click a non-production account and role. Verify the exact account, role,
  and destination; existing mapped container; expected environment color; and
  existing per-window group.
- [ ] Launch the same account again and confirm no duplicate container or group
  appears.
- [ ] Pin the active account, close its tabs, launch the pin with its saved
  portal role, then unpin it without removing its tabs or container.
- [ ] Confirm automatic naming follows the saved rule and the manual title
  remains manual.
- [ ] Revoke optional role discovery. Normal portal clicks must still work,
  saved pin roles must remain, and live role changes must request permission.
  Re-grant it and verify choices return.
- [ ] Inspect the role-discovery request after the portal region is known. It
  must be exactly `https://portal.sso.<region>.amazonaws.com/*`; a grant for a
  different region must not authorize the regional role API call. Clear or
  change the saved portal and confirm an unbound or wrong-origin cached region
  is redetected before any target is offered.
- [ ] Sign out or revoke the exact portal permission. Readiness must identify
  the missing condition, native portal navigation must remain available, and
  no wrong-container console tab may be created.

### Local-helper smoke gate

- [ ] In the dedicated non-production setup, run `python3 server.py --show-token`,
  start the helper normally, paste the token once, then use **Save & test** and
  confirm the helper URL and backend account cache/count. The displayed token
  must not be captured in QA output.
- [ ] Confirm missing, malformed, and wrong tokens fail clearly before
  `accounts.json`, the AWS CLI cache, AWS CLI subprocesses, or federation calls.
  A failed replacement must preserve the last working URL, token, and cache.
- [ ] Confirm the Options password field is empty after reload and a stored-token
  status is shown without displaying the value.
- [ ] Enter the same local alias used for the dedicated non-production
  `aws sso login --profile ...`, choose **Save & test**, and confirm the alias is
  retained without displaying any token, cache path, start URL, or identity
  metadata. Do not record the real alias in QA output.
- [ ] With exactly one usable cached login, confirm a blank profile still works.
  With more than one, confirm setup fails clearly until a profile is selected;
  it must never use whichever cache file was touched most recently.
- [ ] If a protocol-capable no-Origin diagnostic is exercised, confirm it fails
  without a fresh valid challenge/request proof and succeeds with one. The saved
  helper secret itself must never appear in the URL, headers, or body.
- [ ] Confirm portal pins never appear in the helper list and helper pins never
  alter portal pins.
- [ ] Launch an account and verify the existing mapped container and group are
  reused.
- [ ] Select an explicit role and verify only `backendRoleChoice/*` changes.
- [ ] Pin and unpin accounts; names, roles, regions, and launch data must still
  come from the helper.
- [ ] With a controlled helper request counter, confirm an implicit-role repeat
  launch authenticates `/sso-identity` but makes no `/generate-url` request once
  that exact identity's completed sign-in is eligible for reuse. An explicit-role
  launch must call `/generate-url` with that selected role.
- [ ] Change the selected profile or cached login. The previous identity's live
  session and remembered role must be ignored. If the replacement federation
  navigation fails, closes, times out, or lands outside AWS Console, the next
  launch must generate another sign-in rather than trusting the old container.
- [ ] Revoke session-reuse permission and confirm a normal helper launch still
  succeeds.
- [ ] Stop the helper. Cached accounts, pins, and roles must remain; launch must
  fail clearly without creating a console tab.
- [ ] Exercise expired-token and unavailable-role failures against
  non-production data. Neither may open a wrong or partial session.

### Mode-switch race gate

- [ ] With a controlled delayed fake helper, switch to portal before pending
  helper refresh, launch, and pin replies resolve. No helper tab or pin may
  appear and portal state must remain visible.
- [ ] Switch to helper before a pending portal action resolves. The stale
  portal action must not alter the helper view.
- [ ] Switch normally in both directions. Each mode must restore its own pins
  and roles, the shared account must keep its mapped container, and one mode
  must not revoke the other mode's optional permission.
- [ ] While portal mode is active, changing or removing `backendAuthToken` must
  not trigger a helper request or affect portal readiness, pins, or launch flow.

### Live non-production acceptance gate

Status: **deferred/manual for Phase 5**. The Firefox 149.0/155.0 synthetic scope
gate above does not replace these real portal and helper checks.

- [ ] Only after every local gate passes, start the real helper and run both
  launch paths against non-production AWS accounts. Verify the visible account
  ID and role.
- [ ] Validate the custom proof-header preflight in real Firefox: Save & test,
  account refresh, role discovery, and URL generation must all succeed with the
  stored token and fail closed after a controlled token rotation.
- [ ] Stop the real helper and place a controlled fake listener on the configured
  loopback port. It may echo the Firefox Origin, but without a valid signed
  challenge the extension must not send a protected request, accept account data,
  create a container, or open a tab.
- [ ] Keep two accounts open concurrently and confirm their sessions do not
  cross. Perform read-only console navigation only; no AWS resource change is
  needed.

Any lost stable state, unexpected permission change, stale cross-mode action,
wrong account or role, duplicate account container, or duplicate account group
blocks release.
