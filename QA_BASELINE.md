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
fixtures; it is not a real-Firefox end-to-end test. The three Python tests cover
only SSO token-expiry handling. The manual Firefox and non-production AWS gates
below remain necessary.

Phase 1 adds both complete v1.0.3 storage fixtures to `npm test`. The tests prove
that importing the background preserves the full migrated snapshot and that
install/update or startup removes only transient `tabGroups/*` entries,
including when the lifecycle event is repeated. These are synthetic storage
and WebExtension-event checks whose mocked browser APIs resolve immediately;
they are not proof of a same-ID Firefox update or delayed real-browser work.

## Stored-state compatibility contract

Unless a future change has an explicit, tested migration, an in-place upgrade
must preserve:

- all six `config` fields and the active connection mode;
- backend cache data, backend pins, and `backendRoleChoice/*` values;
- portal pins, captured portal names, `portalRoleChoice/*` values, and the
  cached portal region;
- both directions of every account/container mapping;
- manually saved `tabGroupTitle/*` values;
- migration markers and unrelated extension-local keys; and
- exact-origin, role-discovery, and session-reuse permission grants held by
  Firefox.

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
- [ ] Enable the exact portal origin, optional portal role discovery, and
  optional backend session reuse in the test profile.
- [ ] Make a second profile clone with the exact portal origin retained but
  both optional broad host grants revoked. The candidate must preserve both
  granted and revoked states without an unexpected permission prompt.
- [ ] Keep mapped containers and tabs open. Create one automatic group title
  and one manually renamed group, and save a group-name rule.
- [ ] Record a sanitized storage snapshot, `browser.permissions.getAll()`,
  container names/counts, open account tabs, and visible group titles. Do not
  export cookies or session URLs.
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
- [ ] Treat the Python result only as token-expiry coverage; it is not a helper
  integration result.

### In-place upgrade hard gate

- [ ] Perform the same-ID, higher-version update without closing the existing
  account tabs first.
- [ ] Confirm the version changes while active mode and stable storage values
  remain unchanged. In the granted clone, all three grants must remain; in the
  revoked clone, both optional grants must remain revoked without a prompt.
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
- [ ] Sign out or revoke the exact portal permission. Readiness must identify
  the missing condition, native portal navigation must remain available, and
  no wrong-container console tab may be created.

### Local-helper smoke gate

- [ ] In the dedicated non-production setup, use **Save & test** and confirm
  the helper URL and backend account cache/count.
- [ ] Confirm portal pins never appear in the helper list and helper pins never
  alter portal pins.
- [ ] Launch an account and verify the existing mapped container and group are
  reused.
- [ ] Select an explicit role and verify only `backendRoleChoice/*` changes.
- [ ] Pin and unpin accounts; names, roles, regions, and launch data must still
  come from the helper.
- [ ] With a controlled helper request counter, confirm an implicit-role repeat
  launch that reuses a live session makes no `/generate-url` request. An
  explicit-role launch must call `/generate-url` with that selected role.
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

### Live non-production acceptance gate

- [ ] Only after every local gate passes, start the real helper and run both
  launch paths against non-production AWS accounts. Verify the visible account
  ID and role.
- [ ] Keep two accounts open concurrently and confirm their sessions do not
  cross. Perform read-only console navigation only; no AWS resource change is
  needed.

Any lost stable state, unexpected permission change, stale cross-mode action,
wrong account or role, duplicate account container, or duplicate account group
blocks release.
