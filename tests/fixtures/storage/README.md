# v1.0.3 storage fixtures

These files are complete synthetic `browser.storage.local` objects used as
upgrade inputs:

- `portal-v1.0.3.json` starts in portal mode.
- `backend-v1.0.3.json` starts in local-helper mode.

Both use the same three-account topology: one shared account with different
mode-specific names and roles, one portal-only account, and one helper-only
account. Data owned by the inactive mode is present on purpose. An upgrade must
not merge, leak, or silently discard those pins, account names, or remembered
roles. The shared account retains one account-owned Firefox container.

In a storage-only migration test, compare `config`, mode-specific account and
pin data, `portalAccountOriginalName/*`, mode-specific role choices,
`accountContainer/*`, `containerAccount/*`, `tabGroupTitle/*`,
`portalRegionCache`, and migration markers exactly. In a browser-profile test,
stop or stub the helper and provide the matching contextual identities first:
a real account refresh may rewrite `accountsCache` and `accountsCacheAt`, while
a launch may remove a mapping whose Firefox container is absent.

`tabGroups/*` values are pre-upgrade observations, not stable identifiers.
v1.0.3 removes them on install/update and startup but does not rediscover a
still-visible group before creating the next one. Preserving the visible group
and `tabGroupTitle/*` is baseline behavior; reusing that open group without a
duplicate after update is a stricter candidate requirement and a known v1.0.3
gap.

`roleChoice/*` is an ignored legacy key that v1.0.3 leaves untouched. It is
included to detect overly broad storage deletion. A future release may remove
it only through an explicit, documented, and tested migration.

These JSON files cannot represent Firefox optional permissions, contextual
identities, open tabs, visible tab groups, or cookies. Record those separately
in a dedicated test profile. Never add real account data, cookies, access
tokens, credentials, or generated sign-in URLs to a fixture.

`npm test` now loads both complete snapshots. A static contract test validates
their three-account topology, coexistence of distinct mode-owned state,
symmetric one-to-one container mappings, safe group-name rule, and absence of
common session or credential markers. Background lifecycle tests then prove
that importing the current background preserves every value, while
install/update and startup remove only `tabGroups/*`; repeating either event is
idempotent and invokes no mocked tab creation, contextual-identity mutation, or
cookie write/removal.

This remains storage-only automation. Firefox permissions, contextual
identities, open tabs, visible groups, cookies, a signed same-ID update, and
real portal/helper behavior still belong to the manual test-profile gates.
