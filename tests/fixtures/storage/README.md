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

Phase 0 validates these files as JSON and through the production account and
group-name validators. They are not yet loaded by `npm test`; automating the
full install/migration assertions belongs to the next implementation phase.
