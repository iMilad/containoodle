# Containoodle 1.2.0 — one manual acceptance round

Status: maintainer accepted the frozen candidate and authorized release on
2026-09-08, reporting that their test was all good. This is user-reported
acceptance, not an independent claim that every individual checklist item was
observed. The detailed boxes remain unchanged where no item-specific result was
recorded. Signed publication/update results remain separate from local testing;
check the AMO listing for current distribution status.

The local add-on display name is now **Containoodle — AWS Console Containers**.
The version remains 1.2.0, and the extension ID and compact sidebar name remain
unchanged. The final preparation also fixes narrow-sidebar layout; it does not
change account, role, permission, or session logic.

Use this one frozen package for acceptance:
[containoodle-1.2.0.xpi](artifacts/acceptance-1.2.0-449492d64c86/containoodle-1.2.0.xpi).
Its SHA-256 is
`449492d64c861808176530c981702fe86b6c7c8d878a37205631ed9b0d14e5a7`.
This replaces the `ea34e47c0e75` candidate's custom service drawings with original
page favicons and a neutral fallback. The subtitle/Active/Favorites layout is
unchanged. Earlier frozen packages remain intact for comparison/rollback.
The matching checkout helper, `server.py`, has SHA-256
`24680bf66ba7a9a6c86eb0bcb299ea5fd62c514bcb81fc9ed6a4e60662d906b1`.
Do not rebuild or change this candidate during acceptance; a needed fix gets a
new recorded package and an affected-test rerun.

Current AWS-free Firefox evidence is in
[FIREFOX_OFFLINE_TESTING.md](FIREFOX_OFFLINE_TESTING.md). The earlier sidebar
finding is resolved. No live AWS or signed-update item below is marked passed
by those runs. The build-only security exception has been re-reviewed, not
removed; see [TOOLING_SECURITY.md](TOOLING_SECURITY.md).

The agreed local development work and maintainer acceptance are complete. The
release/nomination sequence follows, not another feature phase. Old phase
checkboxes in `QA_BASELINE.md` are historical evidence, not an additional current
to-do list. Only this checklist governs the current manual acceptance round.

## What changed

- First-run setup guides you to portal or helper mode. Completing setup hides the
  guide; existing configured installations keep their normal view.
- One account-name regex now applies to sidebar accounts, automatic containers,
  and automatic tab groups in both modes. Manual names and account/session identity
  remain separate from these display labels.
- The helper rejects malformed account files before AWS access, bounds AWS CLI
  and federation operations, and gives safe errors. The persistent helper token
  and your selected AWS CLI profile work as before.
- Options and sidebar text use an English message catalog. No additional language
  is shipped, no new permissions are added, and background/helper diagnostics can
  still be English.
- CI and packaging have stronger gates. These do not change your browser setup.
- SSO API requests use the selected identity's SSO region, independently of the
  console destination region. Idle helper connections no longer block every
  request; full extension exchanges time out with a recoverable message.
- Session reuse checks a new verified container generation. The first helper
  launch after upgrading or a background restart signs in again; no token reset
  is needed. Portal launches
  and unresolved older sign-in tabs prevent unsafe helper reuse.
- Sidebar sections and tabs work with the keyboard, tab close is a separate
  control, refresh preserves focus, and muted labels have stronger contrast.
- At narrow widths, account names/actions, long role labels and footer controls
  wrap inside the sidebar, including at 200% zoom.
- Tabs show their original Firefox-reported favicon, including embedded SVG.
  Static AWS image requests omit cookies/referrers, refuse redirects and never
  fall back to authentication. No permission is added. Unavailable/blocked icons
  use a small neutral placeholder instead of a custom colored service drawing.
- The small subtitle **AWS Console Containers** sits below Containoodle.
  **Pinned accounts** is now called **Favorites**, including related filters,
  star-button labels and Options text. **Active · Open tabs now** has a cool
  accent; **★ Favorites · Saved shortcuts · no open tabs** is a separate warm
  outlined card. Favorites with open tabs still appear only in Active, then
  move back to Favorites after their last tab closes. Storage keys and account
  classification are unchanged; this does not reset or migrate saved favorites.

## Keep your working Firefox profile safe

Use the **existing `Containoodle-test` profile** for this round. Do not remove an
extension from your main profile, delete/reset a profile, change the default
profile, or change Firefox signature settings. Your main `dev-edition-default`
profile is not part of this procedure.

If the test-profile window is already open, keep using it. Otherwise open
`about:profiles` and use **Launch profile in new browser** for `Containoodle-test`,
not **Set as default profile**. If you are unsure which window is the test profile,
stop before changing anything and ask.

In that test window, open `about:debugging` → **This Firefox**. If Containoodle is
already loaded temporarily, load the frozen XPI above through **Load Temporary
Add-on** to replace that temporary copy with the exact candidate. Otherwise use
the same button to install it. Do not rely on **Reload** of an older XPI: several
local candidates share version 1.2.0. Confirm **1.2.0** in the sidebar and the
full display name in the add-on details. A temporary extension disappears when
Firefox restarts; do not restart Firefox as an acceptance step.

For helper checks, stop your currently running helper normally, then run the
updated `python3 server.py` from this checkout. Keep your existing helper token;
there is no need to rotate it or run `--show-token` again when it is already saved.
Do not edit your real account file to manufacture failure cases.

## Check these once, in order

You can split the round across your existing test laptops: helper checks on the
helper laptop; portal checks on the portal laptop. Do not sign in to the portal
on a laptop where you do not want AWS access. The cross-mode part of item 9 needs
an environment where both methods are available; if none is available, record
that part as deferred rather than passed.

Use only accounts you are authorized to test, preferably non-production, and
read-only console navigation. Do not change AWS resources. Check account/role
identity privately; report only pass/fail and sanitized symptoms, never IDs,
role/profile names, tokens, cookies, or sign-in URLs.

1. [ ] **Existing state:** version is 1.2.0; saved settings, pins, and account
   containers in the test profile remain. Opening Options alone does not request
   new permissions or launch a console session.
2. [ ] **Finish setup, if the guide is present:** choose one connection method.
   That choice only opens its settings. For portal mode, save/grant the portal and
   sign in, then refresh readiness. For helper mode, use **Save & test**. After
   success the guide disappears and the normal sidebar returns. Reopening Options
   does not bring it back. If this test profile already completed setup, do not
   clear storage to force the guide back; mark this item "already configured".
3. [ ] **Portal launch:** open an account and role through the portal. It lands in
   the correct isolated container and group. Repeat once: no duplicate container
   or account group is created. Pin it, close its tabs, then launch the saved pin.
4. [ ] **Portal role choices:** when optional role access is granted, the pin's
   role choices work. Revoking it leaves normal portal launches and pins usable.
   Re-enable it if desired; only the intended regional permission is requested.
   If an older broad grant remains, follow the displayed Revoke/Allow guidance.
5. [ ] **Helper launch:** switch to helper, use **Save & test**, and refresh
   accounts. All expected helper accounts appear, not portal pins. Launch one and
   check its account/role privately. A stored token works with the input left
   blank; the token is never redisplayed after saving.
6. [ ] **Helper reuse and roles:** after a helper launch with session reuse enabled,
   close that account's console tabs, then launch it again from the sidebar.
   Close tabs only; do not delete its container or cookies. Active rows do not
   show a separate launch button, so closing the tabs makes relaunch available.
   If Firefox has restarted the extension background in the meantime, a fresh
   helper sign-in is expected; this is conservative recovery, not lost pairing.
   Explicitly choosing another available role must honor that role. Revoking
   reuse must still allow normal helper launches. Restore the permission if you
   want reuse enabled. No unexpected repeated permission prompt should appear.
   If your existing SSO profile and console use different regions, confirm role
   choices and launch work without changing either setting. Do not edit a real
   profile just to create this case; the mixed-region paths also have synthetic
   regression coverage.
7. [ ] **Names in helper mode:** save your intended naming regex under **Account
   display names**. Check an inactive loaded account, an active account, and a
   pinned account. Sidebar labels, automatic container names, and automatic group
   titles follow the rule. Search finds both original and displayed names.
8. [ ] **Names in portal mode:** check an open account and a pinned account with
   the same rule. Custom container/group names stay unchanged. Clear the rule:
   automatic names return to their originals. Restore your preferred rule. No
   account, role, colour classification, or session changes because of a label.
9. [ ] **Isolation and switching:** keep two accounts open and verify each retains
   its own account/session. Switch portal → helper → portal: each mode restores
   its own list/pins/roles, with no duplicate container or surprise permission
   request. During an ordinary refresh, a mode switch must not show the old
   mode's result afterward.
   In particular: launch an account using the helper, switch to portal mode and
   open that same account (a different available role if appropriate), then switch
   back to helper mode, close that account's console tabs (keep its container and
   cookies), and launch it from the sidebar. It must honor the helper-selected
   identity/role, not silently reuse the portal role. Check identities privately.
   If an older sign-in/error tab remains unfinished, close it and launch again;
   reuse is deliberately conservative while a sign-in is unresolved.
10. [ ] **Helper unavailable:** stop the helper normally. The valid cached list
    and pins remain; refreshing or launching fails clearly, with no new console
    tab. Restart the updated helper and retry: it recovers using the stored token.
11. [ ] **UI finish:** Options and the sidebar show readable English, no raw
    message keys or `$1` placeholders, and no missing controls. Check a narrow
    sidebar and keyboard navigation through setup/settings. Existing show/hide,
    filter, pin, and naming controls still work.
    With just Tab, Shift+Tab, Enter/Space, and Escape: open **Other accounts**,
    activate an account, use role choices, switch an existing tab, and reach its
    separate close button. Focus must remain visible. Refresh should not steal
    focus or erase your place in a filter. Also check at 200% zoom.
    Compare sidebar icons with the original Firefox tab favicons, and navigate
    one tab to another AWS service: its icon should update. If AWS refuses an
    anonymous image request, a small neutral placeholder is expected; report
    only the service name, never a full account URL or cookie. Switching and
    closing tabs must still work. Already-passed unrelated checks do not need restarting
    solely because of these display-only updates.
    Confirm the subtitle, distinguish Active from Favorites, collapse/reopen
    Favorites, and check that a starred account returns there when its last tab
    closes. Its star remains selected; un-starring removes only the shortcut.

Malformed files, bad Unicode, duplicate IDs, idle-socket concurrency, simulated
full-request timeouts, proof failures, delayed sign-in completions, stale
asynchronous replies, storage migration, and archive integrity are covered
by isolated automated tests. You do not need to corrupt real data, expose a token,
or run a fake helper to repeat those cases manually.

## Finish line

Any lost settings, wrong account/role, crossed session, duplicate account container,
or unexpected permission grant blocks publication. Report the checklist number
and what happened; fix and rerun the affected check before proceeding. An item
you cannot exercise is deferred, not passed.

After acceptance: review/commit the candidate, run hosted CI, merge and publish
the exact reviewed version, then finalize the prepared Mozilla nomination draft.
No nomination or publication is performed by the local build command.

A temporary install cannot prove a signed, same-ID in-place update or persistence
across a Firefox restart. That distribution-specific check remains for the signed
candidate/release; the synthetic upgrade tests are supporting evidence, not a
claim that it was manually tested. Recommended selection is Mozilla's decision,
not a guarantee provided by this checklist.
