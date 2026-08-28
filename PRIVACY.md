# Containoodle privacy policy

Effective date: 25 August 2026

Containoodle has no advertising, analytics, telemetry, or hosted service. The
developer does not receive your configuration, account information, browsing
activity, cookies, credentials, or generated console sign-in URLs.

Containoodle nevertheless handles personal and authentication data to provide its core
features. Firefox's installation disclosure therefore lists authentication
information, browsing activity, personally identifying information, website
activity, and website content.

## Data Containoodle handles

- The exact AWS Access Portal URL you configure.
- AWS account IDs, displayed account names, roles, regions, and the account or role
  shortcut you choose.
- URLs, titles, and locally available icons for tabs in Firefox containers, used to
  render and organize the sidebar.
- The AWS portal authentication cookie needed to open the selected account in its
  Firefox container.
- The local helper access token used to authenticate this Firefox profile to
  `server.py` in local-helper mode.
- The optional local AWS CLI profile alias and an opaque helper-derived SSO
  identity key used to keep backend sessions and role choices separated.
- Local preferences such as connection mode, pins, remembered role choices,
  account-to-container mappings, and tab-group naming rules.

Containoodle does not read password fields or form contents. Its portal click handler is
limited to the exact portal origin and path you grant and reads only the selected
console shortcut and its displayed account name.

## Where data goes

In portal mode, Containoodle copies the portal authentication cookie between Firefox
cookie stores on the same device. If you enable role discovery, Containoodle sends that
cookie directly to the AWS portal API as an authentication value. Account and role
details are also sent to AWS when Firefox opens the selected console session.

In local-helper mode, the extension sends the selected account, role, optional
local AWS CLI profile alias, and opaque SSO identity key to
`http://127.0.0.1:<port>` on the same device. The saved helper access token itself
is not transmitted. It is used locally on both sides to authenticate a
short-lived challenge, a one-time proof for the exact request, and a proof over
the exact response. The token is never put in a URL, header, request body, or sent
to AWS. The helper reads local AWS configuration and invokes the AWS CLI and AWS
federation service to create the requested session. The extension rejects
non-loopback helper addresses and responses that do not carry a valid proof.

No data is sold, used for advertising or profiling, or sent to a Containoodle-operated
server.

## Storage and retention

Extension preferences and account metadata remain in this Firefox profile in
`browser.storage.local` until changed or until the add-on's local data is removed.
Containoodle does not use browser sync.

The extension's helper access token, optional AWS CLI profile alias, and opaque SSO
identity key also remain in `browser.storage.local`; they are not browser-synced.
The token is not redisplayed by the extension after saving. The helper stores its matching
copy outside the repository at `~/.containoodle/helper-token` by default. On POSIX
systems it requires a user-only directory and file. Normal helper startup,
responses, and access logs do not print the token; `server.py --show-token` is the
intentional local display command.

The copied portal cookie is not written to extension storage or logs. Firefox may
retain it in the account container until the cookie's original expiry. The helper
keeps generated sign-in URLs in memory and omits request query strings from its
access log. Firefox and AWS may retain data under their own settings and policies.

## Your controls

- Portal and AWS host access is requested at runtime and can be revoked in Containoodle
  settings or Firefox's add-on permissions.
- On the first local-helper **Save & test**, Containoodle offers the
  optional AWS console host permission once so it can reuse an existing signed-in
  session. Accepting enables that feature. Declining, or later revoking it, leaves
  normal helper-generated launches available and prevents another automatic
  prompt; **Allow session reuse** lets you reconsider manually. Firefox's host
  permission remains the authoritative enabled state, while the extension stores
  only that this one-time offer was handled.
- Removing the add-on removes its extension-local storage. Firefox containers,
  browser history, and cookies are managed separately through Firefox.
- Removing the add-on does not remove the helper's token file. Stop the helper and
  manage that local file separately if you want to rotate or remove it.
- You can clear an account container's cookies or remove the container through
  Firefox. Revoking a host permission stops future Containoodle access but does not itself
  delete cookies already held by Firefox.
- AWS-side sessions and data are controlled through your AWS account and service
  settings.

Privacy questions can be filed in the repository's issue tracker.
