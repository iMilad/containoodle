# Containoodle privacy policy

Effective date: 30 July 2026

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

In local-helper mode, the extension sends the selected account and role to
`http://127.0.0.1:<port>` on the same device. The helper reads local AWS
configuration and invokes the AWS CLI and AWS federation service to create the
requested session. The extension rejects non-loopback helper addresses.

No data is sold, used for advertising or profiling, or sent to a Containoodle-operated
server.

## Storage and retention

Extension preferences and account metadata remain in this Firefox profile in
`browser.storage.local` until changed or until the add-on's local data is removed.
Containoodle does not use browser sync.

The copied portal cookie is not written to extension storage or logs. Firefox may
retain it in the account container until the cookie's original expiry. The helper
keeps generated sign-in URLs in memory and omits request query strings from its
access log. Firefox and AWS may retain data under their own settings and policies.

## Your controls

- Portal and AWS host access is requested at runtime and can be revoked in Containoodle
  settings or Firefox's add-on permissions.
- Removing the add-on removes its extension-local storage. Firefox containers,
  browser history, and cookies are managed separately through Firefox.
- You can clear an account container's cookies or remove the container through
  Firefox. Revoking a host permission stops future Containoodle access but does not itself
  delete cookies already held by Firefox.
- AWS-side sessions and data are controlled through your AWS account and service
  settings.

Privacy questions can be filed in the repository's issue tracker.
