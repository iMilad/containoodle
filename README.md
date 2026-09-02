<div align="center">

<img src="branding/containoodle-logo.png" width="160" height="160" alt="Containoodle logo">

# Containoodle

**Two ways in. One organised Firefox.**

Containoodle keeps AWS console sessions from colliding by opening each account in
its own named Firefox container and tab group. See at a glance whether you are in
dev, test, or prod, and launch through either your AWS Access Portal or an existing
local AWS CLI SSO session.

![Firefox](https://img.shields.io/badge/Firefox-MV3%20%C2%B7%20%E2%89%A5142-orange)
![Python](https://img.shields.io/badge/python-3.10%2B%20stdlib-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[Install](#install-the-extension) · [Set up](#set-up-a-connection) · [Privacy](PRIVACY.md)

</div>

---

![Containoodle organising AWS accounts into isolated Firefox containers and tab groups](branding/screenshots/containoodle-overview.png)

<div align="center"><sub>All screenshots use fictional demo account names and IDs.</sub></div>

## Two ways to connect

Choose the path that fits your environment. Both lead to the same result: isolated
AWS sessions, named containers, environment colours, and account-specific tab groups.

| | AWS Access Portal | Local AWS CLI helper |
|---|---|---|
| **Best when** | Your Access Portal is reachable. | Your Access Portal is unavailable or VPN-blocked. |
| **Local component** | None. | `server.py` on `127.0.0.1:8421`, protected by challenge-bound HMAC proofs derived from a local helper secret. |
| **AWS CLI** | Not required. | AWS CLI v2 with a valid `aws sso login` session. |
| **How you launch** | Choose an account and role in the portal as usual. | Launch with one click from the Containoodle sidebar. |
| **Shortcuts** | Pin active portal accounts; role discovery is optional. | Load accounts from `~/.aws/accounts.json` and pin frequent ones. |

<table>
  <tr>
    <td width="50%" valign="top">
      <strong>AWS Access Portal</strong><br><br>
      <a href="branding/screenshots/access-portal-settings.png">
        <img src="branding/screenshots/access-portal-settings.png" alt="Containoodle configured to use an AWS Access Portal">
      </a>
    </td>
    <td width="50%" valign="top">
      <strong>Local AWS CLI helper</strong><br><br>
      <a href="branding/screenshots/local-helper-settings.png">
        <img src="branding/screenshots/local-helper-settings.png" alt="Containoodle configured to use the local AWS CLI helper">
      </a>
    </td>
  </tr>
</table>

## The problem

AWS offers [opt-in multi-session support](https://docs.aws.amazon.com/awsconsolehelpdocs/latest/gsg/multisession.html)
for up to five identities in one browser. Containoodle is aimed at workflows that need
more durable organisation across many accounts:

- **Sessions need structure.** Native multi-session does not create persistent, named Firefox containers or account-specific tab groups.
- **The SSO dance.** Portal → find account → pick role → open, or fall back to a local federation path when the portal is unreachable.
- **"Wait, am I in _prod_?"** A wall of identical console tabs is how the wrong-account change happens.

## What Containoodle does

Containoodle puts every AWS account in a dedicated [Firefox container](https://support.mozilla.org/kb/containers)
so AWS console sessions do not overwrite one another. Use your local AWS CLI SSO
session when the Access Portal is unavailable, or let Containoodle hand launches from
the reachable portal into the right container.

| Capability | Behaviour |
|---|---|
| 🎯 **One click in** | Local helper mode launches from the Containoodle sidebar; portal mode lets you choose the account and role in the AWS Access Portal as usual. A sidebar button focuses or opens the configured portal. Either way, the console lands in the account's container. |
| 🔀 **Two exclusive modes** | **Local helper** uses `server.py` and your AWS CLI SSO token. **Portal** uses the reachable AWS Access Portal with no helper or AWS CLI. Only one mode is active; account lists and remembered roles never cross between them. |
| 🎭 **The right role** | Portal handoffs use the exact role you clicked. Portal shortcuts use only their saved portal role or optional portal role discovery. Backend launches use only backend account/role data and leave final fallback resolution to the helper. |
| 🗂️ **Separated by design** | Each account gets one named container. AWS console cookies stay container-scoped; portal mode copies the scoped SSO authentication cookie needed to bootstrap the selected session. |
| 📑 **Tab groups** | Every account's tabs land in their own Firefox tab group, colour-matched to the environment. Portal handoffs keep the displayed account name when it can be captured; an optional regex pattern and replacement can shorten automatic group titles. Manual titles always win. |
| 🚦 **Environment colours** | The account name decides the colour: **`dev` green · `qa` yellow · `prod` red · `test`/`eval` grey**. Anything unrecognised is treated as **prod (red)** — better a false alarm than a silent prod. |
| 👁️ **Never lose the active tab** | The tab you're on is a solid indigo bar and the sidebar scrolls it into view. |
| 🔌 **Live sidebar** | Containers and tabs are grouped per account and update as you open/close tabs. |
| 🔒 **Local helper** | The optional backend binds to `127.0.0.1` and requires a fresh proof derived from its private local secret before it reads account data or generates a session. It has no hosted Containoodle service or telemetry. Its session-generation calls go to AWS. |

> **Why "Containoodle"?** It contains sessions, it sounds like a noodle, and naming
> meetings are overrated.

## How it works

**Local helper mode** (default — for machines where the access portal is VPN-blocked):

```
┌─────────────────────────────┐          ┌──────────────────────────────┐
│  Firefox extension (sidebar)│ HTTP+HMAC ►│  server.py (Python stdlib)   │
│  • per-account containers   │          │  GET /accounts               │
│  • env colour + active tab  │  ◄─ JSON │  GET /generate-url           │
│  • one-click launch         │          │  GET /roles                  │
└─────────────────────────────┘          └───────────────┬──────────────┘
                                                          ▼
                                          ~/.aws/sso/cache/*.json  (your SSO token)
                                                          ▼
                                          AWS federation endpoint → signed console URL
```

The helper stays on `127.0.0.1`; the extension rejects non-loopback helper
addresses, and every account/session request requires a fresh challenge-bound
HMAC proof derived from the helper's local secret. The secret itself never crosses
the HTTP connection. AWS CLI SSO/STS requests and the AWS
federation request still go to AWS; Containoodle has no hosted backend or telemetry
service.

**Portal mode** (no backend, no AWS CLI — anywhere your access portal is reachable):

```
┌─────────────────────────────┐
│  AWS Access Portal          │   1. sign in in a normal Firefox tab
│  • choose account + role    │   2. click the account/role as usual
└──────────────┬──────────────┘   3. Containoodle recognizes the portal console shortcut
               ▼                  4. the launch is handed into that account's container
┌─────────────────────────────┐   5. the sidebar tracks the tab and tab group
│  Containoodle container  │
└─────────────────────────────┘
```

Configure the portal start URL (`https://d-xxxxxxxxxx.awsapps.com/start`) in the
extension's options page and grant access. A normal portal click captures the
displayed account name associated with the role you selected. If that context is
unavailable, Containoodle uses an existing portal pin or a previously captured portal name
for that account, then finally falls back to `AWS <account-id>`. A successful portal
handoff saves the captured portal name for later sidebar labels, environment colours,
container repair, and automatic tab-group naming.

![Portal mode handing an AWS console launch into its isolated Containoodle container](branding/screenshots/access-portal-handoff.png)

<div align="center"><sub>A portal launch handed into its account-specific container and tab group.</sub></div>

The portal URL is saved in extension-local `browser.storage.local`. Firefox also
persists the exact-origin permission and content-script registration in this Firefox
profile. The URL is never baked into the source or sent to a Containoodle service.

The options page shows only the active connection method. The **Portal readiness**
card uses the same cookie-scope checks as the launch path to report whether the exact
portal permission and a usable signed-in session are present.

| Permission, host access, or configuration | Required? | Used for |
|---|---:|---|
| `storage` | Core | Configuration, account metadata, account/container ownership, and remembered choices. |
| `contextualIdentities`, `tabs`, `tabGroups` | Core | Creating account containers and managing their tabs and groups. |
| `cookies`, `scripting` | Core APIs; host-scoped | Copying permitted session cookies and installing the exact-portal click handler. They do not grant access to a host by themselves. |
| Exact configured AWS Access Portal origin | Portal mode | Click handoff, session detection, and copying the scoped portal authentication cookie into the selected container. |
| `https://portal.sso.<region>.amazonaws.com/*` | Optional in Portal mode | Loading role choices when launching or changing a pinned portal shortcut. Containoodle requests only the exact detected or configured SSO region. |
| `https://*.console.aws.amazon.com/*` | Optional in Backend mode | Reusing a still-valid console session and suppressing the AWS cookie banner in new backend containers. Other `aws.amazon.com` services remain outside this grant. |
| Portal-pinned shortcuts | Optional | Direct portal-mode launches after an active account is pinned from the sidebar. Normal portal-click handoff does not require a pin. |

Portal role choices and backend session reuse have separate **Allow** and
**Revoke** controls inside their respective mode panels. Saving a different portal
URL requests its exact origin and, after a successful change, removes Containoodle's
previous exact-origin grant. Revoking a host permission stops future Containoodle access
to that host but does not delete cookies Firefox already owns.

An older broad `https://*.amazonaws.com/*` role-discovery grant or
`https://*.amazon.com/*` session-reuse grant remains effective after an upgrade so
existing users are not broken. Containoodle removes either legacy grant only from an
explicit **Allow**/**Tighten access** migration and only after Firefox reports the
narrower grant as a separate literal permission. **Revoke** instead removes that
feature's recognized grants directly. If Firefox reports that the broad grant covers
the narrow request without storing that literal grant, Containoodle preserves the broad
grant and asks you to choose **Revoke**, then **Allow** again. Startup, extension update,
opening Options, and switching modes by themselves never migrate existing permissions.
A newly accepted request is rolled back if its mode or target changed while Firefox's
prompt was open. The
manifest temporarily retains the legacy broad patterns as optional request ceilings for
this migration; declaring an optional ceiling does not grant Containoodle that access.

On the first backend **Save & test** in a Firefox profile that has not already
handled this choice, Containoodle automatically asks once for the optional
`https://*.console.aws.amazon.com/*` session-reuse permission. Accepting enables reuse;
declining leaves normal helper launches fully functional. A decline, or a later
**Revoke**, prevents another automatic prompt. Use **Allow session reuse** if you
want Firefox to ask again after either choice. The permission remains optional and
revocable at any time.

Backend mode keeps `~/.aws/accounts.json` as the source of truth and offers an
account-cache refresh in its active panel. Portal mode never reads that cache; its
optional shortcuts are created and removed with the ☆/★ control on active sidebar
rows. Backend mode never reads portal pins or portal role history.

The **Tab group names** settings can optionally apply a JavaScript regex pattern and
replacement to automatic group titles. A disabled or non-matching rule, or an empty
result, keeps the original account name. A manually renamed group always takes
precedence. Backtracking-prone constructs are rejected so a naming preference cannot
freeze the extension. **Reset existing titles to automatic** removes stored Containoodle
title overrides and recalculates current groups from the original account names and
the saved rule.

In **both** modes, launched tabs are grouped per account (Firefox tab groups,
env-coloured). A portal handoff always honors the role and destination you just
clicked rather than silently reusing a possibly different live role.

## Install the extension

Containoodle requires **Firefox 142 or newer** because it uses Firefox tab groups and
Firefox's built-in data-consent disclosure.

- For regular Firefox, install the reviewed version from
  [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/containoodle/).
- Every [GitHub release](../../releases/latest) also includes an unsigned
  `containoodle-<version>.xpi` for testing. Load it temporarily through
  `about:debugging` → **This Firefox** → **Load Temporary Add-on**. It is removed when Firefox restarts.
- For permanent unsigned installation, use Firefox Developer Edition or Nightly, set `xpinstall.signatures.required` to `false`, and install the XPI.

Open the sidebar with **View → Sidebar → Containoodle**, `Alt+Shift+A`, or
`Ctrl+Shift+A` on macOS. The installed version appears in the header; the ⚙ button
opens the options page.

## Set up a connection

Switching modes does not merge account lists or remembered roles. Portal launches
never use backend cache/session-reuse logic, and backend launches never use portal
pins or portal role history. Backend favorites store only account IDs; their names,
roles, and launch data still come exclusively from the helper.

### Portal quick start

1. Open Containoodle options and select **AWS access portal**.
2. Enter the exact start URL, for example `https://d-xxxxxxxxxx.awsapps.com/start`, then choose **Grant access & save**.
3. Use **AWS Portal** at the top of the sidebar to open the configured portal or
   focus its existing normal Firefox tab.
4. Sign in to that portal in the normal, non-container Firefox tab.
5. Confirm that **Portal readiness** reports portal access and a signed-in session.
6. Choose an account and role in the AWS portal normally. Containoodle hands that launch into the matching container and tab group.
7. Optional: in the sidebar, choose ☆ on the active account row to keep it as a direct-launch shortcut. Choose ★ later to unpin it; active tabs and the account container remain untouched.

Normal portal clicks and pinning need no AWS API permission beyond the exact configured
portal origin. Allow **Role choices for pinned accounts** only if you want Containoodle
to load or change a pin's available roles. Firefox then asks for only
`https://portal.sso.<region>.amazonaws.com/*` for the detected or configured SSO
region. Backend session reuse does not apply in portal mode.

### Local helper quick start

Local helper mode requires Python 3.10 or newer and AWS CLI v2. The helper uses only the
Python standard library; no third-party Python packages are required.

1. Clone the public repository:

   ```bash
   git clone <repository-url> containoodle
   cd containoodle
   ```

2. Before starting the helper, create `~/.aws/accounts.json`:

   ```json
   [
     {
       "accountId": "000000000000",
       "accountName": "__CONTAINOODLE_EXAMPLE_ACCOUNT__",
       "role": "__CONTAINOODLE_EXAMPLE_ROLE__",
       "region": "eu-west-1"
     }
   ]
   ```

   These values are unmistakable placeholders. Replace them with an account and
   role available in your own environment. `role` and `region` are optional; when
   omitted, the helper uses its configured fallback values.

3. Create or refresh the intended IAM Identity Center session:

   ```bash
   aws sso login --profile __CONTAINOODLE_TEST_PROFILE__
   ```

   Replace the unmistakable placeholder with your local AWS CLI profile alias.
   Containoodle resolves modern `sso_session` profiles and legacy inline SSO
   profiles to the same cache entry the AWS CLI uses; it never chooses an identity
   by file modification time. If no profile is configured, the helper continues
   only when exactly one distinct, valid SSO login is cached.

4. Create or display the helper access token:

   ```bash
   python3 server.py --show-token
   ```

   This is only a secret shared between this Firefox profile and the local
   helper. It is not an AWS or Mozilla token. The helper stores its copy outside
   the repository at `~/.containoodle/helper-token`; on POSIX systems the directory
   and file must remain user-only (`0700` and `0600`).

5. Start the helper:

   ```bash
   python3 server.py
   # Containoodle is now available at http://127.0.0.1:8421
   ```

6. In Containoodle options select **Local AWS CLI helper**, paste the token into
   **Helper access token**, enter the same local alias under **AWS CLI profile**,
   keep or change the helper URL, then choose **Save & test**. The profile field
   may stay blank only when one valid SSO login is cached. If this Firefox profile
   has not already handled the session-reuse
   choice, that click immediately starts Firefox's one-time optional AWS console
   permission request for `https://*.console.aws.amazon.com/*`, before and in
   parallel with helper validation. Accept to
   enable reuse, or decline to continue with normal helper-generated launches.
   After a successful helper test, the token field is cleared and the saved value
   is never redisplayed by the extension.

This strict helper protocol is not compatible with the earlier unauthenticated
helper: the extension and `server.py` must be updated together. After updating,
all helper-backed refresh, role discovery, and new session generation fail closed
until **Save & test** succeeds with the new token; there is no unauthenticated
helper fallback. An already mapped, still-signed-in Firefox container can avoid
minting a new federation URL through the separately granted session-reuse path,
but the helper must still be running so the extension can verify that the saved
SSO identity has not changed. Portal mode does not require this token.

#### Updating from v1.0.3 local-helper mode

1. Stop the old helper.
2. Update both the Firefox extension and this repository so the extension and
   `server.py` use the same strict protocol.
3. Run `python3 server.py --show-token`.
4. Start the updated helper with `python3 server.py`.
5. Paste the token into Containoodle Options. Also enter the same AWS CLI profile
   alias used for `aws sso login --profile ...`; leave it blank only when exactly
   one usable SSO login is cached. Then choose **Save & test**.

An existing session-reuse grant, including the older broad
`https://*.amazon.com/*` grant, remains effective during an in-place update. A
missing grant remains absent during update and startup; if the profile has not
previously handled the new one-time offer, the first backend **Save & test**
presents it. Declining or revoking the permission does not block helper setup and
prevents another automatic prompt. Narrowing a legacy grant is a separate explicit
Options action; it is never performed by update, startup, or a mode switch.

The existing browser account cache remains available while setup is incomplete,
but helper requests and new helper-generated sessions stay blocked. Portal mode
remains usable throughout the cutover.

The extension keeps its copy in this Firefox profile's local extension storage,
but never sends the saved token itself. For each helper operation it verifies a
short-lived signed challenge, sends a one-time HMAC proof bound to the exact
loopback host, Firefox origin, and request target, then verifies a proof over the
exact response. Challenges and proofs cannot be reused for another request and
the token is never placed in a URL, header, or request body. To use a different
token-file location, set
`CONTAINOODLE_HELPER_TOKEN_FILE` to an absolute path outside the repository before
running either helper command.

Use ☆ beside any backend account to keep it in **Pinned accounts**. The star is
only a sidebar preference: the helper remains the source of its name, role, region,
and launch data. Unpinned inactive accounts remain under **Other accounts**.

For backend sidebar launches, Containoodle checks an explicit backend choice, the account's
configured role, a backend-only remembered choice, and live backend discovery. If the
extension sends no role, the helper uses the account's configured role or
the `CONTAINOODLE_DEFAULT_ROLE` fallback. A configured or selected
role must match a permission set you actually have; otherwise AWS CLI
`get-role-credentials` rejects the launch.

Optional **Reuse an existing console session** access makes repeated backend launches
faster by opening a still-signed-in account container directly and suppressing the
AWS cookie banner in new backend containers. Normal helper launches work without it,
and an explicit role choice always bypasses reuse so the selected role wins. Reuse
and backend-only remembered roles are scoped to the helper's opaque SSO identity
key; a changed profile or cached login cannot reuse the previous identity's state.
The identity key contains no profile name, portal URL, cache path, or AWS token. The
first backend **Save & test** offers this optional permission once;
after a decline or revocation, only the manual **Allow session reuse** control asks
again. New grants are limited to `https://*.console.aws.amazon.com/*`. An older
`https://*.amazon.com/*` grant keeps reuse working until you explicitly tighten or
revoke it.

## Troubleshooting

- **The helper exits immediately:** create a valid `~/.aws/accounts.json` before running `server.py`.
- **Options says the helper access token is required:** run `python3 server.py --show-token`, paste the result into **Helper access token**, then choose **Save & test**.
- **Options says the helper access token was rejected:** make sure `--show-token` and the running helper use the same user and `CONTAINOODLE_HELPER_TOKEN_FILE`, then save and test that token again.
- **The helper rejects its token file permissions:** keep `~/.containoodle` user-only and the token file readable only by its owner. Do not move the token into the repository.
- **Options reports several cached SSO logins:** enter the same local alias used with `aws sso login --profile ...` under **AWS CLI profile**, then choose **Save & test**.
- **The selected SSO login is missing or expired:** run `aws sso login` for the selected profile, then retry. The helper never falls back to another cached identity.
- **The helper reports that the AWS SSO token expires within five minutes:** run `aws sso login` again. Containoodle never moves or deletes the AWS CLI cache to refresh it.
- **AWS CLI rejects a backend role:** select a permission set available to that account, or correct the role in `~/.aws/accounts.json` / `CONTAINOODLE_DEFAULT_ROLE`.
- **A pinned portal shortcut has the wrong role:** allow portal role choices, then click the role chip on that pin and select the intended role.
- **Portal readiness says sign-in is required:** sign in at the exact saved portal URL in a normal Firefox tab, then refresh readiness.
- **The portal opens an ordinary tab or the container asks for login:** verify portal mode, the exact-origin grant, and the signed-in session; then reload the portal page and retry.
- **A tab-group regex does not affect an older group:** use **Reset existing titles to automatic**. This intentionally removes stored manual Containoodle group-title overrides before recalculating them.
- **An unsigned XPI disappears after restart:** temporary add-ons are expected to do that. Use the Firefox Add-ons version on regular Firefox, or Developer Edition/Nightly for permanent unsigned testing.

## Security notes

Firefox's data disclosure describes the categories the extension handles locally;
it does not mean the developer receives that data. Containoodle has no telemetry or
hosted service. See the [privacy policy](PRIVACY.md) for the complete details.

<details>
  <summary><strong>Firefox permissions and data disclosure</strong></summary>
  <br>
  <a href="branding/screenshots/permissions-and-data.png">
    <img src="branding/screenshots/permissions-and-data.png" alt="Firefox permissions and data disclosure for Containoodle">
  </a>
</details>

- The backend binds to `127.0.0.1`, validates the exact loopback `Host`, enforces Firefox extension origins for browser requests, and requires a fresh challenge-bound HMAC proof on every account and session endpoint. A protocol-capable diagnostic without an `Origin` must produce the same host- and target-bound proofs. Keep the port local and never expose or forward it.
- The helper secret is generated with Python's `secrets` module, stored outside the repository, and never accepted through a URL, request header, request body, or command-line argument. Only short-lived challenges and one-time proofs cross the connection, and proofs are compared in constant time. `python3 server.py --show-token` is the only intentional display path; normal startup, responses, and access logs omit it.
- The helper builds session sign-in URLs in memory. It does not write them to Containoodle files or include query strings in its access log; Firefox may retain navigated URLs according to its own history and session policies.
- The optional AWS CLI profile is a local alias used only to resolve the exact modern or legacy SSO cache namespace. Cache candidates are validated before use, multiple identities fail closed, and Containoodle never moves, rewrites, or deletes AWS CLI cache files.
- No real account IDs, credentials, or internal account names are baked into the project. Runtime account metadata comes from `~/.aws`, the clicked AWS Access Portal page, or extension-local storage. Synthetic account IDs remain in examples and tests.
- Container ownership is stored by AWS account ID and Firefox cookie-store ID. A pre-existing Firefox container with the same display name is not reused, so labels cannot merge two account sessions.
- Host permissions are **opt-in at runtime and independently revocable**: core portal setup asks only for the exact configured portal origin. Optional role discovery requests only `https://portal.sso.<region>.amazonaws.com/*` for the detected or configured region. Optional backend session reuse requests only `https://*.console.aws.amazon.com/*`; the first backend **Save & test** offers it once, but declining or revoking it leaves helper mode functional and stops automatic re-prompts. Legacy broad grants remain effective for compatibility. Tightening removes one only after explicit user action plus proof that Firefox stored the narrow replacement; **Revoke** directly removes the feature's recognized grants. Startup, update, Options load, and mode switching do not migrate existing permissions; a newly accepted request is rolled back if its context changed while the prompt was open. Containoodle has no hosted backend and sends no analytics or telemetry to a Containoodle service.
- Containoodle's complete data handling, retention, and deletion terms are in the [privacy policy](PRIVACY.md). Firefox's install prompt discloses the data categories the extension handles even though none of that data is sent to the developer.
- In portal mode, a document-start handler on the exact configured portal reads the validated shortcut URL and the displayed account name associated with the role you click. It does not read forms, credentials, or the rest of the account list. A bounded tab-URL fallback may remove a proven portal-created child tab or return the source tab to the portal only after a successful handoff; redirected or unrelated tabs are left alone.
- **Portal mode trade-off, deliberately accepted:** the `x-amz-sso_authn` cookie can mint console sessions for every account your SSO user is entitled to. Containoodle copies its Firefox domain/path/isolation scope into each launched account's container and verifies the copy before navigation; Firefox may retain it until its original expiry. Optional sidebar role discovery also sends its value as a bearer token directly to the regional AWS portal API. Containoodle never writes the value to extension storage or logs.
- Every release includes an unsigned GitHub XPI for testing and submits the same version to the public Firefox Add-ons listing for Mozilla review.

## Development

```bash
node --version  # Node.js 20 or newer
npm ci --ignore-scripts
python3 -m py_compile server.py
for js_file in $(git ls-files '*.js'); do node --check "$js_file"; done
npm run check
```

- **CI** (`.github/workflows/ci.yml`) runs these checks, validates the manifest, runs `web-ext lint`, and smoke-builds an XPI on every push or pull request to `main`.
- **Releases** (`.github/workflows/release.yml`) test and build a versioned unsigned GitHub XPI, submit that version to the listed AMO channel, and create the GitHub Release when a pushed `v*` tag matches `manifest.json`.

Before tagging, update the version in `firefox-extension/manifest.json` and
`package.json`, then commit those changes. Replace `X.Y.Z` below with the same
version everywhere:

  ```bash
  git tag vX.Y.Z
  git push origin main vX.Y.Z
  ```

## License

[MIT](LICENSE) © Containoodle contributors
