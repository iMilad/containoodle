# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability, exposed credential,
or other sensitive security finding.

Use [GitHub's private vulnerability reporting](https://github.com/iMilad/containoodle/security/advisories/new)
so the report and any supporting details remain private while the issue is investigated.
Include the affected version, reproduction steps, and potential impact when possible.

If you believe a credential has been exposed, revoke or rotate it immediately through
its provider before sending the report. Never include live AWS session URLs, cookies,
the local helper access token, other tokens, or real account data in a reproduction.

## Local helper authentication

The optional helper binds only to `127.0.0.1` and requires a persistent 256-bit
secret before its account, role, or session routes perform any local AWS work.
The secret is generated locally and stored outside the repository. It is never
sent across the loopback connection: each request uses a fresh signed challenge,
a single-use HMAC proof bound to the exact method, target, loopback host, and
Firefox origin, and a proof over the exact response. Proofs are compared in
constant time and expire quickly. Browser requests must also pass the helper's
exact loopback `Host` and Firefox-extension `Origin`-format checks. The Origin
check is not a single-extension UUID allowlist; proof of the secret is required
for protected routes even when the Origin format is accepted.

Use `python3 server.py --show-token` only when you need to copy the token into
Containoodle settings. Never put it in a URL, issue, log, screenshot, test fixture,
or command-line argument. Normal helper startup and request logging omit it. This
control protects against unauthenticated websites, extensions, local clients, and
a process impersonating the configured helper port. A listener that does not know
the secret cannot obtain a usable request proof or forge an accepted response. It
is not a boundary against malware already running as the same OS user, which can
also access that user's helper secret, AWS CLI cache, and Firefox profile.

## Session reuse and availability limits

Portal readiness, role discovery, and cookie copying share one credential
selector. It requires Secure/HttpOnly and valid scope/expiry metadata, and
rejects distinct values across applicable first-party and portal partitions.
An insecure shadow is included in the ambiguity check; API ordering cannot
choose its authority. A rejected selection performs no cookie copy or role
request. Copy readback also checks the protection flags and expiry.

Automatic tab-event handoffs also require source provenance: an observed
immediately prior configured portal page, or a current configured portal opener
for a new child/its initial blank-page navigation. A shortcut destination alone,
an unrelated previous page, or a historical opener cannot authorize cookie
movement. Unknown provenance leaves native navigation untouched; explicit
portal clicks still pass the content script's trusted-click and exact-page checks.

Container labels are presentation, not identity. Account/cookie-store ownership
and verified helper session generations are tracked separately. A portal launch
invalidates the helper reuse record before mutating its cookie jar. Older pending
sign-in tabs fence reuse until resolved; delayed verifications cannot restore an
invalidated generation. Legacy identity-only reuse markers are ignored, so the
first helper launch after upgrading signs in again. Reuse authority is also
limited to generations verified in the current background lifetime: after a
background restart the helper federates again, and unresolved tabs are recovered
before a new generation can verify. Persisted `verified` flags alone cannot
authorize reuse after a failed corrective write and restart. This is conservative
reuse control, not an independent proof of the AWS identity inside arbitrary cookies
changed outside Containoodle. Users should still check the console identity.

The local helper limits concurrent workers to eight and accepted sockets to a
five-second inactivity timeout. SSO requests use fixed regional HTTPS endpoints
with certificate verification and no redirects or endpoint overrides. The cached
bearer stays in an HTTP header, never process arguments or environment variables.
SSO socket operations have a 30-second timeout and 64-KiB response limit; role
discovery also checks a deadline between reads/pages and caps pagination at 100
pages. Federation socket operations have a 15-second timeout and 64-KiB response
limit. These socket timeouts are not total end-to-end deadlines. The
extension's complete helper exchange has a 60-second deadline and rejects late
results without replacing trusted settings or account caches. These limits improve
availability; they do not promise service under sustained local denial of service.

## Build-tool security

Build dependencies are not packaged in the extension. Full dependency audits,
guarded image parsing, bounded lint, and time-limited exceptions are described in
[TOOLING_SECURITY.md](TOOLING_SECURITY.md). Known contained upstream advisories
are disclosed there; a clean runtime-only audit is not a full-toolchain audit.

## Supported versions

Security fixes are applied to the latest published version. Users should update to the
newest release before reporting an issue that may already have been corrected.
