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
exact loopback `Host` and Firefox-extension `Origin` checks.

Use `python3 server.py --show-token` only when you need to copy the token into
Containoodle settings. Never put it in a URL, issue, log, screenshot, test fixture,
or command-line argument. Normal helper startup and request logging omit it. This
control protects against unauthenticated websites, extensions, local clients, and
a process impersonating the configured helper port. A listener that does not know
the secret cannot obtain a usable request proof or forge an accepted response. It
is not a boundary against malware already running as the same OS user, which can
also access that user's helper secret, AWS CLI cache, and Firefox profile.

## Supported versions

Security fixes are applied to the latest published version. Users should update to the
newest release before reporting an issue that may already have been corrected.
