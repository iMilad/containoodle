# Build dependency security

Reviewed 2026-09-08. This concerns local/CI tooling, not code shipped in the XPI.

## Known upstream findings

The locked chain is `web-ext@10.6.0` → `addons-linter@10.10.0` →
`image-size@2.0.2`. Two high-severity denial-of-service advisories affect the image
parser. Both upstream advisory pages list no patched version at this review:

- [GHSA-w3rx-r6r6-pgpr — ICNS parser](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr)
- [GHSA-5p2g-fcmc-qvqq — JXL and HEIF parsers](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq)

The September 8 review rechecked both upstream advisories, the public npm latest
release (`image-size@2.0.2`), and the full dependency audit. No patched release
was available. The audit passed the existing exact exception and containment
checks; its scope and October 5 expiry were not widened or extended. This review
is complete for the local candidate, but upstream remediation remains a future
maintenance responsibility and must be rechecked before publication.

A crafted image supplied in a source change could hang unguarded lint. Checking
the `.png` filename alone is insufficient because parsing detects file contents.
The three affected package entries in `npm audit` are the dependency chain, not
three separate vulnerabilities. None of these packages is in the 21-file XPI.

The service-icon follow-up adds one allowlisted JavaScript module that displays
browser-reported favicons, including SVG rendered as passive browser images, not
DOM markup. It adds no packaged image file or manifest image reference and does
not widen the PNG-only build-parser guard. Runtime favicon downloads are bounded
separately as documented in the reviewer guide and privacy policy.

## Containment, not an upstream fix

1. `npm run lint:ext` validates the package file allowlist and lints a private
   staged snapshot. Its two permitted images must have actual PNG signatures,
   bounded size, the expected IHDR and dimensions. Manifest image references must
   point to those PNGs; new theme/image surfaces require review.
2. The child preloads `scripts/lint-image-guard.cjs`. It resolves the exact CommonJS
   image-size instance used by Mozilla's linter and disables every non-PNG
   calculation through the package's public API. The release signing process uses
   the same guard. No vendor code is modified. Synthetic regression inputs verify
   that the real parser rejects ICNS, JXL, and HEIF before their vulnerable
   calculation paths.
3. Lint has a 60-second hard child-process timeout with forced termination and
   bounded output. CI jobs have outer time limits. Normal extension validation
   remains enabled; none of its errors are ignored.
4. `npm run audit:dependencies` audits **all** dependencies. Only these two exact
   advisories, the exact reviewed versions, their single expected dependency paths,
   and development-only packages qualify for the exception. A new finding, report
   failure, version drift, or expiration fails the gate. CI and release both run it.

The exception expires **2026-10-05 UTC**. This is deliberately not a claim of zero
total audit findings. A future upstream fix should replace this containment after
regression testing; do not silently renew the exception or force a downgrade to
an obsolete web-ext version. Maintainers should recheck before every release.

These guards are designed for the standard repository workflow. Running an
unguarded tool manually bypasses them; a pull request that changes the guards or
workflow itself still needs normal human review. CI does not execute repository
checks with release secrets on untrusted pull requests.
