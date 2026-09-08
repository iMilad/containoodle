# Contributing to Containoodle

Thank you for helping improve Containoodle.

## Before opening a change

- Use synthetic AWS account IDs, names, roles, URLs, and screenshots. Never commit
  credentials, session URLs, cookies, private infrastructure details, or employer data.
- Keep behavior changes focused and explain any new browser permission or network request.
- Report security problems privately as described in [SECURITY.md](SECURITY.md).

## Local checks

Use Node.js 24 LTS or newer, Python 3.10 or newer, and `zip`/`unzip`:

```bash
npm ci --ignore-scripts
npm run audit:dependencies
npm run check
```

The check runs the JavaScript and Python tests, Mozilla's extension linter, and the
verified XPI build. The builder stages two independent archives, checks their exact
file lists and ZIP integrity, and compares their bytes and SHA-256 before replacing
the candidate artifact. This proves reproducibility within the current toolchain,
not identical output across different ZIP implementations.

`npm run build-for-amo` is an alias for the same local checks and packaging. It does
not sign, upload, publish, or contact AMO. CI tests Python 3.10 and 3.14 separately;
the tag-release workflow reuses those CI gates before publication. A pull request
should pass those checks too. Match manifest, package, and lockfile versions.

The tagged release also synchronizes `PRIVACY.md` to Containoodle's existing AMO
privacy-policy field before submission. This release-only step uses the existing
GitHub signing secrets without printing them and changes no EULA or other listing
metadata. It refuses a mismatched tag/add-on identity; local tests mock its requests.

Account validation fixtures are shared between JavaScript and Python. Helper tests
must keep account/config/cache paths, AWS CLI subprocesses, and federation/network
access isolated from the developer's real environment.

The helper suite includes one isolated `127.0.0.1:0` integration test with a
temporary synthetic secret and no AWS access. Restricted sandboxes must permit
that ephemeral local bind. It never starts the configured helper on port 8421.

Dependency auditing includes development tools. The currently unpatched
image-parser advisories have narrowly scoped, expiring build-only containment;
see [TOOLING_SECURITY.md](TOOLING_SECURITY.md). Use `npm run lint:ext`, not a direct
unguarded linter command. New or expired findings block CI/release. Do not use
`npm audit fix --force` to downgrade the Mozilla toolchain.

## UI messages

English is the only shipped language for now. Options and sidebar messages use
`firefox-extension/_locales/en/messages.json` with `shared/i18n.js`; missing APIs or
messages fall back to English. Background/helper diagnostics may remain English.
Translation readiness is not a claim of a fully translated product.

Keep catalog keys stable and explain placeholders in message descriptions. Use
`message(key, englishFallback, substitutions)` for dynamic UI text. For static text,
use `data-i18n` and the supported title/placeholder/aria-label attributes. Rich text
may move existing numbered `data-i18n-slot` nodes, but must preserve each exactly
once. Never render translated text with `innerHTML`, translate protocol identifiers,
or interpolate account data into HTML. Update the catalog and fallback together.

Before adding another locale, include its files in the packaging allowlist and
tests, then review layout, keyboard access, and fallback behavior in real Firefox.
For the current candidate's single manual pass, see [TESTING_1.2.0.md](TESTING_1.2.0.md).

`tests/sidebar-browser-smoke.mjs` is an optional real-DOM keyboard/contrast smoke
using an externally installed Playwright and a disposable headless Chromium
context. It blocks non-fixture traffic and uses only synthetic browser APIs; it
does not touch Firefox profiles or replace Firefox/AWS acceptance. Pass
`--playwright=/absolute/path/to/playwright/index.mjs` and optionally
`--browser=/absolute/path/to/chromium` when those tools are installed outside the
project. It is not part of the default dependency set or CI.

## Pull requests

Describe what changed, why it is needed, and how it was tested. Keep unrelated changes
separate. Changes to permissions, authentication handling, storage, or release packaging
should include tests and an update to the relevant public documentation.
