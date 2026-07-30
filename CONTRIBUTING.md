# Contributing to Containoodle

Thank you for helping improve Containoodle.

## Before opening a change

- Use synthetic AWS account IDs, names, roles, URLs, and screenshots. Never commit
  credentials, session URLs, cookies, private infrastructure details, or employer data.
- Keep behavior changes focused and explain any new browser permission or network request.
- Report security problems privately as described in [SECURITY.md](SECURITY.md).

## Local checks

Use Node.js 20 or newer and Python 3.10 or newer:

```bash
npm ci --ignore-scripts
npm run check
```

The check runs the JavaScript and Python tests, Mozilla's extension linter, and the
reproducible XPI build. A pull request should pass the same checks in GitHub Actions.

## Pull requests

Describe what changed, why it is needed, and how it was tested. Keep unrelated changes
separate. Changes to permissions, authentication handling, storage, or release packaging
should include tests and an update to the relevant public documentation.
