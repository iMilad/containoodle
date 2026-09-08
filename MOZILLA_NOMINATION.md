# Recommended nomination — draft, not sent

Do not send until the candidate passes the recorded acceptance/release gates and
the intended version is available on AMO. Verify the listing, current program
instructions, and every factual claim immediately before sending. No user-count,
security-certification, or multilingual claim is implied.

Mozilla currently invites nominations, including self-nominations, by email to
`amo-featured@mozilla.org` with the listing link and a short explanation. Selection
is curated and not guaranteed. [Program instructions](https://extensionworkshop.com/documentation/publish/recommended-extensions/)

These instructions were rechecked on 2026-09-08. The maintainer accepted the
1.2.0 candidate and authorized release on that date. Publication must still be
verified before sending; preparing this document does not send an email.

## Draft email

To: amo-featured@mozilla.org

Subject: Recommended Extensions nomination — Containoodle

Hello Mozilla Add-ons team,

I would like to nominate [Containoodle — AWS Console Containers](https://addons.mozilla.org/firefox/addon/containoodle/)
for consideration in the Recommended Extensions program.

Containoodle helps AWS users work across accounts with console sessions separated
into clearly named Firefox containers and tab groups. Its primary workflow works
directly with the AWS access portal, without a local service. An optional local
AWS CLI SSO helper supports users who prefer their existing CLI workflow.

The extension is open source, has no telemetry or hosted backend, and requests
feature-specific host access at runtime. It includes first-run guidance, consistent
account naming, keyboard-operable sidebar controls, and automated regression
coverage for session transitions, permission changes, and helper authentication.
The documented threat model explicitly describes the portal-cookie trade-off.

Its audience is specialized: people who manage multiple AWS accounts. I believe
it demonstrates a useful Firefox-specific application of container isolation,
while making this daily workflow easier to understand.

Source: https://github.com/iMilad/containoodle

Release source and reviewer guide:
https://github.com/iMilad/containoodle/blob/v1.2.0/REVIEWER_GUIDE.md

Privacy policy: https://github.com/iMilad/containoodle/blob/v1.2.0/PRIVACY.md

I am committed to ongoing maintenance and would welcome security, policy, or user
experience feedback. I can provide reviewer instructions and coordinate an
appropriate isolated review setup privately if needed.

Thank you for considering it.

## Before sending

- Confirm the AMO listing serves the accepted version and its screenshots contain
  only synthetic account/role information.
- Record user acceptance, hosted CI, and signed-update results; do not rewrite
  untested items as passes.
- Recheck dependency advisories and the build-only exception expiry.
- Include the reviewer guide for the exact released source revision and be ready
  to explain known limitations honestly. Do not send credentials in the email.
