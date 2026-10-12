# Security policy

The Murkio Ruby SDK signs users in and verifies their sessions, so a flaw here can reach every
application that uses it. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/ViitoJooj/murkio-ruby/security/advisories/new).

Say what you found, how to reproduce it and what an attacker gains. A minimal proof of
concept helps; please do not test against applications or accounts that are not yours.

## Supported versions

Only the latest release (and the `master` branch) receives security fixes.

## What the pipeline already checks

Every pull request and every push to `master` runs the workflows in `.github/workflows`:
static analysis, a dependency audit, a secret scan over the whole history, an audit of the
workflows themselves and the checks in `infra/pipeline`. Dependabot keeps the dependencies
and the pinned GitHub Actions up to date. See the README for how to run them locally.
