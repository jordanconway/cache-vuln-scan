# Security Policy

`cache-vuln-scan` is a defensive security tool. We take its own
security posture seriously and eat the dogfood — the scanner's
detectors are run against the workflow files in this repository, and
the CI pipeline is hardened the same way we recommend others harden
theirs.

## Supported versions

Only the latest commit on `main` receives security updates. There are
no tagged releases at this time.

## Reporting a vulnerability

**Please do not open public GitHub issues for security reports.**

Use GitHub's [private vulnerability reporting](../../security/advisories/new)
instead — reports go directly to the maintainers.

In your report, please include:

- A clear description of the issue and its impact.
- Steps to reproduce, ideally with a minimal proof of concept.
- The commit SHA you're working against (or rough date / branch).
- A suggested remediation if you have one.

We aim to acknowledge reports within 5 business days and ship a fix or
documented mitigation within 30 days. You'll be credited in the
advisory unless you'd rather stay anonymous.

## Out of scope

- Findings produced by the scanner against *other people's*
  repositories. Please report those to the affected repository
  owners (the scanner emits permalinks so this is straightforward).
- Issues in upstream third-party GitHub Actions referenced from CI
  here. Please report those upstream; we'll mirror Dependabot bumps
  once an advisory is available.
- Denial-of-service via crafted workflow files (e.g. multi-gigabyte
  YAML) — interesting, but not treated as a security issue.

## Hardening posture

This repo follows the same hardening checklist its scanner enforces:

- Every third-party action used in CI is pinned to a **full 40-char
  commit SHA**, never a floating tag.
- Workflows ship with top-level `permissions: contents: read`; jobs
  grant more only when strictly required.
- `actions/checkout` runs with `persist-credentials: false`.
- The runner is wrapped in
  [`step-security/harden-runner`](https://github.com/step-security/harden-runner)
  in audit mode, which logs network egress, file integrity changes,
  and process activity for later review.
- CodeQL (`python` + `actions` languages) runs on every push, every
  PR, and weekly on `main`, with results written to the GitHub
  Security tab.
- Dependabot watches the `github-actions` ecosystem and opens grouped
  PRs weekly.

If you spot something we've missed, please report it via the channel
above.
