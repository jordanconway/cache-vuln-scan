# cache_vuln_scan.py

A defensive scanner that audits GitHub Actions workflows across every org
and repo you have access to for patterns that enable **cache-poisoning
attacks** — most notably the [Cacheract](https://github.com/adnaneKhan/cacheract)
class — along with the script-injection / unsafe-checkout vulnerabilities
that supply attackers with initial code execution inside privileged
workflows.

The rule set is built directly from the
["Guarding Against Cacheract"](https://github.com/adnaneKhan/cacheract#guarding-against-cacheract)
checklist plus the script-injection research published by the GitHub
Security Lab.

## What it flags

| Rule                     | Sev      | What it means |
| ------------------------ | -------- | ------------- |
| `script-injection`       | Critical | Untrusted GitHub context (`github.event.pull_request.title`, `github.head_ref`, comment/issue bodies, head commit messages, etc.) interpolated directly into a `run:` or `actions/github-script` `script:` block. This is the primary initial-access vector — an attacker controls those values and can run arbitrary shell. |
| `pr-target-checkout`     | Critical | `pull_request_target` workflow that checks out an attacker-controlled head ref. Runs in the default-branch context with full secrets + token, so attacker code executes with elevated privilege. |
| `pr-target-cache`        | High     | `pull_request_target` workflow that consumes any cache — broad cache-poisoning surface even without an unsafe checkout. |
| `issue-comment-checkout` | High     | `issue_comment` trigger combined with `actions/checkout`. Anyone who can comment on an issue may be able to trigger privileged execution. |
| `workflow-run-checkout`  | High     | `workflow_run` handler that checks out code — same class of bug as `pull_request_target`. |
| `cache-in-release`       | High     | Workflow publishes/releases artifacts (`npm publish`, `gh release create`, `docker push`, `pypa/gh-action-pypi-publish`, etc.) **and** consumes a cache. Cacheract README rule #1: never consume caches in release builds. |
| `cache-with-secrets`     | Medium   | Cache + high-value secrets (`NPM_TOKEN`, `PYPI_TOKEN`, AWS creds, signing keys, etc.). Cacheract README rule #2. |
| `actions-write-cache`    | Medium   | Workflow grants `actions: write` **and** uses caches — the precondition that lets Cacheract overwrite existing cache entries on the default branch for long-term persistence. |

## Setup

uv-native via [PEP 723](https://peps.python.org/pep-0723/) — no virtualenv,
no `pip install`. The script declares its Python requirement (`>=3.10`) and
dependencies (none, pure stdlib) inline. uv handles the rest.

```bash
# 1. Install uv (one-time) — see https://docs.astral.sh/uv/
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Auth to GitHub
gh auth login
gh auth refresh -h github.com -s read:org,repo,workflow
# ...or set a PAT with `repo`, `read:org`, `workflow` scopes:
export GITHUB_TOKEN=ghp_...

# 3. Run it. uv resolves Python + deps the first time, then caches.
uv run cache_vuln_scan.py --orgs linuxfoundation
```

If you'd rather invoke it like a normal CLI, `chmod +x cache_vuln_scan.py`
and the `#!/usr/bin/env -S uv run --script` shebang takes over:

```bash
chmod +x cache_vuln_scan.py
./cache_vuln_scan.py --orgs linuxfoundation
```

Don't have uv and don't want it? It's still plain stdlib Python — fall
back to `python3 cache_vuln_scan.py ...` and it works the same.

## Usage

```bash
# Scan every org you belong to (+ your own personal repos):
uv run cache_vuln_scan.py

# Restrict to specific orgs (uses /orgs/{login}/repos):
uv run cache_vuln_scan.py --orgs linuxfoundation cncf openssf

# Scan a user/namespace (uses /users/{login}/repos — public repos
# owned by that user). Falls back to the org endpoint if the login
# turns out to be an org:
uv run cache_vuln_scan.py --users adnaneKhan torvalds

# Scan everything YOU own — public + private repos in your own
# namespace (uses the authenticated /user/repos?affiliation=owner
# endpoint, so private repos show up unlike --users):
uv run cache_vuln_scan.py --me

# Mix orgs, users, and yourself — results are deduped:
uv run cache_vuln_scan.py --orgs cncf --users adnaneKhan --me

# Quick single-repo test (no listing call):
uv run cache_vuln_scan.py --repos AdnaneKhan/Cacheract

# Only flag repos where you have admin (i.e. you can actually fix it):
uv run cache_vuln_scan.py --admin-only

# Skip archived repos and pick your output location:
uv run cache_vuln_scan.py --no-archived --out-dir ./cache-vuln-report

# Verbose progress + rate-limit messages:
uv run cache_vuln_scan.py -v
```

### `--orgs` vs `--users` — which do I want?

GitHub serves repos for orgs and user namespaces from **different API
endpoints**, so the script needs to know which one to hit:

| Flag      | Endpoint hit                                    | Scope                                                |
| --------- | ----------------------------------------------- | ---------------------------------------------------- |
| `--orgs`  | `/orgs/{login}/repos`                           | All repos in the org you can see (private if you're a member, public otherwise) |
| `--users` | `/users/{login}/repos`                          | **Public** repos owned by that user namespace        |
| `--me`    | `/user/repos?affiliation=owner&visibility=all`  | **Everything you own — public + private.** Use this for your own account. |
| `--repos` | `/repos/{owner}/{name}`                         | Specific repos (e.g. for spot-checks)                |
| (none)    | `/user/orgs` → per-org + `/user/repos`          | Everything you have read access to: all your orgs + your own personal repos + collaborator repos |

Don't know if a login is a user or an org? `--users` will fall back to the
org endpoint automatically on 404, so passing the wrong flag isn't fatal.

If you pass `--users jconway` for your own account, you'll only see your
**public** repos — that endpoint is unauthenticated-style. Use `--me` to
also see private ones.

Outputs land in `--out-dir` (default `./cache-vuln-report/`), **split per
owner** with each per-owner file prefixed by the run's ISO 8601 short
date (`YYYY-MM-DD`):

```
cache-vuln-report/
├── summary.md                            # latest cross-owner index
├── linuxfoundation/
│   ├── 2026-05-11-findings.json
│   ├── 2026-05-11-report.md
│   ├── 2026-05-12-findings.json          # today's run
│   └── 2026-05-12-report.md
├── cncf/
│   ├── 2026-05-12-findings.json
│   └── 2026-05-12-report.md
└── jconway/
    ├── 2026-05-12-findings.json
    └── 2026-05-12-report.md
```

Two safety properties from this layout:

1. **Concurrent scans of different orgs don't fight.** Each owner gets
   its own subdir, so running `--orgs linuxfoundation` and
   `--orgs cncf` against the same `--out-dir` at the same time is safe.
2. **Different-day re-runs build up history.** The `YYYY-MM-DD-` prefix
   sorts chronologically, so you can diff yesterday's report against
   today's. Same-day re-runs overwrite the day's report (one report per
   owner per day).

```bash
# Terminal 1
uv run cache_vuln_scan.py --orgs linuxfoundation

# Terminal 2 (concurrent, same --out-dir)
uv run cache_vuln_scan.py --orgs cncf
```

`summary.md` lives at a stable filename so you can bookmark it; it's
regenerated each run and always links to that run's dated per-owner
reports.

## How it works under the hood

1. Resolves auth via `gh auth token`, falling back to `GITHUB_TOKEN`.
2. Enumerates orgs via `/user/orgs`, then `/orgs/{org}/repos` for each. If
   you pass `--orgs`/`--repos`, those steps are short-circuited.
3. For each repo, lists `.github/workflows/*.{yml,yaml}` and downloads
   each file via the `Accept: application/vnd.github.raw` contents API.
4. Applies the rule set above using regex + a small custom YAML
   sectionizer (deliberately no PyYAML dep — that way malformed workflow
   files in the wild don't crash the scanner).
5. Concurrent across repos (`--workers`, default 8) with retry / backoff
   on secondary rate limits.

## False positives & calibration tips

- **`cache-in-release`** can fire on test workflows that happen to call
  `docker push` against a local registry. Review before opening tickets.
- **`script-injection`** is regex-based; it currently lists only the
  *clearly* attacker-controlled contexts. It does **not** flag the
  env-var mitigation pattern:

  ```yaml
  - env:
      TITLE: ${{ github.event.pull_request.title }}
    run: echo "$TITLE"   # safe — value goes through env, not the shell
  ```

  That's intentional — that pattern is the recommended fix.
- **`actions-write-cache`** is informational on repos where `actions: write`
  is needed for legitimate reasons (e.g. self-hosted cache management).
  Use it as a sorting key, not a hard "must fix".

## Remediation cheat-sheet

| Finding                  | Fix |
| ------------------------ | --- |
| `script-injection`       | Move the untrusted value to an `env:` var on the step and reference `$VAR`. Or wrap in `${{ toJSON(...) }}` if it needs to be a JS literal. |
| `pr-target-checkout`     | Switch to `pull_request` (forks have no secrets). If you need PR labels/secrets, gate on `if:` checks and never check out PR head. |
| `issue-comment-checkout` | Gate on `github.event.comment.author_association` being `OWNER`/`MEMBER`/`COLLABORATOR` and remove the checkout if not strictly needed. |
| `cache-in-release`       | Split: build with cache, then run the publish step in a **separate workflow** triggered by `workflow_run` on success — and don't restore caches in that workflow. |
| `cache-with-secrets`     | Same split as above. The secret-using job should not call `actions/cache` or any `cache: true` setup-* action. |
| `actions-write-cache`    | Drop the `actions: write` permission unless a step truly needs it. Most cache producers only need the implicit OIDC. |

## Development

Single-file scanner, single-file test suite under `tests/`, no build
step.

```bash
# Run the tests (no deps — stdlib only)
python3 tests/test_detectors.py
```

The tests load `cache_vuln_scan.py` as a module and run a set of fixture
workflows through the detectors, plus drive the per-owner / dated-output
writer functions end-to-end against a `tempfile.mkdtemp()` directory.

```
cache-vuln-scan/
├── .github/
│   └── workflows/
│       └── tests.yml
├── cache_vuln_scan.py
├── tests/
│   └── test_detectors.py
├── README.md
└── .gitignore
```

### CI

Two workflows under `.github/workflows/`:

- `tests.yml` — runs the test suite on every push / PR across Python
  3.10–3.13, plus a `uv run` smoke test for the PEP 723 inline metadata.
- `codeql.yml` — runs CodeQL static analysis weekly and on every push /
  PR. Two languages are analyzed: `python` (the scanner itself) and
  `actions` (the workflow files in this repo — a different ruleset that
  complements the scanner's own detectors).

Both workflows are hardened against the same class of attacks this
scanner detects, plus the broader supply-chain attack surface:

- **All actions pinned to full 40-char commit SHAs** (not floating
  tags), with a trailing `# vX.Y.Z` comment so Dependabot / Renovate
  can still update them. Tag-based pins like `@v4` can be silently
  rewritten by a compromised maintainer — see the
  [tj-actions supply-chain incident](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/).
- **Top-level `permissions: contents: read`** — the `GITHUB_TOKEN`
  starts read-only; individual jobs can grant more if they need it.
- **`persist-credentials: false`** on `actions/checkout` so the token
  isn't left sitting in `.git/config` for downstream steps to harvest.
- **Runner version pinned to `ubuntu-24.04`** (not `ubuntu-latest`) so
  image-rollover doesn't change behavior under your feet.
- **[`step-security/harden-runner`](https://github.com/step-security/harden-runner)** as the first step in every job — `disable-sudo: true`,
  an explicit `allowed-endpoints` allowlist, and `egress-policy: audit`
  so all network egress and process activity is logged for review in
  the Security tab. Promote to `egress-policy: block` after reviewing
  the audit baseline.
- **Dependabot** (`.github/dependabot.yml`) watches the `github-actions`
  ecosystem and opens grouped PRs weekly so the pinned SHAs above stay
  current.
- **`SECURITY.md`** documents the private vulnerability reporting
  channel (GitHub Security Advisories).
- **No caching, no secrets, no `${{ github.event.* }}` in `run:` blocks**
  in either workflow — i.e. both pass their own scanner with zero
  findings.

The CI uses these pinned actions today (all running on Node 24, the
runtime GitHub will require by default from June 2026):

| Action                       | Pinned SHA                                   | Version | Node |
| ---------------------------- | -------------------------------------------- | ------- | ---- |
| `actions/checkout`           | `de0fac2e4500dabe0009e67214ff5f5447ce83dd`   | v6.0.2  | 24   |
| `actions/setup-python`       | `a309ff8b426b58ec0e2a45f0f869d46889d02405`   | v6.2.0  | 24   |
| `astral-sh/setup-uv`         | `08807647e7069bb48b6ef5acd8ec9567f424441b`   | v8.1.0  | 24   |
| `github/codeql-action`       | `c10b8064de6f491fea524254123dbe5e09572f13`   | v4.35.1 | 24   |
| `step-security/harden-runner`| `f808768d1510423e83855289c910610ca9b43176`   | v2.17.0 | 24   |

To re-pin (e.g. after a Dependabot PR), verify the new SHA via the
release page first:

```bash
gh api repos/actions/checkout/git/refs/tags/v6.0.2 --jq '.object.sha'
```

### Repo-level hardening still to do (settings, not files)

The file-level hardening is in place. A few things require touching
the repo settings on github.com and can't be expressed as files:

- **Enable [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)**
  so the link in `SECURITY.md` works.
- **Branch protection on `main`:** require PRs, require status checks
  (`Tests` and `CodeQL` jobs), require linear history, dismiss stale
  approvals on new pushes.
- **Disallow force pushes and direct pushes to `main`.**
- **Require signed commits.**
- **Enable GitHub Secret Scanning push protection.**
- **Once the Harden-Runner audit-mode log shows a stable egress
  baseline,** switch `egress-policy: audit` → `block` in each workflow.

## Limitations

- Scans the **default branch** only. Workflow files on feature branches
  can still be exploited but tend to be ephemeral.
- Doesn't follow `uses:` references into reusable workflows in other
  repos — review those separately.
- Heuristic. A clean report ≠ proof of no vulnerabilities; a noisy
  report ≠ proof of exploitability. Triage in context.

## Credits

Co-developed with [Claude](https://claude.com) (Anthropic) in a Cowork
session — detector rules, scanner, tests, CI workflow, and docs were
drafted by Claude and reviewed / iterated on by a human maintainer
before shipping. The detector ruleset is grounded in published research
by [Adnan Khan](https://github.com/AdnaneKhan)
([Cacheract](https://github.com/adnaneKhan/cacheract)) and the
[GitHub Security Lab](https://securitylab.github.com/research/github-actions-untrusted-input/).
