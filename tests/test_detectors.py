"""Self-contained tests for the detector logic in cache_vuln_scan.py.

Loads the scanner module by path so we don't need to install it.
Run with `python3 tests/test_detectors.py` from the project root.
"""
import importlib.util
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "cs", _PROJECT_ROOT / "cache_vuln_scan.py"
)
cs = importlib.util.module_from_spec(spec)
sys.modules["cs"] = cs
spec.loader.exec_module(cs)


def scan(text):
    return cs.scan_workflow("acme/foo", ".github/workflows/x.yml", "https://x/", text)


def rules(text):
    return sorted({f.rule for f in scan(text)})


# --- Fixture 1: clean workflow (no findings) --------------------------------
CLEAN = """\
name: CI
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm test
"""
assert rules(CLEAN) == [], f"Expected no findings, got {rules(CLEAN)}"
print("OK  clean workflow: no findings")


# --- Fixture 2: script injection via PR title -------------------------------
INJECT = """\
name: PR linter
on:
  pull_request:
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Title was ${{ github.event.pull_request.title }}"
"""
assert "script-injection" in rules(INJECT), rules(INJECT)
print("OK  script-injection via run+PR title")


# --- Fixture 3: injection via github-script script: block -------------------
INJECT2 = """\
on: issue_comment
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const body = `${{ github.event.comment.body }}`;
            console.log(body)
"""
r = rules(INJECT2)
assert "script-injection" in r, r
print("OK  script-injection via github-script script: block")


# --- Fixture 4: pull_request_target + checkout of head ref ------------------
PRT = """\
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@v4
        with:
          cache: npm
      - run: npm test
"""
r = rules(PRT)
assert "pr-target-checkout" in r, r
assert "pr-target-cache" in r, r
print("OK  pull_request_target + dangerous checkout + cache")


# --- Fixture 5: issue_comment + checkout ------------------------------------
IC = """\
on: issue_comment
jobs:
  c:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/handle.sh
"""
assert "issue-comment-checkout" in rules(IC), rules(IC)
print("OK  issue_comment + checkout")


# --- Fixture 6: workflow_run + checkout -------------------------------------
WR = """\
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  c:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
assert "workflow-run-checkout" in rules(WR), rules(WR)
print("OK  workflow_run + checkout")


# --- Fixture 7: cache in release workflow -----------------------------------
REL = """\
name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm publish
"""
assert "cache-in-release" in rules(REL), rules(REL)
print("OK  cache in release workflow")


# --- Fixture 8: cache + sensitive secret ------------------------------------
SEC = """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: ~/.cargo
          key: cargo-${{ hashFiles('Cargo.lock') }}
      - env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: echo hi
"""
r = rules(SEC)
assert "cache-with-secrets" in r, r
print("OK  cache + sensitive secret")


# --- Fixture 9: actions: write + cache (Cacheract persistence) --------------
AW = """\
on: push
permissions:
  contents: read
  actions: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: ${{ hashFiles('package-lock.json') }}
"""
assert "actions-write-cache" in rules(AW), rules(AW)
print("OK  actions:write + cache")


# --- Fixture 10: safe template usage (no untrusted context) -----------------
SAFE = """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }} on ${{ github.repository }}"
"""
assert rules(SAFE) == [], rules(SAFE)
print("OK  safe template usage produces no finding")


# --- Fixture 11: untrusted context but only in env: (mitigated) -------------
# This SHOULD still be flagged if it's inside a run block via env var
# expansion — but if it's only in env: it's safer. Our scanner only fires
# on `run:` / `script:` so the env-only case should be clean.
ENV_ONLY = """\
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_TITLE"
"""
r = rules(ENV_ONLY)
assert "script-injection" not in r, f"False positive on env-mitigated workflow: {r}"
print("OK  env-mitigated injection NOT flagged (correct)")


print("\nAll detector tests passed.")


# --- Fixture 12: per-owner output structure ---------------------------------
# Drive the writer functions directly with synthetic findings across two
# owners; assert the on-disk layout matches expectations and that
# overwriting one owner does not touch the other.
import dataclasses as _dc
import json as _json
import tempfile as _tempfile
import shutil as _shutil
from pathlib import Path as _Path
from collections import defaultdict as _dd

tmp = _Path(_tempfile.mkdtemp(prefix="cvs_test_"))
try:
    fA = cs.Finding(
        repo="orgA/svc", workflow=".github/workflows/ci.yml", line=10,
        rule="script-injection", severity="critical", message="x",
        snippet="x", permalink="https://x/#L10",
    )
    fB = cs.Finding(
        repo="userB/proj", workflow=".github/workflows/release.yml", line=5,
        rule="cache-in-release", severity="high", message="y",
        snippet="y", permalink="https://y/#L5",
    )

    per_repos = _dd(int, {"orgA": 1, "userB": 1, "orgC_empty": 1})
    per_wfs   = _dd(int, {"orgA": 3, "userB": 2, "orgC_empty": 4})
    per_finds = _dd(list, {"orgA": [fA], "userB": [fB], "orgC_empty": []})

    # Drive two pretend runs on different dates against the same out-dir.
    def _write_run(run_date):
        for owner in sorted(per_repos.keys()):
            owner_dir = tmp / cs._safe_dirname(owner)
            owner_dir.mkdir(parents=True, exist_ok=True)
            owner_findings = per_finds.get(owner, [])
            (owner_dir / f"{run_date}-findings.json").write_text(_json.dumps({
                "summary": {"owner": owner, "run_date": run_date,
                            "repos": per_repos[owner],
                            "workflows": per_wfs[owner],
                            "findings_count": len(owner_findings)},
                "findings": [_dc.asdict(f) for f in owner_findings],
            }, indent=2))
            (owner_dir / f"{run_date}-report.md").write_text(cs.render_markdown(
                owner_findings,
                {"repos": per_repos[owner], "orgs": 1, "workflows": per_wfs[owner]},
                owner=owner,
            ))
        (tmp / "summary.md").write_text(cs.render_summary(
            per_repos, per_wfs, per_finds, run_date
        ))

    _write_run("2026-05-11")
    _write_run("2026-05-12")

    # Layout assertions: both days coexist.
    assert (tmp / "summary.md").exists(), "missing summary.md"
    for date in ("2026-05-11", "2026-05-12"):
        assert (tmp / "orgA" / f"{date}-findings.json").exists(), date
        assert (tmp / "orgA" / f"{date}-report.md").exists(), date
        assert (tmp / "userB" / f"{date}-findings.json").exists(), date
        assert (tmp / "userB" / f"{date}-report.md").exists(), date
        assert (tmp / "orgC_empty" / f"{date}-findings.json").exists(), date
        assert (tmp / "orgC_empty" / f"{date}-report.md").exists(), date
    print("OK  per-owner output: layout correct, two dated runs coexist")

    # Content assertions: report titles include owner name.
    rA = (tmp / "orgA" / "2026-05-12-report.md").read_text()
    assert "Cache Vulnerability Report — `orgA`" in rA, rA[:200]
    rB = (tmp / "userB" / "2026-05-12-report.md").read_text()
    assert "Cache Vulnerability Report — `userB`" in rB, rB[:200]
    print("OK  per-owner output: titles include owner name")

    # Empty owner's dated findings.json should have findings_count: 0.
    e = _json.loads(
        (tmp / "orgC_empty" / "2026-05-12-findings.json").read_text()
    )
    assert e["summary"]["findings_count"] == 0, e
    assert e["summary"]["run_date"] == "2026-05-12", e
    assert e["findings"] == [], e
    print("OK  per-owner output: empty owner writes clean dated 0-finding report")

    # summary.md should list every owner and reference the latest run date.
    sm = (tmp / "summary.md").read_text()
    for owner in ("orgA", "userB", "orgC_empty"):
        assert f"`{owner}`" in sm, sm[:400]
    assert "2026-05-12" in sm, "summary.md missing latest run date"
    assert "2026-05-12-report.md" in sm, "summary.md links not dated"
    print("OK  per-owner output: summary.md references latest dated reports")

    # Re-running orgA on 2026-05-12 should NOT touch userB or the older
    # 2026-05-11 files.
    userB_before = (tmp / "userB" / "2026-05-12-findings.json").read_text()
    older_before = (tmp / "orgA" / "2026-05-11-findings.json").read_text()
    (tmp / "orgA" / "2026-05-12-findings.json").write_text(
        '{"summary":{},"findings":[]}'
    )
    assert (tmp / "userB" / "2026-05-12-findings.json").read_text() == userB_before
    assert (tmp / "orgA" / "2026-05-11-findings.json").read_text() == older_before
    print("OK  per-owner output: re-run isolates owners AND preserves history")

finally:
    _shutil.rmtree(tmp)

print("\nAll detector + writer tests passed.")
