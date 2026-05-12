#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
cache_vuln_scan.py — Audit GitHub Actions workflows across orgs/repos you
have access to for patterns that enable cache-poisoning attacks (e.g.
Cacheract) and the script-injection / unsafe-checkout vulnerabilities
that feed them.

Prior art / required reading:
  - Cacheract (Adnan Khan) — proof-of-concept Actions-cache-native malware
    https://github.com/adnaneKhan/cacheract
  - "Guarding Against Cacheract" — the hardening checklist this scanner
    implements:
    https://github.com/adnaneKhan/cacheract#guarding-against-cacheract
  - GitHub Security Lab — keeping GitHub Actions workflows secure:
    https://securitylab.github.com/research/github-actions-untrusted-input/
  - GitHub docs — Security hardening for GitHub Actions:
    https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions

Run with uv (no virtualenv required):

  uv run cache_vuln_scan.py --orgs linuxfoundation
  # or, after `chmod +x`:
  ./cache_vuln_scan.py --orgs linuxfoundation

USAGE
-----
  # Auth via gh CLI (recommended) or GITHUB_TOKEN env var.
  # Scan every org you belong to (+ your own personal repos):
  uv run cache_vuln_scan.py

  # Scan specific orgs:
  uv run cache_vuln_scan.py --orgs linuxfoundation cncf openssf

  # Scan a user/namespace (public repos owned by that user):
  uv run cache_vuln_scan.py --users adnaneKhan torvalds

  # Scan everything YOU own — public + private repos in your namespace:
  uv run cache_vuln_scan.py --me

  # Mix orgs, users, and yourself in one invocation:
  uv run cache_vuln_scan.py --orgs cncf --users adnaneKhan --me

  # Scan a single repo (quick test):
  uv run cache_vuln_scan.py --repos owner/name

  # Only flag findings where you have admin (i.e. you can fix them):
  uv run cache_vuln_scan.py --admin-only

  # Tune output:
  uv run cache_vuln_scan.py --out-dir ./cache-vuln-report --no-archived

OUTPUT
------
  <out-dir>/summary.md                          — latest cross-owner index
  <out-dir>/<owner>/YYYY-MM-DD-findings.json    — per-owner JSON (dated)
  <out-dir>/<owner>/YYYY-MM-DD-report.md        — per-owner report (dated)

Per-owner subdirectories mean concurrent scans against different orgs
sharing the same --out-dir don't overwrite each other's results. The
ISO 8601 short-date prefix (YYYY-MM-DD) on filenames means re-running
on a different day builds up scan history rather than overwriting it.
Same-day re-runs do overwrite (one report per owner per day).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

API = "https://api.github.com"
USER_AGENT = "cache-vuln-scan/1.0 (defensive; ref: github.com/adnaneKhan/cacheract)"


# --------------------------------------------------------------------------- #
# Auth                                                                        #
# --------------------------------------------------------------------------- #
def get_token() -> str:
    """Resolve a GitHub token from gh CLI first, then GITHUB_TOKEN."""
    if shutil.which("gh"):
        try:
            out = subprocess.run(
                ["gh", "auth", "token"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            tok = out.stdout.strip()
            if tok:
                return tok
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not tok:
        sys.exit(
            "ERROR: No GitHub credentials found. Run `gh auth login` or set "
            "GITHUB_TOKEN."
        )
    return tok


# --------------------------------------------------------------------------- #
# HTTP                                                                        #
# --------------------------------------------------------------------------- #
class GitHub:
    def __init__(self, token: str, verbose: bool = False) -> None:
        self.token = token
        self.verbose = verbose

    def _req(self, url: str, accept: str = "application/vnd.github+json") -> Any:
        backoff = 1.0
        for attempt in range(6):
            req = urlrequest.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": accept,
                    "User-Agent": USER_AGENT,
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                with urlrequest.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                    remaining = resp.headers.get("X-RateLimit-Remaining")
                    if remaining and int(remaining) < 50 and self.verbose:
                        print(
                            f"  [rate-limit] {remaining} requests remaining",
                            file=sys.stderr,
                        )
                    if accept.endswith("raw"):
                        return data
                    return json.loads(data.decode("utf-8")) if data else None
            except urlerror.HTTPError as e:
                # Handle secondary rate limits / abuse detection / transient 5xx.
                if e.code in (403, 429) and "rate limit" in (
                    e.read().decode("utf-8", "ignore") if e.fp else ""
                ).lower():
                    wait = float(e.headers.get("Retry-After", backoff))
                    if self.verbose:
                        print(
                            f"  [rate-limit] sleeping {wait:.1f}s",
                            file=sys.stderr,
                        )
                    time.sleep(wait)
                    backoff *= 2
                    continue
                if e.code in (404, 451):
                    return None
                if e.code >= 500 and attempt < 5:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise
            except urlerror.URLError:
                if attempt < 5:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise
        return None

    def paged(self, url: str, params: dict | None = None) -> Iterable[dict]:
        params = dict(params or {})
        params.setdefault("per_page", 100)
        sep = "&" if "?" in url else "?"
        cur = f"{url}{sep}{urlparse.urlencode(params)}"
        while cur:
            req = urlrequest.Request(
                cur,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": USER_AGENT,
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            with urlrequest.urlopen(req, timeout=30) as resp:
                page = json.loads(resp.read().decode("utf-8"))
                if isinstance(page, dict) and "items" in page:
                    yield from page["items"]
                else:
                    yield from page
                link = resp.headers.get("Link", "")
                cur = None
                for part in link.split(","):
                    if 'rel="next"' in part:
                        cur = part.split(";")[0].strip(" <>")
                        break

    def get(self, path: str, **params) -> Any:
        url = f"{API}{path}"
        if params:
            url = f"{url}?{urlparse.urlencode(params)}"
        return self._req(url)

    def get_raw(self, path: str) -> bytes | None:
        return self._req(f"{API}{path}", accept="application/vnd.github.raw")


# --------------------------------------------------------------------------- #
# Detectors                                                                   #
# --------------------------------------------------------------------------- #
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _safe_dirname(login: str) -> str:
    """Sanitize an owner login for use as a directory name. GitHub logins
    are already restricted to [A-Za-z0-9-], but defensively strip anything
    odd so we can't write outside out-dir."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", login).strip("._-") or "unknown"
    return cleaned


@dataclass
class Finding:
    repo: str
    workflow: str
    line: int
    rule: str
    severity: str
    message: str
    snippet: str
    permalink: str
    extra: dict = field(default_factory=dict)


# Untrusted-input contexts that, when interpolated into a shell or JS step,
# turn into a script-injection sink. List based on the GitHub Security Lab
# research and Adnan Khan's own GHSA disclosures.
UNTRUSTED_CONTEXTS = [
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.pages\.[^}\s]*\.page_name",
    r"github\.event\.commits\.[^}]*\.message",
    r"github\.event\.commits\.[^}]*\.author\.email",
    r"github\.event\.commits\.[^}]*\.author\.name",
    r"github\.event\.head_commit\.message",
    r"github\.event\.head_commit\.author\.email",
    r"github\.event\.head_commit\.author\.name",
    r"github\.event\.workflow_run\.head_branch",
    r"github\.event\.workflow_run\.display_title",
    r"github\.event\.workflow_run\.head_commit\.message",
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.head_ref",
]
RX_UNTRUSTED = re.compile(
    r"\$\{\{\s*[^}]*?(" + "|".join(UNTRUSTED_CONTEXTS) + r")[^}]*?\}\}"
)

RX_RUN_BLOCK = re.compile(r"^\s*(-\s*)?run\s*:\s*(\|[+-]?|>[+-]?|.*)$")
RX_USES_LINE = re.compile(r"^\s*-?\s*uses\s*:\s*(.+?)\s*(#.*)?$")
RX_TRIGGER_LINE = re.compile(r"^\s*(on)\s*:\s*(.*)$")
RX_NAME_LINE = re.compile(r"^\s*name\s*:\s*(.+)$")
RX_SCRIPT_KW = re.compile(r"^\s*script\s*:\s*(\|[+-]?|>[+-]?|.*)$")

CACHE_ACTION_RX = re.compile(
    r"\b(actions/cache|actions/cache/restore|actions/cache/save)@", re.I
)
SETUP_WITH_CACHE_RX = re.compile(
    r"\bactions/(setup-node|setup-python|setup-java|setup-go|setup-ruby|"
    r"setup-dotnet|setup-elixir|setup-haskell)@",
    re.I,
)

CHECKOUT_RX = re.compile(r"\bactions/checkout@", re.I)

# Words that strongly suggest a workflow publishes / releases artifacts —
# i.e. the kind of workflow where cache poisoning lets an attacker tamper
# with what ships to users.
RELEASE_KEYWORDS = [
    r"\bnpm\s+publish\b",
    r"\byarn\s+publish\b",
    r"\bpnpm\s+publish\b",
    r"\bpoetry\s+publish\b",
    r"\btwine\s+upload\b",
    r"\bgh\s+release\s+create\b",
    r"\bdocker\s+push\b",
    r"\bgoreleaser\b",
    r"\bcargo\s+publish\b",
    r"\bmaven-publish\b",
    r"\bgradle\s+publish\b",
    r"\baws\s+s3\s+(cp|sync)\b",
    r"\bcloudflare/wrangler-action\b",
    r"\bsoftprops/action-gh-release\b",
    r"\bjs-?devtools/npm-publish\b",
    r"\bpypa/gh-action-pypi-publish\b",
    r"\bdocker/build-push-action\b.*push:\s*true",
]
RX_RELEASE = re.compile("|".join(RELEASE_KEYWORDS), re.I)

SENSITIVE_SECRET_RX = re.compile(
    r"secrets\.("
    r"NPM_TOKEN|NPM_AUTH_TOKEN|PYPI_TOKEN|PYPI_API_TOKEN|TWINE_PASSWORD|"
    r"DOCKER_(USERNAME|PASSWORD|TOKEN)|GHCR_TOKEN|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"GCP_[A-Z_]+|AZURE_[A-Z_]+|"
    r"GPG_PRIVATE_KEY|SIGNING_KEY|CODESIGN_[A-Z_]+|APPLE_[A-Z_]+|"
    r"CARGO_REGISTRY_TOKEN|MAVEN_(USERNAME|PASSWORD|TOKEN)|"
    r"CLOUDFLARE_API_TOKEN|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|"
    r"SLACK_(BOT_)?TOKEN|"
    r"PERSONAL_ACCESS_TOKEN|PAT|ADMIN_TOKEN"
    r")\b",
    re.I,
)

ACTIONS_WRITE_RX = re.compile(r"^\s*actions\s*:\s*write\s*$", re.I | re.M)


def _split_workflow_top(text: str) -> dict[str, str]:
    """Crudely partition a workflow file into top-level sections by 0-indent
    keys. Good enough for trigger / permissions / jobs detection without a
    full YAML parser (so we don't bail on YAML errors in the wild)."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            key = line.split(":", 1)[0].strip().lower()
            if key and re.match(r"^[a-z_-]+$", key):
                current = key
                sections.setdefault(current, []).append(line)
                continue
        if current:
            sections[current].append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


def _trigger_names(text: str) -> set[str]:
    sections = _split_workflow_top(text)
    on_block = sections.get("on", "")
    triggers: set[str] = set()
    # `on: push` / `on: [push, pull_request]` / `on:\n  push:\n  pull_request:`
    first = on_block.split("\n", 1)[0]
    m = re.match(r"^\s*on\s*:\s*(.*)$", first)
    rest = ""
    if m:
        rest = m.group(1).strip()
    if rest:
        rest = rest.strip("[] ").replace("'", "").replace('"', "")
        for t in re.split(r"[\s,]+", rest):
            if t:
                triggers.add(t)
    for line in on_block.splitlines()[1:]:
        m = re.match(r"^\s{1,4}([a-z_]+)\s*:?\s*$", line)
        if m:
            triggers.add(m.group(1))
    return triggers


def _permissions_block(text: str) -> str:
    return _split_workflow_top(text).get("permissions", "")


def find_in_run_blocks(text: str, finder: re.Pattern) -> list[tuple[int, str]]:
    """Yield (line_number, line) where `finder` matches inside a `run:` or
    `script:` (github-script) value. Handles single-line and block scalars."""
    lines = text.splitlines()
    hits: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m_run = RX_RUN_BLOCK.match(line)
        m_script = RX_SCRIPT_KW.match(line)
        m = m_run or m_script
        if not m:
            i += 1
            continue
        body = (m.group(2) if m_run else m.group(1)) or ""
        indent = len(line) - len(line.lstrip(" "))
        # Single-line run
        if not body.strip().startswith(("|", ">")):
            if finder.search(line):
                hits.append((i + 1, line.rstrip()))
            i += 1
            continue
        # Block scalar — gather while indent > step indent
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            stripped = ln.strip()
            ln_indent = len(ln) - len(ln.lstrip(" "))
            if stripped and ln_indent <= indent:
                break
            if finder.search(ln):
                hits.append((j + 1, ln.rstrip()))
            j += 1
        i = j
    return hits


def find_dangerous_checkout(text: str) -> list[tuple[int, str]]:
    """Find actions/checkout steps that pass an untrusted ref/sha."""
    lines = text.splitlines()
    hits: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        if CHECKOUT_RX.search(lines[i]):
            # Look ahead a small window for a `with:` block.
            window = "\n".join(lines[i : i + 15])
            if re.search(
                r"\bref\s*:\s*.*\$\{\{\s*github\.(event\.(pull_request|issue|workflow_run)\."
                r"[^}]*|head_ref)\s*\}\}",
                window,
            ):
                hits.append((i + 1, lines[i].rstrip()))
        i += 1
    return hits


def line_of(text: str, needle_regex: re.Pattern) -> int | None:
    for idx, line in enumerate(text.splitlines(), 1):
        if needle_regex.search(line):
            return idx
    return None


def scan_workflow(
    repo: str, path: str, html_url: str, text: str
) -> list[Finding]:
    findings: list[Finding] = []
    triggers = _trigger_names(text)
    perms = _permissions_block(text)
    actions_write = bool(ACTIONS_WRITE_RX.search(perms))
    uses_cache = bool(CACHE_ACTION_RX.search(text)) or bool(
        SETUP_WITH_CACHE_RX.search(text)
    )

    def add(rule, severity, message, line, snippet, **extra):
        findings.append(
            Finding(
                repo=repo,
                workflow=path,
                line=line,
                rule=rule,
                severity=severity,
                message=message,
                snippet=snippet[:240],
                permalink=f"{html_url}#L{line}",
                extra=extra,
            )
        )

    # 1) Script injection: untrusted context inside run/script
    for ln, snippet in find_in_run_blocks(text, RX_UNTRUSTED):
        add(
            "script-injection",
            "critical",
            "Untrusted GitHub context interpolated into a run/script step. "
            "This is the primary initial-access vector for Cacheract-style "
            "implants — an attacker can execute arbitrary code via PR title, "
            "comment body, branch name, etc.",
            ln,
            snippet,
        )

    # 2) pull_request_target + checkout of untrusted ref
    if "pull_request_target" in triggers:
        for ln, snippet in find_dangerous_checkout(text):
            add(
                "pr-target-checkout",
                "critical",
                "pull_request_target workflow checks out untrusted head ref. "
                "Runs with default-branch token + secrets; attacker code "
                "executes with full repo permissions.",
                ln,
                snippet,
            )
        # Also flag pull_request_target merely with caches — risky even
        # without explicit checkout of untrusted ref, since downstream steps
        # may consume PR content.
        if uses_cache:
            ln = line_of(text, CACHE_ACTION_RX) or line_of(text, SETUP_WITH_CACHE_RX) or 1
            add(
                "pr-target-cache",
                "high",
                "pull_request_target workflow consumes a cache. Even with a "
                "safe checkout this expands the cache-poisoning attack "
                "surface.",
                ln,
                text.splitlines()[ln - 1] if ln else "",
            )

    # 3) issue_comment + checkout
    if "issue_comment" in triggers and CHECKOUT_RX.search(text):
        ln = line_of(text, CHECKOUT_RX) or 1
        add(
            "issue-comment-checkout",
            "high",
            "issue_comment workflow checks out code. Runs in default-branch "
            "context — anyone who can comment may trigger privileged "
            "execution if PR/issue content is consumed.",
            ln,
            text.splitlines()[ln - 1] if ln else "",
        )

    # 4) workflow_run + checkout + cache
    if "workflow_run" in triggers and CHECKOUT_RX.search(text):
        ln = line_of(text, CHECKOUT_RX) or 1
        add(
            "workflow-run-checkout",
            "high",
            "workflow_run handler checks out code. Like pull_request_target, "
            "runs with elevated permissions in default-branch context.",
            ln,
            text.splitlines()[ln - 1] if ln else "",
        )

    # 5) Cache in release/publish context
    if uses_cache and RX_RELEASE.search(text):
        ln = line_of(text, RX_RELEASE) or 1
        add(
            "cache-in-release",
            "high",
            "Workflow publishes/releases artifacts AND consumes a cache. "
            "Cacheract README rule #1: never consume caches in release "
            "builds — a poisoned cache can ship backdoored artifacts.",
            ln,
            text.splitlines()[ln - 1] if ln else "",
        )

    # 6) Cache + sensitive secret
    if uses_cache and SENSITIVE_SECRET_RX.search(text):
        ln = line_of(text, SENSITIVE_SECRET_RX) or 1
        add(
            "cache-with-secrets",
            "medium",
            "Workflow consumes a cache AND references high-value secrets. "
            "Cacheract README rule #2: don't mix caches with sensitive "
            "secrets — cache poisoning can leak them.",
            ln,
            text.splitlines()[ln - 1] if ln else "",
        )

    # 7) actions: write + cache (Cacheract persistence precondition)
    if actions_write and uses_cache:
        ln = line_of(text, ACTIONS_WRITE_RX) or 1
        add(
            "actions-write-cache",
            "medium",
            "Workflow grants `actions: write` AND uses caches. This is the "
            "precondition that lets Cacheract overwrite existing cache "
            "entries on the default branch for long-term persistence.",
            ln,
            text.splitlines()[ln - 1] if ln else "",
        )

    return findings


# --------------------------------------------------------------------------- #
# Enumeration                                                                 #
# --------------------------------------------------------------------------- #
def list_orgs(gh: GitHub) -> list[str]:
    return [o["login"] for o in gh.paged(f"{API}/user/orgs")]


def list_org_repos(gh: GitHub, org: str, include_archived: bool) -> list[dict]:
    repos = []
    for r in gh.paged(f"{API}/orgs/{org}/repos", {"type": "all"}):
        if r.get("archived") and not include_archived:
            continue
        repos.append(r)
    return repos


def list_user_repos(gh: GitHub, include_archived: bool) -> list[dict]:
    """Repos affiliated with the *authenticated* user (your own personal
    namespace + collaborator repos)."""
    repos = []
    for r in gh.paged(
        f"{API}/user/repos", {"affiliation": "owner,collaborator,organization_member"}
    ):
        if r.get("archived") and not include_archived:
            continue
        repos.append(r)
    return repos


def list_my_owned_repos(gh: GitHub, include_archived: bool) -> list[dict]:
    """Repos *owned* by the authenticated user — public AND private. Hits
    /user/repos?affiliation=owner so it sees private repos a public
    /users/{login}/repos lookup would miss."""
    repos = []
    for r in gh.paged(
        f"{API}/user/repos", {"affiliation": "owner", "visibility": "all"}
    ):
        if r.get("archived") and not include_archived:
            continue
        repos.append(r)
    return repos


def list_named_user_repos(
    gh: GitHub, login: str, include_archived: bool
) -> list[dict]:
    """Public repos owned by a specific user namespace (e.g. `adnaneKhan`).

    GitHub serves user namespaces from /users/{login}/repos and orgs from
    /orgs/{login}/repos — they're different endpoints. If the named login
    turns out to be an org, we fall back to the org endpoint so the user
    doesn't have to know the distinction.
    """
    # Try the user endpoint first.
    try:
        out = []
        for r in gh.paged(
            f"{API}/users/{login}/repos", {"type": "owner"}
        ):
            if r.get("archived") and not include_archived:
                continue
            out.append(r)
        return out
    except urlerror.HTTPError as e:
        if e.code == 404:
            # Maybe it's an org — fall back.
            return list_org_repos(gh, login, include_archived)
        raise


def list_workflows(gh: GitHub, full_name: str) -> list[dict]:
    """Return [{path, html_url}] for files under .github/workflows."""
    out = []
    tree = gh.get(f"/repos/{full_name}/contents/.github/workflows")
    if not isinstance(tree, list):
        return out
    for entry in tree:
        if entry.get("type") != "file":
            continue
        name = entry.get("name", "")
        if not name.endswith((".yml", ".yaml")):
            continue
        out.append(
            {
                "path": entry["path"],
                "html_url": entry.get("html_url", ""),
                "download_url": entry.get("download_url"),
            }
        )
    return out


def fetch_workflow(gh: GitHub, full_name: str, path: str) -> str | None:
    data = gh.get_raw(f"/repos/{full_name}/contents/{urlparse.quote(path)}")
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


# --------------------------------------------------------------------------- #
# Reporting                                                                   #
# --------------------------------------------------------------------------- #
def render_markdown(
    findings: list[Finding],
    scanned: dict[str, int],
    owner: str | None = None,
) -> str:
    findings = sorted(
        findings, key=lambda f: (SEVERITY[f.severity], f.repo, f.workflow, f.line)
    )
    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)
    by_repo: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_repo[f.repo].append(f)

    lines = []
    if owner:
        lines.append(f"# Cache Vulnerability Report — `{owner}`")
    else:
        lines.append("# GitHub Actions Cache Vulnerability Report")
    lines.append("")
    lines.append(
        "Patterns flagged here can enable cache-poisoning attacks such as "
        "[Cacheract](https://github.com/adnaneKhan/cacheract) along with "
        "the script-injection / unsafe-checkout bugs that supply initial "
        "access."
    )
    lines.append("")
    if owner:
        lines.append(
            f"Scanned **{scanned['repos']}** repositories owned by "
            f"`{owner}` — **{scanned['workflows']}** workflow files "
            f"inspected."
        )
    else:
        lines.append(
            f"Scanned **{scanned['repos']}** repositories across "
            f"**{scanned['orgs']}** orgs / owners — "
            f"**{scanned['workflows']}** workflow files inspected."
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if by_sev.get(sev):
            lines.append(f"| {sev.title()} | {len(by_sev[sev])} |")
    lines.append("")
    lines.append("## Rule reference")
    lines.append("")
    rules = {
        "script-injection": "Untrusted context in `run:` / `github-script` — initial access vector.",
        "pr-target-checkout": "`pull_request_target` + checkout of head ref — RCE on default branch.",
        "pr-target-cache": "`pull_request_target` + caching — expanded cache poisoning surface.",
        "issue-comment-checkout": "`issue_comment` + checkout — privileged trigger from comments.",
        "workflow-run-checkout": "`workflow_run` + checkout — privileged trigger from upstream WF.",
        "cache-in-release": "Cache consumed in a publishing workflow — Cacheract README rule #1.",
        "cache-with-secrets": "Cache + high-value secrets — Cacheract README rule #2.",
        "actions-write-cache": "`actions: write` + cache — Cacheract persistence precondition.",
    }
    for rule, desc in rules.items():
        lines.append(f"- **`{rule}`** — {desc}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for repo, items in sorted(by_repo.items()):
        lines.append(f"### `{repo}`")
        lines.append("")
        for f in items:
            badge = {
                "critical": "🔴 CRITICAL",
                "high": "🟠 HIGH",
                "medium": "🟡 MEDIUM",
                "low": "🔵 LOW",
                "info": "⚪ INFO",
            }[f.severity]
            lines.append(f"- {badge} `{f.rule}` — [{f.workflow}:{f.line}]({f.permalink})")
            lines.append(f"  - {f.message}")
            if f.snippet:
                snippet = f.snippet.replace("`", "​`")
                lines.append(f"  - `{snippet}`")
        lines.append("")
    lines.append("---")
    lines.append(
        "Generated by `cache_vuln_scan.py`. Findings are heuristic — review "
        "each one in context before opening tickets. False positives are "
        "expected on linter/lint-only workflows that don't actually ship "
        "artifacts. See the Cacheract \"Guarding Against\" section for the "
        "underlying threat model: "
        "<https://github.com/adnaneKhan/cacheract#guarding-against-cacheract>."
    )
    return "\n".join(lines)


def render_summary(
    per_owner_repos: dict[str, int],
    per_owner_workflows: dict[str, int],
    per_owner_findings: dict[str, list[Finding]],
    run_date: str,
) -> str:
    """Top-level index across every scanned owner.

    `run_date` is the ISO 8601 short date (YYYY-MM-DD) used when this run's
    per-owner files were written; links point at that run's reports.
    """
    lines = [
        "# Cache Vulnerability Scan — Summary",
        "",
        f"Latest run: **{run_date}**",
        "",
        "Patterns flagged here can enable cache-poisoning attacks such as " +
        "[Cacheract](https://github.com/adnaneKhan/cacheract).",
        "",
        "| Owner | Repos | Workflows | Critical | High | Medium | Low | Report |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for owner in sorted(per_owner_repos.keys()):
        sev_counts = defaultdict(int)
        for f in per_owner_findings.get(owner, []):
            sev_counts[f.severity] += 1
        owner_dir = _safe_dirname(owner)
        report_path = f"{owner_dir}/{run_date}-report.md"
        lines.append(
            f"| `{owner}` "
            f"| {per_owner_repos[owner]} "
            f"| {per_owner_workflows[owner]} "
            f"| {sev_counts['critical']} "
            f"| {sev_counts['high']} "
            f"| {sev_counts['medium']} "
            f"| {sev_counts['low']} "
            f"| [{report_path}]({report_path}) |"
        )
    lines.append("")
    total_findings = sum(len(v) for v in per_owner_findings.values())
    lines.append(
        f"Total: **{len(per_owner_repos)}** owners, "
        f"**{sum(per_owner_repos.values())}** repos, "
        f"**{sum(per_owner_workflows.values())}** workflows, "
        f"**{total_findings}** findings."
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--orgs",
        nargs="*",
        default=None,
        help="Restrict to these org logins (uses /orgs/{login}/repos).",
    )
    p.add_argument(
        "--users",
        nargs="*",
        default=None,
        help=(
            "Restrict to these user namespaces (uses /users/{login}/repos). "
            "Falls back to the org endpoint if the login is actually an org."
        ),
    )
    p.add_argument(
        "--repos", nargs="*", default=None, help="Restrict to owner/name repos."
    )
    p.add_argument(
        "--me",
        action="store_true",
        help=(
            "Scan repos owned by the authenticated user — public AND "
            "private. Combinable with --orgs / --users."
        ),
    )
    p.add_argument(
        "--admin-only",
        action="store_true",
        help="Skip repos where you don't have admin permission.",
    )
    p.add_argument(
        "--no-archived", action="store_true", help="Skip archived repos (default: include)."
    )
    p.add_argument(
        "--out-dir",
        default="./cache-vuln-report",
        help="Where to write findings.json and report.md (default: ./cache-vuln-report).",
    )
    p.add_argument("--workers", type=int, default=8, help="Concurrent repo workers.")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args()


def scan_repo(gh: GitHub, repo: dict, admin_only: bool) -> tuple[list[Finding], int]:
    full = repo["full_name"]
    if admin_only and not (repo.get("permissions") or {}).get("admin"):
        return [], 0
    wfs = list_workflows(gh, full)
    findings: list[Finding] = []
    for wf in wfs:
        text = fetch_workflow(gh, full, wf["path"])
        if not text:
            continue
        findings.extend(scan_workflow(full, wf["path"], wf["html_url"], text))
    return findings, len(wfs)


def main() -> int:
    args = parse_args()
    token = get_token()
    gh = GitHub(token, verbose=args.verbose)

    # Stamp every file from this run with the same date so the output is
    # consistent even if midnight rolls over mid-scan.
    run_date = _dt.date.today().isoformat()  # 'YYYY-MM-DD'

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Resolve repos.
    repos: list[dict] = []
    explicit = bool(args.repos or args.orgs or args.users or args.me)
    if args.repos:
        for slug in args.repos:
            r = gh.get(f"/repos/{slug}")
            if r:
                repos.append(r)
    if args.orgs:
        for org in args.orgs:
            print(f"[+] Listing repos in org {org}", file=sys.stderr)
            repos.extend(list_org_repos(gh, org, include_archived=not args.no_archived))
    if args.users:
        for user in args.users:
            print(f"[+] Listing repos in user namespace {user}", file=sys.stderr)
            repos.extend(
                list_named_user_repos(gh, user, include_archived=not args.no_archived)
            )
    if args.me:
        print(
            "[+] Listing repos owned by the authenticated user (public + private)",
            file=sys.stderr,
        )
        repos.extend(list_my_owned_repos(gh, include_archived=not args.no_archived))
    if not explicit:
        print("[+] Discovering accessible orgs", file=sys.stderr)
        orgs = list_orgs(gh)
        print(f"    orgs: {', '.join(orgs) or '(none)'}", file=sys.stderr)
        for org in orgs:
            print(f"[+] Listing repos in {org}", file=sys.stderr)
            repos.extend(list_org_repos(gh, org, include_archived=not args.no_archived))
        # Also include user-affiliated repos (covers personal forks etc.)
        repos.extend(list_user_repos(gh, include_archived=not args.no_archived))

    # Always dedup — combining --orgs/--users can yield overlapping repos
    # (e.g. a user who's also an org member).
    seen = set()
    deduped = []
    for r in repos:
        if r["full_name"] in seen:
            continue
        seen.add(r["full_name"])
        deduped.append(r)
    repos = deduped

    print(f"[+] {len(repos)} repos to scan", file=sys.stderr)

    # Seed per-owner buckets for every owner we plan to scan, so an owner
    # that has zero findings still gets a clean report (rather than leaving
    # stale results from a previous run untouched).
    per_owner_repos: dict[str, int] = defaultdict(int)
    per_owner_workflows: dict[str, int] = defaultdict(int)
    per_owner_findings: dict[str, list[Finding]] = defaultdict(list)
    for r in repos:
        per_owner_repos[r["full_name"].split("/")[0]] += 1

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_repo, gh, r, args.admin_only): r for r in repos}
        done = 0
        for fut in cf.as_completed(futures):
            repo = futures[fut]
            done += 1
            try:
                findings, n_wf = fut.result()
            except Exception as e:  # noqa: BLE001
                print(f"    ! error scanning {repo['full_name']}: {e}", file=sys.stderr)
                continue
            owner = repo["full_name"].split("/")[0]
            per_owner_workflows[owner] += n_wf
            if findings:
                per_owner_findings[owner].extend(findings)
            if args.verbose or done % 25 == 0:
                print(
                    f"    [{done}/{len(repos)}] {repo['full_name']}: "
                    f"{n_wf} workflows, {len(findings)} findings",
                    file=sys.stderr,
                )

    # Write per-owner outputs into <out-dir>/<owner>/. Each file is prefixed
    # with the run date (YYYY-MM-DD) so re-running on a different day adds
    # to the history rather than overwriting. Same-day re-runs do overwrite.
    for owner in sorted(per_owner_repos.keys()):
        owner_dir = out_dir / _safe_dirname(owner)
        owner_dir.mkdir(parents=True, exist_ok=True)
        owner_findings = per_owner_findings.get(owner, [])
        per_summary = {
            "owner": owner,
            "run_date": run_date,
            "repos": per_owner_repos[owner],
            "workflows": per_owner_workflows[owner],
            "findings_count": len(owner_findings),
        }
        (owner_dir / f"{run_date}-findings.json").write_text(
            json.dumps(
                {
                    "summary": per_summary,
                    "findings": [dataclasses.asdict(f) for f in owner_findings],
                },
                indent=2,
            )
        )
        (owner_dir / f"{run_date}-report.md").write_text(
            render_markdown(
                owner_findings,
                {
                    "repos": per_owner_repos[owner],
                    "orgs": 1,
                    "workflows": per_owner_workflows[owner],
                },
                owner=owner,
            )
        )

    # Top-level index — kept at a stable name (summary.md) so it's easy to
    # bookmark; always points at the most recent run's per-owner reports.
    (out_dir / "summary.md").write_text(
        render_summary(
            per_owner_repos, per_owner_workflows, per_owner_findings, run_date
        )
    )

    total_findings = sum(len(v) for v in per_owner_findings.values())
    print(
        f"[+] Wrote per-owner reports under {out_dir}/ "
        f"({run_date}, {len(per_owner_repos)} owners, {total_findings} findings). "
        f"Index: {out_dir/'summary.md'}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
