"""Repo-hygiene controls run over THIS repository (defensive self-checks).

- secret_scan: credential-shaped strings that must never be committed.
- policy_lint: CLAUDE.md hard rules that can be checked mechanically
  (an unignored .env, forbidden third-party content).

Deterministic, offline, stdlib-only. Adapted from the author's sibling
project Cybwaydb (Apache-2.0, same copyright holder).
"""

from __future__ import annotations

import re
from pathlib import Path

# Detection-only patterns for credential-shaped content.
SECRET_PATTERNS = [
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}")),
    ("openai_style_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("generic_api_key", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("password_assignment", re.compile(r"(?i)\bpassword\b\s*[:=]\s*['\"](?!fake|synthetic|changeme|xxx)[^'\"]{6,}['\"]")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# Copyrighted third-party benchmark content is excluded from this repo (LEGAL.md).
POLICY_FORBIDDEN_TERMS = ["cis benchmark", "cis_benchmark"]

SCAN_EXTENSIONS = {".py", ".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".html", ".js"}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "runs", "build", "dist"}


def _iter_files(root: str | Path):
    for p in Path(root).rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix.lower() in SCAN_EXTENSIONS:
            yield p


def secret_scan(root: str | Path, allowlist: set[str] | None = None) -> list[dict]:
    """Scan text files under root for credential-shaped strings. Empty list = clean."""
    allowlist = allowlist or set()
    hits = []
    for p in _iter_files(root):
        if p.name in allowlist:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if "secret-scan: allow" in line or "re.compile(" in line:
                continue  # pattern definitions are not secrets
            for name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    hits.append({"file": str(p), "line": lineno, "pattern": name})
    return hits


def policy_lint(root: str | Path) -> list[dict]:
    """Enforce the mechanically checkable CLAUDE.md rules across the repo."""
    violations = []
    for p in _iter_files(root):
        if p.name in ("controls.py", "CLAUDE.md", "LEGAL.md"):
            continue  # these files state the policy itself
        if "evidence" in p.parts:
            continue  # captured scan output quotes the *target's* files; the secret scan still covers it
        text = p.read_text(encoding="utf-8", errors="replace").lower()
        for term in POLICY_FORBIDDEN_TERMS:
            if term in text:
                violations.append({"file": str(p), "term": term})
    env = Path(root) / ".env"
    if env.exists():
        gitignore = Path(root) / ".gitignore"
        ignored = gitignore.exists() and ".env" in gitignore.read_text(encoding="utf-8")
        if not ignored:
            violations.append({"file": str(env), "term": ".env present but not gitignored"})
    return violations
