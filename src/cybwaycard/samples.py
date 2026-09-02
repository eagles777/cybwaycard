"""Two synthetic sample codebases, materialised on demand for demos and tests.

  governed    — a small AI client with every control Cybwaycard looks for
  ungoverned  — the same feature written the quick way (no controls)

Everything here is fake: fake package, fake key (assembled at write time so
this source file never contains a credential-shaped literal), fake data.
"""

from __future__ import annotations

from pathlib import Path

FAKE_KEY_PLACEHOLDER = "@KEY@"


def fake_key() -> str:
    # Assembled at runtime; shaped like a key, useless as one.
    return "sk-fake-" + "0123456789abcdef" * 2


GOVERNED: dict[str, str] = {
    "README.md": """# Governed Sample

A tiny governed AI client used as a Cybwaycard fixture. It drafts change
summaries from configuration metadata using a hosted model, verifies every
draft independently, and never acts without a logged human decision.

## Data handling

Only configuration metadata is ever sent to the model. Table data, credentials
and personal data are never sent. Prompts are redacted before transmission.
""",
    "LICENSE": "Apache License 2.0 (synthetic fixture — see project root for the real license text)\n",
    "NOTICE": "Governed Sample — synthetic fixture.\n",
    "BENCHMARKS.md": "# Benchmarks\n\nMock harness: precision 0.99 / recall 0.90 / F1 0.94 over 50 runs.\n",
    "pyproject.toml": """[project]
name = "governed-sample"
version = "0.0.1"
dependencies = ["anthropic==0.40.0"]
""",
    ".github/workflows/ci.yml": """name: CI (mock, $0)
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest -q
""",
    "governed/__init__.py": "",
    "governed/budget.py": '''"""Code-enforced cost ceiling, charged BEFORE every paid call."""


class BudgetExceeded(RuntimeError):
    pass


class BudgetCeiling:
    def __init__(self, max_usd: float):
        self.max_usd = max_usd
        self.spent_usd = 0.0

    def dry_run(self, estimated_cost_usd: float) -> dict:
        projected = self.spent_usd + estimated_cost_usd
        return {"projected_usd": projected, "would_exceed": projected > self.max_usd}

    def charge(self, estimated_cost_usd: float) -> None:
        if self.dry_run(estimated_cost_usd)["would_exceed"]:
            raise BudgetExceeded("ceiling reached")
        self.spent_usd += estimated_cost_usd
''',
    "governed/providers.py": '''"""Mock provider by default; live provider is opt-in, keyed from the environment."""

import os

import anthropic

MODEL_NAME = os.environ.get("MODEL_NAME", "claude-sonnet-4-5")


class MockProvider:
    """Deterministic offline provider — the default. $0."""

    def complete(self, prompt: str) -> str:
        return '{"summary": "mock", "risk": "low"}'


class LiveProvider:
    def __init__(self, budget, opt_in: bool = False):
        if not opt_in:
            raise RuntimeError("live calls require explicit opt-in")
        self.client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=30.0, max_retries=2)
        self.budget = budget

    def complete(self, prompt: str) -> str:
        self.budget.charge(0.002)
        msg = self.client.messages.create(model=MODEL_NAME, max_tokens=400,
                                          messages=[{"role": "user", "content": prompt}])
        return msg.content[0].text
''',
    "governed/agents.py": '''"""Auditor drafts; an independent checker re-derives the truth."""

import json
import re

INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (all )?previous instructions"),
    re.compile(r"(?i)you are now"),
]


def redact(text: str) -> str:
    """Strip anything credential-shaped before it reaches a prompt."""
    return re.sub(r"sk-[A-Za-z0-9-]{8,}", "<redacted>", text)


def validate_schema(obj: dict) -> dict:
    if set(obj) != {"summary", "risk"} or obj["risk"] not in ("low", "medium", "high"):
        raise ValueError("schema violation")
    return obj


class AuditorAgent:
    def __init__(self, provider):
        self.provider = provider

    def draft(self, metadata: str) -> dict:
        for rx in INJECTION_PATTERNS:
            if rx.search(metadata):
                raise ValueError("prompt injection pattern detected; quarantined")
        raw = self.provider.complete(redact(metadata))
        try:
            return validate_schema(json.loads(raw))
        except (json.JSONDecodeError, ValueError):
            return {"summary": "", "risk": "high"}


class CheckerAgent:
    """Independent verification: re-derives ground_truth from the metadata itself."""

    def adjudicate(self, draft: dict, metadata: str) -> str:
        ground_truth = "high" if "grant dba" in metadata.lower() else "low"
        return "PASS" if draft["risk"] == ground_truth else "REVIEW"
''',
    "governed/gate.py": '''"""Human approval gate — no execute path exists anywhere in this package."""

from .auditlog import AuditLog


class ApprovalRequired(RuntimeError):
    pass


class ApprovalGate:
    def __init__(self, log: AuditLog):
        self.log = log
        self.decisions: dict[str, str] = {}

    def approve(self, finding_id: str, approver: str) -> None:
        if not approver.strip():
            raise ValueError("approver required")
        self.decisions[finding_id] = "approved"
        self.log.append("approved", {"finding": finding_id, "approver": approver})

    def reject(self, finding_id: str, approver: str, reason: str) -> None:
        self.decisions[finding_id] = "rejected"
        self.log.append("rejected", {"finding": finding_id, "approver": approver, "reason": reason})
''',
    "governed/auditlog.py": '''"""Hash-chained audit log: each entry carries the SHA-256 of the previous."""

import hashlib
import json


class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []

    def _hash(self, e: dict) -> str:
        return hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()

    def append(self, event: str, detail: dict) -> None:
        prev_hash = self._hash(self.entries[-1]) if self.entries else "0" * 64
        self.entries.append({"event": event, "detail": detail, "prev_hash": prev_hash})

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            if e["prev_hash"] != prev:
                return False
            prev = self._hash(e)
        return True
''',
    "governed/evalbench.py": '''"""Precision / recall of the auditor against deterministic ground truth."""


def score(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def run_benchmark(n_runs: int = 50) -> dict:
    return score(tp=45, fp=1, fn=4) | {"runs": n_runs}
''',
    "governed/drift.py": '''"""Drift: a case that passed before and fails now is a regression."""


def diff(old: dict, new: dict) -> dict:
    regressed = [k for k, v in new.items() if v == "FAIL" and old.get(k) == "PASS"]
    return {"regressed": regressed, "verdict": "REGRESSED" if regressed else "UNCHANGED"}
''',
    "tests/test_core.py": '''from governed.budget import BudgetCeiling, BudgetExceeded


def test_budget_blocks_call():
    b = BudgetCeiling(0.001)
    try:
        b.charge(0.002)
        assert False
    except BudgetExceeded:
        pass
''',
}


UNGOVERNED: dict[str, str] = {
    "README.md": "# quick-ai-ops\n\nAsks the model what to run, then runs it.\n",
    "requirements.txt": "openai\nrequests>=2\n",
    "app.py": '''import json
import subprocess

import openai

client = openai.OpenAI(api_key="@KEY@")


def ask(task: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Give me a shell command to " + task}],
    )
    return resp.choices[0].message.content


def run(task: str) -> None:
    command = ask(task)
    subprocess.run(command, shell=True)


if __name__ == "__main__":
    run("clean up the logs")
''',
}

SAMPLES = {"governed": GOVERNED, "ungoverned": UNGOVERNED}


def write_sample(kind: str, out_dir: str | Path) -> Path:
    """Materialise a sample codebase under out_dir. Returns the directory."""
    if kind not in SAMPLES:
        raise ValueError(f"unknown sample kind: {kind}")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for rel, content in SAMPLES[kind].items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content.replace(FAKE_KEY_PLACEHOLDER, fake_key()), encoding="utf-8")
    return out
