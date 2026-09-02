"""GOVERNANCE DRIFT: diff two cards' check results.

Answers what a reviewer asks on every pull request:
- What got WORSE (a control that passed now fails — e.g. the budget ceiling was deleted)?
- What got FIXED?
- What changed evidence (same status, different code locations)?

Pure comparison of two findings.json files. Deterministic, offline, $0.
Adapted from the author's sibling project Cybwaydb (Apache-2.0).
"""

from __future__ import annotations

import json
from pathlib import Path

FAIL = "FAIL"


def load_findings(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff_cards(old: list[dict], new: list[dict]) -> dict:
    old_by_id = {f["check_id"]: f for f in old}
    new_by_id = {f["check_id"]: f for f in new}
    old_fail = {c for c, f in old_by_id.items() if f["status"] == FAIL}
    new_fail = {c for c, f in new_by_id.items() if f["status"] == FAIL}
    common = set(old_by_id) & set(new_by_id)

    evidence_changed = sorted(
        c for c in common
        if old_by_id[c]["status"] == new_by_id[c]["status"]
        and old_by_id[c]["evidence"] != new_by_id[c]["evidence"]
    )
    regressed = sorted((new_fail - old_fail) & common)
    fixed = sorted((old_fail - new_fail) & common)
    return {
        "regressed": regressed,
        "fixed": fixed,
        "still_failing": sorted(old_fail & new_fail),
        "evidence_changed": evidence_changed,
        "checks_added": sorted(set(new_by_id) - set(old_by_id)),
        "checks_removed": sorted(set(old_by_id) - set(new_by_id)),
        "verdict": "REGRESSED" if regressed else "IMPROVED" if fixed else "UNCHANGED",
    }
