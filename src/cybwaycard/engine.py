"""Scan orchestrator: extract signals -> run checks -> build card -> write a
run directory with inventory, findings, card (JSON + Markdown), a hash-chained
audit log and a SHA-256 manifest. Read-only on the target. Offline, $0."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .auditlog import AuditLog, write_manifest
from .card import build_card, render_markdown
from .checks import FAIL, NA, PASS, run_all_checks
from .signals import extract


def run_scan(root: str | Path, out_dir: str | Path, generated_at: str | None = None,
             subject_name: str | None = None) -> dict:
    """Scan `root`, write artifacts to `out_dir`, return the card summary."""
    root = Path(root)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    log = AuditLog(out_dir / "audit.log.jsonl")

    log.append("scan_started", {"root": str(root.resolve()), "mode": "static", "cost_usd": 0}, timestamp=now)
    inv = extract(root)
    findings = run_all_checks(inv)
    for f in findings:
        log.append("check_evaluated", {"check_id": f.check_id, "status": f.status, "severity": f.severity}, timestamp=now)

    card = build_card(inv, findings, generated_at=now, subject_name=subject_name)
    (out_dir / "inventory.json").write_text(json.dumps(inv.to_dict(), indent=2), encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    (out_dir / "card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    (out_dir / "card.md").write_text(render_markdown(card), encoding="utf-8")

    summary = {
        "subject": card["subject"]["name"],
        "verdict": card["summary"]["verdict"],
        "score_pct": card["summary"]["score_pct"],
        "pass": card["summary"]["pass"], "fail": card["summary"]["fail"], "na": card["summary"]["na"],
        "total": len(findings),
        "uses_ai": inv.uses_ai,
        "mode": "static", "cost_usd": 0,
    }
    log.append("scan_completed", summary, timestamp=now)
    write_manifest(out_dir, {"summary": summary, "generated_at": now})
    return summary


def integrity_of(run_dir: str | Path) -> dict:
    """Chain + manifest status for a run directory (used by the HTML render)."""
    from .auditlog import verify_manifest
    run_dir = Path(run_dir)
    chain_ok, chain_msg = AuditLog(run_dir / "audit.log.jsonl").verify_chain()
    man_ok, problems = verify_manifest(run_dir)
    sha = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")).get("manifest_sha256", "")
    return {"chain_ok": chain_ok, "chain_msg": chain_msg, "manifest_ok": man_ok,
            "manifest_problems": problems, "manifest_sha256": sha}


__all__ = ["run_scan", "integrity_of", "PASS", "FAIL", "NA"]
