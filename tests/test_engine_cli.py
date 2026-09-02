"""End-to-end: scan -> artifacts -> verify -> tamper detection -> drift -> CLI -> controls."""

import json
from pathlib import Path

from cybwaycard.auditlog import AuditLog, verify_manifest
from cybwaycard.cli import main
from cybwaycard.controls import policy_lint, secret_scan
from cybwaycard.drift import diff_cards, load_findings
from cybwaycard.engine import integrity_of, run_scan
from cybwaycard.samples import write_sample

REPO = Path(__file__).resolve().parents[1]
NOW = "2026-01-01T00:00:00+00:00"


def test_scan_writes_all_artifacts(tmp_path):
    src = write_sample("governed", tmp_path / "src")
    out = tmp_path / "run"
    summary = run_scan(src, out, generated_at=NOW)
    for name in ("inventory.json", "findings.json", "card.json", "card.md", "audit.log.jsonl", "manifest.json"):
        assert (out / name).exists(), name
    assert summary["verdict"] == "GOVERNED" and summary["cost_usd"] == 0 and summary["mode"] == "static"
    log = AuditLog(out / "audit.log.jsonl")
    events = [e["event"] for e in log.entries()]
    assert events[0] == "scan_started" and events[-1] == "scan_completed"
    assert events.count("check_evaluated") == 19
    assert log.verify_chain()[0] and verify_manifest(out)[0]
    integ = integrity_of(out)
    assert integ["chain_ok"] and integ["manifest_ok"] and len(integ["manifest_sha256"]) == 64


def test_tamper_is_detected(tmp_path):
    src = write_sample("ungoverned", tmp_path / "src")
    out = tmp_path / "run"
    run_scan(src, out, generated_at=NOW)
    # edit a finding after the fact -> manifest mismatch
    p = out / "findings.json"
    p.write_text(p.read_text(encoding="utf-8").replace('"FAIL"', '"PASS"', 1), encoding="utf-8")
    ok, problems = verify_manifest(out)
    assert not ok and problems == ["hash mismatch: findings.json"]
    # delete a log line -> chain broken
    lp = out / "audit.log.jsonl"
    lines = lp.read_text(encoding="utf-8").splitlines()
    lp.write_text("\n".join(lines[:3] + lines[4:]) + "\n", encoding="utf-8")
    ok, msg = AuditLog(lp).verify_chain()
    assert not ok and "chain broken" in msg


def test_drift_detects_removed_control(tmp_path):
    good = write_sample("governed", tmp_path / "good")
    run_scan(good, tmp_path / "r1", generated_at=NOW)
    # remove the drift module -> CARD-012 regresses
    (good / "governed" / "drift.py").unlink()
    run_scan(good, tmp_path / "r2", generated_at=NOW)
    d = diff_cards(load_findings(tmp_path / "r1" / "findings.json"), load_findings(tmp_path / "r2" / "findings.json"))
    assert d["verdict"] == "REGRESSED" and "CARD-012" in d["regressed"]
    assert main(["drift", "--old", str(tmp_path / "r1" / "findings.json"), "--new", str(tmp_path / "r2" / "findings.json")]) == 1
    assert main(["drift", "--old", str(tmp_path / "r2" / "findings.json"), "--new", str(tmp_path / "r1" / "findings.json")]) == 0


def test_cli_end_to_end(tmp_path, capsys):
    assert main(["init-sample", "--kind", "ungoverned", "--out", str(tmp_path / "u")]) == 0
    assert (tmp_path / "u" / "app.py").exists()
    assert main(["scan", "--root", str(tmp_path / "u"), "--out", str(tmp_path / "run"), "--fail-on-gaps"]) == 1
    assert main(["scan", "--root", str(tmp_path / "u"), "--out", str(tmp_path / "run")]) == 0
    assert '"verdict": "GAPS FOUND"' in capsys.readouterr().out
    assert main(["verify", "--run-dir", str(tmp_path / "run")]) == 0
    assert main(["card", "--run-dir", str(tmp_path / "run"), "--out", str(tmp_path / "card.html")]) == 0
    page = (tmp_path / "card.html").read_text(encoding="utf-8")
    assert "GAPS FOUND" in page and "sk-fake" not in page
    assert main(["init-sample", "--kind", "governed", "--out", str(tmp_path / "g")]) == 0
    assert main(["scan", "--root", str(tmp_path / "g"), "--out", str(tmp_path / "rg"), "--fail-on-gaps", "--name", "Governed Sample"]) == 0
    card = json.loads((tmp_path / "rg" / "card.json").read_text(encoding="utf-8"))
    assert card["subject"]["name"] == "Governed Sample"


def test_self_scan_via_cli_passes_gate(tmp_path):
    assert main(["scan", "--root", str(REPO), "--out", str(tmp_path / "self"), "--fail-on-gaps"]) == 0
    assert main(["verify", "--run-dir", str(tmp_path / "self")]) == 0


def test_repo_controls_are_clean():
    assert secret_scan(REPO) == []
    assert policy_lint(REPO) == []
    assert main(["controls", "--root", str(REPO)]) == 0


def test_controls_catch_a_planted_secret(tmp_path):
    (tmp_path / "oops.py").write_text("api_key = " + '"' + "sk-fake-" + "0123456789abcdef" * 2 + '"' + "\n", encoding="utf-8")
    hits = secret_scan(tmp_path)
    assert hits and hits[0]["pattern"] == "generic_api_key"
