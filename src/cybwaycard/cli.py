"""Command-line interface for Cybwaycard (static, offline, no model, $0)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .auditlog import AuditLog, verify_manifest
from .controls import policy_lint, secret_scan
from .engine import integrity_of, run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cybwaycard",
        description="Static AI-system-card + AI-risk-register generator for LLM-using codebases (offline, no model, $0)",
    )
    parser.add_argument("--version", action="version", version=f"cybwaycard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Read a codebase and write its card, findings, audit log and manifest")
    p_scan.add_argument("--root", default=".", help="Codebase to read (never executed)")
    p_scan.add_argument("--out", default="runs/latest", help="Run output directory")
    p_scan.add_argument("--name", default=None, help="Subject name to print on the card (default: folder name)")
    p_scan.add_argument("--fail-on-gaps", action="store_true",
                        help="Exit 1 if any check FAILs (CI gate)")

    p_card = sub.add_parser("card", help="Render a self-contained HTML card from a run directory")
    p_card.add_argument("--run-dir", default="runs/latest")
    p_card.add_argument("--out", default="card.html")

    p_verify = sub.add_parser("verify", help="Verify a run's hash-chained audit log and SHA-256 manifest")
    p_verify.add_argument("--run-dir", default="runs/latest")

    p_drift = sub.add_parser("drift", help="Diff governance posture between two runs (exit 1 on regression)")
    p_drift.add_argument("--old", required=True, help="Previous run's findings.json")
    p_drift.add_argument("--new", required=True, help="Latest run's findings.json")

    p_ctl = sub.add_parser("controls", help="Repo hygiene: secret scan + policy lint over THIS repository")
    p_ctl.add_argument("--root", default=".")

    p_sample = sub.add_parser("init-sample", help="Write a synthetic sample codebase you can scan and edit")
    p_sample.add_argument("--kind", choices=("governed", "ungoverned"), default="ungoverned")
    p_sample.add_argument("--out", default=None, help="Directory (default: ./sample-<kind>)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        summary = run_scan(args.root, args.out, subject_name=args.name)
        print(json.dumps(summary, indent=2))
        print(f"card: {Path(args.out) / 'card.md'}")
        return 1 if (args.fail_on_gaps and summary["fail"]) else 0

    if args.command == "card":
        from .card import render_html
        run_dir = Path(args.run_dir)
        card = json.loads((run_dir / "card.json").read_text(encoding="utf-8"))
        out = Path(args.out)
        out.write_text(render_html(card, integrity_of(run_dir)), encoding="utf-8")
        print(f"Card written to {out} — open it in any browser.")
        return 0

    if args.command == "verify":
        log_ok, msg = AuditLog(Path(args.run_dir) / "audit.log.jsonl").verify_chain()
        man_ok, problems = verify_manifest(args.run_dir)
        print(f"audit log: {msg}")
        print(f"manifest: {'ok' if man_ok else problems}")
        return 0 if (log_ok and man_ok) else 1

    if args.command == "drift":
        from .drift import diff_cards, load_findings
        d = diff_cards(load_findings(args.old), load_findings(args.new))
        print(json.dumps(d, indent=2))
        return 0 if d["verdict"] != "REGRESSED" else 1

    if args.command == "controls":
        secrets = secret_scan(args.root)
        policy = policy_lint(args.root)
        print(json.dumps({"secret_scan_hits": secrets, "policy_violations": policy}, indent=2))
        return 0 if not (secrets or policy) else 1

    if args.command == "init-sample":
        from .samples import write_sample
        out = write_sample(args.kind, args.out or f"sample-{args.kind}")
        print(f"Sample '{args.kind}' written to {out}. Now: cybwaycard scan --root {out} --out runs/{args.kind}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
