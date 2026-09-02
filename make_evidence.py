"""Regenerate docs/evidence/ — committed, reproducible scan outputs.

Subjects:
  self               this repository (dogfood; uses no model -> AI checks NA)
  governed-sample    synthetic sample with every control
  ungoverned-sample  synthetic sample with none
  cybwaydb           the author's public sibling project, cloned into a temp dir (git only, no key)

Usage: python make_evidence.py [--skip-clone]
Deterministic apart from the clone: generated_at is pinned per subject so re-runs diff cleanly.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from cybwaycard.engine import run_scan  # noqa: E402
from cybwaycard.samples import write_sample  # noqa: E402

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "docs" / "evidence"
STAMP = "2026-09-02T00:00:00+00:00"
SIBLING = "https://github.com/eagles777/cybwaydb"


def _scan(subject: str, src: Path, name: str) -> dict:
    out = EVIDENCE / subject
    if out.exists():
        shutil.rmtree(out)
    summary = run_scan(src, out, generated_at=STAMP, subject_name=name)
    # inventory.json carries absolute local paths in `root`; normalise for a clean commit
    inv = out / "inventory.json"
    inv.write_text(inv.read_text(encoding="utf-8").replace(str(src.resolve()).replace("\\", "\\\\"), f"<{subject}>")
                   .replace(str(src.resolve()), f"<{subject}>"), encoding="utf-8")
    log = out / "audit.log.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace(str(src.resolve()).replace("\\", "\\\\"), f"<{subject}>"), encoding="utf-8")
    from cybwaycard.auditlog import write_manifest
    write_manifest(out, {"summary": summary, "generated_at": STAMP})   # re-manifest after path normalisation
    print(f"{subject:18} {summary['verdict']:26} score {summary['score_pct']:3}%  pass {summary['pass']:2} fail {summary['fail']:2} na {summary['na']:2}")
    return summary


def main(argv: list[str]) -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _scan("self", ROOT, "cybwaycard")
        _scan("governed-sample", write_sample("governed", tmp / "governed"), "Governed sample")
        _scan("ungoverned-sample", write_sample("ungoverned", tmp / "ungoverned"), "Ungoverned sample")
        if "--skip-clone" not in argv:
            dest = tmp / "cybwaydb"
            subprocess.run(["git", "clone", "--quiet", "--depth", "1", SIBLING, str(dest)], check=True)
            shutil.rmtree(dest / ".git", ignore_errors=True)
            _scan("cybwaydb", dest, "Cybwaydb (sibling project)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
