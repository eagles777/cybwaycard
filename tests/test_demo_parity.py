"""Parity: the JavaScript mirror in docs/demo.html must grade exactly like the Python engine.

For a set of toggle states, Node builds the synthetic source + facts and grades them with
the JS engine; Python materialises the same source + facts as a tiny repo and grades it with
signals.py / checks.py. Every check status and every register status must match.
Skipped when Node is not installed (CI installs it).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from cybwaycard.card import build_card
from cybwaycard.checks import run_all_checks
from cybwaycard.signals import extract

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "docs" / "demo.html"
NODE = shutil.which("node")

STATES = [
    {"preset": "ungoverned"},
    {"preset": "governed"},
    {"preset": "governed", "budget": False, "timeout": False},
    {"preset": "governed", "gate": False, "exec": True},
    {"preset": "governed", "hardcoded_key": True, "env_key": False},
    {"preset": "ungoverned", "tests_ci": True, "ci_secret": True, "license_readme": True, "data_statement": True},
    {"preset": "ungoverned", "validation": True, "checker": True, "injection": True, "redact": True, "deps_pinned": True},
    {"preset": "governed", "model": False, "evalb": False, "drift": False, "chain": False, "mock": False},
]

HARNESS = r"""
const D = require(process.argv[2]);
const states = JSON.parse(process.argv[3]);
const out = states.map(spec => {
  const st = Object.assign({}, D.PRESETS[spec.preset]);
  for (const [k, v] of Object.entries(spec)) if (k !== "preset") st[k] = v;
  const src = D.buildSource(st), facts = D.factsOf(st), r = D.analyze(src, facts);
  return {src, facts, checks: Object.fromEntries(r.checks.map(c => [c.id, c.status])),
          register: Object.fromEntries(r.register.map(x => [x.id, x.status])), verdict: r.summary.verdict, score: r.summary.score};
});
process.stdout.write(JSON.stringify(out));
"""


def _engine_js(tmp_path: Path) -> Path:
    html = DEMO.read_text(encoding="utf-8")
    m = re.search(r'<script id="engine">(.*?)</script>', html, re.S)
    assert m, "engine script block not found in demo.html"
    p = tmp_path / "engine.js"
    p.write_text(m.group(1), encoding="utf-8")
    return p


def _materialise(tmp_path: Path, src: str, facts: dict) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "ai_client.py").write_text(src, encoding="utf-8")
    (repo / "requirements.txt").write_text("anthropic==0.40.0\n" if facts["deps_pinned"] else "anthropic\n", encoding="utf-8")
    if facts["tests_ci"]:
        (repo / "tests").mkdir()
        (repo / "tests" / "test_x.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        ci = "name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n"
        if facts["ci_secret"]:
            ci += "    env:\n      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n"
        (wf / "ci.yml").write_text(ci, encoding="utf-8")
    if facts["license_readme"]:
        (repo / "LICENSE").write_text("Apache License 2.0 (fixture)\n", encoding="utf-8")
        readme = "# Demo app\n\nA demo AI client used for the parity test.\n"
        if facts["data_statement"]:
            readme += "\nOnly configuration metadata is ever sent to the model; table data is never sent.\n"
        (repo / "README.md").write_text(readme, encoding="utf-8")
    return repo


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_js_mirror_matches_python(tmp_path):
    engine = _engine_js(tmp_path)
    harness = tmp_path / "harness.js"
    harness.write_text(HARNESS, encoding="utf-8")
    res = subprocess.run([NODE, str(harness), str(engine), json.dumps(STATES)], capture_output=True, text=True, check=True)
    results = json.loads(res.stdout)
    assert len(results) == len(STATES)
    for i, (spec, js) in enumerate(zip(STATES, results)):
        repo = _materialise(tmp_path / f"case{i}", js["src"], js["facts"])
        inv = extract(repo)
        findings = run_all_checks(inv)
        card = build_card(inv, findings, generated_at="2026-01-01T00:00:00+00:00")
        py_checks = {f.check_id: f.status for f in findings}
        assert py_checks == js["checks"], f"case {i} {spec}: python={py_checks} js={js['checks']}"
        py_reg = {r["id"]: r["status"] for r in card["risk_register"]}
        assert py_reg == js["register"], f"case {i} {spec}"
        assert card["summary"]["verdict"] == js["verdict"] and card["summary"]["score_pct"] == js["score"], f"case {i} {spec}"


def test_demo_has_no_credential_shaped_literal():
    from cybwaycard.controls import SECRET_PATTERNS
    for n, line in enumerate(DEMO.read_text(encoding="utf-8").splitlines(), 1):
        for name, rx in SECRET_PATTERNS:
            assert not rx.search(line), f"{name} at demo.html:{n}"
