"""Governance checks against the two synthetic samples and a no-AI repo."""

from pathlib import Path

from cybwaycard.checks import CHECKS, FAIL, NA, PASS, OWASP_LLM, run_all_checks
from cybwaycard.samples import write_sample
from cybwaycard.signals import extract

AI_ONLY = {"CARD-003", "CARD-004", "CARD-005", "CARD-006", "CARD-007", "CARD-008", "CARD-009",
           "CARD-010", "CARD-011", "CARD-012", "CARD-013", "CARD-014", "CARD-019"}


def _by_id(findings):
    return {f.check_id: f for f in findings}


def test_check_registry_shape():
    findings = run_all_checks(extract(Path(__file__).parent))
    ids = [f.check_id for f in findings]
    assert len(ids) == len(set(ids)) == len(CHECKS) == 19
    assert ids == sorted(ids)
    for f in findings:
        assert f.status in (PASS, FAIL, NA)
        assert f.severity in ("high", "medium", "low", "info")
        assert f.guidance or f.status == NA or f.check_id == "CARD-001"
        for o in f.owasp:
            assert o in OWASP_LLM
        for r in f.ai_rmf:
            assert r.split(" ")[0] in ("GOVERN", "MAP", "MEASURE", "MANAGE")


def test_governed_sample_passes_everything(tmp_path):
    findings = run_all_checks(extract(write_sample("governed", tmp_path)))
    failed = [f.check_id for f in findings if f.status == FAIL]
    assert failed == [], failed
    assert all(f.status == PASS for f in findings), [(f.check_id, f.status) for f in findings]


def test_ungoverned_sample_fails_the_expected_controls(tmp_path):
    fs = _by_id(run_all_checks(extract(write_sample("ungoverned", tmp_path))))
    assert fs["CARD-001"].status == PASS and "OpenAI" in fs["CARD-001"].note
    assert fs["CARD-002"].status == FAIL and "<redacted>" in fs["CARD-002"].evidence[0]
    assert fs["CARD-003"].status == FAIL
    assert fs["CARD-004"].status == FAIL
    assert fs["CARD-005"].status == FAIL
    assert fs["CARD-006"].status == FAIL and fs["CARD-006"].severity == "high"   # subprocess + no gate
    assert fs["CARD-007"].status == FAIL
    assert fs["CARD-008"].status == FAIL
    assert fs["CARD-009"].status == FAIL
    assert fs["CARD-013"].status == PASS and "gpt-4o" in fs["CARD-013"].note
    assert fs["CARD-014"].status == FAIL
    assert fs["CARD-015"].status == FAIL
    assert fs["CARD-016"].status == NA           # no CI at all
    assert fs["CARD-017"].status == FAIL         # no LICENSE
    assert fs["CARD-018"].status == FAIL and len(fs["CARD-018"].evidence) == 2
    assert fs["CARD-019"].status == FAIL


def test_no_ai_repo_marks_ai_checks_na(tmp_path):
    (tmp_path / "util.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# u\n\nA utility.\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("x", encoding="utf-8")
    fs = _by_id(run_all_checks(extract(tmp_path)))
    assert fs["CARD-001"].status == NA
    for cid in AI_ONLY:
        assert fs[cid].status == NA, cid
    assert fs["CARD-002"].status == PASS
    assert fs["CARD-017"].status == PASS
    assert fs["CARD-018"].status == PASS and "stdlib-only" in fs["CARD-018"].note
    assert fs["CARD-015"].status == FAIL         # no tests, no CI


def test_gate_present_but_exec_primitive_noted(tmp_path):
    (tmp_path / "a.py").write_text(
        "import openai\nimport subprocess\nclass ApprovalGate:\n    def approve(self): pass\n"
        "subprocess.run(['ls'])\n", encoding="utf-8")
    fs = _by_id(run_all_checks(extract(tmp_path)))
    assert fs["CARD-006"].status == PASS and "Execution primitives" in fs["CARD-006"].note


def test_implicit_env_key_passes_with_note(tmp_path):
    (tmp_path / "a.py").write_text("import anthropic\nc = anthropic.Anthropic()\n", encoding="utf-8")
    fs = _by_id(run_all_checks(extract(tmp_path)))
    assert fs["CARD-003"].status == PASS and "assumed" in fs["CARD-003"].note


def test_ci_with_model_secret_fails(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("env:\n  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n", encoding="utf-8")
    fs = _by_id(run_all_checks(extract(tmp_path)))
    assert fs["CARD-016"].status == FAIL


def test_this_repository_is_governed():
    """Dogfood: Cybwaycard's own repo must have no FAIL (it uses no model, so AI checks are NA)."""
    root = Path(__file__).resolve().parents[1]
    fs = _by_id(run_all_checks(extract(root)))
    failed = [c for c, f in fs.items() if f.status == FAIL]
    assert failed == [], failed
    assert fs["CARD-001"].status == NA
    assert fs["CARD-002"].status == PASS
    assert fs["CARD-015"].status == PASS
    assert fs["CARD-018"].status == PASS
