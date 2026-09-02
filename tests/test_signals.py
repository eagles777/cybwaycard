"""Signal extraction: SDK/provider detection, model ids, credentials, exec primitives,
markers, redaction, skip rules. All offline, $0."""

from pathlib import Path

from cybwaycard.samples import fake_key, write_sample
from cybwaycard.signals import extract, first_paragraph, redact, skip_line


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def test_detects_sdk_import_and_call_site(tmp_path):
    root = _repo(tmp_path, {"app.py": (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "msg = client.messages.create(model='claude-sonnet-4-5', max_tokens=10, messages=[])\n")})
    inv = extract(root)
    assert inv.uses_ai
    assert "Anthropic" in inv.providers
    assert len(inv.call_sites) == 1 and inv.call_sites[0].kind.endswith("messages.create")
    assert {e.snippet for e in inv.model_ids} == {"claude-sonnet-4-5"}
    assert inv.ai_files == ["app.py"]


def test_detects_api_host_without_sdk(tmp_path):
    root = _repo(tmp_path, {"raw.py": "import urllib.request\nURL = 'https://api.openai.com/v1/chat/completions'\n"})
    inv = extract(root)
    assert inv.uses_ai and "OpenAI" in inv.providers
    assert inv.ai_files == ["raw.py"]


def test_no_ai_repo(tmp_path):
    root = _repo(tmp_path, {"util.py": "def add(a, b):\n    return a + b\n"})
    inv = extract(root)
    assert not inv.uses_ai and inv.providers == {} and inv.call_sites == []


def test_env_key_and_hardcoded_secret(tmp_path):
    root = _repo(tmp_path, {"a.py": "import os\nk = os.environ['OPENAI_API_KEY']\n",
                            "b.py": "client = make(api_key=" + '"' + fake_key() + '")' + "\n"})
    inv = extract(root)
    assert [e.snippet for e in inv.env_keys] == ["OPENAI_API_KEY"]
    assert len(inv.hardcoded_secrets) == 1
    # the recorded snippet never contains the value
    assert fake_key() not in inv.hardcoded_secrets[0].snippet
    assert "<redacted>" in inv.hardcoded_secrets[0].snippet


def test_exec_primitives_and_test_files_excluded(tmp_path):
    root = _repo(tmp_path, {"run.py": "import subprocess\nsubprocess.run(cmd, shell=True)\n",
                            "tests/test_x.py": "import subprocess\nsubprocess.run(['echo'])\n"})
    inv = extract(root)
    assert len(inv.exec_primitives) == 1 and inv.exec_primitives[0].file == "run.py"
    assert inv.has_tests


def test_markers_found(tmp_path):
    root = _repo(tmp_path, {"g.py": (
        "class BudgetCeiling: pass\n"
        "class ApprovalGate:\n    def approve(self): pass\n"
        "class CheckerAgent: pass\n"
        "prev_hash = '0'\n"
        "INJECTION_PATTERNS = ['ignore previous instructions']\n"
        "precision = 1.0\n"
        "def detect_drift(): pass\n"
        "class MockProvider: pass\n"
        "timeout=30\n"
        "def validate_schema(x): return x\n"
        "def redact(x): return x\n"
        "import json\nobj = json.loads('{}')\n")})
    inv = extract(root)
    for m in ("budget", "gate", "checker", "chain", "injection", "eval", "drift", "mock",
              "timeout", "validation", "redaction", "json_parse"):
        assert m in inv.markers, m


def test_comment_and_regex_lines_are_not_evidence(tmp_path):
    root = _repo(tmp_path, {"d.py": (
        "import re\n"
        "# subprocess.run should never be used here\n"
        "EXEC = re.compile(r'subprocess\\.run')\n")})
    inv = extract(root)
    assert inv.exec_primitives == []
    assert skip_line("# anything") and skip_line("X = re.compile(r'x')") and not skip_line("y = 1")


def test_syntax_error_recorded_not_fatal(tmp_path):
    root = _repo(tmp_path, {"broken.py": "def (:\n", "ok.py": "x = 1\n"})
    inv = extract(root)
    assert inv.parse_errors == ["broken.py:1"] and inv.python_files == 2


def test_skip_dirs(tmp_path):
    root = _repo(tmp_path, {"node_modules/x.py": "import openai\n", ".venv/y.py": "import openai\n",
                            "runs/z.py": "import openai\n", "main.py": "x=1\n"})
    inv = extract(root)
    assert not inv.uses_ai and inv.python_files == 1


def test_deps_pinning(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "openai==1.0.0\nrequests>=2\n# comment\n-r other.txt\n",
                            "pyproject.toml": "[project]\ndependencies = [\"anthropic\", \"httpx==0.27.0\"]\n"})
    inv = extract(root)
    assert inv.deps_declared == 4
    assert sorted(e.snippet for e in inv.unpinned_deps) == ["anthropic", "requests>=2"]


def test_ci_and_docs_signals(tmp_path):
    root = _repo(tmp_path, {
        ".github/workflows/ci.yml": "env:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n",
        "README.md": "# Tool\n\n<img src='x'>\n\nA governed helper. Table data is never sent to the model.\n",
        "LICENSE": "x", "NOTICE": "x", "BENCHMARKS.md": "x"})
    inv = extract(root)
    assert inv.has_ci and len(inv.ci_model_secrets) == 1
    assert inv.has_readme and inv.has_license and inv.has_notice
    assert inv.benchmark_files == ["BENCHMARKS.md"]
    assert inv.intended_use.startswith("A governed helper.")
    assert inv.docs_data_statement and inv.docs_data_statement[0].file == "README.md"


def test_first_paragraph_skips_badges_and_headings():
    text = "<h1 align='center'>X</h1>\n\n![badge](u)\n[![b](u)](l)\n\n## Why\n\nFirst real line\nsecond line\n\nNext para\n"
    assert first_paragraph(text) == "First real line second line"


def test_redact_strips_values():
    line = "client = X(api_key=" + '"abcdefghijkl"' + ")"   # assembled so this test file holds no key-shaped literal
    assert redact(line) == "client = X(api_key=<redacted>)"
    assert "<redacted>" in redact("token sk-ant-" + "a" * 24)


def test_samples_materialise(tmp_path):
    g = extract(write_sample("governed", tmp_path / "g"))
    u = extract(write_sample("ungoverned", tmp_path / "u"))
    assert g.uses_ai and u.uses_ai
    assert g.hardcoded_secrets == [] and len(u.hardcoded_secrets) == 1
    assert u.exec_primitives and not g.exec_primitives
