"""Static signal extraction from a codebase — the raw material for the card.

Reads source text and Python ASTs. Never imports or executes the target,
never opens a network connection, never calls a model. Every signal
carries file + line evidence so a reviewer can verify it by reading code.

Signals are heuristics (identifier and pattern based). They are designed to
be mirrored by the browser demo (docs/demo.html), so keep the regexes
simple and keep the line-skip rules identical.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------- knowledge

# Python modules that talk to a hosted or local model. Name -> provider label.
SDK_MODULES = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "google.generativeai": "Google Gemini (legacy SDK)",
    "google.genai": "Google Gemini",
    "vertexai": "Google Vertex AI",
    "cohere": "Cohere",
    "mistralai": "Mistral",
    "groq": "Groq",
    "together": "Together",
    "replicate": "Replicate",
    "litellm": "LiteLLM (multi-provider)",
    "langchain": "LangChain",
    "langchain_openai": "LangChain / OpenAI",
    "langchain_anthropic": "LangChain / Anthropic",
    "langchain_google_genai": "LangChain / Google",
    "llama_index": "LlamaIndex",
    "transformers": "Hugging Face Transformers (local)",
    "huggingface_hub": "Hugging Face Hub",
    "ollama": "Ollama (local)",
}

# API hosts seen in raw HTTP calls. Host substring -> provider label.
API_HOSTS = {
    "api.anthropic.com": "Anthropic",
    "api.openai.com": "OpenAI",
    "generativelanguage.googleapis.com": "Google Gemini",
    "aiplatform.googleapis.com": "Google Vertex AI",
    "api.cohere.com": "Cohere",
    "api.cohere.ai": "Cohere",
    "api.mistral.ai": "Mistral",
    "bedrock-runtime": "AWS Bedrock",
    "api.groq.com": "Groq",
    "openrouter.ai": "OpenRouter",
    "api.together.xyz": "Together",
}

# Dotted call names that are model invocations (matched as suffixes).
CALL_SUFFIXES = (
    "messages.create", "chat.completions.create", "completions.create", "responses.create",
    "generate_content", "generate_content_async", "invoke_model", "invoke_model_with_response_stream",
    "chat.send_message", "models.generate", "litellm.completion",
)

# Model identifier literals (public model families).
MODEL_ID_RE = re.compile(
    r"\b(claude-[a-z0-9.-]+|gpt-[a-z0-9.-]+|o[134](?:-mini|-pro)?\b|gemini-[a-z0-9.-]+|"
    r"llama-?[0-9][a-z0-9.-]*|mistral-[a-z0-9.-]+|mixtral-[a-z0-9.-]+|command-r[a-z0-9.-]*|"
    r"text-embedding-[a-z0-9.-]+|deepseek-[a-z0-9.-]+)\b"
)
MODEL_ENV_RE = re.compile(r"os\.(?:environ|getenv)[^\n]*MODEL")

# Environment-sourced credentials.
ENV_KEY_RE = re.compile(
    r"(?:os\.environ(?:\.get)?\s*[\[(]|os\.getenv\s*\()\s*['\"]([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET)[A-Z0-9_]*)['\"]"
)

# Hardcoded credentials (detection only). Mirrors controls.SECRET_PATTERNS.
SECRET_RES = [
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}")),
    ("openai_style_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("generic_api_key", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
_GENERIC_VALUE_RE = re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b(\s*[:=]\s*)['\"][^'\"]*['\"]")

# Execution primitives — the capability to ACT on model output.
EXEC_RE = re.compile(
    r"\b(subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen|(?<![\w.])exec\(|(?<![\w.])eval\()"
)

# Governance markers (identifier heuristics; case-insensitive).
MARKER_RES = {
    "budget": re.compile(r"(?i)\b(?:budget\w*|cost_?ceiling\w*|max_(?:usd|cost|spend)\w*|spend_?limit\w*)\b"),
    "gate": re.compile(r"(?i)\b(?:approval_?gate|approvalgate|approvalrequired|approval_?required|require\w*_approval|human_?in_?the_?loop|hitl|def approve\w*|def reject\w*|awaiting_?approval)\b"),
    "checker": re.compile(r"(?i)\b(?:\w*checker\w*|adjudicat\w*|independent_?verif\w*|cross_?check\w*|ground_?truth\w*|second_?opinion\w*)\b"),
    "chain": re.compile(r"(?i)\b(?:prev_?hash|previous_?hash|hash_?chain\w*|verify_?chain|merkle\w*)\b"),
    "injection": re.compile(r"(?i)(?:prompt_?injection|injection_?pattern|ignore (?:all )?previous instructions|jailbreak|red_?team\w*|canary)"),
    "eval": re.compile(r"(?i)\b(?:precision|recall|f1(?:_score)?|benchmark\w*|evalbench|eval_?suite|golden_?(?:set|output)\w*)\b"),
    "drift": re.compile(r"(?i)\b(?:\w*drift\w*|\w*regress(?:ed|ion)\w*)\b"),
    "mock": re.compile(r"(?i)\b(?:mock_?provider\w*|mockprovider|mock_?mode|dry_?run\w*|offline_?mode|fake_?transport|stub_?provider)\b"),
    "timeout": re.compile(r"\b(?:timeout|max_retries)\s*="),
    "validation": re.compile(r"(?i)\b(?:pydantic|jsonschema|basemodel|validate_?\w*|schema\w*|strict_?json)\b"),
    "redaction": re.compile(r"(?i)\b(?:redact\w*|mask_?\w*|anonymi[sz]\w*|scrub\w*|minimi[sz]\w*|pii)\b"),
    "json_parse": re.compile(r"json\.loads\("),
}

# Data-handling statements in docs.
DATA_STATEMENT_RE = re.compile(
    r"(?i)(never (?:sent|sends|send|leaves|shared)|metadata only|no (?:pii|personal data|customer data)|"
    r"not sent to (?:the |any )?(?:model|llm|api)|is never sent|only .{0,60}(?:is|are) (?:ever )?sent|"
    r"data minimi[sz]ation|redact\w*|anonymi[sz]\w*)"
)

# CI secrets that look like model API credentials.
CI_MODEL_SECRET_RE = re.compile(
    r"(?i)\b(?:ANTHROPIC|OPENAI|GOOGLE|GEMINI|COHERE|MISTRAL|GROQ|HF|HUGGINGFACE|TOGETHER|OPENROUTER)[A-Z_]*_(?:API_)?(?:KEY|TOKEN)\b"
)

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "env", "runs",
             "build", "dist", ".mypy_cache", ".ruff_cache", ".tox", "site-packages"}
CODE_EXT = {".py"}
DOC_EXT = {".md", ".rst", ".txt"}
MAX_FILE_BYTES = 2_000_000


# ---------------------------------------------------------------- model

@dataclass
class Evidence:
    file: str
    line: int
    kind: str
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Inventory:
    root: str
    files_scanned: int = 0
    python_files: int = 0
    doc_files: int = 0
    providers: dict = field(default_factory=dict)      # label -> [Evidence]
    call_sites: list = field(default_factory=list)     # Evidence
    model_ids: list = field(default_factory=list)      # Evidence (snippet = id)
    model_env_override: list = field(default_factory=list)
    env_keys: list = field(default_factory=list)       # Evidence (snippet = var name)
    hardcoded_secrets: list = field(default_factory=list)
    exec_primitives: list = field(default_factory=list)
    markers: dict = field(default_factory=dict)        # marker -> [Evidence]
    ai_files: list = field(default_factory=list)       # non-test files importing an SDK / hitting an API host
    docs_data_statement: list = field(default_factory=list)
    intended_use: str = ""
    has_readme: bool = False
    has_license: bool = False
    has_notice: bool = False
    has_tests: bool = False
    has_ci: bool = False
    ci_model_secrets: list = field(default_factory=list)
    benchmark_files: list = field(default_factory=list)
    unpinned_deps: list = field(default_factory=list)
    deps_declared: int = 0
    parse_errors: list = field(default_factory=list)

    @property
    def uses_ai(self) -> bool:
        return bool(self.providers or self.call_sites)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["uses_ai"] = self.uses_ai
        return d


# ---------------------------------------------------------------- helpers

def _rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def _iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and p.stat().st_size <= MAX_FILE_BYTES:
            yield p


def is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    return (any(part in ("tests", "test") for part in parts[:-1])
            or parts[-1].startswith("test_") or parts[-1].endswith("_test.py"))


def skip_line(line: str) -> bool:
    """Lines that must not count as evidence: comments and pattern definitions
    (a detector's own regex source is not a signal). Mirrored in demo.html."""
    s = line.strip()
    return s.startswith("#") or "re.compile(" in s


def redact(line: str) -> str:
    """Strip any credential-shaped value from a snippet before it is recorded."""
    out = _GENERIC_VALUE_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", line)
    for _, rx in SECRET_RES:
        out = rx.sub("<redacted>", out)
    return out


def _snip(line: str, limit: int = 140) -> str:
    s = redact(line.strip())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


# ---------------------------------------------------------------- extraction

def _scan_python(inv: Inventory, root: Path, p: Path, text: str) -> None:
    rel = _rel(root, p)
    is_test = is_test_path(rel)
    lines = text.splitlines()

    def line_at(n: int) -> str:
        return lines[n - 1] if 0 < n <= len(lines) else ""

    # --- AST: imports + call sites
    imported_sdks: set[str] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        inv.parse_errors.append(f"{rel}:{e.lineno}")
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if is_test:
                continue  # a fixture that mentions an SDK is not model usage
            if isinstance(node, ast.Import):
                for a in node.names:
                    for mod, label in SDK_MODULES.items():
                        if a.name == mod or a.name.startswith(mod + "."):
                            imported_sdks.add(label)
                            inv.providers.setdefault(label, []).append(
                                Evidence(rel, node.lineno, "import", _snip(line_at(node.lineno))))
            elif isinstance(node, ast.ImportFrom) and node.module:
                for mod, label in SDK_MODULES.items():
                    if node.module == mod or node.module.startswith(mod + "."):
                        imported_sdks.add(label)
                        inv.providers.setdefault(label, []).append(
                            Evidence(rel, node.lineno, "import", _snip(line_at(node.lineno))))
            elif isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name and any(name == sfx or name.endswith("." + sfx) for sfx in CALL_SUFFIXES):
                    inv.call_sites.append(Evidence(rel, node.lineno, name, _snip(line_at(node.lineno))))

    # --- line scan
    file_is_ai = bool(imported_sdks)
    for n, line in enumerate(lines, 1):
        if skip_line(line):
            continue
        for host, label in API_HOSTS.items():
            if "//" + host in line and not is_test:
                file_is_ai = True
                inv.providers.setdefault(label, []).append(Evidence(rel, n, "api_host", _snip(line)))
        if not is_test:
            for m in MODEL_ID_RE.finditer(line):
                inv.model_ids.append(Evidence(rel, n, "model_id", m.group(1)))
        if MODEL_ENV_RE.search(line):
            inv.model_env_override.append(Evidence(rel, n, "model_env", _snip(line)))
        for m in ENV_KEY_RE.finditer(line):
            inv.env_keys.append(Evidence(rel, n, "env_key", m.group(1)))
        for name, rx in SECRET_RES:
            if rx.search(line):
                inv.hardcoded_secrets.append(Evidence(rel, n, name, _snip(line)))
                break
        if not is_test:
            if EXEC_RE.search(line):
                inv.exec_primitives.append(Evidence(rel, n, "exec", _snip(line)))
            for marker, rx in MARKER_RES.items():
                if rx.search(line):
                    inv.markers.setdefault(marker, []).append(Evidence(rel, n, marker, _snip(line)))
    if file_is_ai and not is_test:
        inv.ai_files.append(rel)


def first_paragraph(text: str) -> str:
    """First prose paragraph of a README (skips headings, badges, HTML tags, blank lines)."""
    buf: list[str] = []
    for raw in text.splitlines():
        if re.match(r"\s*<h[1-6]", raw, re.I):
            continue
        line = re.sub(r"<[^>]+>", " ", raw)
        line = re.sub(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)", "", line)
        line = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", line).strip()
        if not line:
            if buf:
                break
            continue
        if line.startswith(("#", "|", "```", "---", "[![")):
            if buf:
                break
            continue
        buf.append(line)
    para = re.sub(r"\s+", " ", " ".join(buf)).strip()
    return para[:400]


def _scan_doc(inv: Inventory, root: Path, p: Path, text: str) -> None:
    rel = _rel(root, p)
    for n, line in enumerate(text.splitlines(), 1):
        if DATA_STATEMENT_RE.search(line):
            inv.docs_data_statement.append(Evidence(rel, n, "data_statement", _snip(line, 200)))
    if p.name.lower().startswith("readme") and not inv.intended_use:
        inv.intended_use = first_paragraph(text)


def _unpinned(spec: str) -> bool:
    s = spec.strip()
    if not s:
        return False
    return "==" not in s and "@" not in s


def _scan_deps(inv: Inventory, root: Path) -> None:
    for req in sorted(root.glob("requirements*.txt")):
        for n, line in enumerate(req.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = line.split("#", 1)[0].strip()
            if not s or s.startswith(("-", "git+", "http")):
                continue
            inv.deps_declared += 1
            if _unpinned(s):
                inv.unpinned_deps.append(Evidence(_rel(root, req), n, "unpinned", s))
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        in_deps = False
        for n, line in enumerate(pyproject.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = line.strip()
            if re.match(r"^dependencies\s*=\s*\[", s):
                in_deps = True
                s = s.split("[", 1)[1]
            if in_deps:
                for item in re.findall(r"['\"]([^'\"]+)['\"]", s):
                    inv.deps_declared += 1
                    if _unpinned(item):
                        inv.unpinned_deps.append(Evidence("pyproject.toml", n, "unpinned", item))
                if "]" in s:
                    in_deps = False


def _scan_ci(inv: Inventory, root: Path) -> None:
    wf = root / ".github" / "workflows"
    files = sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))) if wf.exists() else []
    inv.has_ci = bool(files)
    for f in files:
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if "secrets." in line and CI_MODEL_SECRET_RE.search(line):
                inv.ci_model_secrets.append(Evidence(_rel(root, f), n, "ci_secret", _snip(line)))


def extract(root: str | Path) -> Inventory:
    """Walk a codebase and collect every signal, with evidence. Read-only."""
    root = Path(root).resolve()
    inv = Inventory(root=str(root))
    for p in _iter_files(root):
        rel = _rel(root, p)
        name = p.name.lower()
        suffix = p.suffix.lower()
        if name.startswith("readme"):
            inv.has_readme = True
        if name.startswith(("license", "licence")):
            inv.has_license = True
        if name == "notice" or name.startswith("notice."):
            inv.has_notice = True
        if "benchmark" in name and suffix in (".md", ".json"):
            inv.benchmark_files.append(rel)
        if suffix == ".py" and is_test_path(rel):
            inv.has_tests = True
        inv.files_scanned += 1
        if suffix in CODE_EXT:
            inv.python_files += 1
            _scan_python(inv, root, p, p.read_text(encoding="utf-8", errors="replace"))
        elif suffix in DOC_EXT:
            inv.doc_files += 1
            _scan_doc(inv, root, p, p.read_text(encoding="utf-8", errors="replace"))
    _scan_deps(inv, root)
    _scan_ci(inv, root)
    inv.ai_files = sorted(set(inv.ai_files))
    return inv
