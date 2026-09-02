"""Governance checks — one function per check, each returning a Finding.

Every check reads the static Inventory only. Statuses:
  PASS  control evidenced in code/docs
  FAIL  control expected but not evidenced (with severity + guidance)
  NA    not applicable (e.g. the codebase does not call a model)

References are by identifier only: OWASP Top 10 for LLM Applications
(category names, attribution to the OWASP Foundation) and NIST AI RMF 1.0
(function + category identifiers, US Government work). See LEGAL.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .signals import Inventory, Evidence

PASS, FAIL, NA = "PASS", "FAIL", "NA"

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP categories no static check can evaluate honestly.
NOT_STATICALLY_ASSESSABLE = {
    "LLM04": "Training/fine-tuning data provenance is a runtime and supply-chain question, not visible in application code.",
    "LLM07": "Whether a system prompt leaks depends on model behaviour at runtime; static analysis can only inventory prompts.",
    "LLM08": "Requires review of the retrieval architecture and access controls on the vector store; not evaluable statically.",
}


@dataclass
class Finding:
    check_id: str
    title: str
    status: str
    severity: str                 # high | medium | low | info
    area: str                     # short governance area label
    owasp: list = field(default_factory=list)      # e.g. ["LLM10"]
    ai_rmf: list = field(default_factory=list)     # e.g. ["MAP 3", "MANAGE 2"]
    evidence: list = field(default_factory=list)   # "file:line — snippet"
    guidance: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _ev(items: list[Evidence], limit: int = 6) -> list[str]:
    out = [f"{e.file}:{e.line} — {e.snippet}" for e in items[:limit]]
    if len(items) > limit:
        out.append(f"… {len(items) - limit} more")
    return out


def _m(inv: Inventory, marker: str) -> list[Evidence]:
    return inv.markers.get(marker, [])


CHECKS: list = []


def check(fn):
    CHECKS.append(fn)
    return fn


# ------------------------------------------------------------------ checks

@check
def card_001_inventory(inv: Inventory) -> Finding:
    """CARD-001 — LLM usage is inventoried (what talks to a model, and where)."""
    f = Finding("CARD-001", "LLM usage inventoried", PASS if inv.uses_ai else NA, "info", "Inventory",
                owasp=[], ai_rmf=["MAP 2"],
                guidance="Every model call site should be known and listed. Cybwaycard derives this from imports, "
                         "API hosts and call names; keep model access behind one module so the inventory stays short.")
    if inv.uses_ai:
        prov = [e for evs in inv.providers.values() for e in evs]
        f.evidence = _ev(prov, 4) + _ev(inv.call_sites, 6)
        f.note = f"providers: {', '.join(sorted(inv.providers))}; call sites: {len(inv.call_sites)}; AI files: {len(inv.ai_files)}"
    else:
        f.note = "No model SDK import, API host, or model call detected. AI-specific checks are marked NA."
    return f


@check
def card_002_no_hardcoded_secrets(inv: Inventory) -> Finding:
    """CARD-002 — No credential-shaped literals in source."""
    hits = inv.hardcoded_secrets
    return Finding("CARD-002", "No hardcoded credentials", FAIL if hits else PASS, "high", "Secrets",
                   owasp=["LLM02"], ai_rmf=["GOVERN 6", "MAP 4"], evidence=_ev(hits),
                   guidance="Move keys to environment variables or a secret store; rotate any key that was committed. "
                            "Values shown here are redacted at scan time.")


@check
def card_003_env_sourced_keys(inv: Inventory) -> Finding:
    """CARD-003 — Model credentials are read from the environment / secret store."""
    if not inv.uses_ai:
        return Finding("CARD-003", "Credentials sourced from environment", NA, "medium", "Secrets",
                       owasp=["LLM02"], ai_rmf=["GOVERN 6"])
    if inv.env_keys:
        return Finding("CARD-003", "Credentials sourced from environment", PASS, "medium", "Secrets",
                       owasp=["LLM02"], ai_rmf=["GOVERN 6"], evidence=_ev(inv.env_keys),
                       guidance="Keep it this way: no key literal in code, CI, or docs.")
    if inv.hardcoded_secrets:
        return Finding("CARD-003", "Credentials sourced from environment", FAIL, "medium", "Secrets",
                       owasp=["LLM02"], ai_rmf=["GOVERN 6"], evidence=_ev(inv.hardcoded_secrets),
                       guidance="Read the key with os.environ / a secret manager and delete the literal.")
    return Finding("CARD-003", "Credentials sourced from environment", PASS, "medium", "Secrets",
                   owasp=["LLM02"], ai_rmf=["GOVERN 6"],
                   note="No explicit environment read found; the SDK's default environment lookup is assumed. "
                        "Make the read explicit so the card can cite it.")


@check
def card_004_budget_ceiling(inv: Inventory) -> Finding:
    """CARD-004 — Code-enforced cost ceiling before any paid call."""
    if not inv.uses_ai:
        return Finding("CARD-004", "Code-enforced cost ceiling", NA, "high", "Cost", ["LLM10"], ["MAP 3", "MANAGE 2"])
    ev = _m(inv, "budget")
    return Finding("CARD-004", "Code-enforced cost ceiling", PASS if ev else FAIL, "high", "Cost",
                   ["LLM10"], ["MAP 3", "MANAGE 2"], _ev(ev),
                   guidance="Add a budget object that is charged BEFORE each network call and raises when the ceiling "
                            "would be exceeded. A dashboard alert is not a control; code is.")


@check
def card_005_offline_default(inv: Inventory) -> Finding:
    """CARD-005 — Offline / mock provider so tests and CI never spend money."""
    if not inv.uses_ai:
        return Finding("CARD-005", "Offline (mock) mode available", NA, "medium", "Cost", ["LLM10"], ["MAP 3"])
    ev = _m(inv, "mock")
    return Finding("CARD-005", "Offline (mock) mode available", PASS if ev else FAIL, "medium", "Cost",
                   ["LLM10"], ["MAP 3"], _ev(ev),
                   guidance="Provide a deterministic mock provider (or dry-run) as the default so the suite runs at $0 "
                            "and live calls are an explicit opt-in.")


@check
def card_006_human_gate(inv: Inventory) -> Finding:
    """CARD-006 — Human approval gate between model output and consequential action."""
    if not inv.uses_ai:
        return Finding("CARD-006", "Human approval gate, no auto-execute", NA, "high", "Agency",
                       ["LLM06", "LLM05"], ["GOVERN 3", "MANAGE 1"])
    gate = _m(inv, "gate")
    execs = inv.exec_primitives
    if gate:
        f = Finding("CARD-006", "Human approval gate, no auto-execute", PASS, "high", "Agency",
                    ["LLM06", "LLM05"], ["GOVERN 3", "MANAGE 1"], _ev(gate))
        if execs:
            f.note = f"Execution primitives are also present ({len(execs)}); confirm they sit behind the gate."
            f.evidence += _ev(execs, 3)
        return f
    sev = "high" if execs else "medium"
    return Finding("CARD-006", "Human approval gate, no auto-execute", FAIL, sev, "Agency",
                   ["LLM06", "LLM05"], ["GOVERN 3", "MANAGE 1"], _ev(execs),
                   guidance=("Model output reaches an execution primitive with no approval step in between. "
                             if execs else "No approval step was found. ")
                            + "Route every consequential action through a logged approve/reject decision by a named human.")


@check
def card_007_independent_verification(inv: Inventory) -> Finding:
    """CARD-007 — Model output is verified by something other than the model."""
    if not inv.uses_ai:
        return Finding("CARD-007", "Independent verification of model output", NA, "high", "Accuracy",
                       ["LLM09"], ["MEASURE 2", "MANAGE 2"])
    ev = _m(inv, "checker")
    return Finding("CARD-007", "Independent verification of model output", PASS if ev else FAIL, "high", "Accuracy",
                   ["LLM09"], ["MEASURE 2", "MANAGE 2"], _ev(ev),
                   guidance="Re-derive the claim from source data (a rule engine, a second independent check) and "
                            "adjudicate PASS / REVIEW / QUARANTINE. The model must never grade its own output.")


@check
def card_008_output_validation(inv: Inventory) -> Finding:
    """CARD-008 — Model output is parsed and validated, not trusted as-is."""
    if not inv.uses_ai:
        return Finding("CARD-008", "Structured output validated", NA, "medium", "Output handling",
                       ["LLM05"], ["MEASURE 2"])
    parse = _m(inv, "json_parse")
    valid = _m(inv, "validation")
    ok = bool(parse) and bool(valid)
    return Finding("CARD-008", "Structured output validated", PASS if ok else FAIL, "medium", "Output handling",
                   ["LLM05"], ["MEASURE 2"], _ev(parse, 3) + _ev(valid, 3),
                   guidance="Ask for strict JSON, parse it inside try/except, and validate the shape (schema, "
                            "allowed values) before anything downstream reads it.")


@check
def card_009_injection_detection(inv: Inventory) -> Finding:
    """CARD-009 — Prompt-injection patterns are detected / red-teamed."""
    if not inv.uses_ai:
        return Finding("CARD-009", "Prompt-injection detection", NA, "high", "Input handling",
                       ["LLM01"], ["MEASURE 2", "MANAGE 2"])
    ev = _m(inv, "injection")
    return Finding("CARD-009", "Prompt-injection detection", PASS if ev else FAIL, "high", "Input handling",
                   ["LLM01"], ["MEASURE 2", "MANAGE 2"], _ev(ev),
                   guidance="Scan untrusted input for published injection patterns before it reaches the prompt, "
                            "plant a canary, and keep a red-team suite in the tests.")


@check
def card_010_audit_chain(inv: Inventory) -> Finding:
    """CARD-010 — Tamper-evident audit trail of AI decisions."""
    if not inv.uses_ai:
        return Finding("CARD-010", "Tamper-evident audit log", NA, "medium", "Accountability",
                       [], ["GOVERN 4", "MEASURE 3"])
    ev = _m(inv, "chain")
    return Finding("CARD-010", "Tamper-evident audit log", PASS if ev else FAIL, "medium", "Accountability",
                   [], ["GOVERN 4", "MEASURE 3"], _ev(ev),
                   guidance="Hash-chain the log (each entry carries the SHA-256 of the previous) and write a manifest "
                            "of run outputs so edits, deletions and reordering are detectable.")


@check
def card_011_accuracy_evaluation(inv: Inventory) -> Finding:
    """CARD-011 — Accuracy is measured against ground truth and published."""
    if not inv.uses_ai:
        return Finding("CARD-011", "Accuracy evaluation exists", NA, "high", "Accuracy",
                       ["LLM09"], ["MEASURE 1", "MEASURE 2"])
    ev = _m(inv, "eval")
    ok = bool(ev) or bool(inv.benchmark_files)
    f = Finding("CARD-011", "Accuracy evaluation exists", PASS if ok else FAIL, "high", "Accuracy",
                ["LLM09"], ["MEASURE 1", "MEASURE 2"], _ev(ev),
                guidance="Score the model against deterministic ground truth (precision / recall / F1 over N runs) "
                         "and commit the numbers with the evidence that produced them.")
    if inv.benchmark_files:
        f.evidence += [f"{b} — benchmark artifact" for b in inv.benchmark_files[:3]]
    return f


@check
def card_012_drift_detection(inv: Inventory) -> Finding:
    """CARD-012 — Regression / drift between runs is detected."""
    if not inv.uses_ai:
        return Finding("CARD-012", "Drift / regression detection", NA, "low", "Monitoring",
                       ["LLM09"], ["MEASURE 3", "MANAGE 4"])
    ev = _m(inv, "drift")
    return Finding("CARD-012", "Drift / regression detection", PASS if ev else FAIL, "low", "Monitoring",
                   ["LLM09"], ["MEASURE 3", "MANAGE 4"], _ev(ev),
                   guidance="Diff each run against the previous one and fail CI when a previously passing "
                            "case regresses. Model updates change behaviour silently.")


@check
def card_013_model_pinned(inv: Inventory) -> Finding:
    """CARD-013 — The model identifier is explicit and reproducible."""
    if not inv.uses_ai:
        return Finding("CARD-013", "Model identifier declared", NA, "medium", "Provenance",
                       ["LLM03"], ["GOVERN 4", "MAP 2"])
    ids = inv.model_ids
    f = Finding("CARD-013", "Model identifier declared", PASS if ids else FAIL, "medium", "Provenance",
                ["LLM03"], ["GOVERN 4", "MAP 2"], _ev(ids, 4),
                guidance="Name the exact model in code (env-overridable), so a card and a benchmark can say which "
                         "model produced which numbers.")
    if ids:
        f.note = "models: " + ", ".join(sorted({e.snippet for e in ids}))
        if inv.model_env_override:
            f.note += "; environment override present"
    return f


@check
def card_014_timeouts(inv: Inventory) -> Finding:
    """CARD-014 — Network calls to the model carry explicit timeouts / retry limits."""
    if not inv.uses_ai:
        return Finding("CARD-014", "Explicit timeouts on model calls", NA, "low", "Resilience",
                       ["LLM10"], ["MANAGE 2"])
    ev = [e for e in _m(inv, "timeout") if e.file in inv.ai_files] or _m(inv, "timeout")
    return Finding("CARD-014", "Explicit timeouts on model calls", PASS if ev else FAIL, "low", "Resilience",
                   ["LLM10"], ["MANAGE 2"], _ev(ev, 3),
                   guidance="Pass an explicit timeout and a bounded retry count to the client; SDK defaults are "
                            "generous and invisible in a review.")


@check
def card_015_tests_and_ci(inv: Inventory) -> Finding:
    """CARD-015 — Automated tests and CI exist."""
    ok = inv.has_tests and inv.has_ci
    parts = [f"tests: {'yes' if inv.has_tests else 'no'}", f"CI workflow: {'yes' if inv.has_ci else 'no'}"]
    return Finding("CARD-015", "Tests and CI present", PASS if ok else FAIL, "medium", "Engineering",
                   [], ["MEASURE 1", "GOVERN 1"], parts,
                   guidance="Governance claims need a test that fails when the control is removed, and a CI job "
                            "that runs it on every push.")


@check
def card_016_ci_no_model_secrets(inv: Inventory) -> Finding:
    """CARD-016 — CI does not inject model API secrets (pushes cannot spend money)."""
    if not inv.has_ci:
        return Finding("CARD-016", "CI runs without model API secrets", NA, "low", "Cost",
                       ["LLM10"], ["MAP 3", "GOVERN 6"], note="No CI workflow found.")
    hits = inv.ci_model_secrets
    return Finding("CARD-016", "CI runs without model API secrets", FAIL if hits else PASS, "low", "Cost",
                   ["LLM10"], ["MAP 3", "GOVERN 6"], _ev(hits),
                   guidance="Run CI in mock mode. If a live job is needed, isolate it behind a manual trigger with "
                            "its own budget ceiling.")


@check
def card_017_license_and_docs(inv: Inventory) -> Finding:
    """CARD-017 — License, README and intended-use statement exist."""
    ok = inv.has_license and inv.has_readme
    parts = [f"LICENSE: {'yes' if inv.has_license else 'no'}", f"README: {'yes' if inv.has_readme else 'no'}",
             f"NOTICE: {'yes' if inv.has_notice else 'no'}"]
    f = Finding("CARD-017", "License and intended-use documentation", PASS if ok else FAIL, "medium", "Transparency",
                [], ["GOVERN 4", "GOVERN 1"], parts,
                guidance="State the license and, in the README's first paragraph, what the system is for and what it "
                         "must not be used for. The card quotes that paragraph as the intended use.")
    if inv.has_readme and not inv.intended_use:
        f.note = "README found but no prose paragraph to quote as intended use."
    return f


@check
def card_018_deps_pinned(inv: Inventory) -> Finding:
    """CARD-018 — Runtime dependencies are pinned (supply chain)."""
    hits = inv.unpinned_deps
    f = Finding("CARD-018", "Dependencies pinned", FAIL if hits else PASS, "medium", "Supply chain",
                ["LLM03"], ["GOVERN 6"], _ev(hits),
                guidance="Pin every runtime dependency to an exact version (==) and bump deliberately; "
                         "model SDKs change behaviour between minor versions.")
    f.note = f"declared dependencies: {inv.deps_declared}" + (" (stdlib-only)" if inv.deps_declared == 0 else "")
    return f


@check
def card_019_data_minimization(inv: Inventory) -> Finding:
    """CARD-019 — What is (and is not) sent to the model is stated, or redaction exists in code."""
    if not inv.uses_ai:
        return Finding("CARD-019", "Data minimisation stated or enforced", NA, "medium", "Data handling",
                       ["LLM02"], ["MAP 4", "MANAGE 2"])
    docs = inv.docs_data_statement
    code = _m(inv, "redaction")
    ok = bool(docs) or bool(code)
    return Finding("CARD-019", "Data minimisation stated or enforced", PASS if ok else FAIL, "medium", "Data handling",
                   ["LLM02"], ["MAP 4", "MANAGE 2"], _ev(docs, 3) + _ev(code, 3),
                   guidance="Write down exactly which fields reach the model (and which never do), and enforce it "
                            "with a redaction / allow-list step in the prompt builder.")


# ------------------------------------------------------------------ runner

def run_all_checks(inv: Inventory) -> list[Finding]:
    findings = [fn(inv) for fn in CHECKS]
    ids = [f.check_id for f in findings]
    assert len(ids) == len(set(ids)), "duplicate check ids"
    return findings
