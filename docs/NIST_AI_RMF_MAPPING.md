# NIST AI RMF 1.0 — Control Mapping for Cybwaycard

This document maps what Cybwaycard *does* and *checks for* to the four core functions of the
**NIST AI Risk Management Framework (AI RMF 1.0)** — GOVERN, MAP, MEASURE, MANAGE. The AI RMF
is a US Government work (public domain); function and category names are referenced by
identifier. Each row cites the code in this repository, so every claim is verifiable by reading
the source.

Scope note: Cybwaycard is a single-developer portfolio project and calls no model itself. This
mapping documents (a) how the tool's own design applies AI RMF principles and (b) which AI RMF
categories each of its 19 checks speaks to when it scans *someone else's* codebase. It is not a
claim of organizational AI RMF conformance, third-party assessment, or certification.

---

## GOVERN — policies, accountability, transparency

| AI RMF category | How Cybwaycard implements / checks it | Evidence in repo |
|---|---|---|
| GOVERN 1 — Policies and procedures for AI risk are in place and transparent | Hard rules are written down (static-only, defensive-only, synthetic-only, honest output) and enforced mechanically: `policy_lint`, `secret_scan`, the self-scan gate in CI. Checks CARD-015 and CARD-017 look for the same in scanned repos. | `CLAUDE.md`, `src/cybwaycard/controls.py`, `.github/workflows/ci.yml`, `checks.py::card_015_tests_and_ci`, `card_017_license_and_docs` |
| GOVERN 3 — Human oversight for consequential decisions | CARD-006 looks for an approval gate and flags model output that reaches `subprocess` / `exec` with no human step; severity is raised to high when an execution primitive is present. | `checks.py::card_006_human_gate`, `signals.py` (`EXEC_RE`, `MARKER_RES["gate"]`) |
| GOVERN 4 — Transparency and documentation | The card itself is the transparency artifact: intended use is quoted from the target's README, every PASS cites `file:line`, caveats are printed on every card. CARD-010 and CARD-013 check for audit trails and declared model identifiers. | `src/cybwaycard/card.py` (`CAVEATS`, `render_markdown`), `checks.py::card_010_audit_chain`, `card_013_model_pinned` |
| GOVERN 6 — Third-party / supply-chain risk | Runtime is stdlib-only; dev dependency pinned. CARD-018 checks pinning in targets; CARD-002/003/016 check where credentials live. | `pyproject.toml`, `checks.py::card_018_deps_pinned`, `card_002_no_hardcoded_secrets`, `card_003_env_sourced_keys`, `card_016_ci_no_model_secrets` |

## MAP — context, categorization, and risk identification

| AI RMF category | How Cybwaycard implements / checks it | Evidence in repo |
|---|---|---|
| MAP 2 — AI system categorization; what the system does | CARD-001 inventories providers, model identifiers, call sites and the files that touch a model. CARD-013 requires the model to be named. | `signals.py` (`SDK_MODULES`, `API_HOSTS`, `CALL_SUFFIXES`, `MODEL_ID_RE`), `checks.py::card_001_inventory` |
| MAP 3 — Benefits, costs, resource constraints | CARD-004 (code-enforced cost ceiling), CARD-005 (offline default), CARD-016 (CI cannot spend). The tool's own cost is $0 by construction: no live mode exists. | `checks.py::card_004_budget_ceiling`, `card_005_offline_default`, `card_016_ci_no_model_secrets`, `CLAUDE.md` |
| MAP 4 — Risks to individuals and data | CARD-019 requires a written data-minimisation statement or redaction in code; CARD-002 detects credential literals. The scanner redacts any credential-shaped value before recording evidence. | `checks.py::card_019_data_minimization`, `signals.py::redact`, `tests/test_signals.py::test_env_key_and_hardcoded_secret` |

## MEASURE — evaluation, testing, monitoring

| AI RMF category | How Cybwaycard implements / checks it | Evidence in repo |
|---|---|---|
| MEASURE 1 — Metrics and methods identified and applied | CARD-011 looks for precision/recall/F1-style evaluation or a committed benchmark artifact; CARD-015 for tests and CI. The tool's own suite runs offline in CI. | `checks.py::card_011_accuracy_evaluation`, `card_015_tests_and_ci`, `tests/` |
| MEASURE 2 — Evaluated for trustworthy characteristics (validity, security, resilience) | CARD-007 (independent verification), CARD-008 (validated structured output), CARD-009 (prompt-injection detection). The browser demo is parity-tested against the Python engine so the two never diverge. | `checks.py::card_007_independent_verification`, `card_008_output_validation`, `card_009_injection_detection`, `tests/test_demo_parity.py` |
| MEASURE 3 — Mechanisms for tracking risks over time | CARD-010 (hash-chained log) and CARD-012 (drift). Every Cybwaycard run is itself hash-chained and manifested; `drift` fails CI when a control disappears. | `src/cybwaycard/auditlog.py`, `src/cybwaycard/drift.py`, `tests/test_engine_cli.py::test_drift_detects_removed_control` |

## MANAGE — responding to and monitoring risks

| AI RMF category | How Cybwaycard implements / checks it | Evidence in repo |
|---|---|---|
| MANAGE 1 — Risks are prioritized and responded to | Every FAIL carries a severity and remediation guidance; the card's verdict distinguishes high-severity gaps from minor ones; `--fail-on-gaps` turns the card into a merge gate. | `checks.py` (`guidance`, `severity`), `card.py` (`verdict`), `cli.py` (`--fail-on-gaps`) |
| MANAGE 2 — Strategies to maximise benefits and minimise negative impacts | Cost (CARD-004/014), injection (CARD-009), verification (CARD-007) and data handling (CARD-019) are the concrete mitigations the card looks for. | `checks.py` |
| MANAGE 4 — Post-deployment monitoring and incident response | CARD-012 drift detection; the risk register makes unmitigated categories explicit rather than implicit. | `checks.py::card_012_drift_detection`, `card.py::_register` |

## What is deliberately NOT claimed

- Three OWASP LLM categories (LLM04, LLM07, LLM08) are reported **NOT ASSESSED** on every card because no honest static check exists for them (`checks.py::NOT_STATICALLY_ASSESSABLE`).
- A PASS means evidence was found by an identifier/pattern heuristic; it is not a certification and can be fooled by naming. The caveats section of every card says so.
- No organisational AI RMF conformance is claimed. This is a self-assessed mapping by the author.
