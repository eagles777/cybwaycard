# PROGRESS.md

## Session 1 — 2026-09-02 — v0.1 BUILT end-to-end (static, offline, $0)

Scope decision: "Cybwaycard" = the **model card + AI risk register** item from Cybwaydb's backlog, generalised
into a tool that reads *any* LLM-using Python codebase and writes the card from code evidence. Pure static
analysis; no model is called anywhere in this project (there is no live mode at all).

Built:
- CLAUDE.md project rules (static-only, defensive-only, synthetic-only, honest output, strict privacy, private until owner says otherwise)
- Package scaffold: `pyproject.toml` (Apache-2.0, stdlib runtime, pytest==8.2.2 dev pin), src layout, `cybwaycard` CLI
- `signals.py`: AST imports/call-site detection for 19 SDK modules + 11 API hosts, model-id / env-key / hardcoded-secret / execution-primitive / 12 governance-marker patterns, README intended-use extraction, dependency pinning, CI secret detection; every signal carries file:line evidence; credential values redacted at capture; comment and regex-definition lines never count; test files excluded from usage/markers
- `checks.py`: 19 checks CARD-001…019, each with OWASP LLM + NIST AI RMF references, severity, guidance, NA branch for non-AI repos
- `card.py`: card dict (system details, intended use, checks, OWASP risk register incl. NOT ASSESSED for LLM04/07/08, AI RMF coverage grid, evaluation/data handling, caveats); Markdown + self-contained theme-aware HTML renderers
- `engine.py` + `cli.py`: scan / card / verify / drift / controls / init-sample; `--fail-on-gaps` CI gate
- `auditlog.py`, `controls.py`, `drift.py` adapted from Cybwaydb (lineage in NOTICE/LEGAL/MAINTENANCE)
- `samples.py`: governed + ungoverned synthetic repos; fake key assembled at runtime (no key-shaped literal anywhere in source, enforced by tests + secret scan)
- `docs/demo.html`: browser-only demo; JS mirror of the check logic; **parity-tested against Python under Node** (8 toggle states, every check/register status + verdict + score must match)
- `docs/evidence/`: committed runs for self, both samples, and the public sibling repo Cybwaydb (cloned at scan time, `.git` removed, local paths normalised); `make_evidence.py` regenerates
- Docs: README (badges, screenshots via headless Chromium, Mermaid architecture, evidence table, quick start), LEGAL.md, NOTICE, MAINTENANCE.md, BACKLOG.md, docs/NIST_AI_RMF_MAPPING.md
- CI workflow: tests, controls, self-scan gate, governed sample must pass, ungoverned must fail the gate. No keys anywhere.

Verified this session:
- `pytest` → 39 passed (all offline, $0), including the Node parity test
- `cybwaycard controls --root .` → clean
- Evidence: self = NO MODEL USAGE DETECTED (5 pass / 14 NA); governed sample = GOVERNED 100%; ungoverned sample = GAPS FOUND 11% (16 FAIL, 6 high); Cybwaydb = GOVERNED 100% (README states the caveat: the checks were designed from Cybwaydb's architecture, so this is a consistency check, not an independent audit)

Design notes worth keeping:
- API hosts only count when they appear as URLs (`//host`), so a detector's own knowledge table is never a signal
- `first_paragraph()` skips HTML headings, badges and link-wrapped badges so the card quotes real prose
- Policy-lint skips `docs/evidence/` (it quotes the *target's* files); the secret scan still covers it

Open (needs owner):
- Create/confirm the GitHub repo visibility (PRIVATE until reviewed), tag v0.1.0, enable Pages for the demo
- Decide whether the optional LLM-assisted "explain this card" mode (BACKLOG) should ever exist; v0.1 deliberately has none
