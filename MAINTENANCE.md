# MAINTENANCE.md

How a future session (or contributor) keeps Cybwaycard healthy.

## Layout

```
src/cybwaycard/
  signals.py    static signal extraction (AST imports/calls + line patterns) -> Inventory with file:line Evidence
  checks.py     one @check function per governance check (CARD-001..019) -> Finding
  card.py       build the card dict; render Markdown and self-contained HTML
  engine.py     run_scan(): extract -> checks -> card -> run dir (inventory/findings/card + audit log + manifest)
  drift.py      diff two findings.json (regressed / fixed / evidence changed)     [adapted from Cybwaydb]
  auditlog.py   hash-chained JSONL log + SHA-256 run manifest                      [adapted from Cybwaydb]
  controls.py   secret scan + policy lint over THIS repo                           [adapted from Cybwaydb]
  samples.py    two synthetic sample codebases (governed / ungoverned), fake key assembled at runtime
  cli.py        cybwaycard scan | card | verify | drift | controls | init-sample
docs/demo.html  browser-only demo mirroring the check logic in JS (parity-tested against Python in tests/test_demo_parity.py when Node is available)
docs/evidence/  committed scan outputs (self, samples, sibling project) — regenerate with make_evidence.py
tests/          all offline, $0
```

## Dependencies

- Runtime: **stdlib only** (ast, re, json, hashlib, pathlib). Keep it that way — the tool audits supply chains.
- Dev: `pytest==8.2.2` (pinned in `pyproject.toml` extras). Bump deliberately, run the full suite.

## Routine tasks

- `pytest` must pass before any merge. CI is static and never needs a key.
- `cybwaycard controls --root .` must return no hits. It runs in CI.
- `cybwaycard scan --root . --fail-on-gaps` (the self-scan) must exit 0. It runs in CI.
- **Adding a check:** write a `@check` function in `checks.py` with a unique `CARD-0xx` id, OWASP/AI-RMF references, guidance text, and an NA branch for non-AI repos; extend `samples.GOVERNED` so it PASSES and `samples.UNGOVERNED` so it FAILS; update the JS mirror in `docs/demo.html`; bump the count assertions in `tests/test_checks.py` and `tests/test_card.py`; regenerate `docs/evidence/`.
- **Adding a signal:** add the regex to `signals.py` (keep it simple enough to mirror in JS), respect `skip_line()`, add a case to `tests/test_signals.py`, mirror it in `docs/demo.html`.
- **Never write a credential-shaped literal into any file**, including tests. Assemble it at runtime (see `samples.fake_key`, and the string concatenations in the tests). The repo's own secret scan will catch it otherwise.
- Regenerate evidence after any check change: `python make_evidence.py` (clones the public sibling repo into a temp dir; needs git, no key).

## Invariants (from CLAUDE.md — do not break)

- Static only: never import, execute, or network-call the scanned code; never call a model. No live mode exists.
- Defensive only; synthetic data only; no copyrighted third-party benchmark content (see LEGAL.md).
- PASS means "evidence found", never "certified"; unassessable categories are reported NOT ASSESSED.
- Track progress in `PROGRESS.md`; queue work in `BACKLOG.md`.
