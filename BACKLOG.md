# BACKLOG.md

## Done — v0.1 (static, offline, $0)

- [x] Signal extraction (AST imports/calls + line patterns, file:line evidence, redaction at capture)
- [x] 19 governance checks CARD-001…019 with OWASP LLM / NIST AI RMF references and guidance
- [x] AI System Card (Markdown, JSON, self-contained HTML) + OWASP risk register + AI RMF coverage grid
- [x] Hash-chained audit log + SHA-256 manifest per run; `verify`
- [x] Governance drift between runs (`drift`, exit 1 on regression)
- [x] Two synthetic samples (`init-sample`), self-scan dogfood in CI, `--fail-on-gaps` CI gate
- [x] Browser demo mirroring the checks in JS, parity-tested under Node
- [x] Evidence directory: self, both samples, sibling project Cybwaydb

## Next

- [ ] Tagged v0.1.0 release (needs owner)
- [ ] GitHub Pages for `docs/demo.html` (needs owner)
- [ ] SARIF output so findings show up in the GitHub code-scanning tab
- [ ] `--baseline` flag: accept known gaps with a justification + review date (POA&M-style, like Cybwaydb's gate)
- [ ] Multi-file prompt inventory (collect string literals passed to the model call) for the LLM07 section
- [ ] JavaScript/TypeScript signal extraction (same checks, second language)

## Later / optional

- [ ] Pre-commit hook packaging
- [ ] PyPI publish (`pip install cybwaycard`) — needs owner account
- [ ] Optional LLM-assisted "explain this card" mode — would need a budget ceiling and opt-in; deliberately NOT in v0.1
