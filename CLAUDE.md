# CLAUDE.md — Project Instructions for Cybwaycard

Cybwaycard is an open-source, static AI-system-card and AI-risk-register generator — a personal AI-engineering portfolio project by V. Vikram. It reads an LLM-using codebase and writes a model-card-style document plus an OWASP-LLM risk register, with file:line evidence for every claim. It is NOT connected to any employer and contains zero employer or organizational data. Everything in the repo is synthetic.

Act as a senior engineer + build partner: direct, practical, push back on weak ideas, no praise-padding. Build the code; the owner supervises and approves. Show passing tests before moving on. Track progress across sessions in PROGRESS.md so it compounds.

## STANDING SESSION REMINDER

At the START of every session, check whether the GitHub repo (eagles777/cybwaycard) is PUBLIC or PRIVATE and report the status before doing anything else. It stays PRIVATE until the owner reviews it and explicitly says to go public. Never change visibility on your own, and never publish anything (release, Pages, PyPI, social) without asking first.

## HARD RULES (never violate)

* DEFENSIVE security only. No offensive/exploit/malware code. The tool detects missing controls in the user's OWN code; it never attacks anything.
* Static only. The tool never imports, executes, or network-calls the code it scans, and it never calls a model. There is no live-LLM mode in this project at all. $0 by design, always.
* Synthetic data only. Sample codebases are fake; the fake API key is assembled at runtime so no credential-shaped literal ever sits in source. Never any real credential, real database, or organizational data in the repo. The repo is "a personal project by V. Vikram."
* Copyright: NIST AI RMF 1.0 = US Government work (cite identifiers). OWASP Top 10 for LLM Applications = reference category names with attribution. "Model Cards" reporting format = referenced by name only. Copyrighted third-party benchmarks (e.g. CIS) are EXCLUDED. Our code = Apache-2.0, V. Vikram = copyright holder. Maintain LEGAL.md + NOTICE.
* Honesty in output: a PASS means "evidence found", never "certified". Categories that static analysis cannot evaluate are reported NOT ASSESSED, never quietly passed. Every claim in README must be reproducible by a command in the repo.
* Privacy (STRICT): NEVER put personal or employer information in the repo — no location/city, no citizenship, no employer or agency names, no job history, no contact info, no career specifics. Attribution is limited to the author's name as copyright holder. Before committing ANY personal detail, STOP and ask the owner first.
* Maintainability: stdlib-only runtime, pinned dev deps, MAINTENANCE.md + BACKLOG.md so a future session can maintain this.
