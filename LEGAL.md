# LEGAL.md — Source Material & Licensing

## Our code

Apache-2.0. Copyright © V. Vikram. See `LICENSE` and `NOTICE`.

The hash-chained audit log, run manifest, repo-hygiene controls and drift comparison
modules are adapted from the author's sibling project Cybwaydb (Apache-2.0, same
copyright holder). Lineage is noted in `NOTICE` and `MAINTENANCE.md`.

## Third-party / reference material

| Source | Status | How we use it |
|---|---|---|
| OWASP Top 10 for LLM Applications | Referenced by name with attribution to the OWASP Foundation | Category identifiers and names (LLM01–LLM10) in `checks.py` and the risk register. No OWASP text is reproduced. |
| NIST AI RMF 1.0 (NIST AI 100-1) | US Government work, public domain | Function/category identifiers (GOVERN / MAP / MEASURE / MANAGE) in `checks.py`, the card's coverage grid and `docs/NIST_AI_RMF_MAPPING.md`. Self-assessed mapping, not a conformance claim. |
| "Model Cards for Model Reporting" (Mitchell et al., 2019) | Referenced by name only | The card's section order (details, intended use, metrics, evaluation, caveats) follows the publicly described structure. No text is reproduced. |
| CWE-798 (hardcoded credentials) | Referenced by identifier | Named in guidance text only. |
| CIS Benchmarks | **Copyrighted — EXCLUDED** | Not used anywhere in this repo; enforced by `policy_lint`. |

## Model and vendor names

Provider and model-family names (Anthropic, OpenAI, Google, Cohere, Mistral, etc.) appear
only as detection labels for imports, API hosts and model-identifier strings. This project
is not affiliated with or endorsed by any of them, by OWASP, by NIST, or by any employer of
the author.

## Data

All sample codebases in this repo are synthetic. The "API key" in the ungoverned sample is
assembled at runtime from a placeholder and is not a real credential. No real credential,
database, personal, or organizational data appears anywhere. Any credential-shaped string
the scanner finds in a target is redacted before it is written to any output.

## Evidence directory

`docs/evidence/cybwaydb/` contains a scan of the author's own public repository
(github.com/eagles777/cybwaydb, Apache-2.0). Snippets quoted there are short lines of that
repository's own source, reproduced under its license for evidence purposes.
