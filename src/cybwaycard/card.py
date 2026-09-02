"""Build the AI System Card + AI Risk Register from an Inventory and its Findings,
and render it as Markdown, JSON-ready dict, or a self-contained HTML page.

Section structure follows the publicly described "Model Cards" reporting format
by name (details, intended use, metrics, evaluation, caveats). The risk register
uses OWASP Top 10 for LLM Applications category names with attribution, and the
coverage grid uses NIST AI RMF 1.0 function identifiers. Static, offline, $0.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from . import __version__
from .checks import FAIL, NA, PASS, NOT_STATICALLY_ASSESSABLE, OWASP_LLM, Finding
from .signals import Inventory

RMF_FUNCTIONS = ("GOVERN", "MAP", "MEASURE", "MANAGE")

CAVEATS = [
    "Static analysis only: the code was read, never executed. A control that exists in code may still be bypassed at runtime; a control implemented under an unusual name may be missed.",
    "Checks are identifier and pattern heuristics with cited evidence. Treat a PASS as 'evidence found', not as certification, and a FAIL as 'no evidence found', not proof of absence.",
    "Three OWASP LLM categories (LLM04, LLM07, LLM08) are reported as NOT ASSESSED because no honest static check exists for them.",
    "Python sources only. Model calls made from other languages, notebooks, or shell scripts are not inventoried.",
    "This card describes the application code around a model, not the model itself. Foundation-model training data, licences and safety evaluations belong to the model provider's own card.",
]

REGISTER_STATUS = ("MITIGATED", "PARTIAL", "UNMITIGATED", "NOT_APPLICABLE", "NOT_ASSESSED")


def _register(findings: list[Finding], uses_ai: bool) -> list[dict]:
    rows = []
    for cat, name in OWASP_LLM.items():
        related = [f for f in findings if cat in f.owasp]
        if cat in NOT_STATICALLY_ASSESSABLE:
            status, note = "NOT_ASSESSED", NOT_STATICALLY_ASSESSABLE[cat]
        elif not related or all(f.status == NA for f in related):
            status = "NOT_APPLICABLE"
            note = "No model usage detected." if not uses_ai else "No applicable check."
        else:
            live = [f for f in related if f.status != NA]
            fails = [f for f in live if f.status == FAIL]
            status = "MITIGATED" if not fails else "UNMITIGATED" if len(fails) == len(live) else "PARTIAL"
            note = "; ".join(f"{f.check_id} {f.status}" for f in live)
        rows.append({"id": cat, "name": name, "status": status, "checks": [f.check_id for f in related], "note": note})
    return rows


def _rmf(findings: list[Finding]) -> dict:
    grid = {}
    for fn in RMF_FUNCTIONS:
        rel = [f for f in findings if any(r.startswith(fn + " ") for r in f.ai_rmf)]
        grid[fn] = {
            "checks": [f.check_id for f in rel],
            "categories": sorted({r for f in rel for r in f.ai_rmf if r.startswith(fn + " ")}),
            "pass": sum(1 for f in rel if f.status == PASS),
            "fail": sum(1 for f in rel if f.status == FAIL),
            "na": sum(1 for f in rel if f.status == NA),
        }
    return grid


def build_card(inv: Inventory, findings: list[Finding], generated_at: str | None = None,
               subject_name: str | None = None) -> dict:
    passed = [f for f in findings if f.status == PASS]
    failed = [f for f in findings if f.status == FAIL]
    na = [f for f in findings if f.status == NA]
    evaluated = len(passed) + len(failed)
    score = round(100 * len(passed) / evaluated) if evaluated else 0
    verdict = ("NO MODEL USAGE DETECTED" if not inv.uses_ai
               else "GOVERNED" if not failed
               else "GAPS FOUND" if any(f.severity == "high" for f in failed) else "MINOR GAPS")
    name = subject_name or inv.root.replace("\\", "/").rstrip("/").split("/")[-1]
    return {
        "card_format": "AI System Card + AI Risk Register (cybwaycard)",
        "generator": {"name": "cybwaycard", "version": __version__, "mode": "static analysis, offline, no model call, $0"},
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": {
            "name": name,
            "files_scanned": inv.files_scanned,
            "python_files": inv.python_files,
            "doc_files": inv.doc_files,
            "parse_errors": inv.parse_errors,
        },
        "system_details": {
            "uses_ai": inv.uses_ai,
            "providers": {label: len(evs) for label, evs in sorted(inv.providers.items())},
            "call_sites": [f"{e.file}:{e.line} — {e.kind}" for e in inv.call_sites],
            "model_ids": sorted({e.snippet for e in inv.model_ids}),
            "model_env_override": bool(inv.model_env_override),
            "ai_files": inv.ai_files,
            "execution_primitives": len(inv.exec_primitives),
        },
        "intended_use": inv.intended_use or "Not declared in a README prose paragraph.",
        "summary": {
            "verdict": verdict, "score_pct": score,
            "pass": len(passed), "fail": len(failed), "na": len(na), "total": len(findings),
            "high_fails": sum(1 for f in failed if f.severity == "high"),
            "medium_fails": sum(1 for f in failed if f.severity == "medium"),
            "low_fails": sum(1 for f in failed if f.severity == "low"),
        },
        "checks": [f.to_dict() for f in findings],
        "risk_register": _register(findings, inv.uses_ai),
        "ai_rmf": _rmf(findings),
        "evaluation": {
            "eval_markers": len(inv.markers.get("eval", [])),
            "benchmark_files": inv.benchmark_files,
        },
        "data_handling": {
            "statements": [f"{e.file}:{e.line} — {e.snippet}" for e in inv.docs_data_statement[:5]],
            "redaction_markers": len(inv.markers.get("redaction", [])),
            "env_keys": sorted({e.snippet for e in inv.env_keys}),
            "hardcoded_secrets": len(inv.hardcoded_secrets),
        },
        "caveats": CAVEATS,
        "references": {
            "owasp": "OWASP Top 10 for LLM Applications — category names used with attribution to the OWASP Foundation",
            "nist_ai_rmf": "NIST AI RMF 1.0 (NIST AI 100-1) — function/category identifiers; self-assessed mapping, not a conformance claim",
        },
    }


# ---------------------------------------------------------------- markdown

def render_markdown(card: dict, integrity: dict | None = None) -> str:
    s, d, sub = card["summary"], card["system_details"], card["subject"]
    L: list[str] = []
    L.append(f"# AI System Card — {sub['name']}")
    L.append("")
    L.append(f"*Generated by cybwaycard {card['generator']['version']} · {card['generator']['mode']} · {card['generated_at']}*")
    L.append("")
    L.append(f"**Verdict: {s['verdict']}** — governance score {s['score_pct']}% "
             f"({s['pass']} pass / {s['fail']} fail / {s['na']} not applicable of {s['total']} checks)")
    L.append("")
    L.append("## 1. System details")
    L.append("")
    L.append(f"- Files scanned: {sub['files_scanned']} ({sub['python_files']} Python, {sub['doc_files']} docs)")
    L.append(f"- Model usage detected: {'yes' if d['uses_ai'] else 'no'}")
    if d["uses_ai"]:
        L.append(f"- Providers: {', '.join(f'{k} ({v} refs)' for k, v in d['providers'].items()) or '—'}")
        L.append(f"- Model identifiers: {', '.join(d['model_ids']) or 'none declared'}"
                 + (" (environment override present)" if d["model_env_override"] else ""))
        L.append(f"- Model call sites: {len(d['call_sites'])}")
        for c in d["call_sites"][:10]:
            L.append(f"  - `{c}`")
        L.append(f"- Files touching a model: {', '.join(f'`{f}`' for f in d['ai_files']) or '—'}")
        L.append(f"- Execution primitives present: {d['execution_primitives']}")
    if sub["parse_errors"]:
        L.append(f"- Files that could not be parsed: {', '.join(sub['parse_errors'])}")
    L.append("")
    L.append("## 2. Intended use (as declared by the repository)")
    L.append("")
    L.append(f"> {card['intended_use']}")
    L.append("")
    L.append("## 3. Governance checks")
    L.append("")
    L.append("| Check | Control | Status | Severity | OWASP LLM | NIST AI RMF |")
    L.append("|---|---|---|---|---|---|")
    for c in card["checks"]:
        L.append(f"| {c['check_id']} | {c['title']} | **{c['status']}** | {c['severity']} | "
                 f"{', '.join(c['owasp']) or '—'} | {', '.join(c['ai_rmf']) or '—'} |")
    L.append("")
    for c in card["checks"]:
        if c["status"] == NA and not c["evidence"] and not c["note"]:
            continue
        L.append(f"### {c['check_id']} — {c['title']} · {c['status']}")
        L.append("")
        if c["note"]:
            L.append(f"{c['note']}")
            L.append("")
        for e in c["evidence"]:
            L.append(f"- `{e}`")
        if c["status"] == FAIL and c["guidance"]:
            L.append("")
            L.append(f"**Guidance:** {c['guidance']}")
        L.append("")
    L.append("## 4. AI risk register (OWASP Top 10 for LLM Applications)")
    L.append("")
    L.append("| ID | Risk | Status | Checks | Note |")
    L.append("|---|---|---|---|---|")
    for r in card["risk_register"]:
        L.append(f"| {r['id']} | {r['name']} | **{r['status'].replace('_', ' ')}** | "
                 f"{', '.join(r['checks']) or '—'} | {r['note']} |")
    L.append("")
    L.append("## 5. NIST AI RMF 1.0 coverage")
    L.append("")
    L.append("| Function | Categories touched | Pass | Fail | N/A |")
    L.append("|---|---|---|---|---|")
    for fn, g in card["ai_rmf"].items():
        L.append(f"| {fn} | {', '.join(g['categories'])} | {g['pass']} | {g['fail']} | {g['na']} |")
    L.append("")
    L.append("## 6. Evaluation and data handling")
    L.append("")
    ev, dh = card["evaluation"], card["data_handling"]
    L.append(f"- Evaluation markers in code: {ev['eval_markers']}; benchmark artifacts: {', '.join(ev['benchmark_files']) or 'none'}")
    L.append(f"- Data-handling statements in docs: {len(dh['statements'])}; redaction markers in code: {dh['redaction_markers']}")
    for st in dh["statements"]:
        L.append(f"  - {st}")
    L.append(f"- Credentials read from environment: {', '.join(dh['env_keys']) or 'none found'}; hardcoded credentials: {dh['hardcoded_secrets']}")
    L.append("")
    L.append("## 7. Caveats")
    L.append("")
    for c in card["caveats"]:
        L.append(f"- {c}")
    L.append("")
    L.append("## 8. Integrity")
    L.append("")
    if integrity:
        L.append(f"- Audit log chain: {integrity.get('chain_msg', '—')}")
        L.append(f"- Run manifest SHA-256: `{integrity.get('manifest_sha256', '—')}`")
    else:
        L.append("- This run's outputs are hash-chained (audit.log.jsonl) and listed in manifest.json; run `cybwaycard verify --run-dir <dir>`.")
    L.append("")
    L.append("---")
    L.append(f"*{card['references']['owasp']}. {card['references']['nist_ai_rmf']}.*")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- html

_CSS = """
:root{--ground:#eef1f5;--surface:#fff;--surface-2:#f6f8fb;--ink:#0f1a26;--muted:#5a6b7d;--line:#dce2ea;
--accent:#0e7fb8;--accent-soft:#e3f1f9;--high:#c0362c;--med:#b0741a;--low:#4a6785;--pass:#1f7a4d;
--high-soft:#f8e6e4;--med-soft:#f7edda;--pass-soft:#e2f1ea;--na:#7a8797}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--ground:#0d141d;--surface:#141d28;--surface-2:#1a2634;
--ink:#e7eef6;--muted:#93a4b8;--line:#26333f;--accent:#38bdf8;--accent-soft:#0f3247;--high:#f2645a;--med:#e0a13c;
--low:#8299b8;--pass:#48c98a;--high-soft:#2a1614;--med-soft:#2a2011;--pass-soft:#12271d;--na:#6b7a8c}}
:root[data-theme="dark"]{--ground:#0d141d;--surface:#141d28;--surface-2:#1a2634;--ink:#e7eef6;--muted:#93a4b8;
--line:#26333f;--accent:#38bdf8;--accent-soft:#0f3247;--high:#f2645a;--med:#e0a13c;--low:#8299b8;--pass:#48c98a;
--high-soft:#2a1614;--med-soft:#2a2011;--pass-soft:#12271d;--na:#6b7a8c}
*{box-sizing:border-box}body{margin:0}
.cc{--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,"SF Mono","Cascadia Code",Menlo,Consolas,monospace;
background:var(--ground);color:var(--ink);font-family:var(--sans);line-height:1.55;padding:32px 20px;-webkit-font-smoothing:antialiased}
.wrap{max-width:1060px;margin:0 auto;display:flex;flex-direction:column;gap:24px}
.label{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:16px;padding-bottom:18px;border-bottom:1px solid var(--line)}
.head h1{font-size:28px;font-weight:680;margin:0;letter-spacing:-.01em}.head .sub{color:var(--muted);font-size:14px;max-width:70ch}
.verdict{display:inline-flex;align-items:center;gap:9px;padding:9px 15px;border-radius:999px;font-family:var(--mono);font-size:13px;font-weight:600;border:1px solid}
.verdict.ok{color:var(--pass);background:var(--pass-soft);border-color:var(--pass)}.verdict.bad{color:var(--high);background:var(--high-soft);border-color:var(--high)}
.verdict.warn{color:var(--med);background:var(--med-soft);border-color:var(--med)}.verdict.na{color:var(--na);background:var(--surface-2);border-color:var(--line)}
.dot{width:9px;height:9px;border-radius:50%;background:currentColor}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.kpi{padding:14px;display:flex;flex-direction:column;gap:5px}.kpi .v{font-size:26px;font-weight:680;font-family:var(--mono);line-height:1}
.kpi .v.ok{color:var(--pass)}.kpi .v.bad{color:var(--high)}.kpi .v.na{color:var(--na)}.kpi .cap{font-size:11.5px;color:var(--muted)}
section{display:flex;flex-direction:column;gap:12px}section h2{font-size:15px;margin:0;font-weight:680}
.meta{padding:16px 18px;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px 24px;font-size:13.5px}
.meta b{color:var(--muted);font-weight:500;font-family:var(--mono);font-size:11.5px;text-transform:uppercase;letter-spacing:.08em;display:block}
blockquote{margin:0;padding:14px 18px;border-left:3px solid var(--accent);background:var(--accent-soft);border-radius:0 10px 10px 0;font-size:14px}
.f{display:grid;grid-template-columns:5px 1fr;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:var(--surface)}
.f .stripe{background:var(--low)}.f.high .stripe{background:var(--high)}.f.medium .stripe{background:var(--med)}.f.PASS .stripe{background:var(--pass)}.f.NA .stripe{background:var(--line)}
.f .b{padding:12px 15px;display:flex;flex-direction:column;gap:7px;min-width:0}.f .top{display:flex;flex-wrap:wrap;align-items:center;gap:9px}
.f .id{font-family:var(--mono);font-size:12px;color:var(--accent);font-weight:600}.f .t{font-weight:600;font-size:14px;flex:1;min-width:200px}
.pill{font-family:var(--mono);font-size:10px;letter-spacing:.05em;text-transform:uppercase;padding:3px 8px;border-radius:999px;font-weight:700;white-space:nowrap}
.pill.PASS,.pill.MITIGATED{color:var(--pass);background:var(--pass-soft)}.pill.FAIL,.pill.UNMITIGATED{color:var(--high);background:var(--high-soft)}
.pill.NA,.pill.NOT_APPLICABLE,.pill.NOT_ASSESSED{color:var(--na);background:var(--surface-2)}.pill.PARTIAL{color:var(--med);background:var(--med-soft)}
.pill.sev{color:var(--muted);background:var(--surface-2);border:1px solid var(--line)}
.ev{font-family:var(--mono);font-size:11.5px;background:var(--surface-2);border:1px solid var(--line);border-radius:7px;padding:8px 10px;overflow-x:auto;white-space:pre;margin:0}
.guide{font-size:13px;color:var(--muted)}.note{font-size:13px}
.refs{display:flex;flex-wrap:wrap;gap:6px}.refs span{font-family:var(--mono);font-size:10.5px;padding:2px 7px;border-radius:5px;background:var(--surface-2);border:1px solid var(--line);color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:600}
.tbl{overflow-x:auto}.rmf{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.rmf .card{padding:14px}.rmf .fn{font-family:var(--mono);font-weight:700;font-size:12px;color:var(--accent)}.rmf .n{font-size:12.5px;color:var(--muted)}
ul.plain{margin:0;padding-left:18px;font-size:13.5px}footer{font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:14px}
"""


def _h(x) -> str:
    return html.escape(str(x))


def render_html(card: dict, integrity: dict | None = None) -> str:
    s, d, sub = card["summary"], card["system_details"], card["subject"]
    vcls = {"GOVERNED": "ok", "GAPS FOUND": "bad", "MINOR GAPS": "warn"}.get(s["verdict"], "na")
    P: list[str] = []
    P.append("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>")
    P.append(f"<title>AI System Card — {_h(sub['name'])}</title><style>{_CSS}</style></head><body><div class='cc'><div class='wrap'>")
    P.append("<div class='head'><div><div class='label'>AI System Card · Risk Register</div>"
             f"<h1>{_h(sub['name'])}</h1><div class='sub'>Generated by cybwaycard {_h(card['generator']['version'])} — "
             f"{_h(card['generator']['mode'])} · {_h(card['generated_at'])}</div></div>"
             f"<div class='verdict {vcls}'><span class='dot'></span>{_h(s['verdict'])}</div></div>")
    P.append("<div class='kpis'>"
             f"<div class='card kpi'><div class='v {'ok' if s['score_pct'] >= 80 else 'bad'}'>{s['score_pct']}%</div><div class='cap'>governance score</div></div>"
             f"<div class='card kpi'><div class='v ok'>{s['pass']}</div><div class='cap'>checks passed</div></div>"
             f"<div class='card kpi'><div class='v {'bad' if s['fail'] else 'ok'}'>{s['fail']}</div><div class='cap'>checks failed</div></div>"
             f"<div class='card kpi'><div class='v na'>{s['na']}</div><div class='cap'>not applicable</div></div>"
             f"<div class='card kpi'><div class='v {'bad' if s['high_fails'] else 'ok'}'>{s['high_fails']}</div><div class='cap'>high-severity gaps</div></div>"
             "</div>")
    # system details
    P.append("<section><h2>1. System details</h2><div class='card meta'>")
    P.append(f"<div><b>Files scanned</b>{sub['files_scanned']} ({sub['python_files']} Python, {sub['doc_files']} docs)</div>")
    P.append(f"<div><b>Model usage</b>{'detected' if d['uses_ai'] else 'none detected'}</div>")
    P.append(f"<div><b>Providers</b>{_h(', '.join(f'{k} ({v})' for k, v in d['providers'].items()) or '—')}</div>")
    P.append(f"<div><b>Model identifiers</b>{_h(', '.join(d['model_ids']) or '—')}{' · env override' if d['model_env_override'] else ''}</div>")
    P.append(f"<div><b>Call sites</b>{len(d['call_sites'])}</div>")
    P.append(f"<div><b>Execution primitives</b>{d['execution_primitives']}</div>")
    P.append(f"<div><b>Files touching a model</b>{_h(', '.join(d['ai_files']) or '—')}</div>")
    P.append("</div></section>")
    P.append(f"<section><h2>2. Intended use (as declared by the repository)</h2><blockquote>{_h(card['intended_use'])}</blockquote></section>")
    # checks
    P.append("<section><h2>3. Governance checks</h2>")
    for c in card["checks"]:
        cls = c["status"] if c["status"] != FAIL else c["severity"]
        P.append(f"<div class='f {cls}'><div class='stripe'></div><div class='b'><div class='top'>"
                 f"<span class='id'>{_h(c['check_id'])}</span><span class='t'>{_h(c['title'])}</span>"
                 f"<span class='pill {c['status']}'>{c['status']}</span><span class='pill sev'>{_h(c['severity'])}</span></div>")
        if c["note"]:
            P.append(f"<div class='note'>{_h(c['note'])}</div>")
        if c["evidence"]:
            P.append("<pre class='ev'>" + "\n".join(_h(e) for e in c["evidence"]) + "</pre>")
        if c["status"] == FAIL and c["guidance"]:
            P.append(f"<div class='guide'><b>Guidance.</b> {_h(c['guidance'])}</div>")
        refs = [f"OWASP {o} {OWASP_LLM.get(o, '')}".strip() for o in c["owasp"]] + [f"AI RMF {r}" for r in c["ai_rmf"]]
        if refs:
            P.append("<div class='refs'>" + "".join(f"<span>{_h(r)}</span>" for r in refs) + "</div>")
        P.append("</div></div>")
    P.append("</section>")
    # register
    P.append("<section><h2>4. AI risk register — OWASP Top 10 for LLM Applications</h2><div class='card tbl'><table>"
             "<tr><th>ID</th><th>Risk</th><th>Status</th><th>Checks</th><th>Note</th></tr>")
    for r in card["risk_register"]:
        P.append(f"<tr><td class='id'>{r['id']}</td><td>{_h(r['name'])}</td><td><span class='pill {r['status']}'>{r['status'].replace('_', ' ')}</span></td>"
                 f"<td>{_h(', '.join(r['checks']) or '—')}</td><td>{_h(r['note'])}</td></tr>")
    P.append("</table></div></section>")
    # rmf
    P.append("<section><h2>5. NIST AI RMF 1.0 coverage</h2><div class='rmf'>")
    for fn, g in card["ai_rmf"].items():
        P.append(f"<div class='card'><div class='fn'>{fn}</div><div class='n'>{_h(', '.join(g['categories']))}</div>"
                 f"<div class='n'><span class='pill PASS'>{g['pass']} pass</span> <span class='pill FAIL'>{g['fail']} fail</span> <span class='pill NA'>{g['na']} n/a</span></div></div>")
    P.append("</div></section>")
    # data
    ev, dh = card["evaluation"], card["data_handling"]
    P.append("<section><h2>6. Evaluation and data handling</h2><div class='card meta'>")
    P.append(f"<div><b>Evaluation markers</b>{ev['eval_markers']}</div><div><b>Benchmark artifacts</b>{_h(', '.join(ev['benchmark_files']) or 'none')}</div>")
    P.append(f"<div><b>Data statements in docs</b>{len(dh['statements'])}</div><div><b>Redaction markers</b>{dh['redaction_markers']}</div>")
    P.append(f"<div><b>Env credentials</b>{_h(', '.join(dh['env_keys']) or 'none found')}</div><div><b>Hardcoded credentials</b>{dh['hardcoded_secrets']}</div>")
    P.append("</div>")
    if dh["statements"]:
        P.append("<pre class='ev'>" + "\n".join(_h(x) for x in dh["statements"]) + "</pre>")
    P.append("</section>")
    P.append("<section><h2>7. Caveats</h2><ul class='plain'>" + "".join(f"<li>{_h(c)}</li>" for c in card["caveats"]) + "</ul></section>")
    P.append("<section><h2>8. Integrity</h2><div class='card meta'>")
    if integrity:
        P.append(f"<div><b>Audit log chain</b>{_h(integrity.get('chain_msg', '—'))}</div>"
                 f"<div><b>Manifest</b>{'ok' if integrity.get('manifest_ok') else _h(integrity.get('manifest_problems', '—'))}</div>"
                 f"<div><b>Manifest SHA-256</b><span style='font-family:var(--mono);font-size:11px;word-break:break-all'>{_h(integrity.get('manifest_sha256', '—'))}</span></div>")
    else:
        P.append("<div>Run <code>cybwaycard verify --run-dir …</code> to check the hash-chained log and manifest.</div>")
    P.append("</div></section>")
    P.append(f"<footer>{_h(card['references']['owasp'])}. {_h(card['references']['nist_ai_rmf'])}. "
             "Static analysis only — no code executed, no model called.</footer>")
    P.append("</div></div></body></html>")
    return "".join(P)
