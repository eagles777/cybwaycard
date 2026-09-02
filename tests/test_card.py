"""Card construction and rendering (Markdown + self-contained HTML)."""

import json

from cybwaycard.card import CAVEATS, build_card, render_html, render_markdown
from cybwaycard.checks import run_all_checks
from cybwaycard.samples import write_sample
from cybwaycard.signals import extract

NOW = "2026-01-01T00:00:00+00:00"


def _card(kind, tmp_path):
    inv = extract(write_sample(kind, tmp_path / kind))
    return build_card(inv, run_all_checks(inv), generated_at=NOW)


def test_card_sections_and_summary(tmp_path):
    card = _card("ungoverned", tmp_path)
    for key in ("generator", "generated_at", "subject", "system_details", "intended_use", "summary",
                "checks", "risk_register", "ai_rmf", "evaluation", "data_handling", "caveats", "references"):
        assert key in card, key
    s = card["summary"]
    assert s["total"] == 19 and s["pass"] + s["fail"] + s["na"] == 19
    assert s["verdict"] == "GAPS FOUND" and s["high_fails"] >= 3
    assert card["system_details"]["providers"] == {"OpenAI": 1}
    assert card["system_details"]["model_ids"] == ["gpt-4o"]
    assert card["intended_use"].startswith("Asks the model")
    assert card["caveats"] == CAVEATS


def test_governed_card_is_governed(tmp_path):
    card = _card("governed", tmp_path)
    assert card["summary"]["verdict"] == "GOVERNED" and card["summary"]["score_pct"] == 100
    reg = {r["id"]: r["status"] for r in card["risk_register"]}
    assert reg["LLM01"] == "MITIGATED" and reg["LLM06"] == "MITIGATED" and reg["LLM10"] == "MITIGATED"
    assert reg["LLM04"] == "NOT_ASSESSED" and reg["LLM07"] == "NOT_ASSESSED" and reg["LLM08"] == "NOT_ASSESSED"


def test_risk_register_statuses_for_ungoverned(tmp_path):
    card = _card("ungoverned", tmp_path)
    reg = {r["id"]: r for r in card["risk_register"]}
    assert reg["LLM01"]["status"] == "UNMITIGATED"
    assert reg["LLM06"]["status"] == "UNMITIGATED"
    assert reg["LLM10"]["status"] in ("UNMITIGATED", "PARTIAL")
    assert reg["LLM03"]["status"] == "PARTIAL"          # model pinned (PASS) but deps unpinned (FAIL)
    assert reg["LLM04"]["status"] == "NOT_ASSESSED" and "runtime" in reg["LLM04"]["note"]
    assert all(r["status"] in ("MITIGATED", "PARTIAL", "UNMITIGATED", "NOT_APPLICABLE", "NOT_ASSESSED")
               for r in card["risk_register"])


def test_no_ai_card_verdict(tmp_path):
    (tmp_path / "x.py").write_text("x = 1\n", encoding="utf-8")
    inv = extract(tmp_path)
    card = build_card(inv, run_all_checks(inv), generated_at=NOW)
    assert card["summary"]["verdict"] == "NO MODEL USAGE DETECTED"
    assert {r["status"] for r in card["risk_register"]} <= {"NOT_APPLICABLE", "NOT_ASSESSED", "MITIGATED", "PARTIAL", "UNMITIGATED"}
    assert all(r["status"] == "NOT_APPLICABLE" for r in card["risk_register"] if r["id"] in ("LLM01", "LLM06", "LLM09"))


def test_ai_rmf_grid_covers_all_functions(tmp_path):
    card = _card("governed", tmp_path)
    assert set(card["ai_rmf"]) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}
    for g in card["ai_rmf"].values():
        assert g["checks"] and g["categories"]


def test_markdown_render(tmp_path):
    card = _card("ungoverned", tmp_path)
    md = render_markdown(card)
    assert md.startswith("# AI System Card — ungoverned")
    for cid in ("CARD-001", "CARD-019"):
        assert cid in md
    assert "LLM01 | Prompt Injection" in md
    assert "**Guidance:**" in md
    assert "sk-fake" not in md               # redaction survives rendering
    assert "NOT ASSESSED" in md


def test_html_render_is_self_contained(tmp_path):
    card = _card("ungoverned", tmp_path)
    page = render_html(card, {"chain_ok": True, "chain_msg": "chain intact", "manifest_ok": True,
                              "manifest_problems": [], "manifest_sha256": "ab" * 32})
    assert page.startswith("<!doctype html>")
    assert "<script" not in page and "<link" not in page and "http://" not in page and "https://" not in page
    assert "prefers-color-scheme" in page and 'data-theme="dark"' in page
    assert "CARD-006" in page and "Excessive Agency" in page and "chain intact" in page
    assert "sk-fake" not in page
    # every check id appears exactly once as a heading id
    assert page.count("<span class='id'>CARD-") == 19


def test_card_is_json_serialisable_and_deterministic(tmp_path):
    a = json.dumps(_card("governed", tmp_path / "a"), sort_keys=True)
    b = json.dumps(_card("governed", tmp_path / "b"), sort_keys=True)
    assert a == b
