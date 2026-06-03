"""Tests for the corroboration escalation engine (review FK-wiring 2026-06-03).

Covers the signed conditions: import-graph purity, ARTIFACT_VOCAB completeness vs
all 16 FK YAMLs, source_class precedence, structured-only entity match, tier split
(execution vs non-execution), timestamp-alignment cap, parse_upgrade_tier across
every YAML, greedy artifact-scoped gap, cold-start, fail-soft, advisory disclaimer.
"""

import sys
from pathlib import Path

import yaml

from sift_mcp import corroboration as C
from sift_mcp.corroboration import (
    ADVISORY_DISCLAIMER,
    ARTIFACT_VOCAB,
    corroboration_state,
    load_fk_slice,
    parse_upgrade_tier,
    present_corroborators,
    resolve_source,
    source_class_from_finding,
)

FK_DIR = Path(__file__).resolve().parent.parent / "data" / "forensic-knowledge" / "artifacts"
ALL_YAMLS = sorted(FK_DIR.glob("windows/*.yaml")) + sorted(FK_DIR.glob("linux/*.yaml"))


# --- non-disruption: import graph -----------------------------------------
def test_import_graph_is_pure():
    # corroboration may import semantics, but NOT server/state/reporting/fastmcp
    mod = sys.modules["sift_mcp.corroboration"]
    src = Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("import sift_mcp.server", "from sift_mcp.server",
                      "import sift_mcp.state", "from sift_mcp.state",
                      "import sift_mcp.reporting", "from sift_mcp.reporting",
                      "import fastmcp", "from fastmcp"):
        assert forbidden not in src, f"forbidden import: {forbidden}"


# --- ARTIFACT_VOCAB completeness vs the real YAMLs -------------------------
def test_vocab_resolves_every_corroborate_with_key():
    unresolved = []
    for y in ALL_YAMLS:
        d = yaml.safe_load(y.read_text(encoding="utf-8")) or {}
        for key in (d.get("corroborate_with") or {}):
            if resolve_source(key) is None:
                unresolved.append(f"{y.name}:{key}")
    assert not unresolved, f"corroborate_with keys not in ARTIFACT_VOCAB: {unresolved}"


def test_parse_upgrade_tier_on_every_combination():
    # every combinations[].upgrades_to across all YAMLs parses to a known tier
    bad = []
    for y in ALL_YAMLS:
        d = yaml.safe_load(y.read_text(encoding="utf-8")) or {}
        esc = d.get("corroboration_escalation") or {}
        for combo in esc.get("combinations") or []:
            if isinstance(combo, dict):
                if parse_upgrade_tier(combo.get("upgrades_to")) is None:
                    bad.append(f"{y.name}:{combo.get('upgrades_to')}")
    assert not bad, f"unparseable upgrades_to: {bad}"


def test_parse_upgrade_tier_labels():
    assert parse_upgrade_tier("PROBABLE execution (~0.85)") == "probable"
    assert parse_upgrade_tier("CONFIRMED / definitive execution trinity (~1.0)") == "confirmed"
    assert parse_upgrade_tier("OBSERVATION / possible (~0.70)") == "observation"
    assert parse_upgrade_tier("DEFINITIVE / PROVEN complete attack lifecycle") == "confirmed"
    assert parse_upgrade_tier("") is None


# --- source_class precedence ----------------------------------------------
def test_source_class_precedence_stored_first():
    f = {"fk_source_class": "prefetch", "tool_name": "disk.get_amcache"}
    assert source_class_from_finding(f) == "prefetch"  # stored wins over tool


def test_source_class_classify_fallback():
    f = {"tool_name": "disk.extract_prefetch"}
    assert source_class_from_finding(f) == "prefetch"


def test_source_class_vocab_fallback_and_null_safe():
    f = {"tool_name": "disk.extract_srum"}  # not in classify_fk_source
    assert source_class_from_finding(f) == "srum"
    assert source_class_from_finding({}) is None  # null-safe


# --- structured-only entity match (never description / corroborated_by) -----
def test_entity_match_uses_structured_fields_not_description():
    f = {"fk_source_class": "prefetch", "artifact_path": "C:/Temp/evil.exe",
         "timestamp_observed": "2020-11-13T03:01:58Z"}
    # corroborator shares the path -> matches
    g_match = {"fk_source_class": "amcache", "artifact_path": "C:/Temp/evil.exe",
               "timestamp_observed": "2020-11-13T03:02:00Z"}
    # decoy only mentions the path in description -> must NOT match
    g_desc = {"fk_source_class": "shimcache", "description": "saw C:/Temp/evil.exe somewhere"}
    present, aligned = present_corroborators(f, [g_match, g_desc])
    assert present == {"amcache"}
    assert aligned == "true"


def test_corroborated_by_is_never_read():
    f = {"fk_source_class": "prefetch", "artifact_path": "C:/x/a.exe"}
    g = {"fk_source_class": "mft", "corroborated_by": ["a.exe"]}  # no shared structured token
    present, _ = present_corroborators(f, [g])
    assert present == set()


# --- tier split: execution vs non-execution --------------------------------
def test_prefetch_alone_is_probable_not_observation():
    # the bug the consensus caught: prefetch-alone = 0.85 = probable
    f = {"fk_source_class": "prefetch", "artifact_path": "C:/a.exe"}
    st = corroboration_state(f, [f], {"artifact": "prefetch"})
    assert st.advisory_corroboration_tier == "probable"


def test_execution_trinity_is_confirmed_when_aligned():
    pf = {"fk_source_class": "prefetch", "artifact_path": "C:/a.exe", "timestamp_observed": "2020-11-13T03:00:00Z"}
    evtx = {"fk_source_class": "evtx_process_creation", "artifact_path": "C:/a.exe", "timestamp_observed": "2020-11-13T03:00:01Z"}
    mft = {"fk_source_class": "mft", "artifact_path": "C:/a.exe", "timestamp_observed": "2020-11-13T03:00:02Z"}
    fk = load_fk_slice("prefetch")
    st = corroboration_state(pf, [pf, evtx, mft], fk)
    assert st.advisory_corroboration_tier == "confirmed"
    assert st.timestamp_aligned == "true"


def test_shimcache_alone_is_observation():
    f = {"fk_source_class": "shimcache", "artifact_path": "C:/a.exe"}
    st = corroboration_state(f, [f], {"artifact": "shimcache"})
    assert st.advisory_corroboration_tier == "observation"


def test_non_execution_two_sources_probable():
    sb = {"fk_source_class": "shellbag", "artifact_path": "C:/docs"}
    lnk = {"fk_source_class": "lnk", "artifact_path": "C:/docs"}
    st = corroboration_state(sb, [sb, lnk], {"artifact": "shellbags"})
    assert st.advisory_corroboration_tier == "probable"


# --- timestamp alignment cap ----------------------------------------------
def test_three_sources_unaligned_capped_at_probable():
    # 3 execution sources but timestamps far apart + combos require alignment
    pf = {"fk_source_class": "prefetch", "artifact_path": "C:/a.exe", "timestamp_observed": "2020-11-13T03:00:00Z"}
    evtx = {"fk_source_class": "evtx_process_creation", "artifact_path": "C:/a.exe", "timestamp_observed": "2021-01-01T00:00:00Z"}
    mft = {"fk_source_class": "mft", "artifact_path": "C:/a.exe", "timestamp_observed": "2022-01-01T00:00:00Z"}
    fk = load_fk_slice("prefetch")
    st = corroboration_state(pf, [pf, evtx, mft], fk)
    assert st.timestamp_aligned == "false"
    assert st.advisory_corroboration_tier == "probable"  # capped from confirmed
    assert "capped" in st.rationale.lower()


# --- cold start + gap ------------------------------------------------------
def test_cold_start_lone_finding_has_gap():
    f = {"fk_source_class": "shimcache", "artifact_path": "C:/a.exe"}
    st = corroboration_state(f, [f], load_fk_slice("shimcache"))
    assert st.advisory_corroboration_tier == "observation"
    assert st.gap_sources  # never empty gap on a lone finding with FK combos
    assert st.present_sources == []


# --- advisory disclaimer + fail-soft --------------------------------------
def test_rationale_carries_disclaimer():
    f = {"fk_source_class": "prefetch", "artifact_path": "C:/a.exe"}
    st = corroboration_state(f, [f], {"artifact": "prefetch"})
    assert ADVISORY_DISCLAIMER in st.rationale


def test_fail_soft_on_bad_input():
    # garbage fk_slice must not raise
    st = corroboration_state({"fk_source_class": "prefetch"}, None, {"corroboration_escalation": "not-a-dict"})
    assert st.advisory_corroboration_tier in {"observation", "probable", "confirmed"}


def test_advisory_reference_sanitizes_and_caps():
    from sift_mcp.corroboration import build_advisory_reference, ENVELOPE_DISCLAIMER
    fk = load_fk_slice("prefetch")
    out = build_advisory_reference(fk)
    assert "advisory_corroboration" in out
    blob = out["advisory_corroboration"]
    assert blob.startswith(ENVELOPE_DISCLAIMER)
    # promotion numerics + words stripped (no gate thresholds leak)
    assert "0.85" not in blob and "1.0" not in blob and "~0." not in blob
    assert "CONFIRMED" not in blob and "definitive" not in blob.lower()
    # caps: heuristics/detection at most 2; each field bounded
    assert len(out.get("key_heuristics", [])) <= 2
    assert len(out.get("anti_forensics_detection", [])) <= 2
    for h in out.get("key_heuristics", []):
        assert len(h) <= 181


def test_advisory_reference_partial_fk_omits_cleanly():
    from sift_mcp.corroboration import build_advisory_reference
    # hayabusa_alerts.yaml has no escalation/heuristics/anti_forensics
    out = build_advisory_reference(load_fk_slice("hayabusa_alerts"))
    assert "key_heuristics" not in out
    assert build_advisory_reference({}) == {}
    assert build_advisory_reference(None) == {}


def test_advisory_reference_honors_char_budget():
    from sift_mcp.corroboration import build_advisory_reference
    tiny = build_advisory_reference(load_fk_slice("prefetch"), char_budget=50)
    total = sum(len(str(v)) for v in tiny.values())
    assert total <= 220  # one field max under a tiny budget


def test_unresolvable_combo_source_is_graceful():
    # a prose-y source that doesn't resolve must not crash and stays as a label
    fk = {"artifact": "x", "corroboration_escalation": {"combinations": [
        {"sources": ["something totally unknown xyz"], "upgrades_to": "PROBABLE", "plus_timestamps": "x"}
    ]}}
    f = {"fk_source_class": "prefetch", "artifact_path": "C:/a.exe"}
    st = corroboration_state(f, [f], fk)
    assert st.advisory_error is None
