"""ITEM C tests: advisory corroboration pivots in the report (FK-wiring 2026-06-03).

Covers the signed implementation gates: artifact->FK-YAML mapping table,
per-finding fail-open, deterministic sorted cap, scope-preserving lane-pivot join,
render confirmed->strongly-corroborated + html.escape + section-omit-when-empty,
REJECTED exclusion.
"""

import pytest

from sift_mcp.corroboration import artifact_name_for_finding
from sift_mcp.reporting import (
    _collect_pivots_for_finding,
    _render_corroboration_pivots,
    build_finding_corroboration_pivots,
)


# --- artifact_name_for_finding mapping table (review blocker #1) -------------
@pytest.mark.parametrize("source_class,expected", [
    ("prefetch", "prefetch"),
    ("amcache", "amcache"),
    ("shimcache", "shimcache"),
    ("mft", "mft"),
    ("mft_timestomp", "mft"),
    ("evtx_process_creation", "event_logs_security"),
    ("evtx_system", "event_logs_security"),
    ("registry_run", "registry_run_keys"),
    ("userassist", "registry_fileaccess"),   # the gotcha: class != yaml name
    ("shellbag", "shellbags"),
    ("lnk", "lnk_files"),
    ("jump_list", "jump_lists"),
    ("browser", "browser"),
    ("srum", "srum"),
    ("usn_journal", "usn_journal"),
    ("memory_process", "volatility_memory"),
    ("injected_code", "volatility_memory"),
    ("sigma_corroborated", "hayabusa_alerts"),
    ("vss", "volume_shadow_copies"),
])
def test_artifact_name_from_source_class(source_class, expected):
    assert artifact_name_for_finding({"fk_source_class": source_class}) == expected


def test_artifact_name_from_subtype_direct_hit():
    assert artifact_name_for_finding({"artifact_subtype": "registry_fileaccess"}) == "registry_fileaccess"


def test_artifact_name_from_tool_name():
    assert artifact_name_for_finding({"tool_name": "disk.extract_srum"}) == "srum"


def test_artifact_name_unmapped_is_none():
    assert artifact_name_for_finding({"tool_name": "state.submit_finding"}) is None
    assert artifact_name_for_finding({}) is None


# --- build_finding_corroboration_pivots ------------------------------------
def _f(fid, sc="prefetch", path="C:/a.exe", status="ACTIVE"):
    return {"finding_id": fid, "fk_source_class": sc, "artifact_path": path,
            "finding_status": status}


def test_build_pivots_sorted_and_capped():
    findings = [_f(f"F-{i:03d}") for i in range(60)]
    rows = build_finding_corroboration_pivots(findings, [], cap=50)
    assert len(rows) == 50
    ids = [r["finding_id"] for r in rows]
    assert ids == sorted(ids)  # deterministic


def test_build_pivots_excludes_rejected():
    findings = [_f("F-001"), _f("F-002", status="REJECTED")]
    rows = build_finding_corroboration_pivots(findings, [])
    assert {r["finding_id"] for r in rows} == {"F-001"}


def test_build_pivots_unmapped_artifact_gets_error():
    findings = [{"finding_id": "F-001", "tool_name": "state.submit_finding"}]
    rows = build_finding_corroboration_pivots(findings, [])
    assert rows[0]["advisory_error"]  # unmapped artifact flagged, not dropped


def test_build_pivots_fail_open_per_finding():
    # a malformed finding must not zero the whole list
    findings = [_f("F-001"), {"finding_id": "F-002", "fk_source_class": 12345}, _f("F-003")]
    rows = build_finding_corroboration_pivots(findings, [])
    assert {r["finding_id"] for r in rows} == {"F-001", "F-002", "F-003"}


# --- scope-preserving pivot join -------------------------------------------
def test_pivot_join_finding_scoped():
    f = {"finding_id": "F-001"}
    lanes = [{"lane_id": "memory", "finding_ids": ["F-001"],
              "next_pivots": [{"tool": "list_dlls", "finding_id": "F-001"}]}]
    agent, lane = _collect_pivots_for_finding(f, lanes)
    assert len(agent) == 1 and agent[0]["pivot_scope"] == "finding"
    assert lane == []


def test_pivot_join_unscoped_lane_owned():
    f = {"finding_id": "F-001"}
    lanes = [{"lane_id": "memory", "finding_ids": ["F-001"],
              "next_pivots": [{"tool": "list_dlls"}]}]  # no finding scope
    agent, lane = _collect_pivots_for_finding(f, lanes)
    assert agent == []
    assert len(lane) == 1 and lane[0]["pivot_scope"] == "lane" and lane[0]["lane_id"] == "memory"


def test_pivot_join_other_finding_not_attached():
    # a pivot scoped to F-002 must NOT attach to F-001 even in a shared lane
    f = {"finding_id": "F-001"}
    lanes = [{"lane_id": "memory", "finding_ids": ["F-001", "F-002"],
              "next_pivots": [{"tool": "x", "finding_ids": ["F-002"]}]}]
    agent, lane = _collect_pivots_for_finding(f, lanes)
    assert agent == [] and lane == []


# --- render -----------------------------------------------------------------
def test_render_empty_omits_section():
    assert _render_corroboration_pivots([]) == ""
    assert _render_corroboration_pivots(None) == ""


def test_render_confirmed_becomes_strongly_corroborated():
    rows = [{"finding_id": "F-001", "artifact": "prefetch",
             "advisory_corroboration_tier": "confirmed", "timestamp_aligned": "true",
             "gap_sources": [], "suggested_tools": [], "rationale": "x"}]
    html = _render_corroboration_pivots(rows)
    assert "strongly-corroborated" in html
    assert ">confirmed<" not in html.lower()  # never raw 'confirmed' status word in a cell
    assert "--good" not in html and "status-confirmed" not in html


def test_render_escapes_html():
    rows = [{"finding_id": "F-001", "artifact": "prefetch",
             "advisory_corroboration_tier": "observation", "timestamp_aligned": "unknown",
             "gap_sources": ["<script>x</script>"], "suggested_tools": [],
             "rationale": "<b>boom</b>"}]
    html = _render_corroboration_pivots(rows)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<b>boom</b>" not in html
