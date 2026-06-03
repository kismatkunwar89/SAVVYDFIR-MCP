"""Unit tests for the pure analysis-debt detector (PART B, review 2026-06-03).

Covers the two ship-blocking invariants both reviewers pinned:
  1. auto-emitted extraction observation findings DO NOT clear debt
  2. (noop gap fingerprint lives in server.py; tested in test_file_access_gate-adjacent)
plus the per-handle / documented-negative / run_analysis-modulates-WARN rules.
"""

from sift_mcp.analysis_debt import (
    EXTRACTION_CATALOG,
    FILE_ACCESS_TOOL_SUFFIXES,
    compute_analysis_debt,
    data_gaps_fingerprint,
    lane_debt,
)


def test_data_gaps_fingerprint_distinguishes_added_gap():
    # SHIP-BLOCKER #2: a COMPLETE_WITH_GAPS -> COMPLETE_WITH_GAPS resubmit that
    # ADDS a gap must produce a different fingerprint (not swallowed as noop).
    empty = data_gaps_fingerprint([])
    one = data_gaps_fingerprint([{"handle_path": "/x.csv", "classification": "analysis_debt"}])
    assert empty != one
    # order-independent: same set of gaps -> same fingerprint
    a = data_gaps_fingerprint([{"a": 1}, {"b": 2}])
    b = data_gaps_fingerprint([{"b": 2}, {"a": 1}])
    assert a == b

ROOTS = ("/cases/CASE-X/artifacts",)
SELECTOR_ON = {"file_access_bundle_required": True}
SELECTOR_OFF = {"file_access_bundle_required": False}


def _ex(tool, eid, *, csv=None, summary="ran", params=None, refs=None):
    row = {"tool_name": tool, "execution_id": eid, "outputs_summary": summary}
    if csv is not None:
        row["csv_path"] = csv
    if params is not None:
        row["parameters"] = params
    if refs is not None:
        row["raw_evidence_refs"] = refs
    return row


def _auto_finding(tool, eid, path):
    # exactly how extraction tools emit (state.add_finding): no assigned_agent
    return {
        "tool_name": tool,
        "execution_id": eid,
        "artifact_path": path,
        "evidence_kind": "observation",
        "finding_status": "active",
    }


def _analyst_finding(eid, path, agent="main-agent"):
    # exactly how submit_finding persists: tool_name state.submit_finding + agent
    return {
        "tool_name": "state.submit_finding",
        "assigned_agent": agent,
        "source_execution_id": eid,
        "artifact_path": path,
    }


def test_unmined_file_access_csv_is_blocking_under_selector():
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [_ex("disk.extract_shellbags", "E-1", csv=csv)]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert len(out["blocking"]) == 1
    assert out["blocking"][0]["handle_path"] == csv
    assert out["blocking"][0]["tool_suffix"] == "extract_shellbags"
    assert out["warning"] == []


def test_file_access_warns_when_selector_off():
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [_ex("disk.extract_shellbags", "E-1", csv=csv)]
    out = compute_analysis_debt(execs, [], SELECTOR_OFF, analysis_roots=ROOTS)
    assert out["blocking"] == []
    assert len(out["warning"]) == 1


def test_analyst_finding_clears_debt():
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [_ex("disk.extract_shellbags", "E-1", csv=csv)]
    findings = [_analyst_finding("E-1", csv)]
    out = compute_analysis_debt(execs, findings, SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"] == []
    assert out["warning"] == []


def test_auto_observation_does_not_clear_debt():
    # SHIP-BLOCKER #1: the file-access tools' own ACTIVE-0.70 observation must
    # NOT satisfy debt, else the detector is defeated at birth.
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [_ex("disk.extract_shellbags", "E-1", csv=csv)]
    findings = [_auto_finding("disk.extract_shellbags", "E-1", csv)]
    out = compute_analysis_debt(execs, findings, SELECTOR_ON, analysis_roots=ROOTS)
    assert len(out["blocking"]) == 1, "auto observation must not clear debt"


def test_documented_negative_clears_debt():
    execs = [_ex("disk.extract_shellbags", "E-1", csv=None,
                 summary="status=artifact_absent no_windows_volume_at_image_path")]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"] == []
    assert out["warning"] == []


def test_no_durable_handle_no_debt():
    # tool ran, produced nothing analyzable -> no Debt row (no phantom handle)
    execs = [_ex("disk.extract_shellbags", "E-1", csv=None)]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"] == [] and out["warning"] == []


def test_substantive_run_analysis_modulates_warn_but_does_not_clear():
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [
        _ex("disk.extract_shellbags", "E-1", csv=csv),
        _ex("analysis.run_analysis", "E-2",
            params={"data_path": csv, "query": "df[df['Value']=='x'].head(20)"}),
    ]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert len(out["blocking"]) == 1, "run_analysis alone must not clear debt"
    assert out["blocking"][0]["run_analysis_seen"] is True


def test_schema_only_run_analysis_not_substantive():
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [
        _ex("disk.extract_shellbags", "E-1", csv=csv),
        _ex("analysis.run_analysis", "E-2",
            params={"data_path": csv, "query": "df.dtypes"}),
    ]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"][0]["run_analysis_seen"] is False


def test_run_analysis_then_analyst_finding_clears_via_ra_exec():
    csv = "/cases/CASE-X/artifacts/shellbags/shellbags.csv"
    execs = [
        _ex("disk.extract_shellbags", "E-1", csv=csv),
        _ex("analysis.run_analysis", "E-2",
            params={"data_path": csv, "query": "df[df.x>0]"}),
    ]
    # analyst cited the run_analysis execution, not the extraction
    findings = [_analyst_finding("E-2", "")]
    out = compute_analysis_debt(execs, findings, SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"] == []


def test_non_file_access_unmined_is_warning_only():
    csv = "/cases/CASE-X/artifacts/srum/srum.csv"
    execs = [_ex("disk.extract_srum", "E-1", csv=csv)]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"] == []
    assert len(out["warning"]) == 1
    assert out["warning"][0]["lane_id"] == "timeline_correlation"


def test_transient_and_denylisted_paths_excluded():
    execs = [
        _ex("disk.extract_shellbags", "E-1", csv="/tmp/savvydfir_x/shellbags.csv"),
        _ex("disk.extract_lnk_files", "E-2", csv="/cases/CASE-X/artifacts/report.json"),
    ]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert out["blocking"] == [] and out["warning"] == []


def test_sigma_json_is_analyzable_csv_is_not_for_sigma():
    # sigma_hunt analyzable_outputs == {json}; a .json handle accrues, .csv would not
    j = "/cases/CASE-X/artifacts/sigma/hits.json"
    execs = [_ex("detection.sigma_hunt", "E-1", refs=[{"path": j, "role": "output"}])]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    # sigma is not report_block_when_required -> warning tier
    assert len(out["warning"]) == 1
    assert out["warning"][0]["handle_path"] == j


def test_by_lane_grouping_and_lane_debt_helper():
    execs = [
        _ex("disk.extract_shellbags", "E-1", csv="/cases/CASE-X/artifacts/sb/sb.csv"),
        _ex("disk.extract_srum", "E-2", csv="/cases/CASE-X/artifacts/srum/srum.csv"),
    ]
    out = compute_analysis_debt(execs, [], SELECTOR_ON, analysis_roots=ROOTS)
    assert lane_debt(out["by_lane"], "disk_execution_persistence")
    assert lane_debt(out["by_lane"], "timeline_correlation")


def test_catalog_lane_consistency_with_legacy_coverage_map():
    # drift guard: catalog lane assignments must agree with the legacy coverage
    # map for every suffix they share (peer reviewer blocker: no silent drift).
    from sift_mcp.reporting import _COVERAGE_SUFFIX_LANES
    for entry in EXTRACTION_CATALOG:
        legacy = _COVERAGE_SUFFIX_LANES.get(entry.tool_suffix)
        if legacy is not None and entry.lane_id is not None:
            assert entry.lane_id == legacy, (
                f"catalog/coverage lane drift for {entry.tool_suffix}: "
                f"{entry.lane_id} != {legacy}"
            )


def test_file_access_suffixes_derived_from_catalog():
    assert set(FILE_ACCESS_TOOL_SUFFIXES) == {
        "extract_shellbags", "extract_lnk_files", "extract_jump_lists",
        "extract_browser_history", "extract_registry_fileaccess",
    }


# ---------------------------------------------------------------------------
# Gate integration: debt BLOCK/WARN tiers through evaluate_ir_coverage_gate.
# This is the ROCBA case -- the file-access overlay PASSES (tool ran), but the
# new debt tier BLOCKS because no analyst finding mined the CSV.
# ---------------------------------------------------------------------------
from sift_mcp.reporting import (  # noqa: E402
    build_file_access_selector_snapshot,
    evaluate_ir_coverage_gate,
)

_SEL = build_file_access_selector_snapshot(
    {"dispute_type": "intrusion_response", "os_in_scope": ["Windows 10/11"]}
)


def _ran(suffix, eid, csv):
    return {
        "tool_name": f"disk.{suffix}", "execution_id": eid,
        "exit_code": 0, "duration_seconds": 1.0,
        "audit_completed_entry_hash": "h",
        "outputs_summary": "status=success merged 10 rows",
        "csv_path": csv,
    }


def _gate(executions, findings):
    return evaluate_ir_coverage_gate(
        findings=findings, executions=executions,
        sigma_result={"status": "ok"}, selector=_SEL,
        analysis_roots=ROOTS,
    )


def _debt_block_tools(res):
    return [m for m in res["missing"] if m.get("classification") == "analysis_debt_file_access"]


def test_gate_blocks_when_file_access_ran_but_unmined():
    # ROCBA: all 5 ran successfully, zero analyst findings -> debt blocks.
    csv = "/cases/CASE-X/artifacts/shellbags/sb.csv"
    res = _gate([_ran("extract_shellbags", "E-1", csv)], [])
    assert res["ok"] is False
    blocks = _debt_block_tools(res)
    assert len(blocks) == 1
    assert blocks[0]["handle_path"] == csv


def test_gate_passes_file_access_when_analyst_mined_it():
    csv = "/cases/CASE-X/artifacts/shellbags/sb.csv"
    findings = [_analyst_finding("E-1", csv)]
    res = _gate([_ran("extract_shellbags", "E-1", csv)], findings)
    # the 5 still missing as not-run is a separate concern; here only shellbags ran.
    assert _debt_block_tools(res) == []


def test_gate_returns_warning_list_for_non_file_access_debt():
    res = evaluate_ir_coverage_gate(
        findings=[], executions=[_ran("extract_srum", "E-1", "/cases/CASE-X/artifacts/srum/s.csv")],
        sigma_result={"status": "ok"}, selector=_SEL, analysis_roots=ROOTS,
    )
    assert any(w["tool_suffix"] == "extract_srum" for w in res.get("analysis_debt_warning", []))
    assert _debt_block_tools(res) == []
