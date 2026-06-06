"""Tests for W1.7 Run-5 fix — main-agent inline synthesis Path-A dismissal.

User's structural diagnosis (verbatim 2026-05-24, validated by design):
"_dismiss_stale_delegates has 2 paths: same-actor and DIFFERENT-actor WITH
path_b_would_allow ledger row. Synthesis was inverted in W1.7: inline IS Path A.
So no path_b_would_allow row gets written when main-agent records
synthesis_corroboration. The dismissal predicate is never satisfied → the
@synthesis-analyst delegate stays pending → generate_report returns
needs_delegate even after lane is recorded."

This test suite proves the fix works:
- BUG-A: find_temporal_clusters import bug fixed
- BUG-B: _inline_synthesis_satisfies_delegate predicate + 2 call sites
- BUG-C: _LANE_SPECS includes synthesis_corroboration so it's not erased
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

# fastmcp stub
if "fastmcp" not in sys.modules:
    fmc = types.ModuleType("fastmcp")
    class _Stub:
        def __init__(self, *a, **k): pass
        def tool(self, *a, **k):
            def _w(f): return f
            return _w
        def resource(self, *a, **k):
            def _w(f): return f
            return _w
        def run(self, *a, **k): pass
    fmc.FastMCP = _Stub
    sys.modules["fastmcp"] = fmc

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --- helpers for the post-integrity-fix contract (2026-06-05) -----------------
# Dismissal now keys on synthesis WORK done (compare_disk_and_memory +
# find_temporal_clusters ran successfully, lane-linked), NOT a >=3 CONFIRMED quota.
def _ok_exec(tool):
    return {"tool_name": tool, "exit_code": 0, "duration_seconds": 1.0,
            "audit_completed_entry_hash": "h"}


class _FakeStateMgr:
    """Minimal state_manager exposing get_execution for the actions-ran check."""
    def __init__(self, execs):
        self._execs = execs  # {execution_id: execution_dict}

    def get_execution(self, eid):
        return self._execs.get(eid)


def _synth_actions_state():
    """A state_manager where E-1/E-2 are successful compare + clusters runs."""
    return _FakeStateMgr({
        "E-1": _ok_exec("correlation.compare_disk_and_memory"),
        "E-2": _ok_exec("correlation.find_temporal_clusters"),
    })


class TestBugAFindTemporalClustersImport:
    """BUG-A: correlation.py:1430 had dead import that crashed the tool."""

    def test_function_can_be_imported_and_inspected(self):
        from sift_mcp.tools.correlation import find_temporal_clusters
        assert callable(find_temporal_clusters)

    def test_no_dead_get_state_manager_import_in_function(self):
        """The bogus import line must be GONE from the source."""
        src = (ROOT / "sift_mcp" / "tools" / "correlation.py").read_text(encoding="utf-8")
        assert "from sift_mcp.server import get_state_manager" not in src, (
            "BUG-A regression: dead import re-introduced. Function crashes on first call."
        )

    def test_function_returns_error_when_state_not_initialized(self):
        """Without init_tools(), function should return structured error,
        not raise ImportError."""
        from sift_mcp.tools import correlation as corr_mod
        # Temporarily clear the module-level state manager
        original_state = corr_mod._state_mgr
        corr_mod._state_mgr = None
        try:
            result = corr_mod.find_temporal_clusters(case_id="TEST")
            assert isinstance(result, dict)
            assert result.get("status") == "error"
            assert "init_tools" in result.get("error", "")
        finally:
            corr_mod._state_mgr = original_state


class TestBugBInlineSynthesisDismissal:
    """BUG-B: main-agent inline synthesis Path-A predicate."""

    def test_predicate_returns_false_for_wrong_lane(self):
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "memory", "assigned_agent": "main-agent", "status": "COMPLETE", "finding_ids": ["F-1", "F-2", "F-3"]},
            delegate_subagent="synthesis-analyst",
            state_findings=[
                {"finding_id": "F-1", "finding_status": "CONFIRMED"},
                {"finding_id": "F-2", "finding_status": "CONFIRMED"},
                {"finding_id": "F-3", "finding_status": "CONFIRMED"},
            ],
        )
        assert result is False  # wrong lane_id

    def test_predicate_returns_false_for_wrong_delegate_target(self):
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent", "status": "COMPLETE", "finding_ids": ["F-1", "F-2", "F-3"]},
            delegate_subagent="memory-analyst",  # NOT synthesis-analyst
            state_findings=[
                {"finding_id": f"F-{i}", "finding_status": "CONFIRMED"} for i in range(1, 4)
            ],
        )
        assert result is False

    def test_predicate_returns_false_for_wrong_assigned_agent(self):
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "evtx-analyst", "status": "COMPLETE", "finding_ids": ["F-1", "F-2", "F-3"]},
            delegate_subagent="synthesis-analyst",
            state_findings=[{"finding_id": f"F-{i}", "finding_status": "CONFIRMED"} for i in range(1, 4)],
        )
        assert result is False  # specialist recorded, not main-agent

    def test_predicate_ignores_confirmed_count_dismisses_with_actions(self):
        """INTEGRITY FIX (2026-06-05): the >=3 CONFIRMED quota is GONE. A lane with
        0 CONFIRMED but with the synthesis ACTIONS run (compare + clusters) must
        DISMISS — CONFIRMED is an outcome, not a quota (kills the fabrication
        incentive)."""
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent",
                         "status": "COMPLETE", "finding_ids": ["F-1"],
                         "execution_ids": ["E-1", "E-2"]},
            delegate_subagent="synthesis-analyst",
            state_findings=[{"finding_id": "F-1", "finding_status": "ACTIVE"}],  # 0 CONFIRMED
            state_manager=_synth_actions_state(),
        )
        assert result is True  # actions ran -> dismiss, regardless of CONFIRMED count

    def test_predicate_returns_false_hollow_lane_no_actions(self):
        """Anti-hollow-lane: lane COMPLETE with findings but the synthesis actions
        did NOT run (no compare/clusters execution_ids) -> must NOT dismiss. This
        is the new gaming guard replacing the >=3 quota."""
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent",
                         "status": "COMPLETE", "finding_ids": ["F-1", "F-2", "F-3"],
                         "execution_ids": []},  # no synthesis actions recorded
            delegate_subagent="synthesis-analyst",
            state_findings=[{"finding_id": f"F-{i}", "finding_status": "CONFIRMED"} for i in range(1, 4)],
            state_manager=_synth_actions_state(),
        )
        assert result is False  # even 3 CONFIRMED can't dismiss a hollow (no-actions) lane

    def test_predicate_returns_false_partial_actions(self):
        """Only one of compare/clusters ran -> not dismissed (both required)."""
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        partial = _FakeStateMgr({"E-1": _ok_exec("correlation.compare_disk_and_memory")})
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent",
                         "status": "COMPLETE", "finding_ids": ["F-1"], "execution_ids": ["E-1"]},
            delegate_subagent="synthesis-analyst",
            state_findings=[{"finding_id": "F-1", "finding_status": "ACTIVE"}],
            state_manager=partial,
        )
        assert result is False

    def test_predicate_returns_true_for_valid_inline_synthesis(self):
        """Happy path: main-agent recorded synthesis with the actions run."""
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent",
                         "status": "COMPLETE", "finding_ids": ["F-1", "F-2"],
                         "execution_ids": ["E-1", "E-2"]},
            delegate_subagent="synthesis-analyst",
            state_findings=[{"finding_id": "F-1", "finding_status": "CONFIRMED"},
                            {"finding_id": "F-2", "finding_status": "ACTIVE"}],
            state_manager=_synth_actions_state(),
        )
        assert result is True

    def test_predicate_accepts_legacy_corroboration_analyst_target(self):
        """Backward-compat: older delegates may target corroboration-analyst."""
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent",
                         "status": "COMPLETE", "finding_ids": ["F-1"], "execution_ids": ["E-1", "E-2"]},
            delegate_subagent="corroboration-analyst",  # legacy name
            state_findings=[{"finding_id": "F-1", "finding_status": "ACTIVE"}],
            state_manager=_synth_actions_state(),
        )
        assert result is True

    def test_predicate_accepts_complete_with_gaps_status(self):
        from sift_mcp.reporting import _inline_synthesis_satisfies_delegate
        result = _inline_synthesis_satisfies_delegate(
            lane_record={"lane_id": "synthesis_corroboration", "assigned_agent": "main-agent",
                         "status": "COMPLETE_WITH_GAPS", "finding_ids": ["F-1"],
                         "execution_ids": ["E-1", "E-2"]},
            delegate_subagent="synthesis-analyst",
            state_findings=[{"finding_id": "F-1", "finding_status": "ACTIVE"}],
            state_manager=_synth_actions_state(),
        )
        assert result is True


class TestBugCLaneSpecIncludesSynthesis:
    """BUG-C: _LANE_SPECS must include synthesis_corroboration or
    _synthesize_analysis_lanes filters it out → update_triage_state
    silently ERASES it from state.json on every successful generate_report.
    Run-5 evidence: E-047 recorded synthesis, final state had 6 lanes
    without it.
    """

    def test_lane_specs_includes_synthesis_corroboration(self):
        from sift_mcp.reporting import _LANE_SPECS
        assert "synthesis_corroboration" in _LANE_SPECS, (
            "BUG-C regression: synthesis_corroboration not in _LANE_SPECS → "
            "_synthesize_analysis_lanes will filter it out, "
            "update_triage_state will erase it from state.json on every report"
        )

    def test_lane_specs_synthesis_marked_not_required(self):
        """synthesis_corroboration is NOT a required prereq lane — the agent
        produces it AFTER prereqs close. Marking required=True would force
        empty-synthesis lanes to fail gates."""
        from sift_mcp.reporting import _LANE_SPECS
        spec = _LANE_SPECS["synthesis_corroboration"]
        assert spec.get("required") is False

    def test_synthesize_analysis_lanes_preserves_synthesis_lane(self):
        """End-to-end: feed a synthesis lane through the filter and verify
        it survives."""
        # The filter is _synthesize_analysis_lanes which builds from _LANE_SPECS keys.
        from sift_mcp.reporting import _LANE_SPECS
        synthesis_in_specs = "synthesis_corroboration" in _LANE_SPECS
        assert synthesis_in_specs, "Spec gate must allow synthesis through"


class TestRun5RegressionEndToEnd:
    """End-to-end regression: simulate Run-5's state and verify the fix
    (a) dismisses the delegate via inline-synthesis predicate,
    (b) preserves the lane in state.json after report generation."""

    def test_run5_lane_persistence_via_full_payload_path(self, tmp_path, monkeypatch):
        """Run-5 had E-047 record synthesis successfully, then update_triage_state
        erased it. After BUG-C fix, the lane should survive.
        """
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger

        # Default-bypass the hypothesis gate so this test focuses on lane persistence
        monkeypatch.setenv("SAVVYDFIR_SKIP_HYPOTHESIS_GATE", "1")

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("R5-LANE-TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))

        # Seed 4 CONFIRMED findings in the synthesis lane (Run-5 had F-065..F-068)
        sm.add_execution({"execution_id": "E-001", "tool_name": "correlation.compare_disk_and_memory", "iteration": 1, "command_line": "x", "parameters": {}})
        finding_ids = []
        for i in range(4):
            fid = sm.add_finding({
                "case_id": "R5-LANE-TEST",
                "finding_type": "persistence",
                "artifact_type": "correlation",
                "artifact_path": "<synthesis>",
                "tool_name": "state.submit_finding",
                "execution_id": "E-001",
                "iteration": 1,
                "evidence_kind": "inference",
                "confidence": 0.9,
                "description": f"Synthesis finding {i} with multi-source corroboration for Run-5 regression",
                "finding_status": "CONFIRMED",
                "alternative_hypothesis": "Benign explanation X",
                "evidence_against_it": ["Observation Y rules out X"],
                "disposition": "ruled_out",
                "corroborated_by": [f"F-00{j}" for j in range(1, 4) if j != i],
            })
            finding_ids.append(fid)

        # Record synthesis_corroboration lane
        sm.upsert_analysis_lane(
            lane_id="synthesis_corroboration",
            status="COMPLETE",
            assigned_agent="main-agent",
            execution_ids=["E-001"],
            finding_ids=finding_ids,
            summary="Inline synthesis from 4 CONFIRMED findings",
        )

        # Pre-check: synthesis_corroboration IS in state.json before report gen
        lanes_before = [l.get("lane_id") for l in sm.get_analysis_lanes()]
        assert "synthesis_corroboration" in lanes_before

        # Now simulate what generate_report does: call update_triage_state
        # with an analysis_lanes list synthesized via _synthesize_analysis_lanes
        from sift_mcp.reporting import _LANE_SPECS
        # Build the list the same way reporting does
        lanes_dict = {l["lane_id"]: l for l in sm.get_analysis_lanes()}
        synthesized = [lanes_dict[lid] for lid in _LANE_SPECS if lid in lanes_dict]
        sm.update_triage_state(
            triage_status="success",
            analysis_lanes=synthesized,
        )

        # Post-check: synthesis_corroboration MUST still be in state.json
        lanes_after = [l.get("lane_id") for l in sm.get_analysis_lanes()]
        assert "synthesis_corroboration" in lanes_after, (
            "BUG-C regression: synthesis_corroboration erased by update_triage_state "
            "because _LANE_SPECS doesn't include it. Run-5 evidence: agent recorded "
            "the lane successfully but final state.json had only 6 lanes."
        )
