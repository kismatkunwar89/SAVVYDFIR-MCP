"""Tests for W1.7 — Activity Thread / Kill Chain blindspot detection (CR13 Option X).

Covers:
- KillChainPhase enum + MITRE technique → phase mapping
- ActivityThread state model (add_finding, empty_phases, filled_phases, coverage_summary)
- classify_finding_to_phase helper for sub-technique base mapping
- HTML report rendering (Mermaid + table)
- Phase 5 gate fourth pass path (main_agent_runtime_query)
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

# fastmcp stub
if "fastmcp" not in sys.modules:
    import types
    fastmcp_stub = types.ModuleType("fastmcp")

    class _Stub:
        def __init__(self, *a, **k): pass
        def tool(self, *a, **k):
            def _w(fn): return fn
            return _w
        def resource(self, *a, **k):
            def _w(fn): return fn
            return _w
        def run(self, *a, **k): pass

    fastmcp_stub.FastMCP = _Stub
    sys.modules["fastmcp"] = fastmcp_stub

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class TestKillChainClassification:

    def test_credential_dumping_maps_to_exploitation(self):
        from sift_mcp.models.activity_thread import classify_finding_to_phase, KillChainPhase
        assert classify_finding_to_phase(["T1003"]) == KillChainPhase.EXPLOITATION

    def test_exfil_maps_to_actions_on_objectives(self):
        from sift_mcp.models.activity_thread import classify_finding_to_phase, KillChainPhase
        assert classify_finding_to_phase(["T1041"]) == KillChainPhase.ACTIONS_ON_OBJECTIVES
        assert classify_finding_to_phase(["T1567"]) == KillChainPhase.ACTIONS_ON_OBJECTIVES

    def test_ransomware_maps_to_actions(self):
        from sift_mcp.models.activity_thread import classify_finding_to_phase, KillChainPhase
        assert classify_finding_to_phase(["T1486"]) == KillChainPhase.ACTIONS_ON_OBJECTIVES
        assert classify_finding_to_phase(["T1490"]) == KillChainPhase.ACTIONS_ON_OBJECTIVES

    def test_persistence_maps_to_installation(self):
        from sift_mcp.models.activity_thread import classify_finding_to_phase, KillChainPhase
        assert classify_finding_to_phase(["T1547"]) == KillChainPhase.INSTALLATION
        assert classify_finding_to_phase(["T1543"]) == KillChainPhase.INSTALLATION

    def test_sub_technique_falls_back_to_base(self):
        """T1059.001 PowerShell should map via T1059 base technique."""
        from sift_mcp.models.activity_thread import classify_finding_to_phase, KillChainPhase
        assert classify_finding_to_phase(["T1059.001"]) == KillChainPhase.EXPLOITATION
        assert classify_finding_to_phase(["T1070.001"]) == KillChainPhase.INSTALLATION

    def test_no_techniques_returns_none(self):
        from sift_mcp.models.activity_thread import classify_finding_to_phase
        assert classify_finding_to_phase([]) is None
        assert classify_finding_to_phase(["UNKNOWN"]) is None


class TestActivityThreadModel:

    def test_add_finding_classifies_into_phase(self):
        from sift_mcp.models.activity_thread import ActivityThread, KillChainPhase
        at = ActivityThread()
        phase = at.add_finding("F-001", ["T1003"])
        assert phase == "exploitation"
        assert "F-001" in at.phases["exploitation"]

    def test_add_finding_idempotent_on_finding_id(self):
        from sift_mcp.models.activity_thread import ActivityThread
        at = ActivityThread()
        at.add_finding("F-001", ["T1003"])
        at.add_finding("F-001", ["T1003"])
        assert at.phases["exploitation"].count("F-001") == 1

    def test_empty_phases_excludes_weaponization(self):
        """Diamond Axiom 4: weaponization is rarely observable on host —
        exclude it from blindspot reporting."""
        from sift_mcp.models.activity_thread import ActivityThread
        at = ActivityThread()
        # Empty thread
        empty = at.empty_phases()
        assert "weaponization" not in empty
        # Other phases should be marked empty
        assert "reconnaissance" in empty
        assert "actions_on_objectives" in empty

    def test_filled_phases_reports_correctly(self):
        from sift_mcp.models.activity_thread import ActivityThread
        at = ActivityThread()
        at.add_finding("F-001", ["T1003"])
        at.add_finding("F-002", ["T1041"])
        filled = at.filled_phases()
        assert "exploitation" in filled
        assert "actions_on_objectives" in filled
        assert "delivery" not in filled

    def test_phase_status_categories(self):
        from sift_mcp.models.activity_thread import ActivityThread, KillChainPhase
        at = ActivityThread()
        # 0 findings = empty
        assert at.phase_status(KillChainPhase.DELIVERY) == "empty"
        # 1 finding = partial
        at.add_finding("F-001", ["T1566"])  # Phishing → delivery
        assert at.phase_status(KillChainPhase.DELIVERY) == "partial"
        # 2+ findings = filled
        at.add_finding("F-002", ["T1190"])
        assert at.phase_status(KillChainPhase.DELIVERY) == "filled"

    def test_coverage_summary(self):
        from sift_mcp.models.activity_thread import ActivityThread
        at = ActivityThread()
        at.add_finding("F-001", ["T1003"])  # exploitation
        at.add_finding("F-002", ["T1003"])  # exploitation (now filled)
        at.add_finding("F-003", ["T1041"])  # actions (partial)
        s = at.coverage_summary()
        assert s["phases_filled"] == 1
        assert s["phases_partial"] == 1
        assert s["total_classified_findings"] == 3


class TestActivityThreadHTMLRendering:

    def test_render_includes_mermaid_block(self):
        from sift_mcp.reporting import render_activity_thread_html
        html = render_activity_thread_html({
            "phases": {
                "exploitation": ["F-001", "F-002"],
                "actions_on_objectives": ["F-003"],
            },
            "blindspot_notes": {},
        })
        assert "graph LR" in html
        assert "EXPLOITATION" in html
        assert "DELIVERY" in html  # empty phase still appears

    def test_render_marks_filled_partial_empty(self):
        from sift_mcp.reporting import render_activity_thread_html
        html = render_activity_thread_html({
            "phases": {
                "exploitation": ["F-1", "F-2"],   # filled
                "delivery": ["F-3"],              # partial
                # reconnaissance empty
            },
            "blindspot_notes": {},
        })
        assert "#16a34a" in html  # green for filled
        assert "#eab308" in html  # amber for partial
        assert "#dc2626" in html  # red for empty (reconnaissance)

    def test_render_shows_blindspot_count(self):
        from sift_mcp.reporting import render_activity_thread_html
        html = render_activity_thread_html({
            "phases": {"exploitation": ["F-1", "F-2"]},
            "blindspot_notes": {},
        })
        # Multiple empty phases → blindspot count > 0
        assert "Blindspots" in html


class TestPhase5GateFourthPath:
    """W1.7.11 — gate accepts main-agent recorded lane with linked
    execution_ids as PRIMARY pass path (new pass_reason='main_agent_runtime_query')."""

    def test_main_agent_lane_with_linked_exec_passes_gate(self, tmp_path, monkeypatch):
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        from sift_mcp.reporting import evaluate_investigation_success_gate

        monkeypatch.setenv(
            "SAVVYDFIR_DELEGATION_LEDGER",
            str(tmp_path / "ledger.jsonl"),
        )

        analysis_dir = tmp_path / "analysis"
        analysis_dir.mkdir()
        audit_path = analysis_dir / "audit.jsonl"

        # Use the canonical state file path so reporting can find audit.jsonl alongside
        state_path = analysis_dir / "state.json"
        sm = CaseStateManager(state_path=str(state_path))
        sm.load("TEST-CASE")

        audit = AuditLogger(str(audit_path))

        # Simulate: each specialist-required lane has been claimed by main-agent
        # with at least one finding that links to a real execution_id
        for lane, agent in [
            ("memory", "memory-analyst"),
            ("disk_execution_persistence", "registry-analyst"),
            ("event_auth", "evtx-analyst"),
            ("timeline_correlation", "mft-analyst"),
        ]:
            eid = audit.next_execution_id()
            sm.add_execution({
                "execution_id": eid,
                "tool_name": f"disk.extract_{lane}",
                "iteration": 1,
                "command_line": "test",
                "parameters": {},
            })
            fid = sm.add_finding({
                "case_id": "TEST-CASE",
                "finding_type": "ioc",
                "artifact_type": "disk",
                "artifact_path": "/x.csv",
                "tool_name": "state.add_finding",
                "execution_id": eid,
                "iteration": 1,
                "evidence_kind": "observation",
                "confidence": 0.7,
                "description": f"Inline finding for {lane}",
            })
            sm.upsert_analysis_lane(
                lane_id=lane,
                status="COMPLETE",
                assigned_agent="main-agent",
                execution_ids=[eid],
                finding_ids=[fid],
            )

        # Gate must pass via main_agent_runtime_query
        result = evaluate_investigation_success_gate("TEST-CASE", sm)
        assert result["status"] == "ok", (
            f"Gate should pass via main_agent_runtime_query; got {result}"
        )
        for lane in ("memory", "disk_execution_persistence", "event_auth", "timeline_correlation"):
            contrib = result["lane_contributions"][lane]
            assert contrib["passed"] is True
            assert contrib["pass_reason"] == "main_agent_runtime_query"
