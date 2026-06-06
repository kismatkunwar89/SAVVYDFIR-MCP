"""Regression tests for Phase 5 — investigation-success gate.

design review 2026-05-22: a separate gate (NOT overloading
evaluate_ir_coverage_gate) verifies each specialist lane received
analyst contribution via submit_finding (Phase 1 provenance).

Pass paths:
  1. Path A: ≥1 submit_finding row from the expected specialist for the lane
  2. Repair fallback: ≥1 repair_succeeded ledger row for the lane
  3. Path B allowance: path_b_would_allow ledger row + main-agent add_finding

Fail path: none of the above → status=needs_specialist_contribution.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def isolated_env(monkeypatch, tmp_path):
    analysis_dir = tmp_path / "analysis"
    analysis_dir.mkdir()
    ledger_path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(ledger_path))
    monkeypatch.setenv("SAVVYDFIR_ANALYSIS_DIR", str(analysis_dir))
    return {
        "analysis_dir": analysis_dir,
        "ledger_path": ledger_path,
        "tmp_path": tmp_path,
    }


def _write_audit(analysis_dir: Path, rows: list[dict]):
    audit = analysis_dir / "audit.jsonl"
    audit.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )


def _write_ledger(ledger_path: Path, rows: list[dict]):
    ledger_path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )


def _make_state(tmp_path: Path):
    from sift_mcp.state import CaseStateManager
    sm = CaseStateManager(state_path=str(tmp_path / "analysis" / "state.json"))
    sm.load("TEST-CASE")
    return sm


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

def test_evaluate_investigation_success_gate_function_exists():
    from sift_mcp.reporting import evaluate_investigation_success_gate
    assert callable(evaluate_investigation_success_gate)


def test_specialist_required_lanes_constant():
    from sift_mcp.reporting import _SPECIALIST_REQUIRED_LANES
    expected = {"memory", "disk_execution_persistence", "event_auth", "timeline_correlation"}
    assert set(_SPECIALIST_REQUIRED_LANES) == expected, (
        f"_SPECIALIST_REQUIRED_LANES drift; got {_SPECIALIST_REQUIRED_LANES}"
    )


# ---------------------------------------------------------------------------
# Pass paths
# ---------------------------------------------------------------------------

def test_gate_passes_with_submit_finding_for_each_specialist_lane(isolated_env):
    """Path A — each lane has ≥1 submit_finding from its expected specialist."""
    from sift_mcp.reporting import evaluate_investigation_success_gate

    analysis_dir = isolated_env["analysis_dir"]
    _write_audit(analysis_dir, [
        # memory lane
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-001",
         "parameters": {"lane_id": "memory", "assigned_agent": "memory-analyst"}},
        # disk_execution_persistence lane (registry-analyst)
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-002",
         "parameters": {"lane_id": "disk_execution_persistence",
                        "assigned_agent": "registry-analyst"}},
        # event_auth lane
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-003",
         "parameters": {"lane_id": "event_auth", "assigned_agent": "evtx-analyst"}},
        # timeline_correlation lane
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-004",
         "parameters": {"lane_id": "timeline_correlation",
                        "assigned_agent": "mft-analyst"}},
    ])
    _write_ledger(isolated_env["ledger_path"], [])
    sm = _make_state(isolated_env["tmp_path"])
    result = evaluate_investigation_success_gate("TEST-CASE", sm)
    assert result["status"] == "ok", f"gate should pass; got {result}"
    for lane in ("memory", "disk_execution_persistence", "event_auth", "timeline_correlation"):
        contrib = result["lane_contributions"][lane]
        assert contrib["passed"] is True
        assert contrib["pass_reason"] == "specialist_submit_finding"


def test_gate_passes_via_repair_succeeded_fallback(isolated_env):
    """Repair fallback — no submit_finding, but repair_succeeded covers the lane."""
    from sift_mcp.reporting import evaluate_investigation_success_gate

    # Only timeline_correlation has direct submit_finding; the other 3 lanes
    # rely on repair_succeeded ledger rows.
    _write_audit(isolated_env["analysis_dir"], [
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-001",
         "parameters": {"lane_id": "timeline_correlation",
                        "assigned_agent": "mft-analyst"}},
    ])
    _write_ledger(isolated_env["ledger_path"], [
        {"event": "repair_succeeded", "lane_id": "memory",
         "specialist": "memory-analyst", "session_id": "S1"},
        {"event": "repair_succeeded", "lane_id": "disk_execution_persistence",
         "specialist": "registry-analyst", "session_id": "S1"},
        {"event": "repair_succeeded", "lane_id": "event_auth",
         "specialist": "evtx-analyst", "session_id": "S1"},
    ])
    sm = _make_state(isolated_env["tmp_path"])
    result = evaluate_investigation_success_gate("TEST-CASE", sm)
    assert result["status"] == "ok"
    assert result["lane_contributions"]["memory"]["pass_reason"] == "repair_succeeded_salvage"
    assert result["lane_contributions"]["timeline_correlation"]["pass_reason"] == "specialist_submit_finding"


def test_gate_passes_via_path_b_allowance(isolated_env):
    """Path B — ledger has path_b_would_allow + main-agent add_finding inline."""
    from sift_mcp.reporting import evaluate_investigation_success_gate

    # No submit_finding, no repair — main-agent inline Path B coverage.
    _write_audit(isolated_env["analysis_dir"], [
        # The submit_finding entries below cover lanes that DO have Path A
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-001",
         "parameters": {"lane_id": "memory", "assigned_agent": "memory-analyst"}},
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-002",
         "parameters": {"lane_id": "event_auth", "assigned_agent": "evtx-analyst"}},
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-003",
         "parameters": {"lane_id": "timeline_correlation",
                        "assigned_agent": "mft-analyst"}},
    ])
    _write_ledger(isolated_env["ledger_path"], [
        # disk_execution_persistence is via Path B
        {"event": "path_b_would_allow", "lane_id": "disk_execution_persistence",
         "specialist": "registry-analyst", "session_id": "S1"},
    ])
    sm = _make_state(isolated_env["tmp_path"])
    # Add a main-agent inline finding (no assigned_agent, tool_name=state.add_finding)
    sm.add_finding({
        "case_id": "TEST-CASE",
        "finding_type": "other",
        "artifact_type": "disk",
        "artifact_path": "/x/file.csv",
        "tool_name": "state.add_finding",
        "execution_id": "E-100",
        "iteration": 1,
        "evidence_kind": "observation",
        "confidence": 0.6,
        "description": "Main-agent inline Path B finding for disk_execution_persistence.",
    })
    # Record E-100 as a real execution so the finding's provenance resolves
    with sm._lock:  # type: ignore[attr-defined]
        sm._state.setdefault("executions", []).append({  # type: ignore[attr-defined]
            "execution_id": "E-100", "tool_name": "state.add_finding",
            "event_type": "completed", "iteration": 1,
        })
    result = evaluate_investigation_success_gate("TEST-CASE", sm)
    assert result["status"] == "ok"
    assert result["lane_contributions"]["disk_execution_persistence"]["pass_reason"] == "path_b_allowance_with_inline_findings"


# ---------------------------------------------------------------------------
# Fail path
# ---------------------------------------------------------------------------

def test_gate_fails_when_lanes_have_no_contribution(isolated_env):
    """Run-15 scenario: audit shows extraction tools ran but ZERO
    submit_finding calls and ZERO repair_succeeded. Gate must reject."""
    from sift_mcp.reporting import evaluate_investigation_success_gate

    _write_audit(isolated_env["analysis_dir"], [
        {"event_type": "completed", "tool": "disk.extract_mft_timeline",
         "execution_id": "E-001"},
        {"event_type": "completed", "tool": "disk.summarize_evtx",
         "execution_id": "E-002"},
        # Extraction tools succeeded but no specialist registered a finding.
    ])
    _write_ledger(isolated_env["ledger_path"], [])
    sm = _make_state(isolated_env["tmp_path"])
    result = evaluate_investigation_success_gate("TEST-CASE", sm)
    assert result["status"] == "needs_specialist_contribution", (
        f"gate should fail with needs_specialist_contribution; got {result}"
    )
    missing = result["missing_lanes"]
    assert len(missing) == 4, (
        f"all 4 specialist-required lanes should be flagged missing; got {missing}"
    )
    lanes = {m["lane_id"] for m in missing}
    assert lanes == {"memory", "disk_execution_persistence", "event_auth", "timeline_correlation"}
    # Reason must surface allow_partial=True escape hatch
    assert result["allow_partial_hint"] is True
    assert "allow_partial" in result["reason"].lower()
    assert "court-defensible" in result["reason"].lower() or "court" in result["reason"].lower()


def test_gate_fails_with_only_some_lanes_covered(isolated_env):
    """Partial Path A coverage — some lanes get submit_finding, others don't."""
    from sift_mcp.reporting import evaluate_investigation_success_gate

    _write_audit(isolated_env["analysis_dir"], [
        {"event_type": "completed", "tool": "state.submit_finding",
         "execution_id": "E-001",
         "parameters": {"lane_id": "memory", "assigned_agent": "memory-analyst"}},
        # event_auth, disk_execution_persistence, timeline_correlation: nothing
    ])
    _write_ledger(isolated_env["ledger_path"], [])
    sm = _make_state(isolated_env["tmp_path"])
    result = evaluate_investigation_success_gate("TEST-CASE", sm)
    assert result["status"] == "needs_specialist_contribution"
    missing_lane_ids = {m["lane_id"] for m in result["missing_lanes"]}
    # memory passes; the other 3 fail
    assert "memory" not in missing_lane_ids
    assert missing_lane_ids == {"disk_execution_persistence", "event_auth", "timeline_correlation"}


# ---------------------------------------------------------------------------
# Integration with generate_report_payload
# ---------------------------------------------------------------------------

def test_generate_report_payload_invokes_success_gate():
    """Source-text guard: generate_report_payload must call
    evaluate_investigation_success_gate BEFORE the coverage gate."""
    src = (ROOT / "sift_mcp" / "reporting.py").read_text()
    fn_idx = src.find("def generate_report_payload(")
    end = src.find("\ndef ", fn_idx + 1)
    body = src[fn_idx:end if end > 0 else fn_idx + 12000]
    assert "evaluate_investigation_success_gate" in body, (
        "generate_report_payload must invoke the Phase 5 gate."
    )
    # And it must use the needs_specialist_contribution status
    assert "needs_specialist_contribution" in body, (
        "generate_report_payload must surface the gate's failure status."
    )
    # Verify ordering: success gate before coverage gate
    success_idx = body.find("evaluate_investigation_success_gate")
    coverage_idx = body.find("evaluate_ir_coverage_gate")
    assert 0 < success_idx < coverage_idx, (
        "Phase 5 success gate must run BEFORE the existing coverage gate so "
        "the operator sees actionable specialist-contribution failures first."
    )
