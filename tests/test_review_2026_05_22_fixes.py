"""review adversarial-review fix regressions (2026-05-22).

review flagged two HIGH-severity wiring bugs after Phases 1-5 shipped:

  Fix #1 — submit_finding audit row was silently never written because
           log_execution() was called with unsupported kwargs (exit_code,
           duration_seconds, outputs_summary, finding_ids_generated). The
           Phase 5 gate reads audit.jsonl looking for tool=='state.submit_finding'
           rows; the broken call meant zero rows ever landed.

  Fix #2 — repair_succeeded ledger rows had no lane_id. The Phase 5 gate
           filters repair_succeeded by lane_id; without it, the repair
           fallback could never satisfy the success gate even when a
           json-repair Task actually salvaged findings for a lane.

These tests exercise the END-TO-END contract review required:
  test_submit_finding_writes_audit_row_phase_5_gate_can_read
  test_json_repair_credits_original_lane_phase_5_gate_passes
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Fix #1 — submit_finding writes a usable audit row that Phase 5 can count
# ---------------------------------------------------------------------------

def test_log_execution_signature_unchanged():
    """Sanity check: AuditLogger.log_execution still has the documented signature.
    If this drifts again we want to know before tests start lying."""
    from sift_mcp.audit import AuditLogger
    import inspect
    sig = inspect.signature(AuditLogger.log_execution)
    params = list(sig.parameters.keys())
    # self, execution_id, tool_name, parameters, command_line, agent_turn
    assert params == ["self", "execution_id", "tool_name", "parameters",
                      "command_line", "agent_turn"], (
        f"AuditLogger.log_execution signature changed: {params}. "
        "Phase 1 audit-write must be updated if extra kwargs are now accepted."
    )


def test_log_result_signature_unchanged():
    """Phase 1 now uses log_result for the completed row — verify its signature."""
    from sift_mcp.audit import AuditLogger
    import inspect
    sig = inspect.signature(AuditLogger.log_result)
    params = set(sig.parameters.keys())
    required = {"self", "execution_id", "exit_code", "duration",
                "outputs_summary", "finding_ids"}
    assert required.issubset(params), (
        f"AuditLogger.log_result missing required params; have {params}"
    )


def test_submit_finding_source_uses_log_result_not_kwargs():
    """Source-text guard: submit_finding must call log_result for the
    completed row, NOT pass unsupported kwargs to log_execution."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    fn_idx = src.find("def submit_finding(")
    end = src.find("\n@mcp.tool()\n", fn_idx + 1)
    body = src[fn_idx:end if end > 0 else fn_idx + 15000]
    assert "_audit_logger.log_result(" in body, (
        "submit_finding must write a completed audit row via log_result(...). "
        "review review 2026-05-22 [HIGH]."
    )
    # Should NOT pass unsupported kwargs to log_execution
    for forbidden in (
        "log_execution(\n", "exit_code=0,",
    ):
        # The forbidden pattern is when log_execution is called with extra kwargs.
        # Specifically, the original buggy call had "exit_code=0," INSIDE the
        # log_execution(...) call. Now exit_code lives inside log_result(...).
        pass
    # Verify: in the body, between "log_execution(" and its closing ")",
    # we should NOT see "exit_code=" before the next call.
    le_idx = body.find("log_execution(")
    le_close = body.find(")", le_idx)
    assert le_idx > 0
    le_call = body[le_idx:le_close + 1]
    forbidden_kwargs = ["exit_code=", "duration_seconds=", "outputs_summary=",
                        "finding_ids_generated="]
    for kw in forbidden_kwargs:
        assert kw not in le_call, (
            f"submit_finding's log_execution call still passes {kw!r}, which "
            "is not in the log_execution signature. This is the exact bug review "
            "flagged on 2026-05-22 — TypeError raised and silently swallowed."
        )


def test_submit_finding_audit_failure_surfaces_in_response():
    """review required: audit write failures must surface, not be silently
    swallowed. The response should include an `audit_warning` field on failure."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    fn_idx = src.find("def submit_finding(")
    end = src.find("\n@mcp.tool()\n", fn_idx + 1)
    body = src[fn_idx:end if end > 0 else fn_idx + 15000]
    assert "audit_warning" in body, (
        "submit_finding must surface audit write failures via an "
        "`audit_warning` field on the response. review required this — "
        "silent swallow is what created the Phase 5 invisibility bug."
    )


def test_submit_finding_end_to_end_audit_row_writable(tmp_path, monkeypatch):
    """Behavior test: writing a finding via the new submit_finding audit
    path produces a real `state.submit_finding` row in audit.jsonl that
    the Phase 5 gate can read."""
    # Set up an isolated audit log + state file.
    analysis_dir = tmp_path / "analysis"
    analysis_dir.mkdir()
    audit_path = analysis_dir / "audit.jsonl"

    from sift_mcp.audit import AuditLogger
    logger = AuditLogger(str(audit_path))

    # Mimic the new Phase 1 audit pair:
    eid = logger.next_execution_id()
    audit_command = "submit_finding(case_id='TEST', lane_id='memory', ...)"
    audit_parameters = {
        "case_id": "TEST",
        "lane_id": "memory",
        "assigned_agent": "memory-analyst",
        "finding_type": "process_injection",
        "artifact_type": "memory",
        "source_execution_id": "E-001",
    }
    logger.log_execution(
        execution_id=eid,
        tool_name="state.submit_finding",
        parameters=audit_parameters,
        command_line=audit_command,
    )
    logger.log_result(
        execution_id=eid,
        exit_code=0,
        duration=0.0,
        outputs_summary="finding_id=F-001 status=ACTIVE assigned_agent=memory-analyst",
        finding_ids=["F-001"],
        tool_name="state.submit_finding",
        command_line=audit_command,
        parameters=audit_parameters,
    )

    # Read audit.jsonl and confirm BOTH rows landed with tool=state.submit_finding
    rows = [json.loads(l) for l in audit_path.read_text().splitlines() if l.strip()]
    submit_rows = [r for r in rows if r.get("tool") == "state.submit_finding"]
    assert len(submit_rows) >= 2, (
        f"Expected started + completed rows, got {len(submit_rows)}: {submit_rows}"
    )
    # The completed row carries lane_id + assigned_agent in parameters
    completed = [r for r in submit_rows if r.get("event_type") == "completed"]
    assert completed
    params = completed[0].get("parameters") or {}
    assert params.get("lane_id") == "memory"
    assert params.get("assigned_agent") == "memory-analyst"


def test_submit_finding_audit_rows_make_phase_5_gate_pass(tmp_path, monkeypatch):
    """End-to-end: submit_finding audit rows for each specialist lane →
    evaluate_investigation_success_gate returns status='ok'."""
    analysis_dir = tmp_path / "analysis"
    analysis_dir.mkdir()
    audit_path = analysis_dir / "audit.jsonl"
    monkeypatch.setenv(
        "SAVVYDFIR_DELEGATION_LEDGER",
        str(tmp_path / "ledger.jsonl"),
    )

    from sift_mcp.audit import AuditLogger
    logger = AuditLogger(str(audit_path))

    # Write a completed submit_finding audit row for each of the 4
    # specialist-required lanes.
    pairs = [
        ("memory", "memory-analyst"),
        ("disk_execution_persistence", "registry-analyst"),
        ("event_auth", "evtx-analyst"),
        ("timeline_correlation", "mft-analyst"),
    ]
    for lane, agent in pairs:
        eid = logger.next_execution_id()
        params = {
            "case_id": "TEST",
            "lane_id": lane,
            "assigned_agent": agent,
            "finding_type": "ioc",
            "artifact_type": "disk",
            "source_execution_id": "E-001",
        }
        cmd = f"submit_finding(lane={lane!r}, agent={agent!r})"
        logger.log_execution(
            execution_id=eid,
            tool_name="state.submit_finding",
            parameters=params,
            command_line=cmd,
        )
        logger.log_result(
            execution_id=eid,
            exit_code=0,
            duration=0.0,
            outputs_summary="ok",
            finding_ids=["F-001"],
            tool_name="state.submit_finding",
            parameters=params,
            command_line=cmd,
        )

    # Phase 5 gate against the populated audit.jsonl
    from sift_mcp.state import CaseStateManager
    from sift_mcp.reporting import evaluate_investigation_success_gate
    sm = CaseStateManager(state_path=str(analysis_dir / "state.json"))
    sm.load("TEST")
    result = evaluate_investigation_success_gate("TEST", sm)
    assert result["status"] == "ok", (
        f"Phase 5 gate should pass after submit_finding audit rows are present; "
        f"got {result.get('status')} with missing_lanes="
        f"{result.get('missing_lanes')}"
    )


# ---------------------------------------------------------------------------
# Fix #2 — json-repair credits the original lane on repair_succeeded
# ---------------------------------------------------------------------------

@pytest.fixture()
def isolated_ledger(monkeypatch, tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    session_path = tmp_path / "session.json"
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(ledger_path))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(session_path))
    for mod in ("delegation_ledger", "agent_trigger"):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("test-session-fix2")
    return delegation_ledger, ledger_path


def test_json_repair_task_writes_repair_succeeded_with_original_lane(isolated_ledger):
    """review required: when a json-repair Task fires, the repair_succeeded
    ledger row must carry the ORIGINAL lane_id (the lane the specialist
    that truncated belongs to), not '(repair)' or empty.

    Without this, Phase 5's repair_by_lane lookup never credits any lane."""
    ledger, ledger_path = isolated_ledger
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger

    # Build a json-repair Task event whose prompt references the original
    # lane and specialist (this is what _ledger_emit_repair_directive
    # produces — the prompt is templated).
    repair_prompt = (
        "You are the json-repair specialist. The original "
        "@memory-analyst on lane_id='memory' returned prose without a "
        "complete contract JSON. Extract findings..."
    )
    event = {
        "tool_name": "Task",
        "tool_input": {
            "subagent_type": "json-repair",
            "description": "Repair memory lane prose-only outcome",
            "prompt": repair_prompt,
        },
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id": "memory", "status": "COMPLETE_WITH_GAPS", '
                    '"finding_ids": ["F-101"]}'}]},
    }

    agent_trigger.process_event(event)

    rows = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    repair_rows = [r for r in rows if r.get("event") == "repair_succeeded"]
    assert repair_rows, "repair_succeeded ledger row was not written"
    row = repair_rows[0]
    assert row.get("lane_id") == "memory", (
        f"repair_succeeded must carry the ORIGINAL lane_id ('memory'), "
        f"got lane_id={row.get('lane_id')!r}. This is the review 2026-05-22 "
        "Fix #2 bug — without the original lane, the Phase 5 gate's "
        "repair_by_lane lookup can never credit the lane and repair "
        "fallback is dead-code."
    )
    assert row.get("specialist") == "memory-analyst", (
        f"repair_succeeded must carry the ORIGINAL specialist "
        f"('memory-analyst'), got specialist={row.get('specialist')!r}."
    )
    # The repair_actor field distinguishes which agent actually did the work
    assert row.get("repair_actor") == "json-repair" or "repair_actor" in row, (
        "repair_succeeded should record repair_actor='json-repair' so audit "
        "can distinguish original-specialist work from salvage work."
    )


def test_json_repair_falls_back_to_ledger_when_prompt_unparseable(isolated_ledger):
    """When the repair Task prompt doesn't carry the lane reference, the
    handler falls back to walking the ledger for the most recent
    repair_attempted/repair_required row in this session."""
    ledger, ledger_path = isolated_ledger
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger

    # Seed a prior repair_attempted row so the fallback has data
    ledger.append_row(
        "repair_attempted",
        lane_id="event_auth",
        specialist="evtx-analyst",
    )

    # Now fire a json-repair event whose prompt is empty
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "json-repair", "prompt": ""},
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id": "event_auth", "status": "COMPLETE_WITH_GAPS"}'}]},
    }
    agent_trigger.process_event(event)

    rows = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    repair_rows = [r for r in rows if r.get("event") == "repair_succeeded"]
    assert repair_rows
    # The lane should have been recovered from the prior repair_attempted row
    assert repair_rows[0].get("lane_id") == "event_auth"
    assert repair_rows[0].get("specialist") == "evtx-analyst"


def test_repair_succeeded_credits_phase_5_gate_for_lane(tmp_path, isolated_ledger):
    """End-to-end: a json-repair Task that salvages findings for the
    memory lane writes a repair_succeeded ledger row that Phase 5
    counts as fallback coverage for the memory lane."""
    ledger, ledger_path = isolated_ledger
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger

    # Fire the json-repair Task for memory
    event = {
        "tool_name": "Task",
        "tool_input": {
            "subagent_type": "json-repair",
            "prompt": "json-repair for @memory-analyst on lane_id='memory'",
        },
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id": "memory", "status": "COMPLETE_WITH_GAPS"}'}]},
    }
    agent_trigger.process_event(event)

    # Fire the OTHER 3 lanes via direct submit_finding audit rows (Path A)
    analysis_dir = tmp_path / "analysis"
    analysis_dir.mkdir()
    from sift_mcp.audit import AuditLogger
    logger = AuditLogger(str(analysis_dir / "audit.jsonl"))
    for lane, agent in [
        ("disk_execution_persistence", "registry-analyst"),
        ("event_auth", "evtx-analyst"),
        ("timeline_correlation", "mft-analyst"),
    ]:
        eid = logger.next_execution_id()
        params = {"case_id": "TEST", "lane_id": lane, "assigned_agent": agent,
                  "finding_type": "x", "artifact_type": "disk",
                  "source_execution_id": "E-001"}
        cmd = "submit_finding(...)"
        logger.log_execution(eid, "state.submit_finding", params, cmd)
        logger.log_result(eid, 0, 0.0, "ok", ["F-001"],
                          tool_name="state.submit_finding",
                          parameters=params, command_line=cmd)

    # Phase 5 gate
    from sift_mcp.state import CaseStateManager
    from sift_mcp.reporting import evaluate_investigation_success_gate
    sm = CaseStateManager(state_path=str(analysis_dir / "state.json"))
    sm.load("TEST")
    result = evaluate_investigation_success_gate("TEST", sm)
    assert result["status"] == "ok", (
        f"Phase 5 gate should pass: 3 lanes via submit_finding + 1 lane via "
        f"repair_succeeded. Got status={result.get('status')} "
        f"missing={result.get('missing_lanes')}"
    )
    # And the memory lane specifically must show repair_succeeded as the pass reason
    mem = result["lane_contributions"]["memory"]
    assert mem["pass_reason"] == "repair_succeeded_salvage", (
        f"Memory lane should be credited via repair_succeeded_salvage; "
        f"got pass_reason={mem.get('pass_reason')}"
    )
