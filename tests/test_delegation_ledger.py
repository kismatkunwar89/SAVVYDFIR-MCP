"""Regression tests for the Phase 3a delegation ledger (observation-only).

peer reviewer consensus 2026-05-19 ITEM-2/ITEM-3: the ledger is the hook-owned
source of truth for Path A / Path B authorization. Phase 3a writes only —
no enforcement yet. These tests prove the writers produce the right
rows under each event scenario and the read primitives respect session
isolation.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def isolated_ledger(monkeypatch, tmp_path):
    """Redirect the ledger + session pointer to a temp directory."""
    ledger_path = tmp_path / "ledger.jsonl"
    session_path = tmp_path / "session.json"
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(ledger_path))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(session_path))
    # Force re-import so env vars take effect.
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger  # noqa: F401
    return delegation_ledger


def _read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# Schema / write tests
# ---------------------------------------------------------------------------

def test_append_row_requires_session_id(isolated_ledger):
    """A row without a resolvable session_id MUST NOT be appended."""
    # No session pointer written yet.
    result = isolated_ledger.append_row(
        "delegation_required",
        lane_id="memory",
        specialist="memory-analyst",
    )
    assert result is None, (
        "append_row must refuse to write when session_id cannot be resolved. "
        "Otherwise the row cannot authorize anything (no session linkage)."
    )
    assert not isolated_ledger.LEDGER_PATH.exists() or _read_rows(isolated_ledger.LEDGER_PATH) == []


def test_session_pointer_then_append(isolated_ledger):
    """After write_session_pointer, append_row inherits the session_id."""
    isolated_ledger.write_session_pointer("sess-AAA")
    row = isolated_ledger.append_row(
        "delegation_required",
        lane_id="memory",
        specialist="memory-analyst",
        tool="mcp__savvydfir__list_dlls",
    )
    assert row is not None
    assert row["session_id"] == "sess-AAA"
    assert row["event"] == "delegation_required"
    assert row["lane_id"] == "memory"
    assert row["specialist"] == "memory-analyst"
    assert row["tool"] == "mcp__savvydfir__list_dlls"


def test_append_rejects_unknown_event(isolated_ledger):
    """Phase 3a only knows specific event names — typos must not silently land."""
    isolated_ledger.write_session_pointer("sess-AAA")
    assert isolated_ledger.append_row(
        "completely_made_up_event",
        lane_id="memory",
        specialist="memory-analyst",
    ) is None


def test_read_session_rows_filters_cross_session_contamination(isolated_ledger):
    """Yesterday's rows must NOT appear when reading today's session."""
    # Yesterday's session
    isolated_ledger.write_session_pointer("sess-YESTERDAY")
    aid_y = isolated_ledger.new_attempt_id()
    isolated_ledger.append_row(
        "task_outcome", lane_id="memory", specialist="memory-analyst",
        attempt_id=aid_y, outcome="timeout", excerpt="yesterday timeout",
    )
    # New session today
    isolated_ledger.write_session_pointer("sess-TODAY")
    aid_t = isolated_ledger.new_attempt_id()
    isolated_ledger.append_row(
        "task_attempt", lane_id="memory", specialist="memory-analyst",
        attempt_id=aid_t,
    )

    # Reading TODAY's session must NOT see yesterday's rows.
    rows = isolated_ledger.read_session_rows()
    sids = {r.get("session_id") for r in rows}
    assert sids == {"sess-TODAY"}, (
        f"Cross-session contamination! got session_ids={sids}. "
        "Yesterday's timeout must not authorize today's Path B."
    )


def test_has_failed_task_outcome_session_scoped(isolated_ledger):
    """has_failed_task_outcome must only see the current session's outcomes."""
    isolated_ledger.write_session_pointer("sess-OLD")
    aid_old = isolated_ledger.new_attempt_id()
    isolated_ledger.append_row(
        "task_outcome", lane_id="memory", specialist="memory-analyst",
        attempt_id=aid_old, outcome="timeout",
    )
    # Old session: returns True.
    assert isolated_ledger.has_failed_task_outcome("memory") is True

    # Roll to a fresh session — that timeout MUST NOT authorize Path B now.
    isolated_ledger.write_session_pointer("sess-NEW")
    assert isolated_ledger.has_failed_task_outcome("memory") is False, (
        "Cross-session timeout leaked into a new session. "
        "Path B authorization must NOT be inherited across sessions."
    )


def test_has_unavailable_marker_session_scoped(isolated_ledger):
    """task_unavailable_session is also session-scoped."""
    isolated_ledger.write_session_pointer("sess-NOTASK")
    isolated_ledger.append_row(
        "task_unavailable_session",
        decision_basis="Agent not in allow list",
    )
    assert isolated_ledger.has_unavailable_marker() is True

    isolated_ledger.write_session_pointer("sess-HASTASK")
    assert isolated_ledger.has_unavailable_marker() is False


# ---------------------------------------------------------------------------
# agent_trigger Task-event integration tests
# ---------------------------------------------------------------------------

def _import_agent_trigger():
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger
    return agent_trigger


def test_task_event_handler_writes_attempt_and_outcome(isolated_ledger):
    """A PostToolUse Task event with a successful subagent JSON return
    must produce one task_attempt + one task_outcome row with outcome=success."""
    isolated_ledger.write_session_pointer("sess-T1")
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {
            "subagent_type": "memory-analyst",
            "description": "Analyze memory lane",
            "prompt": "...",
        },
        "tool_response": {
            "content": [
                {"type": "text",
                 "text": '```json\n{"lane_id": "memory", "status": "COMPLETE", '
                         '"finding_ids": ["F-001"]}\n```'}
            ]
        },
    }
    result = at.process_event(event)
    # Task events are observation-only; process_event must NOT return a decision.
    assert result is None

    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    events = [r["event"] for r in rows]
    assert "task_attempt" in events and "task_outcome" in events
    outcome_row = [r for r in rows if r["event"] == "task_outcome"][0]
    assert outcome_row["outcome"] == "success"
    assert outcome_row["lane_id"] == "memory"
    assert outcome_row["specialist"] == "memory-analyst"
    # attempt_id must match between attempt and outcome
    attempt_row = [r for r in rows if r["event"] == "task_attempt"][0]
    assert attempt_row["attempt_id"] == outcome_row["attempt_id"]


def test_task_event_prose_only_classified_correctly(isolated_ledger):
    """A Task that returns only prose (no JSON object) gets outcome=prose_only."""
    isolated_ledger.write_session_pointer("sess-T2")
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "evtx-analyst"},
        "tool_response": {
            "content": [{"type": "text",
                         "text": "I analyzed the EVTX logs and found suspicious activity."}]
        },
    }
    at.process_event(event)
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    outcome_rows = [r for r in rows if r["event"] == "task_outcome"]
    assert outcome_rows and outcome_rows[0]["outcome"] == "prose_only"


def test_task_event_timeout_classified_correctly(isolated_ledger):
    """An empty Task return → outcome=timeout."""
    isolated_ledger.write_session_pointer("sess-T3")
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "prefetch-analyst"},
        "tool_response": {"content": []},
    }
    at.process_event(event)
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    outcome_rows = [r for r in rows if r["event"] == "task_outcome"]
    assert outcome_rows and outcome_rows[0]["outcome"] == "timeout"


def test_task_event_malformed_json_classified_correctly(isolated_ledger):
    """A response with broken JSON inside braces → outcome=malformed_json."""
    isolated_ledger.write_session_pointer("sess-T4")
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "mft-analyst"},
        "tool_response": {
            "content": [{"type": "text",
                         "text": '{"lane_id": "memory", "broken: yes }'}]
        },
    }
    at.process_event(event)
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    outcome_rows = [r for r in rows if r["event"] == "task_outcome"]
    assert outcome_rows and outcome_rows[0]["outcome"] == "malformed_json"


def test_task_event_for_non_specialist_subagent_ignored(isolated_ledger):
    """If the Task fires with a subagent not in our specialist map
    (e.g. a code-review agent), it must NOT write ledger rows."""
    isolated_ledger.write_session_pointer("sess-T5")
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "some-other-agent"},
        "tool_response": {"content": [{"type": "text", "text": "{}"}]},
    }
    at.process_event(event)
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    assert rows == [], (
        f"Non-specialist subagent should not write ledger rows. Got: {rows}"
    )


def test_mcp_tool_event_writes_delegation_required(isolated_ledger):
    """When the trigger gets queued for a heavy MCP tool, the ledger
    gets a delegation_required row."""
    isolated_ledger.write_session_pointer("sess-D1")
    at = _import_agent_trigger()
    event = {
        "tool_name": "mcp__savvydfir__list_dlls",
        "tool_input": {"case_id": "T", "pid": 1234},
        "tool_response": {
            "content": [
                {"type": "text",
                 "text": '{"status": "ok", "csv_path": "/tmp/x.csv", "records_count": 80}'}
            ]
        },
    }
    # Use a temp delegate-queue path so we don't pollute the real one.
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        trigger_path = tmp.name
    try:
        at.process_event(event, trigger_path=trigger_path)
        rows = _read_rows(isolated_ledger.LEDGER_PATH)
        delegation_rows = [r for r in rows if r["event"] == "delegation_required"]
        assert delegation_rows, "delegation_required row must be written"
        d = delegation_rows[0]
        assert d["lane_id"] == "memory"
        assert d["specialist"] == "memory-analyst"
        assert "list_dlls" in d.get("tool", "")
    finally:
        try:
            os.unlink(trigger_path)
        except FileNotFoundError:
            pass


def test_session_pointer_atomic_replace(isolated_ledger, tmp_path):
    """write_session_pointer must not leave partial-write garbage if interrupted."""
    isolated_ledger.write_session_pointer("sess-X")
    data = json.loads(isolated_ledger.SESSION_POINTER_PATH.read_text())
    assert data["session_id"] == "sess-X"
    # Overwrite with new session
    isolated_ledger.write_session_pointer("sess-Y", cwd="/another/path")
    data = json.loads(isolated_ledger.SESSION_POINTER_PATH.read_text())
    assert data["session_id"] == "sess-Y"
    assert data["cwd"] == "/another/path"


def test_post_tool_use_refreshes_stale_session_pointer(isolated_ledger):
    """2026-05-20 fix: claude -p one-shot mode skips SessionStart, leaving
    a stale pointer across runs. agent_trigger's PostToolUse path must
    detect the mismatch and refresh the pointer from the event's session_id."""
    # Seed a stale pointer (simulating yesterday's session)
    isolated_ledger.write_session_pointer("stale-yesterday-session")
    at = _import_agent_trigger()

    # Today's event carries a fresh session_id — the hook must pick it up.
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id":"memory","status":"COMPLETE"}'}]},
        "session_id": "fresh-today-session",
        "cwd": "/opt/SAVVYDFIR-MCP",
    }
    at.process_event(event)

    # Pointer must now reflect the new session_id
    current = isolated_ledger.read_current_session_id()
    assert current == "fresh-today-session", (
        f"Stale pointer was not refreshed by PostToolUse event. "
        f"current={current!r}, expected 'fresh-today-session'. "
        "This is the Run-12 regression where SessionStart didn't fire."
    )


def test_post_tool_use_no_refresh_when_already_current(isolated_ledger):
    """If the pointer already matches the event's session_id, no rewrite."""
    isolated_ledger.write_session_pointer("matching-session")
    pointer_path = isolated_ledger.SESSION_POINTER_PATH
    mtime_before = pointer_path.stat().st_mtime
    import time; time.sleep(0.05)
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text", "text": "{}"}]},
        "session_id": "matching-session",
        "cwd": "/x",
    }
    at.process_event(event)
    # mtime should be unchanged because we don't rewrite when matched
    mtime_after = pointer_path.stat().st_mtime
    assert mtime_before == mtime_after, (
        "Session pointer was rewritten despite session_id already matching. "
        "Refresh should be a no-op when current."
    )


def test_post_tool_use_ignores_empty_session_id(isolated_ledger):
    """If the event has no session_id, don't clobber the existing pointer."""
    isolated_ledger.write_session_pointer("real-session")
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text", "text": "{}"}]},
        # NO session_id
    }
    at.process_event(event)
    assert isolated_ledger.read_current_session_id() == "real-session"
