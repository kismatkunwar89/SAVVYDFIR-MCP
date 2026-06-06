"""Regression tests for the Path B / main-agent gate in workflow-enforce-pre.py.

design review 2026-05-19 (ORIGINAL): the gate wrote machine-countable
decision rows (path_b_would_deny / path_b_would_allow) during dry-run, and
upgraded to actual deny when SAVVYDFIR_LEDGER_ENFORCE=1 was set. Path A
(specialist Task spawn) was treated as mandatory; main-agent inline was
the fallback that required evidence of failed Path A.

W1.6.1a UPDATE 2026-05-23:
The architecture inverted. Main-agent inline is now the PRIMARY path
(Custom MCP Server #2 in the FIND EVIL! hackathon). The pre-hook ALWAYS
allows main-agent lane records through unconditionally; it still LOGS a
`path_b_would_allow` decision row with decision_basis
'main_agent_inline_primary_path_w1.6.1a' for audit.

The 5 tests that asserted would_deny / enforce-mode deny behavior are
OBSOLETE under the new policy. They are marked skip with a clear reason
pointing at the W1.6.1a change. The test that asserts no-decision for
non-specialist lanes still applies (unchanged).
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_W1_6_1A_SKIP = (
    "W1.6.1a (2026-05-23): main-agent inline is the PRIMARY path per "
    "the design plan. The pre-hook no longer denies "
    "main-agent lane records under any condition (always logs would_allow). "
    "The deny / enforce-mode tests below encoded the prior 'Path A mandatory' "
    "architecture and are obsolete. Replacement assertion: any main-agent lane "
    "record always emits path_b_would_allow."
)

ROOT = Path(__file__).resolve().parent.parent
HOOK_PATH = ROOT / ".claude" / "hooks" / "workflow-enforce-pre.py"
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def hook_env(monkeypatch, tmp_path):
    """Isolated ledger + session pointer + workspace dir for the hook."""
    ledger_path = tmp_path / "ledger.jsonl"
    session_path = tmp_path / "session.json"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(ledger_path))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(session_path))
    # Ensure enforce default-off for tests that don't opt in.
    monkeypatch.delenv("SAVVYDFIR_LEDGER_ENFORCE", raising=False)
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger  # noqa: F401
    return {
        "ledger_path": ledger_path,
        "session_path": session_path,
        "workspace": workspace,
        "ledger": delegation_ledger,
    }


def _load_hook_module(name="workflow_enforce_pre"):
    """Load the hook file as an importable module for direct function calls."""
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HOOK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_decision_rows(ledger_path: Path) -> list[dict]:
    if not ledger_path.exists():
        return []
    rows = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("event") in {"path_b_would_allow", "path_b_would_deny", "path_b_denied"}:
            rows.append(obj)
    return rows


def _build_event(lane_id: str, assigned_agent: str, cwd: Path) -> dict:
    return {
        "tool_name": "mcp__savvydfir__record_analysis_lane",
        "tool_input": {
            "case_id": "TEST-CASE",
            "lane_id": lane_id,
            "assigned_agent": assigned_agent,
            "status": "COMPLETE_WITH_GAPS",
        },
        "cwd": str(cwd),
    }


# ---------------------------------------------------------------------------
# Test matrix
# ---------------------------------------------------------------------------

def test_no_decision_when_lane_has_no_specialist(hook_env):
    """Lane without a specialist mapping (e.g. evidence_access) must NOT
    produce a decision row even with main-agent."""
    hook_env["ledger"].write_session_pointer("sess-1")
    hook = _load_hook_module()
    event = _build_event(
        lane_id="evidence_access",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    assert _read_decision_rows(hook_env["ledger_path"]) == []


@pytest.mark.skip(reason=_W1_6_1A_SKIP)
def test_specialist_lane_empty_ledger_emits_would_deny(hook_env):
    """Specialist lane (memory) + main-agent + no ledger evidence → would_deny."""
    hook_env["ledger"].write_session_pointer("sess-2")
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    rows = _read_decision_rows(hook_env["ledger_path"])
    assert any(r["event"] == "path_b_would_deny" for r in rows)
    row = [r for r in rows if r["event"] == "path_b_would_deny"][0]
    assert row["lane_id"] == "memory"
    assert row["specialist"] == "memory-analyst"
    assert "no_failed_task_outcome_for_lane" in row.get("decision_basis", "")


@pytest.mark.skip(reason=_W1_6_1A_SKIP)
def test_failed_outcome_authorizes_path_b(hook_env):
    """Lane with task_outcome=timeout → would_allow row, no deny."""
    hook_env["ledger"].write_session_pointer("sess-3")
    aid = hook_env["ledger"].new_attempt_id()
    hook_env["ledger"].append_row(
        "task_outcome",
        lane_id="memory",
        specialist="memory-analyst",
        attempt_id=aid,
        outcome="timeout",
    )
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    rows = _read_decision_rows(hook_env["ledger_path"])
    assert any(r["event"] == "path_b_would_allow" for r in rows)
    allow_row = [r for r in rows if r["event"] == "path_b_would_allow"][0]
    assert "failed_task_outcome_recorded" in allow_row["decision_basis"]


def test_prose_only_outcome_also_authorizes_path_b(hook_env):
    """prose_only is a failure mode the memory note explicitly documents."""
    hook_env["ledger"].write_session_pointer("sess-4")
    aid = hook_env["ledger"].new_attempt_id()
    hook_env["ledger"].append_row(
        "task_outcome",
        lane_id="memory",
        specialist="memory-analyst",
        attempt_id=aid,
        outcome="prose_only",
    )
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    rows = _read_decision_rows(hook_env["ledger_path"])
    assert any(r["event"] == "path_b_would_allow" for r in rows)


@pytest.mark.skip(reason=_W1_6_1A_SKIP)
def test_cross_session_outcome_does_not_authorize(hook_env):
    """A task_outcome=timeout written in a different session must NOT
    authorize Path B for the current session."""
    # Yesterday's session
    hook_env["ledger"].write_session_pointer("sess-OLD")
    aid_old = hook_env["ledger"].new_attempt_id()
    hook_env["ledger"].append_row(
        "task_outcome",
        lane_id="memory",
        specialist="memory-analyst",
        attempt_id=aid_old,
        outcome="timeout",
    )
    # Switch to today
    hook_env["ledger"].write_session_pointer("sess-NEW")
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    rows = _read_decision_rows(hook_env["ledger_path"])
    # Only the would_deny from the CURRENT session should be visible.
    decisions_for_current = [r for r in rows if r.get("session_id") == "sess-NEW"]
    assert any(r["event"] == "path_b_would_deny" for r in decisions_for_current), (
        "Yesterday's timeout MUST NOT authorize today's Path B. Gate must emit "
        "would_deny in the new session."
    )


@pytest.mark.skip(reason=_W1_6_1A_SKIP)
def test_unavailable_session_marker_authorizes_all_specialist_lanes(hook_env):
    """task_unavailable_session marker → all specialist lanes allowed."""
    hook_env["ledger"].write_session_pointer("sess-NOTASK")
    hook_env["ledger"].append_row(
        "task_unavailable_session",
        decision_basis="Agent not in allow list",
    )
    hook = _load_hook_module()
    for lane in ("memory", "disk_execution_persistence", "event_auth", "timeline_correlation"):
        event = _build_event(lane_id=lane, assigned_agent="main-agent", cwd=hook_env["workspace"])
        hook._check_path_b_gate(event, ROOT)

    rows = _read_decision_rows(hook_env["ledger_path"])
    allow_rows = [r for r in rows if r["event"] == "path_b_would_allow"]
    assert {r["lane_id"] for r in allow_rows} >= {
        "memory", "disk_execution_persistence", "event_auth", "timeline_correlation",
    }
    for r in allow_rows:
        assert "task_unavailable_session_marker" in r["decision_basis"]


def test_dry_run_does_not_deny(hook_env, capsys):
    """Phase 3b (default): even when would_deny fires, no deny is emitted."""
    hook_env["ledger"].write_session_pointer("sess-DRY")
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    captured = capsys.readouterr()
    # The hook only prints when it denies — in dry-run there should be no output.
    assert "deny" not in captured.out.lower(), (
        "Dry-run must NOT emit a deny. Got stdout: " + captured.out
    )


@pytest.mark.skip(reason=_W1_6_1A_SKIP)
def test_enforce_mode_denies_with_structured_reason(hook_env, monkeypatch, capsys):
    """Phase 3c (SAVVYDFIR_LEDGER_ENFORCE=1): the gate denies with a
    structured reason AND writes a path_b_denied ledger row."""
    monkeypatch.setenv("SAVVYDFIR_LEDGER_ENFORCE", "1")
    hook_env["ledger"].write_session_pointer("sess-ENF")
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="main-agent",
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
    assert "memory-analyst" in reason
    assert "SAVVYDFIR_LEDGER_ENFORCE" in reason
    assert "decision_basis" in reason

    rows = _read_decision_rows(hook_env["ledger_path"])
    assert any(r["event"] == "path_b_denied" for r in rows)


def test_subagent_assigned_lane_skips_gate(hook_env, capsys):
    """If assigned_agent is the specialist itself (Path A success),
    the gate must NOT fire."""
    hook_env["ledger"].write_session_pointer("sess-PATHA")
    hook = _load_hook_module()
    event = _build_event(
        lane_id="memory",
        assigned_agent="memory-analyst",  # Path A
        cwd=hook_env["workspace"],
    )
    hook._check_path_b_gate(event, ROOT)
    rows = _read_decision_rows(hook_env["ledger_path"])
    assert rows == [], (
        "Gate must only fire when assigned_agent='main-agent'. "
        f"Path A (specialist) lane completion got decision rows: {rows}"
    )


def test_enforce_disabled_default(hook_env):
    """SAVVYDFIR_LEDGER_ENFORCE is OFF by default."""
    hook = _load_hook_module()
    assert hook._ledger_enforce_active() is False


def test_enforce_env_var_truthy_values(hook_env, monkeypatch):
    """The enforce flag accepts 1/true/yes/on."""
    hook = _load_hook_module()
    for val in ("1", "true", "yes", "on", "TRUE", "Yes"):
        monkeypatch.setenv("SAVVYDFIR_LEDGER_ENFORCE", val)
        assert hook._ledger_enforce_active() is True, f"Should accept {val!r}"
    monkeypatch.setenv("SAVVYDFIR_LEDGER_ENFORCE", "0")
    assert hook._ledger_enforce_active() is False
    monkeypatch.setenv("SAVVYDFIR_LEDGER_ENFORCE", "")
    assert hook._ledger_enforce_active() is False
