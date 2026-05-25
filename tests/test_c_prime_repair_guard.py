"""Regression tests for C-PRIME (peer reviewer consensus 2026-05-20 final round).

C-PRIME has two coupled pieces:
  1. Prompt tweak at top of every specialist .md — "re-emit JSON after every
     run_analysis call; stop when you have evidence-backed findings, not when
     you've covered every header."
  2. Repair guard: PostToolUse hook detects prose_only/malformed_json outcomes
     on specialist Task events, writes repair_required ledger row, emits a
     non-blocking hookSpecificOutput directing the parent to spawn ONE
     json-repair Task with the raw failed response in the prompt.

Idempotency, recursion suppression, and outcome distinction (success vs
success_with_gaps) are tested here.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def isolated_ledger(monkeypatch, tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    session_path = tmp_path / "session.json"
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(ledger_path))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(session_path))
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("c-prime-test-session")
    return delegation_ledger


def _import_agent_trigger():
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger
    return agent_trigger


def _read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# Step 1 — Prompt tweak presence in every specialist .md
# ---------------------------------------------------------------------------

@pytest.mark.skip(
    reason=(
        "W1.2 (2026-05-23, PLAN-FIND-EVIL-HACKATHON-2026-05-23.md): "
        "C-PRIME Output Discipline block was stripped from specialist "
        ".md files as part of the Phase 3 overlay removal. The user's "
        "original heuristic content (line 200+ of each file) is preserved "
        "and is now framed as 'reference knowledge, not procedural playbook.' "
        "See DECISION-2026-05-23-branch-triage.md Section 5.3. "
        "If C-PRIME-style persistence discipline returns, replace this "
        "test with one that checks the new structure (e.g., section "
        "'How this file is used' is present)."
    )
)
@pytest.mark.parametrize("specialist", [
    "amcache-analyst", "browser-analyst", "corroboration-analyst",
    "evtx-analyst", "memory-analyst", "mft-analyst",
    "prefetch-analyst", "registry-analyst", "sigma-analyst",
    "srum-analyst", "timeline-analyst",
])
def test_specialist_has_c_prime_tweak(specialist):
    """C-PRIME revised wording (peer reviewer 2026-05-21): persist-first via
    add_finding(), evidence-gated, pivot-scoped. Replaces the prior
    'do not chase additional pivots' clause that caused Run-13's
    zero-CONFIRMED regression.

    SKIPPED 2026-05-23 per W1 plan — see decorator reason."""
    path = ROOT / ".claude" / "agents" / f"{specialist}.md"
    text = path.read_text(encoding="utf-8")
    assert "C-PRIME Output Discipline" in text, (
        f"{specialist}: missing C-PRIME tweak block at top of file"
    )
    # Persist-first directive (NEW — required after Run-13 regression)
    assert "call `add_finding()` **BEFORE doing any further narration" in text, (
        f"{specialist}: tweak missing the persist-first add_finding directive"
    )
    # Evidence-gated registration
    assert "Do not register raw tool hits, bulk Sigma matches, or isolated IOCs" in text, (
        f"{specialist}: tweak missing the evidence-gating clause"
    )
    # Description contract
    assert "what was observed, why it matters" in text, (
        f"{specialist}: tweak missing the add_finding description contract"
    )
    # Pivot-scoped guidance
    assert "pivots that can strengthen, validate, scope, or disprove" in text, (
        f"{specialist}: tweak missing the persistence-scoped pivot rule"
    )
    # peer reviewer attribution
    assert "peer reviewer consensus 2026-05-21" in text, (
        f"{specialist}: tweak missing revision attribution"
    )
    # OLD reductive language MUST BE GONE
    assert "do not chase additional pivots unless they are necessary" not in text, (
        f"{specialist}: OLD reductive language still present — this caused "
        "Run-13's zero-CONFIRMED regression"
    )
    assert "stop once you have evidence-backed findings" not in text, (
        f"{specialist}: OLD 'stop once' language still present"
    )


def test_json_repair_agent_does_not_have_tweak():
    """json-repair must NOT get the C-PRIME tweak — it's a transcription
    agent, not a specialist. Including the tweak would confuse its role."""
    path = ROOT / ".claude" / "agents" / "json-repair.md"
    assert path.exists()
    assert "C-PRIME Output Discipline" not in path.read_text()


def test_json_repair_agent_is_tool_less():
    """The repair agent MUST be declared with empty tools to enforce
    transcription-only containment per peer reviewer."""
    path = ROOT / ".claude" / "agents" / "json-repair.md"
    text = path.read_text()
    # Check the YAML frontmatter
    assert "tools: []" in text, "json-repair must declare tools: [] (no tools)"


# ---------------------------------------------------------------------------
# Step 2 — Classifier prefers LAST contract-shaped JSON
# ---------------------------------------------------------------------------

def test_classifier_picks_last_contract_json_when_multiple_present():
    """When a specialist emits two JSON objects (interim + final per the
    tweak), the classifier must read the LAST one."""
    at = _import_agent_trigger()
    response = (
        "Schema discovery complete. Initial findings recorded.\n"
        '{"lane_id": "memory", "status": "COMPLETE_WITH_GAPS", "finding_ids": ["F-001"]}\n'
        "Doing one more pivot for injection check.\n"
        "Found a second indicator.\n"
        '{"lane_id": "memory", "status": "COMPLETE", "finding_ids": ["F-001", "F-002"]}'
    )
    outcome, _ = at._ledger_classify_task_outcome(response)
    # Must be "success" (last status=COMPLETE), NOT "success_with_gaps"
    # (would be wrong — that's the FIRST JSON's status).
    assert outcome == "success", (
        f"Classifier read the first JSON instead of the last. Got {outcome!r}."
    )


def test_classifier_returns_success_with_gaps_when_status_is_gaps():
    at = _import_agent_trigger()
    response = (
        "Quick pass complete.\n"
        '{"lane_id": "memory", "status": "COMPLETE_WITH_GAPS", "finding_ids": ["F-001"]}'
    )
    outcome, _ = at._ledger_classify_task_outcome(response)
    assert outcome == "success_with_gaps"


def test_classifier_returns_success_when_status_is_complete():
    at = _import_agent_trigger()
    response = '{"lane_id": "memory", "status": "COMPLETE", "finding_ids": ["F-001"]}'
    outcome, _ = at._ledger_classify_task_outcome(response)
    assert outcome == "success"


def test_classifier_rejects_incidental_braced_text():
    """Incidental dict-shaped fragments in prose must NOT be misclassified
    as a contract JSON. The outcome is either prose_only or malformed_json
    (both trigger repair); the critical thing is that it's NOT success."""
    at = _import_agent_trigger()
    response = (
        "I ran a query and got back {'pid': 1234, 'name': 'svchost'}.\n"
        "Now looking at process injection. This appears suspicious."
    )
    outcome, _ = at._ledger_classify_task_outcome(response)
    assert outcome in {"prose_only", "malformed_json"}, (
        f"Incidental braced fragments must NOT be classified as success. "
        f"Got {outcome!r}. Both prose_only and malformed_json correctly "
        f"trigger the repair guard; success would silently bypass it."
    )
    assert outcome != "success"
    assert outcome != "success_with_gaps"


def test_classifier_requires_lane_id_AND_status_or_finding_ids():
    at = _import_agent_trigger()
    # Has lane_id but neither status nor finding_ids — should NOT count
    response = '{"lane_id": "memory", "other_key": "value"}'
    outcome, _ = at._ledger_classify_task_outcome(response)
    assert outcome != "success"
    assert outcome != "success_with_gaps"


def test_classifier_handles_nested_braces_in_contract():
    """Top-level brace parser must handle nested data_gaps lists with
    {"gap": "...", "severity": "..."} entries without breaking."""
    at = _import_agent_trigger()
    response = (
        '{"lane_id": "memory", "status": "COMPLETE", '
        '"finding_ids": ["F-001"], '
        '"data_gaps": [{"gap": "x", "severity": "LOW"}, {"gap": "y", "severity": "MEDIUM"}]}'
    )
    outcome, _ = at._ledger_classify_task_outcome(response)
    assert outcome == "success"


# ---------------------------------------------------------------------------
# Step 5/6 — Repair guard wiring
# ---------------------------------------------------------------------------

def test_prose_only_outcome_emits_repair_directive(isolated_ledger):
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text",
            "text": "Both findings registered. Now let me check..."}]},
    }
    result = at.process_event(event)
    assert isinstance(result, dict), "Repair directive must be returned as hook dict"
    payload = result.get("hookSpecificOutput") or {}
    assert payload.get("hookEventName") == "PostToolUse"
    ctx = payload.get("additionalContext") or ""
    assert "C-PRIME REPAIR DIRECTIVE" in ctx
    assert "json-repair" in ctx
    assert "memory-analyst" in ctx
    # Raw response excerpt must be included so the repair Task has context
    assert "Both findings registered" in ctx

    # Ledger gains repair_required row
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    events = [r["event"] for r in rows]
    assert "repair_required" in events


def test_clean_success_does_not_emit_repair_directive(isolated_ledger):
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id": "memory", "status": "COMPLETE", "finding_ids": ["F-001"]}'}]},
    }
    result = at.process_event(event)
    # No directive returned — clean success
    assert result is None or "additionalContext" not in (result.get("hookSpecificOutput") or {})

    # Ledger must NOT have repair_required
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    events = [r["event"] for r in rows]
    assert "repair_required" not in events


def test_success_with_gaps_does_not_emit_repair_directive(isolated_ledger):
    """COMPLETE_WITH_GAPS is success — it should NOT trigger a repair retry."""
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id": "memory", "status": "COMPLETE_WITH_GAPS", "finding_ids": ["F-001"]}'}]},
    }
    result = at.process_event(event)
    assert result is None or "additionalContext" not in (result.get("hookSpecificOutput") or {})
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    assert "repair_required" not in [r["event"] for r in rows]


def test_repair_directive_is_idempotent(isolated_ledger):
    """A second prose_only on the same lane+specialist should NOT re-emit
    the directive if repair_attempted has already been recorded."""
    at = _import_agent_trigger()

    # First prose-only event → emits directive
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "memory-analyst"},
        "tool_response": {"content": [{"type": "text",
            "text": "Both findings registered. Now let me check..."}]},
    }
    first = at.process_event(event)
    assert first is not None  # directive emitted

    # Mark the repair as attempted (simulating parent spawning json-repair)
    at._ledger_mark_repair_attempted("memory", "memory-analyst")

    # Second prose-only event for same lane+specialist → directive suppressed
    second = at.process_event(event)
    if second is not None:
        ctx = (second.get("hookSpecificOutput") or {}).get("additionalContext", "")
        assert "C-PRIME REPAIR DIRECTIVE" not in ctx, (
            "Repair directive must be suppressed once repair_attempted is logged"
        )


def test_json_repair_task_does_not_recursively_trigger_repair(isolated_ledger):
    """A prose_only outcome on a json-repair Task itself must NOT cause
    another repair directive. Anti-recursion guard."""
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "json-repair"},
        "tool_response": {"content": [{"type": "text",
            "text": "Sorry, I couldn't extract anything from the prose."}]},
    }
    result = at.process_event(event)
    # Either None or no repair directive
    if result is not None:
        ctx = (result.get("hookSpecificOutput") or {}).get("additionalContext", "")
        assert "C-PRIME REPAIR DIRECTIVE" not in ctx, (
            "json-repair must not recursively trigger another repair"
        )
    # Ledger should have repair_failed, not repair_required
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    events = [r["event"] for r in rows]
    assert "repair_required" not in events
    assert "repair_failed" in events


def test_json_repair_success_writes_repair_succeeded(isolated_ledger):
    at = _import_agent_trigger()
    event = {
        "tool_name": "Task",
        "tool_input": {"subagent_type": "json-repair"},
        "tool_response": {"content": [{"type": "text",
            "text": '{"lane_id": "memory", "status": "COMPLETE_WITH_GAPS", "finding_ids": ["F-001"]}'}]},
    }
    at.process_event(event)
    rows = _read_rows(isolated_ledger.LEDGER_PATH)
    events = [r["event"] for r in rows]
    assert "repair_succeeded" in events


def test_ledger_has_all_c_prime_events():
    """delegation_ledger must accept the 4 new C-PRIME events."""
    if "delegation_ledger" in sys.modules:
        del sys.modules["delegation_ledger"]
    import delegation_ledger
    expected = {"repair_required", "repair_attempted",
                "repair_succeeded", "repair_failed"}
    assert expected.issubset(delegation_ledger.VALID_EVENTS), (
        f"VALID_EVENTS missing: {expected - delegation_ledger.VALID_EVENTS}"
    )


def test_delegate_queue_has_repair_count_field():
    """Schema migration backfills repair_count alongside retry_count."""
    if "delegate_queue" in sys.modules:
        del sys.modules["delegate_queue"]
    import delegate_queue
    legacy = {"subagent_type": "memory-analyst", "case_id": "X",
              "lane_id": "memory", "processed": False}
    migrated = delegate_queue._migrate_legacy_delegate(legacy)
    assert "repair_count" in migrated
    assert migrated["repair_count"] == 0
