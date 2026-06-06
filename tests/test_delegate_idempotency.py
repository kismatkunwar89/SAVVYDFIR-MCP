"""Regression tests for Tier-B2: delegate idempotency + allow_partial hint.

design review 2026-05-19: an identical record_analysis_lane upsert must
return `duplicate_lane_noop` instead of re-firing _dispatch_corroboration_if_ready
(which regenerates the very delegate that blocked the report — Run-10 had
13 redundant lane writes in one investigation).

Also: needs_coverage / needs_delegate deny messages must surface the
allow_partial=True escape hatch so the agent isn't stuck in a loop.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_record_analysis_lane_short_circuit_for_duplicate_complete():
    """Source-text guard: record_analysis_lane must short-circuit when the
    incoming COMPLETE→COMPLETE upsert is identical (same status, same
    assigned_agent, same execution_ids, same finding_ids)."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def record_analysis_lane(")
    assert func_idx > 0
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 30000]

    assert "duplicate_lane_noop" in body, (
        "record_analysis_lane must return 'duplicate_lane_noop' status when "
        "the upsert is a no-op — that's the Tier-B2 idempotency fix that "
        "prevents corroboration-delegate regeneration."
    )
    # The short-circuit must happen BEFORE _audit_logger.next_execution_id()
    # (so we don't burn an execution ID on a no-op).
    noop_idx = body.find("duplicate_lane_noop")
    audit_idx = body.find("_audit_logger.next_execution_id()")
    assert 0 < noop_idx < audit_idx, (
        "duplicate_lane_noop short-circuit must fire BEFORE allocating an "
        "audit execution_id (lane no-ops shouldn't burn IDs)."
    )


def test_record_analysis_lane_compares_full_state():
    """The duplicate check must compare status AND assigned_agent AND
    execution_ids AND finding_ids — not just status alone (otherwise a
    real lane progression with new finding_ids would be falsely deduped)."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def record_analysis_lane(")
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 30000]

    # Find the duplicate-detection condition
    noop_idx = body.find("duplicate_lane_noop")
    # Slice ~1500 chars before the return to inspect the guard
    guard_block = body[max(0, noop_idx - 1500):noop_idx]
    for field in ("status", "assigned_agent", "execution_ids", "finding_ids"):
        assert field in guard_block, (
            f"Duplicate check must compare {field}. Without comparing all 4 "
            f"keys, real lane progressions (e.g., new findings added) get "
            f"falsely deduped."
        )


def test_needs_delegate_deny_message_includes_allow_partial_hint():
    """When generate_report returns needs_delegate, the response must
    surface allow_partial=True as an escape hatch — preventing the
    agent from looping on a stuck delegate."""
    src = (ROOT / "sift_mcp" / "reporting.py").read_text()
    needs_idx = src.find('"status": "needs_delegate"')
    assert needs_idx > 0
    # Slice the next 800 chars (the response dict body)
    block = src[needs_idx:needs_idx + 1500]
    assert "allow_partial" in block.lower(), (
        "needs_delegate deny message must mention allow_partial=True per "
        "review Tier-B2 review."
    )
    assert "allow_partial_hint" in block, (
        "Response dict must carry 'allow_partial_hint': True so the agent "
        "(and any hooks) can detect the escape hatch programmatically."
    )


def test_needs_coverage_deny_message_includes_allow_partial_hint():
    """Same allow_partial=True hint for needs_coverage."""
    src = (ROOT / "sift_mcp" / "reporting.py").read_text()
    needs_idx = src.find('"status": "needs_coverage"')
    assert needs_idx > 0
    block = src[needs_idx:needs_idx + 1500]
    assert "allow_partial" in block.lower()
    assert "allow_partial_hint" in block


def test_court_defensibility_warning_in_allow_partial_hints():
    """The hint must explicitly warn that allow_partial reports are NOT
    court-defensible — preventing operators from accepting them silently
    as final outputs."""
    src = (ROOT / "sift_mcp" / "reporting.py").read_text()
    needs_delegate_idx = src.find('"status": "needs_delegate"')
    needs_coverage_idx = src.find('"status": "needs_coverage"')
    for idx, label in ((needs_delegate_idx, "needs_delegate"),
                       (needs_coverage_idx, "needs_coverage")):
        block = src[idx:idx + 2000]
        assert "court" in block.lower() or "defensible" in block.lower(), (
            f"{label} deny message must warn that partial reports are NOT "
            f"court-defensible. Otherwise operators may accept allow_partial "
            f"reports as final outputs."
        )
