"""Regression tests for Phase 4 — synthesis-analyst + synthesis_corroboration lane.

design review 2026-05-22: cross-artifact creative reasoning gets its OWN
lane so artifact-specialist completion of timeline_correlation doesn't
silently close the dispatcher's check.

Critical invariants:
  1. synthesis_corroboration is a valid lane in EXPECTED_LANE_AGENTS.
  2. synthesis-analyst is the primary expected agent for that lane.
  3. .claude/agents/synthesis-analyst.md exists.
  4. _CORROBORATION_PREREQ_LANES includes timeline_correlation (review required).
  5. Dispatcher checks synthesis_corroboration status, NOT timeline_correlation.
  6. record_analysis_lane no longer skips dispatch on timeline_correlation.
  7. _SYNTHESIS_LANE_ID and _SYNTHESIS_SPECIALIST constants exist.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Lane spec
# ---------------------------------------------------------------------------

def test_synthesis_corroboration_lane_in_expected_agents():
    from sift_mcp.reporting import EXPECTED_LANE_AGENTS
    assert "synthesis_corroboration" in EXPECTED_LANE_AGENTS, (
        "synthesis_corroboration lane is missing from EXPECTED_LANE_AGENTS — "
        "Phase 4 lane migration incomplete."
    )
    expected_agents = EXPECTED_LANE_AGENTS["synthesis_corroboration"]
    assert "synthesis-analyst" in expected_agents, (
        f"synthesis-analyst not in expected agents for synthesis_corroboration; "
        f"got: {expected_agents}"
    )


def test_synthesis_analyst_md_file_exists():
    path = ROOT / ".claude" / "agents" / "synthesis-analyst.md"
    assert path.is_file(), (
        "Phase 4 requires .claude/agents/synthesis-analyst.md to exist."
    )
    text = path.read_text(encoding="utf-8")
    # Frontmatter has correct name
    assert "name: synthesis-analyst" in text
    # Has the C-PRIME persistence discipline (carried over from Phase 1/2)
    assert "C-PRIME Output Discipline" in text
    # Owns the synthesis_corroboration lane
    assert "synthesis_corroboration" in text
    # References the typed submit_finding tool (Phase 1)
    assert "submit_finding" in text


def test_synthesis_analyst_inherits_assigned_agent_constraint():
    """review required: synthesis-analyst sets assigned_agent='synthesis-analyst'
    on submit_finding calls (Phase 5 audits per-specialist provenance)."""
    text = (ROOT / ".claude" / "agents" / "synthesis-analyst.md").read_text(encoding="utf-8")
    assert "assigned_agent='synthesis-analyst'" in text or "'synthesis-analyst'" in text, (
        "synthesis-analyst.md must instruct calls to use assigned_agent='synthesis-analyst'."
    )


# ---------------------------------------------------------------------------
# Dispatcher constants
# ---------------------------------------------------------------------------

def test_corroboration_prereqs_include_timeline_correlation():
    """review required: timeline_correlation is now a prereq for synthesis,
    not the lane synthesis runs into."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    # Find the _CORROBORATION_PREREQ_LANES definition
    match = re.search(
        r"_CORROBORATION_PREREQ_LANES\s*=\s*\(([^)]+)\)",
        src,
    )
    assert match, "_CORROBORATION_PREREQ_LANES not found"
    body = match.group(1)
    for required in ("memory", "disk_execution_persistence", "event_auth",
                     "timeline_correlation"):
        assert required in body, (
            f"_CORROBORATION_PREREQ_LANES missing {required!r}. "
            "Phase 4 required adding timeline_correlation."
        )


def test_synthesis_lane_constants_defined():
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    assert "_SYNTHESIS_LANE_ID" in src
    assert "_SYNTHESIS_SPECIALIST" in src
    assert '_SYNTHESIS_LANE_ID = "synthesis_corroboration"' in src
    assert '_SYNTHESIS_SPECIALIST = "synthesis-analyst"' in src


def test_dispatcher_checks_synthesis_lane_not_timeline():
    """The dispatcher's 'already done' and 'needs dispatch' predicates
    must key on _SYNTHESIS_LANE_ID, NOT timeline_correlation."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def _dispatch_corroboration_if_ready(")
    end = src.find("\ndef _lane_status_from_state(", func_idx)
    body = src[func_idx:end if end > 0 else func_idx + 15000]

    # Both predicates must check _SYNTHESIS_LANE_ID
    assert body.count("_SYNTHESIS_LANE_ID") >= 4, (
        "_dispatch_corroboration_if_ready does not reference _SYNTHESIS_LANE_ID "
        "in both the already_done and needs_dispatch predicates."
    )
    # The dispatch payload must target synthesis-analyst, not corroboration-analyst
    assert "_SYNTHESIS_SPECIALIST" in body, (
        "Dispatch payload should reference _SYNTHESIS_SPECIALIST."
    )


def test_record_analysis_lane_no_longer_skips_timeline_correlation():
    """review required: remove the 'normalized_lane != timeline_correlation'
    guard so dispatch fires when timeline_correlation closes."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    # The OLD guard pattern must be gone
    old_guard = 'normalized_lane != "timeline_correlation"'
    assert old_guard not in src, (
        f"OLD lane-skip guard {old_guard!r} still present — Phase 4 incomplete. "
        "review required removing it so timeline_correlation closure triggers synthesis dispatch."
    )
    # The NEW guard skips only when recording synthesis_corroboration ITSELF
    # (to prevent the synthesis-closes-its-own-lane infinite loop).
    new_guard = "normalized_lane != _SYNTHESIS_LANE_ID"
    assert new_guard in src, (
        f"NEW guard {new_guard!r} should prevent dispatch when recording "
        "the synthesis lane itself (which would create infinite re-dispatch)."
    )


# ---------------------------------------------------------------------------
# Lane queueing
# ---------------------------------------------------------------------------

def test_dispatcher_enqueues_into_synthesis_lane():
    """Phase 4: enqueue_delegate must target synthesis_corroboration, not
    timeline_correlation."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def _dispatch_corroboration_if_ready(")
    end = src.find("\ndef _lane_status_from_state(", func_idx)
    body = src[func_idx:end if end > 0 else func_idx + 15000]
    # The enqueue_delegate call must use _SYNTHESIS_LANE_ID
    assert "enqueue_delegate(_SYNTHESIS_LANE_ID" in body, (
        "Dispatcher must enqueue into _SYNTHESIS_LANE_ID, not a hardcoded lane."
    )
    # Old hardcoded enqueue must be gone
    assert 'enqueue_delegate("timeline_correlation"' not in body, (
        "Old enqueue_delegate('timeline_correlation', ...) call must be removed."
    )


def test_dispatcher_delegate_key_uses_synthesis_lane():
    """The delegate_key for synthesis must use synthesis_corroboration +
    synthesis-analyst (DEFECT-2 idempotency anchored on the right values)."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def _dispatch_corroboration_if_ready(")
    end = src.find("\ndef _lane_status_from_state(", func_idx)
    body = src[func_idx:end if end > 0 else func_idx + 15000]
    assert "compute_delegate_key(\n                case_id, _SYNTHESIS_LANE_ID, _SYNTHESIS_SPECIALIST" in body \
        or "compute_delegate_key(case_id, _SYNTHESIS_LANE_ID, _SYNTHESIS_SPECIALIST" in body, (
        "delegate_key must be computed against _SYNTHESIS_LANE_ID + _SYNTHESIS_SPECIALIST."
    )


# ---------------------------------------------------------------------------
# Backward-compat — corroboration-analyst still recognized
# ---------------------------------------------------------------------------

def test_corroboration_analyst_md_still_present():
    """corroboration-analyst.md stays (backward-compat). It's the predecessor
    body that already did cross-artifact reasoning. Phase 4 adds synthesis-analyst
    as the canonical name; the old name is accepted as a fallback specialist
    in EXPECTED_LANE_AGENTS for transition."""
    path = ROOT / ".claude" / "agents" / "corroboration-analyst.md"
    assert path.is_file(), (
        "corroboration-analyst.md was removed — back-compat broken."
    )


def test_corroboration_analyst_accepted_for_synthesis_lane():
    """For backward-compat during transition, corroboration-analyst is also
    accepted as a synthesis_corroboration owner."""
    from sift_mcp.reporting import EXPECTED_LANE_AGENTS
    agents = EXPECTED_LANE_AGENTS["synthesis_corroboration"]
    assert "corroboration-analyst" in agents, (
        "corroboration-analyst should be accepted on synthesis_corroboration "
        "lane (backward-compat with prior runs)."
    )
