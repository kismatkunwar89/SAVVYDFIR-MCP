"""Regression tests for Phase 3 — playbook-mode specialists.

peer reviewer consensus 2026-05-22: 8 artifact specialists become playbook executors
with one adaptive pivot slot. Universal forensic queries only (no case-specific
values). Hard cap 6-8 run_analysis calls per specialist.

Tests verify:
  1. All 8 artifact specialists have the playbook block.
  2. corroboration-analyst, timeline-analyst, json-repair are UNCHANGED
     (they stay creative / cross-artifact).
  3. browser-analyst is unchanged (no MCP browser-extract tool exists).
  4. Each playbook has ordered numbered queries with submit_finding callouts.
  5. Each playbook has an ADAPTIVE PIVOT section with the bound.
  6. Each playbook references the typed submit_finding tool (Phase 1).
  7. No case-specific hardcoded values (case-agnostic invariant).

ALL TESTS IN THIS FILE SKIPPED 2026-05-23 (W1.2 of PLAN-FIND-EVIL-HACKATHON-2026-05-23.md).

The Phase 3 playbook overlay was stripped from .md files because it
overlaid prescriptive procedures on top of user-authored "Heuristics,
not procedures" content, contradicting the original design intent.
See DECISION-2026-05-23-branch-triage.md Section 5.3.

The .md files are now forensic-heuristic knowledge bases consumed by the
main agent inline (no Task subagent dispatch). Coverage of the new shape
is in test_evidence_integrity_bypass.py (schema enforcement) and W2 work
(Mermaid DAG renderer + per-tool schema migration).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# Skip the entire module — Phase 3 overlay was stripped in W1.2.
pytestmark = pytest.mark.skip(reason=(
    "Phase 3 playbook overlay stripped in W1.2 (2026-05-23). "
    "See PLAN-FIND-EVIL-HACKATHON-2026-05-23.md and "
    "DECISION-2026-05-23-branch-triage.md."
))

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / ".claude" / "agents"

PLAYBOOK_MARKER = "## Playbook (Phase 3 refactor — peer reviewer consensus 2026-05-22)"
ARTIFACT_SPECIALISTS = [
    ("mft-analyst", "timeline_correlation"),
    ("evtx-analyst", "event_auth"),
    ("prefetch-analyst", "disk_execution_persistence"),
    ("amcache-analyst", "disk_execution_persistence"),
    ("registry-analyst", "disk_execution_persistence"),
    ("srum-analyst", "timeline_correlation"),
    ("sigma-analyst", "timeline_correlation"),
    ("memory-analyst", "memory"),
]
NON_PLAYBOOK_AGENTS = [
    "corroboration-analyst",
    "timeline-analyst",
    "json-repair",
    "browser-analyst",
]

# Case-specific patterns that MUST NEVER appear in framework code.
# This is the hard agnostic constraint.
FORBIDDEN_CASE_SPECIFIC_PATTERNS = [
    r"\bsubject_srv\.exe\b",
    r"\bMnemosyne\.sys\b",
    r"\bcbarton-a\b",
    r"\bBASE-HUNT\b",
    r"\b172\.16\.5\.25\b",
    r"\bHACKATHON-\d{4}\b",
    # Specific hashes we've seen in chats
    r"\ba3f7[0-9a-f]{36}",
]


# ---------------------------------------------------------------------------
# Playbook presence + structure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("specialist,lane", ARTIFACT_SPECIALISTS)
def test_artifact_specialist_has_playbook(specialist, lane):
    path = AGENTS / f"{specialist}.md"
    text = path.read_text(encoding="utf-8")
    assert PLAYBOOK_MARKER in text, (
        f"{specialist} is missing the playbook block — Phase 3 refactor incomplete."
    )
    assert f"lane_id={lane!r}" in text, (
        f"{specialist} playbook does not reference its mapped lane {lane!r}."
    )


@pytest.mark.parametrize("specialist,lane", ARTIFACT_SPECIALISTS)
def test_playbook_has_numbered_queries(specialist, lane):
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    queries = re.findall(r"### QUERY \d+ —", text)
    # Each playbook has 3-4 numbered queries
    assert len(queries) >= 3, (
        f"{specialist} playbook has only {len(queries)} numbered queries; "
        "minimum is 3 for meaningful coverage."
    )
    assert len(queries) <= 5, (
        f"{specialist} playbook has {len(queries)} numbered queries; "
        "peer reviewer cap is 4-5 + adaptive."
    )


@pytest.mark.parametrize("specialist,lane", ARTIFACT_SPECIALISTS)
def test_playbook_has_adaptive_pivot(specialist, lane):
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    assert "### ADAPTIVE PIVOT" in text, (
        f"{specialist} playbook is missing the adaptive pivot section — "
        "peer reviewer required ONE bounded creative slot per specialist."
    )
    assert "≤2" in text or "bounded" in text.lower(), (
        f"{specialist} adaptive pivot is not visibly bounded."
    )


@pytest.mark.parametrize("specialist,lane", ARTIFACT_SPECIALISTS)
def test_playbook_uses_submit_finding(specialist, lane):
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    assert "submit_finding(" in text, (
        f"{specialist} playbook does not invoke the Phase 1 submit_finding tool."
    )
    # Must pass assigned_agent matching the specialist's own name (provenance)
    assert f"assigned_agent={specialist!r}" in text, (
        f"{specialist} playbook does not set assigned_agent={specialist!r} on "
        "submit_finding calls — Phase 5 gate would mis-attribute findings."
    )


@pytest.mark.parametrize("specialist,lane", ARTIFACT_SPECIALISTS)
def test_playbook_has_hard_call_budget(specialist, lane):
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    assert "Hard call budget" in text, (
        f"{specialist} playbook does not declare a hard call budget."
    )


@pytest.mark.parametrize("specialist,lane", ARTIFACT_SPECIALISTS)
def test_playbook_references_precomputed_context(specialist, lane):
    """Playbook must tell the specialist that schema/timestamp_bounds/
    attack_window/originating_execution_id are pre-computed by the parent
    (Phase 2). Otherwise specialists will waste calls on schema discovery."""
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    for marker in (
        "csv_path",
        "schema",
        "timestamp_bounds",
        "attack_window",
        "originating_execution_id",
    ):
        assert marker in text, (
            f"{specialist} playbook does not reference pre-computed context: {marker}"
        )


# ---------------------------------------------------------------------------
# Universal forensic patterns — no case-specific values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("specialist,_lane", ARTIFACT_SPECIALISTS)
def test_playbook_is_case_agnostic(specialist, _lane):
    """The hard constraint: no specific filenames, IPs, users, hashes, or
    attack windows in framework code."""
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    for pattern in FORBIDDEN_CASE_SPECIFIC_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        assert match is None, (
            f"{specialist} playbook contains case-specific value "
            f"{match.group(0)!r}; the framework must remain case-agnostic. "
            "Pattern: {pattern!r}"
        )


# ---------------------------------------------------------------------------
# Non-playbook specialists stay unchanged
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("specialist", NON_PLAYBOOK_AGENTS)
def test_non_playbook_specialists_unchanged(specialist):
    """peer reviewer explicitly said corroboration-analyst + timeline-analyst stay
    creative (cross-artifact reasoning). json-repair stays as transcription-only.
    browser-analyst is deferred (no MCP browser-extract tool exists)."""
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    assert PLAYBOOK_MARKER not in text, (
        f"{specialist} should NOT have a Phase 3 playbook block — it stays creative."
    )


# ---------------------------------------------------------------------------
# Lane consistency with TOOL_AGENT_MAP
# ---------------------------------------------------------------------------

def test_playbook_lanes_match_tool_agent_map():
    """Each specialist's playbook lane_id must match its TOOL_AGENT_MAP entry."""
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger
    # Build {specialist: set_of_lanes} from TOOL_AGENT_MAP
    by_specialist = {}
    for _tool, (spec, lane, _instr) in agent_trigger.TOOL_AGENT_MAP.items():
        by_specialist.setdefault(spec, set()).add(lane)

    for specialist, declared_lane in ARTIFACT_SPECIALISTS:
        mapped_lanes = by_specialist.get(specialist, set())
        assert declared_lane in mapped_lanes, (
            f"{specialist} playbook declares lane {declared_lane!r} but "
            f"TOOL_AGENT_MAP says its lanes are {mapped_lanes!r}. "
            "Phase 5 specialist-contribution gate depends on this consistency."
        )


# ---------------------------------------------------------------------------
# Persist-first discipline preserved
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("specialist,_lane", ARTIFACT_SPECIALISTS)
def test_playbook_preserves_persist_first_contract(specialist, _lane):
    """The C-PRIME Output Discipline block must still appear ABOVE the
    playbook block. Phase 3 added to Phase C-PRIME, not replaced it."""
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    c_prime_idx = text.find("## C-PRIME Output Discipline")
    playbook_idx = text.find(PLAYBOOK_MARKER)
    assert c_prime_idx >= 0, f"{specialist}: C-PRIME block missing"
    assert playbook_idx >= 0, f"{specialist}: playbook block missing"
    assert c_prime_idx < playbook_idx, (
        f"{specialist}: C-PRIME block must appear BEFORE the playbook. "
        "Order matters — agent reads the discipline first, then the playbook."
    )


@pytest.mark.parametrize("specialist,_lane", ARTIFACT_SPECIALISTS)
def test_playbook_instructs_no_narration_between_queries(specialist, _lane):
    """peer reviewer's key constraint: NO narration between queries. Playbook
    must explicitly state this — otherwise specialists revert to free-form."""
    text = (AGENTS / f"{specialist}.md").read_text(encoding="utf-8")
    assert "No narration between queries" in text, (
        f"{specialist} playbook does not explicitly forbid narration between "
        "queries — the C-PRIME revision regression would recur."
    )
