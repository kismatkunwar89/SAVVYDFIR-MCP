"""Regression tests for Tier-A2 alternative-hypothesis gate.

design review 2026-05-19: CONFIRMED findings MUST carry structured
alternative-hypothesis disposition. Boilerplate is prevented by the
4-field structure forcing specificity:
  - alternative_hypothesis (non-empty string)
  - evidence_that_would_support_it (list, optional)
  - evidence_against_it (list, ≥1 entry required when disposition='ruled_out')
  - disposition ('ruled_out' or 'not_applicable' to pass the gate)

unresolved/partially_plausible dispositions MUST downgrade per review sign-off.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class _FakeStateManager:
    def __init__(self, executions=None):
        self._execs = dict(executions or {})

    def get_execution(self, eid):
        return self._execs.get(eid)


# ---------------------------------------------------------------------------
# Pure helper tests
# ---------------------------------------------------------------------------

def test_disposition_ruled_out_requires_alternative_and_evidence_against():
    """disposition='ruled_out' requires alternative_hypothesis text AND
    >=1 evidence_against_it entry."""
    from sift_mcp.semantics import _alternative_hypothesis_complete

    # Complete shape
    ok, reason = _alternative_hypothesis_complete({
        "disposition": "ruled_out",
        "alternative_hypothesis": "Legitimate F-Response IT deployment",
        "evidence_against_it": ["timestomp_2018", "no_change_ticket"],
    })
    assert ok, f"complete shape must pass, got: {reason}"

    # Missing alternative_hypothesis text
    ok, reason = _alternative_hypothesis_complete({
        "disposition": "ruled_out",
        "alternative_hypothesis": "",
        "evidence_against_it": ["timestomp"],
    })
    assert not ok
    assert "alternative_hypothesis_text_missing" in reason

    # Empty evidence_against_it
    ok, reason = _alternative_hypothesis_complete({
        "disposition": "ruled_out",
        "alternative_hypothesis": "Legitimate F-Response IT deployment",
        "evidence_against_it": [],
    })
    assert not ok
    assert "evidence_against_it_empty" in reason


def test_disposition_not_applicable_requires_reason():
    """disposition='not_applicable' requires non-empty
    alternative_hypothesis_not_applicable_reason."""
    from sift_mcp.semantics import _alternative_hypothesis_complete

    # Complete
    ok, reason = _alternative_hypothesis_complete({
        "disposition": "not_applicable",
        "alternative_hypothesis_not_applicable_reason": "Self-extracting ransomware with hardcoded exfil URL.",
    })
    assert ok

    # Missing reason
    ok, reason = _alternative_hypothesis_complete({
        "disposition": "not_applicable",
        "alternative_hypothesis_not_applicable_reason": "",
    })
    assert not ok
    assert "not_applicable_reason_missing" in reason


def test_unresolved_dispositions_fail_the_gate():
    """Per review sign-off: not_resolved and partially_plausible MUST fail
    the gate — unresolved alternatives must cause report partitioning."""
    from sift_mcp.semantics import _alternative_hypothesis_complete

    for bad in ("not_resolved", "partially_plausible"):
        ok, reason = _alternative_hypothesis_complete({
            "disposition": bad,
            "alternative_hypothesis": "Some hypothesis",
            "evidence_against_it": ["x"],
        })
        assert not ok, f"disposition={bad} must fail the gate"
        assert "disposition_unresolved" in reason


def test_empty_disposition_fails():
    """No disposition set → fail (force the analyst to make a call)."""
    from sift_mcp.semantics import _alternative_hypothesis_complete
    ok, reason = _alternative_hypothesis_complete({})
    assert not ok
    assert "disposition_empty" in reason


# ---------------------------------------------------------------------------
# Integration tests via validate_and_prepare_finding
# ---------------------------------------------------------------------------

def _make_confirmed(extra: dict | None = None) -> dict:
    """Build a CONFIRMED candidate finding with valid provenance, ready to
    test the alt-hypothesis gate in isolation."""
    base = {
        "case_id": "TEST",
        "finding_type": "test_finding",
        "tool_name": "test.tool",
        "execution_id": "E-100",
        "iteration": 1,
        "evidence_kind": "INFERENCE",
        "finding_status": "CONFIRMED",
        "confidence": 0.95,
        "description": "Test finding for alt-hypothesis gate regression.",
        "artifact_path": "/test/artifact.csv",
        "artifact_type": "memory",
    }
    base.update(extra or {})
    return base


def test_confirmed_demoted_when_alternative_hypothesis_missing():
    """A CONFIRMED finding without alt-hypothesis fields → demoted to ACTIVE."""
    from sift_mcp.semantics import validate_and_prepare_finding
    sm = _FakeStateManager({"E-100": {"tool_name": "test.tool"}})
    out = validate_and_prepare_finding(_make_confirmed(), state_manager=sm)
    assert out["finding_status"] == "ACTIVE", (
        "CONFIRMED without alternative-hypothesis must be demoted."
    )
    blocks = (out.get("confidence_support_inputs") or {}).get("confirmed_gate_blocks") or []
    assert any("alternative_hypothesis" in b for b in blocks), (
        f"confirmed_gate_blocks must record alt-hypothesis failure. Got: {blocks}"
    )


def test_confirmed_kept_when_ruled_out_with_evidence():
    """CONFIRMED + ruled_out + alternative + ≥1 evidence_against_it → kept."""
    from sift_mcp.semantics import validate_and_prepare_finding
    sm = _FakeStateManager({"E-100": {"tool_name": "test.tool"}})
    f = _make_confirmed({
        "alternative_hypothesis": "Legitimate F-Response IT deployment",
        "evidence_against_it": ["timestomp_2018", "no_change_ticket"],
        "disposition": "ruled_out",
    })
    out = validate_and_prepare_finding(f, state_manager=sm)
    assert out["finding_status"] == "CONFIRMED"
    assert not out.get("requires_re_extraction")


def test_confirmed_kept_when_not_applicable_with_reason():
    """CONFIRMED + not_applicable + reason → kept."""
    from sift_mcp.semantics import validate_and_prepare_finding
    sm = _FakeStateManager({"E-100": {"tool_name": "test.tool"}})
    f = _make_confirmed({
        "disposition": "not_applicable",
        "alternative_hypothesis_not_applicable_reason":
            "Self-extracting ransomware encryption pattern — no benign use exists.",
    })
    out = validate_and_prepare_finding(f, state_manager=sm)
    assert out["finding_status"] == "CONFIRMED"


def test_confirmed_demoted_when_disposition_partially_plausible():
    """review sign-off: unresolved alternatives MUST cause partitioning,
    not CONFIRMED labeling. partially_plausible must downgrade."""
    from sift_mcp.semantics import validate_and_prepare_finding
    sm = _FakeStateManager({"E-100": {"tool_name": "test.tool"}})
    f = _make_confirmed({
        "alternative_hypothesis": "Legitimate IT use",
        "evidence_against_it": ["some_evidence"],
        "disposition": "partially_plausible",
    })
    out = validate_and_prepare_finding(f, state_manager=sm)
    assert out["finding_status"] == "ACTIVE", (
        "partially_plausible must downgrade per review sign-off."
    )


def test_finding_model_carries_new_fields():
    """The 5 new Finding-model fields must be addressable by name."""
    from sift_mcp.models.finding import Finding
    model_fields = set(Finding.model_fields.keys())
    required_new_fields = {
        "requires_re_extraction",
        "alternative_hypothesis",
        "evidence_that_would_support_it",
        "evidence_against_it",
        "disposition",
        "alternative_hypothesis_not_applicable_reason",
    }
    missing = required_new_fields - model_fields
    assert not missing, (
        f"Finding model is missing required gate fields: {missing}"
    )
