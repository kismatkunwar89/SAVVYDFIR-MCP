"""CONFIRMED integrity invariant (review 2026-06-05).

A CONFIRMED finding that still declares `corroboration_outstanding` is
self-contradictory ("still needs X" vs "confirmed") — it must demote to ACTIVE.
This closes the F-061 manufacturing hole. Genuine 3-source stacks clear
corroboration_outstanding (=> empty), so real CONFIRMED (e.g. ROCBA
F-102/103/104) are untouched.
"""
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

if "fastmcp" not in sys.modules:
    fmc = types.ModuleType("fastmcp")
    class _Stub:
        def __init__(self, *a, **k): pass
        def tool(self, *a, **k):
            def _w(f): return f
            return _w
        def resource(self, *a, **k):
            def _w(f): return f
            return _w
        def run(self, *a, **k): pass
    fmc.FastMCP = _Stub
    sys.modules["fastmcp"] = fmc

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sift_mcp.semantics import _apply_confirmed_gates


class _StateOK:
    """state_manager whose execution_id always resolves (provenance passes)."""
    def get_execution(self, eid):
        return {"execution_id": eid, "tool_name": "x", "exit_code": 0,
                "duration_seconds": 1.0, "audit_completed_entry_hash": "h"}


def _confirmed_finding(**over):
    """A CONFIRMED finding that passes provenance + alt-hypothesis (so only the
    corroboration_outstanding gate is under test)."""
    f = {
        "finding_id": "F-X",
        "finding_status": "CONFIRMED",
        "execution_id": "E-1",
        "disposition": "ruled_out",
        "alternative_hypothesis": "benign scheduled task",
        "evidence_against_it": ["off-path binary in C:\\Users\\Public"],
        "corroborated_by": ["F-1", "F-2", "F-3"],
        "corroboration_outstanding": [],
    }
    f.update(over)
    return f


class ConfirmedOutstandingGate:
    pass


def test_outstanding_demotes_confirmed():
    f = _confirmed_finding(corroboration_outstanding=["prefetch", "amcache", "evtx_process_creation"])
    out = _apply_confirmed_gates(f, _StateOK())
    assert out["finding_status"].upper() == "ACTIVE", "non-empty outstanding must demote"
    blocks = out.get("confidence_support_inputs", {}).get("confirmed_gate_blocks", [])
    assert any(b.startswith("corroboration_outstanding:") for b in blocks), blocks


def test_empty_outstanding_stays_confirmed():
    # ROCBA-equivalent: full stack, empty outstanding -> stays CONFIRMED
    f = _confirmed_finding(corroboration_outstanding=[])
    out = _apply_confirmed_gates(f, _StateOK())
    assert out["finding_status"].upper() == "CONFIRMED", "empty outstanding must NOT demote"


def test_missing_outstanding_field_stays_confirmed():
    f = _confirmed_finding()
    f.pop("corroboration_outstanding", None)
    out = _apply_confirmed_gates(f, _StateOK())
    assert out["finding_status"].upper() == "CONFIRMED"


def test_non_confirmed_untouched():
    f = _confirmed_finding(finding_status="ACTIVE",
                           corroboration_outstanding=["prefetch"])
    out = _apply_confirmed_gates(f, _StateOK())
    assert out["finding_status"].upper() == "ACTIVE"  # unchanged (was already ACTIVE)


if __name__ == "__main__":
    import pytest as _p
    _p.main([__file__, "-q"])
