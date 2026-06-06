"""Regression tests for Phase 1 — submit_finding typed tool + durable provenance.

design review 2026-05-22: every specialist-registered finding must carry
``assigned_agent`` provenance so the Phase 5 investigation-success gate can
verify per-lane specialist contribution. ``submit_finding`` is the typed
entry point that enforces this — ``add_finding`` continues to work for
main-agent inline use.

Critical invariants:
  1. Finding model has the ``assigned_agent`` field (Optional[str]).
  2. submit_finding REQUIRES assigned_agent + lane_id (rejects empty).
  3. submit_finding persists assigned_agent to the Finding record.
  4. tool_name stays as ``state.submit_finding`` — NOT overloaded with the
     specialist name (review sign-off — would break lane/tool inference elsewhere).
  5. assigned_agent normalization strips leading ``@``.
  6. submit_finding still routes through validate_and_prepare_finding so
     A1 (provenance) and A2 (alt-hypothesis) gates fire as before.
  7. Audit row is written so ``which specialist registered F-NNN`` is queryable.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Model-level tests (no MCP runtime needed)
# ---------------------------------------------------------------------------

def test_finding_model_has_assigned_agent_field():
    """The Finding pydantic model must declare assigned_agent as Optional[str]."""
    from sift_mcp.models.finding import Finding
    fields = Finding.model_fields
    assert "assigned_agent" in fields, (
        "Finding model is missing the assigned_agent provenance field. "
        "Phase 5 investigation-success gate depends on this."
    )
    info = fields["assigned_agent"]
    # Default must be None — backward compatibility with existing add_finding flows
    assert info.default is None, "assigned_agent default must be None (backward-compat)"


def test_finding_accepts_assigned_agent_value():
    """End-to-end Finding instantiation with assigned_agent persists it."""
    from sift_mcp.models.finding import Finding
    f = Finding(
        case_id="TEST",
        finding_type="timestomping",
        artifact_type="disk",
        artifact_path="/x/mft.csv",
        tool_name="state.submit_finding",
        execution_id="E-001",
        iteration=1,
        evidence_kind="observation",
        confidence=0.9,
        description="MFT $SI < $FN delta > 1h on Mnemosyne.sys path placeholder.",
        assigned_agent="mft-analyst",
    )
    assert f.assigned_agent == "mft-analyst"


def test_finding_default_assigned_agent_is_none():
    """Findings created via add_finding (no assigned_agent set) must default to None."""
    from sift_mcp.models.finding import Finding
    f = Finding(
        case_id="TEST",
        finding_type="other",
        artifact_type="disk",
        artifact_path="/x/foo.csv",
        tool_name="state.add_finding",
        execution_id="E-001",
        iteration=1,
        evidence_kind="observation",
        confidence=0.5,
        description="Some finding without specialist provenance.",
    )
    assert f.assigned_agent is None


# ---------------------------------------------------------------------------
# Source-text guards on the MCP tool definition
# ---------------------------------------------------------------------------

def test_submit_finding_mcp_tool_exists():
    """source-text guard: server.py must define @mcp.tool() submit_finding."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    assert "def submit_finding(" in src, (
        "server.py is missing the submit_finding MCP tool (Phase 1)."
    )
    # The @mcp.tool() decorator must immediately precede submit_finding
    func_idx = src.find("def submit_finding(")
    assert func_idx > 0
    # Walk back to find the @mcp.tool() decorator
    preamble = src[max(0, func_idx - 200):func_idx]
    assert "@mcp.tool()" in preamble, (
        "submit_finding is defined but NOT decorated as @mcp.tool() — "
        "Claude Code won't expose it to the agent."
    )


def test_submit_finding_signature_has_required_params():
    """assigned_agent + lane_id are mandatory contract parameters."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    sig_start = src.find("def submit_finding(")
    sig_end = src.find(") -> dict[str, Any]:", sig_start)
    sig = src[sig_start:sig_end]
    # Must be positional / non-default (no `= "..."` or `= None`) to enforce required.
    # We allow either bare type annotation or no default value at all.
    for required in ("case_id: str", "lane_id: str", "assigned_agent: str",
                     "finding_type: str", "artifact_type: str",
                     "evidence_kind: str", "description: str", "confidence: float"):
        assert required in sig, (
            f"submit_finding signature missing required param: {required}"
        )


def test_submit_finding_keeps_tool_name_unchanged():
    """review sign-off: tool_name MUST stay as 'state.submit_finding'.
    Overloading tool_name with the specialist would break lane/tool inference."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def submit_finding(")
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 12000]
    # Tool name must be the MCP function name, NOT the specialist name.
    assert '"tool_name": "state.submit_finding"' in body, (
        "submit_finding must set tool_name='state.submit_finding'. "
        "review required keeping the producing-tool identity in tool_name."
    )
    # And it must explicitly set assigned_agent separately (the provenance anchor).
    assert "'assigned_agent': normalized_agent" in body or '"assigned_agent": normalized_agent' in body, (
        "submit_finding must persist assigned_agent as a separate field, NOT in tool_name."
    )


def test_submit_finding_writes_audit_row():
    """source-text guard: submit_finding must call _audit_logger.log_execution
    with tool_name='state.submit_finding' and the assigned_agent in parameters."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def submit_finding(")
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 12000]
    assert "_audit_logger.log_execution(" in body, (
        "submit_finding must write an audit row so the investigation-success "
        "gate can verify per-lane specialist contribution."
    )
    assert '"assigned_agent": normalized_agent' in body, (
        "audit row must include assigned_agent so it's queryable later."
    )
    assert '"lane_id": lane_id' in body, (
        "audit row must include lane_id."
    )


# ---------------------------------------------------------------------------
# Behavior tests via CaseStateManager (no MCP runtime needed)
# ---------------------------------------------------------------------------

def _make_state(tmp_path: Path):
    from sift_mcp.state import CaseStateManager
    sm = CaseStateManager(state_path=str(tmp_path / "state.json"))
    sm.load("TEST-CASE")
    return sm


def _record_execution(sm, eid: str, tool_name: str):
    with sm._lock:  # type: ignore[attr-defined]
        executions = sm._state.setdefault("executions", [])  # type: ignore[attr-defined]
        executions.append({
            "execution_id": eid,
            "tool_name": tool_name,
            "event_type": "completed",
            "iteration": 1,
        })


def test_state_add_finding_persists_assigned_agent(tmp_path):
    """When a caller (the new submit_finding tool) passes assigned_agent
    in the dict, CaseStateManager.add_finding persists it."""
    sm = _make_state(tmp_path)
    _record_execution(sm, "E-001", "state.submit_finding")
    fid = sm.add_finding({
        "case_id": "TEST-CASE",
        "finding_type": "timestomping",
        "artifact_type": "disk",
        "artifact_path": "/x/mft.csv",
        "tool_name": "state.submit_finding",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "confidence": 0.9,
        "description": "MFT $SI < $FN delta > 1h on staging-path binary.",
        "assigned_agent": "mft-analyst",
    })
    stored = sm.get_finding(fid)
    assert stored is not None
    assert stored.get("assigned_agent") == "mft-analyst", (
        f"assigned_agent not persisted; got: {stored.get('assigned_agent')!r}"
    )


def test_state_add_finding_assigned_agent_none_when_not_supplied(tmp_path):
    """A finding registered without assigned_agent gets None — backward-compat."""
    sm = _make_state(tmp_path)
    _record_execution(sm, "E-001", "state.add_finding")
    fid = sm.add_finding({
        "case_id": "TEST-CASE",
        "finding_type": "other",
        "artifact_type": "disk",
        "artifact_path": "/x/y.csv",
        "tool_name": "state.add_finding",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "confidence": 0.5,
        "description": "Main-agent inline finding without specialist provenance.",
    })
    stored = sm.get_finding(fid)
    assert stored.get("assigned_agent") is None, (
        "Findings without assigned_agent must default to None."
    )


def test_gate_still_fires_on_submit_finding_findings(tmp_path):
    """Phase 1 must NOT break the existing A1/A2 gates.

    A submit_finding call attempting CONFIRMED status without alt-hypothesis
    must still be demoted to ACTIVE — the gates run inside the shared
    validate_and_prepare_finding chokepoint."""
    sm = _make_state(tmp_path)
    _record_execution(sm, "E-001", "state.submit_finding")
    fid = sm.add_finding({
        "case_id": "TEST-CASE",
        "finding_type": "timestomping",
        "artifact_type": "disk",
        "artifact_path": "/x/mft.csv",
        "tool_name": "state.submit_finding",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "confidence": 0.9,
        "finding_status": "CONFIRMED",
        "description": "MFT delta finding attempting CONFIRMED without alt-hypothesis.",
        "assigned_agent": "mft-analyst",
        # NO alternative_hypothesis / disposition — A2 gate should fire.
    })
    stored = sm.get_finding(fid)
    # A2 gate must have demoted to ACTIVE
    assert stored["finding_status"] == "ACTIVE", (
        f"A2 alt-hypothesis gate failed to demote a CONFIRMED submit_finding "
        f"call without alt-hypothesis. Got status={stored['finding_status']!r}. "
        "Phase 1 must NOT bypass existing gates."
    )
    # assigned_agent must still be preserved through the gate demotion
    assert stored.get("assigned_agent") == "mft-analyst", (
        "Gate demotion must not strip assigned_agent provenance."
    )


def test_confirmed_submit_finding_with_full_alt_hypothesis_stays_confirmed(tmp_path):
    """Happy path under the integrity-fix contract (2026-06-05): A1 (provenance) +
    A2 (alt-hypothesis) + A3 (corroboration cleared) keeps CONFIRMED AND retains
    assigned_agent. CONFIRMED now carries weight — it requires 2+ sources — so this
    legitimate finding cites the sources its FK class (mft_timestomp) requires
    (prefetch + evtx_process_creation), clearing its outstanding."""
    sm = _make_state(tmp_path)
    _record_execution(sm, "E-001", "disk.extract_mft_timeline")
    fid = sm.add_finding({
        "case_id": "TEST-CASE",
        "finding_type": "timestomping",
        "artifact_type": "disk",
        "artifact_path": "/x/mft.csv",
        "tool_name": "state.submit_finding",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "confidence": 0.95,
        "finding_status": "CONFIRMED",
        "description": "$SI=2018-04-10 < $FN=2021-09-16 by >3y on staging-path drop.",
        "assigned_agent": "mft-analyst",
        "alternative_hypothesis": "Legitimate IT-deployed agent backdated by maintenance script",
        "evidence_against_it": [
            "no change-management ticket present",
            "drop time aligns with cross-source NTLM lateral-movement burst",
            "$FN timestamp post-dates $SI by >3y — only NTFS-API timestomping can produce this",
        ],
        "disposition": "ruled_out",
        # A3: corroboration cleared (2+ sources) -> CONFIRMED carries weight
        "corroborated_by": ["prefetch", "evtx_process_creation"],
    })
    stored = sm.get_finding(fid)
    assert stored["finding_status"] == "CONFIRMED"
    assert stored.get("assigned_agent") == "mft-analyst"
    assert not stored.get("requires_re_extraction")


def test_confirmed_single_source_demotes_to_active(tmp_path):
    """Integrity fix (2026-06-05): a single-artifact CONFIRMED with full A1+A2 but
    NO corroboration is demoted to ACTIVE — CONFIRMED requires 2+ sources (stacking
    principle). This is the F-061 prevention: one source of truth is not 'confirmed'."""
    sm = _make_state(tmp_path)
    _record_execution(sm, "E-001", "disk.extract_mft_timeline")
    fid = sm.add_finding({
        "case_id": "TEST-CASE",
        "finding_type": "timestomping",
        "artifact_type": "disk",
        "artifact_path": "/x/mft.csv",
        "tool_name": "state.submit_finding",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "confidence": 0.95,
        "finding_status": "CONFIRMED",
        "description": "$SI<$FN timestomping, single MFT artifact only.",
        "alternative_hypothesis": "Legitimate maintenance backdating",
        "evidence_against_it": ["no change ticket"],
        "disposition": "ruled_out",
        # NO corroborated_by -> outstanding (prefetch, evtx) stays -> demote
    })
    stored = sm.get_finding(fid)
    assert stored["finding_status"] == "ACTIVE", "single-source CONFIRMED must demote"
    blocks = stored.get("confidence_support_inputs", {}).get("confirmed_gate_blocks", [])
    assert any(b.startswith("corroboration_outstanding:") for b in blocks), blocks


# ---------------------------------------------------------------------------
# Lane mapping consistency
# ---------------------------------------------------------------------------

def test_submit_finding_signature_documents_lane_id_match():
    """Docstring must communicate that lane_id should match the specialist's
    mapped lane in TOOL_AGENT_MAP (for the Phase 5 gate to work)."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def submit_finding(")
    docstring_start = src.find('"""', func_idx)
    docstring_end = src.find('"""', docstring_start + 3)
    doc = src[docstring_start:docstring_end]
    assert "lane_id" in doc.lower() and ("TOOL_AGENT_MAP" in doc or "mapped lane" in doc.lower()), (
        "submit_finding docstring must explain that lane_id should match the "
        "specialist's TOOL_AGENT_MAP entry. Without this, the Phase 5 gate "
        "can't infer expected-specialist-for-lane."
    )
