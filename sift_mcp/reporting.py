"""Report-generation helpers that stay importable without FastMCP."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# Tier-A report-gate invariants:
# alternative-hypothesis completeness check shared with semantics.py.
from sift_mcp.semantics import (
    _alternative_hypothesis_complete,
    apply_hypothesis_status_gate,
)

# PART B (review 2026-06-03): the single extraction catalog lives in
# analysis_debt.py (pure, no reporting/server dependency). FILE_ACCESS_TOOL_SUFFIXES
# is a DERIVED view from it (one source of truth; additive migration). The legacy
# _COVERAGE_SUFFIX_LANES coverage map below is left untouched and a unit test
# guards it against catalog drift.
from sift_mcp.analysis_debt import (
    FILE_ACCESS_TOOL_SUFFIXES,
    compute_analysis_debt,
)
# FK-wiring ITEM C: advisory corroboration pivots (pure engine; no server._FK).
from sift_mcp.corroboration import (
    artifact_name_for_finding,
    corroboration_state,
    load_fk_slice,
)


def _parse_iso8601(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _pending_delegate_is_fresh(
    pending_delegate: dict[str, Any], *, delegate_file: Path
) -> bool:
    try:
        max_age_seconds = int(
            os.environ.get("SAVVYDFIR_TRIGGER_MAX_AGE_SECONDS", "21600") or "21600"
        )
    except ValueError:
        max_age_seconds = 21600
    if max_age_seconds <= 0:
        return True

    created_at = _parse_iso8601(pending_delegate.get("created_at"))
    if created_at is None:
        modified_at = datetime.fromtimestamp(
            delegate_file.stat().st_mtime, tz=timezone.utc
        )
    else:
        modified_at = created_at
    age_seconds = (datetime.now(timezone.utc) - modified_at).total_seconds()
    return age_seconds <= max_age_seconds


def _pending_delegate_blocks_case(
    pending_delegate: dict[str, Any], *, case_id: str, delegate_file: Path
) -> bool:
    if pending_delegate.get("processed") is not False:
        return False
    if not _pending_delegate_is_fresh(pending_delegate, delegate_file=delegate_file):
        return False
    pending_case_id = str(pending_delegate.get("case_id") or "").strip()
    if pending_case_id and pending_case_id != case_id:
        return False
    # DEFECT-3: stale-dismissed and processed
    # entries should not block. The status field is authoritative; the
    # legacy processed boolean is checked above.
    status = str(pending_delegate.get("status") or "").lower()
    if status in {"processed", "stale_dismissed"}:
        return False
    return True


# DEFECT-3 - stale-delegate filter helpers
def _import_scripts_module(name: str) -> Any:
    """Best-effort import of a script in scripts/ - returns None on failure
    so the report gate degrades gracefully without the new helpers."""
    try:
        import sys as _sys
        from pathlib import Path as _P
        scripts_dir = _P(__file__).resolve().parent.parent / "scripts"
        if str(scripts_dir) not in _sys.path:
            _sys.path.insert(0, str(scripts_dir))
        return __import__(name)
    except Exception:
        return None


def _normalize_specialist(name: Any) -> str:
    """Strip @ and lowercase a specialist name for comparison."""
    return str(name or "").strip().lstrip("@").lower()


def _lane_recorded_by_same_specialist(
    lane_record: dict[str, Any],
    delegate_subagent: str,
) -> bool:
    """Return True if the lane was completed by the same specialist that
    the delegate requested (the -distinguished "same actor" case)."""
    if not isinstance(lane_record, dict):
        return False
    assigned = _normalize_specialist(lane_record.get("assigned_agent"))
    target = _normalize_specialist(delegate_subagent)
    if not target:
        return False
    return assigned == target


# W1.7 Run-5 fix (BUG-B)
# Synthesis is inverted in W1.7: main-agent inline IS Path A; @synthesis-analyst
# Task spawn is the opt-in escape hatch. The legacy dismissal predicate had
# only same-actor and DIFFERENT-actor+path_b_would_allow paths - both fail
# for main-agent inline synthesis (Run-5 evidence: agent recorded the lane,
# generate_report still returned needs_delegate). This predicate adds the
# missing Path-A satisfaction: main-agent recorded synthesis_corroboration
# COMPLETE with ≥3 CONFIRMED findings → delegate satisfied.
_SYNTHESIS_LANE_NAME = "synthesis_corroboration"
_SYNTHESIS_DELEGATE_NAMES = {"synthesis-analyst", "corroboration-analyst"}
# _SYNTHESIS_MIN_CONFIRMED (=3) REMOVED 2026-06-05 (integrity fix): it was a
# CONFIRMED quota that incentivized fabricating findings to clear the synthesis
# delegate gate. Dismissal now keys on synthesis WORK done (see
# _inline_synthesis_satisfies_delegate), not a CONFIRMED count.


def _safe_get_findings(state_manager: Any) -> list[dict[str, Any]]:
    """Defensive wrapper - some test fakes don't implement get_findings();
    returning [] in that case means the predicate evaluates to False naturally
    instead of crashing dismissal entirely (preserves legacy test contracts).
    """
    try:
        result = state_manager.get_findings()
        return list(result) if result else []
    except (AttributeError, Exception):
        return []


def _inline_synthesis_satisfies_delegate(
    *,
    lane_record: dict[str, Any],
    delegate_subagent: str,
    state_findings: list[dict[str, Any]],
    state_manager: Any = None,
) -> bool:
    """Return True iff the synthesis_corroboration lane was genuinely WORKED by
    main-agent inline, satisfying the pending @synthesis-analyst delegate.

    INTEGRITY FIX (review 2026-06-05): the prior rule required >=3 CONFIRMED
    findings in the lane (_SYNTHESIS_MIN_CONFIRMED). That made CONFIRMED a QUOTA and
    directly incentivized fabricating CONFIRMED findings to clear the gate. CONFIRMED
    must be an OUTCOME of evidence, never a target.

    New rule gates on synthesis WORK DONE, not on a CONFIRMED count:
      - lane_id is the synthesis lane
      - delegate target normalizes to a synthesis specialist
      - lane assigned_agent normalizes to 'main-agent'
      - lane status is a done state (COMPLETE / COMPLETE_WITH_GAPS)
      - lane has >=1 finding_id (synthesis produced something)
      - the synthesis ACTIONS actually RAN: the lane's OWN execution_ids resolve to
        SUCCESSFUL correlation.compare_disk_and_memory AND
        correlation.find_temporal_clusters executions (lane-linked, audit-verified
        via _execution_was_successful). This is the anti-hollow-lane guard: a lane
        marked COMPLETE without the synthesis tools actually running cannot dismiss
        the delegate. We do NOT require those actions to PRODUCE results -- a sparse
        honest case legitimately yields 0 clusters; requiring output re-introduces
        the fabrication incentive.
    The honest CONFIRMED count (0, 1, 2, ...) is then whatever the evidence supports.
    """
    if not isinstance(lane_record, dict):
        return False
    if str(lane_record.get("lane_id") or "") != _SYNTHESIS_LANE_NAME:
        return False
    if _normalize_specialist(delegate_subagent) not in _SYNTHESIS_DELEGATE_NAMES:
        return False
    if _normalize_specialist(lane_record.get("assigned_agent")) != "main-agent":
        return False
    lane_status = str(lane_record.get("status") or "").upper()
    if lane_status not in {"COMPLETE", "COMPLETE_WITH_GAPS"}:
        return False
    lane_finding_ids = {str(fid).strip() for fid in (lane_record.get("finding_ids") or [])}
    if not lane_finding_ids:
        return False
    # Anti-hollow-lane: require the synthesis tools to have RUN successfully,
    # referenced by THIS lane's execution_ids (not merely "ran somewhere").
    if state_manager is None:
        return False
    lane_exec_ids = [str(e).strip() for e in (lane_record.get("execution_ids") or []) if str(e).strip()]
    if not lane_exec_ids:
        return False
    required_actions = {
        "correlation.compare_disk_and_memory",
        "correlation.find_temporal_clusters",
    }
    satisfied_actions: set[str] = set()
    for eid in lane_exec_ids:
        try:
            ex = state_manager.get_execution(eid)
        except Exception:
            ex = None
        if not isinstance(ex, dict):
            continue
        tool_name = str(ex.get("tool_name") or "")
        if tool_name in required_actions and _execution_was_successful(ex):
            satisfied_actions.add(tool_name)
    return required_actions.issubset(satisfied_actions)


def _find_lane_in_state(
    case_id: str, state_manager: Any, lane_id: str
) -> Optional[dict[str, Any]]:
    """Look up a single lane record from state.json:analysis_lanes."""
    if not lane_id:
        return None
    try:
        state_manager.load(case_id)
    except Exception:
        pass
    try:
        for lane in state_manager.get_analysis_lanes():
            if not isinstance(lane, dict):
                continue
            if str(lane.get("lane_id") or "") == lane_id:
                return lane
    except Exception:
        return None
    return None


def _dismiss_stale_delegates(
    case_id: str,
    state_manager: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Walk the per-lane delegate queue and dismiss stale entries.

    
      * SAME-actor stale → mark stale_dismissed, ledger=`delegate_satisfied_by_lane_record`
      * DIFFERENT-actor + ledger has `path_b_would_allow` for the lane in
        current session → mark stale_dismissed, ledger=`delegate_satisfied_by_path_b_allowance`
      * Otherwise → keep blocking (returned in still_blocking)

    Returns (dismissed, still_blocking). Idempotent under repeat calls.
    """
    dq = _import_scripts_module("delegate_queue")
    ledger = _import_scripts_module("delegation_ledger")
    if dq is None:
        return ([], [])

    try:
        pending = dq.all_pending_delegates()
    except Exception:
        return ([], [])

    dismissed: list[dict[str, Any]] = []
    still_blocking: list[dict[str, Any]] = []

    for entry in pending:
        entry_case = str(entry.get("case_id") or "").strip()
        if entry_case and entry_case != case_id:
            # Foreign-case entry - not ours to block on or dismiss.
            continue
        lane_id = str(entry.get("lane_id") or "").strip()
        delegate_key = str(entry.get("delegate_key") or "").strip()
        subagent = _normalize_specialist(entry.get("subagent_type"))
        if not lane_id:
            still_blocking.append(entry)
            continue
        lane_record = _find_lane_in_state(case_id, state_manager, lane_id)
        if lane_record is None:
            still_blocking.append(entry)
            continue
        status = str(lane_record.get("status") or "").upper()
        if status not in {"COMPLETE", "COMPLETE_WITH_GAPS"}:
            still_blocking.append(entry)
            continue

        # Timestamp comparison - lane must have been updated AFTER delegate
        # was queued. We use updated_at (close to recorded_at).
        lane_ts = _parse_iso8601(
            lane_record.get("updated_at") or lane_record.get("recorded_at")
            or lane_record.get("created_at")
        )
        delegate_ts = _parse_iso8601(entry.get("created_at"))
        if lane_ts is not None and delegate_ts is not None and lane_ts <= delegate_ts:
            still_blocking.append(entry)
            continue

        # Lane is satisfied. Now the distinction:
        # (a) SAME specialist? Auto-dismiss.
        # (b) Different specialist? Only dismiss if ledger has Path B
        #     allowance for the same lane in current session.
        if _lane_recorded_by_same_specialist(lane_record, subagent):
            event_name = "delegate_satisfied_by_lane_record"
            basis = (
                f"lane={lane_id!r} status={status} "
                f"assigned_agent={lane_record.get('assigned_agent')!r} "
                f"matches delegate.subagent_type={subagent!r}"
            )
        elif _inline_synthesis_satisfies_delegate(
            lane_record=lane_record,
            delegate_subagent=subagent,
            state_findings=_safe_get_findings(state_manager),
            state_manager=state_manager,
        ):
            # W1.7 Run-5 BUG-B fix: main-agent inline synthesis is Path A
            # for this lane (not a fallback). Dismiss the @synthesis-analyst
            # delegate without requiring path_b_would_allow.
            event_name = "delegate_satisfied_by_inline_synthesis"
            basis = (
                f"lane={lane_id!r} status={status} "
                f"assigned_agent=main-agent ran inline synthesis "
                f"(compare_disk_and_memory + find_temporal_clusters executed) - "
                f"inline Path A satisfies @{subagent} delegate; CONFIRMED count is "
                f"evidence-determined (no quota)"
            )
        else:
            # Different actor - check ledger for Path B allowance.
            has_path_b_allowance = False
            if ledger is not None:
                try:
                    rows = ledger.read_session_rows(
                        lane_id=lane_id, event="path_b_would_allow"
                    )
                    has_path_b_allowance = bool(rows)
                except Exception:
                    has_path_b_allowance = False
            if not has_path_b_allowance:
                # Phantom Path A: the lane was completed by a different
                # actor without recorded Path B authorization. KEEP
                # blocking - this is exactly the case insisted on.
                still_blocking.append(entry)
                continue
            event_name = "delegate_satisfied_by_path_b_allowance"
            basis = (
                f"lane={lane_id!r} status={status} "
                f"assigned_agent={lane_record.get('assigned_agent')!r} "
                f"!= delegate.subagent_type={subagent!r}; "
                f"ledger has path_b_would_allow row(s)"
            )

        # Mark stale in the queue and write the audit row.
        try:
            dq.mark_delegate_stale(delegate_key, reason=event_name)
        except Exception:
            pass
        if ledger is not None:
            try:
                ledger.append_row(
                    event_name,
                    lane_id=lane_id,
                    specialist=subagent,
                    decision_basis=basis,
                    extra={"case_id": case_id, "delegate_key": delegate_key},
                )
                # Also append the generic stale_delegate_dismissed event for
                # broad audit queries.
                ledger.append_row(
                    "stale_delegate_dismissed",
                    lane_id=lane_id,
                    specialist=subagent,
                    decision_basis=f"via={event_name}",
                    extra={"case_id": case_id, "delegate_key": delegate_key},
                )
            except Exception:
                pass
        dismissed.append({
            "delegate_key": delegate_key,
            "lane_id": lane_id,
            "subagent_type": subagent,
            "event": event_name,
            "basis": basis,
        })

    return (dismissed, still_blocking)


# ---------------------------------------------------------------------------
# Phase 5 - Investigation-success gate
#
# Separate from evaluate_ir_coverage_gate (which checks artifact tool coverage)
# this gate checks SPECIALIST CONTRIBUTION: did each lane receive at least one
# submit_finding call from its expected specialist? If not, the lane is
# documented as "specialist contribution missing" and generate_report blocks
# unless allow_partial=True.
# ---------------------------------------------------------------------------

# Lanes that REQUIRE specialist contribution (artifact-collection lanes).
# evidence_access is main-agent-only (no specialist counterpart).
# synthesis_corroboration is the synthesis output - checked separately.
_SPECIALIST_REQUIRED_LANES = (
    "memory",
    "disk_execution_persistence",
    "event_auth",
    "timeline_correlation",
)


def evaluate_hypothesis_gate(
    case_id: str,
    state_manager: Any,
    findings_count: int,
    confirmed_count: int,
    sigma_result: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """W1.7 (CR-revised plan 2026-05-23): Phase 4 hypothesis-formation gate.

    Enforces that the LLM brain-step (prepare_hypothesis_context +
    record_hypotheses) ran when the investigation produced meaningful
    evidence. Threshold 
        confirmed_count >= 1  OR  findings_count >= 25  OR  sigma_hunt success.
    Below that threshold (triage-only runs) the gate is a no-op.

    Escape hatch: SAVVYDFIR_SKIP_HYPOTHESIS_GATE=1 in env bypasses the
    gate AND writes an audit-visible row recording the bypass + reason.
    Per requirement: no silent weakening.

    Returns:
        {"status": "ok"}  - gate passed or below threshold or bypassed
        {"status": "needs_hypothesis", "reason": ..., "next_required_tool": ...,
         "allow_partial_hint": True}  - block generate_report
    """
    # Triage-only threshold
    sigma_ok = bool(
        sigma_result
        and (
            sigma_result.get("status") == "ok"
            or sigma_result.get("exit_code") == 0
            or (sigma_result.get("total_hits") or 0) > 0
        )
    )
    meaningful_evidence = (
        confirmed_count >= 1
        or findings_count >= 25
        or sigma_ok
    )
    if not meaningful_evidence:
        return {"status": "ok", "reason": "below_evidence_threshold"}

    # Escape hatch - audit-visible, never silent
    if os.environ.get("SAVVYDFIR_SKIP_HYPOTHESIS_GATE") == "1":
        try:
            scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
            import sys as _sys
            if str(scripts_dir) not in _sys.path:
                _sys.path.insert(0, str(scripts_dir))
            from delegation_ledger import write_event as _ledger_write
            _ledger_write({
                "event_type": "hypothesis_gate_bypassed",
                "case_id": case_id,
                "reason": "SAVVYDFIR_SKIP_HYPOTHESIS_GATE=1",
                "findings_count": findings_count,
                "confirmed_count": confirmed_count,
                "sigma_ok": sigma_ok,
            })
        except Exception:
            pass
        return {
            "status": "ok",
            "reason": "bypassed_via_env_var",
            "bypass_audited": True,
        }

    # Check actual hypotheses
    try:
        hypotheses = state_manager.get_hypotheses() or []
    except Exception:
        hypotheses = []
    if len(hypotheses) > 0:
        return {"status": "ok", "hypothesis_count": len(hypotheses)}

    return {
        "status": "needs_hypothesis",
        "tool": "evaluate_hypothesis_gate",
        "case_id": case_id,
        "reason": (
            "Phase 4 (AI Hypothesis Formation) was skipped. The investigation produced "
            f"meaningful evidence (findings={findings_count}, confirmed={confirmed_count}, "
            f"sigma_ok={sigma_ok}) but state.hypotheses is empty. Per W1.7 (CR-revised "
            "2026-05-23): call prepare_hypothesis_context(case_id) to receive the "
            "bundle, then record_hypotheses(case_id, hypotheses=[...]) with 2-5 ranked "
            "hypotheses before generate_report. Bypass for emergency demo recovery: "
            "set SAVVYDFIR_SKIP_HYPOTHESIS_GATE=1 (audit-logged)."
        ),
        "next_required_tool": "prepare_hypothesis_context",
        "next_required_tool_chain": ["prepare_hypothesis_context", "record_hypotheses"],
        "allow_partial_hint": True,
    }


def evaluate_investigation_success_gate(
    case_id: str,
    state_manager: Any,
) -> dict[str, Any]:
    """Phase 5: per-lane specialist contribution audit.

    Reads two signals:
      1. ``audit.jsonl`` (state.submit_finding events grouped by ``assigned_agent``)
      2. ``/tmp/savvydfir_delegation_ledger.jsonl`` (repair_succeeded as fallback
         coverage, plus path_b_would_allow + main-agent add_finding for Path B
         lanes)

    For each lane in ``_SPECIALIST_REQUIRED_LANES``:
      * Pass if ≥1 ``submit_finding`` row from the expected specialist for that lane
      * Pass if ≥1 ``repair_succeeded`` ledger row for the lane (json-repair salvaged
        findings from a truncated specialist response)
      * Pass if a ``path_b_would_allow`` ledger row exists AND main-agent has
        ``add_finding`` calls attributable to that lane
      * Otherwise FAIL with reason ``"specialist_contribution_missing"``

    Returns:
        {
          "status": "ok"  if all lanes pass,
          "status": "needs_specialist_contribution"  if any lane fails,
          "missing_lanes": [
            {"lane_id": "...", "expected_specialists": [...], "reason": "..."},
            ...
          ],
          "lane_contributions": {
            "<lane_id>": {"submit_findings": int, "repair_succeeded": int,
                          "path_b_allow": bool, "passed": bool},
            ...
          },
        }

    The Phase 1 ``submit_finding`` provenance is the primary signal. This gate
    DEPENDS on Phase 1 - without ``assigned_agent`` on findings, we can't tell
    which specialist registered them.
    """
    # Import here to avoid module-level state dependencies.
    audit_rows = _read_audit_jsonl(state_manager)
    ledger_rows = _read_ledger_for_case(case_id)
    expected_lane_agents = EXPECTED_LANE_AGENTS

    # Count submit_finding events grouped by (lane_id, assigned_agent).
    # Each audit row for state.submit_finding carries parameters with both.
    submit_by_lane: dict[str, dict[str, int]] = {}
    for row in audit_rows:
        if row.get("tool") != "state.submit_finding":
            continue
        if row.get("event_type") not in {"started", "completed", None}:
            continue
        params = row.get("parameters") or {}
        if not isinstance(params, dict):
            continue
        lane_id = str(params.get("lane_id") or "").strip()
        agent = str(params.get("assigned_agent") or "").strip().lstrip("@")
        if not lane_id or not agent:
            continue
        submit_by_lane.setdefault(lane_id, {}).setdefault(agent, 0)
        submit_by_lane[lane_id][agent] += 1

    # Count repair_succeeded events per lane (fallback coverage).
    repair_by_lane: dict[str, int] = {}
    for r in ledger_rows:
        if r.get("event") == "repair_succeeded":
            lane = str(r.get("lane_id") or "").strip()
            if lane:
                repair_by_lane[lane] = repair_by_lane.get(lane, 0) + 1

    # Path B allowance markers per lane (means main-agent inline was legitimate).
    path_b_allowed_lanes: set[str] = set()
    for r in ledger_rows:
        if r.get("event") == "path_b_would_allow":
            lane = str(r.get("lane_id") or "").strip()
            if lane:
                path_b_allowed_lanes.add(lane)

    # Detect main-agent add_finding calls per lane (for Path B coverage gate).
    main_agent_findings_by_lane: dict[str, int] = {}
    try:
        for f in state_manager.get_findings():
            if not isinstance(f, dict):
                continue
            # If a finding came via state.add_finding (NOT submit_finding) AND
            # has no assigned_agent, it's main-agent inline. We attribute it to
            # whatever lane it was recorded against via raw_evidence_refs or
            # by inferring from the finding's tool_name+content. For the gate
            # we accept ANY add_finding call as Path B coverage for ANY lane
            # the ledger marked path_b_would_allow.
            tool_name = str(f.get("tool_name") or "").strip()
            assigned = (f.get("assigned_agent") or "")
            if tool_name == "state.add_finding" and not assigned:
                # We can't reliably tie this to a specific lane without lane_id
                # on add_finding (the existing tool doesn't accept lane_id).
                # As a heuristic, count it once per Path-B-allowed lane.
                for lane in path_b_allowed_lanes:
                    main_agent_findings_by_lane[lane] = (
                        main_agent_findings_by_lane.get(lane, 0) + 1
                    )
                break  # one match per finding is enough for the gate signal
    except Exception:
        pass

    # W1.7.11 (CR13 Option X) - Main-agent runtime query path (NEW primary).
    # The W1.6.1 architecture made main-agent inline analysis the PRIMARY
    # path. Per CR13: when a lane has been recorded via record_analysis_lane
    # with assigned_agent='main-agent' AND has ≥1 finding with a resolvable
    # execution_id, that satisfies the gate without needing specialist
    # provenance or Path B failure-fallback evidence.
    main_agent_runtime_query_by_lane: dict[str, int] = {}
    try:
        # Index existing execution IDs for quick membership check
        existing_eids: set[str] = set()
        for ex in state_manager.get_executions():
            eid = ex.get("execution_id")
            if eid:
                existing_eids.add(str(eid))

        # Lanes claimed by main-agent via record_analysis_lane
        for lane in state_manager.get_analysis_lanes():
            lane_id = str(lane.get("lane_id") or "").strip()
            assigned = str(lane.get("assigned_agent") or "").strip().lower()
            status = str(lane.get("status") or "").strip().upper()
            if not lane_id or assigned not in {"main-agent", "main"}:
                continue
            if status not in {"COMPLETE", "COMPLETE_WITH_GAPS"}:
                continue
            # Count findings referenced by the lane that have resolvable eids
            finding_ids = lane.get("finding_ids") or []
            findings_with_eid = 0
            for f in state_manager.get_findings():
                if f.get("finding_id") in finding_ids:
                    eid = str(f.get("execution_id") or "")
                    if eid and eid in existing_eids and eid != "E-000":
                        findings_with_eid += 1
            if findings_with_eid > 0:
                main_agent_runtime_query_by_lane[lane_id] = findings_with_eid
    except Exception:
        pass

    lane_contributions: dict[str, dict[str, Any]] = {}
    missing_lanes: list[dict[str, Any]] = []

    # Memory-conditional (review 2026-06-05): on a disk-only case (no memory
    # image in the manifest) the memory lane is an auto-recorded documented-absence
    # lane and cannot contribute findings. Skip its specialist-contribution audit so
    # a legitimately memory-less case is not failed here. Case-agnostic: keyed on the
    # frozen memory_present flag; default True keeps every memory case unchanged.
    try:
        _memory_present = bool(state_manager.get_memory_present())
    except Exception:
        _memory_present = True

    for lane_id in _SPECIALIST_REQUIRED_LANES:
        if lane_id == "memory" and not _memory_present:
            lane_contributions[lane_id] = {
                "passed": True,
                "reason": "memory_not_in_scope_disk_only_case",
            }
            continue
        expected = list(expected_lane_agents.get(lane_id, ()))
        # Path A success: any expected specialist registered ≥1 finding.
        path_a_hits = {
            agent: submit_by_lane.get(lane_id, {}).get(agent, 0)
            for agent in expected
        }
        path_a_pass = sum(path_a_hits.values()) > 0

        repair_count = repair_by_lane.get(lane_id, 0)
        repair_pass = repair_count > 0

        path_b_pass = (
            lane_id in path_b_allowed_lanes
            and main_agent_findings_by_lane.get(lane_id, 0) > 0
        )

        # W1.7.11: NEW primary path - main-agent recorded the lane with
        # at least one finding linked to a real execution. This is the
        # default architecture per W1.6.1, NOT a fallback.
        runtime_query_count = main_agent_runtime_query_by_lane.get(lane_id, 0)
        runtime_query_pass = runtime_query_count > 0

        passed = runtime_query_pass or path_a_pass or repair_pass or path_b_pass
        lane_contributions[lane_id] = {
            "expected_specialists": expected,
            "submit_findings_by_specialist": path_a_hits,
            "repair_succeeded": repair_count,
            "path_b_would_allow": lane_id in path_b_allowed_lanes,
            "main_agent_inline_findings": main_agent_findings_by_lane.get(lane_id, 0),
            "main_agent_runtime_query_findings": runtime_query_count,
            "passed": passed,
            "pass_reason": (
                # Order reflects priority: main-agent inline is PRIMARY in
                # the W1.6.1 architecture, specialist is opt-in escape.
                "main_agent_runtime_query" if runtime_query_pass else
                "specialist_submit_finding" if path_a_pass else
                "repair_succeeded_salvage" if repair_pass else
                "path_b_allowance_with_inline_findings" if path_b_pass else
                "missing"
            ),
        }
        if not passed:
            missing_lanes.append({
                "lane_id": lane_id,
                "expected_specialists": expected,
                "reason": (
                    "lane_contribution_missing - no main-agent lane record "
                    "with linked execution_id findings, no specialist "
                    "submit_finding, no repair_succeeded fallback, no "
                    "Path B allowance with inline findings."
                ),
            })

    if missing_lanes:
        return {
            "status": "needs_specialist_contribution",
            "tool": "investigation_success_gate",
            "case_id": case_id,
            "missing_lanes": missing_lanes,
            "lane_contributions": lane_contributions,
            "reason": (
                "One or more specialist lanes received no analyst contribution. "
                f"Lanes missing: {[m['lane_id'] for m in missing_lanes]}. "
                "Spawn the expected specialist(s) for those lanes via Task, OR "
                "if Path B was used, record a path_b_would_allow ledger row + "
                "add_finding calls. Call generate_report(case_id, allow_partial=True) "
                "to ship a report labeled as missing specialist contribution - "
                "NOT court-defensible without first-pass specialist coverage."
            ),
            "allow_partial_hint": True,
        }

    return {
        "status": "ok",
        "tool": "investigation_success_gate",
        "case_id": case_id,
        "lane_contributions": lane_contributions,
    }


def _count_correction_events(state_manager: Any) -> int:
    """Count CorrectionEvent rows in audit.jsonl for the current case.

    Run-11 polish - surfaces the W1.5 criterion-#1 tiebreaker signal
    (self-correction count) into the report metrics grid. The canonical
    predicate is ``row.get("correction_event") is not None`` per
    ``sift_mcp/audit.py:171`` where the field defaults to None and is set
    only when an execution produced a structural correction. Reuses the
    existing ``_read_audit_jsonl`` iterator so no new file path resolution
    is introduced. Returns 0 if audit.jsonl is missing or unreadable.
    """
    rows = _read_audit_jsonl(state_manager)
    if not rows:
        return 0
    return sum(1 for row in rows if isinstance(row, dict) and row.get("correction_event") is not None)


def _read_audit_jsonl(state_manager: Any) -> list[dict[str, Any]]:
    """Best-effort read of audit.jsonl alongside the state file."""
    try:
        state_path = getattr(state_manager, "_state_path", None)
        if not state_path:
            return []
        audit_path = Path(state_path).resolve().parent / "audit.jsonl"
        if not audit_path.is_file():
            return []
        rows = []
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows
    except Exception:
        return []


def _read_ledger_for_case(case_id: str) -> list[dict[str, Any]]:
    """Best-effort read of /tmp/savvydfir_delegation_ledger.jsonl filtered
    by case_id (when present in extra) - Phase 5 fallback signal."""
    try:
        ledger_path = Path(
            os.environ.get(
                "SAVVYDFIR_DELEGATION_LEDGER",
                "/tmp/savvydfir_delegation_ledger.jsonl",
            )
        )
        if not ledger_path.is_file():
            return []
        rows = []
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            # If the row carries case_id, filter; otherwise keep (session-scoped).
            row_case = row.get("case_id")
            if row_case and row_case != case_id:
                continue
            rows.append(row)
        return rows
    except Exception:
        return []


def _status_label(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


# Status precedence: CONFIRMED findings surface first, then HYPOTHESIS → OBSERVATION.
# REJECTED findings are demoted to last.
_STATUS_PRECEDENCE: dict[str, int] = {
    "CONFIRMED": 4,
    "HYPOTHESIS": 3,
    "ACTIVE": 2,
    "OBSERVATION": 1,
    "REJECTED": 0,
}


def _short_description(value: Any, limit: int = 140) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    cut = text[: limit - 3]
    # Rewind to last whitespace ONLY if it sits past the half-limit floor.
    # Long single-token strings (hashes, paths, registry keys, IDs) fall
    # through to the original hard cut so they never collapse to just "...".
    last_space = cut.rfind(" ")
    if last_space >= limit // 2:
        cut = cut[:last_space]
    return cut + "..."


def _rank_findings(findings: list[dict[str, Any]], *, limit: int = 25) -> list[dict[str, Any]]:
    """Rank findings for the report. W1.7 (CR13-5): TTP-first ordering per
    Pyramid of Pain - findings carrying MITRE techniques rank above raw IOCs.

    Sort key (descending priority):
        1. Status precedence (CONFIRMED > HYPOTHESIS > ACTIVE > OBSERVATION)
        2. has_mitre_techniques (TTP-bearing > IOC-only)
        3. has_heuristic_context_refs (heuristic-cited > uncited)
        4. confidence
        5. recency
    """
    findings = [
        finding for finding in findings
        if str(finding.get("finding_kind") or "validated").lower() != "raw_detector_hit"
    ]

    def _has_mitre(finding: dict[str, Any]) -> int:
        techs = finding.get("mitre_techniques") or finding.get("mitre_technique")
        if isinstance(techs, str):
            return 1 if techs.strip() else 0
        if isinstance(techs, list):
            return 1 if any(str(t).strip() for t in techs) else 0
        return 0

    def _has_heuristic_refs(finding: dict[str, Any]) -> int:
        refs = finding.get("heuristic_context_refs") or []
        return 1 if (isinstance(refs, list) and refs) else 0

    def _sort_key(finding: dict[str, Any]) -> tuple[int, int, int, float, str]:
        status = _status_label(finding.get("finding_status"))
        precedence = _STATUS_PRECEDENCE.get(status, 1)
        confidence = float(finding.get("confidence", 0.0) or 0.0)
        recency = str(finding.get("updated_at") or finding.get("created_at") or "")
        return (precedence, _has_mitre(finding), _has_heuristic_refs(finding), confidence, recency)

    ranked = sorted(findings, key=_sort_key, reverse=True)
    return [dict(finding) for finding in ranked[:limit]]


def _split_findings_by_status(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Bucket findings by normalized status."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        status = _status_label(f.get("finding_status"))
        buckets.setdefault(status, []).append(f)
    return buckets


def _count_by_key(
    findings: list[dict[str, Any]], key: str,
) -> dict[str, int]:
    """Count findings grouped by a given key field."""
    counts: dict[str, int] = {}
    for f in findings:
        val = str(f.get(key) or "UNKNOWN").upper()
        counts[val] = counts.get(val, 0) + 1
    return counts


def _finding_quality_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Clarify raw finding counts versus reportable investigation claims."""
    status_breakdown = _count_by_key(findings, "finding_status")
    kind_breakdown = _count_by_key(findings, "finding_kind")
    reportable_statuses = {"CONFIRMED", "HYPOTHESIS", "ACTIVE"}
    raw_detector_hits = kind_breakdown.get("RAW_DETECTOR_HIT", 0)
    reportable_count = sum(
        1
        for finding in findings
        if (
            _status_label(finding.get("finding_status")) in reportable_statuses
            and str(finding.get("finding_kind") or "validated").lower() != "raw_detector_hit"
        )
    )
    return {
        "raw_persisted_findings": len(findings),
        "raw_detector_hits": raw_detector_hits,
        "reportable_findings": reportable_count,
        "confirmed_findings": status_breakdown.get("CONFIRMED", 0),
        "active_or_hypothesis_findings": (
            status_breakdown.get("ACTIVE", 0) + status_breakdown.get("HYPOTHESIS", 0)
        ),
        "rejected_findings": status_breakdown.get("REJECTED", 0),
        "semantics": (
            "findings_count is the raw persisted finding-record count. "
            "It is not a de-duplicated incident count. Sigma and other detector "
            "observations can be stored as raw_detector_hit records; use "
            "reportable_findings, raw_detector_hits, and status_breakdown for "
            "investigation quality."
        ),
    }


def _render_findings_rows(
    findings: list[dict[str, Any]],
    evidence_col: str = "tool",
) -> str:
    """Render finding rows for a report table.

    ``evidence_col`` controls the third-from-last column:
      * ``"tool"`` (default) - shows ``tool_name``; used by Top Active Leads.
      * ``"corroborated_by"`` - shows comma-joined ``F-NNN`` IDs; used by Top
        Confirmed Findings to surface the multi-source corroboration that
        the framework's self-correction story rests on.
    Unknown values fall back to the tool column for safety.
    """
    rows: list[str] = []
    for finding in findings:
        if evidence_col == "corroborated_by":
            corroborated = finding.get("corroborated_by") or []
            evidence_cell = ", ".join(str(x) for x in corroborated) if corroborated else "-"
        else:
            evidence_cell = str(finding.get("tool_name", ""))
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('finding_id', '')))}</td>"
            f"<td>{html.escape(_status_label(finding.get('finding_status')))}</td>"
            f"<td>{float(finding.get('confidence', 0.0) or 0.0):.3f}</td>"
            f"<td>{html.escape(evidence_cell)}</td>"
            f"<td>{html.escape(_short_description(finding.get('description', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='5'>No findings recorded.</td></tr>"


def _render_tactic_tags(tactics: list[dict[str, Any]], *, class_name: str) -> str:
    if not tactics:
        return "<span class='tag muted'>None</span>"
    return "".join(
        f"<span class='tag {class_name}'>{html.escape(tactic['id'])} - {html.escape(tactic['name'])}</span>"
        for tactic in tactics
    )


def _render_suggested_tools(suggestions: dict[str, list[str]]) -> str:
    if not suggestions:
        return "<li>No additional ATT&amp;CK blind-spot follow-up suggested.</li>"
    items: list[str] = []
    for tactic_id, tools in suggestions.items():
        items.append(
            f"<li><strong>{html.escape(tactic_id)}</strong>: {html.escape(', '.join(tools))}</li>"
        )
    return "\n".join(items)


def _render_leads(leads: list[dict[str, Any]]) -> str:
    if not leads:
        return "<tr><td colspan='5'>No actionable leads recorded.</td></tr>"
    rows: list[str] = []
    for lead in leads[:25]:
        pivot = lead.get("next_pivot") if isinstance(lead.get("next_pivot"), dict) else {}
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(lead.get('severity', '')))}</td>"
            f"<td>{html.escape(str(lead.get('detector', '')))}</td>"
            f"<td>{float(lead.get('confidence', 0.0) or 0.0):.2f}</td>"
            f"<td>{html.escape(_short_description(lead.get('description', ''), 180))}</td>"
            f"<td>{html.escape(str(pivot.get('human_readable') or ''))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_warning_items(items: list[dict[str, Any]]) -> str:
    """Render a list of warning-shaped dicts to <li> rows.

    Handles two label vocabularies (data_gaps + anti_forensics_warnings) and
    falls back to a safe JSON-encoded dump when no message field is present,
    so the rendered HTML never shows a raw ``{'k': 'v'}`` Python repr.
    """
    if not items:
        return "<li>None recorded.</li>"
    rendered: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            rendered.append(f"<li>{html.escape(str(item))}</li>")
            continue
        label = (
            item.get("type")
            or item.get("detector")
            or item.get("artifact_family")
            or item.get("classification")
            or "warning"
        )
        message = (
            item.get("message")
            or item.get("description")
            or item.get("reason")
        )
        if message is None:
            message = json.dumps(item, sort_keys=True, default=str)
        rendered.append(
            f"<li><strong>{html.escape(str(label))}</strong>: "
            f"{html.escape(str(message))}</li>"
        )
    return "".join(rendered)


def _render_json_items(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<li>None recorded.</li>"
    return "".join(
        f"<li><pre>{html.escape(json.dumps(item, indent=2, default=str))}</pre></li>"
        for item in items
    )


def _render_lane_rows(lanes: list[dict[str, Any]]) -> str:
    if not lanes:
        return "<tr><td colspan='7'>No analysis lanes recorded.</td></tr>"
    rows: list[str] = []
    for lane in lanes:
        agents = [str(lane.get("assigned_agent") or "")]
        agents.extend(str(agent) for agent in (lane.get("supporting_agents") or []))
        agent_text = ", ".join(agent for agent in agents if agent)
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(lane.get('lane_id') or ''))}</td>"
            f"<td>{html.escape(str(lane.get('status') or ''))}</td>"
            f"<td>{'yes' if lane.get('required') else 'no'}</td>"
            f"<td>{html.escape(agent_text or 'unowned')}</td>"
            f"<td>{len(lane.get('execution_ids', []) or [])}</td>"
            f"<td>{len(lane.get('finding_ids', []) or [])}</td>"
            f"<td>{html.escape(_short_description(lane.get('summary') or '', 180))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


# Closes the hypothesis-driven threat-hunting loop (PEAK/TaHiTI): renders each
# RECORDED hunting hypothesis with its resolved verdict + the finding IDs that
# informed it. Distinct from the finding-level evidence_kind=HYPOTHESIS metric.
# Read-only over the get_hypotheses() snapshot; never mutates state.
# Verdict → (existing .tag modifier class, label). Reuses the report's tag
# palette (covered=green, uncovered=amber, muted=grey) + one added .tag.refuted
# (red) so proven / disproven / inconclusive / unresolved are visually distinct.
_HYPOTHESIS_VERDICT_BADGES: dict[str, tuple[str, str]] = {
    "CONFIRMED":     ("covered",   "CONFIRMED - proven"),
    "REFUTED":       ("refuted",   "REFUTED - disproven"),
    "SUSPENDED":     ("uncovered", "SUSPENDED - inconclusive"),
    "INVESTIGATING": ("muted",     "INVESTIGATING - open"),
    "ACTIVE":        ("muted",     "ACTIVE - unresolved"),
}
_MONO = "font-family: var(--mono)"
_TERMINAL_HYPOTHESIS_STATUSES = {"CONFIRMED", "REFUTED", "SUSPENDED"}


def _count_unresolved_hypotheses(hypotheses: list[dict[str, Any]]) -> int:
    """Count recorded hypotheses still open (not a terminal verdict). The loop
    is 'closed' only when every hypothesis is CONFIRMED/REFUTED/SUSPENDED.
    Surfaced as an honest quality signal (warning + status_flag), NOT a gate
    (v1 Simplicity-First; enforcement gate is the deferred Scope-B hardening)."""
    n = 0
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        if str(h.get("status") or "ACTIVE").upper() not in _TERMINAL_HYPOTHESIS_STATUSES:
            n += 1
    return n


def _render_hypothesis_validation(hypotheses: list[dict[str, Any]]) -> str:
    if not hypotheses:
        return "<tr><td colspan='5'>No hunting hypotheses recorded (triage-only case).</td></tr>"
    rows: list[str] = []
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        hid = str(h.get("hypothesis_id") or "")
        status = str(h.get("status") or "ACTIVE").upper()
        tag_cls, badge_text = _HYPOTHESIS_VERDICT_BADGES.get(
            status, ("muted", html.escape(status))
        )
        # Defensive normalisation - state should be clean, but never assume.
        linked = h.get("related_finding_ids")
        linked = linked if isinstance(linked, list) else ([linked] if linked else [])
        linked_text = ", ".join(html.escape(str(fid)) for fid in linked if fid) or "-"
        techs = h.get("mitre_techniques") or h.get("mitre_technique")
        techs = techs if isinstance(techs, list) else ([techs] if techs else [])
        techs_text = ", ".join(html.escape(str(t)) for t in techs if t) or "-"
        attack = html.escape(str(h.get("attack_class") or "-"))
        rank = h.get("rank")
        rank_text = html.escape(str(rank)) if rank is not None else "-"
        rows.append(
            "<tr>"
            f"<td style='{_MONO}' title='{html.escape(hid)}'>{html.escape(hid)}</td>"
            f"<td>{attack} <span style='color: var(--muted)'>(rank {rank_text})</span></td>"
            f"<td><span class='tag {tag_cls}'>{html.escape(badge_text)}</span></td>"
            f"<td style='{_MONO}'>{linked_text}</td>"
            f"<td>{techs_text}</td>"
            "</tr>"
        )
    return "\n".join(rows)


_LANE_SPECS: dict[str, dict[str, Any]] = {
    "evidence_access": {"title": "Evidence Access", "required": False, "phase": "phase0"},
    "memory": {"title": "Memory Analyst", "required": True, "phase": "analysis"},
    "disk_execution_persistence": {"title": "Disk Execution and Persistence", "required": True, "phase": "analysis"},
    "event_auth": {"title": "Event Log and Auth", "required": True, "phase": "analysis"},
    "anti_forensics_recovery": {"title": "Anti-Forensics and Recovery", "required": True, "phase": "analysis"},
    "timeline_correlation": {"title": "Timeline and Correlation", "required": True, "phase": "analysis"},
    # W1.7 Run-5 fix (BUG-C, proven mechanism 2026-05-24): without this
    # entry, _synthesize_analysis_lanes filters synthesis_corroboration OUT
    # (line ~1700 returns only lanes whose key is in _LANE_SPECS), then
    # update_triage_state replaces the entire array - silently ERASING the
    # main-agent inline synthesis lane from state.json on every generate_report
    # success. Run-5 evidence: E-047 recorded synthesis, audit confirmed,
    # final state.json had only 6 lanes. Adding here fixes the wipe.
    "synthesis_corroboration": {"title": "Synthesis and Corroboration", "required": False, "phase": "synthesis"},
}

EXPECTED_LANE_AGENTS: dict[str, tuple[str, ...]] = {
    "memory": ("memory-analyst",),
    "disk_execution_persistence": (
        "registry-analyst",
        "prefetch-analyst",
        "amcache-analyst",
        "browser-analyst",
    ),
    "event_auth": ("evtx-analyst",),
    "anti_forensics_recovery": (
        "evtx-analyst",
        "sigma-analyst",
        "timeline-analyst",
    ),
    "timeline_correlation": (
        "mft-analyst",
        "sigma-analyst",
        "srum-analyst",
        "timeline-analyst",
    ),
    # Phase 4 - creative cross-artifact synthesis
    # gets its OWN lane. timeline_correlation closes when the artifact
    # specialists finish; synthesis_corroboration runs AFTER, taking all
    # closed lanes as input.
    "synthesis_corroboration": (
        "synthesis-analyst",
        "corroboration-analyst",  # legacy name accepted for backward-compat
    ),
}

_BARE_TOOL_ALIASES: dict[str, str] = {
    "analyze_vss": "disk.analyze_vss",
    "sigma_hunt": "detection.sigma_hunt",
    "sigma_scan": "detection.sigma_scan",
    "query_sigma_results": "detection.query_sigma_results",
    "compare_disk_and_memory": "correlation.compare_disk_and_memory",
    "generate_graph": "graph.generate_graph",
}


def _canonical_tool_name(tool_name: Any) -> str:
    text = str(tool_name or "").strip()
    if not text:
        return ""
    if "." in text:
        return text.lower()
    return _BARE_TOOL_ALIASES.get(text, text).lower()


def _lane_template(lane_id: str, *, legacy_inferred: bool = False) -> dict[str, Any]:
    spec = _LANE_SPECS.get(lane_id, {})
    return {
        "lane_id": lane_id,
        "title": spec.get("title", lane_id.replace("_", " ").title()),
        "status": "UNKNOWN" if legacy_inferred else "PENDING",
        "required": bool(spec.get("required", True)),
        "legacy_inferred": legacy_inferred,
        "phase": spec.get("phase", "analysis"),
        "assigned_agent": None,
        "supporting_agents": [],
        "summary": "",
        "lane_inference_confidence": "low" if legacy_inferred else None,
        "execution_ids": [],
        "finding_ids": [],
        "related_lane_ids": [],
        "data_gaps": [],
        "anti_forensics_warnings": [],
        "next_pivots": [],
        "started_at": None,
        "completed_at": None,
    }


def _infer_lane_from_tool_name(tool_name: Any) -> str | None:
    canonical = _canonical_tool_name(tool_name)
    if not canonical:
        return None
    if canonical.startswith("memory."):
        return "memory"
    if canonical in {
        "disk.extract_mft_timeline",
        "disk.extract_prefetch",
        "disk.get_amcache",
        "disk.extract_shimcache",
        "disk.extract_registry_run_keys",
        "disk.extract_pca",
        "disk.extract_srum",
        "disk.extract_scheduled_tasks",
        "disk.extract_recycle_bin",
        "disk.extract_powershell_history",
    }:
        return "disk_execution_persistence"
    if canonical in {
        "disk.summarize_evtx",
        "detection.sigma_hunt",
        "detection.sigma_scan",
        "detection.query_sigma_results",
    }:
        return "event_auth"
    if canonical == "disk.analyze_vss":
        return "anti_forensics_recovery"
    if canonical.startswith("correlation.") or canonical.startswith("timeline.") or canonical.startswith("graph."):
        return "timeline_correlation"
    return None


def _infer_lane_from_finding(finding: dict[str, Any]) -> tuple[str | None, str | None]:
    finding_type = str(finding.get("finding_type") or "").lower()
    description = str(finding.get("description") or "").lower()
    if finding_type == "anti_forensics_recovery" or any(token in description for token in ("shadow cop", "log clear", "empty log", "wiped")):
        return "anti_forensics_recovery", "medium"
    lane_id = _infer_lane_from_tool_name(finding.get("tool_name"))
    if lane_id:
        return lane_id, "high"
    if any(token in description for token in ("scheduled task", "services.xml", "gpo", "run key", "timestomp")):
        return "disk_execution_persistence", "medium"
    if any(token in description for token in ("winrm", "lateral movement", "connection", "c2", "netscan")):
        return "timeline_correlation", "medium"
    return None, None


def classify_missing_artifact_record(
    *,
    artifact_family: str,
    is_mandatory: bool,
    exists: bool | None = None,
    parser_succeeded: bool | None = None,
    record_count: int | None = None,
    file_size_bytes: int | None = None,
    corroborating_signals: list[str] | None = None,
    reason: str | None = None,
    lane_id: str | None = None,
) -> dict[str, Any]:
    signals = [str(signal) for signal in (corroborating_signals or []) if str(signal).strip()]
    classification = "unknown"
    if exists is False:
        classification = "not_collected" if is_mandatory else "outside_manifest_scope"
    elif parser_succeeded is False:
        classification = "parser_failed"
    elif record_count == 0 or (file_size_bytes is not None and file_size_bytes < 131072):
        classification = "wiped" if signals else "empty"
    elif exists and parser_succeeded:
        classification = "present"
    return {
        "artifact_family": artifact_family,
        "classification": classification,
        "reason": reason or "",
        "lane_id": lane_id,
        "corroborating_signals": signals,
    }


def _merge_warning_lists(*collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for collection in collections:
        for item in collection:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("type") or item.get("detector") or item.get("classification") or ""),
                str(item.get("message") or item.get("description") or item.get("reason") or ""),
                str(item.get("lane_id") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
    return merged


MANDATORY_DISK_TOOL_SUFFIXES = frozenset({
    "extract_mft_timeline",
    "extract_usn_journal",
    "summarize_evtx",
    "extract_registry_run_keys",
    "get_amcache",
    "extract_prefetch",
    "extract_shimcache",
    "extract_srum",
})
MANDATORY_MEMORY_TOOL_SUFFIXES = frozenset({
    "list_processes",
    "scan_processes",
    "scan_network",
})

# ---------------------------------------------------------------------------
# Taxonomy-conditional file-access bundle (review 2026-06-03, signed).
#
# The 8 file-access / navigation extractors are NOT unconditional baseline (they
# stay OUT of MANDATORY_DISK_TOOL_SUFFIXES). They become REQUIRED as a CONDITIONAL
# OVERLAY when the case taxonomy says "which files/folders did the subject access"
# is a core question -- keyed on investigative_taxonomy.dispute_type (+ Windows in
# scope), a structured field present for every case. Case-agnostic: no host/IOC/
# scenario anywhere. Documented-absence (escape A) keeps non-Windows/mount-less
# cases from bricking.
# ---------------------------------------------------------------------------
# FILE_ACCESS_TOOL_SUFFIXES is now imported (derived) from analysis_debt.py above.
_FILE_ACCESS_DISPUTE_TYPES = frozenset({
    "intrusion_response",
    "data_exfiltration",
    "insider_threat",
    "financial_fraud",
    "policy_violation",
    "ransomware",
})
# Documented-absence tokens that SATISFY the gate (tool ran, evidence legitimately
# absent). collection_failed / partial_collection are NOT here -- they are real
# gaps that must block/retry.
_FILE_ACCESS_ABSENCE_TOKENS = (
    "no_windows_volume_at_image_path",
    "artifact_absent",
    "no_data",
    # tool_incompatible: the artifact is present but this parser cannot read its
    # format (e.g. legacy INFO2 recycle bin vs the modern $I parser). A documented
    # non-applicability -> satisfies the gate (already in analysis_debt._ABSENCE_TOKENS).
    "tool_incompatible",
    # F-B (review 2026-06-04): a genuine timeout is an honest attempt with
    # a documented gap -> do not hard-block the report; surface it as a data gap.
    "collection_timeout",
)
_FILE_ACCESS_SELECTOR_VERSION = 1


def windows_in_scope(os_in_scope: Any) -> bool:
    """Normalized, type-guarded 'is Windows in scope' predicate.

    Accepts a list/str/None. Returns True iff any entry contains 'windows'
    (case-insensitive) -- handles 'Windows 10/11', 'Windows Server 2019/2022'.
    Missing/malformed -> False (fail-closed on the OS axis; do NOT infer Windows
    from mount paths here).
    """
    if isinstance(os_in_scope, str):
        return "windows" in os_in_scope.lower()
    if isinstance(os_in_scope, (list, tuple)):
        return any(isinstance(o, str) and "windows" in o.lower() for o in os_in_scope)
    return False


def file_access_required(taxonomy: Optional[dict[str, Any]]) -> bool:
    """True iff the file-access bundle is REQUIRED for this case's taxonomy.

    dispute_type in the file-centric set AND Windows in scope. Missing/unknown
    dispute_type -> False (no bundle; fail-open on the dispute axis).
    """
    t = taxonomy or {}
    dispute = str(t.get("dispute_type", "") or "").strip().lower()
    return dispute in _FILE_ACCESS_DISPUTE_TYPES and windows_in_scope(t.get("os_in_scope"))


def build_file_access_selector_snapshot(taxonomy: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Frozen selector snapshot persisted at start_investigation so the report-time
    gate keys on a stable decision, not a possibly-edited live manifest."""
    t = taxonomy or {}
    return {
        "dispute_type": str(t.get("dispute_type", "") or ""),
        "windows_in_scope": windows_in_scope(t.get("os_in_scope")),
        "file_access_bundle_required": file_access_required(t),
        "selector_version": _FILE_ACCESS_SELECTOR_VERSION,
    }
_COVERAGE_SUFFIX_LANES: dict[str, str] = {
    "list_processes": "memory",
    "scan_processes": "memory",
    "scan_network": "memory",
    "detect_injection": "memory",
    "list_dlls": "memory",
    "extract_mft_timeline": "timeline_correlation",
    "summarize_evtx": "event_auth",
    "extract_registry_run_keys": "disk_execution_persistence",
    "get_amcache": "disk_execution_persistence",
    "extract_prefetch": "disk_execution_persistence",
    "analyze_vss": "anti_forensics_recovery",
    "extract_shimcache": "disk_execution_persistence",
    "extract_srum": "timeline_correlation",
}
_EXTENDED_ANTI_FORENSICS_PATTERNS = (
    "1102",
    "104",
    "wevtutil",
    "sdelete",
    "cipher /w",
    "cipher ",
    "clearing event",
    "event log was cleared",
    "audit log was cleared",
    "cleared the security log",
)


def _execution_tool_suffix(tool_name: str) -> str:
    tn = str(tool_name or "").strip()
    if "." in tn:
        return tn.rsplit(".", 1)[-1]
    return tn


def _collect_execution_suffixes(executions: list[dict[str, Any]]) -> set[str]:
    return {_execution_tool_suffix(e.get("tool_name")) for e in executions}


def _needs_detect_injection(findings: list[dict[str, Any]]) -> bool:
    """Demand detect_injection when:
    - any finding records psscan_only_count > 0 (verified hidden PIDs), OR
    - requires_deeper_analysis is explicitly True, OR
    - psscan ran without a pslist baseline AND a later pslist is now
      available - recompute the delta from current state and demand
      detect_injection if real hidden PIDs surface.

    round-7 P2: prior implementation forced detect_injection on
    every run because scan_processes set psscan_only_count = len(psscan_pids)
    when pslist absent. Now scan_processes records psscan_unverified=True
    + psscan_pids list, and this gate recomputes the real delta when both
    artifacts are present.
    """
    # Collect any unverified psscan finding's PID list, and any pslist
    # PID list from a list_processes finding.
    unverified_psscan: list[set[int]] = []
    pslist_pid_sets: list[set[int]] = []
    for f in findings:
        try:
            if int(f.get("psscan_only_count") or 0) > 0:
                return True
        except (TypeError, ValueError):
            pass
        if f.get("requires_deeper_analysis") is True:
            return True
        if f.get("psscan_unverified") is True:
            pids = f.get("psscan_pids") or []
            if isinstance(pids, list):
                unverified_psscan.append({int(p) for p in pids if str(p).isdigit()})
        pslist_pids = f.get("pslist_pids") or []
        if isinstance(pslist_pids, list) and pslist_pids:
            pslist_pid_sets.append({int(p) for p in pslist_pids if str(p).isdigit()})

    # Recompute on the fly: if any unverified psscan has PIDs not in any
    # known pslist set, demand detect_injection now.
    if unverified_psscan and pslist_pid_sets:
        merged_pslist = set().union(*pslist_pid_sets)
        for psscan in unverified_psscan:
            if psscan - merged_pslist:
                return True
    return False


def _needs_list_dlls(findings: list[dict[str, Any]]) -> bool:
    """Backwards-compatible boolean version. Prefer _list_dlls_missing_pids
    when you need to know which specific PIDs lack coverage."""
    return bool(_list_dlls_missing_pids(findings))


def _list_dlls_missing_pids(findings: list[dict[str, Any]]) -> list[int]:
    """E.2: return PIDs that need list_dlls but
    haven't been covered yet.

    Required PIDs = union of every finding's network_followup_pids /
    network_pids (PIDs flagged by netscan as needing DLL follow-up).
    Covered PIDs = every finding's dlllist_covered_pid (set by list_dlls).
    Missing = required - covered.

    Prior implementation only checked whether ANY list_dlls execution
    existed, so running list_dlls on PID 1234 falsely satisfied the gate
    for PIDs 5678 and 9999 too.
    """
    # Kernel pseudo-processes (0 = System Idle, 4 = System) can NEVER have
    # user-mode DLLs enumerated; list_dlls on them is impossible. A network
    # socket Volatility could not attribute to a real process lands on PID 0,
    # which previously made the coverage gate demand an impossible
    # list_dlls(0) -> report blocked forever (LONEWOLF run, 2026-06-05).
    # Universal Windows truth -> case-agnostic exclusion.
    _KERNEL_PSEUDO_PIDS = frozenset({0, 4})
    required: set[int] = set()
    covered: set[int] = set()
    for f in findings:
        pids = f.get("network_followup_pids") or f.get("network_pids") or []
        if isinstance(pids, list):
            for p in pids:
                try:
                    pid_int = int(p)
                except (TypeError, ValueError):
                    continue
                if pid_int in _KERNEL_PSEUDO_PIDS:
                    continue  # idle/System: not a real process, can't list DLLs
                required.add(pid_int)
        covered_pid = f.get("dlllist_covered_pid")
        if covered_pid is not None:
            try:
                covered.add(int(covered_pid))
            except (TypeError, ValueError):
                pass
    return sorted(required - covered)


def _execution_was_successful(ex: dict[str, Any]) -> bool:
    """Universal success predicate for an execution record.

    Used by every mandatory-tool check, not just sigma_hunt. review
    round-2 #M2: prior implementation only required tool suffix presence,
    meaning a failed parser counted toward coverage.
    """
    try:
        exit_code = ex.get("exit_code")
        if exit_code is None:
            return False
        if int(exit_code) != 0:
            return False
    except (TypeError, ValueError):
        return False
    try:
        duration = float(ex.get("duration_seconds") or 0.0)
    except (TypeError, ValueError):
        duration = 0.0
    if duration <= 0.0:
        return False
    if not ex.get("audit_completed_entry_hash"):
        return False
    return True


def _has_successful_execution(executions: list[dict[str, Any]], tool_suffix: str) -> bool:
    """Return True iff at least one execution of the named tool succeeded.

    `tool_suffix` is the bare suffix (e.g. "list_processes", "sigma_hunt"),
    matching the `_collect_execution_suffixes` convention used elsewhere
    in this module.
    """
    for ex in executions:
        tool = str(ex.get("tool_name") or "")
        if tool != tool_suffix and not tool.endswith(f".{tool_suffix}"):
            continue
        if _execution_was_successful(ex):
            return True
    return False


def _needs_sigma_hunt_run(executions: list[dict[str, Any]]) -> bool:
    """sigma_scan != sigma_hunt. Bypass-resistant check.

    review round-1 #2: a naive 'tool_name present' check would pass
    for a failed/timed-out/wrong-input/zero-output sigma_hunt run.

    review round-2 #H: the prior shipped check missed the durable-
    output invariant. A successful sigma_hunt without a readable Chainsaw
    JSON at the recorded output_path means there is no rule-engine evidence
    for the report or specialists to corroborate.

    A run satisfies the gate only when ALL of these hold for at least one
    matching execution record:
      - tool_name matches detection.sigma_hunt (or .endswith(".sigma_hunt"))
      - exit_code == 0
      - duration_seconds > 0 (defends the 0.02s-pattern silent failure)
      - audit_completed_entry_hash is present
      - outputs_summary surfaces a writable JSON output_path (or the
        finding_ids_generated list is non-empty, which only happens when
        sigma_hunt successfully wrote and parsed Chainsaw output)

    Zero detections on a clean system is a valid pass - sigma_hunt's
    correctness is judged by execution success + durable output, not hit
    count.
    """
    for ex in executions:
        tool = str(ex.get("tool_name") or "")
        if not (tool == "detection.sigma_hunt" or tool.endswith(".sigma_hunt")):
            continue
        if not _execution_was_successful(ex):
            continue
        # Durable-output invariant:
        # Substring matching '.json' in outputs_summary was bypassable
        # (prose can claim ".json" without an actual file). Now require
        # structured proof:
        #   - finding_ids_generated is non-empty (sigma_hunt always emits
        #     at least a summary finding on success, even for 0 hits), OR
        #   - explicit output_handle/output_path field is set.
        finding_ids = ex.get("finding_ids_generated") or []
        has_findings = isinstance(finding_ids, list) and len(finding_ids) > 0
        has_output_handle = bool(ex.get("output_handle") or ex.get("output_path"))
        if not (has_findings or has_output_handle):
            continue
        return False  # at least one fully-satisfied run
    return True  # no fully-satisfied sigma_hunt → gate must block


def _needs_build_timeline_run(executions: list[dict[str, Any]]) -> bool:
    """Unconditional check: at least one successful build_timeline required.

    H.2 fix: Plaso super-timeline is mandatory for all IR investigations.
    Reconstructs attacker activity across filesystem, registry, and event logs
    simultaneously. Multi-stage intrusions cannot be reconstructed without it.

    A run satisfies the gate only when ALL of these hold for at least one
    matching execution record:
      - tool_name matches timeline.build_timeline (or .endswith(".build_timeline"))
      - exit_code == 0
      - duration_seconds > 0
      - audit_completed_entry_hash is present
      - storage_path or output_path is set (the .plaso file)
    """
    for ex in executions:
        tool = str(ex.get("tool_name") or "")
        if not (tool == "timeline.build_timeline" or tool.endswith(".build_timeline")):
            continue
        if not _execution_was_successful(ex):
            continue
        # Durable-output invariant: storage_path must exist
        storage_path = ex.get("storage_path") or ex.get("output_path")
        if not storage_path:
            continue
        return False  # at least one fully-satisfied run
    return True  # no fully-satisfied build_timeline → gate must block


def _signals_extended_anti_forensics_coverage(
    findings: list[dict[str, Any]],
    sigma_result: dict[str, Any],
) -> bool:
    if sigma_result.get("anti_forensics_warnings"):
        return True
    for f in findings:
        blob = f"{f.get('description', '')} {f.get('tool_name', '')}".lower()
        if any(p in blob for p in _EXTENDED_ANTI_FORENSICS_PATTERNS):
            return True
    return False


def _coverage_lane_acceptance(
    suffix: str,
    analysis_lanes: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Return the explicit lane record that can satisfy missing tool coverage."""
    lane_id = _COVERAGE_SUFFIX_LANES.get(suffix)
    if not lane_id or not analysis_lanes:
        return None
    for lane in analysis_lanes:
        if not isinstance(lane, dict) or lane.get("lane_id") != lane_id:
            continue
        if str(lane.get("status") or "").upper() not in {"COMPLETE", "COMPLETE_WITH_GAPS"}:
            return None
        if not str(lane.get("assigned_agent") or "").strip():
            return None
        has_evidence = bool(lane.get("execution_ids") or lane.get("finding_ids"))
        if not has_evidence:
            return None
        return lane
    return None


def evaluate_ir_coverage_gate(
    *,
    findings: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    sigma_result: dict[str, Any],
    analysis_lanes: list[dict[str, Any]] | None = None,
    selector: dict[str, Any] | None = None,
    analysis_roots: tuple[str, ...] = (),
    memory_present: bool = True,
) -> dict[str, Any]:
    """Return missing Windows IR tool coverage required before a final report.

    *memory_present* (review 2026-06-05) gates the baseline memory-triage
    requirement. Default True preserves current behavior for every case that has a
    memory image; only a frozen-False (manifest memory_dumps == []) disk-only case
    relaxes it. compare_disk_and_memory stays mandatory regardless (disk-primary
    checks). Case-agnostic: keyed solely on the flag, no case specifics.

    *selector* is the frozen file-access selector snapshot persisted at
    start_investigation (``build_file_access_selector_snapshot``). When it sets
    ``file_access_bundle_required``, the 8 file-access extractors are enforced as
    a CONDITIONAL OVERLAY (escape A: satisfied by successful run OR documented
    absence). When absent/false (legacy state, non-Windows, unknown dispute_type)
    the overlay is off, so old cases never brick.
    """
    suffixes = _collect_execution_suffixes(executions)
    missing: list[dict[str, Any]] = []
    accepted_by_lane: list[dict[str, Any]] = []

    def _file_access_documented_absence(ex: dict[str, Any]) -> bool:
        """Escape A: tool ran and recorded a legitimate-absence outcome. Anchored
        to status=/reason= keys (prefix allowlist), NOT loose substring, so a token
        inside unrelated error prose can't false-satisfy. collection_failed /
        partial_collection are deliberately NOT tokens here (real gaps)."""
        summ = str(ex.get("outputs_summary") or "").lower()
        return any(
            f"status={tok}" in summ or f"reason={tok}" in summ
            for tok in _FILE_ACCESS_ABSENCE_TOKENS
        )

    def _add_file_access(tool: str, suffix: str) -> None:
        if suffix not in suffixes:
            missing.append({
                "tool": tool,
                "classification": "taxonomy_file_access",
                "reason": (
                    "Case taxonomy (dispute_type + Windows in scope) requires file-access / "
                    "navigation coverage; this extractor has no recorded execution. Run it, then "
                    "run_analysis + submit_finding -- or it will record a documented-absence result."
                ),
            })
            return
        candidates = [
            ex for ex in executions
            if (str(ex.get("tool_name") or "") == tool
                or str(ex.get("tool_name") or "").endswith(f".{suffix}"))
        ]
        if not candidates:
            return  # name-match without prefix path - keep presence behavior (legacy fixtures)
        if any(
            _execution_was_successful(ex) or _file_access_documented_absence(ex)
            for ex in candidates
        ):
            return  # satisfied: successful collection OR documented absence
        missing.append({
            "tool": tool,
            "classification": "taxonomy_file_access",
            "reason": (
                f"{tool} ran but neither succeeded nor recorded a documented-absence outcome "
                "(collection_failed / partial_collection are real gaps, not 'no evidence'); "
                "resolve the collection failure or retry."
            ),
        })

    def _add(tool: str, suffix: str, classification: str, reason: str) -> None:
        """round-2 #M2: presence is not enough; require a successful run.

        Falls back to presence-only when an execution record lacks success
        metadata (exit_code/duration/hash) - protects backwards compatibility
        with test fixtures and legacy state.json files that did not populate
        those fields. Real audited executions WILL have them.
        """
        if suffix not in suffixes:
            missing.append({"tool": tool, "classification": classification, "reason": reason})
            return
        # Suffix is present - check if at least one of those executions was
        # success-recorded. If none have the success fields populated, fall
        # back to presence-only to avoid breaking on legacy fixtures.
        candidates = [
            ex for ex in executions
            if (str(ex.get("tool_name") or "") == tool
                or str(ex.get("tool_name") or "").endswith(f".{suffix}"))
        ]
        if not candidates:
            return  # name-match without prefix path - keep presence behavior
        # If ANY candidate has populated success fields, REQUIRE at least
        # one of them to satisfy success. Otherwise (legacy fixture) accept.
        any_with_metadata = any(
            ex.get("exit_code") is not None or ex.get("duration_seconds") is not None
            for ex in candidates
        )
        if any_with_metadata and not any(_execution_was_successful(ex) for ex in candidates):
            missing.append({
                "tool": tool,
                "classification": classification,
                "reason": f"{reason} A prior execution was recorded but did not succeed; retry.",
            })

    # Memory baseline triage is required ONLY when a memory image is in scope
    # (review 2026-06-05). A disk-only case (frozen memory_present=False)
    # cannot run pslist/psscan/netscan; requiring them would brick the report.
    # Default True = unchanged for every memory case.
    if memory_present:
        for suff in ("list_processes", "scan_processes", "scan_network"):
            _add(
                f"memory.{suff}",
                suff,
                "mandatory_memory_baseline",
                "Universal Windows IR memory triage requires pslist, psscan, and netscan.",
            )

    if memory_present and _needs_detect_injection(findings):
        _add(
            "memory.detect_injection",
            "detect_injection",
            "memory_hidden_process_followup",
            "Psscan-only PIDs or requires_deeper_analysis; run detect_injection on the dump.",
        )
    missing_dll_pids = _list_dlls_missing_pids(findings) if memory_present else []
    if missing_dll_pids:
        # E.2: surface the specific uncovered PIDs so the parent agent
        # knows which list_dlls invocations to make, not just that some
        # list_dlls execution is needed.
        missing.append({
            "tool": "memory.list_dlls",
            "classification": "memory_network_pid_followup",
            "reason": (
                f"Established external connections require list_dlls for "
                f"PIDs {missing_dll_pids}; only some PIDs were covered."
            ),
            "missing_pids": missing_dll_pids,
        })

    for suff in sorted(MANDATORY_DISK_TOOL_SUFFIXES):
        _add(
            f"disk.{suff}",
            suff,
            "mandatory_disk_baseline",
            "Universal Windows IR disk triage requires MFT, EVTX, registry, Amcache, and Prefetch.",
        )

    # Taxonomy-conditional file-access overlay (review 2026-06-03). Only
    # when the frozen selector snapshot says required (Windows + file-centric
    # dispute_type); never for legacy state / non-Windows / unknown dispute_type.
    if (selector or {}).get("file_access_bundle_required"):
        for suff in FILE_ACCESS_TOOL_SUFFIXES:
            _add_file_access(f"disk.{suff}", suff)

    if _needs_sigma_hunt_run(executions):
        missing.append(
            {
                "tool": "detection.sigma_hunt",
                "classification": "mandatory_rule_engine",
                "reason": (
                    "sigma_scan is an internal anomaly post-processor; sigma_hunt runs "
                    "Chainsaw rule engine against the EVTX corpus. A successful sigma_hunt "
                    "execution (exit_code 0, duration > 0) is required before the report "
                    "can finalize. Run2 evidence: zero rule-based detections without it."
                ),
            }
        )

    # build_timeline is now OPTIONAL (not mandatory)
    # Specialists work from individual CSV extracts (MFT, EVTX, Prefetch, Amcache, Registry)
    # which are fast and already extracted. Plaso super-timeline remains available for
    # deep-dive timeline analysis but is not required for report generation.
    # User decision 2026-05-18: "no plaso lets keep it optional i think we dont need it for now"
    #
    # if _needs_build_timeline_run(executions):
    #     missing.append(
    #         {
    #             "tool": "timeline.build_timeline",
    #             "classification": "mandatory_timeline_baseline",
    #             "reason": (
    #                 "Plaso super-timeline is mandatory for all IR investigations. "
    #                 "Reconstructs attacker activity across filesystem, registry, and "
    #                 "event logs simultaneously. Required before report finalization."
    #             ),
    #         }
    #     )

    if _signals_extended_anti_forensics_coverage(findings, sigma_result):
        for suff, full in (
            ("analyze_vss", "disk.analyze_vss"),
            ("extract_shimcache", "disk.extract_shimcache"),
            ("extract_srum", "disk.extract_srum"),
        ):
            _add(
                full,
                suff,
                "anti_forensics_signal",
                "Anti-forensics or log-manipulation signals require VSS, ShimCache, and SRUM follow-up.",
            )

    # Analysis-debt detection (PART B, review 2026-06-03). A handle was
    # extracted but never mined by an analyst finding -- the exact ROCBA miss
    # (extraction without analysis). BLOCK only the taxonomy-required file-access
    # handles; everything else is WARN (returned for report.json/HTML, never
    # blocking). run_analysis ALONE does not clear -- only an analyst finding or a
    # documented-absence does.
    debt = compute_analysis_debt(
        executions, findings, selector, analysis_roots=analysis_roots
    )
    analysis_debt_warning = debt.get("warning", [])
    for d in debt.get("blocking", []):
        missing.append({
            "tool": "analysis.run_analysis",
            "classification": "analysis_debt_file_access",
            "reason": (
                f"{d['tool_suffix']} extracted {d['handle_path']} but no analyst finding "
                f"mined it (a run_analysis query alone does NOT clear this). Run run_analysis "
                f"on the CSV, then submit_finding citing execution {d['execution_id']} -- or "
                f"record a documented-absence result."
            ),
            "handle_path": d["handle_path"],
            "execution_id": d["execution_id"],
            "lane_id": d["lane_id"],
        })

    if not missing:
        return {
            "ok": True,
            "missing": [],
            "next_required_tool": None,
            "accepted_by_lane": accepted_by_lane,
            "analysis_debt_warning": analysis_debt_warning,
        }
    return {
        "ok": False,
        "missing": missing,
        "next_required_tool": missing[0]["tool"],
        "accepted_by_lane": accepted_by_lane,
        "analysis_debt_warning": analysis_debt_warning,
    }


def refresh_report_graph_flags(
    *,
    case_id: str,
    reports_root: str = "./reports",
) -> dict[str, Any]:
    """Update graph_missing / data_gaps in an existing report.json after graph generation."""
    report_dir = (Path(reports_root) / case_id).resolve()
    report_json_path = report_dir / "report.json"
    if not report_json_path.is_file():
        return {"status": "skipped", "reason": "report.json not found"}

    try:
        payload = json.loads(report_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "error", "reason": str(exc)}

    graph_html_path = report_dir / "graph.html"
    graph_json_path = report_dir / "graph.json"
    graph_exists = graph_html_path.is_file() or graph_json_path.is_file()

    status_flags = dict(payload.get("status_flags") or {})
    status_flags["graph_missing"] = not graph_exists
    payload["status_flags"] = status_flags

    gaps = [g for g in (payload.get("data_gaps") or []) if isinstance(g, dict)]
    gaps = [g for g in gaps if g.get("classification") != "graph_missing"]
    if not graph_exists:
        gaps.append(
            {
                "artifact_family": "graph",
                "classification": "graph_missing",
                "reason": "graph.html / graph.json not present under report directory.",
                "lane_id": "timeline_correlation",
                "next_required_tool": "generate_graph",
            }
        )
    payload["data_gaps"] = gaps
    payload["next_required_tool"] = "generate_graph" if not graph_exists else None
    if graph_exists and "graph_path" not in payload:
        payload["graph_path"] = str(graph_html_path) if graph_html_path.is_file() else None
        payload["graph_json_path"] = str(graph_json_path) if graph_json_path.is_file() else None

    try:
        report_json_path.write_text(
            json.dumps(payload, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        return {"status": "error", "reason": str(exc)}

    return {
        "status": "ok",
        "graph_missing": not graph_exists,
        "report_json_path": str(report_json_path),
    }


def _lane_has_work(lane: dict[str, Any]) -> bool:
    return bool(lane.get("execution_ids") or lane.get("finding_ids"))


def _lane_owned(lane: dict[str, Any]) -> bool:
    return bool(lane.get("assigned_agent") or lane.get("supporting_agents"))


def build_orchestration_warnings(analysis_lanes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Warn when required lanes are complete only by inference."""
    warnings: list[dict[str, Any]] = []
    for lane in analysis_lanes:
        lane_id = str(lane.get("lane_id") or "")
        if not lane.get("required"):
            continue
        if _lane_owned(lane):
            continue
        if str(lane.get("status") or "") in {"PENDING", "IN_PROGRESS", "FAILED"}:
            continue
        if not _lane_has_work(lane):
            continue
        warnings.append(
            {
                "type": "specialist_lane_not_recorded",
                "lane_id": lane_id,
                "expected_agents": list(EXPECTED_LANE_AGENTS.get(lane_id, ())),
                "message": (
                    "Lane has tool executions or findings but no explicit specialist "
                    "lane record. Treat this as inferred coverage until "
                    "record_analysis_lane validates the specialist or main-agent return."
                ),
            }
        )
    return warnings


def _validate_subagent_lane_ids(
    lane: dict[str, Any],
    *,
    persisted_execution_ids: set[str],
    persisted_finding_ids: set[str],
) -> list[dict[str, Any]]:
    """Return fail-closed data gaps for subagent lane IDs absent from state."""
    if not _lane_owned(lane):
        return []

    execution_ids = {
        str(execution_id).strip()
        for execution_id in (lane.get("execution_ids") or [])
        if str(execution_id).strip()
    }
    finding_ids = {
        str(finding_id).strip()
        for finding_id in (lane.get("finding_ids") or [])
        if str(finding_id).strip()
    }
    missing_execution_ids = sorted(execution_ids - persisted_execution_ids)
    missing_finding_ids = sorted(finding_ids - persisted_finding_ids)
    if not missing_execution_ids and not missing_finding_ids:
        return []

    return [
        {
            "artifact_family": lane.get("lane_id") or "analysis_lane",
            "classification": "subagent_return_invalid",
            "reason": (
                "Subagent lane references execution or finding IDs that are "
                "not present in persisted state."
            ),
            "lane_id": lane.get("lane_id"),
            "assigned_agent": lane.get("assigned_agent"),
            "missing_execution_ids": missing_execution_ids,
            "missing_finding_ids": missing_finding_ids,
        }
    ]


def _synthesize_analysis_lanes(
    *,
    findings: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    persisted_lanes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    lanes: dict[str, dict[str, Any]] = {}
    if persisted_lanes:
        for lane in persisted_lanes:
            lane_id = str(lane.get("lane_id") or "").strip()
            if not lane_id:
                continue
            merged = _lane_template(lane_id, legacy_inferred=bool(lane.get("legacy_inferred")))
            merged.update(dict(lane))
            merged.setdefault("supporting_agents", [])
            lanes[lane_id] = merged
    else:
        for lane_id in _LANE_SPECS:
            lanes[lane_id] = _lane_template(lane_id, legacy_inferred=True)

    for execution in executions:
        lane_id = _infer_lane_from_tool_name(execution.get("tool_name"))
        if not lane_id:
            continue
        lane = lanes.setdefault(lane_id, _lane_template(lane_id, legacy_inferred=not persisted_lanes))
        execution_id = str(execution.get("execution_id") or "").strip()
        if execution_id and execution_id not in lane["execution_ids"]:
            lane["execution_ids"].append(execution_id)
        if lane["status"] in {"PENDING", "UNKNOWN"}:
            lane["status"] = "COMPLETE"

    for finding in findings:
        lane_id, confidence = _infer_lane_from_finding(finding)
        if not lane_id:
            continue
        lane = lanes.setdefault(lane_id, _lane_template(lane_id, legacy_inferred=not persisted_lanes))
        finding_id = str(finding.get("finding_id") or "").strip()
        if finding_id and finding_id not in lane["finding_ids"]:
            lane["finding_ids"].append(finding_id)
        if lane.get("lane_inference_confidence") in (None, "low") and confidence:
            lane["lane_inference_confidence"] = confidence
        if lane["status"] in {"PENDING", "UNKNOWN"}:
            lane["status"] = "COMPLETE"

    anti_findings = [
        finding for finding in findings
        if str(finding.get("finding_type") or "").lower() == "anti_forensics_recovery"
    ]
    anti_lane = lanes.get("anti_forensics_recovery")
    sigma_owned_lane = next(
        (
            lane for lane in lanes.values()
            if lane.get("assigned_agent") == "sigma-analyst"
            or "sigma-analyst" in (lane.get("supporting_agents") or [])
        ),
        None,
    )
    if anti_lane and anti_findings and not _lane_owned(anti_lane) and sigma_owned_lane:
        anti_lane["assigned_agent"] = "sigma-analyst"
        anti_lane["supporting_agents"] = sorted(
            set((anti_lane.get("supporting_agents") or []) + ["evtx-analyst"])
        )
        anti_lane["summary"] = anti_lane.get("summary") or (
            "Anti-forensics findings were produced during Sigma/event analysis; "
            "ownership derived from the recorded sigma-analyst lane."
        )

    return [lanes[lane_id] for lane_id in _LANE_SPECS if lane_id in lanes]


def _mark_required_lane_failed(
    lane: dict[str, Any],
    *,
    data_gaps: list[dict[str, Any]],
    reason: str = "Required lane has no recorded executions or findings.",
) -> list[dict[str, Any]]:
    lane_id = lane.get("lane_id")
    lane["status"] = "FAILED"
    lane_gap = {
        "artifact_family": lane_id,
        "classification": "not_collected",
        "reason": reason,
        "lane_id": lane_id,
    }
    lane["data_gaps"] = _merge_warning_lists(lane.get("data_gaps", []), [lane_gap])
    return _merge_warning_lists(data_gaps, lane["data_gaps"])


def validate_report(
    *,
    state_manager: Any,
    findings: list[dict[str, Any]],
    sigma_result: dict[str, Any],
) -> dict[str, Any]:
    executions = state_manager.get_executions()
    persisted_lanes = state_manager.get_analysis_lanes()
    persisted_execution_ids = {
        str(execution.get("execution_id") or "").strip()
        for execution in executions
        if str(execution.get("execution_id") or "").strip()
    }
    persisted_finding_ids = {
        str(finding.get("finding_id") or "").strip()
        for finding in findings
        if str(finding.get("finding_id") or "").strip()
    }
    analysis_lanes = _synthesize_analysis_lanes(
        findings=findings,
        executions=executions,
        persisted_lanes=persisted_lanes,
    )
    unresolved = sum(
        1
        for f in findings
        if (f.get("contradicted_by") or [])
        and str(f.get("finding_status") or "").upper() != "REJECTED"
    )

    anti_forensics_warnings = _merge_warning_lists(
        list(sigma_result.get("anti_forensics_warnings", [])),
    )
    data_gaps = list(sigma_result.get("data_gaps", []))

    for lane in analysis_lanes:
        lane_id = lane.get("lane_id")
        invalid_subagent_gaps = _validate_subagent_lane_ids(
            lane,
            persisted_execution_ids=persisted_execution_ids,
            persisted_finding_ids=persisted_finding_ids,
        )
        if invalid_subagent_gaps:
            lane["status"] = "FAILED"
            lane["data_gaps"] = _merge_warning_lists(
                lane.get("data_gaps", []),
                invalid_subagent_gaps,
            )
            data_gaps = _merge_warning_lists(data_gaps, invalid_subagent_gaps)
        if lane_id == "anti_forensics_recovery":
            anti_findings = [
                finding for finding in findings
                if str(finding.get("finding_type") or "").lower() == "anti_forensics_recovery"
            ]
            if anti_findings and lane["status"] in {"PENDING", "UNKNOWN", "COMPLETE"}:
                lane["status"] = "COMPLETE_WITH_GAPS"
                if not lane["data_gaps"]:
                    lane["data_gaps"].append(
                        {
                            "artifact_family": "anti_forensics_recovery",
                            "classification": "not_collected",
                            "reason": "Analyst anti-forensics evidence exists without structured classification.",
                            "lane_id": lane_id,
                        }
                    )
            if lane["data_gaps"]:
                data_gaps = _merge_warning_lists(data_gaps, lane["data_gaps"])
            if lane.get("required") and lane["status"] in {"PENDING", "UNKNOWN"}:
                data_gaps = _mark_required_lane_failed(
                    lane,
                    data_gaps=data_gaps,
                    reason=(
                        "Required anti-forensics lane was not explicitly completed "
                        "or marked COMPLETE_WITH_GAPS."
                    ),
                )
        elif lane.get("required"):
            if lane["status"] == "PENDING":
                data_gaps = _mark_required_lane_failed(lane, data_gaps=data_gaps)
            if lane["status"] == "FAILED":
                if not lane.get("data_gaps"):
                    data_gaps = _mark_required_lane_failed(lane, data_gaps=data_gaps)
                data_gaps = _merge_warning_lists(data_gaps, lane["data_gaps"])

    required_lanes = [lane for lane in analysis_lanes if lane.get("required")]
    all_required_complete = bool(required_lanes) and all(
        str(lane.get("status") or "") == "COMPLETE" for lane in required_lanes
    )
    orchestration_warnings = build_orchestration_warnings(analysis_lanes)
    specialist_lanes_inferred = bool(orchestration_warnings)
    if specialist_lanes_inferred:
        for warning in orchestration_warnings:
            warning_lane_id = warning.get("lane_id")
            if not warning_lane_id:
                continue
            inferred_gap = {
                "artifact_family": warning_lane_id,
                "classification": "lane_not_owned_by_subagent",
                "reason": (
                    "Required lane has executions or findings but no "
                    "specialist or main-agent record. Call record_analysis_lane "
                    "to validate ownership before TRIAGE_COMPLETE is honest."
                ),
                "lane_id": warning_lane_id,
                "expected_agents": warning.get("expected_agents", []),
            }
            data_gaps = _merge_warning_lists(data_gaps, [inferred_gap])
    status_flags = {
        "open_leads": bool(sigma_result.get("actionable_leads", [])),
        "anti_forensics_warning": bool(anti_forensics_warnings),
        "unresolved_discrepancy": unresolved > 0,
        "specialist_lanes_inferred": specialist_lanes_inferred,
        # Honest quality signal: hunt loop not fully closed if any recorded
        # hypothesis is still ACTIVE/INVESTIGATING (not a gate - see
        # _count_unresolved_hypotheses).
        "hypotheses_unresolved": _count_unresolved_hypotheses(
            state_manager.get_hypotheses()
        ),
    }
    triage_status = (
        "TRIAGE_COMPLETE"
        if (
            all_required_complete
            and not anti_forensics_warnings
            and not unresolved
            and not specialist_lanes_inferred
        )
        else "COMPLETE_WITH_GAPS"
    )
    return {
        "analysis_lanes": analysis_lanes,
        "anti_forensics_warnings": anti_forensics_warnings,
        "data_gaps": data_gaps,
        "orchestration_warnings": orchestration_warnings,
        "status_flags": status_flags,
        "triage_status": triage_status,
    }


# ===========================================================================
# Report-quality helpers. Deterministic, evidence-bounded, no LLM at render
# time. Same report.json snapshot -> same HTML. See the report-rebuild
# review for the full narrator policy and IOC/timeline guardrails.
# ===========================================================================

def _status_color_class(status: Any) -> str:
    """Map a finding status to a CSS color class. Green=confirmed,
    red=refuted/rejected, yellow=hypothesis/active, gray=everything else."""
    s = str(status or "").upper()
    if s == "CONFIRMED":
        return "covered"
    if s in ("REFUTED", "REJECTED"):
        return "refuted"
    if s in ("HYPOTHESIS", "ACTIVE"):
        return "uncovered"
    return "muted"


def _confidence_tier(confidence: Any) -> str:
    """Coarse confidence tier label. The Finding model has no severity field,
    so we describe confidence directly rather than invent a severity."""
    try:
        c = float(confidence or 0.0)
    except (TypeError, ValueError):
        c = 0.0
    if c >= 0.85:
        return "high"
    if c >= 0.60:
        return "moderate"
    return "low"


def _classify_indicator(indicator: Any) -> str:
    """Conservative IOC type label. Structured prefix first, then a narrow
    regex pass, else the neutral 'indicator'. Never over-labels."""
    s = str(indicator or "").strip()
    low = s.lower()
    for prefix, label in (
        ("executable:", "executable"), ("owner_process:", "process"),
        ("process:", "process"), ("account:", "account"),
        ("ip:", "ip"), ("domain:", "domain"), ("hash:", "hash"),
        ("port:", "port"),
    ):
        if low.startswith(prefix):
            return label
    ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", s)
    if ip_match:
        try:
            ipaddress.ip_address(ip_match.group(0))
            return "ip"
        except ValueError:
            pass  # malformed octets -> not a real IP; fall through to neutral
    if re.search(r"(?i)\b(?:tcp|udp)\b", s):
        port_match = re.search(r":(\d{2,5})\b", s)
        if port_match and 1 <= int(port_match.group(1)) <= 65535:
            return "port"
    if re.search(r"[A-Za-z]:\\", s) or re.search(r"(?i)\.(?:exe|dll|sys|ps1|bat|vbs)\b", s):
        return "path/file"
    if re.search(r"(?i)\bpid\s*\d+", s):
        return "process"
    if re.search(r"(?i)\bbytes?\b|\bMB\b|\bGB\b", s):
        return "data-volume"
    if re.search(r"\S+\\\S+", s):
        return "account"
    return "indicator"


def _render_killchain_strip(rows: list[tuple[str, str, int, str]]) -> str:
    """Pure HTML/CSS horizontal kill-chain strip (replaces the CDN Mermaid
    diagram). rows = (key, label, count, status in filled/partial/empty).
    Status color reflects finding COUNT per phase, not corroboration strength."""
    cls = {"filled": "kc-covered", "partial": "kc-partial", "empty": "kc-gap"}
    cells: list[str] = []
    for i, (key, label, count, status) in enumerate(rows):
        cells.append(
            f'<div class="kc-phase {cls.get(status, "kc-gap")}">'
            f'<div class="kc-name">{html.escape(label)}</div>'
            f'<div class="kc-count">{count}</div></div>'
        )
        if i < len(rows) - 1:
            cells.append('<div class="kc-arrow">&rsaquo;</div>')
    return f'<div class="killchain">{"".join(cells)}</div>'


def _render_attack_coverage_table(
    coverage: dict[str, Any], findings: list[dict[str, Any]]
) -> str:
    """Color-coded ATT&CK tactic coverage. Tactic-level is authoritative
    (covered/uncovered from coverage payload); technique + finding columns are
    inferred from findings and labeled as observed, not claimed authoritative."""
    covered = coverage.get("covered_tactics") or []
    uncovered = coverage.get("uncovered_tactics") or []
    suggested = coverage.get("suggested_next_tools") or {}
    by_tactic: dict[str, dict[str, set]] = {}
    for f in findings:
        tac = str(f.get("mitre_tactic") or "")
        if not tac:
            continue
        slot = by_tactic.setdefault(tac, {"techs": set(), "fids": set()})
        if f.get("mitre_technique"):
            slot["techs"].add(str(f.get("mitre_technique")))
        if f.get("finding_id"):
            slot["fids"].add(str(f.get("finding_id")))

    def _row(tac: Any, status_class: str, status_text: str) -> str:
        tid = tac.get("id", "") if isinstance(tac, dict) else str(tac)
        tname = tac.get("name", "") if isinstance(tac, dict) else ""
        slot = by_tactic.get(tid, {})
        techs = ", ".join(sorted(slot.get("techs", set()))) or "-"
        fids = ", ".join(sorted(slot.get("fids", set()))) or "-"
        tools = ", ".join(suggested.get(tid, [])) if isinstance(suggested, dict) else ""
        return (
            "<tr>"
            f"<td><strong>{html.escape(str(tid))}</strong> {html.escape(str(tname))}</td>"
            f'<td><span class="tag {status_class}">{status_text}</span></td>'
            f"<td>{html.escape(techs)}</td>"
            f'<td class="mono">{html.escape(fids)}</td>'
            f"<td>{html.escape(tools)}</td>"
            "</tr>"
        )

    rows = [_row(t, "covered", "covered") for t in covered]
    rows += [_row(t, "uncovered", "gap") for t in uncovered]
    if not rows:
        return "<tr><td colspan='5'>No ATT&amp;CK tactic coverage recorded.</td></tr>"
    return "\n".join(rows)


def _render_ioc_table(findings: list[dict[str, Any]]) -> str:
    """Deduplicated IOC table from finding supporting_indicators. Indicator
    text is evidence-derived and rendered verbatim (em-dashes preserved)."""
    seen: dict[str, tuple[str, str, str]] = {}
    for f in findings:
        fid = str(f.get("finding_id", ""))
        status = _status_label(f.get("finding_status"))
        tech = str(f.get("mitre_technique") or "")
        for ind in (f.get("supporting_indicators") or []):
            key = str(ind).strip()
            if key and key not in seen:
                seen[key] = (fid, status, tech)
    if not seen:
        return "<tr><td colspan='5'>No supporting indicators recorded.</td></tr>"
    rows: list[str] = []
    for ind, (fid, status, tech) in list(seen.items())[:80]:
        rows.append(
            "<tr>"
            f'<td class="mono">{html.escape(ind)}</td>'
            f'<td><span class="tag info">{html.escape(_classify_indicator(ind))}</span></td>'
            f"<td>{html.escape(fid)}</td>"
            f"<td>{html.escape(status)}</td>"
            f"<td>{html.escape(tech)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_timeline(findings: list[dict[str, Any]]) -> str:
    """Key event timeline from structured timestamp_observed ONLY. When no
    finding carries a structured event time, render an honest empty state
    rather than fabricating times from created_at (report-write time)."""
    events: list[tuple[str, str, str, str]] = []
    for f in findings:
        ts = f.get("timestamp_observed")
        if ts:
            events.append((
                str(ts), str(f.get("finding_id", "")),
                _status_label(f.get("finding_status")),
                _short_description(f.get("description", ""), 120),
            ))
    if not events:
        return (
            '<p class="muted">No structured event timestamps were captured in the report '
            "payload. Findings carry descriptive timestamps in their evidence text, but no "
            "normalized <span class=\"mono\">timestamp_observed</span> field is present, so a "
            "chronological timeline is omitted rather than inferred from record-creation time.</p>"
        )
    events.sort(key=lambda e: e[0])
    rows = "\n".join(
        "<tr>"
        f'<td class="mono">{html.escape(ts)}</td>'
        f"<td>{html.escape(fid)}</td>"
        f"<td>{html.escape(status)}</td>"
        f"<td>{html.escape(desc)}</td>"
        "</tr>"
        for ts, fid, status, desc in events[:60]
    )
    return (
        "<table><thead><tr><th>Time (UTC)</th><th>Finding</th><th>Status</th>"
        f"<th>Event</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _render_finding_cards(
    findings: list[dict[str, Any]], *, show_corroboration: bool = True
) -> str:
    """Finding cards with status + confidence color chrome."""
    if not findings:
        return "<p class='muted'>None recorded.</p>"
    cards: list[str] = []
    for f in findings:
        fid = html.escape(str(f.get("finding_id", "")))
        status = _status_label(f.get("finding_status"))
        scls = _status_color_class(status)
        conf = float(f.get("confidence", 0.0) or 0.0)
        tier = _confidence_tier(conf)
        tac = html.escape(str(f.get("mitre_tactic") or ""))
        tech = html.escape(str(f.get("mitre_technique") or ""))
        desc = html.escape(_short_description(f.get("description", ""), 280))
        mitre_tag = (
            f'<span class="tag muted">{tac}{" / " + tech if tech else ""}</span>'
            if (tac or tech) else ""
        )
        corr = f.get("corroborated_by") or []
        corr_html = ""
        if show_corroboration and corr:
            corr_html = (
                '<div class="card-meta"><span class="k">Corroborated by</span> '
                f'<span class="mono">{html.escape(", ".join(str(x) for x in corr))}</span></div>'
            )
        inds = f.get("supporting_indicators") or []
        ind_html = ""
        if inds:
            chips = "".join(
                f'<span class="chip">{html.escape(str(i))}</span>' for i in inds[:6]
            )
            ind_html = f'<div class="chips">{chips}</div>'
        # CONFIRMED-only provenance expansion (case-agnostic: renders whatever
        # defensibility fields the finding carries). Keeps the high-bar claims
        # auditable from the report alone without bloating ACTIVE cards.
        prov_html = ""
        if show_corroboration and status == "CONFIRMED":
            bits: list[str] = []
            if f.get("execution_id"):
                bits.append(f'<span class="k">execution_id</span> <span class="mono">{html.escape(str(f.get("execution_id")))}</span>')
            if f.get("evidence_kind"):
                bits.append(f'<span class="k">evidence</span> {html.escape(str(f.get("evidence_kind")))}')
            if f.get("disposition"):
                bits.append(f'<span class="k">disposition</span> {html.escape(str(f.get("disposition")))}')
            if f.get("alternative_hypothesis"):
                bits.append(f'<span class="k">alt. hypothesis</span> {html.escape(_short_description(str(f.get("alternative_hypothesis")), 160))}')
            _ea = f.get("evidence_against_it") or []
            if _ea:
                _ea_txt = ", ".join(str(x) for x in _ea) if isinstance(_ea, list) else str(_ea)
                bits.append(f'<span class="k">ruled out by</span> {html.escape(_short_description(_ea_txt, 160))}')
            _ctx = f.get("heuristic_context_refs") or []
            if _ctx:
                bits.append(f'<span class="k">heuristics</span> <span class="mono">{html.escape(", ".join(str(x) for x in _ctx))}</span>')
            if bits:
                prov_html = '<div class="card-meta">' + " &middot; ".join(bits) + "</div>"
        cards.append(
            '<div class="finding">'
            f'<div class="finding-head"><span class="fid">{fid}</span>'
            f'<span class="tag {scls}">{html.escape(status)}</span>'
            f'<span class="tag info">conf {conf:.2f} ({tier})</span>{mitre_tag}</div>'
            f'<div class="finding-desc">{desc}</div>{corr_html}{prov_html}{ind_html}</div>'
        )
    return "\n".join(cards)


def _render_finding_index(findings: list[dict[str, Any]]) -> str:
    """Compact appendix table of EVERY finding, so a reviewer can look up any
    F-NNN (status, confidence, evidence kind, tool, execution_id) from the report
    alone. Case-agnostic: renders whatever findings exist, no hardcoded values."""
    if not findings:
        return "<p class='muted'>No findings recorded.</p>"
    rows: list[str] = []
    for f in findings:
        fid = html.escape(str(f.get("finding_id", "")))
        status = _status_label(f.get("finding_status"))
        scls = _status_color_class(status)
        conf = float(f.get("confidence", 0.0) or 0.0)
        ek = html.escape(str(f.get("evidence_kind") or ""))
        tech = html.escape(str(f.get("mitre_technique") or ""))
        tool = html.escape(str(f.get("tool_name") or ""))
        eid = html.escape(str(f.get("execution_id") or ""))
        desc = html.escape(_short_description(f.get("description", ""), 160))
        rows.append(
            f'<tr><td class="mono">{fid}</td>'
            f'<td><span class="tag {scls}">{html.escape(status)}</span></td>'
            f'<td>{conf:.2f}</td><td>{ek}</td><td>{tech}</td>'
            f'<td class="mono">{tool}</td><td class="mono">{eid}</td><td>{desc}</td></tr>'
        )
    return (
        '<table><thead><tr><th>ID</th><th>Status</th><th>Conf</th><th>Evidence</th>'
        "<th>MITRE</th><th>Tool</th><th>Execution</th><th>Description</th></tr></thead>"
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


# Executive summary is for decision-makers (managers, counsel, IR leads), NOT
# analysts. It must read as plain narrative - internal identifiers (finding IDs,
# execution/audit IDs, CTX refs, raw MITRE codes, hypothesis ULIDs) belong in
# the Technical Appendix, never the brief. review 2026-06-05.
_INTERNAL_TOKEN_RE = re.compile(
    r"\b(?:F-\d+|E-\d+|CTX-\d+|TA\d{4}|T\d{4}(?:\.\d{3})?|[0-9A-HJKMNPQRSTVWXYZ]{26})\b"
)


def _strip_internal_tokens(text: str) -> str:
    """Remove internal identifiers (F-/E-/CTX- IDs, raw MITRE TAxxxx/Txxxx codes,
    26-char ULIDs) from executive-summary prose, then tidy the punctuation/space
    the removal leaves behind. Court-readable narrative only; the IDs live in the
    appendix."""
    if not text:
        return text
    out = _INTERNAL_TOKEN_RE.sub("", text)
    out = re.sub(r"\(\s*[;,/]?\s*\)", "", out)   # empty parens left behind
    out = re.sub(r"\[\s*/?\s*\]", "", out)        # empty brackets
    out = re.sub(r"[ \t]{2,}", " ", out)          # collapse runs of spaces
    out = re.sub(r"\s+([.,;:])", r"\1", out)      # space before punctuation
    return out.strip()


def _render_executive_summary(payload: dict[str, Any]) -> str:
    """Deterministic narrative executive summary (Item 1 = A). Assembled from
    structured, agent-authored fields the payload already carries. No LLM at
    render time; same snapshot -> same prose. Confirmed-only primary narrative,
    defensible language, summarize-and-point (full detail lives in the
    Top Confirmed Findings section), graceful zero-confirmed branch."""
    summary = payload.get("summary", {}) or {}
    coverage = payload.get("coverage", {}) or {}
    sigma = payload.get("sigma_scan", {}) or {}
    status_breakdown = payload.get("status_breakdown", {}) or {}
    activity_thread = payload.get("activity_thread", {}) or {}
    lanes = payload.get("analysis_lanes", []) or []
    hypotheses = payload.get("hypotheses", []) or []
    case_id = html.escape(str(payload.get("case_id", "")))
    triage = html.escape(str(payload.get("triage_status", summary.get("triage_status", "UNKNOWN"))))
    confirmed_count = status_breakdown.get("CONFIRMED", summary.get("confirmed_count", 0))
    active_count = status_breakdown.get("ACTIVE", 0) + status_breakdown.get("HYPOTHESIS", 0)
    unresolved = summary.get("unresolved_discrepancies", payload.get("unresolved_count", 0))
    sig_crit = sigma.get("critical_count", 0)
    sig_high = sigma.get("high_count", 0)
    all_confirmed = list(payload.get("top_confirmed_findings") or [])
    confirmed = all_confirmed[:5]
    # Corroboration is asserted only where the finding actually carries >=2
    # corroborating source IDs; absence is surfaced as a caveat, never claimed.
    multi_src = sum(1 for f in all_confirmed if len(f.get("corroborated_by") or []) >= 2)
    weak_corr = sum(1 for f in all_confirmed if not (f.get("corroborated_by") or []))

    parts: list[str] = []
    if confirmed_count and confirmed_count > 0:
        if multi_src:
            corr_clause = (
                f", {multi_src} of which {'is' if multi_src == 1 else 'are'} corroborated "
                f"by multiple independent artifact sources,"
            )
        else:
            corr_clause = ""
        parts.append(
            f"<p>Investigation <strong>{case_id}</strong> reached triage status "
            f"<strong>{triage}</strong> with <strong>{confirmed_count}</strong> structurally "
            f"confirmed finding(s){corr_clause} and "
            f"<strong>{active_count}</strong> active lead(s) pending validation.</p>"
        )
        bullets = []
        for f in confirmed:
            # Plain narrative only - no finding IDs, confidence decimals, or raw
            # MITRE codes in the brief (they live in Top Confirmed Findings).
            d = html.escape(_strip_internal_tokens(_short_description(f.get("description", ""), 200)))
            if d:
                bullets.append(f"<li>{d}</li>")
        if bullets:
            parts.append(
                '<p class="muted" style="margin:.6rem 0 .3rem;">Confirmed activity '
                "(full detail in Top Confirmed Findings below):</p>"
                f"<ul>{''.join(bullets)}</ul>"
            )
    else:
        parts.append(
            f"<p>Investigation <strong>{case_id}</strong> reached triage status "
            f"<strong>{triage}</strong>. <strong>No structurally confirmed findings</strong> "
            f"were established; <strong>{active_count}</strong> active lead(s) remain pending "
            f"corroboration. The items below are unconfirmed and require further validation "
            f"before any conclusion is drawn.</p>"
        )

    # Hunt closure - summarize hypothesis verdicts by human-readable attack_class,
    # NEVER raw ULIDs. Statuses are already gated (record_hypotheses write gate +
    # payload-assembly re-check); we read them as-is. Self-contradicting verdicts
    # (e.g. a CONFIRMED hypothesis with no multi-source finding) were downgraded
    # to SUSPENDED upstream, so the brief never over-claims a hunt.
    closure_groups: list[str] = []
    for stat, word in (("CONFIRMED", "confirmed"), ("REFUTED", "refuted"), ("SUSPENDED", "suspended")):
        labels = [
            html.escape(_strip_internal_tokens(_short_description(str(h.get("attack_class") or "").strip(), 70)))
            for h in hypotheses
            if str(h.get("status", "")).upper() == stat
        ]
        labels = [l for l in labels if l]
        if labels:
            closure_groups.append(f"{len(labels)} {word} ({'; '.join(labels)})")
    if closure_groups:
        parts.append(
            f'<p><span class="k">Hunt closed:</span> {"; ".join(closure_groups)}.</p>'
        )

    syn = next((l for l in lanes if "synth" in str(l.get("lane_id", "")).lower()), None)
    if syn and syn.get("summary") and multi_src:
        # Clean derived sentence - the raw lane summary carries tool names and
        # execution IDs that do not belong in the brief. Only claim multi-source
        # corroboration when a confirmed finding actually carries it (multi_src).
        parts.append(
            '<p><span class="k">Cross-artifact synthesis:</span> the confirmed '
            "activity is corroborated across multiple independent artifact sources.</p>"
        )

    phases = activity_thread.get("phases") or {}
    if phases:
        empty = sum(1 for k, _ in _KILLCHAIN_DISPLAY_ORDER if len(phases.get(k, []) or []) == 0)
        total = len(_KILLCHAIN_DISPLAY_ORDER)
        parts.append(
            f'<p><span class="k">Kill-chain coverage:</span> {total - empty} of {total} '
            f"phases evidenced, {empty} blindspot(s).</p>"
        )

    caveats = []
    if weak_corr:
        caveats.append(
            f"{weak_corr} confirmed finding(s) without recorded multi-source corroboration"
        )
    if unresolved:
        caveats.append(f"{unresolved} unresolved cross-artifact discrepancy(ies)")
    if sig_crit or sig_high:
        caveats.append(f"{sig_crit} critical / {sig_high} high Sigma anomalies")
    if caveats:
        parts.append(
            f'<p class="muted"><span class="k">Caveats:</span> '
            f"{html.escape('; '.join(caveats))}.</p>"
        )
    # Belt-and-suspenders: scrub any internal identifier that slipped through a
    # description/caveat before the brief reaches a decision-maker.
    return _strip_internal_tokens("\n".join(parts))


# Activity Thread renderer. Maps the case's findings (via classified MITRE
# techniques) onto Cyber Kill Chain phases. Empty phase = blindspot
# (Diamond Axiom 4). Rendered as a pure HTML/CSS strip (no external JS).

_KILLCHAIN_DISPLAY_ORDER = [
    ("reconnaissance",       "Reconnaissance"),
    ("delivery",             "Delivery"),
    ("exploitation",         "Exploitation"),
    ("installation",         "Installation / Persistence"),
    ("command_and_control",  "Command and Control"),
    ("actions_on_objectives", "Actions on Objectives"),
]


def render_activity_thread_html(activity_thread: dict[str, Any]) -> str:
    """Render the Activity Thread state as an HTML section with a Mermaid
    diagram + filled/empty phase breakdown.

    Filled phase (≥2 findings) shows green; partial (1 finding) shows amber;
    empty (0 findings, excluding WEAPONIZATION) shows red as blindspot.
    """
    phases_state = (activity_thread or {}).get("phases", {})
    notes = (activity_thread or {}).get("blindspot_notes", {})

    rows: list[tuple[str, str, int, str]] = []  # (key, label, count, status)
    for key, label in _KILLCHAIN_DISPLAY_ORDER:
        count = len(phases_state.get(key, []) or [])
        if count >= 2:
            status = "filled"
        elif count == 1:
            status = "partial"
        else:
            status = "empty"
        rows.append((key, label, count, status))

    filled = sum(1 for r in rows if r[3] == "filled")
    partial = sum(1 for r in rows if r[3] == "partial")
    empty = sum(1 for r in rows if r[3] == "empty")

    # Per-phase table rows (with blindspot notes)
    table_rows_html = []
    for key, label, count, status in rows:
        if status == "filled":
            badge_class = "covered"
            badge_text = f"{count} findings"
        elif status == "partial":
            badge_class = "muted"
            badge_text = f"{count} finding (single source)"
        else:
            badge_class = "uncovered"
            badge_text = "BLINDSPOT - no evidence"
        note = html.escape((notes.get(key) or "")) if status == "empty" else ""
        note_html = f'<div style="color: var(--muted); font-size: 0.85em; margin-top: 0.3rem;">{note}</div>' if note else ""
        table_rows_html.append(
            f'<tr><td>{html.escape(label)}</td>'
            f'<td><span class="tag {badge_class}">{html.escape(badge_text)}</span>{note_html}</td>'
            f'</tr>'
        )

    return f"""
  <div class="card">
    <h2>Activity Thread - Cyber Kill Chain Coverage</h2>
    <p style="color: var(--muted); font-size: 0.92em;">
      Per Diamond Model Axiom 4, every malicious activity traverses a
      succession of kill-chain phases. Empty phases below represent
      <strong>blindspots</strong>: areas where evidence was either not
      extracted, not retained, or actively destroyed by anti-forensics.
      Phase color reflects the number of findings mapped to that phase.
    </p>
    {_render_killchain_strip(rows)}
    <div class="grid" style="margin-top: 1rem;">
      <div class="metric">
        <div class="metric-label">Phases with corroborated evidence</div>
        <div class="metric-value good">{filled}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Single-source phases</div>
        <div class="metric-value warn">{partial}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Blindspots (empty phases)</div>
        <div class="metric-value danger">{empty}</div>
      </div>
    </div>
    <table>
      <thead><tr><th>Kill-chain phase</th><th>Status</th></tr></thead>
      <tbody>
        {''.join(table_rows_html)}
      </tbody>
    </table>
  </div>
"""


# ---------------------------------------------------------------------------
# FK-wiring ITEM C: advisory corroboration pivots (additive, fail-open).
# ---------------------------------------------------------------------------
_FK_TIER_DISPLAY = {
    "observation": "observation",
    "probable": "probable",
    "confirmed": "strongly-corroborated",  # NEVER render 'confirmed' (status conflation)
}


def _collect_pivots_for_finding(
    finding: dict[str, Any], analysis_lanes: list[dict[str, Any]] | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scope-preserving join of lane next_pivots to a finding.

    finding-scoped pivot -> agent_pivots; unscoped pivot on a lane that owns the
    finding -> lane_pivots (+lane_id). NEVER promotes unscoped lane pivots to
    agent_pivots.
    """
    fid = str(finding.get("finding_id") or "")
    agent_pivots: list[dict[str, Any]] = []
    lane_pivots: list[dict[str, Any]] = []
    for lane in analysis_lanes or []:
        if not isinstance(lane, dict):
            continue
        lane_id = lane.get("lane_id")
        owns = bool(fid) and fid in {str(x) for x in (lane.get("finding_ids") or [])}
        for piv in lane.get("next_pivots") or []:
            if not isinstance(piv, dict):
                continue
            scope_ids = {str(piv["finding_id"])} if piv.get("finding_id") else set()
            scope_ids |= {str(x) for x in (piv.get("finding_ids") or [])}
            if scope_ids:
                if fid and fid in scope_ids:
                    agent_pivots.append({**piv, "pivot_scope": "finding", "lane_id": lane_id})
            elif owns:
                lane_pivots.append({**piv, "pivot_scope": "lane", "lane_id": lane_id})
    return agent_pivots, lane_pivots


def build_finding_corroboration_pivots(
    findings: list[dict[str, Any]],
    analysis_lanes: list[dict[str, Any]] | None,
    *,
    cap: int = 50,
) -> list[dict[str, Any]]:
    """Per-finding advisory corroboration rows (engine + scoped lane pivots).

    Full non-REJECTED corpus, deterministically sorted, capped. Per-finding
    fail-open: one bad finding never collapses the list.
    """
    try:
        corpus = [
            f for f in (findings or [])
            if str(f.get("finding_status") or "").upper() != "REJECTED"
        ]
        corpus = sorted(corpus, key=lambda f: str(f.get("finding_id") or ""))[:cap]
    except Exception:
        return []
    pivots: list[dict[str, Any]] = []
    for f in corpus:
        try:
            art = artifact_name_for_finding(f)
            fk = load_fk_slice(art) if art else {}
            row = corroboration_state(f, findings, fk).to_dict()
            if not art and not row.get("advisory_error"):
                row["advisory_error"] = "unmapped artifact"
            row["agent_pivots"], row["lane_pivots"] = _collect_pivots_for_finding(f, analysis_lanes)
            pivots.append(row)
        except Exception as exc:  # never let one finding zero the list
            pivots.append({
                "finding_id": f.get("finding_id"),
                "advisory_corroboration_tier": "observation",
                "advisory_error": str(exc),
            })
    return pivots


def _render_corroboration_pivots(rows: list[dict[str, Any]] | None) -> str:
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""  # omit the section entirely when empty

    def esc(x: Any) -> str:
        return html.escape(str(x))

    def esc_list(xs: Any) -> str:
        return ", ".join(html.escape(str(x)) for x in (xs or [])) or "-"

    body: list[str] = []
    for r in rows:
        tier = _FK_TIER_DISPLAY.get(
            str(r.get("advisory_corroboration_tier") or "observation"), "observation"
        )
        body.append(
            "<tr>"
            f"<td>{esc(r.get('finding_id') or '-')}</td>"
            f"<td>{esc(r.get('artifact') or '-')}</td>"
            f"<td><span class='muted'>{esc(tier)}</span></td>"
            f"<td>{esc(r.get('timestamp_aligned') or 'unknown')}</td>"
            f"<td>{esc_list(r.get('gap_sources'))}</td>"
            f"<td>{esc_list(r.get('suggested_tools'))}</td>"
            f"<td>{esc(r.get('rationale') or '')}</td>"
            "</tr>"
        )
    intro = (
        "<p class='muted'>Advisory only - does not change finding_status or confidence. "
        "Distinct from ATT&amp;CK <em>Suggested Next Tools</em> (tactic blind-spots) and "
        "<em>Active Leads</em> (detector pivots): this is forensic-knowledge corroboration "
        "- what would raise each finding to the next evidentiary tier.</p>"
    )
    return (
        intro
        + "<table><thead><tr><th>Finding</th><th>Artifact</th><th>Advisory Tier</th>"
        "<th>TS Aligned</th><th>Gap</th><th>Suggested Tools</th><th>Rationale</th></tr></thead>"
        "<tbody>" + "".join(body) + "</tbody></table>"
    )


def render_report_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    sigma = payload["sigma_scan"]
    coverage = payload["coverage"]
    top_findings = payload["top_findings"]
    open_questions = payload.get("open_questions", [])
    status_breakdown = payload.get("status_breakdown", {})
    evidence_kind_breakdown = payload.get("evidence_kind_breakdown", {})
    triage_status = payload.get("triage_status", summary.get("triage_status", "UNKNOWN"))
    # Run-11 polish #8: explicit allowlist for triage-status color class -
    # defaults to ``warn`` (amber) so future unknown statuses are NEVER
    # accidentally rendered green.
    _TRIAGE_STATUS_CLASSES = {
        "TRIAGE_COMPLETE": "good",
        "COMPLETE_WITH_GAPS": "good",
        "TRIAGE_INCOMPLETE": "warn",
    }
    triage_status_class = _TRIAGE_STATUS_CLASSES.get(str(triage_status), "warn")
    status_flags = payload.get("status_flags", {})
    actionable_leads = payload.get("actionable_leads", [])
    anti_forensics_warnings = payload.get("anti_forensics_warnings", [])
    data_gaps = payload.get("data_gaps", [])
    analysis_lanes = payload.get("analysis_lanes", [])
    orchestration_warnings = payload.get("orchestration_warnings", [])
    # W1.7 - Activity Thread state for blindspot reporting
    activity_thread = payload.get("activity_thread", {"phases": {}, "blindspot_notes": {}})
    hypotheses = payload.get("hypotheses", [])

    confirmed_count = status_breakdown.get("CONFIRMED", 0)
    hypothesis_count = status_breakdown.get("HYPOTHESIS", 0) + status_breakdown.get("ACTIVE", 0)

    # Split top findings into confirmed vs active leads
    confirmed_findings = [
        f for f in top_findings
        if _status_label(f.get("finding_status")) == "CONFIRMED"
    ]
    active_findings = [
        f for f in top_findings
        if _status_label(f.get("finding_status")) in ("HYPOTHESIS", "ACTIVE", "OBSERVATION")
    ]

    # FK-wiring ITEM C: advisory corroboration section (omitted when empty;
    # render-only, reads the payload field built in generate_report_payload).
    _corro_html = _render_corroboration_pivots(payload.get("finding_corroboration_pivots", []))
    corroboration_section_html = (
        f"""<section>
    <h2>Corroboration &amp; Suggested Next Steps (advisory)</h2>
    {_corro_html}
  </section>"""
        if _corro_html else ""
    )

    no_confirmed_banner = ""
    if confirmed_count == 0:
        no_confirmed_banner = (
            '<section style="border-color: var(--warn); border-left: 4px solid var(--warn);">'
            '<h2 style="color: var(--warn);">No Structurally Confirmed Findings</h2>'
            "<p>No findings have been independently corroborated by multiple artifact sources. "
            "All findings below are hypotheses or observations that require further validation.</p>"
            "</section>"
        )

    # Trace companion links (rendered in the header band; hidden in print).
    _trace_d = payload.get("trace_detailed_path")
    _trace_s = payload.get("trace_path")
    if _trace_d:
        trace_links = ' &middot; <a href="trace-detailed.html">Agent Session Trace</a>'
        if _trace_s:
            trace_links += ' (<a href="trace.html">summary</a>)'
    elif _trace_s:
        trace_links = ' &middot; <a href="trace.html">Agent Session Trace</a>'
    else:
        trace_links = ""

    # By-the-numbers strip (metrics demoted below the narrative per Item 1).
    _metrics = [
        ("Case Status", html.escape(str(summary.get("status", "UNKNOWN"))), "accent"),
        ("Triage", html.escape(str(triage_status)), triage_status_class),
        ("Findings", summary.get("findings_count", 0), ""),
        ("Confirmed", confirmed_count, "good"),
        ("Unconfirmed findings", hypothesis_count, "warn"),
        ("Correction Events", payload.get("correction_events_count", 0), "accent"),
        ("Unresolved", summary.get("unresolved_discrepancies", 0), "warn"),
        ("Sigma Hits", sigma.get("total_hits", 0), "danger"),
        ("ATT&CK Coverage", f"{coverage.get('coverage_percent', 0):.1f}%", ""),
    ]
    by_numbers = "".join(
        f'<div class="metric"><div class="metric-label">{html.escape(lbl)}</div>'
        f'<div class="metric-value {cls}">{val}</div></div>'
        for lbl, val, cls in _metrics
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAVVYDFIR-MCP Report - {html.escape(payload['case_id'])}</title>
<style>
  :root {{
    --bg: #f4f6fb;
    --surface: #ffffff;
    --ink: #1a2230;
    --muted: #5b6675;
    --line: #e2e7f0;
    --accent: #1d4ed8;
    --good: #15803d; --good-bg: #dcfce7;
    --warn: #b45309; --warn-bg: #fef3c7;
    --danger: #b91c1c; --danger-bg: #fee2e2;
    --info: #1e40af; --info-bg: #dbeafe;
    --mono: 'JetBrains Mono', 'Cascadia Code', ui-monospace, monospace;
    --sans: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: var(--sans); line-height: 1.5; }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 0 1.5rem 3rem; }}
  a {{ color: var(--accent); }}
  h1 {{ margin: 0; font-size: 1.5rem; }}
  h2 {{ margin: 0 0 0.8rem; font-size: 1.15rem; border-bottom: 2px solid var(--line); padding-bottom: 0.4rem; }}
  h3 {{ margin: 0 0 0.5rem; font-size: 1rem; }}
  p, li {{ color: var(--ink); }}
  .mono {{ font-family: var(--mono); font-size: 0.86em; }}
  .muted {{ color: var(--muted); }}
  .k {{ color: var(--muted); font-weight: 600; }}
  .banner {{ background: #0f172a; color: #e5e7eb; padding: 1.4rem 1.5rem; }}
  .banner .wrap {{ max-width: 1080px; margin: 0 auto; display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }}
  .banner .classification {{ font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.12em; color: #fca5a5; text-transform: uppercase; }}
  .banner .case {{ font-family: var(--mono); color: #93c5fd; font-size: 0.85rem; margin-top: 0.3rem; }}
  .banner .statuspill {{ font-family: var(--mono); font-size: 0.8rem; padding: 0.3rem 0.7rem; border-radius: 6px; background: rgba(255,255,255,0.1); white-space: nowrap; }}
  section, .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 1.1rem 1.25rem; margin: 1.1rem 0; box-shadow: 0 1px 2px rgba(16,24,40,0.04); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.8rem; }}
  .metric {{ background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 0.6rem 0.8rem; }}
  .metric-label {{ color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; }}
  .metric-value {{ font-size: 1.5rem; font-weight: 700; margin-top: 0.2rem; }}
  .good {{ color: var(--good); }} .warn {{ color: var(--warn); }} .danger {{ color: var(--danger); }} .accent {{ color: var(--accent); }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 0.4rem; }}
  .tag {{ display: inline-block; padding: 0.18rem 0.55rem; border-radius: 5px; font-size: 0.76rem; font-family: var(--mono); font-weight: 600; }}
  .tag.covered {{ background: var(--good-bg); color: var(--good); }}
  .tag.uncovered {{ background: var(--warn-bg); color: var(--warn); }}
  .tag.refuted {{ background: var(--danger-bg); color: var(--danger); }}
  .tag.info {{ background: var(--info-bg); color: var(--info); }}
  .tag.muted {{ background: #eef1f6; color: var(--muted); }}
  .killchain {{ display: flex; align-items: stretch; gap: 0.25rem; flex-wrap: wrap; margin: 0.4rem 0 0.2rem; }}
  .kc-phase {{ flex: 1 1 0; min-width: 108px; border-radius: 6px; padding: 0.6rem 0.5rem; text-align: center; border: 1px solid var(--line); }}
  .kc-name {{ font-size: 0.74rem; font-weight: 600; }}
  .kc-count {{ font-size: 1.3rem; font-weight: 700; margin-top: 0.2rem; }}
  .kc-covered {{ background: var(--good-bg); color: var(--good); border-color: #86efac; }}
  .kc-partial {{ background: var(--warn-bg); color: var(--warn); border-color: #fcd34d; }}
  .kc-gap {{ background: var(--danger-bg); color: var(--danger); border-color: #fca5a5; }}
  .kc-arrow {{ display: flex; align-items: center; color: var(--muted); font-size: 1.4rem; }}
  .finding {{ border: 1px solid var(--line); border-left: 4px solid var(--line); border-radius: 6px; padding: 0.7rem 0.85rem; margin: 0.6rem 0; background: var(--bg); }}
  .finding-head {{ display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }}
  .finding .fid {{ font-family: var(--mono); font-weight: 700; }}
  .finding-desc {{ margin: 0.45rem 0; }}
  .card-meta {{ font-size: 0.82rem; color: var(--muted); }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.45rem; }}
  .chip {{ background: #eef1f6; border: 1px solid var(--line); border-radius: 4px; padding: 0.15rem 0.45rem; font-family: var(--mono); font-size: 0.72rem; color: #334155; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 0.55rem 0.6rem; border-bottom: 1px solid var(--line); vertical-align: top; }}
  th {{ color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; }}
  pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f8fafc; border: 1px solid var(--line); border-radius: 6px; padding: 0.8rem; font-family: var(--mono); font-size: 0.82rem; color: #334155; }}
  ul {{ margin: 0.3rem 0 0; padding-left: 1.2rem; }}
  .appendix-divider {{ margin-top: 2rem; border-top: 3px double var(--line); padding-top: 0.5rem; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; }}
  @media print {{
    body {{ background: #fff; }}
    main {{ max-width: none; padding: 0 0.5rem; }}
    section, .card, .finding {{ box-shadow: none; break-inside: avoid; }}
    .banner {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .tag, .kc-phase, .chip {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    #executive-brief {{ break-after: page; }}
    a[href^="trace"] {{ display: none; }}
  }}
</style>
</head>
<body>
<header class="banner">
  <div class="wrap">
    <div>
      <div class="classification">INTERNAL - DFIR WORK PRODUCT</div>
      <h1>SAVVYDFIR-MCP Investigation Report</h1>
      <div class="case">{html.escape(payload['case_id'])} &middot; Generated {html.escape(str(payload.get('report_generated_at', '')))}{trace_links}</div>
    </div>
    <div class="statuspill">{html.escape(str(summary.get('status', 'UNKNOWN')))} / {html.escape(str(triage_status))}</div>
  </div>
</header>
<main>
  <section id="executive-brief">
    <h2>Summary</h2>
    {_render_executive_summary(payload)}
    <div class="grid" style="margin-top: 1rem;">
      {by_numbers}
    </div>
  </section>

  {no_confirmed_banner}

  {render_activity_thread_html(activity_thread)}

  <section>
    <h2>ATT&amp;CK Coverage</h2>
    <p class="muted">Tactic-level coverage (covered / gap) is authoritative. Technique and finding columns are inferred from the findings mapped to each tactic.</p>
    <table>
      <thead><tr><th>Tactic</th><th>Status</th><th>Techniques observed</th><th>Findings</th><th>Suggested next tools</th></tr></thead>
      <tbody>{_render_attack_coverage_table(coverage, top_findings)}</tbody>
    </table>
  </section>

  <section>
    <h2>Key Event Timeline</h2>
    {_render_timeline(top_findings)}
  </section>

  <section>
    <h2>Top Confirmed Findings</h2>
    {_render_finding_cards(confirmed_findings, show_corroboration=True) if confirmed_findings else "<p class='muted'>No confirmed findings; all evidence requires further corroboration.</p>"}
  </section>

  <section>
    <h2>Active Leads &amp; Recommended Pivots</h2>
    <p class="muted" style="font-size: 0.92em;">These are <strong>unconfirmed</strong> findings - single-source observations and leads to pivot on, not corroborated conclusions. Only items in "Top Confirmed Findings" above meet the multi-source CONFIRMED bar.</p>
    <table>
      <thead><tr><th>Severity</th><th>Detector</th><th>Confidence</th><th>Description</th><th>Recommended Next Pivot</th></tr></thead>
      <tbody>{_render_leads(actionable_leads)}</tbody>
    </table>
    <h3 style="margin-top: 1rem;">Active Finding Leads</h3>
    {_render_finding_cards(active_findings, show_corroboration=False)}
  </section>

  {corroboration_section_html}

  <section>
    <h2>Indicators of Compromise</h2>
    <table>
      <thead><tr><th>Indicator</th><th>Type</th><th>Source Finding</th><th>Status</th><th>Technique</th></tr></thead>
      <tbody>{_render_ioc_table(top_findings)}</tbody>
    </table>
  </section>

  <section>
    <h2>Anti-Forensics Warnings</h2>
    <ul>{_render_warning_items(anti_forensics_warnings)}</ul>
  </section>

  <section>
    <h2>Data Gaps</h2>
    <ul>{_render_warning_items(data_gaps)}</ul>
  </section>

  <div class="appendix-divider">Technical Appendix</div>

  <section>
    <h2>Sigma Anomaly Summary</h2>
    <pre>{html.escape(str(sigma.get('summary_markdown', 'No anomalies detected.')))}</pre>
  </section>

  <section>
    <h2>Full Finding Index ({len(payload.get('all_findings') or [])})</h2>
    <p class="muted" style="font-size: 0.92em;">Every recorded finding, so any <span class="mono">F-NNN</span> can be looked up from this report alone. CONFIRMED = multi-source corroborated conclusion; ACTIVE/OBSERVATION = an unconfirmed lead (a single-source observation, not yet a conclusion).</p>
    {_render_finding_index(payload.get('all_findings') or [])}
  </section>

  <section>
    <h2>Recorded Hunting Hypotheses</h2>
    <p class="muted" style="font-size: 0.92em;">Each hypothesis formed during the hunt and its verdict after testing against the evidence: proven (CONFIRMED), disproven (REFUTED), or inconclusive (SUSPENDED). "Linked finding IDs" are the F-NNN that proved, refuted, or materially informed the verdict.</p>
    {(f'<p class="tag uncovered" style="display:inline-block">Hunt loop not fully closed: {_count_unresolved_hypotheses(hypotheses)} of {len(hypotheses)} hypotheses still unresolved (ACTIVE/INVESTIGATING). Resolve each via record_hypotheses before final reporting.</p>' if _count_unresolved_hypotheses(hypotheses) else '')}
    <table>
      <thead><tr><th>Hypothesis ID</th><th>Attack Class</th><th>Verdict</th><th>Linked finding IDs</th><th>MITRE</th></tr></thead>
      <tbody>{_render_hypothesis_validation(hypotheses)}</tbody>
    </table>
  </section>

  <section>
    <h2>Analysis Lanes</h2>
    <table>
      <thead><tr><th>Lane</th><th>Status</th><th>Required</th><th>Agents</th><th>Executions</th><th>Findings</th><th>Summary</th></tr></thead>
      <tbody>{_render_lane_rows(analysis_lanes)}</tbody>
    </table>
  </section>

  <section>
    <h2>Orchestration Warnings</h2>
    <ul>{_render_json_items(orchestration_warnings)}</ul>
  </section>

  <section>
    <h2>Open Questions</h2>
    <ul>
      {''.join(f"<li>{html.escape(str(question))}</li>" for question in open_questions) if open_questions else '<li>No open questions recorded.</li>'}
    </ul>
  </section>

  <section>
    <h2>Status Flags</h2>
    <pre>{html.escape(json.dumps(status_flags, indent=2, default=str))}</pre>
  </section>

  <section>
    <h2>Findings Status Breakdown</h2>
    <div class="grid">
      {''.join(f'<div class="metric"><div class="metric-label">{html.escape(k)}</div><div class="metric-value">{v}</div></div>' for k, v in sorted(status_breakdown.items()))}
    </div>
  </section>
</main>
</body>
</html>
"""


def generate_report_payload(
    *,
    case_id: str,
    state_manager: Any,
    sigma_scan_fn: Callable[[str], dict[str, Any]],
    coverage_fn: Callable[[str], dict[str, Any]],
    reports_root: str = "./reports",
    allow_partial: bool = False,
    delegate_path: str | None = None,
) -> dict[str, Any]:
    """Build the final report payload, write HTML, and then mark the case complete."""
    report_dir = (Path(reports_root) / case_id).resolve()
    report_path = report_dir / "report.html"
    report_json_path = report_dir / "report.json"
    graph_html_path = report_dir / "graph.html"
    graph_json_path = report_dir / "graph.json"

    delegate_file = Path(
        delegate_path
        or os.environ.get("SAVVYDFIR_DELEGATE_PATH")
        or "/tmp/savvydfir_delegate.json"
    )

    # DEFECT-3: dismiss stale delegates first.
    # Walks the per-lane queue, marks entries whose lane is already
    # satisfied by the same specialist (or has Path B allowance) as
    # stale_dismissed. Returns (dismissed, still_blocking) for audit.
    stale_delegates_dismissed, _live_delegates = _dismiss_stale_delegates(
        case_id, state_manager
    )

    # Also dismiss the single-file legacy delegate if its corresponding
    # lane has been completed by the requested specialist.
    if delegate_file.exists():
        try:
            _legacy_delegate = json.loads(delegate_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _legacy_delegate = None
        if isinstance(_legacy_delegate, dict) and _legacy_delegate.get("processed") is False:
            _legacy_lane = str(_legacy_delegate.get("lane_id") or "").strip()
            _legacy_specialist = _normalize_specialist(_legacy_delegate.get("subagent_type"))
            if _legacy_lane:
                _legacy_lane_record = _find_lane_in_state(
                    case_id, state_manager, _legacy_lane
                )
                # W1.7 Run-5 BUG-B (nuance): legacy single-file delegate
                # path is the surface _pending_delegate_blocks_case reads. Same
                # synthesis Path-A dismissal logic must apply here, not just
                # to the per-lane queue.
                _legacy_lane_done = (
                    _legacy_lane_record is not None
                    and str(_legacy_lane_record.get("status") or "").upper()
                    in {"COMPLETE", "COMPLETE_WITH_GAPS"}
                )
                _legacy_dismiss_event = None
                _legacy_dismiss_basis = None
                if _legacy_lane_done and _lane_recorded_by_same_specialist(
                    _legacy_lane_record, _legacy_specialist
                ):
                    _legacy_dismiss_event = "delegate_satisfied_by_lane_record"
                    _legacy_dismiss_basis = (
                        "legacy single-file delegate; lane satisfied by same specialist"
                    )
                elif _legacy_lane_done and _inline_synthesis_satisfies_delegate(
                    lane_record=_legacy_lane_record,
                    delegate_subagent=_legacy_specialist,
                    state_findings=_safe_get_findings(state_manager),
                    state_manager=state_manager,
                ):
                    _legacy_dismiss_event = "delegate_satisfied_by_inline_synthesis"
                    _legacy_dismiss_basis = (
                        "legacy single-file delegate; lane satisfied by main-agent "
                        "inline synthesis Path A (W1.7 inversion)"
                    )

                if _legacy_dismiss_event is not None:
                    # Mark the legacy file processed in-place so the
                    # downstream check below treats it as cleared.
                    try:
                        _legacy_delegate["processed"] = True
                        _legacy_delegate["status"] = "stale_dismissed"
                        _legacy_delegate["processed_reason"] = _legacy_dismiss_event
                        delegate_file.write_text(
                            json.dumps(_legacy_delegate, indent=2), encoding="utf-8"
                        )
                    except OSError:
                        pass
                    stale_delegates_dismissed.append({
                        "delegate_key": _legacy_delegate.get("delegate_key", ""),
                        "lane_id": _legacy_lane,
                        "subagent_type": _legacy_specialist,
                        "event": _legacy_dismiss_event,
                        "basis": _legacy_dismiss_basis,
                        "source": "legacy_single_file",
                    })

    if delegate_file.exists():
        try:
            pending_delegate = json.loads(delegate_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pending_delegate = {"path": str(delegate_file), "error": "unreadable delegate file"}
        if (
            isinstance(pending_delegate, dict)
            and _pending_delegate_blocks_case(
                pending_delegate,
                case_id=case_id,
                delegate_file=delegate_file,
            )
            and not allow_partial
        ):
            # Tier-B2: enrich deny message with
            # allow_partial=True escape hatch. The agent shouldn't loop
            # forever trying to clear a stuck delegate.
            return {
                "status": "needs_delegate",
                "tool": "generate_report",
                "case_id": case_id,
                "reason": (
                    "A specialist delegate is pending; final report files were not written. "
                    "If this delegate keeps regenerating despite record_analysis_lane writes, "
                    "the delegate may be stuck - call generate_report(case_id, allow_partial=True) "
                    "to force partial-report mode. Partial reports clearly label which findings/lanes "
                    "were incomplete and are NOT court-defensible without re-running the missing tools."
                ),
                "pending_delegate": pending_delegate,
                "next_required_tool": "record_analysis_lane",
                "allow_partial_hint": True,
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
                # DEFECT-3: surface dismissed-stale entries so the operator
                # can verify what the gate already cleared automatically.
                "stale_delegates_dismissed": stale_delegates_dismissed,
            }

    graph_missing = not (graph_html_path.exists() or graph_json_path.exists())
    if graph_missing and not allow_partial:
        return {
            "status": "needs_graph",
            "tool": "generate_report",
            "case_id": case_id,
            "reason": "Graph output is required before final report files are written.",
            "next_required_tool": "generate_graph",
            "recommended_call": {
                "tool": "generate_graph",
                "arguments": {"case_id": case_id},
            },
            "report_path": str(report_path),
            "report_json_path": str(report_json_path),
            "graph_path": str(graph_html_path),
            "graph_json_path": str(graph_json_path),
        }

    sigma_result = sigma_scan_fn(case_id)
    if sigma_result.get("status") == "error":
        return {
            "status": "error",
            "tool": "generate_report",
            "error": sigma_result.get("error", "sigma_scan preflight failed"),
            "sigma_scan": sigma_result,
        }

    coverage_result = coverage_fn(case_id)
    if coverage_result.get("status") == "error":
        return {
            "status": "error",
            "tool": "generate_report",
            "error": coverage_result.get("error", "coverage_report failed"),
            "sigma_scan": sigma_result,
            "coverage": coverage_result,
        }

    findings = state_manager.get_findings()
    executions = state_manager.get_executions()
    if not allow_partial:
        # Phase 5: investigation-success gate.
        # Checked BEFORE the existing coverage gate so the operator first
        # sees specialist-contribution failures (which are usually the
        # actionable signal), then tool-coverage failures.
        success_check = evaluate_investigation_success_gate(
            case_id=case_id,
            state_manager=state_manager,
        )
        if success_check.get("status") == "needs_specialist_contribution":
            return {
                **success_check,
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
            }

    # W1.7 (Run 2 review 2026-05-24, Q4 / ordering): hypothesis
    # gate is now EXTRACTED from the `if not allow_partial:` wrapper so it
    # fires even under partial mode. Run 2 used allow_partial=True to bypass
    # a stuck synthesis delegate and the hypothesis gate was silently
    # disabled. Only SAVVYDFIR_SKIP_HYPOTHESIS_GATE=1 (audited) bypasses
    # now; allow_partial=True still bypasses delegate/coverage/provenance
    # checks but NOT hypothesis formation. Ordering preserved: in non-partial
    # runs, success_check still runs first (above).
    confirmed_count = sum(
        1 for f in findings
        if str(f.get("finding_status") or "").upper() == "CONFIRMED"
    )
    hypothesis_check = evaluate_hypothesis_gate(
        case_id=case_id,
        state_manager=state_manager,
        findings_count=len(findings),
        confirmed_count=confirmed_count,
        sigma_result=sigma_result,
    )
    if hypothesis_check.get("status") == "needs_hypothesis":
        return {
            **hypothesis_check,
            "report_path": str(report_path),
            "report_json_path": str(report_json_path),
        }

    # PART B (review 2026-06-03): analysis-debt roots + WARN list, computed
    # ONCE and surfaced into report.json/HTML regardless of allow_partial (WARN
    # never blocks; it documents extracted-but-unmined artifacts for defensibility).
    analysis_roots = tuple(
        r for r in (
            str(Path(os.environ.get("OUTPUT_BASE", "/cases")).resolve()),
            "/cases",
            str(Path(os.environ.get("SAVVYDFIR_ANALYSIS_DIR", "./analysis")).resolve()),
        ) if r
    )
    _debt = compute_analysis_debt(
        executions, findings, state_manager.get_file_access_selector(),
        analysis_roots=analysis_roots,
    )
    analysis_debt_warning = _debt.get("warning", [])
    analysis_debt_blocking = _debt.get("blocking", [])

    if not allow_partial:
        try:
            _memory_present = bool(state_manager.get_memory_present())
        except Exception:
            _memory_present = True
        coverage_check = evaluate_ir_coverage_gate(
            findings=findings,
            executions=executions,
            sigma_result=sigma_result,
            analysis_lanes=state_manager.get_analysis_lanes(),
            selector=state_manager.get_file_access_selector(),
            analysis_roots=analysis_roots,
            memory_present=_memory_present,
        )
        if not coverage_check["ok"]:
            # Tier-B2: surface allow_partial=True
            # escape hatch in the deny message so the agent doesn't loop.
            return {
                "status": "needs_coverage",
                "tool": "generate_report",
                "case_id": case_id,
                "reason": (
                    "Required Windows IR artifact coverage is incomplete. "
                    "If this gate keeps blocking after repeated tool calls, "
                    "investigate WHY the tool is missing (look at audit.jsonl "
                    "for the failing execution) or call "
                    "generate_report(case_id, allow_partial=True) to force "
                    "partial-report mode. Partial reports clearly label which "
                    "tools were missing and are NOT court-defensible without "
                    "re-running them."
                ),
                "missing_coverage": coverage_check["missing"],
                "next_required_tool": coverage_check["next_required_tool"],
                "allow_partial_hint": True,
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
            }

        # Tier-A report-gate invariants:
        # CONFIRMED findings MUST have (1) resolvable execution_id and
        # (2) populated alternative-hypothesis disposition. Block report
        # generation if either is missing; allow_partial=True partitions
        # instead of blocking (handled in the report-body path below).
        provenance_block: list[dict[str, Any]] = []
        alt_hypothesis_block: list[dict[str, Any]] = []
        for f in findings:
            status_label = str(f.get("finding_status") or "").upper()
            if status_label != "CONFIRMED":
                continue
            if f.get("requires_re_extraction"):
                provenance_block.append({
                    "finding_id": f.get("finding_id"),
                    "finding_type": f.get("finding_type"),
                    "execution_id": f.get("execution_id"),
                    "reason": "requires_re_extraction=True",
                })
                continue  # don't double-report alt-hyp on already-flagged
            ah_ok, ah_reason = _alternative_hypothesis_complete(f)
            if not ah_ok:
                alt_hypothesis_block.append({
                    "finding_id": f.get("finding_id"),
                    "finding_type": f.get("finding_type"),
                    "reason": ah_reason,
                })
        if provenance_block:
            return {
                "status": "needs_re_extraction",
                "tool": "generate_report",
                "case_id": case_id,
                "reason": (
                    "CONFIRMED findings cite execution_ids that are not "
                    "resolvable in the current evidence ledger. Re-extract "
                    "the underlying tool runs in this session, OR pass "
                    "allow_partial=True to partition these findings into a "
                    "'Requires Re-extraction Before Trial Use' section."
                ),
                "findings_needing_re_extraction": provenance_block,
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
            }
        if alt_hypothesis_block:
            return {
                "status": "needs_alternative_hypothesis",
                "tool": "generate_report",
                "case_id": case_id,
                "reason": (
                    "CONFIRMED findings are missing structured "
                    "alternative-hypothesis disposition. Populate "
                    "alternative_hypothesis + evidence_against_it + "
                    "disposition='ruled_out' (or 'not_applicable' with "
                    "alternative_hypothesis_not_applicable_reason). "
                    "Pass allow_partial=True to partition instead."
                ),
                "findings_missing_alternative_hypothesis": alt_hypothesis_block,
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
            }

    pre_summary = state_manager.to_summary()
    report_dir.mkdir(parents=True, exist_ok=True)

    status_breakdown = _count_by_key(findings, "finding_status")
    evidence_kind_breakdown = _count_by_key(findings, "evidence_kind")
    finding_kind_breakdown = _count_by_key(findings, "finding_kind")
    finding_quality = _finding_quality_summary(findings)
    report_generated_at = datetime.now(timezone.utc).isoformat()

    actionable_leads = list(sigma_result.get("actionable_leads", []))
    validation = validate_report(
        state_manager=state_manager,
        findings=findings,
        sigma_result=sigma_result,
    )
    anti_forensics_warnings = validation["anti_forensics_warnings"]
    data_gaps = validation["data_gaps"]
    status_flags = validation["status_flags"]
    triage_status = validation["triage_status"]

    # PART B: surface WARN-tier analysis debt (extracted-but-unmined, non
    # taxonomy-required) into data_gaps so report.json + HTML carry the
    # defensibility context. BLOCK-tier debt either blocked above (non-partial)
    # or is partitioned below as a labeled non-defensible section (partial mode).
    for _d in analysis_debt_warning:
        data_gaps.append({
            "artifact_family": _d.get("tool_suffix"),
            "classification": "analysis_debt_warning",
            "reason": (
                f"{_d.get('tool_suffix')} extracted {_d.get('handle_path')} but no analyst "
                f"finding mined it (run_analysis alone does not clear). "
                f"{'A run_analysis query was recorded; ' if _d.get('run_analysis_seen') else ''}"
                f"submit_finding citing execution {_d.get('execution_id')} or record a "
                f"documented-absence result."
            ),
            "lane_id": _d.get("lane_id"),
            "execution_id": _d.get("execution_id"),
            "handle_path": _d.get("handle_path"),
            "next_required_tool": "run_analysis",
        })
    analysis_lanes = validation["analysis_lanes"]
    orchestration_warnings = validation["orchestration_warnings"]
    unresolved_discrepancies = [
        dict(finding) for finding in state_manager.get_unresolved_discrepancies()
    ]
    unresolved = len(unresolved_discrepancies)
    if graph_missing:
        graph_gap = {
            "artifact_family": "graph",
            "classification": "graph_missing",
            "reason": "Final report exists without graph.html or graph.json. Call generate_graph(case_id) before treating the case as fully complete.",
            "lane_id": "timeline_correlation",
            "next_required_tool": "generate_graph",
        }
        data_gaps = _merge_warning_lists(data_gaps, [graph_gap])
        status_flags = dict(status_flags)
        status_flags["graph_missing"] = True
        triage_status = "COMPLETE_WITH_GAPS"

    # W1.7 (CR13 Option X) - surface Activity Thread for blindspot reporting
    # and rebuild it from current findings so MITRE-classified findings get
    # mapped to kill-chain phases even if state.activity_thread is stale.
    activity_thread_state = state_manager.get_activity_thread()
    try:
        from sift_mcp.models.activity_thread import classify_finding_to_phase
        for f in findings:
            fid = f.get("finding_id")
            if not fid:
                continue
            techs = f.get("mitre_techniques") or f.get("mitre_technique") or []
            if isinstance(techs, str):
                techs = [techs] if techs.strip() else []
            phase = classify_finding_to_phase(techs)
            if phase is None:
                continue
            bucket = activity_thread_state.setdefault("phases", {}).setdefault(phase.value, [])
            if fid not in bucket:
                bucket.append(fid)
    except Exception:
        pass

    # Run-11 polish:
    #   #5 Dedupe sigma summary_markdown for display ONLY - never mutate the
    #      underlying sigma_result hits / counts. Build a display-only copy.
    sigma_for_display = dict(sigma_result) if isinstance(sigma_result, dict) else sigma_result
    if isinstance(sigma_for_display, dict):
        summary_md = sigma_for_display.get("summary_markdown")
        if isinstance(summary_md, str) and summary_md:
            seen: set[str] = set()
            dedup_lines: list[str] = []
            for line in summary_md.split("\n"):
                key = line.strip()
                if not key:
                    dedup_lines.append(line)
                    continue
                if key in seen:
                    continue
                seen.add(key)
                dedup_lines.append(line)
            sigma_for_display["summary_markdown"] = "\n".join(dedup_lines)
    #   #6 Surface CorrectionEvent count (criterion-#1 tiebreaker signal).
    correction_events_count = _count_correction_events(state_manager)

    payload = {
        "status": "ok",
        "case_id": case_id,
        "summary": {**pre_summary, "status": "COMPLETE", "triage_status": triage_status},
        "triage_status": triage_status,
        "status_flags": status_flags,
        "actionable_leads": actionable_leads,
        "analysis_lanes": analysis_lanes,
        "orchestration_warnings": orchestration_warnings,
        "anti_forensics_warnings": anti_forensics_warnings,
        "data_gaps": data_gaps,
        "activity_thread": activity_thread_state,
        # Render-time re-application of the hunting-hypothesis verdict gate
        # (defense in depth + corrects hypotheses recorded before the gate
        # existed): a CONFIRMED/REFUTED verdict not backed by a multi-source
        # finding is shown as SUSPENDED, never over-claimed in the report.
        "hypotheses": [
            apply_hypothesis_status_gate(h, state_manager)
            for h in (state_manager.get_hypotheses() or [])
        ],
        "findings_count": pre_summary.get("findings_count", 0),
        "unresolved_count": unresolved,
        "unresolved_discrepancies": unresolved_discrepancies,
        "correction_events_count": correction_events_count,
        "open_questions": pre_summary.get("open_questions", []),
        "sigma_scan": sigma_for_display,
        "coverage": coverage_result,
        "artifact_coverage": coverage_result,
        # PART B: extracted-but-unmined artifact handles. warning = non-blocking
        # (surfaced for defensibility); blocking = taxonomy-required file-access
        # handles. In allow_partial mode these blocking entries ship as a labeled
        # non-defensible section instead of blocking report generation.
        "analysis_debt": {
            "warning": analysis_debt_warning,
            "blocking_non_defensible": analysis_debt_blocking if allow_partial else [],
        },
        # FK-wiring ITEM C: advisory per-finding corroboration pivots (additive,
        # render-only, fail-open). Does NOT affect coverage/suggested_next_tools.
        "finding_corroboration_pivots": build_finding_corroboration_pivots(
            findings, analysis_lanes
        ),
        "top_findings": _rank_findings(findings),
        "status_breakdown": status_breakdown,
        "evidence_kind_breakdown": evidence_kind_breakdown,
        "finding_kind_breakdown": finding_kind_breakdown,
        "finding_quality_summary": finding_quality,
        "report_generated_at": report_generated_at,
        "report_path": str(report_path),
        "report_json_path": str(report_json_path),
        "graph_path": str(graph_html_path) if graph_html_path.exists() else None,
        "graph_json_path": str(graph_json_path) if graph_json_path.exists() else None,
        # Run-11 trace integration: mark trace.html present
        # only when the sibling file actually exists. The renderer treats this
        # as a boolean signal - the href is rendered as a fixed relative
        # string "trace.html" (NOT interpolated from this field) to avoid
        # href-injection via report state. The trace itself is produced by
        # `scripts/render_session_trace.py`, an operator-explicit helper.
        # Detailed companion: `trace-detailed.html` is the FULL-detail
        # render (`--detail full`) of the session - every event preserved
        # post-redaction. `trace.html` is the filtered scan-friendly view.
        "trace_path": "trace.html" if (report_dir / "trace.html").exists() else None,
        "trace_detailed_path": "trace-detailed.html" if (report_dir / "trace-detailed.html").exists() else None,
        "next_required_tool": "generate_graph" if graph_missing else None,
    }
    payload["top_confirmed_findings"] = [
        dict(finding)
        for finding in payload["top_findings"]
        if _status_label(finding.get("finding_status")) == "CONFIRMED"
    ][:10]
    payload["top_active_leads"] = [
        dict(finding)
        for finding in payload["top_findings"]
        if _status_label(finding.get("finding_status")) in {"HYPOTHESIS", "ACTIVE", "OBSERVATION"}
        and str(finding.get("finding_kind") or "validated").lower() != "raw_detector_hit"
    ][:10]
    # Full finding index for the report appendix (every finding, compact) so any
    # F-NNN is auditable from the report alone. Case-agnostic: maps over the live
    # findings list, no hardcoded values; also written into report.json.
    payload["all_findings"] = [
        {
            "finding_id": f.get("finding_id"),
            "finding_status": _status_label(f.get("finding_status")),
            "confidence": f.get("confidence"),
            "evidence_kind": f.get("evidence_kind"),
            "finding_type": f.get("finding_type"),
            "mitre_technique": f.get("mitre_technique"),
            "tool_name": f.get("tool_name"),
            "execution_id": f.get("execution_id"),
            "description": _short_description(str(f.get("description", "")), 160),
        }
        for f in findings
    ]

    state_manager.update_triage_state(
        triage_status=triage_status,
        status_flags=status_flags,
        analysis_lanes=analysis_lanes,
        actionable_leads=actionable_leads,
        artifact_coverage=coverage_result,
        anti_forensics_warnings=anti_forensics_warnings,
        data_gaps=data_gaps,
    )
    state_manager.set_status("COMPLETE")
    summary = state_manager.to_summary()
    payload["summary"] = summary
    payload["triage_status"] = summary.get("triage_status", triage_status)
    payload["status_flags"] = summary.get("status_flags", status_flags)
    payload["analysis_lanes"] = summary.get("analysis_lanes", analysis_lanes)
    payload["orchestration_warnings"] = orchestration_warnings
    payload["findings_count"] = summary.get("findings_count", 0)
    payload["unresolved_count"] = len(payload.get("unresolved_discrepancies", []))
    status_flags_payload = dict(payload.get("status_flags") or {})
    status_flags_payload["unresolved_discrepancy"] = payload["unresolved_count"] > 0
    payload["status_flags"] = status_flags_payload
    payload["open_questions"] = summary.get("open_questions", [])
    report_path.write_text(render_report_html(payload), encoding="utf-8")
    report_json_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return payload
