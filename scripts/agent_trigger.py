#!/usr/bin/env python3
"""Canonical SAVVYDFIR PostToolUse dispatcher."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Per-lane delegate queue (replaces single trigger file)
# Handle import from scripts/ directory
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from delegate_queue import (
    enqueue_delegate,
    get_pending_delegate,
    mark_delegate_processed,
    is_tool_already_queued,
)

# Phase 3a observation-only ledger.
# Import is best-effort - ledger absence must never break the hook.
try:
    import delegation_ledger as _ledger  # type: ignore  # noqa: WPS433
except Exception:  # pragma: no cover - import safety net
    _ledger = None  # type: ignore[assignment]


def _ledger_specialist_for_lane(lane_id: str) -> str:
    """Resolve a specialist subagent name from a lane id by scanning the
    TOOL_AGENT_MAP. Used when a Task tool fires without an originating
    MCP tool linkage - we recover the specialist by lane."""
    if not lane_id:
        return ""
    for _tool, (specialist, mapped_lane, _instruction) in TOOL_AGENT_MAP.items():
        if mapped_lane == lane_id:
            return specialist
    return ""


def _ledger_lane_for_specialist(specialist: str) -> str:
    """Resolve a lane id from a specialist name (inverse lookup)."""
    if not specialist:
        return ""
    normalized = specialist.lower().lstrip("@").strip()
    for _tool, (mapped_specialist, lane, _instruction) in TOOL_AGENT_MAP.items():
        if mapped_specialist.lower() == normalized:
            return lane
    return ""


def _ledger_extract_task_response_text(event: dict[str, Any]) -> str:
    """Pull a flat text payload out of a PostToolUse Task event response."""
    for key in ("tool_response", "toolResponse", "tool_result", "toolResult", "response"):
        payload = event.get(key)
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            content = payload.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts: list[str] = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            parts.append(text)
                if parts:
                    return "\n".join(parts)
            text = payload.get("text") or payload.get("output")
            if isinstance(text, str):
                return text
        if isinstance(payload, list):
            parts = []
            for item in payload:
                if isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str) and text:
                        parts.append(text)
            if parts:
                return "\n".join(parts)
    return ""


def _is_contract_shaped(obj: Any) -> bool:
    """C-PRIME: a contract-shaped JSON has lane_id AND (status OR finding_ids).

    This rules out incidental JSON snippets (tool outputs, dict fragments
    in prose) that happen to parse but aren't the specialist's final
    contract return.
    """
    if not isinstance(obj, dict):
        return False
    if "lane_id" not in obj:
        return False
    return ("status" in obj) or ("finding_ids" in obj) or ("finding_ids_promoted" in obj)


def _ledger_classify_task_outcome(response_text: str) -> tuple[str, str]:
    """Classify a Task return into one of FAILED_OUTCOMES / 'success' /
    'success_with_gaps'.

    (C-PRIME):
      * Specialists now emit interim JSON after every run_analysis call,
        producing MULTIPLE JSON objects in the response. We must prefer
        the LAST contract-shaped JSON, not the first.
      * "Contract-shaped" requires lane_id AND (status OR finding_ids) so
        incidental braced text (tool outputs, dict snippets in prose)
        doesn't masquerade as the final return.
      * status="COMPLETE_WITH_GAPS" returns outcome="success_with_gaps"
        so we can track gap-marked completions separately from clean
        COMPLETE. Both are non-failure.

    Returns (outcome, excerpt) where excerpt is the first 200 chars of
    the response, useful for the ledger row.
    """
    excerpt = (response_text or "")[:200]
    if not response_text or not response_text.strip():
        return ("timeout", excerpt)

    lowered = response_text.lower()
    for marker in ("interrupted", "tool call limit", "exceeded budget", "task error"):
        if marker in lowered:
            return ("error", excerpt)

    import re as _re
    candidates: list[str] = []
    # 1. Fenced code blocks (```json {...} ```)
    for match in _re.finditer(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", response_text):
        candidates.append(match.group(1))
    # 2. Every top-level braced section (greedy match for nested braces).
    #    Scan left-to-right, tracking brace depth, so we collect each
    #    complete top-level JSON candidate as a separate string.
    depth = 0
    start = -1
    for idx, ch in enumerate(response_text):
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    candidates.append(response_text[start : idx + 1])
                    start = -1

    # Walk candidates from LAST to FIRST, returning the last contract-shaped one.
    last_contract: Any = None
    for candidate in reversed(candidates):
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if _is_contract_shaped(obj):
            last_contract = obj
            break

    if last_contract is not None:
        status = str(last_contract.get("status") or "").upper().strip()
        if status == "COMPLETE_WITH_GAPS":
            return ("success_with_gaps", excerpt)
        if status == "PARTIAL":
            return ("success_with_gaps", excerpt)
        return ("success", excerpt)

    has_braces = "{" in response_text and "}" in response_text
    if has_braces:
        return ("malformed_json", excerpt)
    return ("prose_only", excerpt)


def _ledger_handle_task_event(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    """PostToolUse handler for Task - emits task_attempt + task_outcome
    ledger rows. Best-effort, never raises.

    C-PRIME: on outcome ∈
    {prose_only, malformed_json}, also emit a repair_required ledger row
    AND return a non-blocking hookSpecificOutput dict instructing the
    parent agent to spawn a json-repair Task. Idempotent - if a
    repair_attempted row already exists for the same delegate_key in
    this session, no instruction is emitted.

    Returns the hook response dict (or None for clean outcomes).
    """
    import re as _re  # function-scoped - used for lane recovery on repair Tasks
    if _ledger is None:
        return None
    inputs = _event_input_dicts(event)
    subagent_type = ""
    for payload in inputs:
        candidate = payload.get("subagent_type") or payload.get("agent")
        if isinstance(candidate, str) and candidate.strip():
            subagent_type = candidate.strip().lstrip("@")
            break
    if not subagent_type:
        return None

    # C-PRIME: a json-repair Task itself never triggers another repair
    # (no recursion). We DO record its outcome so we can audit repair
    # success rates, but we skip the repair-required emit on failure.
    is_repair_invocation = subagent_type == "json-repair"

    lane_id = _ledger_lane_for_specialist(subagent_type)
    if not lane_id and not is_repair_invocation:
        # Unknown specialist (not in the SAVVYDFIR set) - ignore entirely.
        return None

    # adversarial review 2026-05-22 [HIGH]: when this is a json-repair
    # Task, recover the ORIGINAL lane_id (the lane the specialist that
    # truncated belongs to) so the Phase 5 investigation-success gate can
    # credit the lane for the repair_succeeded fallback. Without this, the
    # repair fallback is dead-code from the gate's perspective.
    original_lane_id = ""
    original_specialist = ""
    if is_repair_invocation:
        # Source 1: parse the repair Task's prompt - it's templated with
        # "lane_id=<lane>" + "@<specialist> on lane".
        try:
            for payload in inputs:
                prompt_text = str(payload.get("prompt") or "")
                m = _re.search(r"lane_id=['\"]([^'\"]+)['\"]", prompt_text)
                if m:
                    original_lane_id = m.group(1)
                spec_m = _re.search(r"@([\w\-]+)\s+on lane", prompt_text)
                if spec_m:
                    original_specialist = spec_m.group(1)
                if original_lane_id and original_specialist:
                    break
        except Exception:
            pass
        # Source 2 (fallback): walk the ledger backwards for the most
        # recent repair_attempted / repair_required row in this session.
        if not original_lane_id or not original_specialist:
            try:
                rows = _ledger.read_session_rows(events={"repair_attempted", "repair_required"})
                for row in reversed(rows or []):
                    if not original_lane_id and row.get("lane_id"):
                        original_lane_id = str(row.get("lane_id"))
                    if not original_specialist and row.get("specialist"):
                        original_specialist = str(row.get("specialist"))
                    if original_lane_id and original_specialist:
                        break
            except Exception:
                pass

    attempt_id = _ledger.new_attempt_id()
    # For repair invocations, write the audit rows under the ORIGINAL lane
    # (and original specialist) so Phase 5's repair_by_lane lookup credits
    # the right lane. The "(repair)" placeholder is only used when even
    # the prompt-and-ledger fallback failed to resolve.
    audit_lane_id = (
        original_lane_id if (is_repair_invocation and original_lane_id) else (lane_id or "(repair)")
    )
    audit_specialist = (
        original_specialist if (is_repair_invocation and original_specialist) else subagent_type
    )
    try:
        _ledger.append_row(
            "task_attempt",
            lane_id=audit_lane_id,
            specialist=audit_specialist,
            attempt_id=attempt_id,
            extra={"repair_actor": subagent_type} if is_repair_invocation else None,
        )
    except Exception:
        return None

    response_text = _ledger_extract_task_response_text(event)
    outcome, excerpt = _ledger_classify_task_outcome(response_text)
    try:
        _ledger.append_row(
            "task_outcome",
            lane_id=audit_lane_id,
            specialist=audit_specialist,
            attempt_id=attempt_id,
            outcome=outcome,
            excerpt=excerpt,
            extra={"repair_actor": subagent_type} if is_repair_invocation else None,
        )
    except Exception:
        pass

    # C-PRIME: handle repair-side outcomes specifically (audit only, no
    # recursive repair).
    if is_repair_invocation:
        repair_event = "repair_succeeded" if outcome in {"success", "success_with_gaps"} else "repair_failed"
        try:
            _ledger.append_row(
                repair_event,
                lane_id=audit_lane_id,
                specialist=audit_specialist,
                attempt_id=attempt_id,
                outcome=outcome,
                excerpt=excerpt,
                extra={"repair_actor": "json-repair"},
            )
        except Exception:
            pass
        return None

    # C-PRIME: trigger repair on prose-only / malformed-json outcomes.
    if outcome in {"prose_only", "malformed_json"}:
        return _ledger_emit_repair_directive(
            subagent_type=subagent_type,
            lane_id=lane_id,
            failed_excerpt=excerpt,
            failed_response_text=response_text,
            attempt_id=attempt_id,
        )

    return None


def _ledger_emit_repair_directive(
    *,
    subagent_type: str,
    lane_id: str,
    failed_excerpt: str,
    failed_response_text: str,
    attempt_id: str,
) -> Optional[dict[str, Any]]:
    """C-PRIME: emit a non-blocking hookSpecificOutput directing the
    parent agent to spawn ONE json-repair Task. Idempotent via ledger:
    if repair_attempted already exists for this lane/specialist in the
    current session, skip emit.

    Returns the hook response dict or None when the directive is
    suppressed (idempotency / failure).
    """
    if _ledger is None:
        return None

    # Idempotency: search recent ledger rows for an existing
    # repair_attempted on this lane + specialist in the current session.
    try:
        sid = _ledger.read_current_session_id()
    except Exception:
        sid = None
    if sid:
        try:
            existing_attempts = _ledger.read_session_rows(
                lane_id=lane_id, event="repair_attempted"
            )
            for row in existing_attempts:
                if (row.get("specialist") or "").lower().lstrip("@") == subagent_type.lower():
                    return None  # already requested; don't spam
        except Exception:
            pass

    # Write repair_required row so the next PostToolUse event from a
    # json-repair Task can correlate via the lane_id.
    try:
        _ledger.append_row(
            "repair_required",
            lane_id=lane_id,
            specialist=subagent_type,
            attempt_id=attempt_id,
            excerpt=failed_excerpt,
        )
    except Exception:
        return None

    # Trim the failed response text for inclusion in the repair prompt.
    # insisted the repair Task get the raw text - otherwise a fresh
    # Task has no context to repair from.
    max_len = 6000
    trimmed = failed_response_text or ""
    if len(trimmed) > max_len:
        trimmed = trimmed[:max_len] + "\n\n[...truncated for repair prompt...]"

    repair_prompt = (
        "You are the json-repair specialist. The original "
        f"@{subagent_type} on lane_id={lane_id!r} returned prose without "
        "a complete contract JSON. Extract findings the original "
        "explicitly stated were being recorded / confirmed / added / "
        "summarized, and emit ONE JSON object per the json-repair "
        "agent definition. Do not call any tools. Do not investigate. "
        "Do not interpret speculation. If the original prose contains "
        "no explicitly registered findings, emit JSON with empty "
        "finding_ids and a HIGH-severity data_gap explaining that.\n\n"
        "=== ORIGINAL TRUNCATED RESPONSE ===\n"
        f"{trimmed}\n"
        "=== END ORIGINAL ==="
    )

    # Non-blocking telemetry-first: PostToolUse decision is omitted; we
    # instead surface the directive in `additionalContext` so the parent
    # sees it but isn't blocked. (required telemetry-first.)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"C-PRIME REPAIR DIRECTIVE: @{subagent_type} on lane "
                f"{lane_id!r} returned prose without contract JSON. "
                f"Spawn ONE Task with subagent_type='json-repair' and "
                f"the prompt below to salvage findings. This is "
                f"non-blocking — the framework records the directive "
                f"either way. Cost is ~10% of a full specialist spawn.\n\n"
                f"REPAIR PROMPT:\n{repair_prompt}"
            ),
        }
    }


def _ledger_mark_repair_attempted(lane_id: str, specialist: str) -> None:
    """Called when the parent has spawned the json-repair Task. Anchors
    idempotency so we don't re-emit the directive."""
    if _ledger is None:
        return
    try:
        _ledger.append_row(
            "repair_attempted",
            lane_id=lane_id,
            specialist=specialist,
        )
    except Exception:
        return


def _ledger_handle_delegation_required(trigger: dict[str, Any]) -> None:
    """Write a delegation_required ledger row right after a delegate is queued."""
    if _ledger is None:
        return
    lane_id = str(trigger.get("lane_id") or "").strip()
    specialist = str(trigger.get("subagent_type") or "").strip().lstrip("@")
    tool = str(trigger.get("tool") or "").strip()
    if not lane_id or not specialist:
        return
    try:
        _ledger.append_row(
            "delegation_required",
            lane_id=lane_id,
            specialist=specialist,
            tool=tool,
        )
    except Exception:
        return


def _ledger_refresh_session_pointer_from_event(event: dict[str, Any]) -> None:
    """Update /tmp/savvydfir_current_session.json from the PostToolUse event's
    session_id when needed.

    Claude Code's `claude -p ...` (one-shot mode) may not fire SessionStart
    on every invocation, so the session pointer can go stale across runs.
    PostToolUse events DO carry session_id, so we mirror it into the pointer
    whenever the pointer is missing or stale (different session_id).
    This makes ledger correlation robust to missed SessionStart firings.
    """
    if _ledger is None:
        return
    event_session_id = str(event.get("session_id") or event.get("sessionId") or "").strip()
    if not event_session_id:
        return
    try:
        current = _ledger.read_current_session_id()
    except Exception:
        current = None
    if current == event_session_id:
        return
    try:
        cwd = str(event.get("cwd") or "")
        _ledger.write_session_pointer(event_session_id, cwd=cwd or None)
    except Exception:
        return

# Map MCP tool -> subagent type + lane + default instruction
TOOL_AGENT_MAP: dict[str, tuple[str, str, str]] = {
    "mcp__savvydfir__extract_mft_timeline": (
        "mft-analyst",
        "timeline_correlation",
        "Analyze the MFT CSV for timestomping, attacker file drops, sequential entry clusters, and staging artifacts.",
    ),
    "mcp__savvydfir__extract_usn_journal": (
        "mft-analyst",
        "timeline_correlation",
        "Analyze the USN journal CSV with run_analysis only — do not load rows. "
        "Hunt for: rename-burst encryption (BasicInfoChange + DataExtend + "
        "RenameNewName to .encrypted/.locked extensions), large-file staging "
        "(>10MB writes under Temp/Downloads), and delete cascades preceded by "
        "Copy operations. Use the existing MFT findings to ground PID/path "
        "context. Cross-reference timestamps with EVTX 4688 process creation.",
    ),
    "mcp__savvydfir__summarize_evtx": (
        "evtx-analyst",
        "event_auth",
        "Analyze the EVTX CSV for auth anomalies, lateral movement, NTLM attacks, persistence, and log clearing.",
    ),
    "mcp__savvydfir__extract_registry_run_keys": (
        "registry-analyst",
        "disk_execution_persistence",
        "Analyze the registry CSV for ASEP persistence, fileless malware, LSA packages, and credential theft.",
    ),
    "mcp__savvydfir__get_amcache": (
        "amcache-analyst",
        "disk_execution_persistence",
        "Analyze the Amcache CSV for renamed malware (SHA-1), loose executables, and BYOVD drivers.",
    ),
    "mcp__savvydfir__extract_prefetch": (
        "prefetch-analyst",
        "disk_execution_persistence",
        "Analyze prefetch records for multi-path execution, SysWOW64 LOLBins, and orphaned .pf files.",
    ),
    "mcp__savvydfir__detect_injection": (
        "memory-analyst",
        "memory",
        "Analyze memory injection findings for confirmed code injection, DKOM hidden processes, and C2 indicators.",
    ),
    "mcp__savvydfir__list_dlls": (
        "memory-analyst",
        "memory",
        "Analyze loaded DLLs for unsigned modules, DLLs from staging paths, and unexpected network capability.",
    ),
    "mcp__savvydfir__sigma_hunt": (
        "sigma-analyst",
        "timeline_correlation",
        "Analyze the Sigma rule hits: triage false positives, confirm ATT&CK techniques, and cross-reference with existing findings.",
    ),
    "mcp__savvydfir__analyze_vss": (
        "evtx-analyst",
        "anti_forensics_recovery",
        "Analyze VSS shadow copy inventory and recover pre-incident logs when available.",
    ),
    "mcp__savvydfir__extract_pca": (
        "prefetch-analyst",
        "disk_execution_persistence",
        "Analyze PCA execution artifacts and correlate them with Amcache and Prefetch.",
    ),
    "mcp__savvydfir__extract_shimcache": (
        "registry-analyst",
        "disk_execution_persistence",
        "Analyze ShimCache entries, corroborate with Amcache/Prefetch, and flag suspicious execution paths.",
    ),
    "mcp__savvydfir__extract_srum": (
        "srum-analyst",
        "timeline_correlation",
        "Analyze SRUM network usage, quantify exfiltration volume, and flag deleted or unresolved applications.",
    ),
    "mcp__savvydfir__build_timeline": (
        "timeline-analyst",
        "timeline_correlation",
        "Use the storage handle to run narrow timeline pivots around attacker time windows, execution paths, and cleanup activity.",
    ),
    "mcp__savvydfir__query_timeline": (
        "timeline-analyst",
        "timeline_correlation",
        "Review the bounded timeline slice, identify the strongest pivots, and refine the next query window.",
    ),
    # User-activity extractors (OPTIONAL, FK-only). Mapped to the
    # disk_execution_persistence lane for completeness; legacy/opt-in field.
    "mcp__savvydfir__extract_shellbags": (
        "registry-analyst",
        "disk_execution_persistence",
        "Review ShellBag folder-navigation entries: a ShellBag proves Explorer rendered the folder, NOT file access. Corroborate with LNK / Jump Lists / RecentDocs.",
    ),
    "mcp__savvydfir__extract_lnk_files": (
        "registry-analyst",
        "disk_execution_persistence",
        "Review LNK shortcut targets: a LNK records a referenced path, NOT a human click. Corroborate with ShellBags + RecentDocs + Prefetch.",
    ),
    "mcp__savvydfir__extract_jump_lists": (
        "registry-analyst",
        "disk_execution_persistence",
        "Review Jump List destinations: they tie a target file to the application AppId. Corroborate with LNK + ShellBags.",
    ),
    "mcp__savvydfir__extract_browser_history": (
        "registry-analyst",
        "disk_execution_persistence",
        "Review browser visits/downloads: a record proves the browser process logged the event, NOT a human action. Corroborate downloads with $MFT / Prefetch.",
    ),
    "mcp__savvydfir__extract_registry_fileaccess": (
        "registry-analyst",
        "disk_execution_persistence",
        "Review file-access registry artifacts (UserAssist/RecentDocs/OpenSavePidlMRU/etc.): they prove a path was written to a user-activity list, NOT that a human clicked it.",
    ),
}

ERROR_PATTERNS: dict[str, str] = {
    "not found": "Tool output contains 'not found'. Check paths and tool availability.",
    "permission denied": "Permission denied. Check RBAC path model: evidence paths are read-only.",
    "timed out": "Tool timed out. Try a smaller dataset or increase timeout.",
    "no such file": "File not found. Verify evidence is mounted and paths are correct.",
}

DEFAULT_TRIGGER_PATH = "/tmp/savvydfir_delegate.json"
SAVVYDFIR_TOOL_PREFIXES = ("mcp__savvydfir__", "savvydfir__")
REPORT_GATE_TOOLS = {"generate_report", "mcp__savvydfir__generate_report"}
try:
    _trigger_age_raw = int(
        os.environ.get("SAVVYDFIR_TRIGGER_MAX_AGE_SECONDS", "21600") or "21600"
    )
except ValueError:
    _trigger_age_raw = 21600
TRIGGER_MAX_AGE_SECONDS = max(0, _trigger_age_raw)
DELEGATION_BYPASS_TOOLS = {
    # Lane control - unblocks the pending delegate
    "mcp__savvydfir__read_state",
    "mcp__savvydfir__record_analysis_lane",
    "read_state",
    "record_analysis_lane",
    # State inspection - needed to write a useful lane summary before calling record_analysis_lane
    "mcp__savvydfir__get_findings",
    "mcp__savvydfir__get_finding",
    "mcp__savvydfir__get_investigation_gates",
    "mcp__savvydfir__query_sigma_results",
    "get_findings",
    "get_finding",
    "get_investigation_gates",
    "query_sigma_results",
}
SUBAGENT_REQUIRED_FIELDS = {
    "lane_id",
    "status",
    "execution_ids",
    "finding_ids",
    "data_gaps",
    "summary",
    "confidence_notes",
}
SUBAGENT_FINAL_STATUSES = {"COMPLETE", "COMPLETE_WITH_GAPS", "FAILED"}


def _candidate_tool_names(tool_name: str) -> tuple[str, ...]:
    """Return equivalent tool-name forms (namespaced + bare) for dispatch matching."""
    normalized = str(tool_name or "").strip()
    if not normalized:
        return tuple()

    candidates = {normalized}
    if normalized.startswith("mcp__savvydfir__"):
        bare = normalized[len("mcp__savvydfir__"):]
        if bare:
            candidates.add(bare)
    elif normalized.startswith("savvydfir__"):
        bare = normalized[len("savvydfir__"):]
        if bare:
            candidates.add(bare)
            candidates.add(f"mcp__savvydfir__{bare}")
    elif not normalized.startswith("mcp__"):
        candidates.add(f"mcp__savvydfir__{normalized}")
    return tuple(candidates)


def _iter_text_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(_iter_text_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_iter_text_values(item))
        return values
    return []


def _json_objects_from_text(text: str) -> list[dict[str, Any]]:
    candidates: list[str] = []
    stripped = text.strip()
    if stripped:
        candidates.append(stripped)
    candidates.extend(
        match.group(1).strip()
        for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    )
    for start, ch in enumerate(text):
        if ch != "{":
            continue
        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(text)):
            current = text[idx]
            if escape:
                escape = False
                continue
            if current == "\\" and in_string:
                escape = True
                continue
            if current == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if current == "{":
                depth += 1
            elif current == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : idx + 1])
                    break

    parsed: list[dict[str, Any]] = []
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            parsed.append(obj)
    return parsed


def _extract_subagent_contract(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    for text in _iter_text_values(event):
        for obj in _json_objects_from_text(text):
            if "lane_id" in obj or "finding_ids" in obj or "execution_ids" in obj:
                return obj
    return None


def _subagent_contract_block_reason(pending: dict[str, Any], *, detail: str) -> str:
    lane_id = str(pending.get("lane_id") or "analysis")
    source = str(
        pending.get("source_artifact_path")
        or pending.get("csv_path")
        or pending.get("storage_path")
        or "the delegated artifact handle"
    )
    return (
        "SUBAGENT CONTRACT INVALID. "
        f"{detail} Parent must use Path B now: run focused run_analysis/add_finding "
        f"against {source}, then call record_analysis_lane(case_id=..., "
        f"lane_id={lane_id!r}, status='COMPLETE_WITH_GAPS', assigned_agent='main-agent', "
        "execution_ids=[...], finding_ids=[...], data_gaps=[...], summary=<one sentence>)."
    )


def process_subagent_stop(
    event: dict[str, Any], *, trigger_path: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Validate specialist final JSON before the parent resumes."""
    pending = _read_pending_trigger(trigger_path=trigger_path)
    if not pending:
        return None
    expected_lane = str(pending.get("lane_id") or "").strip()
    if not expected_lane:
        return None

    contract = _extract_subagent_contract(event)
    if contract is None:
        return {
            "decision": "block",
            "reason": _subagent_contract_block_reason(
                pending,
                detail="The specialist did not return parseable compact JSON with lane state.",
            ),
        }

    missing = sorted(field for field in SUBAGENT_REQUIRED_FIELDS if field not in contract)
    if missing:
        return {
            "decision": "block",
            "reason": _subagent_contract_block_reason(
                pending,
                detail=f"The specialist JSON is missing required fields: {missing}.",
            ),
        }

    lane_id = str(contract.get("lane_id") or "").strip()
    if lane_id != expected_lane:
        return {
            "decision": "block",
            "reason": _subagent_contract_block_reason(
                pending,
                detail=(
                    f"The specialist returned lane_id={lane_id!r}, but pending "
                    f"lane_id is {expected_lane!r}."
                ),
            ),
        }

    status = str(contract.get("status") or "").strip().upper()
    if status not in SUBAGENT_FINAL_STATUSES:
        return {
            "decision": "block",
            "reason": _subagent_contract_block_reason(
                pending,
                detail=f"The specialist returned invalid status={status!r}.",
            ),
        }

    for field in ("execution_ids", "finding_ids", "data_gaps", "confidence_notes"):
        if not isinstance(contract.get(field), list):
            return {
                "decision": "block",
                "reason": _subagent_contract_block_reason(
                    pending,
                    detail=f"The specialist field {field!r} must be a list.",
                ),
            }
    if not str(contract.get("summary") or "").strip():
        return {
            "decision": "block",
            "reason": _subagent_contract_block_reason(
                pending,
                detail="The specialist summary must be a non-empty sentence.",
            ),
        }
    if status == "COMPLETE_WITH_GAPS" and not contract.get("data_gaps"):
        return {
            "decision": "block",
            "reason": _subagent_contract_block_reason(
                pending,
                detail="COMPLETE_WITH_GAPS requires at least one explicit data_gaps entry.",
            ),
        }
    return None


def _is_savvydfir_tool(tool_name: str) -> bool:
    """True when the tool belongs to the SAVVYDFIR flow/gates domain."""
    normalized = str(tool_name or "").strip()
    if normalized.startswith(SAVVYDFIR_TOOL_PREFIXES):
        return True
    candidates = _candidate_tool_names(tool_name)
    if not candidates:
        return False
    if any(name in TOOL_AGENT_MAP for name in candidates):
        return True
    return any(name in DELEGATION_BYPASS_TOOLS for name in candidates)


def _is_report_gate_tool(tool_name: str) -> bool:
    return any(name in REPORT_GATE_TOOLS for name in _candidate_tool_names(tool_name))


def _event_input_dicts(event: dict[str, Any]) -> list[dict[str, Any]]:
    inputs: list[dict[str, Any]] = []
    for key in ("tool_input", "toolInput", "input"):
        maybe = event.get(key)
        if isinstance(maybe, dict):
            inputs.append(maybe)
    return inputs


def _event_case_id(event: dict[str, Any], result_data: dict[str, Any]) -> str:
    for payload in _event_input_dicts(event):
        case_id = payload.get("case_id")
        if case_id is not None and str(case_id).strip():
            return str(case_id).strip()
    case_id = result_data.get("case_id")
    if case_id is not None and str(case_id).strip():
        return str(case_id).strip()
    lane = result_data.get("lane")
    if isinstance(lane, dict):
        nested_case_id = lane.get("case_id")
        if nested_case_id is not None and str(nested_case_id).strip():
            return str(nested_case_id).strip()
    return ""


def _event_context(event: dict[str, Any], result_data: dict[str, Any]) -> dict[str, str]:
    session_id = str(event.get("session_id") or event.get("sessionId") or "").strip()
    cwd = str(event.get("cwd") or "").strip()
    case_id = _event_case_id(event, result_data)
    return {
        "session_id": session_id,
        "cwd": cwd,
        "case_id": case_id,
    }


def _parse_iso8601(value: Any) -> Optional[datetime]:
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


def _trigger_is_stale(trigger: dict[str, Any]) -> bool:
    if TRIGGER_MAX_AGE_SECONDS <= 0:
        return False
    created_at = _parse_iso8601(
        trigger.get("created_at") or trigger.get("_trigger_file_mtime")
    )
    if created_at is None:
        return True
    age_seconds = (datetime.now(timezone.utc) - created_at).total_seconds()
    return age_seconds > TRIGGER_MAX_AGE_SECONDS


def _pending_matches_context(trigger: dict[str, Any], context: dict[str, str]) -> bool:
    if not isinstance(trigger, dict):
        return False
    if trigger.get("processed"):
        return False
    if _trigger_is_stale(trigger):
        return False
    for key in ("case_id", "session_id", "cwd"):
        trigger_value = str(trigger.get(key) or "").strip()
        context_value = str(context.get(key) or "").strip()
        if trigger_value and context_value and trigger_value != context_value:
            return False
    return True


def _parse_result_payload(tool_result: Any) -> tuple[dict[str, Any], str]:
    """Extract structured tool-result data plus raw text for hook evaluation."""
    raw_text = ""
    data: dict[str, Any] = {}

    if isinstance(tool_result, dict):
        content = tool_result.get("content", tool_result)
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                raw_text = str(first.get("text", ""))
        elif isinstance(content, dict):
            data = dict(content)
        elif isinstance(content, str):
            raw_text = content

    if not data and raw_text:
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                data = parsed
        except Exception:
            pass

    return data, raw_text


def _extract_event_payload(event: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    """Normalize both the namespaced and generic hook payload shapes."""
    tool_name = str(event.get("tool_name", "") or "")

    result_data: dict[str, Any] = {}
    raw_text = ""

    if "tool_result" in event:
        result_data, raw_text = _parse_result_payload(event.get("tool_result"))
    elif "tool_output" in event:
        tool_output = event.get("tool_output")
        if isinstance(tool_output, dict):
            result_data = dict(tool_output)
        elif isinstance(tool_output, str):
            raw_text = tool_output
            try:
                parsed = json.loads(tool_output)
                if isinstance(parsed, dict):
                    result_data = parsed
            except Exception:
                pass

    return tool_name, result_data, raw_text


def _detect_block_reason(result_data: dict[str, Any], raw_text: str) -> Optional[str]:
    """Return a block reason only for clear failure-pattern outputs."""
    fragments: list[str] = []
    for key in ("error", "error_message", "stderr", "outputs_summary"):
        value = result_data.get(key)
        if isinstance(value, str) and value:
            fragments.append(value)
    if raw_text:
        fragments.append(raw_text)

    combined = " ".join(fragments).lower()
    if not combined:
        return None

    for pattern, suggestion in ERROR_PATTERNS.items():
        if pattern in combined:
            return suggestion
    return None


# P2 #7 fix (review 2026-06-03): documented-absence / no-data outcomes.
# These are NOT status="error" (already skipped) but produce no analyzable
# handle, so dispatching a specialist just emits "ANALYSIS REQUIRED" against
# nothing and churns the lane. Mirror the _ABSENCE_MARKERS the workflow-enforce
# hooks use (Run-9: artifact_absent / no_data / tool_incompatible) plus the
# explicit documented-negative statuses extraction tools emit.
_ABSENCE_STATUSES = frozenset({
    "artifact_absent", "no_data", "tool_incompatible",
    "collection_failed", "not_applicable", "documented_absence", "absent",
})
_ABSENCE_MARKER_SUBSTRINGS = ("artifact_absent", "no_data", "tool_incompatible",
                              "documented absence", "documented_absence")


def _result_signals_absence(result_data: dict[str, Any]) -> bool:
    """True when a (non-error) tool result is a documented absence / no-data
    outcome with no analyzable handle - nothing for a specialist to mine."""
    status = str(result_data.get("status") or "").strip().lower()
    if status in _ABSENCE_STATUSES:
        return True
    # Explicit boolean flags some extractors set on documented absence.
    for flag in ("documented_absence", "artifact_absent", "absence"):
        if result_data.get(flag) is True:
            return True
    # Marker substrings in summary-ish fields, but ONLY when no durable handle
    # is present (a real CSV means there IS something to analyze).
    if _source_artifact_path(result_data) is None:
        for key in ("outputs_summary", "message", "reason", "note", "summary"):
            value = result_data.get(key)
            if isinstance(value, str) and any(
                m in value.lower() for m in _ABSENCE_MARKER_SUBSTRINGS
            ):
                return True
    return False


def _normalize_subagent_type(agent: str) -> str:
    """Return the Agent() subagent_type without legacy @ prose prefix."""
    return str(agent or "").strip().lstrip("@")


def _lane_for_agent(subagent_type: str) -> str:
    """Best-effort lane mapping for metadata-driven agent requests."""
    if subagent_type in {"memory-analyst"}:
        return "memory"
    if subagent_type in {"evtx-analyst"}:
        return "event_auth"
    if subagent_type in {"registry-analyst", "amcache-analyst", "prefetch-analyst", "browser-analyst"}:
        return "disk_execution_persistence"
    if subagent_type in {"sigma-analyst", "timeline-analyst", "mft-analyst", "srum-analyst"}:
        return "timeline_correlation"
    return "timeline_correlation"


def _resolve_dispatch(tool_name: str, result_data: dict[str, Any]) -> Optional[tuple[str, str, str]]:
    """Return (subagent_type, lane_id, instruction) when delegation is required."""
    requires_agent = result_data.get("requires_agent")
    agent_instruction = result_data.get("agent_instruction")
    if isinstance(requires_agent, str) and requires_agent.strip():
        subagent_type = _normalize_subagent_type(requires_agent)
        return (
            subagent_type,
            _lane_for_agent(subagent_type),
            str(agent_instruction or "Review the tool output."),
        )

    if any(name in {"sigma_scan", "mcp__savvydfir__sigma_scan"} for name in _candidate_tool_names(tool_name)):
        total_hits = int(result_data.get("total_hits", 0) or 0)
        if total_hits <= 0:
            return None
        critical = int(result_data.get("critical_count", 0) or 0)
        high = int(result_data.get("high_count", 0) or 0)
        return (
            "sigma-analyst",
            "timeline_correlation",
            (
                f"Review sigma_scan results immediately. Prioritize {critical} CRITICAL "
                f"and {high} HIGH anomalies first, then pivot using summary_markdown."
            ),
        )

    for candidate in _candidate_tool_names(tool_name):
        dispatch = TOOL_AGENT_MAP.get(candidate)
        if dispatch is not None:
            return dispatch
    return None


_CONTEXT_CACHE: dict[str, dict[str, Any]] = {}


def _bounded_csv_inspect(csv_path: str) -> dict[str, Any]:
    """Phase 2: bounded local inspect of a
    CSV header + timestamp column min/max. Returns a dict with schema +
    timestamp_bounds, or empty dict on any failure.

    required: NO MCP callback from the hook. This reads pandas
    directly with usecols + nrows, so the cost is bounded regardless
    of CSV size. Results are cached by csv_path so repeat invocations
    do not re-scan.
    """
    if not csv_path:
        return {}
    cached = _CONTEXT_CACHE.get(csv_path)
    if cached is not None:
        return cached
    try:
        import pandas as _pd
    except Exception:
        return {}
    inspect: dict[str, Any] = {}
    try:
        # Header-only read for schema (zero rows).
        header_df = _pd.read_csv(csv_path, nrows=0)
        schema = [
            {"column": str(col), "dtype": str(header_df[col].dtype)}
            for col in header_df.columns
        ]
        inspect["schema"] = schema
        # Identify a primary timestamp column (heuristic: name contains
        # 'time'/'date'/'created'/'modified'/'timestamp'). Universal,
        # case-agnostic - works on any CSV with a timestamp-shaped column.
        ts_candidates = [
            str(c) for c in header_df.columns
            if any(needle in str(c).lower()
                   for needle in ("timestamp", "time_created", "created",
                                  "datetime", "_date", "first_run", "last_run"))
        ]
        primary_ts = ts_candidates[0] if ts_candidates else None
        inspect["primary_timestamp_column"] = primary_ts
        if primary_ts:
            try:
                ts_df = _pd.read_csv(
                    csv_path, usecols=[primary_ts], parse_dates=[primary_ts]
                )
                ts_series = ts_df[primary_ts].dropna()
                if not ts_series.empty:
                    inspect["timestamp_bounds"] = {
                        "min": str(ts_series.min()),
                        "max": str(ts_series.max()),
                    }
            except Exception:
                pass
    except Exception:
        inspect = {}
    _CONTEXT_CACHE[csv_path] = inspect
    return inspect


def _load_manifest_attack_window(cwd: Optional[str] = None) -> dict[str, Any]:
    """Read the case manifest's attack_window if present. Case-agnostic -
    we just surface the manifest's own declared window; the field is
    optional in manifest.json.
    """
    try:
        base = Path(cwd) if cwd else Path.cwd()
    except Exception:
        return {}
    for candidate in (
        base / "case-templates" / "manifest.json",
        base / "manifest.json",
    ):
        try:
            if not candidate.is_file():
                continue
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        # The manifest may carry an attack_window under several names -
        # we accept any of them. Case-agnostic surface.
        for key in ("attack_window", "attackWindow", "incident_window",
                    "known_attack_window"):
            window = data.get(key)
            if isinstance(window, dict) and ("start" in window or "from" in window):
                return {
                    "start": window.get("start") or window.get("from"),
                    "end": window.get("end") or window.get("to"),
                }
        # Some manifests use a nested case.attack_window
        case_obj = data.get("case") or {}
        if isinstance(case_obj, dict):
            window = case_obj.get("attack_window") or case_obj.get("incident_window")
            if isinstance(window, dict):
                return {
                    "start": window.get("start") or window.get("from"),
                    "end": window.get("end") or window.get("to"),
                }
        return {}
    return {}


def _augment_instruction(
    instruction: str,
    result_data: dict[str, Any],
    *,
    cwd: Optional[str] = None,
    originating_execution_id: Optional[str] = None,
) -> str:
    """Append high-signal artifact context to the base instruction.

    Phase 2 extension: in addition to the
    existing summary / csv_path / storage_path / summary_markdown hints,
    inject schema, timestamp_bounds, attack_window, and originating
    execution_id into the prompt. This is the pre-computed context the
    playbook specialist will read instead of running schema-discovery
    queries.

    specifically forbade MCP callbacks from this hook. The bounded
    CSV inspect runs pandas locally with nrows=0 / usecols=[ts_col].
    """
    parts = [instruction.strip()]

    summary = result_data.get("summary")
    if isinstance(summary, str) and summary:
        parts.append(f"Summary: {summary}")

    csv_path = result_data.get("csv_path")
    if isinstance(csv_path, str) and csv_path:
        total_records = result_data.get(
            "total_records", result_data.get("records_count"))
        if total_records is not None:
            parts.append(f"CSV at: {csv_path} ({total_records} total rows).")
        else:
            parts.append(f"CSV at: {csv_path}.")

    storage_path = result_data.get("storage_path")
    if isinstance(storage_path, str) and storage_path:
        parts.append(f"Timeline storage at: {storage_path}.")

    if "summary_markdown" in result_data and result_data.get("summary_markdown"):
        parts.append("Use summary_markdown to orient before drilling down.")

    # Phase 2 - Pre-computed context injection
    # Schema can come from the tool result itself (preferred path) OR from a
    # bounded local CSV inspect (fallback). required NOT calling MCP.
    schema = result_data.get("schema")
    timestamp_bounds = result_data.get("timestamp_bounds")
    if (not schema or not timestamp_bounds) and isinstance(csv_path, str) and csv_path:
        inspect = _bounded_csv_inspect(csv_path)
        if not schema and inspect.get("schema"):
            schema = inspect["schema"]
        if not timestamp_bounds and inspect.get("timestamp_bounds"):
            timestamp_bounds = inspect["timestamp_bounds"]

    if isinstance(schema, list) and schema:
        # Render as a compact column list to keep the prompt readable.
        cols = ", ".join(
            (col.get("column") if isinstance(col, dict) else str(col))
            for col in schema[:30]
        )
        more = "" if len(schema) <= 30 else f" (+{len(schema) - 30} more)"
        parts.append(f"Schema columns: {cols}{more}.")

    if isinstance(timestamp_bounds, dict):
        ts_min = timestamp_bounds.get("min")
        ts_max = timestamp_bounds.get("max")
        if ts_min and ts_max:
            parts.append(f"Timestamp bounds: {ts_min} → {ts_max}.")

    # Attack window from manifest (case-specific INPUT - flows through
    # manifest.json, not hardcoded anywhere in the framework).
    attack_window = result_data.get("attack_window")
    if not attack_window:
        attack_window = _load_manifest_attack_window(cwd)
    if isinstance(attack_window, dict):
        start = attack_window.get("start")
        end = attack_window.get("end")
        if start and end:
            parts.append(f"Manifest attack window: {start} → {end}.")
        elif start:
            parts.append(f"Manifest attack window start: {start}.")

    # Originating execution_id - useful so the specialist can pass it as
    # source_execution_id when calling submit_finding (Phase 1 provenance).
    eid = originating_execution_id or result_data.get("execution_id")
    if isinstance(eid, str) and eid:
        parts.append(f"Originating execution_id: {eid}.")

    return " ".join(parts)


def _source_artifact_path(result_data: dict[str, Any]) -> Optional[str]:
    """Return the most specific durable artifact path surfaced by a tool result."""
    for key in (
        "csv_path",
        "storage_path",
        "report_json_path",
        "export_dir",
        "evtx_dir",
        "registry_dir",
        "amcache_hive",
        "prefetch_dir",
        "mft_path",
        "artifact_path",
        "resolved_path",
    ):
        value = result_data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _agent_description(subagent_type: str, lane_id: str, tool_name: str) -> str:
    return f"Analyze {lane_id} lane after {tool_name}"


def _delegation_text(
    *,
    subagent_type: str,
    description: str,
    prompt: str,
) -> str:
    legacy_agent = f"@{subagent_type}"
    return f"{legacy_agent} - {description}. {prompt}"


def _write_trigger(trigger: dict[str, Any], trigger_path: Optional[str] = None) -> None:
    """Legacy compatibility wrapper for enqueue_delegate.

    New behavior: appends to per-lane queue instead of overwriting single file.
    If trigger_path is provided, temporarily override SAVVYDFIR_DELEGATE_QUEUE_PATH.
    """
    lane_id = str(trigger.get("lane_id", "")).strip()
    if not lane_id:
        # Fallback: if no lane_id, cannot queue (should not happen in practice)
        return

    # Support custom trigger_path for tests
    if trigger_path:
        old_path = os.environ.get("SAVVYDFIR_DELEGATE_QUEUE_PATH")
        os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = trigger_path
        try:
            enqueue_delegate(lane_id, trigger)
        finally:
            if old_path is not None:
                os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = old_path
            else:
                os.environ.pop("SAVVYDFIR_DELEGATE_QUEUE_PATH", None)
    else:
        enqueue_delegate(lane_id, trigger)


def _read_pending_trigger(trigger_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Legacy compatibility wrapper for get_pending_delegate.

    New behavior: returns head of highest-priority lane's queue.
    If trigger_path is provided, temporarily override SAVVYDFIR_DELEGATE_QUEUE_PATH.
    """
    if trigger_path:
        old_path = os.environ.get("SAVVYDFIR_DELEGATE_QUEUE_PATH")
        os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = trigger_path
        try:
            return get_pending_delegate()
        finally:
            if old_path is not None:
                os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = old_path
            else:
                os.environ.pop("SAVVYDFIR_DELEGATE_QUEUE_PATH", None)
    else:
        return get_pending_delegate()


def _mark_trigger_processed(trigger_path: Optional[str] = None) -> None:
    """Legacy compatibility wrapper for mark_delegate_processed.

    New behavior: pops head of the delegate's lane queue.
    If trigger_path is provided, temporarily override SAVVYDFIR_DELEGATE_QUEUE_PATH.
    """
    if trigger_path:
        old_path = os.environ.get("SAVVYDFIR_DELEGATE_QUEUE_PATH")
        os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = trigger_path
        try:
            pending = get_pending_delegate()
            if pending:
                lane_id = str(pending.get("lane_id", "")).strip()
                if lane_id:
                    mark_delegate_processed(lane_id)
        finally:
            if old_path is not None:
                os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = old_path
            else:
                os.environ.pop("SAVVYDFIR_DELEGATE_QUEUE_PATH", None)
    else:
        pending = get_pending_delegate()
        if pending:
            lane_id = str(pending.get("lane_id", "")).strip()
            if lane_id:
                mark_delegate_processed(lane_id)


def _recorded_lane_id_from_event(
    event: dict[str, Any], result_data: dict[str, Any]
) -> str:
    """Resolve lane_id from hook event (tool input) or tool result payload."""
    for payload in _event_input_dicts(event):
        lane = payload.get("lane_id")
        if lane is not None and str(lane).strip():
            return str(lane).strip()
    lane_value = result_data.get("lane_id")
    if lane_value is not None and str(lane_value).strip():
        return str(lane_value).strip()
    lane_obj = result_data.get("lane")
    if isinstance(lane_obj, dict):
        nested_lane = lane_obj.get("lane_id")
        if nested_lane is not None and str(nested_lane).strip():
            return str(nested_lane).strip()
    return ""


def _pending_requires_hard_block(
    trigger: dict[str, Any], tool_name: str, result_data: dict[str, Any]
) -> bool:
    """Check if a pending delegate blocks the current tool.

    NEW QUEUE-BASED BEHAVIOR (H.1 fix):
    - Report gate tools always block (unchanged)
    - Same tool already queued in same lane → block (prevents duplicates)
    - Different tool in same lane → allow (enables parallel specialists)

    This replaces the old "same lane always blocks" logic that prevented
    same-lane specialists from running in parallel.
    """
    if _is_report_gate_tool(tool_name):
        return True

    pending_lane = str(trigger.get("lane_id") or "").strip()
    if not pending_lane:
        return False

    dispatch = _resolve_dispatch(tool_name, result_data)
    if dispatch is None:
        return False

    _, lane_id, _ = dispatch

    # NEW: Only block if the SAME tool is already queued in this lane
    # Different tools in the same lane can queue concurrently
    if lane_id != pending_lane:
        return False  # Different lane, no blocking

    # Same lane - check if this specific tool is already queued
    return is_tool_already_queued(lane_id, tool_name)


def _delegation_block_reason(trigger: dict[str, Any]) -> str:
    """Build the BLOCK message that nudges the main agent to analyze the lane.

    Hackathon update 2026-05-23:
    inverted from "MANDATORY Path A specialist Task spawn" to "preferred
    inline run_analysis using <artifact>-analyst heuristic context."

    Why: Task subagents hit the hardcoded 32K output-token ceiling
    (anthropics/claude-code#25569) and truncated in 7/8 cases on the
    an early test run. Main-agent inline analysis has no such
    ceiling, gets full case context, and persists findings immediately
    via add_finding/submit_finding.

    The specialist Task spawn remains AVAILABLE as an opt-in escape hatch
    for genuinely isolated work (cross-artifact synthesis, deep-dive),
    but is no longer the default first action after extraction.
    """
    subagent_type = str(trigger.get("subagent_type") or "specialist")
    lane_id = str(trigger.get("lane_id") or "analysis")
    description = str(trigger.get("description") or f"Analyze {lane_id} lane")
    prompt = str(trigger.get("prompt") or "")
    agent_call = str(trigger.get("delegation_text") or trigger.get("agent_call") or "")
    artifact_md = f".claude/agents/{subagent_type}.md"
    return (
        f"ANALYSIS REQUIRED for lane_id={lane_id!r}.\n"
        "\n"
        "PREFERRED PATH — inline main-agent analysis (no Task spawn):\n"
        f"  1. Read {artifact_md} for the forensic heuristics that apply to "
        "this artifact. The file is a knowledge base, not a procedural playbook.\n"
        "  2. Apply heuristics via run_analysis(data_path=<csv_path>, query=...) "
        "calls. Each run_analysis call gets an execution_id and audit row.\n"
        "  3. For each evidence-backed conclusion, call submit_finding(...) "
        "with the typed schema (claim + evidence_excerpt + confidence + "
        "supporting_indicators + source_execution_id). Findings persist "
        "immediately to state.json — no truncation risk.\n"
        f"  4. Call record_analysis_lane(case_id=..., lane_id={lane_id!r}, "
        "status='COMPLETE' or 'COMPLETE_WITH_GAPS', assigned_agent='main-agent', "
        "execution_ids=[...], finding_ids=[...], summary=<one sentence>).\n"
        "\n"
        "WHY THIS IS INLINE-ONLY: artifact analysis happens in the main agent. "
        "Prior architecture used Task subagents that hit a hardcoded 32K output "
        "token ceiling and truncated in 7/8 production runs (W1.6 retirement, "
        "see DECISION-2026-05-23-branch-triage.md). Cross-artifact synthesis "
        "and corroboration use their own dedicated lanes — do not invoke them "
        "from this artifact-analysis context.\n"
        "\n"
        "DO NOT stop the investigation. DO NOT abandon the run with a free-text "
        "'investigation summary' — that is a skipped lane, not a completed one. "
        "Apply heuristics, persist findings, record the lane."
    )


_DEBUG_LOG_PATH = os.environ.get(
    "SAVVYDFIR_HOOK_DEBUG_LOG", "/tmp/savvydfir_hook_debug.log"
)


def _debug_trace(message: str) -> None:
    """Append a single timestamped line so we can verify hook invocation
    from the agent's actual run (independent of audit.jsonl).
    Best-effort; never raises.
    """
    try:
        from datetime import datetime as _dt, timezone as _tz
        ts = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        line = f"{ts} {message}\n"
        fd = os.open(
            _DEBUG_LOG_PATH,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o666,
        )
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(_DEBUG_LOG_PATH, 0o666)
        except OSError:
            pass
    except Exception:
        return


def process_event(event: dict[str, Any], *, trigger_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Process one PostToolUse event and return a hook response dict or None."""
    tool_name, result_data, raw_text = _extract_event_payload(event)

    # Diagnostic trace - verify the hook is being invoked by Claude Code.
    # event-level keys (NOT inner data) + a sample of session_id are enough.
    _debug_trace(
        f"process_event tool={tool_name!r} "
        f"keys={sorted(event.keys())} "
        f"sid={(event.get('session_id') or event.get('sessionId') or '?')!r}"
    )

    if not tool_name:
        return None

    # 2026-05-20 fix: refresh session pointer from PostToolUse event's
    # session_id. `claude -p` one-shot mode may skip SessionStart, leaving
    # the pointer stale across runs and breaking ledger correlation.
    try:
        _ledger_refresh_session_pointer_from_event(event)
    except Exception:
        pass

    # Phase 3a observation-only: Task PostToolUse events carry the
    # specialist outcome the ledger needs. We never block Task behavior.
    # C-PRIME (2026-05-20): on prose_only/malformed_json outcomes,
    # _ledger_handle_task_event returns a non-blocking
    # hookSpecificOutput directing the parent to spawn json-repair.
    if tool_name in {"Task", "Agent"}:
        try:
            directive = _ledger_handle_task_event(event)
        except Exception:
            directive = None
        # Detect when the parent has just spawned a json-repair Task; mark
        # repair_attempted so the directive isn't re-emitted on another
        # failed specialist response in the same lane.
        try:
            for payload in _event_input_dicts(event):
                cand = payload.get("subagent_type") or payload.get("agent") or ""
                if str(cand).strip().lstrip("@") == "json-repair":
                    desc = str(payload.get("description") or "")
                    prompt_field = str(payload.get("prompt") or "")
                    lane_for_repair = ""
                    # Heuristic: extract lane name from the repair prompt.
                    import re as _re2
                    m = _re2.search(r"lane_id=['\"](.*?)['\"]", prompt_field)
                    if m:
                        lane_for_repair = m.group(1)
                    if not lane_for_repair:
                        m = _re2.search(r"lane[_ ]?id\s*[:=]\s*['\"](.*?)['\"]", desc)
                        if m:
                            lane_for_repair = m.group(1)
                    # Pull specialist name out of "@<specialist> on lane..."
                    spec_match = _re2.search(r"@([\w\-]+)\s+on lane", prompt_field)
                    spec_for_repair = spec_match.group(1) if spec_match else ""
                    if lane_for_repair:
                        _ledger_mark_repair_attempted(lane_for_repair, spec_for_repair)
                    break
        except Exception:
            pass
        return directive

    context = _event_context(event, result_data)
    pending = _read_pending_trigger(trigger_path=trigger_path)
    if pending and not _pending_matches_context(pending, context):
        _mark_trigger_processed(trigger_path=trigger_path)
        pending = None

    candidate_names = set(_candidate_tool_names(tool_name))
    if any(name in DELEGATION_BYPASS_TOOLS for name in candidate_names):
        status_ok = str(result_data.get("status") or "").lower() in {"ok", "success"}
        if status_ok and any(
            name in {"mcp__savvydfir__record_analysis_lane", "record_analysis_lane"}
            for name in candidate_names
        ):
            if pending:
                recorded_lane = _recorded_lane_id_from_event(event, result_data)
                pending_lane = str(pending.get("lane_id") or "").strip()
                if pending_lane and recorded_lane == pending_lane:
                    _mark_trigger_processed(trigger_path=trigger_path)
            # W1.7 Run-2 review 2026-05-24: soft nudge
            # toward inline main-agent synthesis when a prereq lane closes.
            # Run 2 showed Claude completed all 4 prereq lanes then jumped
            # straight to generate_report - never crossed the "should I
            # synthesize?" decision point. This is the forcing function.
            try:
                _PREREQ_LANES = {
                    "memory",
                    "disk_execution_persistence",
                    "event_auth",
                    "timeline_correlation",
                }
                recorded_lane = _recorded_lane_id_from_event(event, result_data)
                if recorded_lane in _PREREQ_LANES:
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PostToolUse",
                            "additionalContext": (
                                f"SYNTHESIS NUDGE — lane {recorded_lane!r} just "
                                "closed. If all 4 prereq lanes (memory, "
                                "disk_execution_persistence, event_auth, "
                                "timeline_correlation) are now COMPLETE or "
                                "COMPLETE_WITH_GAPS, do NOT call generate_report "
                                "yet. Run inline main-agent synthesis FIRST per "
                                "CLAUDE.md PHASE 6:\n"
                                "  1. compare_disk_and_memory(case_id)\n"
                                "  2. find_temporal_clusters(case_id, window_seconds=300, "
                                "min_sources=2, min_events=3)\n"
                                "  3. For each 3+ source cluster: submit_finding(...) "
                                "with evidence_kind='inference' (NOT 'corroborated' — "
                                "invalid enum), status='CONFIRMED', "
                                "corroborated_by=[F-NNN ids], "
                                "source_execution_id=<real audit row>, "
                                "alternative_hypothesis=..., "
                                "evidence_against_it=[...], "
                                "disposition='ruled_out' or 'not_applicable'.\n"
                                "  3a. Response includes confirmed_eligibility "
                                "{eligible, missing, gate_blocks} — read it, "
                                "resubmit if not eligible and you wanted CONFIRMED.\n"
                                "  4. record_analysis_lane("
                                "lane_id='synthesis_corroboration', "
                                "assigned_agent='main-agent', status='COMPLETE', "
                                "execution_ids=[...], finding_ids=[<promoted ids>], "
                                "summary=...).\n"
                                "Delegate synthesis (@synthesis-analyst) is opt-in, "
                                "not required. Skipping synthesis caps CONFIRMED at 0 "
                                "(Run 2 lesson). The hypothesis gate will block "
                                "generate_report regardless of allow_partial."
                            ),
                        }
                    }
            except Exception:
                pass
        return None

    if pending and _is_savvydfir_tool(tool_name):
        if _pending_requires_hard_block(pending, tool_name, result_data):
            return {
                "decision": "block",
                "reason": _delegation_block_reason(pending),
            }
        # NEW (H.1 fix): If tool doesn't hard block, continue to dispatch logic
        # below so different tools in same lane can queue concurrently.
        # Don't return None here - that would skip queueing.

    block_reason = _detect_block_reason(result_data, raw_text)
    if block_reason:
        return {"decision": "block", "reason": block_reason}

    # Operational fix: do not spawn specialists on failed tool calls.
    # If status is error/failed/not_initialised, the specialist has nothing
    # to analyse and will burn tokens before bailing. Let the main agent
    # retry the originating tool first.
    tool_status = str(result_data.get("status") or "").strip().lower()
    if tool_status in {"error", "failed", "fail", "not_initialised", "tool_not_found"}:
        return None

    # P2 #7 fix: also skip documented-absence / no-data outcomes (review gap -
    # these are not status="error" but have no handle to analyze).
    if _result_signals_absence(result_data):
        return None

    dispatch = _resolve_dispatch(tool_name, result_data)
    if dispatch is None:
        return None

    subagent_type, lane_id, base_instruction = dispatch
    # Phase 2 - pre-compute context for the specialist (schema, timestamp
    # bounds, manifest attack_window, originating execution_id).
    # review 2026-05-22 - NOT via an MCP callback; bounded local inspect
    # of the CSV header + the manifest file on disk.
    instruction = _augment_instruction(
        base_instruction,
        result_data,
        cwd=context.get("cwd"),
        originating_execution_id=event.get("execution_id") or None,
    )
    source_path = _source_artifact_path(result_data)
    description = _agent_description(subagent_type, lane_id, tool_name)
    prompt = (
        f"Read current SAVVYDFIR state, own lane_id={lane_id!r}, and analyze the "
        f"artifact handle from {tool_name}. {instruction} "
        "Do not ask the parent to load the full CSV into context. Use run_analysis "
        "for focused pivots, add evidence-backed findings only, and return compact JSON "
        "with lane_id, status, execution_ids, finding_ids, data_gaps, "
        "anti_forensics_warnings, unresolved_discrepancies, next_pivots, summary, "
        "and confidence_notes so the parent can call record_analysis_lane."
    )
    if source_path:
        prompt += f" Context handle: {source_path}."
    delegation_text = _delegation_text(
        subagent_type=subagent_type,
        description=description,
        prompt=prompt,
    )

    trigger = {
        "agent": f"@{subagent_type}",
        "subagent_type": subagent_type,
        "description": description,
        "prompt": prompt,
        "lane_id": lane_id,
        "source_artifact_path": source_path,
        "agent_call": delegation_text,
        "delegation_text": delegation_text,
        "tool": tool_name,
        "instruction": instruction,
        "csv_path": result_data.get("csv_path"),
        "storage_path": result_data.get("storage_path"),
        "case_id": context.get("case_id") or "",
        "session_id": context.get("session_id") or "",
        "cwd": context.get("cwd") or "",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "processed": False,
    }
    _write_trigger(trigger, trigger_path=trigger_path)

    # Phase 3a observation-only: record that a specialist delegation
    # is required for this lane. workflow-enforce-pre.py (Phase 3b/3c)
    # reads these alongside task_outcome rows to authorize Path B.
    try:
        _ledger_handle_delegation_required(trigger)
    except Exception:
        pass

    return {
        "decision": "block",
        "reason": _delegation_block_reason(trigger),
    }


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except Exception:
        return

    if "--subagent-stop" in sys.argv or event.get("hook_event_name") == "SubagentStop":
        result = process_subagent_stop(event)
    else:
        result = process_event(event)
    if result is not None:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
