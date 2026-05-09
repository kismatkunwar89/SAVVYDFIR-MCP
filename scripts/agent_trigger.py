#!/usr/bin/env python3
"""Canonical SAVVYDFIR PostToolUse dispatcher."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Map MCP tool -> subagent type + lane + default instruction
TOOL_AGENT_MAP: dict[str, tuple[str, str, str]] = {
    "mcp__savvydfir__extract_mft_timeline": (
        "mft-analyst",
        "timeline_correlation",
        "Analyze the MFT CSV for timestomping, attacker file drops, sequential entry clusters, and staging artifacts.",
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
    # Lane control — unblocks the pending delegate
    "mcp__savvydfir__read_state",
    "mcp__savvydfir__record_analysis_lane",
    "read_state",
    "record_analysis_lane",
    # State inspection — needed to write a useful lane summary before calling record_analysis_lane
    "mcp__savvydfir__get_findings",
    "mcp__savvydfir__get_finding",
    "mcp__savvydfir__get_investigation_gates",
    "mcp__savvydfir__query_sigma_results",
    "get_findings",
    "get_finding",
    "get_investigation_gates",
    "query_sigma_results",
}


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
    created_at = _parse_iso8601(trigger.get("created_at"))
    if created_at is None:
        return False
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


def _augment_instruction(instruction: str, result_data: dict[str, Any]) -> str:
    """Append high-signal artifact context to the base instruction."""
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
    try:
        path = Path(trigger_path or os.environ.get(
            "SAVVYDFIR_DELEGATE_PATH", DEFAULT_TRIGGER_PATH))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(trigger, indent=2), encoding="utf-8")
    except (OSError, IOError):
        pass  # Trigger file is advisory — failure must not block the hook


def _read_pending_trigger(trigger_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    try:
        path = Path(trigger_path or os.environ.get(
            "SAVVYDFIR_DELEGATE_PATH", DEFAULT_TRIGGER_PATH))
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and not payload.get("processed"):
            return payload
    except (OSError, IOError, json.JSONDecodeError):
        return None
    return None


def _mark_trigger_processed(trigger_path: Optional[str] = None) -> None:
    try:
        path = Path(trigger_path or os.environ.get(
            "SAVVYDFIR_DELEGATE_PATH", DEFAULT_TRIGGER_PATH))
        if not path.exists():
            return
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return
        payload["processed"] = True
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except (OSError, IOError, json.JSONDecodeError):
        pass


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
    if _is_report_gate_tool(tool_name):
        return True
    pending_lane = str(trigger.get("lane_id") or "").strip()
    if not pending_lane:
        return False
    dispatch = _resolve_dispatch(tool_name, result_data)
    if dispatch is None:
        return False
    _, lane_id, _ = dispatch
    return lane_id == pending_lane


def _delegation_block_reason(trigger: dict[str, Any]) -> str:
    subagent_type = str(trigger.get("subagent_type") or "specialist")
    lane_id = str(trigger.get("lane_id") or "analysis")
    description = str(trigger.get("description") or f"Analyze {lane_id} lane")
    prompt = str(trigger.get("prompt") or "")
    agent_call = str(trigger.get("delegation_text") or trigger.get("agent_call") or "")
    return (
        "SPECIALIST DELEGATION REQUIRED BEFORE CONTINUING. "
        f"Start @{subagent_type} now for lane_id={lane_id!r}.\n"
        "ORCHESTRATION CONTRACT (pick PATH A or PATH B, then ALWAYS finish with step 3):\n"
        "PATH A — Task tool IS available:\n"
        "  1A) Call Task SYNCHRONOUSLY (run_in_background=false, the default). "
        "Task returns ONLY after the subagent has finished — do NOT say 'specialist is "
        "still running' or wait for another user message.\n"
        "  2A) When Task returns, parse the subagent's JSON and IMMEDIATELY proceed to step 3.\n"
        f"  Use Task with: subagent_type={subagent_type!r}, "
        f"description={description!r}, prompt={prompt!r}.\n"
        "PATH B — Task tool is NOT available in this session:\n"
        "  1B) DO NOT loop forever. As the parent, run focused run_analysis(...) queries "
        "against the durable handle (csv_path / storage_path / artifact directory) printed "
        "in the originating tool's response. Add evidence-backed findings via add_finding(...).\n"
        "  2B) Then proceed to step 3 with assigned_agent='main-agent'.\n"
        "STEP 3 — UNBLOCK THE GATE (BOTH paths must do this in the same turn):\n"
        f"  Call record_analysis_lane(case_id=..., lane_id={lane_id!r}, "
        "status='COMPLETE' or 'COMPLETE_WITH_GAPS', assigned_agent='" + subagent_type + "' "
        "(PATH A) or 'main-agent' (PATH B), execution_ids=[...], finding_ids=[...], "
        "summary=<one sentence>). The lane_id MUST equal "
        f"{lane_id!r} verbatim or the delegate stays unprocessed.\n"
        "DO NOT stop your turn between the analysis step and record_analysis_lane. "
        "DO NOT collect more artifacts before recording the lane. "
        "DO NOT abandon the run with a free-text 'investigation summary' — that is a "
        "skipped lane, not a completed one.\n"
        f"Main-style fallback text: {agent_call}"
    )


def process_event(event: dict[str, Any], *, trigger_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Process one PostToolUse event and return a hook response dict or None."""
    tool_name, result_data, raw_text = _extract_event_payload(event)

    if not tool_name:
        return None

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
        return None

    if pending and _is_savvydfir_tool(tool_name):
        if _pending_requires_hard_block(pending, tool_name, result_data):
            return {
                "decision": "block",
                "reason": _delegation_block_reason(pending),
            }
        return None

    block_reason = _detect_block_reason(result_data, raw_text)
    if block_reason:
        return {"decision": "block", "reason": block_reason}

    dispatch = _resolve_dispatch(tool_name, result_data)
    if dispatch is None:
        return None

    subagent_type, lane_id, base_instruction = dispatch
    instruction = _augment_instruction(base_instruction, result_data)
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

    return {
        "decision": "block",
        "reason": _delegation_block_reason(trigger),
    }


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except Exception:
        return

    result = process_event(event)
    if result is not None:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
