#!/usr/bin/env python3
"""Canonical SAVVYDFIR PostToolUse dispatcher."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

# Map MCP tool -> agent + default instruction
TOOL_AGENT_MAP: dict[str, tuple[str, str]] = {
    "mcp__savvydfir__extract_mft_timeline": (
        "@mft-analyst",
        "Analyze the MFT CSV for timestomping, attacker file drops, sequential entry clusters, and staging artifacts.",
    ),
    "mcp__savvydfir__summarize_evtx": (
        "@evtx-analyst",
        "Analyze the EVTX CSV for auth anomalies, lateral movement, NTLM attacks, persistence, and log clearing.",
    ),
    "mcp__savvydfir__extract_registry_run_keys": (
        "@registry-analyst",
        "Analyze the registry CSV for ASEP persistence, fileless malware, LSA packages, and credential theft.",
    ),
    "mcp__savvydfir__get_amcache": (
        "@amcache-analyst",
        "Analyze the Amcache CSV for renamed malware (SHA-1), loose executables, and BYOVD drivers.",
    ),
    "mcp__savvydfir__extract_prefetch": (
        "@prefetch-analyst",
        "Analyze prefetch records for multi-path execution, SysWOW64 LOLBins, and orphaned .pf files.",
    ),
    "mcp__savvydfir__detect_injection": (
        "@memory-analyst",
        "Analyze memory injection findings for confirmed code injection, DKOM hidden processes, and C2 indicators.",
    ),
    "mcp__savvydfir__list_dlls": (
        "@memory-analyst",
        "Analyze loaded DLLs for unsigned modules, DLLs from staging paths, and unexpected network capability.",
    ),
    "mcp__savvydfir__sigma_hunt": (
        "@sigma-analyst",
        "Analyze the Sigma rule hits: triage false positives, confirm ATT&CK techniques, and cross-reference with existing findings.",
    ),
    "mcp__savvydfir__analyze_vss": (
        "@evtx-analyst",
        "Analyze VSS shadow copy inventory and recover pre-incident logs when available.",
    ),
    "mcp__savvydfir__extract_pca": (
        "@prefetch-analyst",
        "Analyze PCA execution artifacts and correlate them with Amcache and Prefetch.",
    ),
    "mcp__savvydfir__extract_shimcache": (
        "@registry-analyst",
        "Analyze ShimCache entries, corroborate with Amcache/Prefetch, and flag suspicious execution paths.",
    ),
    "mcp__savvydfir__extract_srum": (
        "@srum-analyst",
        "Analyze SRUM network usage, quantify exfiltration volume, and flag deleted or unresolved applications.",
    ),
}

ERROR_PATTERNS: dict[str, str] = {
    "not found": "Tool output contains 'not found'. Check paths and tool availability.",
    "permission denied": "Permission denied. Check RBAC path model: evidence paths are read-only.",
    "timed out": "Tool timed out. Try a smaller dataset or increase timeout.",
    "no such file": "File not found. Verify evidence is mounted and paths are correct.",
}

DEFAULT_TRIGGER_PATH = "/tmp/savvydfir_delegate.json"


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


def _resolve_dispatch(tool_name: str, result_data: dict[str, Any]) -> Optional[tuple[str, str]]:
    """Return (agent, instruction) when this tool result requires delegation."""
    requires_agent = result_data.get("requires_agent")
    agent_instruction = result_data.get("agent_instruction")
    if isinstance(requires_agent, str) and requires_agent.strip():
        return requires_agent.strip(), str(agent_instruction or "Review the tool output.")

    if tool_name in ("sigma_scan", "mcp__savvydfir__sigma_scan"):
        total_hits = int(result_data.get("total_hits", 0) or 0)
        if total_hits <= 0:
            return None
        critical = int(result_data.get("critical_count", 0) or 0)
        high = int(result_data.get("high_count", 0) or 0)
        return (
            "@sigma-analyst",
            (
                f"Review sigma_scan results immediately. Prioritize {critical} CRITICAL "
                f"and {high} HIGH anomalies first, then pivot using summary_markdown."
            ),
        )

    return TOOL_AGENT_MAP.get(tool_name)


def _augment_instruction(instruction: str, result_data: dict[str, Any]) -> str:
    """Append high-signal artifact context to the base instruction."""
    parts = [instruction.strip()]

    csv_path = result_data.get("csv_path")
    if isinstance(csv_path, str) and csv_path:
        total_records = result_data.get("total_records", result_data.get("records_count"))
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


def _write_trigger(trigger: dict[str, Any], trigger_path: Optional[str] = None) -> None:
    path = Path(trigger_path or os.environ.get("SAVVYDFIR_DELEGATE_PATH", DEFAULT_TRIGGER_PATH))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(trigger, indent=2), encoding="utf-8")


def process_event(event: dict[str, Any], *, trigger_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Process one PostToolUse event and return a hook response dict or None."""
    tool_name, result_data, raw_text = _extract_event_payload(event)

    if not tool_name:
        return None

    block_reason = _detect_block_reason(result_data, raw_text)
    if block_reason:
        return {"decision": "block", "reason": block_reason}

    dispatch = _resolve_dispatch(tool_name, result_data)
    if dispatch is None:
        return None

    agent, base_instruction = dispatch
    instruction = _augment_instruction(base_instruction, result_data)

    trigger = {
        "agent": agent,
        "tool": tool_name,
        "instruction": instruction,
        "csv_path": result_data.get("csv_path"),
        "storage_path": result_data.get("storage_path"),
        "processed": False,
    }
    _write_trigger(trigger, trigger_path=trigger_path)

    return {
        "decision": "allow",
        "message": (
            f"SAVVYDFIR HOOK: {tool_name} completed. "
            f"MANDATORY: invoke {agent} before proceeding. Instruction: {instruction}"
        ),
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
