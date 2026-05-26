#!/usr/bin/env python3
"""PostToolUse workflow-enforcement hook.

Fires after `mcp__savvydfir__start_investigation` and major Phase 2 tools.
Reads `analysis/state.json` to determine which mandatory tools are still
pending, and emits `additionalContext` to nudge the main agent toward the
next required tool. Designed to FAIL OPEN — if state.json doesn't exist or
the script errors, the investigation continues uninterrupted.

Schema: https://code.claude.com/docs/en/hooks
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Mandatory tools per the Run7 plan. Maps MCP tool name → executions tool_name.
MANDATORY_PHASE_TOOLS: dict[str, dict[str, str]] = {
    # Phase 1 — Memory (parallel-safe)
    "mcp__savvydfir__list_processes":         {"exec": "memory.list_processes",         "phase": "1"},
    "mcp__savvydfir__scan_processes":         {"exec": "memory.scan_processes",         "phase": "1"},
    "mcp__savvydfir__detect_injection":       {"exec": "memory.detect_injection",       "phase": "1"},
    "mcp__savvydfir__scan_network":           {"exec": "memory.scan_network",           "phase": "1"},
    "mcp__savvydfir__list_dlls":              {"exec": "memory.list_dlls",              "phase": "1"},
    # Phase 2 — Disk (sequential)
    "mcp__savvydfir__extract_mft_timeline":   {"exec": "disk.extract_mft_timeline",     "phase": "2"},
    "mcp__savvydfir__extract_usn_journal":    {"exec": "disk.extract_usn_journal",      "phase": "2"},
    "mcp__savvydfir__summarize_evtx":         {"exec": "disk.summarize_evtx",           "phase": "2"},
    "mcp__savvydfir__extract_prefetch":       {"exec": "disk.extract_prefetch",         "phase": "2"},
    "mcp__savvydfir__get_amcache":            {"exec": "disk.get_amcache",              "phase": "2"},
    "mcp__savvydfir__extract_shimcache":      {"exec": "disk.extract_shimcache",        "phase": "2"},
    "mcp__savvydfir__extract_registry_run_keys": {"exec": "disk.extract_registry_run_keys", "phase": "2"},
    "mcp__savvydfir__extract_srum":           {"exec": "disk.extract_srum",             "phase": "2"},
    # Phase 3 — Detection
    "mcp__savvydfir__sigma_hunt":             {"exec": "detection.sigma_hunt",          "phase": "3"},
    # Phase 5 — Correlation
    "mcp__savvydfir__compare_disk_and_memory":{"exec": "correlation.compare_disk_and_memory", "phase": "5"},
}


def _emit(additional_context: str) -> None:
    """Print a hookSpecificOutput payload with the supplied directive."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": additional_context,
        }
    }))


# Explicit structured markers only — match workflow-enforce-pre.py.
# peer reviewer review removed broad substring matching and the 3-attempt bypass.
# Run 9 fix: added "tool_incompatible" (Vol3 profile mismatch / missing symbols
# → tool genuinely cannot run on this image; gate should treat as satisfied).
_ABSENCE_MARKERS = ("artifact_absent", "no_data", "tool_incompatible")


def _called_tools(state_path: Path) -> set[str]:
    """Return tool_names that are either successful OR have explicit absence.

    A tool is considered 'satisfied' if any of:
      * an execution returned exit_code in (0, None) — clean success, OR
      * any execution's outputs_summary contains "artifact_absent" or
        "no_data" — explicit structured gap from the MCP tool itself.
    Transient/unexplained failures stay UNSATISFIED.
    """
    try:
        state = json.loads(state_path.read_text())
    except Exception:
        return set()

    attempts: dict[str, list[tuple[object, str]]] = {}
    for exe in state.get("executions") or []:
        tn = exe.get("tool_name") or ""
        if not tn:
            continue
        ec = exe.get("exit_code")
        out = str(exe.get("outputs_summary") or "").lower()
        attempts.setdefault(tn, []).append((ec, out))

    satisfied: set[str] = set()
    for tn, runs in attempts.items():
        if any(ec in (0, None) for ec, _ in runs):
            satisfied.add(tn)
            continue
        if any(any(m in s for m in _ABSENCE_MARKERS) for _, s in runs):
            satisfied.add(tn)
    return satisfied


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except Exception:
        return

    tool_name = event.get("tool_name") or ""
    cwd = event.get("cwd") or os.getcwd()
    state_path = Path(cwd) / "analysis" / "state.json"

    # After mount_image: if SleuthKit-direct access was detected, the next
    # disk tool MUST be extract_windows_artifacts — otherwise every other
    # disk tool will fail with file-not-found because /mnt/disk/$MFT etc.
    # don't exist. Read the tool_result to detect tsk_direct.
    if tool_name == "mcp__savvydfir__mount_image":
        result = event.get("tool_result") or {}
        # Result may be wrapped in {"data": {...}} or flat
        data = result.get("data") if isinstance(result, dict) else None
        access = ""
        device = ""
        offset = 0
        if isinstance(data, dict):
            access = str(data.get("access_mode") or data.get("mount_status") or "")
            device = str(data.get("tsk_device_path") or data.get("mount_path") or "")
            offset = data.get("next_tools", {}).get("partition_offset_sectors", 0) if isinstance(data.get("next_tools"), dict) else 0
        elif isinstance(result, dict):
            access = str(result.get("access_mode") or result.get("mount_status") or "")
            device = str(result.get("tsk_device_path") or "")
            offset = result.get("next_tools", {}).get("partition_offset_sectors", 0) if isinstance(result.get("next_tools"), dict) else 0
        if "tsk_direct" in access or "sleuthkit_direct" in access:
            msg = (
                f"SleuthKit-direct access — no NTFS volume mount. "
                f"Next required tool: extract_windows_artifacts(case_id, "
                f"image_path='{device}', tsk_device_path='{device}', "
                f"partition_offset_sectors={offset}). "
                f"Stage raw artifacts BEFORE any other disk tool — "
                f"calling extract_mft_timeline / summarize_evtx / get_amcache "
                f"/ extract_registry_run_keys / extract_shimcache / extract_srum "
                f"/ extract_usn_journal first will fail with file-not-found."
            )
            _emit(msg)
            return

    # Analysis-contract nudge: every artifact-producing tool returns a
    # csv_path / output_path. Run-9 showed the agent was running extractions
    # then MOVING ON without calling run_analysis or spawning specialists,
    # producing 552 ACTIVE / 2 CONFIRMED instead of Run-8's 8 CONFIRMED.
    # Remind the agent IMMEDIATELY after every extractor that the response
    # is a pivot point, not an endpoint.
    #
    # W1.6.1b (2026-05-23): inverted to mirror agent_trigger.py's
    # main-agent-first orchestration (PLAN-FIND-EVIL-HACKATHON-2026-05-23.md).
    # The .md files at .claude/agents/<artifact>-analyst.md are now
    # FORENSIC-HEURISTIC KNOWLEDGE BASES (reference context), not Task
    # subagent dispatch targets. Specialist Task spawn remains as an
    # opt-in escape hatch when isolation matters.
    HEURISTIC_REFERENCE = {
        "mcp__savvydfir__extract_mft_timeline":       "mft-analyst",
        "mcp__savvydfir__extract_usn_journal":        "mft-analyst",
        "mcp__savvydfir__summarize_evtx":             "evtx-analyst",
        "mcp__savvydfir__extract_prefetch":           "prefetch-analyst",
        "mcp__savvydfir__get_amcache":                "amcache-analyst",
        "mcp__savvydfir__extract_shimcache":          "registry-analyst",
        "mcp__savvydfir__extract_registry_run_keys":  "registry-analyst",
        "mcp__savvydfir__extract_srum":               "srum-analyst",
        "mcp__savvydfir__sigma_hunt":                 "sigma-analyst",
    }
    if tool_name in HEURISTIC_REFERENCE:
        result = event.get("tool_result") or {}
        data = result.get("data") if isinstance(result, dict) else result
        csv_path = ""
        if isinstance(data, dict):
            csv_path = data.get("csv_path") or data.get("output_path") or data.get("network_csv_path") or ""
        if csv_path:
            heuristic_md = HEURISTIC_REFERENCE[tool_name]
            short = tool_name.replace("mcp__savvydfir__", "")
            _emit(
                f"{short} produced csv_path={csv_path}. ANALYZE IT NOW — do NOT "
                f"move to the next mandatory extraction yet.\n"
                f"Analysis path (main-agent inline):\n"
                f"  1. Read .claude/agents/{heuristic_md}.md for forensic "
                f"heuristics that apply to this artifact (heuristics, not "
                f"procedures).\n"
                f"  2. Call run_analysis(data_path='{csv_path}', query='df.dtypes') "
                f"to inspect schema, then run targeted Pandas queries shaped "
                f"by the heuristics.\n"
                f"  3. Persist each evidence-backed conclusion via "
                f"submit_finding() with execution_id linkage for the Mermaid "
                f"evidence chain DAG.\n"
                f"  4. Close the lane via record_analysis_lane(... assigned_agent="
                f"'main-agent' ...) when this artifact's findings are persisted."
            )
            return

    # Short next-step hint after major Phase 2/3/5 milestones.
    # Compact by design — verbose context bloat caused token-budget exhaustion
    # in Run7. The agent has CLAUDE.md + the start_investigation workflow_contract;
    # we only need to point at the NEXT tool, not re-explain the whole plan.
    if tool_name in ("mcp__savvydfir__summarize_evtx",
                     "mcp__savvydfir__sigma_hunt",
                     "mcp__savvydfir__compare_disk_and_memory"):
        called = _called_tools(state_path)
        pending: list[str] = []
        for mcp_name, meta in MANDATORY_PHASE_TOOLS.items():
            if meta["exec"] not in called:
                pending.append(mcp_name.replace("mcp__savvydfir__", ""))
        if pending:
            next_tool = pending[0]
            remaining = len(pending) - 1
            msg = (
                f"Next required tool: {next_tool}"
                + (f" ({remaining} more pending after this)" if remaining else "")
                + ". generate_report will be denied until all run successfully or "
                "report documented absence."
            )
            _emit(msg)
        return


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Fail-open: never block the investigation due to a hook bug
        sys.exit(0)
