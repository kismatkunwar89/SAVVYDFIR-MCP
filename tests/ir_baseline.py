"""Helpers for Windows IR baseline tool executions in tests."""

from __future__ import annotations

from typing import Any

# Order matches evaluate_ir_coverage_gate: memory baseline, then disk (sorted suffixes).
FULL_WINDOWS_IR_BASELINE_TOOLS: tuple[str, ...] = (
    "memory.list_processes",
    "memory.scan_processes",
    "memory.scan_network",
    "disk.extract_mft_timeline",
    "disk.extract_prefetch",
    "disk.extract_registry_run_keys",
    "disk.get_amcache",
    "disk.summarize_evtx",
)

EXTENDED_ANTI_FORENSICS_TOOLS: tuple[str, ...] = (
    "disk.analyze_vss",
    "disk.extract_shimcache",
    "disk.extract_srum",
)


def add_windows_ir_baseline_executions(
    manager: Any,
    case_id: str,
    *,
    first_id: int = 1,
) -> None:
    """Register the universal mandatory memory + disk tool suffixes as executions."""
    for i, tool_name in enumerate(FULL_WINDOWS_IR_BASELINE_TOOLS):
        manager.add_execution(
            {
                "case_id": case_id,
                "execution_id": f"E-{first_id + i:03d}",
                "iteration": 1,
                "tool_name": tool_name,
                "command_line": f"{tool_name}()",
            }
        )


def add_extended_anti_forensics_executions(
    manager: Any,
    case_id: str,
    *,
    first_id: int,
) -> int:
    """Register analyze_vss, extract_shimcache, extract_srum; returns next free id index."""
    offset = 0
    for tool_name in EXTENDED_ANTI_FORENSICS_TOOLS:
        manager.add_execution(
            {
                "case_id": case_id,
                "execution_id": f"E-{first_id + offset:03d}",
                "iteration": 1,
                "tool_name": tool_name,
                "command_line": f"{tool_name}()",
            }
        )
        offset += 1
    return first_id + offset
