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
    include_sigma_hunt: bool = True,
    include_build_timeline: bool = True,
) -> None:
    """Register the universal mandatory memory + disk tool suffixes as executions.

    sigma_hunt is now part of the mandatory IR baseline (review review #2:
    gate must enforce a successful Chainsaw run, not just sigma_scan post-
    processing). Tests that need to verify gate-without-sigma_hunt behavior
    can pass `include_sigma_hunt=False`.

    build_timeline is now part of the mandatory IR baseline (H.2 fix:
    Plaso super-timeline required for cross-artifact temporal correlation).
    Tests that need to verify gate-without-build_timeline behavior can pass
    `include_build_timeline=False`.
    """
    for i, tool_name in enumerate(FULL_WINDOWS_IR_BASELINE_TOOLS):
        manager.add_execution(
            {
                "case_id": case_id,
                "execution_id": f"E-{first_id + i:03d}",
                "iteration": 1,
                "tool_name": tool_name,
                "command_line": f"{tool_name}()",
                "exit_code": 0,
                "duration_seconds": 2.0 + (i * 0.5),  # Vary slightly for realism
                "audit_completed_entry_hash": f"test-baseline-{tool_name.split('.')[-1]}-hash",
            }
        )
    idx = first_id + len(FULL_WINDOWS_IR_BASELINE_TOOLS)
    if include_sigma_hunt:
        manager.add_execution(
            {
                "case_id": case_id,
                "execution_id": f"E-{idx:03d}",
                "iteration": 1,
                "tool_name": "detection.sigma_hunt",
                "command_line": "sigma_hunt(...)",
                "exit_code": 0,
                "duration_seconds": 12.5,
                "audit_completed_entry_hash": "test-baseline-sigma-hunt-hash",
                # Phase-A-boundary: gate requires finding_ids_generated or
                # output_handle as structured proof of durable output.
                "outputs_summary": "0 hits (clean fixture)",
                "finding_ids_generated": [f"F-{case_id}-SIGMA-SUMMARY"],
            }
        )
        idx += 1
    if include_build_timeline:
        manager.add_execution(
            {
                "case_id": case_id,
                "execution_id": f"E-{idx:03d}",
                "iteration": 1,
                "tool_name": "timeline.build_timeline",
                "command_line": "build_timeline(...)",
                "exit_code": 0,
                "duration_seconds": 45.2,
                "audit_completed_entry_hash": "test-baseline-build-timeline-hash",
                "storage_path": f"/cases/{case_id}/analysis/timeline.plaso",
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
