#!/usr/bin/env python3
"""PreToolUse workflow-gate hook (peer reviewer-tightened).

Fires before `mcp__savvydfir__generate_report` and BLOCKS the call if any
mandatory Phase 1–5 tool has neither (a) run successfully nor (b) been
attempted and explicitly reported a structured artifact-absent status.

Per peer reviewer review (HIGH): the previous version had two loopholes that
silently bypassed coverage:
  * 3-attempt bypass — three transient failures unblocked generate_report
    even though zero evidence was collected. REMOVED.
  * Broad substring matching ("not found", "validation failed", "fls
    failed") — these match tool crashes, not artifact absence. NARROWED.

A tool is now SATISFIED only if:
  * exit_code in (0, None) — it completed cleanly, OR
  * outputs_summary contains the explicit structured marker
    "artifact_absent" or "no_data" — i.e. the MCP tool itself
    classified the result as a legitimate evidence-access gap.

Tool failures (path errors, dotnet crashes, transient I/O) remain
BLOCKING — they are not evidence-absent, they are unresolved errors
the operator should investigate.

Designed to FAIL OPEN on script errors — never block due to a hook bug.

Schema: https://code.claude.com/docs/en/hooks
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional
from typing import Any

# Mandatory tools per the Run7 coverage gate.
MANDATORY: dict[str, str] = {
    # MCP tool name → state.json:executions tool_name
    "list_processes":            "memory.list_processes",
    "scan_processes":            "memory.scan_processes",
    "detect_injection":          "memory.detect_injection",
    "scan_network":              "memory.scan_network",
    "list_dlls":                 "memory.list_dlls",
    "extract_mft_timeline":      "disk.extract_mft_timeline",
    "extract_usn_journal":       "disk.extract_usn_journal",
    "summarize_evtx":            "disk.summarize_evtx",
    "extract_prefetch":          "disk.extract_prefetch",
    "get_amcache":               "disk.get_amcache",
    "extract_shimcache":         "disk.extract_shimcache",
    "extract_registry_run_keys": "disk.extract_registry_run_keys",
    "extract_srum":              "disk.extract_srum",
    "sigma_hunt":                "detection.sigma_hunt",
    "compare_disk_and_memory":   "correlation.compare_disk_and_memory",
}

# Explicit structured markers that MCP tools emit in their response
# `status` field for legitimate evidence-access gaps. The hook treats
# these as "satisfied" — no further retry needed. ANY OTHER non-zero
# exit (including path errors, dotnet crashes, transient I/O) is a
# real failure that must be retried or escalated.
ABSENCE_MARKERS: tuple[str, ...] = (
    "artifact_absent",  # MCP tools set status="artifact_absent" when source missing on image
    "no_data",          # MCP tools set status="no_data" when tool ran but artifact empty
)

# Phase 3b/3c (peer reviewer consensus 2026-05-19): Path B authorization is
# governed by the hook-owned delegation ledger. Default behavior is
# dry-run (log decisions, allow all calls). Setting
# SAVVYDFIR_LEDGER_ENFORCE=1 in the environment flips to real deny.
LEDGER_ENFORCE_ENV = "SAVVYDFIR_LEDGER_ENFORCE"


def _ledger_enforce_active() -> bool:
    return os.environ.get(LEDGER_ENFORCE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _load_specialist_lane_map(repo_root: Path) -> dict[str, str]:
    """Build {lane_id: specialist_name} from scripts/agent_trigger.TOOL_AGENT_MAP.

    Returning an empty dict makes the Path B gate fail-open (no
    enforcement) — that's correct: if we can't read the mapping we have
    no business denying calls.
    """
    scripts_dir = repo_root / "scripts"
    if not scripts_dir.is_dir():
        return {}
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        import agent_trigger  # type: ignore  # noqa: WPS433
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    try:
        for _tool, (specialist, lane, _instruction) in agent_trigger.TOOL_AGENT_MAP.items():
            if lane and specialist:
                # First-write-wins; multiple tools per lane share a specialist.
                mapping.setdefault(lane, specialist)
    except Exception:
        return {}
    return mapping


def _allow() -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
    }))


def _deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def _extract_lane_record_inputs(event: dict[str, Any]) -> tuple[str, str]:
    """Pull (lane_id, assigned_agent) out of a record_analysis_lane PreToolUse event."""
    for key in ("tool_input", "toolInput", "input"):
        payload = event.get(key)
        if isinstance(payload, dict):
            lane_id = str(payload.get("lane_id") or "").strip()
            assigned_agent = str(payload.get("assigned_agent") or "").strip()
            if lane_id:
                return lane_id, assigned_agent
    return "", ""


def _check_path_b_gate(event: dict[str, Any], repo_root: Path) -> None:
    """Phase 3b dry-run / Phase 3c enforce: gate Path B (main-agent)
    completion of specialist lanes on ledger evidence.

    Writes machine-countable decision rows to the ledger:
      - path_b_would_allow / path_b_would_deny (dry-run, both phases)
      - path_b_denied (Phase 3c when enforcement is active)

    Decision basis recorded for every row so peer reviewer's "zero false positives /
    negatives" criterion is auditable, not anecdotal.
    """
    lane_id, assigned_agent = _extract_lane_record_inputs(event)
    if not lane_id:
        return  # nothing we can gate
    # W1.6.1a (2026-05-23): main-agent inline is the PREFERRED path in the
    # FIND EVIL! hackathon submission architecture (Custom MCP Server #2,
    # PLAN-FIND-EVIL-HACKATHON-2026-05-23.md). The Path A specialist Task
    # spawn became an opt-in escape hatch in W1.6 (agent_trigger.py).
    # The pre-existing "main-agent requires failed-Path-A evidence" gate
    # contradicted that inversion and would block legitimate inline
    # analysis. Now: main-agent is allowed through unconditionally. We
    # still log the decision for audit completeness, but never deny.
    if assigned_agent.lower() not in {"main-agent", "main"}:
        return

    lane_map = _load_specialist_lane_map(repo_root)
    if lane_id not in lane_map:
        return  # lane has no specialist counterpart — no Path A to log
    expected_specialist = lane_map[lane_id]

    scripts_dir = repo_root / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        import delegation_ledger as ledger  # type: ignore  # noqa: WPS433
    except Exception:
        return  # ledger not importable — fail open

    # Log the main-agent claim for audit. The specific decision_basis
    # reflects whether Path A was even attempted (no = inline-from-start;
    # yes-failed = recovered via inline; yes-succeeded = unusual, log it).
    has_failed_attempt = ledger.has_failed_task_outcome(lane_id)
    has_unavailable = ledger.has_unavailable_marker()
    has_success = ledger.has_successful_task_outcome(lane_id)
    basis_parts = ["main_agent_inline_primary_path_w1.6.1a"]
    if has_failed_attempt:
        basis_parts.append("path_a_failed_recovered_inline")
    if has_unavailable:
        basis_parts.append("path_a_unavailable")
    if has_success:
        basis_parts.append("path_a_also_succeeded")
    try:
        ledger.append_row(
            "path_b_would_allow",
            lane_id=lane_id,
            specialist=expected_specialist,
            decision_basis=";".join(basis_parts),
        )
    except Exception:
        pass
    # No deny path — main-agent is the primary architecture per
    # PLAN-FIND-EVIL-HACKATHON-2026-05-23.md Section 6 (Week 1 deliverable).
    return


# Phase 3 entry tools — sigma_hunt / compare_disk_and_memory / hayabusa_hunt
# are the detection/correlation calls that should NOT run before Phase 2 disk
# extraction is complete. Run-8 ROCBA proved the existing generate_report
# gate fires too late: agent ran sigma_hunt (301s) and compare_disk_and_memory
# while USN / SRUDB / ShimCache / Registry / Security.evtx were still missing,
# then MCP died at the next heavy call before report time. Per peer reviewer + peer reviewer
# consensus 2026-05-26: gate Phase 3 entry on Phase 2 completion.
PHASE3_ENTRY_TOOLS = {
    "mcp__savvydfir__sigma_hunt",
    "mcp__savvydfir__hayabusa_hunt",
    "mcp__savvydfir__compare_disk_and_memory",
}

# Phase 2 disk tools that must be satisfied before Phase 3 entry. Subset of
# MANDATORY above — the memory tools are checked separately by Phase 1.
PHASE2_DISK_REQUIRED: tuple[str, ...] = (
    "disk.extract_mft_timeline",
    "disk.extract_usn_journal",
    "disk.summarize_evtx",
    "disk.extract_prefetch",
    "disk.get_amcache",
    "disk.extract_shimcache",
    "disk.extract_registry_run_keys",
    "disk.extract_srum",
)


def _check_phase3_entry_gate(state: dict) -> Optional[str]:
    """Return deny-reason if Phase 3 entry tool is attempted with Phase 2 incomplete.

    "Satisfied" means the same as for the generate_report gate: clean exit_code
    OR an explicit ``artifact_absent`` / ``no_data`` absence marker. Anything
    else (timeouts, crashes, never-invoked) is unsatisfied.

    Override the gate with ``SAVVYDFIR_SKIP_PHASE3_GATE=1`` for advanced
    operator workflows (e.g., evidence partial-acquisition cases).
    """
    if os.environ.get("SAVVYDFIR_SKIP_PHASE3_GATE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return None

    attempts: dict[str, list[tuple[Any, str]]] = {}
    for exe in state.get("executions") or []:
        tn = exe.get("tool_name") or ""
        if not tn:
            continue
        ec = exe.get("exit_code")
        out = str(exe.get("outputs_summary") or "").lower()
        attempts.setdefault(tn, []).append((ec, out))

    missing: list[str] = []
    for full in PHASE2_DISK_REQUIRED:
        runs = attempts.get(full) or []
        if not runs:
            missing.append(full)
            continue
        if any(ec in (0, None) for ec, _ in runs):
            continue
        if any(any(m in summary for m in ABSENCE_MARKERS) for _, summary in runs):
            continue
        missing.append(full)

    if not missing:
        return None

    return (
        "BLOCKED: Phase 3 detection/correlation tools cannot run until Phase 2 "
        "disk extraction is complete. The agent must call all 8 mandatory disk "
        "tools (or mark them as artifact_absent / no_data) BEFORE invoking "
        "sigma_hunt / compare_disk_and_memory / hayabusa_hunt.\n\n"
        "MISSING (or failed without absence marker):\n  - " +
        "\n  - ".join(missing) +
        "\n\nIf the disk is not mounted at /mnt/disk, first call "
        "extract_windows_artifacts(case_id, image_path) to stage raw hives, "
        "SRUDB.dat, and the USN journal. Then re-run each missing extractor.\n\n"
        "Override (advanced operator only — partial-acquisition cases): "
        "set SAVVYDFIR_SKIP_PHASE3_GATE=1 in the environment."
    )


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except Exception:
        return

    tool_name = event.get("tool_name") or ""
    cwd = event.get("cwd") or os.getcwd()
    repo_root = Path(cwd)

    # Phase 3b/3c Path B gate: fires on record_analysis_lane, may deny
    # if SAVVYDFIR_LEDGER_ENFORCE=1 and no ledger evidence backs Path B.
    # The function returns normally (no _allow / _deny) when it has no
    # decision to make, so existing tools fall through to the generate_report
    # gate below.
    if tool_name in {"mcp__savvydfir__record_analysis_lane", "record_analysis_lane"}:
        try:
            _check_path_b_gate(event, repo_root)
        except Exception:
            pass
        return  # this hook only governs record_analysis_lane and generate_report

    # Phase 3 entry gate (Run-8 fix): block detection/correlation tools when
    # Phase 2 disk extraction is incomplete. Fail-soft on missing state.
    if tool_name in PHASE3_ENTRY_TOOLS:
        try:
            state_path = repo_root / "analysis" / "state.json"
            if state_path.exists():
                state = json.loads(state_path.read_text())
                deny_reason = _check_phase3_entry_gate(state)
                if deny_reason:
                    _deny(deny_reason)
                    return  # _deny exits the process
        except Exception:
            pass  # fail-open on state read errors
        return

    if tool_name != "mcp__savvydfir__generate_report":
        # Not our target — let the call through.
        return

    state_path = repo_root / "analysis" / "state.json"

    try:
        state = json.loads(state_path.read_text())
    except Exception:
        # No state yet — let the MCP tool itself handle this case
        return

    # Build {tool_name: [(exit_code, outputs_summary_lower), ...]}
    attempts: dict[str, list[tuple[Any, str]]] = {}
    for exe in state.get("executions") or []:
        tn = exe.get("tool_name") or ""
        if not tn:
            continue
        ec = exe.get("exit_code")
        out = str(exe.get("outputs_summary") or "").lower()
        attempts.setdefault(tn, []).append((ec, out))

    def _is_satisfied(full_name: str) -> bool:
        runs = attempts.get(full_name) or []
        if not runs:
            return False
        # 1) Clean success at any point
        if any(ec in (0, None) for ec, _ in runs):
            return True
        # 2) Explicit structured absence marker from the MCP tool itself.
        #    "artifact_absent" or "no_data" — legitimate evidence gap.
        #    Anything else (transient errors, path failures, dotnet crashes)
        #    stays blocking until either resolved or explicitly waived.
        for _, summary in runs:
            if any(marker in summary for marker in ABSENCE_MARKERS):
                return True
        return False

    missing = [short for short, full in MANDATORY.items() if not _is_satisfied(full)]

    if not missing:
        # All mandatory tools have run — allow the report.
        return

    reason = (
        "BLOCKED: generate_report cannot proceed until these mandatory Run7 tools "
        "have run successfully. Call each one with its required arguments before "
        "retrying generate_report.\n\nMISSING:\n  - " +
        "\n  - ".join(missing) +
        "\n\nIf the disk is not mounted at /mnt/disk, first call "
        "extract_windows_artifacts(case_id, image_path) to stage raw hives, "
        "SRUDB.dat, and the USN journal under /cases/<case_id>/artifacts/raw/. "
        "extract_shimcache and extract_srum will then fall back to those staged paths."
    )
    _deny(reason)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(0)
