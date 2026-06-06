#!/usr/bin/env python3
"""Stop hook: ensures investigation is complete before ending session.

review-tightened: incomplete cases CANNOT exit silently after a retry
threshold. Closure requires either:
  * state.json status == COMPLETE + sigma_hunt + compare_disk_and_memory
    in audit.jsonl — i.e. the investigation actually finished, OR
  * an explicit auditable operator override via a waiver file
    (ANALYSIS_DIR/.savvydfir_waiver) containing a reason string.

The hook detects the loop scenario (agent has nothing useful to do but
keeps trying to stop) by counting consecutive block events. After
MAX_BLOCKS, the reason now INSTRUCTS the operator to create the waiver
file — but still blocks. Auto-approve is removed entirely per review.

If the operator wants to bail without writing a waiver, Ctrl+C bypasses
the hook (kernel signal, not a hook decision). This makes silent
unaudited closure impossible.

Waiver semantics:
  * File ANALYSIS_DIR/.savvydfir_waiver must contain a non-empty reason
  * On approve, the hook appends a "waiver_used" record to audit.jsonl
    so the incomplete closure is auditable
  * The waiver file is consumed on use (renamed to .savvydfir_waiver.used)
    so it doesn't silently apply to future sessions
"""
import json
import sys
import os
import time
from pathlib import Path

MAX_BLOCKS = 2  # after this many blocks, reason starts mentioning waiver path


def _find_state_json() -> str | None:
    env_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR")
    if env_dir:
        candidate = os.path.join(env_dir, "state.json")
        if os.path.isfile(candidate):
            return candidate
        return None
    candidate = os.path.join("./analysis", "state.json")
    if os.path.isfile(candidate):
        return candidate
    return None


def _find_audit_jsonl() -> str | None:
    env_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR")
    if env_dir:
        candidate = os.path.join(env_dir, "audit.jsonl")
        if os.path.isfile(candidate):
            return candidate
        return None
    candidate = os.path.join("./analysis", "audit.jsonl")
    if os.path.isfile(candidate):
        return candidate
    return None


def _audit_has_completed_tool(audit_path: str, tool_fragment: str) -> bool:
    try:
        with open(audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("event_type") != "completed":
                    continue
                tool_name = str(entry.get("tool", "") or "")
                if tool_fragment in tool_name:
                    return True
    except (OSError, IOError):
        pass
    return False


def _investigation_is_in_progress(state_path: str) -> tuple[bool, str]:
    """Return (in_progress, case_id)."""
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return (False, "")
    if not isinstance(state, dict):
        return (False, "")
    case_id = str(state.get("case_id") or "").strip()
    if not case_id:
        return (False, "")
    executions = state.get("executions") or []
    if isinstance(executions, list) and len(executions) > 0:
        return (True, case_id)
    executions_count = state.get("executions_count") or 0
    try:
        if int(executions_count) > 0:
            return (True, case_id)
    except (TypeError, ValueError):
        pass
    return (False, case_id)


def _block_counter_path() -> Path:
    """Where the persisted block counter lives — sits next to state.json."""
    env_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR") or "./analysis"
    return Path(env_dir) / ".stop_block_count.json"


def _read_block_count(case_id: str) -> int:
    p = _block_counter_path()
    try:
        data = json.loads(p.read_text())
        if data.get("case_id") == case_id:
            return int(data.get("count", 0))
    except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
        pass
    return 0


def _write_block_count(case_id: str, count: int) -> None:
    p = _block_counter_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"case_id": case_id, "count": count}))
    except OSError:
        pass


def _analysis_dir() -> Path:
    """Directory hosting state.json/audit.jsonl/waiver/counter."""
    return Path(os.environ.get("SAVVYDFIR_ANALYSIS_DIR") or "./analysis")


def _waiver_path() -> Path:
    return _analysis_dir() / ".savvydfir_waiver"


def _read_waiver() -> str | None:
    """Return the waiver reason string if a valid waiver exists, else None."""
    p = _waiver_path()
    if not p.is_file():
        return None
    try:
        reason = p.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not reason:
        return None
    return reason


def _audit_append(record: dict, audit_path: Path) -> tuple[bool, str]:
    """Append a JSONL record to audit.jsonl, fsync, and return (ok, error_text).

    fsync is required because crash durability matters when a record is the
    only artifact of an audited waiver consumption.
    """
    try:
        with open(audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError as exc:
                # fsync may legitimately fail on non-disk fs (procfs, tmpfs
                # variants). Treat as soft warning, not fatal — the data is
                # in the page cache and will be visible to the next reader.
                return (True, f"fsync_warning:{exc}")
        return (True, "")
    except OSError as exc:
        return (False, f"audit_append_failed:{exc}")


def _consume_waiver(case_id: str, reason: str, missing: list[str]) -> dict:
    """Audit waiver consumption and rename the waiver file. Fail-closed.

    review-required attempt-then-finalize pattern:
      1. Write `stop_hook_waiver_consumption_attempted` audit record (fsync).
      2. Rename waiver to unique consumed-filename (timestamp+pid+random tag).
      3. Write `stop_hook_waiver_consumed` audit record (fsync).
    Only step 3 reaching completion authorizes the caller to approve the
    stop. Any failure → caller blocks with a concrete remediation message.

    Returns {ok, reason, remediation}.
    """
    audit_dir = _analysis_dir()
    audit_path = audit_dir / "audit.jsonl"
    waiver = _waiver_path()
    ts = int(time.time())
    # Unique consumed-filename so concurrent sessions or repeated waiver use
    # don't collide. pid+random tag avoids same-second collisions.
    tag = f"{ts}.{os.getpid()}.{os.urandom(2).hex()}"
    used_path = waiver.with_suffix(f"{waiver.suffix}.consumed.{tag}")

    base_record = {
        "case_id": case_id,
        "reason": reason,
        "missing_tools": missing,
        "timestamp": ts,
        "pid": os.getpid(),
    }

    # Step 1: record consumption attempt
    attempt_record = {**base_record, "event_type": "stop_hook_waiver_consumption_attempted"}
    ok, err = _audit_append(attempt_record, audit_path)
    if not ok:
        return {
            "ok": False,
            "reason": f"audit_append_failed: {err}",
            "remediation": (
                f"Cannot write to {audit_path}. Ensure the analysis directory "
                "is writable (chmod +w) and has free space, then retry."
            ),
        }

    # Step 2: rename waiver to unique consumed-filename (transactional anchor)
    try:
        waiver.rename(used_path)
    except OSError as exc:
        # Audit the failure so the operator sees the trail
        _audit_append({
            **base_record,
            "event_type": "stop_hook_waiver_consumption_failed",
            "failed_step": "rename",
            "error": str(exc),
        }, audit_path)
        return {
            "ok": False,
            "reason": f"waiver_rename_failed: {exc}",
            "remediation": (
                f"Cannot rename {waiver} to {used_path}. Check filesystem "
                "permissions and cross-device-link constraints. The waiver "
                "remains in place and consumption was NOT authorized."
            ),
        }

    # Step 3: record final consumption — only after rename committed
    consumed_record = {
        **base_record,
        "event_type": "stop_hook_waiver_consumed",
        "consumed_path": str(used_path),
    }
    ok, err = _audit_append(consumed_record, audit_path)
    if not ok:
        # Rare: rename succeeded but final audit failed. The waiver is
        # already gone — block anyway so the operator notices the audit
        # gap and can fix the filesystem before retrying.
        return {
            "ok": False,
            "reason": f"final_audit_append_failed_after_rename: {err}",
            "remediation": (
                f"Waiver was renamed to {used_path} but the 'consumed' audit "
                f"record failed to write to {audit_path}. Fix the filesystem "
                "and add a manual audit entry referencing the consumed-path."
            ),
        }

    return {"ok": True, "reason": "waiver_consumed", "remediation": ""}


def _missing_tools_actionable(state_path: str, audit_path: str | None) -> list[str]:
    """Compute the list of mandatory tools NOT yet called successfully.

    Mirrors the workflow-enforce-pre.py mandatory list. Returns short MCP
    tool names (without the disk./memory./detection. prefix) so the agent
    sees an actionable to-do list.
    """
    MANDATORY = {
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
        "generate_report":           "reporting.generate_report",
    }
    # review-tightened: only explicit structured markers count as gap.
    # No 3-attempt bypass — persistent failure stays unsatisfied.
    # F-B (review 2026-06-04): collection_timeout = an honest required-tool
    # attempt that timed out (e.g. a multi-GB EVTX/USN parse on this 4-vCPU box).
    # Treat it as attempted-with-gap so the stop hook stops RE-DEMANDING the same
    # heavy parse forever (the timeout loop). It is NOT success - the report still
    # records it as a data gap (exit_code != 0).
    ABSENCE = ("artifact_absent", "no_data", "collection_timeout")
    # Memory-conditional (review 2026-06-05): on a disk-only case (manifest
    # had no memory_dumps -> state.memory_present == False) the 5 memory tools can
    # never run; do NOT re-demand them. compare_disk_and_memory is NOT in this set
    # (it stays mandatory; its checks are disk-primary). Default True (absent flag)
    # keeps every memory case unchanged. Case-agnostic.
    MEMORY_ONLY_TOOLS = frozenset({
        "list_processes", "scan_processes", "scan_network",
        "detect_injection", "list_dlls",
    })
    try:
        state = json.loads(Path(state_path).read_text())
    except Exception:
        return list(MANDATORY.keys())
    memory_present = bool(state.get("memory_present", True))
    attempts: dict[str, list[tuple]] = {}
    for exe in state.get("executions") or []:
        tn = exe.get("tool_name") or ""
        if not tn:
            continue
        ec = exe.get("exit_code")
        out = str(exe.get("outputs_summary") or "").lower()
        attempts.setdefault(tn, []).append((ec, out))

    missing: list[str] = []
    for short, full in MANDATORY.items():
        if not memory_present and short in MEMORY_ONLY_TOOLS:
            continue  # disk-only case: memory tools not applicable, never demand
        runs = attempts.get(full) or []
        if not runs:
            missing.append(short)
            continue
        if any(ec in (0, None) for ec, _ in runs):
            continue  # satisfied via clean success
        if any(any(m in s for m in ABSENCE) for _, s in runs):
            continue  # satisfied via explicit artifact_absent / no_data
        missing.append(short)
    return missing


def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        return

    state_path = _find_state_json()
    in_progress = False
    case_id = ""
    if state_path:
        in_progress, case_id = _investigation_is_in_progress(state_path)

    # Gate 0: no investigation in progress → never block.
    if not in_progress:
        print(json.dumps({"decision": "approve"}))
        return

    warnings: list[str] = []

    # Check 1: state.json status == "COMPLETE"
    state_complete = False
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if isinstance(state, dict) and state.get("status", "").upper() == "COMPLETE":
            state_complete = True
    except (json.JSONDecodeError, OSError):
        pass

    if not state_complete:
        warnings.append("generate_report() was not called (state.json status != COMPLETE).")

    # Check 2-3: audit.jsonl has completed entries for synthesis tools
    audit_path = _find_audit_jsonl()
    if not audit_path:
        warnings.append(
            "audit.jsonl not found in analysis directory. Investigation tracking "
            "requires an audit trail. If this is intentional (non-DFIR session), "
            "remove state.json to bypass this check."
        )
    else:
        if not _audit_has_completed_tool(audit_path, "sigma_hunt"):
            warnings.append(
                "sigma_hunt() has no completed audit entry — no rule-engine "
                "evidence in this case (sigma_scan alone does not count)."
            )
        if not _audit_has_completed_tool(audit_path, "compare_disk_and_memory"):
            warnings.append("compare_disk_and_memory() has no completed audit entry.")

    # Investigation is complete → approve and reset counter
    if not warnings:
        _write_block_count(case_id, 0)
        print(json.dumps({"decision": "approve"}))
        return

    missing = _missing_tools_actionable(state_path, audit_path)

    # review-required: explicit operator waiver is the only audited way to
    # close an incomplete investigation. The consumption itself must succeed
    # (audit append + rename) before the hook approves — otherwise we'd
    # silently exit without the promised audit trail.
    waiver_reason = _read_waiver()
    if waiver_reason:
        result = _consume_waiver(case_id, waiver_reason, missing)
        if result.get("ok"):
            _write_block_count(case_id, 0)
            sys.stderr.write(
                f"[stop-hook] case {case_id}: incomplete-closure waiver applied "
                f"(reason: {waiver_reason!r}). Recorded to audit.jsonl. Waiver "
                "file consumed. Remaining gaps: " + ", ".join(missing) + "\n"
            )
            print(json.dumps({"decision": "approve"}))
            return
        # Waiver consumption FAILED — block with concrete remediation.
        # Do NOT auto-approve; the audit contract requires both steps.
        block_count = _read_block_count(case_id) + 1
        _write_block_count(case_id, block_count)
        reason = (
            f"Waiver consumption failed: {result.get('reason')}. "
            f"{result.get('remediation')} "
            "The waiver file may still be present; fix the underlying "
            "filesystem issue before retrying the stop."
        )
        print(json.dumps({"decision": "block", "reason": reason}))
        return

    # No waiver — keep blocking. Count attempts only to escalate the message.
    block_count = _read_block_count(case_id) + 1
    _write_block_count(case_id, block_count)

    next_tool = missing[0] if missing else "generate_report"
    n_remaining = max(0, len(missing) - 1)
    waiver_path = _waiver_path()

    base_reason = (
        f"Investigation incomplete (block {block_count}). "
        f"Next required: {next_tool}"
        + (f" (+{n_remaining} more pending)" if n_remaining else "")
        + "."
    )
    if block_count > MAX_BLOCKS:
        # Don't auto-approve. Tell the operator how to audit a deliberate exit.
        reason = (
            base_reason
            + f" To exit without completing, create '{waiver_path}' "
            f"containing a one-line reason (e.g. 'image_lacks_disk_image'). "
            "The hook will then approve and record a waiver entry in "
            "audit.jsonl. Ctrl+C also exits but bypasses audit."
        )
    else:
        reason = base_reason

    print(json.dumps({"decision": "block", "reason": reason}))


if __name__ == "__main__":
    main()
