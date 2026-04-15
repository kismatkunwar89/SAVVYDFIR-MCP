#!/usr/bin/env python3
"""Stop hook: ensures investigation is complete before ending session.

Validates completion from authoritative state.json and audit.jsonl — never
from transcript text (which is brittle and produces false-blocking).

Checks:
1. state.json status == "COMPLETE"   → generate_report() was called
2. audit.jsonl has sigma_scan completed entry
3. audit.jsonl has compare_disk_and_memory completed entry
"""
import json
import sys
import os
import glob


def _find_state_json() -> str | None:
    """Locate state.json under the analysis directory."""
    analysis_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR", "./analysis")
    candidate = os.path.join(analysis_dir, "state.json")
    if os.path.isfile(candidate):
        return candidate
    # Fallback: search common locations
    for pattern in ["./analysis/state.json", "/cases/*/state.json", "/tmp/savvydfir/state.json"]:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def _find_audit_jsonl() -> str | None:
    """Locate audit.jsonl under the analysis directory."""
    analysis_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR", "./analysis")
    candidate = os.path.join(analysis_dir, "audit.jsonl")
    if os.path.isfile(candidate):
        return candidate
    for pattern in ["./analysis/audit.jsonl", "/cases/*/audit.jsonl"]:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def _audit_has_completed_tool(audit_path: str, tool_fragment: str) -> bool:
    """Return True if audit.jsonl has a 'completed' entry whose tool field contains the fragment."""
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


def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        return

    warnings = []

    # --- Check 1: state.json status == "COMPLETE" (proves generate_report ran) ---
    state_path = _find_state_json()
    state_complete = False
    if state_path:
        try:
            with open(state_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            if isinstance(state, dict) and state.get("status", "").upper() == "COMPLETE":
                state_complete = True
        except (json.JSONDecodeError, OSError):
            pass

    if not state_complete:
        warnings.append(
            "generate_report() was not called (state.json status != COMPLETE).")

    # --- Check 2 & 3: audit.jsonl has completed entries for synthesis tools ---
    audit_path = _find_audit_jsonl()
    if audit_path:
        if not _audit_has_completed_tool(audit_path, "sigma_scan"):
            warnings.append("sigma_scan() has no completed audit entry.")
        if not _audit_has_completed_tool(audit_path, "compare_disk_and_memory"):
            warnings.append(
                "compare_disk_and_memory() has no completed audit entry.")
    else:
        # No audit file at all — investigation never started, allow exit
        pass

    if warnings:
        print(json.dumps({
            "decision": "block",
            "reason": "Investigation incomplete: " + "; ".join(warnings),
        }))
    else:
        print(json.dumps({"decision": "allow"}))


if __name__ == "__main__":
    main()
