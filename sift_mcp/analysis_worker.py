"""Memory-isolated worker for run_analysis (F1, review 2026-06-04).

run_analysis used to execute pandas IN the MCP server process, so a runaway
query (e.g. a multi-GB intermediate on the MFT/USN CSV) drove server RSS to
15.3GB and systemd-oomd killed the whole server mid-investigation.

This module is spawned as a CHILD process (`python -m sift_mcp.analysis_worker`):
it caps its own address space with RLIMIT_AS *before importing pandas*, runs the
query via the existing run_safe_analysis, and returns a small JSON envelope on
stdout. If the query blows the cap, only THIS child dies (clean MemoryError, or
SIGKILL if mmap bypasses the soft limit) — the parent MCP server survives and
returns a structured error. This restores the process isolation that existed
when analysis ran via Bash, before run_analysis became an in-process MCP tool.

Protocol: a single JSON object on stdin:
    {"data_path": str, "query": str, "output_format": str, "mem_cap_bytes": int}
Response: a single JSON object on stdout:
    {"ok": true,  "result": <AnalysisResult dict>}
    {"ok": false, "error": str, "kind": "safe_analysis"|"memory"|"other"}
"""
from __future__ import annotations

import json
import sys

DEFAULT_CAP_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB


def _apply_memory_cap(cap_bytes: int) -> None:
    """Cap this process's virtual address space BEFORE pandas/numpy import.

    Best-effort: if the platform rejects the limit we still have process
    isolation (a child OOM cannot take down the server). RLIMIT_AS is preferred
    over RLIMIT_DATA because numpy/pandas allocation patterns make address-space
    the better coarse boundary.
    """
    try:
        import resource
    except Exception:
        return
    if cap_bytes <= 0:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_hard = hard
        if hard == resource.RLIM_INFINITY or hard > cap_bytes:
            new_hard = cap_bytes
        resource.setrlimit(resource.RLIMIT_AS, (cap_bytes, new_hard))
    except (ValueError, OSError):
        # Soft-fail: isolation (separate PID) is the real guard.
        pass


def main() -> int:
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except Exception as exc:  # malformed request
        sys.stdout.write(json.dumps({"ok": False, "error": f"bad request: {exc}", "kind": "other"}))
        return 0

    cap = int(req.get("mem_cap_bytes") or DEFAULT_CAP_BYTES)
    _apply_memory_cap(cap)  # MUST precede the pandas import inside run_safe_analysis

    # Import AFTER the cap is set so pandas/numpy allocate under RLIMIT_AS.
    from sift_mcp.safe_analysis import run_safe_analysis, SafeAnalysisError

    try:
        result = run_safe_analysis(
            req["data_path"], req["query"], req.get("output_format", "table")
        )
        sys.stdout.write(json.dumps({"ok": True, "result": result}))
    except SafeAnalysisError as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc), "kind": "safe_analysis"}))
    except MemoryError:
        sys.stdout.write(json.dumps({
            "ok": False,
            "error": f"analysis exceeded the {cap // (1024*1024)}MB memory budget",
            "kind": "memory",
        }))
    except Exception as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc), "kind": "other"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
