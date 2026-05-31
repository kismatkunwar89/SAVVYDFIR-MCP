"""
sift_mcp.tools.state_tools
~~~~~~~~~~~~~~~~~~~~~~~~~~~

MCP tool functions for reading authoritative case state and exporting the
full audit trace.

Two tools are exposed:

* ``read_state`` - Returns a summary of the current case state (findings,
  executions, open questions, status).
* ``export_trace`` - Returns the full JSONL audit trail as a list of
  :class:`~sift_mcp.audit.AuditEntry` dicts.

Both tools are synchronous (FastMCP supports sync).

Tool init
---------
Call :func:`init_tools` once at server startup, passing the
:class:`~sift_mcp.audit.AuditLogger` and :class:`~sift_mcp.state.CaseStateManager`
instances.
"""

from __future__ import annotations

from typing import Any, Optional

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager

__all__ = [
    "read_state",
    "export_trace",
    "init_tools",
]

# ---------------------------------------------------------------------------
# Module-level singletons (initialised by init_tools)
# ---------------------------------------------------------------------------

_audit: Optional[AuditLogger] = None
_state_mgr: Optional[CaseStateManager] = None


def init_tools(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
) -> None:
    """Wire the shared audit logger and state manager into this tool module.

    Must be called once at server startup before any tool function is invoked.

    Parameters
    ----------
    audit_logger:
        The process-wide :class:`~sift_mcp.audit.AuditLogger` instance.
    state_manager:
        The process-wide :class:`~sift_mcp.state.CaseStateManager` instance.
    """
    global _audit, _state_mgr
    _audit = audit_logger
    _state_mgr = state_manager


# ---------------------------------------------------------------------------
# Tool 1: read_state
# ---------------------------------------------------------------------------


def read_state(case_id: str) -> dict[str, Any]:
    """Return the current authoritative case state summary.

    Loads (or reads from cache) the ``state.json`` file managed by
    :class:`~sift_mcp.state.CaseStateManager` and returns a compact summary
    with the current finding/execution counts, status, open questions, and
    the 10 most recently added findings.

    Parameters
    ----------
    case_id:
        The forensic case identifier (e.g. ``"SRL-2018-WKSTN-01"``).

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "case_id": "SRL-2018-WKSTN-01",
              "investigation_status": "IN_PROGRESS",
              "findings_count": 12,
              "executions_count": 8,
              "confirmed_count": 4,
              "hypothesis_count": 3,
              "rejected_count": 1,
              "unresolved_discrepancies": 2,
              "open_questions": [
                "What process injected into svchost.exe (PID 1832)?",
                ...
              ],
              "latest_findings": [
                {
                  "finding_id": "F-012",
                  "finding_type": "process_injection",
                  "artifact_type": "memory",
                  "description": "...",
                  "confidence": 0.9,
                  "evidence_kind": "observation",
                  "created_at": "2026-05-01T14:23:11.000Z"
                },
                ...
              ],
              "created_at": "2026-05-01T12:00:00.000Z",
              "updated_at": "2026-05-01T14:23:11.000Z"
            }

        On error::

            {
              "status": "error",
              "error": "..."
            }
    """
    if _state_mgr is None:
        return {
            "status": "error",
            "error": "Tool module not initialised — call init_tools() first.",
        }

    try:
        _state_mgr.load(case_id)
    except Exception as exc:
        return {"status": "error", "error": f"Cannot load case state for '{case_id}': {exc}"}

    try:
        summary = _state_mgr.to_summary()
    except Exception as exc:
        return {"status": "error", "error": f"Cannot generate state summary: {exc}"}

    return {
        "status": "ok",
        **summary,
    }


# ---------------------------------------------------------------------------
# Tool 2: export_trace
# ---------------------------------------------------------------------------


def export_trace(case_id: str) -> dict[str, Any]:
    """Export the full execution trace as a list of audit entries.

    Reads every entry from ``audit.jsonl`` managed by the
    :class:`~sift_mcp.audit.AuditLogger`.  The returned entries are in file
    order (chronological).  Each entry captures a ``started`` or
    ``completed`` event for a tool invocation, including the exact command
    line, parameters, exit code, duration, and any ``CORRECTION_EVENT``
    that was produced.

    Use this tool to:

    * Reconstruct the full execution timeline of an investigation.
    * Verify that every finding has a corresponding ``started`` + ``completed``
      audit entry.
    * Export the trace for external analysis or court-admissible documentation.

    Parameters
    ----------
    case_id:
        The forensic case identifier.  Used only for labelling - the audit
        log path is set at server startup.

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "case_id": "SRL-2018-WKSTN-01",
              "entry_count": 24,
              "entries": [
                {
                  "timestamp": "2026-05-01T14:23:11.442Z",
                  "execution_id": "E-001",
                  "event_type": "started",
                  "tool": "disk.extract_prefetch",
                  "parameters": {...},
                  "command_line": "dotnet /opt/zimmermantools/PECmd.dll ...",
                  "agent_turn": 1,
                  "iteration": 1,
                  "exit_code": null,
                  "duration_seconds": null,
                  "outputs_summary": null,
                  "finding_ids_generated": [],
                  "correction_event": null
                },
                ...
              ],
              "started_count": 12,
              "completed_count": 12,
              "correction_events_count": 1
            }

        On error::

            {
              "status": "error",
              "error": "..."
            }
    """
    if _audit is None:
        return {
            "status": "error",
            "error": "Tool module not initialised — call init_tools() first.",
        }

    try:
        entries = _audit.read_all()
    except Exception as exc:
        return {"status": "error", "error": f"Cannot read audit log: {exc}"}

    # Compute summary statistics
    started = sum(1 for e in entries if e.get("event_type") == "started")
    completed = sum(1 for e in entries if e.get("event_type") == "completed")
    corrections = sum(
        1 for e in entries
        if e.get("correction_event") is not None
    )

    return {
        "status": "ok",
        "case_id": case_id,
        "entry_count": len(entries),
        "entries": entries,
        "started_count": started,
        "completed_count": completed,
        "correction_events_count": corrections,
    }
