"""Structured JSONL audit logger for SAVVYDFIR-MCP.

Every forensic tool invocation produces two entries in ``audit.jsonl``:
a ``started`` entry written *before* the subprocess runs, and a
``completed`` entry written *after* it returns.  This design means:

* If the MCP server crashes mid-execution, the started entry without a
  corresponding completed entry marks the interrupted execution.
* Observers can stream the JSONL file in real-time to watch investigations
  as they proceed.
* Full provenance is available: execution_id ↔ finding_id linkage enables
  bidirectional tracing.

Fail-closed contract
--------------------
If any log write raises an exception (disk full, permission error, etc.) the
exception propagates to the caller.  ``SafeRunner.run`` treats this as a
hard failure and **does not execute the subprocess**.  Audit integrity is
never sacrificed for availability.

File format
-----------
Each line in ``audit.jsonl`` is an independent, valid JSON object terminated
by a newline character.  The file is never rewritten; new entries are always
appended.

Concurrent access
-----------------
The logger is *not* designed for concurrent multi-process access.  Within a
single SAVVYDFIR-MCP process it is used synchronously, and writes are flushed
after every entry.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["AuditLogger", "AuditEntry"]


# ---------------------------------------------------------------------------
# Audit entry type alias (for callers that want typed dicts)
# ---------------------------------------------------------------------------


AuditEntry = dict[str, Any]
"""A single JSONL audit record as a plain Python dict."""


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Synchronous, fail-closed JSONL audit logger.

    Parameters
    ----------
    output_path:
        Path to the JSONL file to write.  Parent directories are created on
        first write if they do not exist.  Defaults to
        ``./analysis/audit.jsonl``.

    Attributes
    ----------
    output_path:
        Resolved absolute path of the audit file.

    Thread safety
    -------------
    A reentrant lock guards all writes so that the logger is safe to call
    from multiple threads within a single process (e.g. if async tool
    handlers are being scheduled concurrently on a thread pool).
    """

    def __init__(self, output_path: str = "./analysis/audit.jsonl") -> None:
        self.output_path = Path(output_path).resolve()
        self._lock = threading.RLock()
        self._execution_counter: int = 0
        self._current_iteration: int = 1

        # Initialise counter from existing file so IDs remain monotonic
        # across server restarts.
        self._sync_counter_from_file()

    # ------------------------------------------------------------------
    # Public counter helpers
    # ------------------------------------------------------------------

    @property
    def current_iteration(self) -> int:
        """The current investigation iteration number (1-based)."""
        return self._current_iteration

    @current_iteration.setter
    def current_iteration(self, value: int) -> None:
        if value < 1:
            raise ValueError("iteration must be >= 1")
        self._current_iteration = value

    def next_execution_id(self) -> str:
        """Allocate and return the next monotonic execution ID.

        Returns
        -------
        str
            An ID of the form ``E-001``, ``E-002``, … (zero-padded to at
            least 3 digits).  IDs are allocated atomically under the
            internal lock and never reused.
        """
        with self._lock:
            self._execution_counter += 1
            return f"E-{self._execution_counter:03d}"

    # ------------------------------------------------------------------
    # Core log methods
    # ------------------------------------------------------------------

    def log_execution(
        self,
        execution_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        command_line: str,
        agent_turn: int = 0,
    ) -> None:
        """Write a ``started`` entry to ``audit.jsonl``.

        This is called **before** the subprocess is launched.  If this write
        fails the exception propagates and the subprocess is never started
        (fail-closed).

        Parameters
        ----------
        execution_id:
            The E-NNN execution identifier, obtained from
            :py:meth:`next_execution_id`.
        tool_name:
            The logical MCP tool name (e.g. ``"memory.list_processes"``).
        parameters:
            High-level MCP parameters dict (not the raw command arguments).
        command_line:
            The fully assembled command string that will be executed.
        agent_turn:
            The Claude agent turn counter at time of invocation.
        """
        entry: AuditEntry = {
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "event_type": "started",
            "tool": tool_name,
            "parameters": parameters,
            "command_line": command_line,
            "agent_turn": agent_turn,
            "iteration": self._current_iteration,
            # Fields populated in the "completed" entry:
            "exit_code": None,
            "duration_seconds": None,
            "outputs_summary": None,
            "finding_ids_generated": [],
            "correction_event": None,
        }
        self._write_entry(entry)

    def log_result(
        self,
        execution_id: str,
        exit_code: int,
        duration: float,
        outputs_summary: str,
        finding_ids: list[str],
        correction_event: Optional[dict[str, Any]] = None,
    ) -> None:
        """Write a ``completed`` entry to ``audit.jsonl``.

        This is called **after** the subprocess returns (or times out).

        Parameters
        ----------
        execution_id:
            The E-NNN identifier matching the preceding ``started`` entry.
        exit_code:
            Process exit code (``-1`` for timeout).
        duration:
            Wall-clock duration in seconds.
        outputs_summary:
            Short human-readable summary of tool output (max ~500 chars).
        finding_ids:
            List of F-NNN finding IDs generated as a result of this execution.
        correction_event:
            If this execution produced a self-correction, a dict describing
            the correction (``prior_claim``, ``contradiction_source``,
            ``revised_claim``, ``confidence_delta``).  ``None`` otherwise.
        """
        entry: AuditEntry = {
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "event_type": "completed",
            "tool": None,  # Already recorded in the started entry
            "parameters": None,
            "command_line": None,
            "agent_turn": None,
            "iteration": self._current_iteration,
            "exit_code": exit_code,
            "duration_seconds": round(duration, 4),
            "outputs_summary": outputs_summary,
            "finding_ids_generated": finding_ids,
            "correction_event": correction_event,
        }
        self._write_entry(entry)

    def log_timeout(self, execution_id: str, timeout_seconds: int) -> None:
        """Write a ``completed`` entry marking an execution timeout.

        Convenience wrapper around :py:meth:`log_result` specifically for the
        timeout path in ``SafeRunner.run``.

        Parameters
        ----------
        execution_id:
            The E-NNN identifier of the timed-out execution.
        timeout_seconds:
            The timeout budget (in seconds) that was exceeded.
        """
        self.log_result(
            execution_id=execution_id,
            exit_code=-1,
            duration=float(timeout_seconds),
            outputs_summary=f"TIMED OUT after {timeout_seconds}s",
            finding_ids=[],
            correction_event=None,
        )

    # ------------------------------------------------------------------
    # Query / read methods
    # ------------------------------------------------------------------

    def get_execution_chain(self, finding_id: str) -> list[AuditEntry]:
        """Return all audit entries whose ``finding_ids_generated`` contains *finding_id*.

        This lets callers trace a specific finding back to the exact tool
        invocation and command line that produced it.

        Parameters
        ----------
        finding_id:
            A finding ID such as ``"F-003"``.

        Returns
        -------
        list[AuditEntry]
            All matching entries from ``audit.jsonl`` in file order.  Each
            entry is a plain dict.

        Raises
        ------
        FileNotFoundError
            If ``audit.jsonl`` does not yet exist.
        json.JSONDecodeError
            If a line in the file is not valid JSON (indicates file
            corruption).
        """
        if not self.output_path.exists():
            raise FileNotFoundError(
                f"Audit log not found: {self.output_path}. "
                "Has any tool been executed yet?"
            )

        chain: list[AuditEntry] = []
        with self._lock:
            with self.output_path.open("r", encoding="utf-8") as fh:
                for lineno, raw_line in enumerate(fh, start=1):
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        entry: AuditEntry = json.loads(raw_line)
                    except json.JSONDecodeError as exc:
                        raise json.JSONDecodeError(
                            f"Corrupt JSON on line {lineno} of {self.output_path}",
                            exc.doc,
                            exc.pos,
                        ) from exc

                    generated: list[str] = entry.get("finding_ids_generated") or []
                    if finding_id in generated:
                        chain.append(entry)

        return chain

    def read_all(self) -> list[AuditEntry]:
        """Return every entry in ``audit.jsonl`` as a list of dicts.

        Returns
        -------
        list[AuditEntry]
            All entries in file order.  Returns an empty list if the file
            does not yet exist.
        """
        if not self.output_path.exists():
            return []

        entries: list[AuditEntry] = []
        with self._lock:
            with self.output_path.open("r", encoding="utf-8") as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if raw_line:
                        entries.append(json.loads(raw_line))
        return entries

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_entry(self, entry: AuditEntry) -> None:
        """Serialise *entry* to a JSONL line and flush to disk.

        This is the single write bottleneck.  The internal lock serialises
        concurrent writers.  Any I/O error propagates to the caller
        (fail-closed).

        Parameters
        ----------
        entry:
            The audit record dict to serialise.

        Raises
        ------
        OSError
            If the file cannot be opened or written (e.g. disk full).
        """
        with self._lock:
            # Ensure parent directory exists on first write.
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

            line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"

            # Open in append mode so we never truncate existing entries.
            with self.output_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                # Force kernel buffer to disk so a crash cannot lose the entry.
                import os as _os
                _os.fsync(fh.fileno())

    def _sync_counter_from_file(self) -> None:
        """Initialise ``_execution_counter`` from any pre-existing audit file.

        Scans every entry for the highest E-NNN numeric suffix and sets the
        internal counter to that value so the next call to
        :py:meth:`next_execution_id` produces a strictly higher ID.

        This is called once at construction.  If the file does not exist or
        is empty the counter stays at 0.
        """
        if not self.output_path.exists():
            return

        max_id = 0
        try:
            with self.output_path.open("r", encoding="utf-8") as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        entry: AuditEntry = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue  # Skip corrupt lines during recovery

                    eid: str = entry.get("execution_id", "")
                    if eid.startswith("E-"):
                        try:
                            numeric = int(eid[2:])
                            if numeric > max_id:
                                max_id = numeric
                        except ValueError:
                            pass
        except OSError:
            pass  # Best-effort; counter stays at 0

        self._execution_counter = max_id


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with 'Z' suffix.

    Example: ``"2026-05-01T14:23:11.442Z"``
    """
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(tz=timezone.utc).microsecond // 1000:03d}Z"
