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

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["AuditLogger", "AuditEntry"]


_SCHEMA_VERSION = 2


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
        self._last_entry_hash: Optional[str] = None

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
    ) -> AuditEntry:
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
        return self._write_entry(entry)

    def log_result(
        self,
        execution_id: str,
        exit_code: int,
        duration: float,
        outputs_summary: str,
        finding_ids: list[str],
        correction_event: Optional[dict[str, Any]] = None,
        tool_name: Optional[str] = None,
        command_line: Optional[str] = None,
        parameters: Optional[dict[str, Any]] = None,
        agent_turn: Optional[int] = None,
    ) -> AuditEntry:
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
        tool_name:
            Logical MCP tool name written redundantly onto the completed entry.
        command_line:
            Reconstructed subprocess command line for this execution.
        parameters:
            Structured high-level parameters associated with this execution.
        agent_turn:
            Claude agent turn number associated with this execution.
        """
        entry: AuditEntry = {
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "event_type": "completed",
            "tool": tool_name,
            "parameters": parameters,
            "command_line": command_line,
            "agent_turn": agent_turn,
            "iteration": self._current_iteration,
            "exit_code": exit_code,
            "duration_seconds": round(duration, 4),
            "outputs_summary": outputs_summary,
            "finding_ids_generated": finding_ids,
            "correction_event": correction_event,
        }
        return self._write_entry(entry)

    def log_link(
        self,
        execution_id: str,
        tool_name: str,
        finding_ids: list[str],
        artifact_refs: list[str],
        artifact_hashes: list[dict[str, Any]],
        raw_evidence_refs: list[dict[str, Any]],
    ) -> AuditEntry:
        """Write a post-execution ``linked`` entry once findings are known."""
        entry: AuditEntry = {
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "event_type": "linked",
            "tool": tool_name,
            "iteration": self._current_iteration,
            "finding_ids_generated": finding_ids,
            "artifact_refs": artifact_refs,
            "artifact_hashes": artifact_hashes,
            "raw_evidence_refs": raw_evidence_refs,
        }
        return self._write_entry(entry)

    def log_correction(
        self,
        *,
        execution_id: str,
        tool_name: str,
        correction_type: str,
        original_finding_id: str,
        original_claim: str,
        original_confidence: str,
        contradiction_summary: str,
        revised_confidence: str,
        contradiction_source_finding_id: Optional[str] = None,
        contradiction_source_execution_id: Optional[str] = None,
        revised_claim: Optional[str] = None,
        revised_finding_id: Optional[str] = None,
        correction_id: Optional[str] = None,
    ) -> AuditEntry:
        """Write a ``correction`` audit entry for self-correction events.

        Hackathon FIND EVIL! 2026-05-23: this is the tiebreaker criterion #1
        wiring (Autonomous Execution Quality). When a finding is corrected
        based on contradicting evidence, this method writes a structured
        record to ``audit.jsonl`` that the investigation_graph renderer
        (scripts/investigation_graph.py:558) reads to create CORR-NNN nodes.

        The CorrectionEvent payload conforms to ``sift_mcp.models.evidence_finding.CorrectionEvent``.
        Validation of the payload should occur at the call site (typically
        in correlation.py or gate handlers).

        Parameters
        ----------
        execution_id:
            The execution_id of the tool/correlation that detected the
            contradiction (e.g., compare_disk_and_memory's E-NNN).
        tool_name:
            The tool that detected the contradiction.
        correction_type:
            One of: 'evidence_contradiction', 'provenance_demotion',
            'alternative_hypothesis_unresolved', 'operator_override'.
        original_finding_id:
            The finding ID (legacy F-NNN or ULID) being revised.
        original_claim / original_confidence:
            The prior claim and confidence being corrected.
        contradiction_summary:
            One-line description of what contradicts the original claim.
        revised_confidence:
            New confidence level (HIGH / MEDIUM / LOW / NULL).
        contradiction_source_finding_id (optional):
            Finding ID whose evidence contradicts the original.
        contradiction_source_execution_id (optional):
            Execution ID of the gate/correlator that detected the contradiction.
            At least one of source_finding_id or source_execution_id must be set.
        revised_claim (optional):
            Updated claim text if the finding is being revised (not just demoted).
        revised_finding_id (optional):
            ULID of a new finding that supersedes the original.
        correction_id (optional):
            Pre-generated ULID for this correction event. If None, the audit
            layer leaves it None — generation is the caller's job (or the
            CorrectionEvent model's default).

        Returns
        -------
        AuditEntry
            The dictionary that was appended to audit.jsonl.
        """
        # The correction_event payload — graph renderer expects these field names
        # (scripts/investigation_graph.py:565-607 reads `affected_finding_ids`).
        affected = [original_finding_id]
        revised_ids = [revised_finding_id] if revised_finding_id else []
        correction_payload: dict[str, Any] = {
            "correction_id": correction_id,
            "correction_type": correction_type,
            "original_finding_id": original_finding_id,
            "original_claim": original_claim,
            "original_confidence": original_confidence,
            "contradiction_source_finding_id": contradiction_source_finding_id,
            "contradiction_source_execution_id": contradiction_source_execution_id,
            "contradiction_summary": contradiction_summary,
            "revised_claim": revised_claim,
            "revised_confidence": revised_confidence,
            "revised_finding_id": revised_finding_id,
            # Graph renderer compatibility fields
            "affected_finding_ids": affected,
        }

        entry: AuditEntry = {
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "event_type": "correction",
            "tool": tool_name,
            "iteration": self._current_iteration,
            "correction_event": correction_payload,
            # Mirror onto finding_ids_generated so existing graph code picks up revised IDs
            "finding_ids_generated": revised_ids,
        }
        return self._write_entry(entry)

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
            tool_name=None,
            command_line=None,
            parameters=None,
            agent_turn=None,
        )

    # ------------------------------------------------------------------
    # W1.7 — CTX (context bundle) audit primitive
    # ------------------------------------------------------------------

    _ctx_counter: int = 0

    def next_context_id(self) -> str:
        """Generate the next CTX-NNN identifier (zero-padded to 3 digits).

        Counter persists for the lifetime of the AuditLogger instance.
        Used by log_context_bundle and the heuristic injection layer
        to produce stable, citeable provenance handles.
        """
        self._ctx_counter += 1
        return f"CTX-{self._ctx_counter:03d}"

    def log_context_bundle(
        self,
        *,
        case_id: str,
        artifact: str,
        heuristic_source_path: str,
        heuristic_source_hash: str,
        heuristic_section: str,
        heuristic_excerpt_hash: str,
        excerpt_token_count: int,
        triggered_by: str,
        execution_id: Optional[str] = None,
        context_id: Optional[str] = None,
    ) -> AuditEntry:
        """Write a ``context_bundle`` audit row recording that a heuristic
        slice from a canonical .md file was delivered to the LLM.

        W1.7 (PLAN-FIND-EVIL-HACKATHON-2026-05-23.md + tri-agent CR13 sign-off):
        every Tier-1 / Tier-2 / Tier-3 heuristic injection writes one of these
        rows. Findings can then cite ``heuristic_context_refs: ["CTX-003"]``,
        forming a court-defensible chain: finding → execution_id → CTX-NNN
        → canonical .md path + SHA256.

        Parameters
        ----------
        case_id:
            Active investigation case ID.
        artifact:
            Artifact name the heuristic applies to ('mft', 'evtx', etc.).
        heuristic_source_path:
            Repository-relative path to the canonical .md file (e.g.,
            ``.claude/agents/mft-analyst.md``).
        heuristic_source_hash:
            ``sha256:<hex>`` of the FULL source .md file content.
        heuristic_section:
            The section header(s) included in this excerpt
            (e.g., ``"Forensic Ground Rules + What to Hunt"``).
        heuristic_excerpt_hash:
            ``sha256:<hex>`` of the assembled excerpt actually delivered.
        excerpt_token_count:
            Approximate token count of the excerpt.
        triggered_by:
            Which tool / call path triggered the bundle. One of:
            ``'extract_<artifact>'``, ``'prepare_hypothesis_context'``,
            ``'get_heuristic'``.
        execution_id:
            Optional E-NNN linking this bundle to the triggering tool execution.
        context_id:
            Optional pre-generated CTX-NNN. If None, one is generated.

        Returns
        -------
        AuditEntry
            The appended audit row (includes ``context_id`` field).
        """
        if not context_id:
            context_id = self.next_context_id()

        entry: AuditEntry = {
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id or context_id,
            "event_type": "context_bundle",
            "tool": "context.log_context_bundle",
            "iteration": self._current_iteration,
            "context_id": context_id,
            "case_id": case_id,
            "artifact": artifact,
            "heuristic_source_path": heuristic_source_path,
            "heuristic_source_hash": heuristic_source_hash,
            "heuristic_section": heuristic_section,
            "heuristic_excerpt_hash": heuristic_excerpt_hash,
            "excerpt_token_count": excerpt_token_count,
            "triggered_by": triggered_by,
        }
        return self._write_entry(entry)

    # ------------------------------------------------------------------
    # Query / read methods
    # ------------------------------------------------------------------

    def get_execution_chain(self, finding_id: str) -> list[AuditEntry]:
        """Return the full audit chain for the execution(s) that produced *finding_id*.

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

        entries: list[AuditEntry] = []
        matching_execution_ids: set[str] = set()
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

                    entries.append(entry)
                    generated: list[str] = entry.get("finding_ids_generated") or []
                    if finding_id in generated:
                        execution_id = entry.get("execution_id")
                        if execution_id:
                            matching_execution_ids.add(str(execution_id))

        return [
            entry
            for entry in entries
            if entry.get("execution_id") in matching_execution_ids
        ]

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

    def _write_entry(self, entry: AuditEntry) -> AuditEntry:
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

            sealed = self._seal_entry(entry)
            line = json.dumps(sealed, ensure_ascii=False, default=str) + "\n"

            # Open in append mode so we never truncate existing entries.
            with self.output_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                # Force kernel buffer to disk so a crash cannot lose the entry.
                import os as _os
                _os.fsync(fh.fileno())
            self._last_entry_hash = sealed["entry_hash"]
            return sealed

    def _seal_entry(self, entry: AuditEntry) -> AuditEntry:
        """Attach forward-only hash-chain metadata to a newly written entry."""
        sealed = dict(entry)
        sealed["schema_version"] = _SCHEMA_VERSION
        sealed["prev_entry_hash"] = self._last_entry_hash
        sealed["entry_hash"] = self._compute_entry_hash(sealed)
        return sealed

    def _compute_entry_hash(self, entry: AuditEntry) -> str:
        """Return the canonical SHA-256 hash for an audit entry."""
        payload = {key: value for key, value in entry.items() if key != "entry_hash"}
        canonical = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

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
        last_entry_hash: Optional[str] = None
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
                    if entry.get("entry_hash"):
                        last_entry_hash = str(entry["entry_hash"])
                    else:
                        last_entry_hash = None
        except OSError:
            pass  # Best-effort; counter stays at 0

        self._execution_counter = max_id
        self._last_entry_hash = last_entry_hash


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with 'Z' suffix.

    Example: ``"2026-05-01T14:23:11.442Z"``
    """
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(tz=timezone.utc).microsecond // 1000:03d}Z"
