"""Authoritative case state manager for SAVVYDFIR-MCP.

``CaseStateManager`` is the single source of truth for an investigation.  It
owns:

* **Findings** — forensic observations, inferences, and hypotheses with full
  provenance chains.
* **Executions** — lightweight metadata records for every tool invocation
  (the full JSONL audit trail lives in :mod:`sift_mcp.audit`).

The state is persisted as a JSON file at ``./analysis/state.json`` and
updated atomically (write-to-tmp, rename) to prevent partial writes.

ID allocation
-------------
Both finding IDs (``F-NNN``) and execution IDs (``E-NNN``) are allocated by
this class.  The counters are stored in the state file so they survive server
restarts and remain globally monotonic within a case.  ``AuditLogger`` calls
:py:meth:`next_execution_id` so that IDs in ``audit.jsonl`` match those in
``state.json``.

Usage pattern
-------------
::

    mgr = CaseStateManager()
    state = mgr.load("SRL-2018")

    finding_id = mgr.generate_finding_id()
    mgr.add_finding({
        "finding_id": finding_id,
        "artifact_type": "process",
        "evidence_kind": "MEMORY_ARTIFACT",
        "description": "...",
        "confidence": 0.9,
        "status": "CONFIRMED",
        ...
    })

    summary = mgr.to_summary()
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["CaseStateManager", "CaseStateError"]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CaseStateError(RuntimeError):
    """Raised when the case state cannot be loaded, saved, or mutated."""


# ---------------------------------------------------------------------------
# CaseStateManager
# ---------------------------------------------------------------------------


class CaseStateManager:
    """Manages the authoritative JSON state file for a DFIR case.

    Parameters
    ----------
    state_path:
        Path to the state JSON file.  Defaults to
        ``"./analysis/state.json"``.  Parent directories are created when
        the state is first saved.

    Thread safety
    -------------
    A reentrant lock serialises all reads and writes within a single process.
    Cross-process access is not supported; only one MCP server instance
    should own a given case directory.
    """

    def __init__(self, state_path: str = "./analysis/state.json") -> None:
        self._state_path = Path(state_path).resolve()
        self._lock = threading.RLock()
        self._state: dict[str, Any] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Load / save
    # ------------------------------------------------------------------

    def load(self, case_id: str) -> dict[str, Any]:
        """Load state for *case_id* from disk, or create a fresh state.

        If ``state.json`` already exists it is read and returned.  If it does
        not exist, a new empty state structure is initialised and **saved to
        disk immediately** so subsequent calls always find the file.

        Parameters
        ----------
        case_id:
            Forensic case identifier (e.g. ``"SRL-2018"``).  Used to
            validate the file if it already exists and to populate the
            ``case_id`` field of a new state.

        Returns
        -------
        dict[str, Any]
            The full state dict.

        Raises
        ------
        CaseStateError
            If the on-disk file contains invalid JSON or a mismatching
            ``case_id``.
        """
        with self._lock:
            if self._state_path.exists():
                try:
                    raw = self._state_path.read_text(encoding="utf-8")
                    loaded: dict[str, Any] = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise CaseStateError(
                        f"state.json at {self._state_path} is not valid JSON: {exc}"
                    ) from exc

                if loaded.get("case_id") != case_id:
                    raise CaseStateError(
                        f"state.json contains case_id={loaded.get('case_id')!r} "
                        f"but load() was called with case_id={case_id!r}. "
                        "Use a separate state file per case."
                    )

                self._state = loaded
            else:
                # Create a new, empty state.
                self._state = _new_state(case_id)
                self._save_locked()

            self._loaded = True
            return dict(self._state)  # Return a shallow copy

    def save(self) -> None:
        """Atomically persist the current in-memory state to disk.

        The state is serialised to a temporary file (``state.json.tmp``) in
        the same directory and then renamed over the target file.  On POSIX
        systems ``os.replace`` is atomic at the filesystem level.

        Raises
        ------
        CaseStateError
            If the state has not yet been loaded via :py:meth:`load`.
        OSError
            If the file system write or rename fails.
        """
        with self._lock:
            if not self._loaded:
                raise CaseStateError(
                    "Cannot save: state has not been loaded. Call load() first."
                )
            self._save_locked()

    # ------------------------------------------------------------------
    # Finding mutators
    # ------------------------------------------------------------------

    def add_finding(self, finding: dict[str, Any]) -> str:
        """Append *finding* to the findings list and persist.

        If *finding* does not already contain a ``"finding_id"`` key, one is
        allocated via :py:meth:`generate_finding_id`.  A
        ``"created_at"`` timestamp is injected if absent.

        Parameters
        ----------
        finding:
            A dict representing the finding.  Recommended keys match the
            ``Finding`` Pydantic model in ``sift_mcp/models/finding.py``.

        Returns
        -------
        str
            The ``finding_id`` (F-NNN) of the stored finding.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            if "finding_id" not in finding:
                finding = dict(finding)
                finding["finding_id"] = self.generate_finding_id()
            finding.setdefault("created_at", _utcnow_iso())
            self._state["findings"].append(finding)
            # Bump findings_count
            self._state["findings_count"] = len(self._state["findings"])
            self._save_locked()
            return finding["finding_id"]

    def update_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any]:
        """Update one or more fields of an existing finding and persist.

        Parameters
        ----------
        finding_id:
            The F-NNN identifier of the finding to update.
        **kwargs:
            Field name → new value pairs.  The ``finding_id`` itself cannot
            be changed; any ``finding_id`` kwarg is silently ignored.

        Returns
        -------
        dict[str, Any]
            The updated finding dict.

        Raises
        ------
        KeyError
            If no finding with *finding_id* exists.
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            kwargs.pop("finding_id", None)  # Protect the primary key

            for finding in self._state["findings"]:
                if finding.get("finding_id") == finding_id:
                    finding.update(kwargs)
                    finding["updated_at"] = _utcnow_iso()
                    self._save_locked()
                    return dict(finding)

            raise KeyError(
                f"Finding {finding_id!r} not found in case "
                f"{self._state.get('case_id')!r}."
            )

    # ------------------------------------------------------------------
    # Execution mutators
    # ------------------------------------------------------------------

    def add_execution(self, execution: dict[str, Any]) -> str:
        """Append *execution* to the executions list and persist.

        Parameters
        ----------
        execution:
            A dict representing the execution record.  At minimum should
            contain ``"execution_id"``, ``"tool_name"``, and
            ``"command_line"``.

        Returns
        -------
        str
            The ``execution_id`` (E-NNN) of the stored execution.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            execution = dict(execution)
            execution.setdefault("recorded_at", _utcnow_iso())
            self._state["executions"].append(execution)
            self._state["executions_count"] = len(self._state["executions"])
            self._save_locked()
            return execution.get("execution_id", "")

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_findings(
        self,
        artifact_type: Optional[str] = None,
        evidence_kind: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return a filtered list of findings.

        All filters are ANDed together.  Omitting a filter means "any value".

        Parameters
        ----------
        artifact_type:
            Filter by ``finding["artifact_type"]`` (case-insensitive).
            Example: ``"process"``, ``"prefetch"``, ``"registry_key"``.
        evidence_kind:
            Filter by ``finding["evidence_kind"]`` (case-insensitive).
            Example: ``"MEMORY_ARTIFACT"``, ``"DISK_ARTIFACT"``.
        status:
            Filter by ``finding["status"]`` (case-insensitive).
            Example: ``"CONFIRMED"``, ``"HYPOTHESIS"``, ``"REJECTED"``.

        Returns
        -------
        list[dict[str, Any]]
            Matching findings as shallow copies, in insertion order.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            results = []
            for f in self._state["findings"]:
                if artifact_type is not None:
                    if (f.get("artifact_type") or "").lower() != artifact_type.lower():
                        continue
                if evidence_kind is not None:
                    if (f.get("evidence_kind") or "").lower() != evidence_kind.lower():
                        continue
                if status is not None:
                    if (f.get("status") or "").lower() != status.lower():
                        continue
                results.append(dict(f))
            return results

    def get_finding(self, finding_id: str) -> Optional[dict[str, Any]]:
        """Return a single finding by ID, or ``None`` if not found.

        Parameters
        ----------
        finding_id:
            The F-NNN identifier.

        Returns
        -------
        dict[str, Any] or None
            A shallow copy of the finding dict, or ``None``.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            for f in self._state["findings"]:
                if f.get("finding_id") == finding_id:
                    return dict(f)
            return None

    def get_unresolved_discrepancies(self) -> list[dict[str, Any]]:
        """Return findings with unresolved contradictions.

        A finding is "unresolved" when its ``contradicted_by`` list is
        non-empty **and** its ``status`` is not ``"REJECTED"``.  These
        findings represent open investigative threads that the agent must
        resolve before it can complete the case.

        Returns
        -------
        list[dict[str, Any]]
            Shallow copies of matching findings in insertion order.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            results = []
            for f in self._state["findings"]:
                contradicted_by: list = f.get("contradicted_by") or []
                status: str = (f.get("status") or "").upper()
                if contradicted_by and status != "REJECTED":
                    results.append(dict(f))
            return results

    # ------------------------------------------------------------------
    # ID generators
    # ------------------------------------------------------------------

    def generate_finding_id(self) -> str:
        """Allocate and return the next monotonic finding ID.

        Returns
        -------
        str
            An ID of the form ``F-001``, ``F-002``, … (zero-padded to at
            least 3 digits).  Atomically increments the persistent counter.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            self._state["_finding_counter"] = (
                self._state.get("_finding_counter", 0) + 1
            )
            return f"F-{self._state['_finding_counter']:03d}"

    def generate_execution_id(self) -> str:
        """Allocate and return the next monotonic execution ID.

        These IDs match the ``execution_id`` fields in ``audit.jsonl``.
        The counter is persisted in ``state.json`` so IDs are globally
        monotonic even across server restarts.

        Returns
        -------
        str
            An ID of the form ``E-001``, ``E-002``, … (zero-padded to at
            least 3 digits).

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            self._state["_execution_counter"] = (
                self._state.get("_execution_counter", 0) + 1
            )
            return f"E-{self._state['_execution_counter']:03d}"

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def to_summary(self) -> dict[str, Any]:
        """Return a compact summary dict suitable for MCP tool responses.

        The summary contains counts, the investigation status, any open
        questions, and the ten most recently added findings.

        Returns
        -------
        dict[str, Any]
            A summary dictionary.  Keys:

            ``case_id``
                Case identifier.
            ``status``
                Investigation status string (e.g. ``"IN_PROGRESS"``).
            ``findings_count``
                Total number of findings.
            ``executions_count``
                Total number of recorded executions.
            ``confirmed_count``
                Findings with status ``"CONFIRMED"``.
            ``hypothesis_count``
                Findings with status ``"HYPOTHESIS"``.
            ``rejected_count``
                Findings with status ``"REJECTED"``.
            ``unresolved_discrepancies``
                Count of findings with unresolved contradictions.
            ``open_questions``
                List of open-question strings from the state.
            ``latest_findings``
                Up to 10 most recent findings (shallow copies).
            ``created_at``
                ISO 8601 timestamp of case creation.
            ``updated_at``
                ISO 8601 timestamp of last state save.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()

            findings: list[dict] = self._state.get("findings", [])
            status_counts: dict[str, int] = {}
            for f in findings:
                s = (f.get("status") or "UNKNOWN").upper()
                status_counts[s] = status_counts.get(s, 0) + 1

            unresolved = sum(
                1
                for f in findings
                if (f.get("contradicted_by") or [])
                and (f.get("status") or "").upper() != "REJECTED"
            )

            return {
                "case_id": self._state.get("case_id"),
                "status": self._state.get("status", "IN_PROGRESS"),
                "findings_count": len(findings),
                "executions_count": len(self._state.get("executions", [])),
                "confirmed_count": status_counts.get("CONFIRMED", 0),
                "hypothesis_count": status_counts.get("HYPOTHESIS", 0),
                "rejected_count": status_counts.get("REJECTED", 0),
                "unresolved_discrepancies": unresolved,
                "open_questions": list(self._state.get("open_questions", [])),
                "latest_findings": [
                    dict(f) for f in findings[-10:]
                ],
                "created_at": self._state.get("created_at"),
                "updated_at": self._state.get("updated_at"),
            }

    # ------------------------------------------------------------------
    # Additional state helpers
    # ------------------------------------------------------------------

    def set_status(self, status: str) -> None:
        """Set the top-level investigation ``status`` field and persist.

        Parameters
        ----------
        status:
            One of ``"IN_PROGRESS"``, ``"COMPLETE"``, ``"FAILED"``, etc.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            self._state["status"] = status
            self._save_locked()

    def add_open_question(self, question: str) -> None:
        """Append an open question / limitation to the state and persist.

        Open questions are surfaced in the final report when the agent
        cannot resolve a discrepancy before ``max_iterations`` is reached.

        Parameters
        ----------
        question:
            A short description of the unresolved issue.

        Raises
        ------
        CaseStateError
            If the state has not been loaded.
        """
        with self._lock:
            self._assert_loaded()
            self._state.setdefault("open_questions", [])
            self._state["open_questions"].append(question)
            self._save_locked()

    def get_state_path(self) -> Path:
        """Return the resolved path of the state file.

        Returns
        -------
        Path
            Absolute path to ``state.json``.
        """
        return self._state_path

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _assert_loaded(self) -> None:
        """Raise ``CaseStateError`` if :py:meth:`load` has not been called."""
        if not self._loaded:
            raise CaseStateError(
                "CaseStateManager has not been initialised. Call load(case_id) first."
            )

    def _save_locked(self) -> None:
        """Write state to disk atomically.  Caller must hold ``_lock``."""
        self._state["updated_at"] = _utcnow_iso()

        target = self._state_path
        tmp = target.with_suffix(".json.tmp")

        target.parent.mkdir(parents=True, exist_ok=True)
        serialised = json.dumps(self._state, ensure_ascii=False, indent=2, default=str) + "\n"

        try:
            tmp.write_text(serialised, encoding="utf-8")
            os.replace(str(tmp), str(target))
        except OSError as exc:
            raise CaseStateError(
                f"Failed to save state to {target}: {exc}"
            ) from exc
        finally:
            # Remove tmp file if rename failed.
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with 'Z' suffix."""
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _new_state(case_id: str) -> dict[str, Any]:
    """Return a fresh state dict for a new case.

    Parameters
    ----------
    case_id:
        The forensic case identifier.

    Returns
    -------
    dict[str, Any]
        A minimal valid state structure.
    """
    now = _utcnow_iso()
    return {
        "case_id": case_id,
        "status": "IN_PROGRESS",
        "created_at": now,
        "updated_at": now,
        # ID counters — persisted so they survive server restarts.
        "_finding_counter": 0,
        "_execution_counter": 0,
        # Collections
        "findings": [],
        "executions": [],
        "open_questions": [],
        # Derived counts (denormalised for quick summary)
        "findings_count": 0,
        "executions_count": 0,
    }
