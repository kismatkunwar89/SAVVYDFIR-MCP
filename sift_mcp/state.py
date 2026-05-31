"""Authoritative case state manager for SAVVYDFIR-MCP.

``CaseStateManager`` is the single source of truth for an investigation.  It
owns:

* **Findings** - forensic observations, inferences, and hypotheses with full
  provenance chains.
* **Executions** - lightweight metadata records for every tool invocation
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
        "finding_status": "CONFIRMED",
        ...
    })

    summary = mgr.to_summary()
"""

from __future__ import annotations

import copy
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from sift_mcp.models.execution import Execution
from sift_mcp.semantics import (
    compute_content_key,
    validate_and_prepare_finding,
)

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
                self._migrate_loaded_state_locked()
            else:
                # Create a new, empty state.
                self._state = _new_state(case_id)
                self._save_locked()

            self._loaded = True
            # MCP segfault fix 2026-05-23: deep-copy under the lock so the
            # serializer never walks live nested structures. Shallow
            # dict(self._state) leaked findings/executions/analysis_lanes
            # by reference, which segfaulted Python 3.10's _json.so when
            # another thread mutated them mid-serialization.
            return copy.deepcopy(self._state)

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

        New persisted finding IDs are always allocated by this manager after
        semantic de-duplication. Incoming IDs are treated as transient model or
        import values and are not trusted for new records.

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
            original = dict(finding)
            created_at = _utcnow_iso()
            original.setdefault("created_at", created_at)
            original.setdefault("updated_at", original["created_at"])

            # Resolve a real execution_id BEFORE validation so the
            # provenance gate (A1) sees a resolvable ID and does not
            # pre-emptively demote CONFIRMED findings.
            resolved_eid: Optional[str] = None
            resolved_source: Optional[str] = None
            incoming_eid = str(original.get("execution_id") or "").strip()
            if incoming_eid and incoming_eid != "E-000":
                resolved_eid = incoming_eid
                resolved_source = "operator_supplied"
            else:
                tool_name = str(original.get("tool_name") or "").strip().lower()
                executions = self._state.get("executions") or []
                if tool_name:
                    for execution in reversed(executions):
                        if not isinstance(execution, dict):
                            continue
                        if str(execution.get("tool_name") or "").strip().lower() == tool_name:
                            candidate = str(execution.get("execution_id") or "").strip()
                            if candidate:
                                resolved_eid = candidate
                                resolved_source = "auto_linked_same_tool_execution"
                                break
                if not resolved_eid:
                    for execution in reversed(executions):
                        if not isinstance(execution, dict):
                            continue
                        candidate = str(execution.get("execution_id") or "").strip()
                        if candidate:
                            resolved_eid = candidate
                            resolved_source = "auto_linked_latest_tool_execution"
                            break
                if not resolved_eid:
                    resolved_eid = self.generate_execution_id()
                    resolved_source = "state_autogenerated"
                original["execution_id"] = resolved_eid
                support_inputs = dict(original.get("confidence_support_inputs") or {})
                support_inputs.setdefault("execution_id_source", resolved_source)
                original["confidence_support_inputs"] = support_inputs

            finding = validate_and_prepare_finding(
                original,
                fallback_case_id=self._state.get("case_id"),
                fallback_execution_id=resolved_eid,
                fallback_iteration=original.get("iteration") or 1,
                state_manager=self,
            )

            dirty_existing = False
            for existing in self._state["findings"]:
                if not isinstance(existing, dict):
                    continue
                existing_key = existing.get("content_key")
                if not existing_key:
                    existing_key = compute_content_key(existing)
                    existing["content_key"] = existing_key
                    dirty_existing = True
                if existing_key == finding["content_key"]:
                    if dirty_existing:
                        self._save_locked()
                    return str(existing.get("finding_id", ""))

            legacy_finding_id = str(finding.get("finding_id") or "").strip()
            if legacy_finding_id and legacy_finding_id != "F-000":
                support_inputs = dict(finding.get("confidence_support_inputs") or {})
                support_inputs.setdefault("incoming_finding_id", legacy_finding_id)
                finding["confidence_support_inputs"] = support_inputs
            finding["finding_id"] = self.generate_finding_id()

            self._state["findings"].append(finding)
            self._state["findings_count"] = len(self._state["findings"])
            # W1.7 (CR-revised plan 2026-05-23): activity-thread classification
            # MUST run in CaseStateManager.add_finding (not only server.add_finding /
            # submit_finding) - most extraction-tool findings go through state
            # directly. Normalizes both mitre_techniques (list) and
            # mitre_technique (singular legacy).
            try:
                techniques = self._extract_mitre_techniques(finding)
                if techniques:
                    self._classify_finding_into_activity_thread_locked(
                        str(finding["finding_id"]),
                        techniques,
                    )
            except Exception:
                pass  # classification is enhancement, never block add_finding
            self._save_locked()
            return str(finding["finding_id"])

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

            for index, finding in enumerate(self._state["findings"]):
                if finding.get("finding_id") == finding_id:
                    updated = dict(finding)
                    updated.update(kwargs)
                    updated["updated_at"] = _utcnow_iso()
                    updated = validate_and_prepare_finding(
                        updated,
                        fallback_case_id=updated.get("case_id") or self._state.get("case_id"),
                        fallback_execution_id=updated.get("execution_id") or "E-000",
                        fallback_iteration=updated.get("iteration") or 1,
                        state_manager=self,
                    )
                    updated["finding_id"] = finding_id
                    self._state["findings"][index] = updated
                    # W1.7 (CR-revised 2026-05-23): re-classify if MITRE
                    # techniques changed (late-added technique on dedup or
                    # corroboration upgrade should populate activity_thread).
                    try:
                        techniques = self._extract_mitre_techniques(updated)
                        if techniques:
                            self._classify_finding_into_activity_thread_locked(
                                finding_id, techniques
                            )
                    except Exception:
                        pass
                    self._save_locked()
                    # MCP segfault fix 2026-05-23.
                    return copy.deepcopy(updated)

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
            if not execution.get("execution_id"):
                execution["execution_id"] = self.generate_execution_id()
            normalized = _normalize_execution_record(
                execution,
                fallback_case_id=self._state.get("case_id"),
                fallback_iteration=1,
            )
            execution_id = str(normalized.get("execution_id", ""))
            self._sync_execution_counter_locked(execution_id)
            existing_index = self._find_execution_index_locked(execution_id)
            if existing_index is None:
                self._state["executions"].append(normalized)
            else:
                self._state["executions"][existing_index] = normalized
            self._state["executions_count"] = len(self._state["executions"])
            self._save_locked()
            return execution_id

    def link_execution(self, execution_id: str, **kwargs: Any) -> dict[str, Any]:
        """Enrich an existing execution record with provenance linkage metadata."""
        with self._lock:
            self._assert_loaded()
            index = self._find_execution_index_locked(execution_id)

            base_record: dict[str, Any]
            if index is None:
                base_record = {
                    "execution_id": execution_id,
                    "case_id": self._state.get("case_id"),
                    "iteration": kwargs.get("iteration") or 1,
                    "tool_name": kwargs.get("tool_name") or "unknown.tool",
                    "command_line": kwargs.get("command_line") or "<unavailable>",
                    "parameters": kwargs.get("parameters") or {},
                    "agent_reason": kwargs.get("agent_reason"),
                }
            else:
                base_record = dict(self._state["executions"][index])

            merged = dict(base_record)
            for field_name in (
                "tool_name",
                "command_line",
                "parameters",
                "iteration",
                "duration_seconds",
                "exit_code",
                "outputs_summary",
                "stdout_ref",
                "stderr_ref",
                "agent_turn",
                "agent_reason",
                "audit_started_entry_hash",
                "audit_completed_entry_hash",
                "audit_linked_entry_hash",
                # Artifact metadata for specialist agent access
                "csv_path",
                "total_records",
                "records_count",
                "storage_path",
                "output_path",
                "export_dir",
                "artifact_path",
            ):
                if field_name in kwargs and kwargs[field_name] is not None:
                    merged[field_name] = kwargs[field_name]

            merged["finding_ids_generated"] = _merge_unique_strings(
                base_record.get("finding_ids_generated"),
                kwargs.get("finding_ids_generated"),
            )
            merged["artifact_hashes"] = _merge_unique_dicts(
                base_record.get("artifact_hashes"),
                kwargs.get("artifact_hashes"),
                key_fields=("path", "sha256", "role", "source"),
            )
            merged["raw_evidence_refs"] = _merge_unique_dicts(
                base_record.get("raw_evidence_refs"),
                kwargs.get("raw_evidence_refs"),
                key_fields=("path", "role", "offset", "hash_status"),
            )

            normalized = _normalize_execution_record(
                merged,
                fallback_case_id=self._state.get("case_id"),
                fallback_iteration=kwargs.get("iteration") or 1,
            )
            self._sync_execution_counter_locked(execution_id)
            if index is None:
                self._state["executions"].append(normalized)
            else:
                self._state["executions"][index] = normalized
            self._state["executions_count"] = len(self._state["executions"])
            self._save_locked()
            # MCP segfault fix 2026-05-23: normalized shares nested
            # artifact_hashes/raw_evidence_refs refs with state.
            return copy.deepcopy(normalized)

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_findings(
        self,
        artifact_type: Optional[str] = None,
        evidence_kind: Optional[str] = None,
        finding_status: Optional[str] = None,
        finding_type: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        min_confidence: Optional[float] = None,
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
        finding_status:
            Filter by ``finding["finding_status"]`` (case-insensitive).
            Example: ``"CONFIRMED"``, ``"HYPOTHESIS"``, ``"REJECTED"``.
        finding_type:
            Filter by ``finding["finding_type"]`` (case-insensitive).
            Example: ``"threat_detection"``, ``"persistence"``.
        mitre_tactic:
            Filter by ``finding["mitre_tactic"]`` (case-insensitive).
            Example: ``"TA0003"``.
        min_confidence:
            Minimum confidence threshold inclusive.
        status:
            Backward-compatible alias for *finding_status*.

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
            effective_status = finding_status or status
            results = []
            for f in self._state["findings"]:
                if artifact_type is not None:
                    requested_type = artifact_type.lower()
                    available_types = {
                        (f.get("artifact_type") or "").lower(),
                        (f.get("artifact_subtype") or "").lower(),
                    }
                    if requested_type not in available_types:
                        continue
                if evidence_kind is not None:
                    if (f.get("evidence_kind") or "").lower() != evidence_kind.lower():
                        continue
                if effective_status is not None:
                    if (f.get("finding_status") or "").lower() != effective_status.lower():
                        continue
                if finding_type is not None:
                    if (f.get("finding_type") or "").lower() != finding_type.lower():
                        continue
                if mitre_tactic is not None:
                    if (f.get("mitre_tactic") or "").lower() != mitre_tactic.lower():
                        continue
                if min_confidence is not None:
                    try:
                        confidence = float(f.get("confidence", 0.0) or 0.0)
                    except (TypeError, ValueError):
                        confidence = 0.0
                    if confidence < float(min_confidence):
                        continue
                # MCP segfault fix 2026-05-23: deepcopy each finding so
                # nested lists (supporting_indicators, corroborated_by,
                # confidence_support_inputs) are detached from live state.
                results.append(copy.deepcopy(f))
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
                    # MCP segfault fix 2026-05-23: deepcopy detaches
                    # nested lists from live state.
                    return copy.deepcopy(f)
            return None

    def get_execution(self, execution_id: str) -> Optional[dict[str, Any]]:
        """Return one execution record by execution_id, or ``None`` if absent."""
        with self._lock:
            self._assert_loaded()
            index = self._find_execution_index_locked(execution_id)
            if index is None:
                return None
            # MCP segfault fix 2026-05-23: executions carry artifact_hashes
            # nested lists - deepcopy detaches them from live state.
            return copy.deepcopy(self._state["executions"][index])

    def get_executions(self, tool_name: Optional[str] = None) -> list[dict[str, Any]]:
        """Return execution records in insertion order.

        Parameters
        ----------
        tool_name:
            Optional tool-name filter matched case-insensitively against the
            stored ``execution["tool_name"]`` field.

        Returns
        -------
        list[dict[str, Any]]
            Matching execution records as shallow copies, oldest first.
        """
        with self._lock:
            self._assert_loaded()
            results: list[dict[str, Any]] = []
            requested = str(tool_name or "").strip().lower()
            for execution in self._state.get("executions", []):
                if not isinstance(execution, dict):
                    continue
                if requested and str(execution.get("tool_name") or "").strip().lower() != requested:
                    continue
                # MCP segfault fix 2026-05-23: deepcopy nested artifact_hashes.
                results.append(copy.deepcopy(execution))
            return results

    def lookup_artifact_hash(self, artifact_path: str) -> Optional[dict[str, Any]]:
        """Return the most recent artifact-hash record for *artifact_path*."""
        with self._lock:
            self._assert_loaded()
            needle = _normalize_path_lookup(artifact_path)
            for execution in reversed(self._state.get("executions", [])):
                if not isinstance(execution, dict):
                    continue
                for artifact_hash in reversed(execution.get("artifact_hashes", [])):
                    if not isinstance(artifact_hash, dict):
                        continue
                    candidate = _normalize_path_lookup(artifact_hash.get("path"))
                    if candidate == needle:
                        # MCP segfault fix 2026-05-23.
                        return copy.deepcopy(artifact_hash)
            return None

    def get_unresolved_discrepancies(self) -> list[dict[str, Any]]:
        """Return findings with unresolved contradictions.

        A finding is "unresolved" when its ``contradicted_by`` list is
        non-empty **and** its ``finding_status`` is not ``"REJECTED"``.  These
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
                status: str = (f.get("finding_status") or "").upper()
                if contradicted_by and status != "REJECTED":
                    # MCP segfault fix 2026-05-23.
                    results.append(copy.deepcopy(f))
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
            return self._allocate_finding_id_locked()

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
                s = (f.get("finding_status") or "UNKNOWN").upper()
                status_counts[s] = status_counts.get(s, 0) + 1
            hypothesis_count = sum(
                1
                for f in findings
                if (f.get("evidence_kind") or "").lower() == "hypothesis"
                and (f.get("finding_status") or "").upper() != "REJECTED"
            )

            unresolved = sum(
                1
                for f in findings
                if (f.get("contradicted_by") or [])
                and (f.get("finding_status") or "").upper() != "REJECTED"
            )

            # MCP segfault fix 2026-05-23: every nested container is
            # deepcopied so the JSON serializer never walks live state.
            # to_summary() is the hottest read path (hooks + ratchets),
            # so this is the most important place to detach references.
            return {
                "case_id": self._state.get("case_id"),
                "status": self._state.get("status", "IN_PROGRESS"),
                "triage_status": self._state.get("triage_status", "IN_PROGRESS"),
                "status_flags": copy.deepcopy(self._state.get("status_flags", {})),
                "analysis_lanes": copy.deepcopy(
                    self._state.get("analysis_lanes", [])
                ),
                "actionable_leads": copy.deepcopy(
                    self._state.get("actionable_leads", [])
                ),
                "artifact_coverage": copy.deepcopy(
                    self._state.get("artifact_coverage", {})
                ),
                "anti_forensics_warnings": copy.deepcopy(
                    self._state.get("anti_forensics_warnings", [])
                ),
                "data_gaps": copy.deepcopy(self._state.get("data_gaps", [])),
                "migration_warnings": copy.deepcopy(
                    self._state.get("migration_warnings", [])
                ),
                "enabled_detectors": self._state.get("enabled_detectors"),
                "findings_count": len(findings),
                "executions_count": len(self._state.get("executions", [])),
                "confirmed_count": status_counts.get("CONFIRMED", 0),
                "hypothesis_count": hypothesis_count,
                "rejected_count": status_counts.get("REJECTED", 0),
                "unresolved_discrepancies": unresolved,
                "open_questions": list(self._state.get("open_questions", [])),
                "latest_findings": copy.deepcopy(findings[-10:]),
                "created_at": self._state.get("created_at"),
                "updated_at": self._state.get("updated_at"),
            }

    @property
    def case_id(self) -> str:
        """Return the case identifier for the currently loaded state."""
        return self._state.get("case_id", "unknown") if self._loaded else "unknown"

    def cache_artifact(
        self, cache_key: str, result_summary: dict[str, Any]
    ) -> None:
        """Persist a cached artifact summary for idempotent tool reuse."""
        with self._lock:
            self._assert_loaded()
            self._state.setdefault("cached_artifacts", {})
            self._state["cached_artifacts"][cache_key] = {
                "timestamp": _utcnow_iso(),
                **dict(result_summary),
            }
            self._save_locked()

    def get_artifact_cache(self, cache_key: str) -> Optional[dict[str, Any]]:
        """Return a cached artifact summary by key, or ``None``."""
        with self._lock:
            self._assert_loaded()
            cached = self._state.get("cached_artifacts", {}).get(cache_key)
            # MCP segfault fix 2026-05-23.
            return copy.deepcopy(cached) if isinstance(cached, dict) else None

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

    def update_triage_state(
        self,
        *,
        triage_status: str,
        status_flags: Optional[dict[str, Any]] = None,
        analysis_lanes: Optional[list[dict[str, Any]]] = None,
        actionable_leads: Optional[list[dict[str, Any]]] = None,
        artifact_coverage: Optional[dict[str, Any]] = None,
        anti_forensics_warnings: Optional[list[dict[str, Any]]] = None,
        data_gaps: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        """Persist additive triage/reporting fields without changing old schemas."""
        with self._lock:
            self._assert_loaded()
            self._state["triage_status"] = triage_status
            if status_flags is not None:
                self._state["status_flags"] = dict(status_flags)
            if analysis_lanes is not None:
                self._state["analysis_lanes"] = [dict(lane) for lane in analysis_lanes]
            if actionable_leads is not None:
                self._state["actionable_leads"] = list(actionable_leads)
            if artifact_coverage is not None:
                # Shallow merge: new keys win, old keys not being set survive.
                # This preserves evtx_inventory and other per-tool coverage data
                # when reporting.generate_report writes its own coverage_result.
                merged = dict(self._state.get("artifact_coverage", {}) or {})
                for key, value in artifact_coverage.items():
                    merged[key] = value
                self._state["artifact_coverage"] = merged
            if anti_forensics_warnings is not None:
                self._state["anti_forensics_warnings"] = list(anti_forensics_warnings)
            if data_gaps is not None:
                self._state["data_gaps"] = list(data_gaps)
            self._save_locked()

    def get_analysis_lanes(self) -> list[dict[str, Any]]:
        """Return persisted analysis-lane records (independent snapshots)."""
        with self._lock:
            self._assert_loaded()
            # MCP segfault fix 2026-05-23: deepcopy lanes - they hold
            # finding_ids, data_gaps, confidence_notes nested lists.
            return [copy.deepcopy(lane) for lane in self._state.get("analysis_lanes", [])]

    # ------------------------------------------------------------------
    # W1.7 - heuristic refs (dedup), hypotheses, activity thread
    # ------------------------------------------------------------------

    def next_context_id(self) -> str:
        """Allocate the next CTX-NNN id. Persisted via _context_counter so
        IDs are stable across server restarts (mirrors execution_id/finding_id).
        """
        with self._lock:
            self._assert_loaded()
            self._state["_context_counter"] = (
                self._state.get("_context_counter", 0) + 1
            )
            self._save_locked()
            return f"CTX-{self._state['_context_counter']:03d}"

    def lookup_heuristic_ref(
        self,
        artifact: str,
        excerpt_hash: str,
    ) -> Optional[dict[str, Any]]:
        """Return the existing CTX bundle record for (artifact, excerpt_hash),
        or None if not yet loaded for this case. Lets prepare_hypothesis_context
        skip duplicate slice delivery (CR13-3 dedup requirement).
        """
        with self._lock:
            self._assert_loaded()
            for ref in self._state.get("heuristic_refs_loaded", []):
                if (
                    str(ref.get("artifact") or "").lower() == artifact.lower()
                    and ref.get("excerpt_hash") == excerpt_hash
                ):
                    return copy.deepcopy(ref)
        return None

    def record_heuristic_ref(
        self,
        *,
        context_id: str,
        artifact: str,
        source_hash: str,
        excerpt_hash: str,
        section: str,
        triggered_by: str,
    ) -> dict[str, Any]:
        """Append a heuristic-bundle ref to state. Idempotent on (context_id)."""
        record = {
            "context_id": context_id,
            "artifact": artifact.lower(),
            "source_hash": source_hash,
            "excerpt_hash": excerpt_hash,
            "section": section,
            "triggered_by": triggered_by,
        }
        with self._lock:
            self._assert_loaded()
            refs = self._state.setdefault("heuristic_refs_loaded", [])
            for existing in refs:
                if existing.get("context_id") == context_id:
                    return copy.deepcopy(existing)
            refs.append(record)
            self._save_locked()
            return copy.deepcopy(record)

    def get_heuristic_refs(self) -> list[dict[str, Any]]:
        """Return all heuristic refs loaded for this case (snapshot)."""
        with self._lock:
            self._assert_loaded()
            return copy.deepcopy(self._state.get("heuristic_refs_loaded", []))

    def record_hypotheses(self, hypotheses: list[dict[str, Any]]) -> list[str]:
        """Persist a list of Hypothesis records. Returns the list of
        hypothesis_ids written. Idempotent on hypothesis_id (existing
        entries are UPDATED in place rather than duplicated).
        """
        ids_written: list[str] = []
        with self._lock:
            self._assert_loaded()
            bucket = self._state.setdefault("hypotheses", [])
            for h in hypotheses:
                hid = str(h.get("hypothesis_id") or "").strip()
                if not hid:
                    continue
                replaced = False
                for i, existing in enumerate(bucket):
                    if existing.get("hypothesis_id") == hid:
                        bucket[i] = dict(h)
                        replaced = True
                        break
                if not replaced:
                    bucket.append(dict(h))
                ids_written.append(hid)
            self._save_locked()
        return ids_written

    def get_hypotheses(self) -> list[dict[str, Any]]:
        """Return all hypotheses for this case (snapshot)."""
        with self._lock:
            self._assert_loaded()
            return copy.deepcopy(self._state.get("hypotheses", []))

    @staticmethod
    def _extract_mitre_techniques(finding: dict[str, Any]) -> list[str]:
        """Normalize MITRE techniques across the two field-name conventions
        in use: `mitre_techniques` (list, EvidenceFinding/Section 3-lite) and
        `mitre_technique` (singular string, legacy Finding model). without this normalization, activity-thread
        classification silently no-ops on the majority of disk/memory findings.
        """
        out: list[str] = []
        v_list = finding.get("mitre_techniques")
        if isinstance(v_list, list):
            for t in v_list:
                s = str(t or "").strip()
                if s:
                    out.append(s)
        v_singular = finding.get("mitre_technique")
        if v_singular:
            s = str(v_singular).strip()
            if s and s not in out:
                out.append(s)
        return out

    def _classify_finding_into_activity_thread_locked(
        self,
        finding_id: str,
        mitre_techniques: list[str],
    ) -> Optional[str]:
        """Lock-free variant for callers already holding self._lock (add_finding,
        update_finding). Does NOT call _save_locked - caller is responsible.
        """
        from sift_mcp.models.activity_thread import classify_finding_to_phase

        phase = classify_finding_to_phase(mitre_techniques)
        if phase is None:
            return None

        at_state = self._state.setdefault("activity_thread", {})
        phases = at_state.setdefault("phases", {})
        bucket = phases.setdefault(phase.value, [])
        if finding_id not in bucket:
            bucket.append(finding_id)
        return phase.value

    def classify_finding_into_activity_thread(
        self,
        finding_id: str,
        mitre_techniques: list[str],
    ) -> Optional[str]:
        """Classify a finding into its Cyber Kill Chain phase using its MITRE
        techniques. Returns the phase.value the finding was added to, or
        None if no technique mapped.

        Called by add_finding / submit_finding (or correlator) to keep the
        Activity Thread in sync with state.findings. Blindspot detection
        (empty phases) is computed at report time from this state.
        """
        with self._lock:
            self._assert_loaded()
            result = self._classify_finding_into_activity_thread_locked(
                finding_id, mitre_techniques
            )
            if result is not None:
                self._save_locked()
            return result

    def get_activity_thread(self) -> dict[str, Any]:
        """Return the Activity Thread state (deepcopy snapshot)."""
        with self._lock:
            self._assert_loaded()
            return copy.deepcopy(self._state.get("activity_thread", {
                "phases": {},
                "blindspot_notes": {},
            }))

    def set_blindspot_note(self, phase: str, note: str) -> None:
        """Record an analyst-authored note explaining why a kill-chain phase
        is empty (e.g., 'evidence not extracted', 'logs cleared')."""
        with self._lock:
            self._assert_loaded()
            at_state = self._state.setdefault("activity_thread", {})
            notes = at_state.setdefault("blindspot_notes", {})
            notes[phase] = note
            self._save_locked()

    def try_claim_status_flag(
        self,
        flag_name: str,
        *,
        readiness_predicate: Callable[[dict[str, Any]], bool],
        reason: str,
    ) -> bool:
        """Atomic compare-and-set on a status_flags boolean.

        corroboration dispatch must be a
        single atomic transition under the state lock - read the flag,
        check the readiness predicate against current state, and set
        the flag, all in one critical section. Two concurrent callers
        can no longer both pass the false-flag check and both write a
        delegate.

        Args:
            flag_name: status_flags key to claim (e.g. 'corroboration_dispatched').
            readiness_predicate: called with the full state dict; must
                return True if the claim should proceed (e.g., all
                prereq lanes complete). Evaluated INSIDE the lock so
                the lane state seen here is the durable one.
            reason: stored alongside the flag for observability.

        Returns:
            True if THIS call won the claim, False if the flag was
            already set or readiness was not met. Caller-side action
            (e.g. writing the delegate file) should only happen on True.
        """
        with self._lock:
            self._assert_loaded()
            flags = dict(self._state.get("status_flags") or {})
            if flags.get(flag_name):
                return False
            try:
                if not readiness_predicate(self._state):
                    return False
            except Exception:
                return False
            flags[flag_name] = True
            flags[f"{flag_name}_reason"] = reason
            flags[f"{flag_name}_at"] = datetime.now(tz=timezone.utc).isoformat()
            self._state["status_flags"] = flags
            self._save_locked()
            return True

    def upsert_analysis_lane(self, lane_id: str, **updates: Any) -> dict[str, Any]:
        """Create or update one analysis lane and persist it."""
        with self._lock:
            self._assert_loaded()
            lanes = self._state.setdefault("analysis_lanes", [])
            candidate = _normalize_analysis_lane_record(
                {
                    **updates,
                    "lane_id": lane_id,
                }
            )
            for index, existing in enumerate(lanes):
                if not isinstance(existing, dict) or existing.get("lane_id") != lane_id:
                    continue
                merged = dict(existing)
                merged.update(candidate)
                merged["execution_ids"] = _merge_unique_strings(
                    existing.get("execution_ids"),
                    candidate.get("execution_ids"),
                )
                merged["finding_ids"] = _merge_unique_strings(
                    existing.get("finding_ids"),
                    candidate.get("finding_ids"),
                )
                merged["related_lane_ids"] = _merge_unique_strings(
                    existing.get("related_lane_ids"),
                    candidate.get("related_lane_ids"),
                )
                merged["supporting_agents"] = _merge_unique_strings(
                    existing.get("supporting_agents"),
                    candidate.get("supporting_agents"),
                )
                merged["data_gaps"] = _merge_unique_dicts(
                    existing.get("data_gaps"),
                    candidate.get("data_gaps"),
                    key_fields=("artifact_family", "classification", "reason"),
                )
                merged["anti_forensics_warnings"] = _merge_unique_dicts(
                    existing.get("anti_forensics_warnings"),
                    candidate.get("anti_forensics_warnings"),
                    key_fields=("type", "message", "description"),
                )
                merged["next_pivots"] = _merge_unique_dicts(
                    existing.get("next_pivots"),
                    candidate.get("next_pivots"),
                    key_fields=("tool", "human_readable"),
                )
                normalized = _normalize_analysis_lane_record(merged)
                lanes[index] = normalized
                self._save_locked()
                # MCP segfault fix 2026-05-23: lane holds finding_ids,
                # data_gaps, confidence_notes, next_pivots nested lists.
                return copy.deepcopy(normalized)
            lanes.append(candidate)
            self._save_locked()
            # MCP segfault fix 2026-05-23.
            return copy.deepcopy(candidate)

    def set_enabled_detectors(self, enabled_detectors: Optional[list[str]]) -> None:
        """Persist the manifest detector allow-list using additive case config."""
        with self._lock:
            self._assert_loaded()
            self._state["enabled_detectors"] = (
                None if enabled_detectors is None else list(enabled_detectors)
            )
            self._save_locked()

    def get_enabled_detectors(self) -> Optional[list[str]]:
        """Return the configured detector allow-list, if the manifest provided one."""
        with self._lock:
            self._assert_loaded()
            value = self._state.get("enabled_detectors")
            return list(value) if isinstance(value, list) else None

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
        serialised = json.dumps(
            self._state, ensure_ascii=False, indent=2, default=str) + "\n"

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

    def _migrate_loaded_state_locked(self) -> None:
        """Backfill missing keys and normalize finding lifecycle fields."""
        dirty = False

        if "cached_artifacts" not in self._state:
            self._state["cached_artifacts"] = {}
            dirty = True

        for key, value in {
            "triage_status": "IN_PROGRESS",
            "status_flags": {},
            "analysis_lanes": [],
            "actionable_leads": [],
            "artifact_coverage": {},
            "anti_forensics_warnings": [],
            "data_gaps": [],
            "migration_warnings": [],
            "enabled_detectors": None,
            # W1.7 (CR13 Option X) - backfill for older state files
            "heuristic_refs_loaded": [],
            "hypotheses": [],
            "activity_thread": {
                "phases": {
                    "reconnaissance": [], "weaponization": [], "delivery": [],
                    "exploitation": [], "installation": [],
                    "command_and_control": [], "actions_on_objectives": [],
                },
                "blindspot_notes": {},
            },
            "_context_counter": 0,
        }.items():
            if key not in self._state:
                self._state[key] = value.copy() if isinstance(value, (dict, list)) else value
                dirty = True

        findings = self._state.get("findings", [])
        if isinstance(findings, list):
            seen_finding_ids: set[str] = set()
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    continue
                normalized = validate_and_prepare_finding(
                    finding,
                    mode="migration",
                    fallback_case_id=self._state.get("case_id"),
                    fallback_execution_id="E-000",
                    fallback_iteration=1,
                )
                finding_id = str(normalized.get("finding_id") or "").strip()
                if not finding_id or finding_id == "F-000" or finding_id in seen_finding_ids:
                    replacement_id = self._allocate_finding_id_locked()
                    if finding_id and finding_id != "F-000":
                        normalized["legacy_finding_id"] = finding_id
                    normalized["finding_id"] = replacement_id
                    self._state.setdefault("migration_warnings", []).append(
                        {
                            "type": "finding_id_reassigned",
                            "legacy_finding_id": finding_id or None,
                            "new_finding_id": replacement_id,
                            "reason": "missing, placeholder, or duplicate finding_id",
                        }
                    )
                    dirty = True
                seen_finding_ids.add(str(normalized.get("finding_id") or ""))
                self._sync_finding_counter_locked(str(normalized.get("finding_id") or ""))
                if normalized != finding:
                    findings[index] = normalized
                    dirty = True

        executions = self._state.get("executions", [])
        if isinstance(executions, list):
            for index, execution in enumerate(executions):
                if not isinstance(execution, dict):
                    continue
                normalized_execution = _normalize_execution_record(
                    execution,
                    fallback_case_id=self._state.get("case_id"),
                    fallback_iteration=1,
                )
                if normalized_execution != execution:
                    executions[index] = normalized_execution
                    dirty = True
                self._sync_execution_counter_locked(
                    str(normalized_execution.get("execution_id", ""))
                )

        self._state["executions_count"] = len(self._state.get("executions", []))
        self._state["findings_count"] = len(self._state.get("findings", []))

        if dirty:
            self._save_locked()

    def _find_execution_index_locked(self, execution_id: str) -> Optional[int]:
        for index, execution in enumerate(self._state.get("executions", [])):
            if isinstance(execution, dict) and execution.get("execution_id") == execution_id:
                return index
        return None

    def _sync_execution_counter_locked(self, execution_id: str) -> None:
        if not execution_id.startswith("E-"):
            return
        try:
            numeric = int(execution_id[2:])
        except ValueError:
            return
        current = int(self._state.get("_execution_counter", 0) or 0)
        if numeric > current:
            self._state["_execution_counter"] = numeric

    def _allocate_finding_id_locked(self) -> str:
        self._state["_finding_counter"] = (
            int(self._state.get("_finding_counter", 0) or 0) + 1
        )
        return f"F-{self._state['_finding_counter']:03d}"

    def _sync_finding_counter_locked(self, finding_id: str) -> None:
        if not finding_id.startswith("F-"):
            return
        try:
            numeric = int(finding_id[2:])
        except ValueError:
            return
        current = int(self._state.get("_finding_counter", 0) or 0)
        if numeric > current:
            self._state["_finding_counter"] = numeric


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with 'Z' suffix."""
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _normalize_path_lookup(path: Any) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    try:
        return os.path.realpath(text)
    except OSError:
        return text


def _merge_unique_strings(*values: Any) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        items = value if isinstance(value, (list, tuple, set)) else [value]
        for item in items:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            merged.append(text)
    return merged


def _merge_unique_dicts(*values: Any, key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for value in values:
        if value is None:
            continue
        items = value if isinstance(value, (list, tuple)) else [value]
        for item in items:
            if not isinstance(item, dict):
                continue
            key = tuple(str(item.get(field, "") or "").strip() for field in key_fields)
            if key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
    return merged


def _normalize_execution_record(
    execution: dict[str, Any],
    *,
    fallback_case_id: Optional[str],
    fallback_iteration: int,
) -> dict[str, Any]:
    normalized = dict(execution)
    if fallback_case_id and not normalized.get("case_id"):
        normalized["case_id"] = fallback_case_id
    normalized.setdefault("iteration", fallback_iteration)
    normalized.setdefault("tool_name", "unknown.tool")
    normalized.setdefault("parameters", {})
    normalized.setdefault("command_line", "<unavailable>")
    normalized.setdefault("agent_reason", None)
    normalized.setdefault("outputs_summary", None)
    normalized.setdefault("agent_turn", 0)
    normalized.setdefault("finding_ids_generated", [])
    normalized.setdefault("artifact_hashes", [])
    normalized.setdefault("raw_evidence_refs", [])
    normalized.setdefault("recorded_at", _utcnow_iso())
    return Execution(**normalized).model_dump(mode="json")


def _normalize_analysis_lane_record(lane: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(lane)
    normalized.setdefault("title", str(normalized.get("lane_id") or "Unknown").replace("_", " ").title())
    normalized.setdefault("status", "PENDING")
    normalized.setdefault("required", True)
    normalized.setdefault("legacy_inferred", False)
    normalized.setdefault("phase", "analysis")
    normalized.setdefault("assigned_agent", None)
    normalized.setdefault("supporting_agents", [])
    normalized.setdefault("summary", "")
    normalized.setdefault("lane_inference_confidence", None)
    normalized.setdefault("execution_ids", [])
    normalized.setdefault("finding_ids", [])
    normalized.setdefault("related_lane_ids", [])
    normalized.setdefault("data_gaps", [])
    normalized.setdefault("anti_forensics_warnings", [])
    normalized.setdefault("next_pivots", [])
    normalized.setdefault("started_at", None)
    normalized.setdefault("completed_at", None)
    return normalized


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
        "triage_status": "IN_PROGRESS",
        "status_flags": {},
        "analysis_lanes": [],
        "actionable_leads": [],
        "artifact_coverage": {},
        "anti_forensics_warnings": [],
        "data_gaps": [],
        "migration_warnings": [],
        "enabled_detectors": None,
        "created_at": now,
        "updated_at": now,
        # ID counters - persisted so they survive server restarts.
        "_finding_counter": 0,
        "_execution_counter": 0,
        # Collections
        "findings": [],
        "executions": [],
        "open_questions": [],
        "cached_artifacts": {},
        # Derived counts (denormalised for quick summary)
        "findings_count": 0,
        "executions_count": 0,
        # W1.7 (CR13 Option X) - heuristic injection dedup + hypothesis registry
        # + Activity Thread state for kill-chain phase mapping.
        # heuristic_refs_loaded tracks (case_id, artifact, section_hash) tuples
        # so prepare_hypothesis_context can return refs-only on repeat calls,
        # avoiding the 5K-per-cycle context bloat that flagged in CR13-3.
        "heuristic_refs_loaded": [],   # list of {"context_id", "artifact", "source_hash", "excerpt_hash"}
        "hypotheses": [],              # list of Hypothesis.model_dump() entries
        "activity_thread": {           # ActivityThread.model_dump()
            "phases": {
                "reconnaissance": [],
                "weaponization": [],
                "delivery": [],
                "exploitation": [],
                "installation": [],
                "command_and_control": [],
                "actions_on_objectives": [],
            },
            "blindspot_notes": {},
        },
        # CTX counter - persisted so CTX-NNN IDs are stable across server restarts
        "_context_counter": 0,
    }
