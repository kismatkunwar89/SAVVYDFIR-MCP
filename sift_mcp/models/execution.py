"""
execution.py — Tool execution and self-correction data models for SAVVYDFIR-MCP.

Every time the agent invokes an MCP tool, one ``Execution`` record is written
to ``<case_dir>/audit.jsonl``.  If that tool call reveals evidence that
contradicts a previously recorded finding, a ``CorrectionEvent`` is attached
to the ``Execution`` before it is persisted.

This module also provides the thread-safe counter used to generate ``E-NNN``
execution IDs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

_ARTIFACT_HASH_SOURCES = {"computed", "verify_integrity"}
_ARTIFACT_HASH_ROLES = {"input", "output"}
_RAW_EVIDENCE_REF_ROLES = {"input", "output", "derived", "handle"}


# ---------------------------------------------------------------------------
# Auto-incrementing ID counter (thread-safe)
# ---------------------------------------------------------------------------


class CorrectionEvent(BaseModel):
    """Records a self-correction triggered by contradicting physical evidence.

    A ``CorrectionEvent`` is attached to the ``Execution`` record whose tool
    output caused the contradiction.  It is NEVER produced by LLM
    introspection alone — it must be backed by concrete artifact evidence.

    Attributes:
        prior_claim:             The exact text of the finding that is being
                                 revised (copied verbatim from the original
                                 ``Finding.description``).
        contradiction_source:    Which MCP tool or finding ID produced the
                                 contradicting evidence.
        revised_claim:           The corrected claim that replaces the prior
                                 one.
        affected_finding_ids:    Finding IDs whose status should be updated to
                                 ``CORRECTED`` or ``REJECTED`` as a result of
                                 this event.
        confidence_delta:        Change in analyst confidence (positive →
                                 increased certainty, negative → decreased).
                                 Range: -1.0 to +1.0.
        correction_type:         Semantic category of the correction:
                                   - ``evidence_contradiction``: physical
                                     evidence contradicts a prior finding.
                                   - ``tool_error_recovery``: a tool failed
                                     and was retried with different parameters.
                                   - ``reclassification``: the finding's
                                     ``evidence_kind`` changed (e.g.
                                     HYPOTHESIS → REJECTED).
    """

    prior_claim: str = Field(
        ...,
        min_length=1,
        description=(
            "Verbatim text of the finding being revised.  Must match the "
            "original Finding.description exactly."
        ),
    )
    contradiction_source: str = Field(
        ...,
        description=(
            "MCP tool name or Finding ID that produced the contradicting evidence "
            "(e.g. 'detect_injection', 'F-003')."
        ),
    )
    revised_claim: str = Field(
        ...,
        min_length=1,
        description="The corrected claim that replaces prior_claim.",
    )
    affected_finding_ids: list[str] = Field(
        ...,
        min_length=1,
        description="Finding IDs (F-NNN) whose status is changed by this correction.",
    )
    confidence_delta: float = Field(
        ...,
        ge=-1.0,
        le=1.0,
        description=(
            "Change in analyst confidence caused by this correction "
            "(positive = more certain, negative = less certain)."
        ),
    )
    correction_type: Literal[
        "evidence_contradiction",
        "tool_error_recovery",
        "reclassification",
    ] = Field(
        ...,
        description=(
            "Semantic category of the correction.  "
            "'evidence_contradiction' is the highest-signal value — it means "
            "a physical artifact contradicted a prior analytic conclusion."
        ),
    )
    occurred_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when the correction was logged.",
    )


# ---------------------------------------------------------------------------
# Execution record
# ---------------------------------------------------------------------------


class Execution(BaseModel):
    """Record of a single MCP tool invocation — one line in ``audit.jsonl``.

    Every execution is self-contained: it records WHY the agent called the
    tool (``agent_reason``), WHAT command was actually run (``command_line``),
    WHAT the outcome was (``exit_code``, ``stdout_ref``, ``stderr_ref``), and
    WHAT findings resulted (``finding_ids_generated``).  Together, the chain
    Execution → Finding → CorrectionEvent forms the complete provenance graph.

    Attributes:
        execution_id:          Auto-generated sequential ID in ``E-NNN`` format.
        case_id:               Parent case identifier.
        iteration:             Triage iteration that triggered this execution
                               (≥ 1).
        tool_name:             MCP tool that was invoked.
        parameters:            The exact parameters dict passed to the tool.
        command_line:          The subprocess command constructed by the tool
                               backend (for reproducibility / peer review).
        start_time:            UTC timestamp when the tool was invoked.
        end_time:              UTC timestamp when the tool returned.
        duration_seconds:      Wall-clock duration of the execution.
        exit_code:             OS exit code (0 = success).
        stdout_ref:            Absolute path to the file where the tool's full
                               stdout was saved (None if stdout was empty or
                               not captured).
        stderr_ref:            Absolute path to the file where the tool's full
                               stderr was saved (None if stderr was empty or
                               not captured).
        finding_ids_generated: F-NNN IDs of every finding created by this
                               execution.
        correction_event:      Populated when this execution's output
                               triggered a self-correction of a prior finding.
        agent_reason:          One-sentence explanation of why the agent chose
                               to call this tool at this point in the
                               investigation.
    """

    execution_id: Optional[str] = Field(
        default=None,
        pattern=r"^E-\d{3,}$",
        description="Auto-generated sequential ID: E-001, E-002, …",
    )
    case_id: str = Field(..., description="Parent case identifier.")
    iteration: int = Field(
        ..., ge=1, description="Triage iteration that triggered this execution."
    )
    tool_name: str = Field(
        ..., description="MCP tool name that was invoked."
    )
    parameters: dict = Field(
        default_factory=dict,
        description="Exact parameters dict passed to the MCP tool.",
    )
    command_line: str = Field(
        ...,
        description=(
            "Exact subprocess command constructed by the tool backend, "
            "including all flags and paths, for reproducibility."
        ),
    )
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when the tool invocation began.",
    )
    end_time: Optional[datetime] = Field(
        None,
        description="UTC timestamp when the tool returned (None while running).",
    )
    duration_seconds: Optional[float] = Field(
        None,
        ge=0.0,
        description="Wall-clock duration of the execution in seconds.",
    )
    exit_code: Optional[int] = Field(
        None,
        description="OS exit code returned by the subprocess (0 = success).",
    )
    stdout_ref: Optional[str] = Field(
        None,
        description=(
            "Absolute path to the file where the tool's full stdout was "
            "saved (e.g. '<case_dir>/executions/E-001_stdout.txt')."
        ),
    )
    stderr_ref: Optional[str] = Field(
        None,
        description=(
            "Absolute path to the file where the tool's full stderr was "
            "saved (e.g. '<case_dir>/executions/E-001_stderr.txt')."
        ),
    )
    outputs_summary: Optional[str] = Field(
        None,
        description="Short human-readable summary of the tool output.",
    )
    agent_turn: int = Field(
        0,
        ge=0,
        description="Claude turn counter associated with this execution.",
    )
    finding_ids_generated: list[str] = Field(
        default_factory=list,
        description="F-NNN IDs of every Finding created by this execution.",
    )
    audit_started_entry_hash: Optional[str] = Field(
        None,
        description="Hash of the append-only audit 'started' entry for this execution.",
    )
    audit_completed_entry_hash: Optional[str] = Field(
        None,
        description="Hash of the append-only audit 'completed' entry for this execution.",
    )
    audit_linked_entry_hash: Optional[str] = Field(
        None,
        description="Hash of the append-only audit 'linked' entry for this execution.",
    )
    artifact_hashes: list[dict[str, str]] = Field(
        default_factory=list,
        description="Structured SHA-256 hashes for input/output artifacts tied to this execution.",
    )
    raw_evidence_refs: list[dict[str, str]] = Field(
        default_factory=list,
        description="Structured references to primary and derived evidence artifacts.",
    )
    correction_event: Optional[CorrectionEvent] = Field(
        None,
        description=(
            "Populated when this execution's output triggered a self-correction "
            "of one or more prior findings."
        ),
    )
    agent_reason: Optional[str] = Field(
        None,
        description=(
            "One-sentence explanation of why the agent chose to call this "
            "tool at this point in the investigation."
        ),
    )
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this execution record was persisted to state.",
    )
    storage_path: Optional[str] = Field(
        None,
        description=(
            "Absolute path to the primary durable output file produced by this "
            "execution (e.g., Plaso .plaso file, CSV timeline, Amcache database). "
            "Used by coverage gate to validate tool completion."
        ),
    )
    output_path: Optional[str] = Field(
        None,
        description=(
            "Legacy/alias field for storage_path. Some tools may populate this "
            "instead of storage_path for backwards compatibility."
        ),
    )

    @field_validator("execution_id", mode="before")
    @classmethod
    def _coerce_auto_id(cls, v: object) -> Optional[str]:
        """Normalize supplied IDs without allocating process-local IDs."""
        if not v:
            return None
        return str(v)

    @field_validator("finding_ids_generated", mode="before")
    @classmethod
    def _normalize_finding_ids(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("finding_ids_generated must be a list of finding IDs.")
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    @field_validator("artifact_hashes", mode="before")
    @classmethod
    def _normalize_artifact_hashes(cls, value: object) -> list[dict[str, str]]:
        if value is None:
            return []
        if not isinstance(value, (list, tuple)):
            raise ValueError("artifact_hashes must be a list of dicts.")
        normalized: list[dict[str, str]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("Each artifact_hash must be a dict.")
            path = str(item.get("path") or "").strip()
            sha256 = str(item.get("sha256") or "").strip().lower()
            role = str(item.get("role") or "").strip().lower()
            source = str(item.get("source") or "").strip().lower()
            if not path or not sha256:
                raise ValueError("artifact_hashes items must include path and sha256.")
            if role not in _ARTIFACT_HASH_ROLES:
                raise ValueError("artifact_hashes.role must be 'input' or 'output'.")
            if source not in _ARTIFACT_HASH_SOURCES:
                raise ValueError("artifact_hashes.source must be computed or verify_integrity.")
            key = (path, sha256, role, source)
            if key in seen:
                continue
            seen.add(key)
            normalized.append(
                {"path": path, "sha256": sha256, "role": role, "source": source}
            )
        return normalized

    @field_validator("raw_evidence_refs", mode="before")
    @classmethod
    def _normalize_raw_evidence_refs(cls, value: object) -> list[dict[str, str]]:
        if value is None:
            return []
        if not isinstance(value, (list, tuple)):
            raise ValueError("raw_evidence_refs must be a list of dicts.")
        normalized: list[dict[str, str]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("Each raw_evidence_ref must be a dict.")
            path = str(item.get("path") or "").strip()
            role = str(item.get("role") or "").strip().lower()
            if not path:
                raise ValueError("raw_evidence_refs items must include path.")
            if role not in _RAW_EVIDENCE_REF_ROLES:
                raise ValueError(
                    "raw_evidence_refs.role must be one of input, output, derived, handle."
                )
            offset = str(item.get("offset") or "").strip()
            hash_status = str(item.get("hash_status") or "").strip()
            key = (path, role, offset, hash_status)
            if key in seen:
                continue
            seen.add(key)
            ref = {"path": path, "role": role}
            if offset:
                ref["offset"] = offset
            if hash_status:
                ref["hash_status"] = hash_status
            normalized.append(ref)
        return normalized

    @model_validator(mode="after")
    def _compute_duration(self) -> "Execution":
        """Auto-compute duration_seconds from start/end times when both present."""
        if (
            self.duration_seconds is None
            and self.end_time is not None
            and self.start_time is not None
        ):
            delta = (self.end_time - self.start_time).total_seconds()
            object.__setattr__(self, "duration_seconds", max(0.0, delta))
        return self

    model_config = {"validate_assignment": True}
