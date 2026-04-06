"""
finding.py — Forensic finding data models for SAVVYDFIR-MCP.

Every piece of analytic output produced by the agent is stored as a
``Finding``.  Findings are the atom of the audit trail: each one links back
to the exact tool execution (``execution_id``) that produced it, the evidence
file it came from (``artifact_path``), and the optional byte-level location
within that evidence (``artifact_offset``).

The ``EvidenceKind`` and ``FindingStatus`` enumerations encode the epistemic
state of each finding and MUST be updated as the investigation progresses.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EvidenceKind(str, Enum):
    """Epistemic classification for every forensic finding.

    Per the CLAUDE.md constraint, EVERY finding must carry one of these
    labels.  The agent is not permitted to omit or invent new values.

    Values:
        OBSERVATION:  Directly supported by tool output.  The evidence
                      artifact and (where available) the byte offset are
                      recorded so a human examiner can verify independently.
        INFERENCE:    Analytical conclusion derived from combining two or more
                      observations.  The reasoning chain must be documented in
                      ``description``.
        HYPOTHESIS:   A candidate lead that requires further confirmation.
                      Findings of this kind should not be cited as evidence
                      in a formal report until confirmed.
        REJECTED:     A lead that was considered and ruled out.  The reason
                      for rejection must appear in ``description``.  Rejected
                      findings are retained for auditability.
    """

    OBSERVATION = "observation"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"
    REJECTED = "rejected"


class FindingStatus(str, Enum):
    """Lifecycle status of a forensic finding.

    Values:
        ACTIVE:     The finding stands as originally recorded.
        CORRECTED:  The finding was revised by a ``CorrectionEvent``.  The
                    original text is preserved in the ``Execution`` record.
        CONFIRMED:  The finding has been corroborated by at least one
                    independent source (disk or memory) and is considered
                    reliable for the final report.
        REJECTED:   The finding was invalidated by contradicting evidence and
                    should not appear in the final narrative.
    """

    ACTIVE = "active"
    CORRECTED = "corrected"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Auto-incrementing ID counter (thread-safe)
# ---------------------------------------------------------------------------


class _FindingIDCounter:
    """Thread-safe, process-lifetime counter for generating F-NNN IDs."""

    _lock = threading.Lock()
    _value: int = 0

    @classmethod
    def next(cls) -> str:
        with cls._lock:
            cls._value += 1
            return f"F-{cls._value:03d}"

    @classmethod
    def reset(cls, value: int = 0) -> None:
        """Reset counter (test use only)."""
        with cls._lock:
            cls._value = value


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single forensic finding with full provenance.

    Findings are immutable once committed to the audit log.  To revise a
    finding, create a ``CorrectionEvent`` on the associated ``Execution`` and
    update ``finding_status`` to ``CORRECTED``.

    Attributes:
        finding_id:           Auto-generated sequential ID in ``F-NNN`` format.
        case_id:              Parent case identifier.
        finding_type:         Forensic category of the finding (e.g.
                              'process_injection', 'persistence').
        artifact_type:        Broad evidence domain the finding came from.
        artifact_path:        Absolute path to the evidence file.
        artifact_offset:      Byte offset or memory address within the evidence
                              file (None when not applicable).
        timestamp_observed:   UTC timestamp of the event the finding describes
                              (not the time the finding was created).
        tool_name:            MCP tool that produced this finding.
        execution_id:         Links this finding to the ``Execution`` record in
                              the audit log.
        iteration:            Triage iteration number that produced this finding
                              (≥ 1).
        evidence_kind:        Epistemic classification (OBSERVATION, INFERENCE,
                              HYPOTHESIS, REJECTED).
        finding_status:       Lifecycle status (ACTIVE, CORRECTED, CONFIRMED,
                              REJECTED).
        confidence:           Analyst confidence in the finding (0.0–1.0).
        description:          Human-readable explanation of the finding and
                              supporting reasoning (≥ 10 characters).
        supporting_indicators: Raw strings (hashes, paths, offsets) that
                              directly support this finding.
        mitre_tactic:         Optional MITRE ATT&CK tactic ID (e.g. 'TA0003').
        mitre_technique:      Optional MITRE ATT&CK technique ID (e.g.
                              'T1055.001').
        contradicted_by:      Finding IDs that contradict this one.
        corroborated_by:      Finding IDs that independently support this one.
        related_finding_ids:  Finding IDs that are related but neither
                              contradicting nor corroborating.
        created_at:           UTC timestamp when the finding was first recorded.
        updated_at:           UTC timestamp of the most recent modification.
    """

    finding_id: str = Field(
        default_factory=_FindingIDCounter.next,
        pattern=r"^F-\d{3,}$",
        description="Auto-generated sequential ID: F-001, F-002, …",
    )
    case_id: str = Field(..., description="Parent case identifier.")
    finding_type: str = Field(
        ...,
        description=(
            "Forensic category: process_injection | persistence | "
            "lateral_movement | timestomping | data_exfil | "
            "credential_access | defense_evasion | initial_access | other"
        ),
    )
    artifact_type: Literal["disk", "memory", "correlation", "timeline", "yara"] = Field(
        ..., description="Broad evidence domain the finding came from."
    )
    artifact_path: str = Field(
        ..., description="Absolute path to the evidence file that was analysed."
    )
    artifact_offset: Optional[str] = Field(
        None,
        description="Byte offset or virtual memory address within the evidence file.",
    )
    timestamp_observed: Optional[datetime] = Field(
        None,
        description=(
            "UTC timestamp of the event described by this finding "
            "(not the creation time of the finding record itself)."
        ),
    )
    tool_name: str = Field(
        ..., description="MCP tool name that produced this finding."
    )
    execution_id: str = Field(
        ...,
        pattern=r"^E-\d{3,}$",
        description="Links to the Execution record in audit.jsonl.",
    )
    iteration: int = Field(
        ..., ge=1, description="Triage iteration number that produced this finding."
    )
    evidence_kind: EvidenceKind = Field(
        ..., description="Epistemic classification (mandatory per CLAUDE.md)."
    )
    finding_status: FindingStatus = Field(
        default=FindingStatus.ACTIVE,
        description="Lifecycle status of the finding.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Analyst confidence in the finding (0.0 = none, 1.0 = certain).",
    )
    description: str = Field(
        ...,
        min_length=10,
        description=(
            "Human-readable explanation of the finding and supporting reasoning.  "
            "Must include the chain of evidence for INFERENCE-class findings."
        ),
    )
    supporting_indicators: list[str] = Field(
        default_factory=list,
        description=(
            "Raw indicator strings (file hashes, memory addresses, file paths, "
            "registry key values) that directly support this finding."
        ),
    )
    mitre_tactic: Optional[str] = Field(
        None, description="MITRE ATT&CK tactic ID, e.g. 'TA0003' (Persistence)."
    )
    mitre_technique: Optional[str] = Field(
        None,
        description="MITRE ATT&CK technique ID, e.g. 'T1055.001' (Process Injection: DLL).",
    )
    contradicted_by: list[str] = Field(
        default_factory=list,
        description="Finding IDs whose evidence contradicts this finding.",
    )
    corroborated_by: list[str] = Field(
        default_factory=list,
        description="Finding IDs that independently support this finding.",
    )
    related_finding_ids: list[str] = Field(
        default_factory=list,
        description="Finding IDs related to but not contradicting/corroborating this one.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this finding was first recorded.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp of the most recent update to this finding.",
    )

    @field_validator("finding_id", mode="before")
    @classmethod
    def _coerce_auto_id(cls, v: object) -> str:
        """Allow callers to pass None/empty to trigger auto-generation."""
        if not v:
            return _FindingIDCounter.next()
        return str(v)

    @model_validator(mode="after")
    def _validate_observation_has_offset_or_path(self) -> "Finding":
        """OBSERVATION findings SHOULD reference an artifact path."""
        if self.evidence_kind == EvidenceKind.OBSERVATION and not self.artifact_path:
            raise ValueError(
                "OBSERVATION findings must include artifact_path."
            )
        return self

    model_config = {"validate_assignment": True}
