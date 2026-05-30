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

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

_MITRE_TACTIC_RE = re.compile(r"^TA\d{4}$", re.IGNORECASE)
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_RAW_EVIDENCE_REF_ROLES = {"input", "output", "derived", "handle"}


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

    finding_id: Optional[str] = Field(
        default=None,
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
    artifact_subtype: Optional[str] = Field(
        None,
        description=(
            "Legacy or narrow artifact classification preserved alongside the canonical "
            "broad artifact_type (for example 'evtx', 'mft', 'pca')."
        ),
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
    finding_kind: Literal["validated", "raw_detector_hit"] = Field(
        default="validated",
        description=(
            "Whether this record is an analyst/reportable finding or a raw "
            "detector observation that still needs specialist validation."
        ),
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
    corroboration_outstanding: list[str] = Field(
        default_factory=list,
        description="Evidence source classes that still need corroboration before promotion.",
    )
    corroboration_completed_by: Optional[str] = Field(
        None,
        description="Source class that satisfied the latest corroboration requirement.",
    )
    # --- peer reviewer consensus 2026-05-19 (Tier-A report-gate invariants) -------
    requires_re_extraction: bool = Field(
        default=False,
        description=(
            "True when the finding's execution_id cannot be resolved in the "
            "current evidence ledger (cross-session inheritance or autogen "
            "placeholder). CONFIRMED status is blocked until either the "
            "execution is re-run in this session or this flag is set as an "
            "explicit operator waiver."
        ),
    )
    alternative_hypothesis: str = Field(
        default="",
        description=(
            "Strongest benign / competing explanation for the same evidence. "
            "Mandatory for CONFIRMED findings (or set disposition='not_applicable' "
            "with a reason). Required for dual-use tools and admin/IR activity."
        ),
    )
    evidence_that_would_support_it: list[str] = Field(
        default_factory=list,
        description=(
            "Concrete observable facts that would be present if the alternative "
            "(benign) hypothesis were true."
        ),
    )
    evidence_against_it: list[str] = Field(
        default_factory=list,
        description=(
            "What was actually observed that rules out the alternative hypothesis. "
            "Must contain >=1 entry when disposition='ruled_out'."
        ),
    )
    disposition: Literal["", "ruled_out", "not_resolved", "partially_plausible", "not_applicable"] = Field(
        default="",
        description=(
            "Final analyst disposition of the alternative hypothesis. "
            "CONFIRMED status requires disposition='ruled_out' or 'not_applicable'."
        ),
    )
    alternative_hypothesis_not_applicable_reason: str = Field(
        default="",
        description=(
            "Required when disposition='not_applicable'. One-line reason why "
            "no plausible benign alternative exists (e.g. 'self-extracting "
            "ransomware encryption pattern — no benign use of this binary')."
        ),
    )
    # --- peer reviewer consensus 2026-05-22 (Phase 1 — durable specialist provenance) ---
    assigned_agent: Optional[str] = Field(
        default=None,
        description=(
            "The specialist subagent_type that registered this finding via "
            "submit_finding (e.g. 'mft-analyst', 'evtx-analyst'). NULL when the "
            "finding was registered via state.add_finding by the main agent or "
            "auto-recorded by an MCP extraction tool. Required for the Phase 5 "
            "investigation-success gate to verify per-lane specialist contribution. "
            "Keep tool_name as the MCP producing tool — DO NOT overload it with "
            "the specialist name (peer reviewer sign-off)."
        ),
    )
    fk_source_class: Optional[str] = Field(
        None,
        description="FK/source-strength bucket used for structural confidence handling.",
    )
    fk_confidence_note: Optional[str] = Field(
        None,
        description="Human-readable explanation of any structural confidence adjustment.",
    )
    supporting_tool_families: list[str] = Field(
        default_factory=list,
        description="Broad tool families that currently support this finding.",
    )
    supporting_artifact_families: list[str] = Field(
        default_factory=list,
        description="Broad artifact families that currently support this finding.",
    )
    confidence_support_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured inputs that explain how the current confidence was derived.",
    )
    promotion_eligibility: Optional[str] = Field(
        None,
        description="Structural promotion state such as direct, needs_corroboration, or confirmed.",
    )
    group_key: Optional[str] = Field(
        None,
        description=(
            "Stable grouping key for noise-controlled findings. "
            "Multiple raw signals sharing the same group_key are collapsed "
            "into a single finding with a support_count."
        ),
    )
    support_count: int = Field(
        1,
        ge=1,
        description="Number of raw signals collapsed into this grouped finding.",
    )
    promotion_reason: Optional[str] = Field(
        None,
        description=(
            "Why this grouped finding was promoted to state (e.g. "
            "'mz_header_present', 'established_external', 'multi_region_injection')."
        ),
    )
    raw_evidence_refs: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Structured raw evidence references backing this finding. Each item "
            "records a path plus optional offset and provenance role."
        ),
    )
    psscan_only_count: Optional[int] = Field(
        None,
        ge=0,
        description=(
            "PIDs seen in psscan but not in pslist for the same dump — DKOM-hidden "
            "or unlinked processes; triggers mandatory detect_injection coverage."
        ),
    )
    psscan_unverified: Optional[bool] = Field(
        None,
        description=(
            "True when scan_processes ran without a matching pslist baseline. "
            "peer reviewer round-7 P2: replaces the prior false-positive of treating all "
            "psscan PIDs as hidden. Gate recomputes the delta when pslist later runs."
        ),
    )
    psscan_pids: list[int] = Field(
        default_factory=list,
        description=(
            "Full PID set observed by psscan; used by the report gate to recompute "
            "the psscan-pslist delta when both findings are available."
        ),
    )
    pslist_pids: list[int] = Field(
        default_factory=list,
        description=(
            "Full PID set observed by list_processes; pairs with psscan_pids for "
            "deferred DKOM detection in the report gate."
        ),
    )
    requires_deeper_analysis: Optional[bool] = Field(
        None,
        description="When true, memory follow-up tools (e.g. detect_injection) are required before final report.",
    )
    network_followup_pids: list[int] = Field(
        default_factory=list,
        description=(
            "PIDs with established non-loopback connections; use list_dlls for "
            "follow-up before final report."
        ),
    )
    dlllist_covered_pid: Optional[int] = Field(
        None,
        ge=0,
        description=(
            "PID a list_dlls finding actually examined. E.2 (peer reviewer round-1 P2): "
            "the report gate uses this to verify per-PID coverage instead of "
            "accepting any list_dlls execution as full coverage."
        ),
    )
    network_pids: list[int] = Field(
        default_factory=list,
        description=(
            "Plan/API alias for PIDs requiring list_dlls follow-up; mirrors "
            "network_followup_pids for external-connection findings."
        ),
    )
    next_required_tool: Optional[str] = Field(
        None,
        description=(
            "Suggested MCP tool to run next for this finding (e.g. detect_injection, "
            "list_dlls) when coverage gates require follow-up."
        ),
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
    def _coerce_auto_id(cls, v: object) -> Optional[str]:
        """Normalize supplied IDs without allocating process-local IDs."""
        if not v:
            return None
        return str(v)

    @field_validator("mitre_tactic")
    @classmethod
    def _validate_mitre_tactic(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not _MITRE_TACTIC_RE.fullmatch(normalized):
            raise ValueError("mitre_tactic must match TA#### when present.")
        return normalized

    @field_validator("mitre_technique")
    @classmethod
    def _validate_mitre_technique(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not _MITRE_TECHNIQUE_RE.fullmatch(normalized):
            raise ValueError("mitre_technique must match T#### or T####.### when present.")
        return normalized

    @field_validator("raw_evidence_refs", mode="before")
    @classmethod
    def _normalize_raw_evidence_refs(cls, value: Any) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, (list, tuple)):
            raise ValueError("raw_evidence_refs must be a list of evidence-reference dicts.")

        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("Each raw_evidence_ref must be a dict.")
            path = str(item.get("path") or "").strip()
            if not path:
                raise ValueError("raw_evidence_refs items must include a non-empty path.")
            role = str(item.get("role") or "").strip().lower()
            if role not in _RAW_EVIDENCE_REF_ROLES:
                raise ValueError(
                    "raw_evidence_refs.role must be one of input, output, derived, handle."
                )
            offset = item.get("offset")
            offset_text = "" if offset in (None, "") else str(offset).strip()
            hash_status = str(item.get("hash_status") or "").strip()
            key = (path, role, offset_text, hash_status)
            if key in seen:
                continue
            seen.add(key)
            ref: dict[str, Any] = {"path": path, "role": role}
            if offset_text:
                ref["offset"] = offset_text
            if hash_status:
                ref["hash_status"] = hash_status
            normalized.append(ref)
        return normalized

    @model_validator(mode="after")
    def _validate_observation_has_offset_or_path(self) -> "Finding":
        """OBSERVATION findings SHOULD reference an artifact path.

        Run-11 fix (2026-05-29): expanded error message — operator's debrief
        noted the rule was surfaced only at submit time after the agent had
        already authored the full payload. Hint at the INFERENCE alternative
        when the finding describes derived/aggregate analysis (which doesn't
        bind to a single artifact).
        """
        if self.evidence_kind == EvidenceKind.OBSERVATION and not self.artifact_path:
            raise ValueError(
                "OBSERVATION findings must include artifact_path "
                "(the single evidence file/CSV/hive the observation came from). "
                "If your finding is derived from multiple artifacts or is an "
                "aggregate/cross-source inference, use evidence_kind=INFERENCE "
                "instead and populate corroborated_by with the source finding IDs."
            )
        return self

    model_config = {"validate_assignment": True}
