"""hypothesis.py - Pydantic schema for LLM-formed investigation hypotheses.

W1.7 (CR13 Option X): persistence target for the agent's hypothesis-formation
step. The LLM forms 2-5 ranked hypotheses from prepare_hypothesis_context's
bundle; record_hypotheses persists them via this schema for audit and
follow-on pivot iteration.

Design constraint (CR13-3): MCP must NOT pretend to do the thinking.
The Hypothesis schema is a STRUCTURED CONTAINER for LLM-emitted analysis,
not a planner that generates hypotheses itself. Python validates shape and
provenance; the LLM authors the content.
"""
from __future__ import annotations

import re
import time
import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# ULID re-use (same format as EvidenceFinding)
# ---------------------------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_RE = re.compile(r"^[0-9A-HJKMNPQRSTVWXYZ]{26}$")
_CTX_RE = re.compile(r"^CTX-\d{3,}$")


def _encode_crockford(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def generate_hypothesis_id() -> str:
    """ULID-format hypothesis ID (26 chars, sortable by time)."""
    ts_ms = int(time.time() * 1000)
    rand = int.from_bytes(uuid.uuid4().bytes[:10], "big")
    return _encode_crockford(ts_ms, 10) + _encode_crockford(rand, 16)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class HypothesisStatus(str, Enum):
    """Lifecycle for an LLM-formed hypothesis.

    ACTIVE → newly emitted, awaiting investigation
    INVESTIGATING → main agent has begun pivots against it
    CONFIRMED → evidence chain converges. GATED (review 2026-06-05):
                a CONFIRMED verdict is only accepted when >=1 linked finding is
                itself CONFIRMED with multi-source corroboration (the same
                finding-level multi-source bar). Otherwise it is downgraded to
                SUSPENDED by apply_hypothesis_status_gate. Verdict status is NOT
                pure agent judgment.
    REFUTED → evidence contradicts (CorrectionEvent path). Absence-based
                refutation is valid, but a REFUTED verdict linking to a
                multi-source-CONFIRMED finding is downgraded to SUSPENDED.
    SUSPENDED → blocked on missing data / artifact unavailable, OR a verdict
                that did not clear the gate above.
    """
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    SUSPENDED = "SUSPENDED"


class HypothesisPivotType(str, Enum):
    """Diamond Model pivot edge - for adaptive pivot suggestions.

    From threat-hunting research (notebook #43):
    Victim ↔ Capability ↔ Infrastructure ↔ Adversary
    """
    VICTIM_TO_CAPABILITY = "victim_to_capability"
    CAPABILITY_TO_INFRASTRUCTURE = "capability_to_infrastructure"
    INFRASTRUCTURE_TO_VICTIM = "infrastructure_to_victim"
    INFRASTRUCTURE_TO_ADVERSARY = "infrastructure_to_adversary"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    OCCURRENCE_STACKING = "occurrence_stacking"
    KNOWN_GOOD_FILTER = "known_good_filter"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Hypothesis schema
# ---------------------------------------------------------------------------

class Hypothesis(BaseModel):
    """One LLM-formed investigation hypothesis.

    The bundle returned by prepare_hypothesis_context lets the LLM emit
    2-5 ranked hypotheses. The user-facing report shows their disposition
    (CONFIRMED / REFUTED / SUSPENDED) at end of investigation.
    """

    # Identity
    hypothesis_id: str = Field(default_factory=generate_hypothesis_id)
    timestamp: Optional[str] = Field(default=None)

    # Core content (LLM-authored)
    attack_class: str = Field(
        ...,
        min_length=4,
        description=(
            "Concise label for the hypothesized attack pattern, e.g.,"
            "'credential-theft via LSASS access', 'lateral movement via SMB',"
            "'ransomware staging + shadow copy deletion'."
        ),
    )
    initial_pivot: str = Field(
        ...,
        min_length=4,
        description=(
            "The first artifact/indicator/query the agent will use to test"
            "this hypothesis. E.g., 'process tree around PID 1234',"
            "'EVTX 4624 Type 3 burst between 14:00-14:30', 'MFT entries in"
            "C:\\Windows\\Temp during attack window'."
        ),
    )
    expected_evidence_chain: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of evidence types that should appear IF this"
            "hypothesis is correct (Diamond Model Activity Thread phases)."
            "E.g., ['Prefetch first-run', 'EVTX 4688 process creation',"
            "'memory injected DLL', 'C2 network connection']."
        ),
    )

    # Provenance - which CTX bundle did the LLM use to form this?
    source_context_refs: list[str] = Field(
        default_factory=list,
        description=(
            "CTX-NNN audit IDs of the heuristic bundles the LLM consumed"
            "when forming this hypothesis. Court-defensible chain to the"
            "canonical .md heuristic source."
        ),
    )

    # Lifecycle
    status: HypothesisStatus = Field(default=HypothesisStatus.ACTIVE)
    rank: Optional[int] = Field(
        default=None,
        description="Rank among the 2-5 hypotheses formed in this session (1=highest priority).",
    )

    # Optional: associated findings + pivot suggestions
    related_finding_ids: list[str] = Field(
        default_factory=list,
        description="EvidenceFinding ULIDs that support OR refute this hypothesis.",
    )
    next_pivot_type: Optional[HypothesisPivotType] = Field(
        default=None,
        description="Suggested Diamond Model pivot for next iteration.",
    )

    # MITRE attribution (optional but encouraged)
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (T1XXX or T1XXX.NNN) associated with the hypothesized attack.",
    )

    # ----- Validators -----

    @field_validator("hypothesis_id")
    @classmethod
    def _validate_ulid(cls, v: str) -> str:
        if not _ULID_RE.match(v):
            raise ValueError(f"hypothesis_id must be a valid ULID, got: {v!r}")
        return v

    @field_validator("source_context_refs")
    @classmethod
    def _validate_ctx_refs(cls, v: list[str]) -> list[str]:
        for ref in v:
            if not _CTX_RE.match(ref):
                raise ValueError(
                    f"source_context_refs entries must match CTX-NNN format, got: {ref!r}"
                )
        return v

    @field_validator("mitre_techniques")
    @classmethod
    def _validate_mitre(cls, v: list[str]) -> list[str]:
        tech_re = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
        normalized = []
        for t in v:
            tu = t.strip().upper()
            if not tech_re.match(tu):
                raise ValueError(f"MITRE technique must be T1XXX or T1XXX.NNN, got: {t!r}")
            normalized.append(tu)
        return normalized

    @model_validator(mode="after")
    def _set_timestamp(self) -> "Hypothesis":
        if not self.timestamp:
            from datetime import datetime, timezone
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return self


__all__ = [
    "Hypothesis",
    "HypothesisStatus",
    "HypothesisPivotType",
    "generate_hypothesis_id",
]
