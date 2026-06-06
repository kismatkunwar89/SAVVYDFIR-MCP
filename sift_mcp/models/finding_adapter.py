"""finding_adapter.py - Map existing Finding dict to Section 3-lite EvidenceFinding.

Allows incremental migration: tools that produce findings via the old
Finding model can continue working while submit_finding writes BOTH the
old shape (state.json) AND the new EvidenceFinding shape (for the
hackathon-target audit trail and Mermaid DAG renderer).

The adapter handles:
  - Confidence float → enum bucketing (HIGH/MEDIUM/LOW/NULL)
  - Free-form description → claim (one sentence) + evidence_excerpt
  - Optional fields that the legacy Finding doesn't have:
    tool_input_hash, tool_output_hash, evidence_chain_parent
  - MITRE technique/tactic merge from legacy fields
  - finding_id legacy F-NNN preserved as alias; ULID generated for DAG

See the design plan Section 4.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from .evidence_finding import (
    Confidence,
    CorrectionEvent,
    EvidenceFinding,
    EvidenceFindingStatus,
    fence_evidence_content,
    generate_ulid,
    sha256_string,
)


# ---------------------------------------------------------------------------
# Confidence bucketing - float to enum
# ---------------------------------------------------------------------------

# Legacy float thresholds (calibrated to match existing finding distributions)
#   ≥ 0.90 → HIGH (corroborated by 2+ independent sources)
#   ≥ 0.60 → MEDIUM (one strong indicator or stacked weak indicators)
#   ≥ 0.10 → LOW (single weak indicator, observation only)
#    else  → NULL (not determined / contradicted)

def confidence_float_to_enum(value: Any) -> Confidence:
    """Bucket a free-form confidence value into the Section 3 enum.

    Accepts float (0.0-1.0), int, string (e.g., "high"), or Confidence.
    Returns the canonical Confidence enum.
    """
    if isinstance(value, Confidence):
        return value
    if isinstance(value, str):
        v = value.strip().upper()
        if v in {"HIGH", "MEDIUM", "MED", "LOW", "NULL", "NONE"}:
            if v == "MED":
                return Confidence.MEDIUM
            if v == "NONE":
                return Confidence.NULL
            return Confidence[v]
        # Try parsing as numeric string
        try:
            value = float(v)
        except ValueError:
            return Confidence.NULL
    try:
        f = float(value)
    except (TypeError, ValueError):
        return Confidence.NULL
    if f >= 0.90:
        return Confidence.HIGH
    if f >= 0.60:
        return Confidence.MEDIUM
    if f >= 0.10:
        return Confidence.LOW
    return Confidence.NULL


# ---------------------------------------------------------------------------
# Status mapping - legacy FindingStatus to EvidenceFindingStatus
# ---------------------------------------------------------------------------

_LEGACY_STATUS_MAP = {
    "ACTIVE": EvidenceFindingStatus.ACTIVE,
    "HYPOTHESIS": EvidenceFindingStatus.ACTIVE,
    "CONFIRMED": EvidenceFindingStatus.CONFIRMED,
    "REJECTED": EvidenceFindingStatus.REJECTED,
    "OBSERVATION": EvidenceFindingStatus.ACTIVE,
    "CORRECTED": EvidenceFindingStatus.CORRECTED,
}


def status_str_to_enum(value: Any) -> EvidenceFindingStatus:
    if isinstance(value, EvidenceFindingStatus):
        return value
    if value is None:
        return EvidenceFindingStatus.ACTIVE
    key = str(value).strip().upper()
    return _LEGACY_STATUS_MAP.get(key, EvidenceFindingStatus.ACTIVE)


# ---------------------------------------------------------------------------
# Claim / evidence_excerpt extraction from free-form description
# ---------------------------------------------------------------------------

def split_claim_and_evidence(description: str, max_claim_chars: int = 280) -> tuple[str, str]:
    """Split a free-form description into (one-sentence claim, evidence excerpt).

    Heuristic:
      - Claim = first sentence (terminated by . ! or ?) up to max_claim_chars
      - Evidence = full description (fenced)

    If description has no sentence terminator, claim = first max_claim_chars,
    evidence = full text (fenced).

    Both outputs are non-empty as long as input is non-empty.
    """
    desc = (description or "").strip()
    if not desc:
        return "Finding recorded without description.", fence_evidence_content("(no description)")

    # Find first sentence end
    end_chars = ".!?"
    first_end = -1
    for i, ch in enumerate(desc):
        if ch in end_chars and i > 5:
            first_end = i + 1
            break

    if first_end > 0 and first_end <= max_claim_chars:
        claim = desc[:first_end].strip()
    else:
        # No sentence terminator or claim too long; take first N chars
        claim = desc[:max_claim_chars].strip()
        if len(desc) > max_claim_chars:
            claim = claim.rstrip(".") + "."

    # Guarantee min length
    if len(claim) < 8:
        claim = (claim + " " + desc).strip()[:max_claim_chars]

    evidence_excerpt = fence_evidence_content(desc)
    return claim, evidence_excerpt


# ---------------------------------------------------------------------------
# Main adapter
# ---------------------------------------------------------------------------

def adapt_finding_to_evidence_finding(
    legacy: Mapping[str, Any],
    *,
    source_mcp_server: str = "savvydfir",
    fallback_source_tool: str = "state.add_finding",
    tool_input_hash: Optional[str] = None,
    tool_output_hash: Optional[str] = None,
    evidence_chain_parent: Optional[str] = None,
) -> EvidenceFinding:
    """Convert a legacy Finding dict (or model_dump) to an EvidenceFinding.

    Use during W1/W2 migration to populate Section 3 fields on every
    new finding without rewriting every tool. submit_finding calls this
    adapter and emits BOTH the legacy Finding (state.json) and the
    EvidenceFinding (audit DAG).

    Required input fields on `legacy`:
      - description OR claim (used to derive claim + evidence_excerpt)
      - tool_name OR source_tool (for source_tool)

    Optional input fields used when present:
      - confidence (float or string) → Confidence enum
      - finding_status → EvidenceFindingStatus
      - assigned_agent → specialist
      - artifact_path
      - mitre_technique / mitre_techniques (list or single string)
      - alternative_hypothesis → confidence_rationale (if HIGH)
      - contradicted_by → contradicts
      - corroborated_by → corroborates
      - execution_id → tool_input_hash fallback if no explicit hash given
    """
    # Required-ish: pick source_tool
    src_tool = (
        legacy.get("source_tool")
        or legacy.get("tool_name")
        or fallback_source_tool
    )

    # Derive claim + evidence excerpt from description or pre-set claim
    if legacy.get("claim"):
        claim = str(legacy["claim"]).strip()
        evidence_excerpt = legacy.get("evidence_excerpt") or fence_evidence_content(
            legacy.get("description") or claim
        )
    else:
        desc = str(legacy.get("description") or "").strip()
        claim, evidence_excerpt = split_claim_and_evidence(desc)

    # Confidence bucketing
    confidence = confidence_float_to_enum(legacy.get("confidence"))

    # Confidence rationale - promote alt-hypothesis info if HIGH
    rationale = (
        legacy.get("confidence_rationale")
        or legacy.get("evidence_against_it")
        or legacy.get("alternative_hypothesis")
    )
    if isinstance(rationale, list):
        rationale = "; ".join(str(r) for r in rationale if r)
    if rationale:
        rationale = str(rationale).strip() or None

    # If HIGH but no rationale, downgrade to MEDIUM to satisfy schema
    if confidence == Confidence.HIGH and not rationale:
        confidence = Confidence.MEDIUM

    # MITRE techniques - accept singular or list, normalize to list
    mitre = legacy.get("mitre_techniques") or legacy.get("mitre_technique") or []
    if isinstance(mitre, str):
        mitre = [mitre] if mitre else []
    elif not isinstance(mitre, list):
        mitre = []
    mitre = [str(t).strip().upper() for t in mitre if str(t).strip()]
    # Filter out invalid technique strings
    import re
    valid_re = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
    mitre = [t for t in mitre if valid_re.match(t)]

    # Status mapping
    status = status_str_to_enum(legacy.get("finding_status") or legacy.get("status"))

    # Specialist (from assigned_agent on legacy)
    specialist = legacy.get("assigned_agent") or legacy.get("specialist")
    if specialist == "main-agent" or specialist == "(unset)":
        specialist = None
    if specialist:
        specialist = str(specialist).strip() or None

    # Artifact + hashes (use provided values, fall back to legacy fields)
    artifact_path = legacy.get("artifact_path") or legacy.get("source_artifact")
    if tool_input_hash is None:
        # Fall back to a deterministic hash of execution_id if present
        eid = legacy.get("execution_id")
        if eid and isinstance(eid, str) and not eid.startswith(("E-000", "PLACEHOLDER")):
            tool_input_hash = sha256_string(f"execution_id={eid}")
    if tool_output_hash is None:
        # Fall back to hash of the description content (audit anchor)
        desc = str(legacy.get("description") or "")
        if desc:
            tool_output_hash = sha256_string(desc)

    # Graph edges - contradicted_by → contradicts (ULID validation will reject
    # legacy F-NNN format, so we omit them rather than fail validation)
    raw_contradicts = legacy.get("contradicted_by") or legacy.get("contradicts") or []
    raw_corroborates = legacy.get("corroborated_by") or legacy.get("corroborates") or []
    if not isinstance(raw_contradicts, list):
        raw_contradicts = [raw_contradicts]
    if not isinstance(raw_corroborates, list):
        raw_corroborates = [raw_corroborates]
    # Only include if they're already ULIDs (26 chars Crockford)
    import re as _re
    ulid_re = _re.compile(r"^[0-9A-HJKMNPQRSTVWXYZ]{26}$")
    contradicts = [c for c in raw_contradicts if isinstance(c, str) and ulid_re.match(c)]
    corroborates = [c for c in raw_corroborates if isinstance(c, str) and ulid_re.match(c)]

    # Build the EvidenceFinding (validation will run; structural enforcement)
    return EvidenceFinding(
        finding_id=generate_ulid(),  # new ULID; legacy F-NNN preserved separately
        source_mcp_server=source_mcp_server,
        source_tool=src_tool,
        specialist=specialist,
        artifact_path=artifact_path,
        tool_input_hash=tool_input_hash,
        tool_output_hash=tool_output_hash,
        claim=claim,
        evidence_excerpt=evidence_excerpt,
        confidence=confidence,
        confidence_rationale=rationale,
        mitre_techniques=mitre,
        evidence_chain_parent=evidence_chain_parent,
        contradicts=contradicts,
        corroborates=corroborates,
        status=status,
    )


__all__ = [
    "adapt_finding_to_evidence_finding",
    "confidence_float_to_enum",
    "status_str_to_enum",
    "split_claim_and_evidence",
]
