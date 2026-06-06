"""Deterministic semantic helpers for finding ingestion and coverage analysis."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Iterable, Literal, Optional

from sift_mcp.models.finding import EvidenceKind, Finding, FindingStatus
from sift_mcp.tool_catalog import artifact_families_for, tool_domain_for

_FK_CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    "shimcache": 0.70,
    "amcache": 0.75,
    "userassist": 0.72,
    "shellbag": 0.68,
    "mft_timestomp": 0.80,
    "registry_run": 0.85,
    "prefetch": 1.00,
    "evtx_process_creation": 1.00,
    "memory_process": 1.00,
    "sigma_corroborated": 1.05,
}

_FK_CORROBORATION_REQUIREMENTS: dict[str, list[str]] = {
    "shimcache": ["prefetch", "amcache", "evtx_process_creation"],
    "amcache": ["prefetch", "evtx_process_creation"],
    "userassist": ["prefetch", "amcache"],
    "shellbag": ["prefetch", "amcache"],
    "mft_timestomp": ["prefetch", "evtx_process_creation"],
    "registry_run": ["prefetch", "amcache", "evtx_process_creation"],
}


def _derive_execution_confidence(artifact_sources: set[str]) -> tuple[float, str]:
    """
    Determine execution confidence based on artifact combination.

    Professional hierarchy:
    - Observation (0.70): ShellBags, ShimCache, Amcache alone
    - Probable (0.85): Prefetch OR BAM/DAM
    - Definitive (1.00): Prefetch + EVTX 4688 + MFT
    - Stacked (1.00): 3+ independent sources

    Args:
        artifact_sources: Set of forensic source classes (e.g., {"prefetch", "evtx_process_creation", "mft"})

    Returns:
        (confidence: float, reasoning: str) tuple for audit trail
    """
    # Definitive execution (all three forensic pillars)
    if {"prefetch", "evtx_process_creation", "mft"}.issubset(artifact_sources):
        return (1.00, "definitive_execution_trinity")

    # Stacked evidence (3+ independent)
    if len(artifact_sources) >= 3:
        return (1.00, "stacked_evidence_3plus")

    # Probable execution (Prefetch or BAM/DAM registry keys)
    if "prefetch" in artifact_sources or "bam_dam" in artifact_sources:
        return (0.85, "probable_execution_prefetch")

    # Two independent sources
    if len(artifact_sources) == 2:
        return (0.80, "two_source_corroboration")

    # Single observation artifact
    if artifact_sources & {"shellbag", "shimcache", "amcache", "userassist"}:
        return (0.70, "observation_only_single_source")

    # Fallback for unknown sources
    return (0.65, "insufficient_evidence")


_TACTIC_CATALOG: list[tuple[str, str]] = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
    ("TA0042", "Resource Development"),
    ("TA0043", "Reconnaissance"),
]

_TACTIC_TOOL_SUGGESTIONS: dict[str, list[str]] = {
    "TA0001": ["disk.summarize_evtx", "memory.scan_network"],
    "TA0002": ["disk.extract_prefetch", "disk.summarize_evtx"],
    "TA0003": ["disk.extract_registry_run_keys", "disk.extract_shimcache", "disk.extract_pca"],
    "TA0004": ["disk.summarize_evtx", "memory.scan_processes"],
    "TA0005": ["disk.extract_mft_timeline", "memory.detect_injection", "detection.sigma_hunt"],
    "TA0006": ["disk.extract_shimcache", "disk.get_amcache", "disk.summarize_evtx"],
    "TA0007": ["memory.scan_processes", "memory.list_dlls", "timeline.query_timeline"],
    "TA0008": ["disk.summarize_evtx", "memory.scan_network", "timeline.query_timeline"],
    "TA0009": ["disk.extract_prefetch", "disk.get_amcache", "memory.scan_processes"],
    "TA0010": ["disk.extract_srum", "memory.scan_network", "timeline.query_timeline"],
    "TA0011": ["memory.scan_network", "memory.detect_injection", "detection.sigma_hunt"],
    "TA0040": ["disk.summarize_evtx", "memory.detect_injection", "timeline.query_timeline"],
    "TA0042": ["disk.get_amcache", "disk.extract_prefetch", "timeline.query_timeline"],
    "TA0043": ["disk.summarize_evtx", "memory.scan_network", "timeline.query_timeline"],
}

_ADAPTIVE_EVTX_BASE_EIDS: set[int] = {4624, 4625, 4648, 4688, 4689}

_CANONICAL_ARTIFACT_TYPES = {"disk", "memory", "correlation", "timeline", "yara"}
_ARTIFACT_TYPE_ALIASES: dict[str, str] = {
    "file_system": "disk",
    "filesystem": "disk",
    "evtx": "disk",
    "evtx_event": "disk",
    "event_log": "disk",
    "eventlog": "disk",
    "mft": "disk",
    "mft_entry": "disk",
    "prefetch": "disk",
    "prefetch_record": "disk",
    "amcache": "disk",
    "shimcache": "disk",
    "userassist": "disk",
    "shellbag": "disk",
    "registry": "disk",
    "registry_key": "disk",
    "persistence": "disk",
    "pca": "disk",
    "vss": "disk",
    "srum": "disk",
    "process": "memory",
    "process_tree": "memory",
    "network": "memory",
    "network_connection": "memory",
    "dll": "memory",
    "injection": "memory",
}
_EVIDENCE_KIND_ALIASES: dict[str, str] = {
    "observation": EvidenceKind.OBSERVATION.value,
    "disk_artifact": EvidenceKind.OBSERVATION.value,
    "memory_artifact": EvidenceKind.OBSERVATION.value,
    "timeline_artifact": EvidenceKind.OBSERVATION.value,
    "yara_artifact": EvidenceKind.OBSERVATION.value,
    "inference": EvidenceKind.INFERENCE.value,
    "correlation": EvidenceKind.INFERENCE.value,
    "hypothesis": EvidenceKind.HYPOTHESIS.value,
    "rejected": EvidenceKind.REJECTED.value,
}
_LEGACY_STATUS_TO_EVIDENCE_KIND: dict[str, str] = {
    "observation": EvidenceKind.OBSERVATION.value,
    "inference": EvidenceKind.INFERENCE.value,
    "hypothesis": EvidenceKind.HYPOTHESIS.value,
}
_SOURCE_CLASS_TO_ARTIFACT_FAMILY: dict[str, str] = {
    "shimcache": "disk",
    "amcache": "disk",
    "userassist": "disk",
    "shellbag": "disk",
    "mft_timestomp": "disk",
    "registry_run": "disk",
    "prefetch": "disk",
    "evtx_process_creation": "disk",
    "memory_process": "memory",
    "sigma_corroborated": "yara",
}
_SOURCE_CLASS_TO_TOOL_FAMILY: dict[str, str] = {
    "shimcache": "disk",
    "amcache": "disk",
    "userassist": "disk",
    "shellbag": "disk",
    "mft_timestomp": "disk",
    "registry_run": "disk",
    "prefetch": "disk",
    "evtx_process_creation": "disk",
    "memory_process": "memory",
    "sigma_corroborated": "detection",
}


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _normalize_whitespace(value: Any) -> str:
    return re.sub(r"\s+", " ", _to_text(value)).strip()


def _normalize_status(value: Any) -> str:
    text = _normalize_whitespace(value)
    return text.upper() if text else FindingStatus.ACTIVE.value.upper()


def _normalize_lower_token(value: Any) -> str:
    return _normalize_whitespace(value).lower()


def _normalize_indicator_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return _unique_preserve(
            _normalize_whitespace(item) for item in value if _normalize_whitespace(item)
        )
    normalized = _normalize_whitespace(value)
    return [normalized] if normalized else []


def _unique_preserve(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = _normalize_whitespace(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _normalized_path_token(value: str) -> str:
    token = value.strip().strip("\"'").replace("/", "\\").lower()
    while "\\\\" in token:
        token = token.replace("\\\\", "\\")
    return token


def _basename(value: str) -> str:
    token = _normalized_path_token(value)
    token = token.rstrip("\\/")
    if not token:
        return ""
    parts = re.split(r"[\\/]", token)
    return parts[-1] if parts else token


def _infer_artifact_family_from_tool(tool_name: Any) -> Optional[str]:
    text = _normalize_lower_token(tool_name)
    if not text:
        return None
    if text.startswith("memory."):
        return "memory"
    if text.startswith("timeline."):
        return "timeline"
    if text.startswith("correlation."):
        return "correlation"
    if text.startswith("detection.") or "yara" in text:
        return "yara"
    if text.startswith("disk."):
        return "disk"
    return None


def _canonicalize_artifact_type(value: Any, tool_name: Any) -> tuple[str, Optional[str]]:
    token = _normalize_lower_token(value)
    if token in _CANONICAL_ARTIFACT_TYPES:
        return token, None
    if token in _ARTIFACT_TYPE_ALIASES:
        return _ARTIFACT_TYPE_ALIASES[token], token
    inferred = _infer_artifact_family_from_tool(tool_name)
    if inferred and token:
        return inferred, token
    if inferred:
        return inferred, None
    supported = ", ".join(sorted(_CANONICAL_ARTIFACT_TYPES))
    aliases = ", ".join(sorted(_ARTIFACT_TYPE_ALIASES))
    raise ValueError(
        f"Unsupported artifact_type {value!r}. "
        f"valid_artifact_types=[{supported}]; supported_aliases=[{aliases}]"
    )


# Canonical artifact_subtype values recoverable from a staged artifact path.
# Spelling matches what _canonicalize_artifact_type + existing tests assert
# (e.g. staged dir "evtx" -> subtype "evtx", NOT "evtx_event"). Allowlist-
# gated so an unrecognised dir name never produces a bogus subtype.
_PATH_SUBTYPE_CANONICAL = {
    "mft": "mft",
    "usn": "usn",
    "evtx": "evtx",
    "prefetch": "prefetch",
    "amcache": "amcache",
    "shimcache": "shimcache",
    "registry": "registry",
    "pca": "pca",
    "srum": "srum",
    "vss": "vss",
    "sigma": "sigma",
    "hayabusa": "hayabusa",
}

# Framework staging contract: extraction tools write artifacts to
# /cases/<case_id>/artifacts/<subtype>/...  (with an optional raw/ intermediate
# for raw evidence). The <subtype> dir name is authoritative. Matches the raw
# /cases/... path AND a graph-redacted <case-dir>/... path, since only the
# /artifacts/<subtype>/ segment is needed.
_ARTIFACTS_PATH_RE = re.compile(r"/artifacts/(?:raw/)?([a-z0-9_]+)(?:/|$)")

# Extraction tool name -> canonical subtype. Recovers subtype for AUTO-GENERATED
# disk findings that arrive with artifact_type="disk" already canonical (so
# _canonicalize_artifact_type returns no subtype) but carry the producing
# extractor in tool_name (e.g. "disk.extract_registry_run_keys"). Spelling
# matches _PATH_SUBTYPE_CANONICAL so both derives agree (
# 2026-05-30). The category prefix ("disk."/"memory.") is stripped before lookup.
_TOOL_NAME_TO_SUBTYPE = {
    "extract_mft_timeline": "mft",
    "extract_usn_journal": "usn",
    "summarize_evtx": "evtx",
    "extract_prefetch": "prefetch",
    "get_amcache": "amcache",
    "extract_shimcache": "shimcache",
    "extract_registry_run_keys": "registry",
    "extract_pca": "pca",
    "extract_srum": "srum",
    "analyze_vss": "vss",
    "sigma_hunt": "sigma",
    "hayabusa_hunt": "hayabusa",
}


def _derive_artifact_subtype_from_tool(tool_name: Any) -> Optional[str]:
    """Recover a canonical artifact_subtype from the producing tool name.

    For auto-generated disk findings whose artifact_type is already canonical
    "disk" (so _canonicalize_artifact_type skips tool-name inference). Strips
    the "disk."/"memory." category prefix, then maps the bare extractor name.
    Allowlist-gated; returns None for unknown tools (stays blank, never guessed).
    """
    text = _normalize_whitespace(tool_name).lower()
    if not text:
        return None
    if "." in text:
        text = text.split(".")[-1]
    return _TOOL_NAME_TO_SUBTYPE.get(text)


def _derive_artifact_subtype_from_path(artifact_path: Any) -> Optional[str]:
    """Recover a canonical artifact_subtype from a staged artifact_path.

    Used as a LAST-RESORT fallback for analyst-submitted findings
    (tool_name="state.submit_finding") that set artifact_type="disk" and an
    artifact_path like ``/cases/<id>/artifacts/mft/mft_timeline.csv`` but leave
    artifact_subtype blank. The staging-dir name is the framework's authoritative
    subtype signal (tier-1 only; no filename-keyword heuristics - ).

    Returns the canonical subtype string, or None when the path has no
    recognised ``/artifacts/<kind>/`` segment (kept blank, never guessed).
    """
    text = _normalize_whitespace(artifact_path).replace("\\", "/").lower()
    if not text:
        return None
    match = _ARTIFACTS_PATH_RE.search(text)
    if match:
        return _PATH_SUBTYPE_CANONICAL.get(match.group(1))
    return None


# Memory tool -> coarse source family (peer reviewer allowlist, G1 fix 2026-06-04).
# Memory findings have artifact_type="memory" with no subtype; map the producing
# Volatility tool to process/network so a memory burst can register as a distinct
# clustering source instead of collapsing into one "memory" bucket.
_MEMORY_TOOL_TO_SOURCE = {
    "list_processes": "process",
    "scan_processes": "process",
    "detect_injection": "process",
    "list_dlls": "process",
    "detect_profile": "process",
    "load_memory": "process",
    "scan_network": "network",
}


def resolve_cluster_source_family(finding: dict[str, Any]) -> Optional[str]:
    """Resolve a finding's FINE source family for temporal-cluster diversity.

    G1 fix (review 2026-06-04): find_temporal_clusters previously keyed
    cluster sources on the COARSE artifact_type (disk/memory/correlation), so a
    burst of 30 disk findings from MFT+USN+Prefetch+Amcache+Registry collapsed to
    ONE source and could never satisfy min_sources>=2. This resolver derives the
    fine family using ONLY existing allowlisted signals - no free-text token
    scraping - in priority order:
      1. explicit artifact_subtype
      2. producing tool name (disk extractors + memory tools)
      3. staged artifact_path /artifacts/<subtype>/
      4. coarse artifact_type fallback
    Returns None only when nothing resolves.
    """
    sub = _normalize_whitespace(finding.get("artifact_subtype")).lower()
    if sub:
        return sub
    fam = _derive_artifact_subtype_from_tool(finding.get("tool_name"))
    if fam:
        return fam
    tn = _normalize_whitespace(finding.get("tool_name")).lower()
    if "." in tn:
        tn = tn.split(".")[-1]
    if tn in _MEMORY_TOOL_TO_SOURCE:
        return _MEMORY_TOOL_TO_SOURCE[tn]
    fam = _derive_artifact_subtype_from_path(finding.get("artifact_path"))
    if fam:
        return fam
    at = _normalize_whitespace(finding.get("artifact_type")).lower()
    return at or None


def _canonicalize_evidence_kind(value: Any) -> str:
    token = _normalize_lower_token(value)
    if not token:
        return EvidenceKind.OBSERVATION.value
    if token in _EVIDENCE_KIND_ALIASES:
        return _EVIDENCE_KIND_ALIASES[token]
    raise ValueError(f"Unsupported evidence_kind {value!r}.")


def _canonicalize_finding_status(value: Any) -> str:
    token = _normalize_lower_token(value)
    if not token:
        return FindingStatus.ACTIVE.value
    if token in {status.value for status in FindingStatus}:
        return token
    raise ValueError(f"Unsupported finding_status {value!r}.")


def _normalize_lifecycle_fields(finding: dict[str, Any]) -> tuple[str, str]:
    legacy_status = finding.get("finding_status")
    if "status" in finding and "finding_status" not in finding:
        legacy_status = finding.get("status")
    evidence_token = finding.get("evidence_kind")
    legacy_status_token = _normalize_lower_token(legacy_status)

    if legacy_status_token in _LEGACY_STATUS_TO_EVIDENCE_KIND:
        current_kind = _EVIDENCE_KIND_ALIASES.get(
            _normalize_lower_token(evidence_token),
            _normalize_lower_token(evidence_token),
        )
        if not current_kind or current_kind == EvidenceKind.OBSERVATION.value:
            evidence_token = _LEGACY_STATUS_TO_EVIDENCE_KIND[legacy_status_token]
        legacy_status_token = FindingStatus.ACTIVE.value

    evidence_kind = _canonicalize_evidence_kind(evidence_token)
    finding_status = _canonicalize_finding_status(legacy_status_token)
    return evidence_kind, finding_status


def _tool_family_from_token(value: Any) -> Optional[str]:
    text = _normalize_lower_token(value)
    if not text:
        return None
    catalog_domain = tool_domain_for(text)
    if catalog_domain:
        return catalog_domain
    if text in _SOURCE_CLASS_TO_TOOL_FAMILY:
        return _SOURCE_CLASS_TO_TOOL_FAMILY[text]
    if "." in text:
        return text.split(".", 1)[0]
    if ":" in text:
        return text.split(":", 1)[0]
    return None


def _artifact_families_from_token(value: Any) -> list[str]:
    text = _normalize_lower_token(value)
    if not text:
        return []
    catalog_families = artifact_families_for(text)
    if catalog_families:
        return catalog_families
    if text in _CANONICAL_ARTIFACT_TYPES:
        return [text]
    if text in _SOURCE_CLASS_TO_ARTIFACT_FAMILY:
        return [_SOURCE_CLASS_TO_ARTIFACT_FAMILY[text]]
    if text in _ARTIFACT_TYPE_ALIASES:
        return [_ARTIFACT_TYPE_ALIASES[text]]
    inferred = _infer_artifact_family_from_tool(text)
    return [inferred] if inferred else []


def _normalize_support_lists(finding: dict[str, Any]) -> None:
    for field_name in (
        "contradicted_by",
        "corroborated_by",
        "related_finding_ids",
        "supporting_indicators",
        "corroboration_outstanding",
        "supporting_tool_families",
        "supporting_artifact_families",
    ):
        finding[field_name] = _normalize_indicator_list(finding.get(field_name))


def _derive_supporting_tool_families(finding: dict[str, Any]) -> list[str]:
    values: list[Any] = [finding.get("tool_name")]
    values.extend(finding.get("corroborated_by", []))
    values.extend(finding.get("corroboration_outstanding", []))
    values.append(finding.get("corroboration_completed_by"))
    existing = finding.get("supporting_tool_families", [])
    values.extend(existing if isinstance(existing, list) else [existing])
    return _unique_preserve(
        family for token in values if (family := _tool_family_from_token(token))
    )


def _derive_supporting_artifact_families(finding: dict[str, Any]) -> list[str]:
    values: list[Any] = [
        finding.get("artifact_type"),
        finding.get("artifact_subtype"),
        finding.get("tool_name"),
    ]
    values.extend(finding.get("corroborated_by", []))
    values.extend(finding.get("corroboration_outstanding", []))
    values.append(finding.get("corroboration_completed_by"))
    existing = finding.get("supporting_artifact_families", [])
    values.extend(existing if isinstance(existing, list) else [existing])
    families: list[str] = []
    for token in values:
        families.extend(_artifact_families_from_token(token))
    return _unique_preserve(families)


def _derive_promotion_eligibility(finding: dict[str, Any]) -> str:
    status = _normalize_lower_token(finding.get("finding_status"))
    if status == FindingStatus.CONFIRMED.value:
        return "confirmed"
    if status == FindingStatus.REJECTED.value:
        return "rejected"
    if finding.get("contradicted_by"):
        return "blocked_by_contradiction"
    if finding.get("corroboration_outstanding"):
        return "needs_corroboration"
    if finding.get("corroborated_by"):
        return "eligible"
    return "direct"


def _derive_confidence_support_inputs(
    finding: dict[str, Any],
    *,
    original_confidence: Optional[float] = None,
    applied_multiplier: Optional[float] = None,
) -> dict[str, Any]:
    existing = finding.get("confidence_support_inputs")
    merged = dict(existing) if isinstance(existing, dict) else {}
    merged.update(
        {
            "supporting_indicator_count": len(finding.get("supporting_indicators", [])),
            "corroboration_count": len(finding.get("corroborated_by", [])),
            "contradiction_count": len(finding.get("contradicted_by", [])),
            "supporting_tool_families": list(finding.get("supporting_tool_families", [])),
            "supporting_artifact_families": list(
                finding.get("supporting_artifact_families", [])
            ),
        }
    )
    if finding.get("artifact_subtype"):
        merged["artifact_subtype"] = finding["artifact_subtype"]
    if finding.get("fk_source_class"):
        merged["fk_source_class"] = finding["fk_source_class"]
    if applied_multiplier is not None:
        merged["fk_multiplier"] = round(applied_multiplier, 3)
    if original_confidence is not None:
        merged["base_confidence"] = round(float(original_confidence), 3)
    if "confidence" in finding:
        try:
            merged["effective_confidence"] = round(float(finding.get("confidence", 0.0)), 3)
        except (TypeError, ValueError):
            pass
    if finding.get("corroboration_outstanding"):
        merged["required_corroboration"] = list(finding["corroboration_outstanding"])
    if finding.get("corroboration_completed_by"):
        merged["completed_corroboration"] = [finding["corroboration_completed_by"]]
    if finding.get("promotion_eligibility"):
        merged["promotion_eligibility"] = finding["promotion_eligibility"]
    return merged


def _build_model_input(
    normalized: dict[str, Any],
    *,
    fallback_finding_id: str,
    fallback_execution_id: str,
) -> dict[str, Any]:
    model_input = dict(normalized)
    model_input["finding_id"] = _normalize_whitespace(
        normalized.get("finding_id") or fallback_finding_id
    )
    model_input["execution_id"] = _normalize_whitespace(
        normalized.get("execution_id") or fallback_execution_id
    )
    model_input["evidence_kind"] = _canonicalize_evidence_kind(normalized.get("evidence_kind"))
    model_input["finding_status"] = _canonicalize_finding_status(
        normalized.get("finding_status")
    )
    return model_input


def _execution_id_resolvable(
    finding: dict[str, Any], state_manager: Any
) -> tuple[bool, str]:
    """Tier-A1 gate - strict.

    Return (ok, reason) - True ONLY when the finding's execution_id
    resolves to an auditable execution record in the current evidence
    ledger. The ``requires_re_extraction`` flag is a STATE marker
    describing why a finding is non-CONFIRMED - it is NOT a bypass.
    Operator override happens at the report layer (allow_partial=True),
    not at the finding layer.

    Non-resolvable cases (return False):
      * execution_id is missing, empty, or "E-000" placeholder
      * confidence_support_inputs marks execution_id_source as auto-generated
      * state_manager.get_execution(eid) returns None
    """
    eid = _normalize_whitespace(finding.get("execution_id"))
    if not eid or eid == "E-000":
        return False, "execution_id_missing_or_placeholder"

    support_inputs = finding.get("confidence_support_inputs") or {}
    if isinstance(support_inputs, dict):
        if support_inputs.get("execution_id_source") == "state_autogenerated":
            return False, "execution_id_autogenerated_no_audit_link"

    if state_manager is None:
        # No ledger context available (e.g., migration mode, isolated unit
        # test). Accept here - the reporting-layer gate is the second
        # line of defense before the report is written.
        return True, "no_state_manager_context"

    try:
        record = state_manager.get_execution(eid)
    except Exception:
        return True, "state_manager_unavailable"

    if record is None:
        return False, f"execution_id_unresolvable:{eid}"

    return True, "ok"


def _alternative_hypothesis_complete(
    finding: dict[str, Any],
) -> tuple[bool, str]:
    """Tier-A2 gate.

    Return (ok, reason) - True when the finding has populated structured
    alternative-hypothesis fields sufficient for a CONFIRMED state.

    Acceptable shapes:
      * disposition='ruled_out' AND alternative_hypothesis non-empty
        AND evidence_against_it has >=1 entry
      * disposition='not_applicable' AND
        alternative_hypothesis_not_applicable_reason non-empty

    Rejected shapes (return False):
      * empty disposition
      * disposition='not_resolved' or 'partially_plausible' (unresolved
        alternative must downgrade per )
    """
    disposition = _normalize_whitespace(finding.get("disposition"))
    if disposition == "ruled_out":
        alt = _normalize_whitespace(finding.get("alternative_hypothesis"))
        against = finding.get("evidence_against_it") or []
        if not alt:
            return False, "alternative_hypothesis_text_missing"
        if not isinstance(against, list) or len(against) == 0:
            return False, "evidence_against_it_empty"
        return True, "ok"
    if disposition == "not_applicable":
        reason = _normalize_whitespace(
            finding.get("alternative_hypothesis_not_applicable_reason")
        )
        if not reason:
            return False, "not_applicable_reason_missing"
        return True, "ok"
    if disposition in ("not_resolved", "partially_plausible"):
        return False, f"disposition_unresolved:{disposition}"
    return False, "disposition_empty"


def _satisfied_source_classes(finding: dict[str, Any], state_manager: Any = None) -> set[str]:
    """Lowercased set of source classes already corroborating this finding.

    Source-aware (review 2026-06-05): a raw source-class token in
    corroborated_by (e.g. 'prefetch', 'evtx_process_creation' from the promoter
    path) counts directly; an F-NNN finding id is RESOLVED via state to the cited
    finding's fk_source_class. Unresolvable ids do NOT clear a requirement
    (fail-safe — opaque ids cannot satisfy FK corroboration). corroboration_
    completed_by counts too. Used by the FK auto-populate subtraction AND the A3
    CONFIRMED gate so a genuine 2+-source stack clears its outstanding.
    """
    satisfied: set[str] = set()
    for item in _normalize_indicator_list(finding.get("corroborated_by")):
        token = _to_text(item).lower()
        if not token:
            continue
        if not token.startswith("f-"):
            satisfied.add(token)  # raw source-class token (e.g. "prefetch")
            continue
        if state_manager is None:
            continue  # cannot resolve the id -> fail-safe, do not clear
        try:
            other = state_manager.get_finding(item)
        except Exception:
            other = None
        if isinstance(other, dict):
            sc = other.get("fk_source_class") or classify_fk_source(other)
            if sc:
                satisfied.add(_to_text(sc).lower())
    completed = _to_text(finding.get("corroboration_completed_by")).lower()
    if completed:
        satisfied.add(completed)
    return satisfied


def _apply_confirmed_gates(
    normalized: dict[str, Any], state_manager: Any
) -> dict[str, Any]:
    """combined Tier-A1 + Tier-A2 gate.

    If the incoming finding is CONFIRMED but fails either gate, demote
    to ACTIVE, set ``requires_re_extraction`` for the provenance case,
    and record the gate reason(s) in confidence_support_inputs so the
    operator/agent sees why promotion was blocked.

    Returns the (possibly modified) normalized dict.
    """
    status = _normalize_status(normalized.get("finding_status"))
    confirmed_label = FindingStatus.CONFIRMED.value.upper()
    if status != confirmed_label:
        return normalized

    gate_failures: list[str] = []
    prov_ok, prov_reason = _execution_id_resolvable(normalized, state_manager)
    if not prov_ok:
        gate_failures.append(f"provenance:{prov_reason}")
    alt_ok, alt_reason = _alternative_hypothesis_complete(normalized)
    if not alt_ok:
        gate_failures.append(f"alternative_hypothesis:{alt_reason}")
    # Tier-A3 (integrity fix, review 2026-06-05): a finding that still has
    # UNSATISFIED corroboration cannot be CONFIRMED -- it is self-contradictory
    # ("still needs X" vs "confirmed"). This closes the manufacturing hole where a
    # finding flagged corroboration_outstanding=[prefetch, amcache, ...] was
    # nonetheless labeled CONFIRMED (F-061). Source-aware: a genuine 2+-source
    # stack whose corroborated_by covers the outstanding sources clears it (so real
    # CONFIRMED, incl ROCBA F-102/103/104 and any analyst-built stack, are
    # untouched); only GENUINELY-uncorroborated single-source CONFIRMED demote.
    outstanding = normalized.get("corroboration_outstanding")
    if isinstance(outstanding, (list, tuple)) and len(outstanding) > 0:
        satisfied = _satisfied_source_classes(normalized, state_manager)
        effective = [o for o in outstanding if _to_text(o).lower() not in satisfied]
        if effective:
            gate_failures.append(
                "corroboration_outstanding:" + ",".join(str(x) for x in effective)
            )

    if not gate_failures:
        return normalized

    # Demote to ACTIVE and record why. Do NOT silently keep CONFIRMED.
    normalized["finding_status"] = FindingStatus.ACTIVE.value.upper()
    if any(f.startswith("provenance:") for f in gate_failures):
        normalized["requires_re_extraction"] = True
    support_inputs = normalized.get("confidence_support_inputs") or {}
    if not isinstance(support_inputs, dict):
        support_inputs = {}
    existing_blocks = list(support_inputs.get("confirmed_gate_blocks") or [])
    for reason in gate_failures:
        if reason not in existing_blocks:
            existing_blocks.append(reason)
    support_inputs["confirmed_gate_blocks"] = existing_blocks
    normalized["confidence_support_inputs"] = support_inputs
    return normalized


def _finding_is_multisource_confirmed(
    finding: dict[str, Any], state_manager: Any = None
) -> bool:
    """True iff a finding is CONFIRMED *and* cleared the multi-source bar - the
    same bar ``_apply_confirmed_gates`` enforces: finding_status CONFIRMED, >=2
    corroborating sources, and no UNSATISFIED ``corroboration_outstanding``
    (source-aware). Used by the hunting-hypothesis verdict gate so a hypothesis
    inherits the finding-level corroboration standard."""
    if not isinstance(finding, dict):
        return False
    if _normalize_status(finding.get("finding_status")) != FindingStatus.CONFIRMED.value.upper():
        return False
    if len(_normalize_indicator_list(finding.get("corroborated_by"))) < 2:
        return False
    outstanding = finding.get("corroboration_outstanding")
    if isinstance(outstanding, (list, tuple)) and len(outstanding) > 0:
        satisfied = _satisfied_source_classes(finding, state_manager)
        effective = [o for o in outstanding if _to_text(o).lower() not in satisfied]
        if effective:
            return False
    return True


def apply_hypothesis_status_gate(
    hypothesis: dict[str, Any], state_manager: Any = None
) -> dict[str, Any]:
    """Integrity gate for hunting-hypothesis verdicts (review 2026-06-05).

    Findings get the multi-source CONFIRMED gate (``_apply_confirmed_gates``);
    hypotheses previously got only Pydantic shape-validation, so an agent could
    stamp a hypothesis CONFIRMED on its own judgment - the same gaming hole,
    relocated. This gate closes it:

    - A ``CONFIRMED`` verdict requires >=1 linked finding that is itself
      CONFIRMED with multi-source corroboration. Otherwise -> ``SUSPENDED``.
    - A ``REFUTED`` verdict that links to a finding which is itself multi-source
      CONFIRMED (attack evidence IS present) is self-contradictory -> ``SUSPENDED``.
      Absence-based refutation (no supporting findings) is legitimate and kept.
    - ``ACTIVE`` / ``INVESTIGATING`` / ``SUSPENDED`` need no gate.

    A downgrade records an auditable ``status_gate_reason``. Returns a (possibly
    modified) COPY; never mutates the input.
    """
    if not isinstance(hypothesis, dict):
        return hypothesis
    h = dict(hypothesis)
    status = str(h.get("status") or "ACTIVE").upper()
    if status not in ("CONFIRMED", "REFUTED"):
        return h

    linked = h.get("related_finding_ids")
    linked = linked if isinstance(linked, list) else ([linked] if linked else [])
    resolved: list[dict[str, Any]] = []
    for fid in linked:
        if not fid or state_manager is None:
            continue
        try:
            f = state_manager.get_finding(str(fid))
        except Exception:
            f = None
        if isinstance(f, dict):
            resolved.append(f)

    supports_attack = any(
        _finding_is_multisource_confirmed(f, state_manager) for f in resolved
    )
    if status == "CONFIRMED" and not supports_attack:
        h["status"] = "SUSPENDED"
        h["status_gate_reason"] = (
            "downgraded_from_CONFIRMED: no linked finding is CONFIRMED with "
            "multi-source corroboration (>=2 independent sources). A hunting "
            "hypothesis inherits the finding-level multi-source bar; a verdict "
            "cannot exceed the evidence its findings carry."
        )
    elif status == "REFUTED" and supports_attack:
        h["status"] = "SUSPENDED"
        h["status_gate_reason"] = (
            "downgraded_from_REFUTED: a linked finding is CONFIRMED with "
            "multi-source corroboration, contradicting a refuted verdict."
        )
    return h


def validate_and_prepare_finding(
    finding: dict[str, Any],
    *,
    mode: Literal["strict", "migration"] = "strict",
    fallback_case_id: Optional[str] = None,
    fallback_execution_id: str = "E-000",
    fallback_iteration: Optional[int] = 1,
    state_manager: Any = None,
) -> dict[str, Any]:
    """Return a canonical stored finding dict, validating the core schema."""
    normalized = dict(finding)

    if fallback_case_id and not _normalize_whitespace(normalized.get("case_id")):
        normalized["case_id"] = fallback_case_id
    if fallback_iteration is not None and not normalized.get("iteration"):
        normalized["iteration"] = fallback_iteration
    if not _normalize_whitespace(normalized.get("execution_id")):
        normalized["execution_id"] = fallback_execution_id

    if mode == "migration":
        normalized.setdefault("finding_type", "other")
        normalized.setdefault("artifact_path", "<legacy-unavailable>")
        normalized.setdefault("tool_name", "legacy.migrated")
        normalized.setdefault("confidence", 0.0)
        normalized.setdefault("description", "Legacy migrated finding.")

    evidence_kind, finding_status = _normalize_lifecycle_fields(normalized)
    normalized.pop("status", None)
    normalized["evidence_kind"] = evidence_kind
    normalized["finding_status"] = _normalize_status(finding_status)

    artifact_type, artifact_subtype = _canonicalize_artifact_type(
        normalized.get("artifact_type"), normalized.get("tool_name")
    )
    normalized["artifact_type"] = artifact_type
    if artifact_subtype and not _normalize_whitespace(normalized.get("artifact_subtype")):
        normalized["artifact_subtype"] = artifact_subtype
    # Source-of-truth fallbacks for disk findings that arrive with a blank
    # artifact_subtype. Recovers it so state.json is correct for every
    # downstream consumer (graph, report, correlation) rather than each
    # guessing. Precedence:
    #   explicit subtype > _canonicalize alias subtype (above)
    #   > tool_name derive (auto-generated findings) > path derive (analyst
    #     findings) > blank.
    # tool_name is the authoritative producing tool, so it runs before the
    # path parse. Both are metadata-only - they do NOT feed fk_source_class /
    # confidence / status gates (classify_fk_source never reads subtype).
    if artifact_type == "disk" and not _normalize_whitespace(
        normalized.get("artifact_subtype")
    ):
        derived_subtype = _derive_artifact_subtype_from_tool(normalized.get("tool_name"))
        if not derived_subtype and _normalize_whitespace(normalized.get("artifact_path")):
            derived_subtype = _derive_artifact_subtype_from_path(
                normalized.get("artifact_path")
            )
        if derived_subtype:
            normalized["artifact_subtype"] = derived_subtype

    normalized["mitre_tactic"] = _normalize_whitespace(normalized.get("mitre_tactic")).upper() or None
    normalized["mitre_technique"] = (
        _normalize_whitespace(normalized.get("mitre_technique")).upper() or None
    )

    _normalize_support_lists(normalized)

    source_class = normalized.get("fk_source_class") or classify_fk_source(normalized)
    original_confidence: Optional[float] = None
    applied_multiplier: Optional[float] = None
    if source_class:
        normalized["fk_source_class"] = source_class
        if source_class in _FK_CORROBORATION_REQUIREMENTS:
            # Correlation exemption + source-aware subtraction (review
            # 2026-06-05). Synthesis/inference findings (artifact_type=correlation)
            # ARE the cross-source stack -> NEVER auto-populate FK requirements for
            # them (e.g. persistence+correlation mis-classes as registry_run and
            # would falsely demote legit synthesis CONFIRMED). For single-artifact
            # FK findings, outstanding = required MINUS already-satisfied sources,
            # so a genuine 2+-source stack has empty outstanding and stays CONFIRMED.
            if _to_text(normalized.get("artifact_type")).lower() != "correlation":
                if not normalized.get("corroboration_outstanding"):
                    satisfied = _satisfied_source_classes(normalized, state_manager)
                    normalized["corroboration_outstanding"] = [
                        r for r in _FK_CORROBORATION_REQUIREMENTS[source_class]
                        if _to_text(r).lower() not in satisfied
                    ]
                normalized["corroboration_outstanding"] = _normalize_indicator_list(
                    normalized.get("corroboration_outstanding")
                )
        if not normalized.get("fk_confidence_note"):
            original_confidence = float(normalized.get("confidence", 0.0) or 0.0)
            applied_multiplier = _FK_CONFIDENCE_MULTIPLIERS[source_class]
            adjusted = round(min(original_confidence * applied_multiplier, 1.0), 3)
            normalized["confidence"] = adjusted
            normalized["fk_confidence_note"] = (
                f"FK multiplier {applied_multiplier:.2f} applied for {source_class}. "
                f"Original: {original_confidence:.3f} -> Adjusted: {adjusted:.3f}"
            )

    normalized["supporting_tool_families"] = _derive_supporting_tool_families(normalized)
    normalized["supporting_artifact_families"] = _derive_supporting_artifact_families(
        normalized
    )
    normalized["promotion_eligibility"] = _derive_promotion_eligibility(normalized)
    normalized["confidence_support_inputs"] = _derive_confidence_support_inputs(
        normalized,
        original_confidence=original_confidence,
        applied_multiplier=applied_multiplier,
    )

    validated = Finding(**_build_model_input(
        normalized,
        fallback_finding_id="F-000",
        fallback_execution_id=fallback_execution_id,
    )).model_dump(mode="json")

    merged = dict(normalized)
    merged.update(validated)
    merged["finding_status"] = _normalize_status(merged.get("finding_status"))
    # Tier-A: apply CONFIRMED gates AFTER the
    # Pydantic validation pass so the new fields (requires_re_extraction,
    # alternative_hypothesis, disposition) are in their canonical form
    # before we decide whether to allow CONFIRMED status.
    merged = _apply_confirmed_gates(merged, state_manager)
    merged["content_key"] = compute_content_key(merged)
    return merged


def classify_fk_source(finding: dict[str, Any]) -> Optional[str]:
    """Classify the artifact strength bucket for a finding."""
    tool_name = _to_text(finding.get("tool_name")).lower()
    finding_type = _to_text(finding.get("finding_type")).lower()
    artifact_type = _to_text(finding.get("artifact_type")).lower()
    description = _to_text(finding.get("description")).lower()
    indicators = " ".join(_normalize_indicator_list(finding.get("supporting_indicators"))).lower()

    if "shimcache" in tool_name:
        return "shimcache"
    if "amcache" in tool_name:
        return "amcache"
    if "userassist" in tool_name:
        return "userassist"
    if "shellbag" in tool_name:
        return "shellbag"
    if "prefetch" in tool_name:
        return "prefetch"
    if "extract_registry_run_keys" in tool_name or finding_type == "persistence":
        return "registry_run"
    if finding_type == "timestomping" or "t1070.006" in _to_text(finding.get("mitre_technique")).lower():
        return "mft_timestomp"
    if "scan_processes" in tool_name and artifact_type == "memory":
        return "memory_process"
    if "sigma" in tool_name and finding.get("corroborated_by"):
        return "sigma_corroborated"
    if "summarize_evtx" in tool_name and (
        "4688" in description
        or "4688" in indicators
        or "event 4688" in description
        or "process creation" in description
    ):
        return "evtx_process_creation"
    return None


def compute_content_key(finding: dict[str, Any]) -> str:
    """Compute the deterministic semantic content key for deduplication.

    When a ``group_key`` is present (Phase 5 noise-controlled findings), it
    replaces the description fragment in the hash material so that reruns
    of the same grouped signal produce a stable key regardless of minor
    description wording changes.
    """
    group_key = _normalize_whitespace(finding.get("group_key"))
    desc_fragment = group_key if group_key else _normalize_whitespace(
        finding.get("description")
    )[:160]
    material = "|".join(
        [
            _normalize_whitespace(finding.get("tool_name")),
            _normalize_whitespace(finding.get("artifact_path")),
            _normalize_whitespace(finding.get("finding_type")),
            _normalize_whitespace(finding.get("timestamp_observed")),
            _normalize_whitespace(finding.get("mitre_technique")),
            desc_fragment,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def normalize_finding_for_storage(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalize, validate, and enrich a finding for authoritative storage."""
    return validate_and_prepare_finding(finding)


def adaptive_eids_from_findings(findings: Iterable[dict[str, Any]]) -> list[int]:
    """Return ATT&CK-informed EVTX EIDs based on the current finding set."""
    techniques = {
        _to_text(finding.get("mitre_technique")).upper()
        for finding in findings
        if finding.get("mitre_technique")
    }
    eids = set(_ADAPTIVE_EVTX_BASE_EIDS)

    if any(technique.startswith("T1078") for technique in techniques):
        eids |= {4672, 4776, 4768, 4769}
    if any(technique.startswith("T1059") for technique in techniques):
        eids |= {4103, 4104}
    if any(technique.startswith("T1543") for technique in techniques):
        eids |= {7045, 4698, 4702}
    if any(technique.startswith("T1021") for technique in techniques):
        eids |= {5140, 5145, 4648}
    if any(technique.startswith("T1003") for technique in techniques):
        eids |= {4776, 4768, 4769, 4663}
    if any(technique.startswith("T1070") for technique in techniques):
        eids |= {1102, 4719}
    if any(
        technique.startswith("T1547") or technique.startswith("T1546")
        for technique in techniques
    ):
        eids |= {4698, 4702, 7045}

    return sorted(eids)


_TACTIC_TOKEN_RE = re.compile(r"TA\d{4}")
_TECHNIQUE_TOKEN_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
_TACTIC_NAME_TO_ID: dict[str, str] = {
    name.lower(): tactic_id for tactic_id, name in _TACTIC_CATALOG
}
_TECHNIQUE_TACTIC_INDEX: Optional[dict[str, set[str]]] = None


def _technique_tactic_index() -> dict[str, set[str]]:
    """Build (and cache) a technique-ID -> tactic-ID-set index from the routing
    catalog. Both the full sub-technique key (T1021.001) and its base (T1021,
    mapped to the union of all sub-technique tactics) are indexed so a finding
    that records only the base technique still resolves.
    """
    global _TECHNIQUE_TACTIC_INDEX
    if _TECHNIQUE_TACTIC_INDEX is not None:
        return _TECHNIQUE_TACTIC_INDEX
    index: dict[str, set[str]] = {}
    try:
        from sift_mcp.routing import load_routing_catalog

        catalog = load_routing_catalog()
    except Exception:
        catalog = {}
    for technique_id, entry in (catalog or {}).items():
        if not isinstance(entry, dict):
            continue
        tactics = {
            str(t).strip().upper()
            for t in (entry.get("tactics") or [])
            if str(t).strip()
        }
        if not tactics:
            continue
        tid = str(technique_id).strip().upper()
        index.setdefault(tid, set()).update(tactics)
        base = tid.split(".")[0]
        index.setdefault(base, set()).update(tactics)
    _TECHNIQUE_TACTIC_INDEX = index
    return index


def _normalize_tactic_ids(value: Any) -> set[str]:
    """Resolve an explicit mitre_tactic value to a set of TA-IDs.

    Accepts TA-IDs (``TA0008``), tactic display names (``Lateral Movement``),
    or a comma/space-joined mix. Returns an empty set when nothing resolves.
    """
    text = _to_text(value)
    if not text:
        return set()
    ids = {tok.upper() for tok in _TACTIC_TOKEN_RE.findall(text.upper())}
    if ids:
        return ids
    key = text.strip().lower()
    if key in _TACTIC_NAME_TO_ID:
        return {_TACTIC_NAME_TO_ID[key]}
    return set()


def _tactics_from_technique(value: Any) -> set[str]:
    """Resolve a mitre_technique value (e.g. ``T1021.001`` or ``T1021``) to its
    tactic-ID set via the routing catalog. Tolerates names appended to the ID
    (``T1021.001 (Remote Desktop)``) and lists rendered as text.
    """
    text = _to_text(value).upper()
    if not text:
        return set()
    index = _technique_tactic_index()
    resolved: set[str] = set()
    for token in _TECHNIQUE_TOKEN_RE.findall(text):
        token = token.upper()
        if token in index:
            resolved |= index[token]
        else:
            resolved |= index.get(token.split(".")[0], set())
    return resolved


def compute_coverage_from_findings(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Compute ATT&CK tactic coverage and suggested next tools.

    Coverage resolves per finding as: explicit ``mitre_tactic`` wins; otherwise
    the tactic is derived from ``mitre_technique`` via the routing catalog
    (P1 #9, review 2026-06-03). Before this, findings that carried only a
    technique (e.g. F-094 ``T1021.*`` lateral movement with a null tactic) left
    their tactic uncovered, understating the report's ATT&CK matrix.
    """
    covered_ids: set[str] = set()
    for finding in findings:
        tactic_ids = _normalize_tactic_ids(finding.get("mitre_tactic"))
        if not tactic_ids:
            tactic_ids = _tactics_from_technique(finding.get("mitre_technique"))
        covered_ids |= tactic_ids
    all_ids = [tactic_id for tactic_id, _ in _TACTIC_CATALOG]

    covered = [
        {"id": tactic_id, "name": tactic_name}
        for tactic_id, tactic_name in _TACTIC_CATALOG
        if tactic_id in covered_ids
    ]
    uncovered = [
        {"id": tactic_id, "name": tactic_name}
        for tactic_id, tactic_name in _TACTIC_CATALOG
        if tactic_id not in covered_ids
    ]

    return {
        "covered_tactics": covered,
        "uncovered_tactics": uncovered,
        "coverage_percent": round((len(covered) / len(all_ids)) * 100, 1),
        "suggested_next_tools": {
            tactic["id"]: list(_TACTIC_TOOL_SUGGESTIONS.get(tactic["id"], []))
            for tactic in uncovered
        },
    }


def _candidate_strings_from_finding(finding: dict[str, Any]) -> list[str]:
    values = [_to_text(finding.get("artifact_path")), _to_text(finding.get("description"))]
    values.extend(_normalize_indicator_list(finding.get("supporting_indicators")))
    return [value for value in values if value]


def promote_corroborated_findings(
    state_manager: Any,
    evidence_source_class: str,
    observed_paths: Iterable[str],
) -> list[str]:
    """Promote ACTIVE weak-source findings when a stronger corroborating source matches."""
    observed = [_normalized_path_token(path) for path in observed_paths if _normalize_whitespace(path)]
    if not observed:
        return []

    observed_full = {path for path in observed if path}
    observed_basenames = {_basename(path) for path in observed_full if _basename(path)}
    promoted: list[str] = []

    try:
        findings = state_manager.get_findings()
    except Exception:
        return promoted

    for finding in findings:
        finding_id = _to_text(finding.get("finding_id"))
        if not finding_id:
            continue

        outstanding = [
            _normalize_whitespace(item).lower()
            for item in finding.get("corroboration_outstanding", [])
            if _normalize_whitespace(item)
        ]
        if evidence_source_class.lower() not in outstanding:
            continue

        status = _normalize_status(finding.get("finding_status"))
        if status == FindingStatus.REJECTED.value.upper():
            continue

        matched = False
        for candidate in _candidate_strings_from_finding(finding):
            normalized_candidate = _normalized_path_token(candidate)
            if normalized_candidate in observed_full:
                matched = True
                break
            base = _basename(normalized_candidate)
            if base and base in observed_basenames:
                matched = True
                break

        if not matched:
            continue

        corroborated_by = _normalize_indicator_list(finding.get("corroborated_by"))
        if evidence_source_class not in corroborated_by:
            corroborated_by.append(evidence_source_class)

        remaining = [
            item
            for item in finding.get("corroboration_outstanding", [])
            if _normalize_whitespace(item).lower() != evidence_source_class.lower()
        ]

        # Apply execution validation hierarchy if this is execution-related
        artifact_sources = set(corroborated_by)
        artifact_sources.add(finding.get("fk_source_class", "unknown"))

        # Use execution hierarchy for execution-related findings
        execution_sources = {"prefetch", "amcache", "shimcache", "evtx_process_creation", "bam_dam", "mft"}
        if artifact_sources & execution_sources:
            # Execution-related: use professional hierarchy
            hierarchy_confidence, reasoning = _derive_execution_confidence(artifact_sources)
            new_confidence = hierarchy_confidence
            confidence_note = f"execution_hierarchy: {reasoning}"
        else:
            # Non-execution: use traditional +0.15 boost
            new_confidence = round(min(float(finding.get("confidence", 0.0) or 0.0) + 0.15, 1.0), 3)
            confidence_note = "traditional_corroboration_boost"

        # Get existing confidence_support_inputs and update
        support_inputs = finding.get("confidence_support_inputs", {})
        if not isinstance(support_inputs, dict):
            support_inputs = {}
        support_inputs["promotion_method"] = confidence_note
        support_inputs["artifact_sources"] = list(artifact_sources)

        # Integrity fix (review 2026-06-05): promote to CONFIRMED ONLY when
        # ALL outstanding corroboration is cleared (remaining == []). If sources
        # are still outstanding, record the progress (new corroborated_by +
        # reduced remaining + higher confidence) but keep the finding ACTIVE --
        # never CONFIRMED-with-outstanding (the F-061 self-contradiction). This is
        # consistent with _apply_confirmed_gates Tier-A3.
        promoted_status = (
            FindingStatus.CONFIRMED.value.upper()
            if not remaining
            else FindingStatus.ACTIVE.value.upper()
        )
        state_manager.update_finding(
            finding_id,
            finding_status=promoted_status,
            corroborated_by=corroborated_by,
            corroboration_outstanding=remaining,
            corroboration_completed_by=evidence_source_class,
            confidence=new_confidence,
            confidence_support_inputs=support_inputs,
        )
        if promoted_status == FindingStatus.CONFIRMED.value.upper():
            promoted.append(finding_id)

    return promoted
