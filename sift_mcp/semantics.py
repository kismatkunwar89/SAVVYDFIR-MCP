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
    "evtx": "disk",
    "evtx_event": "disk",
    "event_log": "disk",
    "eventlog": "disk",
    "mft": "disk",
    "mft_entry": "disk",
    "prefetch": "disk",
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
    raise ValueError(f"Unsupported artifact_type {value!r}.")


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


def validate_and_prepare_finding(
    finding: dict[str, Any],
    *,
    mode: Literal["strict", "migration"] = "strict",
    fallback_case_id: Optional[str] = None,
    fallback_execution_id: str = "E-000",
    fallback_iteration: Optional[int] = 1,
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
            if not normalized.get("corroboration_outstanding"):
                normalized["corroboration_outstanding"] = list(
                    _FK_CORROBORATION_REQUIREMENTS[source_class]
                )
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


def compute_coverage_from_findings(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Compute ATT&CK tactic coverage and suggested next tools."""
    covered_ids = {
        _to_text(finding.get("mitre_tactic")).upper()
        for finding in findings
        if _to_text(finding.get("mitre_tactic")).upper()
    }
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
        new_confidence = round(min(float(finding.get("confidence", 0.0) or 0.0) + 0.15, 1.0), 3)
        state_manager.update_finding(
            finding_id,
            finding_status=FindingStatus.CONFIRMED.value.upper(),
            corroborated_by=corroborated_by,
            corroboration_outstanding=remaining,
            corroboration_completed_by=evidence_source_class,
            confidence=new_confidence,
        )
        promoted.append(finding_id)

    return promoted
