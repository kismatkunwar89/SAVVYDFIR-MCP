"""Deterministic semantic helpers for finding ingestion and coverage analysis."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Iterable, Optional

from sift_mcp.models.finding import FindingStatus

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


def _normalize_indicator_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_normalize_whitespace(item) for item in value if _normalize_whitespace(item)]
    normalized = _normalize_whitespace(value)
    return [normalized] if normalized else []


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
    """Compute the deterministic semantic content key for deduplication."""
    material = "|".join(
        [
            _normalize_whitespace(finding.get("tool_name")),
            _normalize_whitespace(finding.get("artifact_path")),
            _normalize_whitespace(finding.get("finding_type")),
            _normalize_whitespace(finding.get("timestamp_observed")),
            _normalize_whitespace(finding.get("mitre_technique")),
            _normalize_whitespace(finding.get("description"))[:160],
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def normalize_finding_for_storage(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalize lifecycle fields, attach FK metadata, and add content_key."""
    normalized = dict(finding)

    if "status" in normalized and "finding_status" not in normalized:
        normalized["finding_status"] = normalized.pop("status")
    else:
        normalized.pop("status", None)

    normalized["finding_status"] = _normalize_status(normalized.get("finding_status"))
    normalized["contradicted_by"] = _normalize_indicator_list(normalized.get("contradicted_by"))
    normalized["corroborated_by"] = _normalize_indicator_list(normalized.get("corroborated_by"))
    normalized["related_finding_ids"] = _normalize_indicator_list(normalized.get("related_finding_ids"))
    normalized["supporting_indicators"] = _normalize_indicator_list(
        normalized.get("supporting_indicators")
    )

    source_class = normalized.get("fk_source_class") or classify_fk_source(normalized)
    if source_class:
        normalized["fk_source_class"] = source_class
        if not normalized.get("fk_confidence_note"):
            original_confidence = float(normalized.get("confidence", 0.0) or 0.0)
            penalty = _FK_CONFIDENCE_MULTIPLIERS[source_class]
            adjusted = round(min(original_confidence * penalty, 1.0), 3)
            normalized["confidence"] = adjusted
            normalized["fk_confidence_note"] = (
                f"FK multiplier {penalty:.2f} applied for {source_class}. "
                f"Original: {original_confidence:.3f} -> Adjusted: {adjusted:.3f}"
            )
            if source_class in _FK_CORROBORATION_REQUIREMENTS:
                normalized.setdefault(
                    "corroboration_outstanding",
                    list(_FK_CORROBORATION_REQUIREMENTS[source_class]),
                )

    normalized["content_key"] = compute_content_key(normalized)
    return normalized


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
