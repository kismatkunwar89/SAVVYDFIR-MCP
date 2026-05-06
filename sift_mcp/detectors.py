"""Two-phase, case-agnostic FOR508-style detectors for sigma_scan."""

from __future__ import annotations

import base64
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import median
from typing import Any, Callable

from sift_mcp.models.sigma import ArtifactHit

PHASE1_BUDGET_SECONDS = 5.0
PHASE2_BUDGET_SECONDS = 10.0
AGGREGATE_BUDGET_SECONDS = 30.0

STABLE_DETECTORS = {
    "zeroed_fractional_timestamps",
    "si_fn_timestomp",
    "motw_presence",
    "log_clear",
    "encoded_powershell",
    "defender_detection",
    "sdelete_cipher_trace",
    "explicit_logon_smb_correlation",
    "m_before_c_copy",
    "mft_sequence_anomaly",
}


@dataclass
class DetectionContext:
    findings: list[dict[str, Any]]
    buckets: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    warnings: list[dict[str, Any]] = field(default_factory=list)


def normalize_enabled_detectors(value: Any) -> set[str]:
    """Return the enabled detector allow-list using v6 manifest semantics."""
    if value is None:
        return set(STABLE_DETECTORS)
    if not isinstance(value, list):
        raise ValueError("enabled_detectors must be omitted/null or a non-empty list.")
    normalized = {str(item).strip() for item in value if str(item).strip()}
    if not normalized:
        raise ValueError("enabled_detectors=[] is invalid; omit/null to enable all detectors.")
    unknown = normalized - STABLE_DETECTORS
    if unknown:
        raise ValueError(f"Unknown enabled_detectors: {sorted(unknown)}")
    return normalized


def run_two_phase_scan(
    findings: list[dict[str, Any]],
    *,
    enabled_detectors: Any = None,
) -> dict[str, Any]:
    enabled = normalize_enabled_detectors(enabled_detectors)
    context = build_detection_context(findings)
    hits: list[ArtifactHit] = []
    timings: dict[str, float] = {}
    warnings: list[dict[str, Any]] = list(context.warnings)
    detectors_run: list[str] = []
    total_start = time.monotonic()

    phase1: list[tuple[str, Callable[[DetectionContext], list[ArtifactHit]]]] = [
        ("zeroed_fractional_timestamps", detect_zeroed_fractional_timestamps),
        ("si_fn_timestomp", detect_si_fn_timestomp),
        ("motw_presence", detect_motw_presence),
        ("log_clear", detect_log_clear),
        ("encoded_powershell", detect_encoded_powershell),
        ("defender_detection", detect_defender_detection),
        ("sdelete_cipher_trace", detect_sdelete_cipher_trace),
    ]
    phase2: list[tuple[str, Callable[[DetectionContext], list[ArtifactHit]]]] = [
        ("explicit_logon_smb_correlation", correlate_explicit_logon_smb),
        ("m_before_c_copy", correlate_m_before_c_copy),
        ("mft_sequence_anomaly", correlate_mft_sequence_anomaly),
    ]

    for name, detector in phase1:
        if name not in enabled:
            continue
        detector_hits, elapsed, detector_warning = _run_detector(
            name, detector, context, PHASE1_BUDGET_SECONDS
        )
        detectors_run.append(name)
        timings[name] = elapsed
        hits.extend(detector_hits)
        if detector_warning:
            warnings.append(detector_warning)

    phase2_timings: dict[str, float] = {}
    for name, detector in phase2:
        if name not in enabled:
            continue
        if time.monotonic() - total_start > AGGREGATE_BUDGET_SECONDS:
            warnings.append(
                {
                    "type": "aggregate_budget_exceeded",
                    "detector": name,
                    "phase": 2,
                    "budget_seconds": AGGREGATE_BUDGET_SECONDS,
                    "message": "Aggregate detector budget exceeded; slow correlator skipped.",
                }
            )
            continue
        detector_hits, elapsed, detector_warning = _run_detector(
            name, detector, context, PHASE2_BUDGET_SECONDS
        )
        detectors_run.append(name)
        timings[name] = elapsed
        phase2_timings[name] = elapsed
        hits.extend(detector_hits)
        if detector_warning:
            warnings.append(detector_warning)

    if time.monotonic() - total_start > AGGREGATE_BUDGET_SECONDS and phase2_timings:
        slowest = max(phase2_timings, key=phase2_timings.get)
        warnings.append(
            {
                "type": "aggregate_budget_exceeded",
                "detector": slowest,
                "phase": 2,
                "budget_seconds": AGGREGATE_BUDGET_SECONDS,
                "message": "Aggregate budget exceeded; slowest correlator should be disabled first.",
            }
        )

    anti_forensics = [
        _hit_to_lead(hit) for hit in hits if hit.detector in {"log_clear", "sdelete_cipher_trace"}
    ]
    return {
        "hits": hits,
        "detectors_run": detectors_run,
        "detector_timings": timings,
        "detector_warnings": warnings,
        "actionable_leads": sorted(
            [_hit_to_lead(hit) for hit in hits],
            key=lambda lead: (
                _severity_rank(lead.get("severity")),
                str(lead.get("timestamp") or ""),
                float(lead.get("confidence", 0.0) or 0.0),
            ),
            reverse=True,
        ),
        "anti_forensics_warnings": anti_forensics,
        "data_gaps": [w for w in warnings if w.get("type") == "data_gap"],
    }


def build_detection_context(findings: list[dict[str, Any]]) -> DetectionContext:
    context = DetectionContext(findings=[_flatten(finding) for finding in findings])
    for finding in context.findings:
        subtype = _text(_value(finding, "artifact_subtype", "artifact_type")).lower()
        tool = _text(_value(finding, "tool_name")).lower()
        description = _text(_value(finding, "description")).lower()
        event_id = _event_id(finding)
        if subtype in {"mft", "mft_entry"} or "mft" in tool:
            context.buckets["mft"].append(finding)
        if subtype in {"evtx", "evtx_event", "event_log"} or "evtx" in tool or event_id is not None:
            context.buckets["evtx"].append(finding)
            if event_id is not None:
                context.buckets[f"event:{event_id}"].append(finding)
        if subtype in {"prefetch", "amcache"} or "prefetch" in tool or "amcache" in tool:
            context.buckets["execution_evidence"].append(finding)
        if "zone.identifier" in description or "zoneid=" in description:
            context.buckets["motw"].append(finding)
        if "usnjrnl" in subtype or "usn" in tool or "$usn" in description:
            context.buckets["usn"].append(finding)
    return context


def detect_zeroed_fractional_timestamps(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    for finding in context.buckets.get("mft", []):
        zeroed_fields = []
        for key, value in finding.items():
            key_text = str(key).lower()
            value_text = _text(value)
            if any(token in key_text for token in ("created", "modified", "access", "change", "timestamp")):
                if re.search(r"[:.]\d{2}:\d{2}:\d{2}\.0{3,7}(?:z|[+-]\d{2}:?\d{2})?$", value_text.lower()):
                    zeroed_fields.append(key)
                elif re.search(r"t\d{2}:\d{2}:\d{2}\.0{3,7}", value_text.lower()):
                    zeroed_fields.append(key)
        if zeroed_fields:
            hits.append(
                _hit(
                    detector="zeroed_fractional_timestamps",
                    severity="HIGH",
                    description=f"Zeroed fractional timestamp fields on MFT record: {', '.join(zeroed_fields[:4])}",
                    artifact_type="mft",
                    raw_data={"fields": zeroed_fields, "finding_id": finding.get("finding_id")},
                    technique="T1070.006",
                    tactic="TA0005",
                    pivot=("timeline.query_timeline", {"around": _timestamp(finding)}, "Pivot around the zeroed timestamp and compare $SI/$FN/PF/Amcache context."),
                )
            )
    return hits


def detect_si_fn_timestomp(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    pairs = [
        ("created", ("created0x10", "si_created"), ("created0x30", "fn_created")),
        ("modified", ("lastmodified0x10", "si_modified"), ("lastmodified0x30", "fn_modified")),
        ("accessed", ("lastaccess0x10", "si_accessed"), ("lastaccess0x30", "fn_accessed")),
        ("changed", ("mftrecordchange0x10", "si_changed"), ("mftrecordchange0x30", "fn_changed")),
    ]
    for finding in context.buckets.get("mft", []):
        for label, si_keys, fn_keys in pairs:
            si_dt = _datetime(_value(finding, *si_keys))
            fn_dt = _datetime(_value(finding, *fn_keys))
            if not si_dt or not fn_dt:
                continue
            delta = abs((si_dt - fn_dt).total_seconds())
            if delta > 3600:
                hits.append(
                    _hit(
                        detector="si_fn_timestomp",
                        severity="HIGH",
                        description=f"$SI/$FN {label} timestamp mismatch of {delta:.0f}s.",
                        artifact_type="mft",
                        raw_data={"field": label, "delta_seconds": delta, "finding_id": finding.get("finding_id")},
                        technique="T1070.006",
                        tactic="TA0005",
                        pivot=("disk.extract_prefetch", {}, "Check Prefetch and Amcache execution evidence near the mismatched MFT timestamps."),
                    )
                )
                break
    return hits


def detect_motw_presence(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    for finding in context.buckets.get("motw", []):
        hits.append(
            _hit(
                detector="motw_presence",
                severity="MEDIUM",
                description="Mark-of-the-Web Zone.Identifier evidence is present.",
                artifact_type="mft",
                raw_data={"finding_id": finding.get("finding_id")},
                technique="T1204",
                tactic="TA0001",
                pivot=("timeline.query_timeline", {"around": _timestamp(finding)}, "Correlate MotW file creation with browser, LNK, Jump List, and execution artifacts."),
            )
        )
    return hits


def detect_log_clear(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    for event_id in (1102, 104):
        for finding in context.buckets.get(f"event:{event_id}", []):
            hits.append(
                _hit(
                    detector="log_clear",
                    severity="CRITICAL",
                    description=f"Windows event log clear detected: Event ID {event_id}.",
                    artifact_type="evtx",
                    raw_data={"event_id": event_id, "finding_id": finding.get("finding_id")},
                    technique="T1070.001",
                    tactic="TA0005",
                    pivot=("detection.analyze_vss", {}, "Recover cleared log context from VSS and compare surrounding timeline gaps."),
                )
            )
    return hits


def detect_encoded_powershell(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    admin_parent_exclusions = ("ccmexec.exe", "gpupdate.exe", "taskeng.exe", "taskhostw.exe")
    pattern = re.compile(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{40,})", re.IGNORECASE)
    for finding in context.buckets.get("evtx", []):
        haystack = " ".join(_text(value) for value in finding.values())
        if any(parent in haystack.lower() for parent in admin_parent_exclusions):
            continue
        for match in pattern.finditer(haystack):
            decoded = _decode_powershell(match.group(1))
            if len(decoded) >= 200:
                hits.append(
                    _hit(
                        detector="encoded_powershell",
                        severity="HIGH",
                        description=f"Encoded PowerShell payload decoded to {len(decoded)} characters.",
                        artifact_type="evtx",
                        raw_data={"decoded_length": len(decoded), "finding_id": finding.get("finding_id")},
                        technique="T1059.001",
                        tactic="TA0002",
                        pivot=("timeline.query_timeline", {"around": _timestamp(finding)}, "Correlate encoded PowerShell with process creation, script block, and network events."),
                    )
                )
                break
    return hits


def detect_defender_detection(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    for event_id in (1116, 1117):
        for finding in context.buckets.get(f"event:{event_id}", []):
            hits.append(
                _hit(
                    detector="defender_detection",
                    severity="HIGH",
                    description=f"Microsoft Defender malware event detected: Event ID {event_id}.",
                    artifact_type="evtx",
                    raw_data={"event_id": event_id, "finding_id": finding.get("finding_id")},
                    technique="T1562",
                    tactic="TA0005",
                    pivot=("timeline.query_timeline", {"around": _timestamp(finding)}, "Review Defender event details, quarantined path, and adjacent execution evidence."),
                )
            )
    return hits


def detect_sdelete_cipher_trace(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    for finding in context.buckets.get("execution_evidence", []) + context.buckets.get("evtx", []):
        text = " ".join(_text(value) for value in finding.values()).lower()
        if re.search(r"\bsdelete(?:64)?\.exe\b", text) or re.search(r"\bcipher\.exe\b[^\n\r]{0,80}/w", text):
            hits.append(
                _hit(
                    detector="sdelete_cipher_trace",
                    severity="HIGH",
                    description="Execution evidence indicates SDelete or cipher /w wiping activity.",
                    artifact_type="persistence",
                    raw_data={"finding_id": finding.get("finding_id")},
                    technique="T1070",
                    tactic="TA0005",
                    pivot=("timeline.query_timeline", {"around": _timestamp(finding)}, "Correlate wiping execution with deleted files, USN records, and VSS recovery."),
                )
            )
    usn_by_second: dict[int, int] = defaultdict(int)
    for finding in context.buckets.get("usn", []):
        text = " ".join(_text(value) for value in finding.values()).lower()
        if "delete" not in text and "file_delete" not in text:
            continue
        ts = _datetime(_timestamp(finding))
        if ts:
            usn_by_second[int(ts.timestamp())] += 1
    seconds = sorted(usn_by_second)
    for start in seconds:
        count = sum(value for second, value in usn_by_second.items() if start <= second < start + 5)
        if count > 100:
            hits.append(
                _hit(
                    detector="sdelete_cipher_trace",
                    severity="HIGH",
                    description=f"$UsnJrnl deletion burst detected: {count} records within <5s.",
                    artifact_type="mft",
                    raw_data={"deletion_count": count, "window_start": start},
                    technique="T1070",
                    tactic="TA0005",
                    pivot=("detection.analyze_vss", {}, "Recover likely wiped files from VSS and inspect deletion-burst neighbors."),
                )
            )
            break
    return hits


def correlate_explicit_logon_smb(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    logons = context.buckets.get("event:4648", [])
    smb_events = context.buckets.get("event:5140", []) + context.buckets.get("event:5145", [])
    for logon in logons:
        logon_ts = _datetime(_timestamp(logon))
        if not logon_ts:
            continue
        logon_src = _principal_key(logon)
        for smb in smb_events:
            smb_ts = _datetime(_timestamp(smb))
            if not smb_ts:
                continue
            if abs((smb_ts - logon_ts).total_seconds()) > 60:
                continue
            if logon_src and _principal_key(smb) and logon_src != _principal_key(smb):
                continue
            hits.append(
                _hit(
                    detector="explicit_logon_smb_correlation",
                    severity="HIGH",
                    description="Explicit credential logon correlated with SMB share access within 60 seconds.",
                    artifact_type="evtx",
                    raw_data={"logon_finding_id": logon.get("finding_id"), "smb_finding_id": smb.get("finding_id")},
                    technique="T1021.002",
                    tactic="TA0008",
                    pivot=("timeline.query_timeline", {"around": logon_ts.isoformat()}, "Review 4648, 4624, 5140/5145, process creation, and destination host artifacts."),
                )
            )
            break
    return hits


def correlate_m_before_c_copy(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    for finding in context.buckets.get("mft", []):
        si_modified = _datetime(_value(finding, "lastmodified0x10", "si_modified"))
        fn_created = _datetime(_value(finding, "created0x30", "fn_created"))
        if not si_modified or not fn_created:
            continue
        delta = (fn_created - si_modified).total_seconds()
        if delta >= 1:
            hits.append(
                _hit(
                    detector="m_before_c_copy",
                    severity="HIGH",
                    description=f"M-before-C copy artifact: $SI.Modified is {delta:.0f}s before $FN.Created.",
                    artifact_type="mft",
                    raw_data={"delta_seconds": delta, "finding_id": finding.get("finding_id")},
                    technique="T1105",
                    tactic="TA0011",
                    pivot=("timeline.query_timeline", {"around": fn_created.isoformat()}, "Inspect file-copy neighbors, SMB events, Prefetch, Amcache, and directory siblings."),
                )
            )
    return hits


def correlate_mft_sequence_anomaly(context: DetectionContext) -> list[ArtifactHit]:
    hits: list[ArtifactHit] = []
    siblings: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for finding in context.buckets.get("mft", []):
        parent_ref = _text(_value(finding, "parent_reference", "parententry", "parent_entry", "filename_parent_reference"))
        sequence = _int(_value(finding, "sequence_number", "sequencenumber", "seq"))
        if not parent_ref or sequence is None:
            continue
        volume = _text(_value(finding, "volume", "volume_serial", "source_volume", "artifact_path")) or "unknown-volume"
        siblings[(volume, parent_ref)].append((sequence, finding))
    for (volume, parent_ref), records in siblings.items():
        if len(records) < 4:
            continue
        med = median(sequence for sequence, _ in records)
        for sequence, finding in records:
            delta = abs(sequence - med)
            if delta > 1000:
                hits.append(
                    _hit(
                        detector="mft_sequence_anomaly",
                        severity="MEDIUM",
                        description=f"MFT sequence number differs from same-directory median by {delta:.0f}.",
                        artifact_type="mft",
                        raw_data={"volume": volume, "parent_reference": parent_ref, "sequence": sequence, "median": med, "finding_id": finding.get("finding_id")},
                        technique="T1036",
                        tactic="TA0005",
                        pivot=("disk.extract_mft_timeline", {}, "Review same-parent MFT siblings using $FILE_NAME.parent_reference, not parent path strings."),
                    )
                )
    return hits


def _run_detector(
    name: str,
    detector: Callable[[DetectionContext], list[ArtifactHit]],
    context: DetectionContext,
    budget_seconds: float,
) -> tuple[list[ArtifactHit], float, dict[str, Any] | None]:
    start = time.monotonic()
    try:
        hits = detector(context)
    except Exception as exc:
        elapsed = time.monotonic() - start
        return [], elapsed, {"type": "detector_error", "detector": name, "error": str(exc)}
    elapsed = time.monotonic() - start
    if elapsed > budget_seconds:
        return hits, elapsed, {
            "type": "detector_budget_exceeded",
            "detector": name,
            "budget_seconds": budget_seconds,
            "elapsed_seconds": elapsed,
            "message": "Detector exceeded soft budget; results are partial-risk and detector may be skipped in constrained runs.",
        }
    return hits, elapsed, None


def _hit(
    *,
    detector: str,
    severity: str,
    description: str,
    artifact_type: str,
    raw_data: dict[str, Any],
    technique: str,
    tactic: str,
    pivot: tuple[str, dict[str, Any], str],
) -> ArtifactHit:
    tool, args, human = pivot
    return ArtifactHit(
        detector=detector,
        severity=severity,  # type: ignore[arg-type]
        description=description,
        artifact_type=artifact_type,  # type: ignore[arg-type]
        raw_data=raw_data,
        mitre_technique=technique,
        mitre_tactic=tactic,
        pivot_suggestion=human,
        next_pivot={"tool": tool, "args": dict(args), "human_readable": human},
    )


def _hit_to_lead(hit: ArtifactHit) -> dict[str, Any]:
    return {
        "detector": hit.detector,
        "severity": hit.severity,
        "confidence": _confidence_for(hit.severity),
        "timestamp": _timestamp(hit.raw_data),
        "affected_findings": [
            value for key, value in hit.raw_data.items() if key.endswith("finding_id") and value
        ],
        "description": hit.description,
        "mitre_technique": hit.mitre_technique,
        "next_pivot": hit.next_pivot,
        "raw_data": hit.raw_data,
    }


def _flatten(value: dict[str, Any]) -> dict[str, Any]:
    flattened = dict(value)
    for nested_key in ("raw_data", "confidence_support_inputs"):
        nested = value.get(nested_key)
        if isinstance(nested, dict):
            for key, nested_value in nested.items():
                flattened.setdefault(str(key), nested_value)
    return flattened


def _value(finding: dict[str, Any], *candidates: str) -> Any:
    norm = {str(key).lower().replace(" ", "_").replace("-", "_").replace("$", ""): value for key, value in finding.items()}
    for candidate in candidates:
        token = candidate.lower().replace(" ", "_").replace("-", "_").replace("$", "")
        if token in norm:
            return norm[token]
    for candidate in candidates:
        token = candidate.lower().replace(" ", "_").replace("-", "_").replace("$", "")
        for key, value in norm.items():
            if token in key:
                return value
    return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key}={_text(item)}" for key, item in value.items())
    return str(value)


def _datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = _text(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _timestamp(finding: dict[str, Any]) -> Any:
    return _value(finding, "timestamp_observed", "timestamp", "timecreated", "time_created", "date_time_utc")


def _event_id(finding: dict[str, Any]) -> int | None:
    value = _value(finding, "event_id", "eventid", "id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _decode_powershell(value: str) -> str:
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except Exception:
        return ""
    for encoding in ("utf-16le", "utf-8"):
        try:
            return raw.decode(encoding, errors="ignore").strip()
        except Exception:
            continue
    return ""


def _principal_key(finding: dict[str, Any]) -> str:
    source = _text(_value(finding, "source_ip", "ipaddress", "workstation_name", "source_network_address")).lower()
    account = _text(_value(finding, "target_user_name", "account_name", "subject_user_name", "user")).lower()
    return "|".join(part for part in (source, account) if part)


def _severity_rank(severity: Any) -> int:
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(str(severity).upper(), 0)


def _confidence_for(severity: Any) -> float:
    return {"CRITICAL": 0.95, "HIGH": 0.85, "MEDIUM": 0.7, "LOW": 0.5, "INFO": 0.3}.get(str(severity).upper(), 0.5)
