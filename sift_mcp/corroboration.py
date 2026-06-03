"""Corroboration escalation engine (review signed 2026-06-03, FK-wiring).

ADVISORY-ONLY, PURE module. Given a finding + the case finding set + that
artifact's forensic-knowledge slice, it computes:
  * present_sources  - corroborating source-classes already in the case
  * advisory_corroboration_tier - observation / probable / confirmed (DISPLAY label)
  * timestamp_aligned - true/false/unknown (caps tier when alignment required)
  * gap_sources / suggested_tools - the MINIMAL next step toward the next tier
  * rationale - one line, carries the advisory disclaimer

Non-disruption invariants (do NOT weaken without re-consensus):
  - NEVER writes state, NEVER promotes findings, NEVER sets confidence/status.
  - Promotion authority stays in semantics._derive_execution_confidence /
    promote_corroborated_findings. This module is DISPLAY/ADVISORY only.
  - Imports ONLY sift_mcp.semantics (classify_fk_source + _derive_execution_confidence);
    NO server / state / reporting / fastmcp (enforced by test_corroboration import-graph).
  - Entity match uses STRUCTURED fields only (artifact_path / typed
    supporting_indicators / basename); NEVER description, NEVER corroborated_by.
  - Unresolvable combination sources degrade to advisory text; never raise.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sift_mcp.semantics import _derive_execution_confidence, classify_fk_source

ADVISORY_DISCLAIMER = "advisory only; does not reflect finding_status or promotion"


# ---------------------------------------------------------------------------
# Single artifact vocabulary registry (the ONLY artifact<->tool reverse map).
# alias -> {source_class, mcp_tool}. Aliases cover artifact keys + the prose-y
# keys used in YAML corroborate_with / corroboration_escalation.combinations.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VocabEntry:
    source_class: str
    mcp_tool: Optional[str]


def _v(source_class: str, mcp_tool: Optional[str]) -> VocabEntry:
    return VocabEntry(source_class, mcp_tool)


ARTIFACT_VOCAB: dict[str, VocabEntry] = {
    # execution-class (route to _derive_execution_confidence)
    "prefetch": _v("prefetch", "disk.extract_prefetch"),
    "amcache": _v("amcache", "disk.get_amcache"),
    "shimcache": _v("shimcache", "disk.extract_shimcache"),
    "shimcache_disk": _v("shimcache", "disk.extract_shimcache"),
    "mft": _v("mft", "disk.extract_mft_timeline"),
    "$mft": _v("mft", "disk.extract_mft_timeline"),
    "mft_timestomp": _v("mft", "disk.extract_mft_timeline"),
    "evtx": _v("evtx_process_creation", "disk.summarize_evtx"),
    "evtx_4688": _v("evtx_process_creation", "disk.summarize_evtx"),
    "event_logs_security": _v("evtx_process_creation", "disk.summarize_evtx"),
    "event_logs_network": _v("evtx_network", "disk.summarize_evtx"),
    "registry_run": _v("registry_run", "disk.extract_registry_run_keys"),
    "registry_run_keys": _v("registry_run", "disk.extract_registry_run_keys"),
    "userassist": _v("userassist", "disk.extract_registry_fileaccess"),
    "registry_userassist": _v("userassist", "disk.extract_registry_fileaccess"),
    "registry_fileaccess": _v("userassist", "disk.extract_registry_fileaccess"),
    "shellbag": _v("shellbag", "disk.extract_shellbags"),
    "shellbags": _v("shellbag", "disk.extract_shellbags"),
    "bam_dam": _v("bam_dam", None),
    "memory_process": _v("memory_process", "memory.scan_processes"),
    "memory": _v("memory_process", "memory.scan_processes"),
    "memory_network": _v("memory_network", "memory.scan_network"),
    "injected_code": _v("injected_code", "memory.detect_injection"),
    # non-execution (tier via FK combo rank + parse_upgrade_tier)
    "lnk_files": _v("lnk", "disk.extract_lnk_files"),
    "lnk": _v("lnk", "disk.extract_lnk_files"),
    "jump_lists": _v("jump_list", "disk.extract_jump_lists"),
    "jump_list": _v("jump_list", "disk.extract_jump_lists"),
    "browser": _v("browser", "disk.extract_browser_history"),
    "browser_history": _v("browser", "disk.extract_browser_history"),
    "srum": _v("srum", "disk.extract_srum"),
    "recycle_bin": _v("recycle_bin", None),
    "usn_journal": _v("usn_journal", "disk.extract_usn_journal"),
    "usnjrnl": _v("usn_journal", "disk.extract_usn_journal"),
    "$usnjrnl": _v("usn_journal", "disk.extract_usn_journal"),
    "volume_shadow_copies": _v("vss", "disk.analyze_vss"),
    "vss": _v("vss", "disk.analyze_vss"),
    "sigma": _v("sigma_corroborated", "detection.sigma_hunt"),
    "sigma_corroborated": _v("sigma_corroborated", "detection.sigma_hunt"),
    # --- auxiliary corroborators referenced by FK corroborate_with -----------
    # (mapped to an existing extractor where one exists; None = valid corroboration
    #  concept with no dedicated one-shot tool -> engine keeps it as an advisory
    #  gap label but cannot name a tool to run)
    "sysmon": _v("sysmon", "disk.summarize_evtx"),
    "sysmon_operational": _v("sysmon", "disk.summarize_evtx"),
    "event_logs_system": _v("evtx_system", "disk.summarize_evtx"),
    "logon_sessions": _v("logon_session", "disk.summarize_evtx"),
    "hayabusa_alerts": _v("hayabusa", "detection.hayabusa_hunt"),
    "recentdocs": _v("recentdocs", "disk.extract_registry_fileaccess"),
    "registry_user_mru": _v("userassist", "disk.extract_registry_fileaccess"),
    "mui_cache": _v("muicache", "disk.extract_registry_fileaccess"),
    "preferences_engagement": _v("browser", "disk.extract_browser_history"),
    "zone_identifier": _v("zone_identifier", None),
    "zone_identifier_ads": _v("zone_identifier", None),
    "local_cache": _v("browser_cache", None),
    "dns_cache": _v("dns_cache", None),
    "usbstor_mounteddevices": _v("usb_registry", None),
    "usbstor_partition_diagnostic": _v("usb_registry", None),
    "usb_registry": _v("usb_registry", None),
    "software_hive": _v("software_hive", None),
    "registry_profilelist": _v("registry_profilelist", None),
    "logfile": _v("logfile", None),
    "$logfile": _v("logfile", None),
    "i30_index": _v("i30_index", None),
    "$i30_index": _v("i30_index", None),
    "bitmap": _v("bitmap", None),
}

# Source classes whose tiering is owned by _derive_execution_confidence.
EXECUTION_SOURCE_CLASSES = frozenset({
    "prefetch", "amcache", "shimcache", "mft", "mft_timestomp",
    "evtx_process_creation", "shellbag", "userassist", "registry_run",
    "bam_dam", "memory_process",
})

_TIER_ORDER = {"observation": 0, "probable": 1, "confirmed": 2}
_TIER_CONFIDENCE = {"observation": 0.70, "probable": 0.85, "confirmed": 1.0}


# ---------------------------------------------------------------------------
# Resolution helpers (graceful: unresolvable -> None, never raise)
# ---------------------------------------------------------------------------
def _norm_alias(text: Any) -> str:
    return re.sub(r"[^a-z0-9_$]", "", str(text or "").strip().lower())


def resolve_source(alias: Any) -> Optional[VocabEntry]:
    """Best-effort alias -> VocabEntry. Tries exact, then token containment.

    Prose-y combination sources (e.g. 'memory malfind (RWX + MZ/MZAR header)')
    resolve by scanning for any known vocab token; unresolvable -> None.
    """
    key = _norm_alias(alias)
    if not key:
        return None
    if key in ARTIFACT_VOCAB:
        return ARTIFACT_VOCAB[key]
    raw = str(alias or "").lower()
    # token containment: longest alias first to prefer specific matches
    for vocab_key in sorted(ARTIFACT_VOCAB, key=len, reverse=True):
        bare = vocab_key.lstrip("$")
        if len(bare) >= 3 and bare in raw:
            return ARTIFACT_VOCAB[vocab_key]
    return None


def resolve_tool(alias: Any) -> Optional[str]:
    entry = resolve_source(alias)
    return entry.mcp_tool if entry else None


def parse_upgrade_tier(text: Any) -> Optional[str]:
    """Canonical tier label from an FK upgrades_to / tiers string.

    Handles 'PROBABLE execution (~0.85)', 'CONFIRMED / definitive ...',
    'OBSERVATION / possible (~0.70)', 'DEFINITIVE / PROVEN ...', etc.
    Returns 'observation' | 'probable' | 'confirmed' | None.
    """
    t = str(text or "").lower()
    if not t:
        return None
    if "confirmed" in t or "definitive" in t or "proven" in t:
        return "confirmed"
    if "probable" in t:
        return "probable"
    if "observation" in t or "possible" in t:
        return "observation"
    return None


# ---------------------------------------------------------------------------
# Finding -> source_class (precedence: stored -> classify -> vocab; null-safe)
# ---------------------------------------------------------------------------
def source_class_from_finding(finding: dict[str, Any]) -> Optional[str]:
    stored = str(finding.get("fk_source_class") or "").strip()
    if stored:
        return stored
    try:
        classified = classify_fk_source(finding)
    except Exception:
        classified = None
    if classified:
        return classified
    # fall back to ARTIFACT_VOCAB via tool_name / artifact_type
    for hint in (finding.get("tool_name"), finding.get("artifact_type"),
                 finding.get("artifact_subtype")):
        entry = resolve_source(hint)
        if entry:
            return entry.source_class
    return None


# ---------------------------------------------------------------------------
# Entity matching (STRUCTURED fields only - never description/corroborated_by)
# ---------------------------------------------------------------------------
_INDICATOR_PREFIXES = ("executable:", "hash:", "sha1:", "sha256:", "md5:",
                       "ip:", "path:", "file:", "domain:")


def _norm_path_token(path: Any) -> str:
    text = str(path or "").strip().strip('"').lower().replace("\\", "/")
    return text


def _entity_tokens(finding: dict[str, Any]) -> set[str]:
    """Structured identity tokens of a finding: full-path, basename, typed IOCs."""
    tokens: set[str] = set()
    ap = _norm_path_token(finding.get("artifact_path"))
    if ap:
        tokens.add(ap)
        base = ap.rsplit("/", 1)[-1]
        if base:
            tokens.add(base)
    inds = finding.get("supporting_indicators")
    if isinstance(inds, list):
        for ind in inds:
            s = str(ind or "").strip().lower()
            if not s:
                continue
            if ":" in s and s.split(":", 1)[0] + ":" in _INDICATOR_PREFIXES:
                val = s.split(":", 1)[1].strip()
                if val:
                    tokens.add(val)
                    if "/" in val or "\\" in val:
                        tokens.add(_norm_path_token(val).rsplit("/", 1)[-1])
            elif "." in s and "/" not in s and "\\" not in s and len(s) <= 64:
                tokens.add(s)  # bare basename-ish indicator (executable name)
    tokens.discard("")
    return tokens


def _parse_ts(value: Any) -> Optional[float]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        from datetime import datetime
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def present_corroborators(
    finding: dict[str, Any],
    case_findings: list[dict[str, Any]],
    *,
    window_seconds: int = 300,
) -> tuple[set[str], str]:
    """Source-classes in the case that corroborate *finding* by structured match.

    Returns (present_source_classes, timestamp_aligned) where timestamp_aligned
    in {'true','false','unknown'}.
    """
    f_class = source_class_from_finding(finding)
    f_tokens = _entity_tokens(finding)
    f_ts = _parse_ts(finding.get("timestamp_observed"))
    present: set[str] = set()
    any_ts_pair = False
    any_ts_aligned = False

    for g in case_findings or []:
        if g is finding:
            continue
        if str(g.get("finding_status") or "").upper() == "REJECTED":
            continue
        g_class = source_class_from_finding(g)
        if not g_class or g_class == f_class:
            continue
        g_tokens = _entity_tokens(g)
        if not (f_tokens & g_tokens):
            continue  # no shared structured entity -> not the same activity
        present.add(g_class)
        g_ts = _parse_ts(g.get("timestamp_observed"))
        if f_ts is not None and g_ts is not None:
            any_ts_pair = True
            if abs(f_ts - g_ts) <= window_seconds:
                any_ts_aligned = True

    if not any_ts_pair:
        aligned = "unknown"
    else:
        aligned = "true" if any_ts_aligned else "false"
    return present, aligned


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------
@dataclass
class CorroborationState:
    finding_id: Optional[str]
    artifact: Optional[str]
    advisory_corroboration_tier: str
    timestamp_aligned: str
    present_sources: list[str]
    gap_sources: list[str]
    suggested_tools: list[str]
    rationale: str
    advisory_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "finding_id": self.finding_id,
            "artifact": self.artifact,
            "advisory_corroboration_tier": self.advisory_corroboration_tier,
            "timestamp_aligned": self.timestamp_aligned,
            "present_sources": self.present_sources,
            "gap_sources": self.gap_sources,
            "suggested_tools": self.suggested_tools,
            "rationale": self.rationale,
        }
        if self.advisory_error:
            d["advisory_error"] = self.advisory_error
        return d


def _tier_for_sources(source_classes: set[str], fk_slice: dict[str, Any]) -> str:
    """Display tier. Execution-class -> reuse _derive_execution_confidence;
    otherwise count-based against the FK 'tiers' semantics (1/2/3+)."""
    if source_classes & EXECUTION_SOURCE_CLASSES:
        # normalize mft_timestomp -> mft for the trinity check
        normalized = {("mft" if s == "mft_timestomp" else s) for s in source_classes}
        conf, _ = _derive_execution_confidence(normalized)
        if conf >= 1.0:
            return "confirmed"
        if conf >= 0.85:
            return "probable"
        if conf >= 0.80:
            return "probable"
        return "observation"
    # non-execution: pure count
    n = len(source_classes)
    if n >= 3:
        return "confirmed"
    if n == 2:
        return "probable"
    return "observation"


def corroboration_state(
    finding: dict[str, Any],
    case_findings: list[dict[str, Any]],
    fk_slice: Optional[dict[str, Any]],
    *,
    window_seconds: int = 300,
) -> CorroborationState:
    """Compute advisory corroboration state for *finding*. Fail-soft."""
    fid = finding.get("finding_id")
    artifact = (fk_slice or {}).get("artifact")
    try:
        f_class = source_class_from_finding(finding)
        present, aligned = present_corroborators(
            finding, case_findings, window_seconds=window_seconds
        )
        all_sources = set(present)
        if f_class:
            all_sources.add(f_class)

        tier = _tier_for_sources(all_sources, fk_slice or {})

        # timestamp-alignment cap: if the next-tier combo requires alignment and
        # alignment is not satisfied, cap at probable.
        capped = False
        combos = ((fk_slice or {}).get("corroboration_escalation") or {}).get("combinations") or []
        if tier == "confirmed" and aligned in {"false", "unknown"}:
            if _combos_require_alignment(combos):
                tier = "probable"
                capped = True

        gap_sources, suggested_tools = _greedy_gap(present, tier, combos)

        rationale = _build_rationale(
            f_class, present, tier, aligned, capped, gap_sources
        )
        return CorroborationState(
            finding_id=fid, artifact=artifact,
            advisory_corroboration_tier=tier, timestamp_aligned=aligned,
            present_sources=sorted(present), gap_sources=gap_sources,
            suggested_tools=suggested_tools, rationale=rationale,
        )
    except Exception as exc:  # fail-soft: never break report generation
        return CorroborationState(
            finding_id=fid, artifact=artifact,
            advisory_corroboration_tier="observation", timestamp_aligned="unknown",
            present_sources=[], gap_sources=[], suggested_tools=[],
            rationale=f"{ADVISORY_DISCLAIMER}",
            advisory_error=str(exc),
        )


def _combos_require_alignment(combos: list[Any]) -> bool:
    for combo in combos or []:
        if isinstance(combo, dict) and str(combo.get("plus_timestamps") or "").strip():
            return True
    return False


def _greedy_gap(
    present: set[str], current_tier: str, combos: list[Any]
) -> tuple[list[str], list[str]]:
    """Lowest-rank combination whose upgrades_to exceeds current_tier; gap =
    its sources minus present. Unresolvable sources are dropped from tools but
    retained as advisory gap labels. Artifact-scoped (combos are F's own slice)."""
    cur_rank = _TIER_ORDER.get(current_tier, 0)
    for combo in combos or []:
        if not isinstance(combo, dict):
            continue
        up = parse_upgrade_tier(combo.get("upgrades_to"))
        if up is None or _TIER_ORDER.get(up, 0) <= cur_rank:
            continue
        sources = combo.get("sources")
        if not isinstance(sources, list):
            continue
        gap_labels: list[str] = []
        tools: list[str] = []
        for src in sources:
            entry = resolve_source(src)
            if entry and entry.source_class in present:
                continue  # already have it
            gap_labels.append(str(src))
            if entry and entry.mcp_tool and entry.mcp_tool not in tools:
                tools.append(entry.mcp_tool)
        if gap_labels:
            return gap_labels, tools
    return [], []


def _build_rationale(
    f_class: Optional[str], present: set[str], tier: str,
    aligned: str, capped: bool, gap: list[str],
) -> str:
    parts = [ADVISORY_DISCLAIMER + "."]
    src = f_class or "this artifact"
    if present:
        parts.append(
            f"{src} corroborated by {len(present)} source(s) "
            f"({', '.join(sorted(present))}) -> {tier}."
        )
    else:
        parts.append(f"{src} alone -> {tier} (no corroborating source found).")
    if capped:
        parts.append("Tier capped at probable: required timestamp alignment "
                     f"is {aligned}.")
    if gap:
        parts.append("To strengthen, corroborate with: " + "; ".join(gap[:4]) + ".")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Pure FK loader (mirrors server precedence; NO server import) - for ITEM C
# ---------------------------------------------------------------------------
def _fk_bases() -> list[Path]:
    return [
        Path("/opt/valhuntir-knowledge/packages/forensic-knowledge/data"),
        Path(__file__).parent.parent / "data" / "forensic-knowledge",
    ]


def load_fk_slice(artifact: str) -> dict[str, Any]:
    """Load one artifact's FK YAML (external-first, vendored fallback). {} if absent."""
    name = str(artifact or "").strip()
    if not name:
        return {}
    for base in _fk_bases():
        for platform in ("windows", "linux"):
            p = base / "artifacts" / platform / f"{name}.yaml"
            if p.exists():
                try:
                    import yaml
                    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                except Exception:
                    return {}
    return {}
