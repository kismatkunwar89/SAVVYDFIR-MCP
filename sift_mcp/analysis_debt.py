"""Agnostic analysis-debt detection (PART B, validated 2026-06-03).

Closes the "compliance-by-extraction" failure mode: an extraction tool runs and
writes a durable CSV/JSON handle, but the agent never analyzes it (0 run_analysis,
0 analyst finding) and the framework still reports the case as done. ROCBA shipped
at 63% recall this way -- the 4 misses were all unmined file-access artifacts.

This module is PURE and self-contained:
  * No import from server.py / reporting.py (avoids the server<->reporting cycle).
  * compute_analysis_debt(...) takes ledger rows + a selector + durable roots and
    returns {blocking, warning, by_lane, next_required_actions}.
  * EXTRACTION_CATALOG is the single source of truth for which tools accrue debt,
    which lane owns them, and which produce analyzable handles. reporting.py
    derives FILE_ACCESS_TOOL_SUFFIXES from it (additive migration; a unit test
    guards drift against the legacy _COVERAGE_SUFFIX_LANES coverage map).

Signed-off invariants (do not weaken without re-review):
  1. Debt clears ONLY via an analyst submit_finding (assigned_agent provenance) OR
     a documented-negative. A run_analysis ALONE never clears -- the goal is
     findings, not queries. (Item 1.)
  2. Auto-emitted extraction observation findings (tool_name == the extraction
     tool, no assigned_agent) DO NOT clear debt -- else the detector is defeated
     at birth by the file-access tools' own ACTIVE-0.70 observations. (Item 1.)
  3. Per-handle, not per-execution: a multi-handle execution accrues debt per
     durable analyzable handle. (Item 1.)
  4. A substantive run_analysis only down-modulates WARN copy via
     run_analysis_seen; it is informational. (Item 1.)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Single extraction catalog (one source of truth for debt accrual + ownership)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CatalogEntry:
    tool_suffix: str
    lane_id: Optional[str]
    taxonomy_group: str  # baseline | file_access | extended | memory
    is_extraction: bool = True
    report_block_when_required: bool = False
    analyzable_outputs: frozenset[str] = field(default_factory=lambda: frozenset({"csv"}))


# taxonomy_group=="file_access" entries fold into the disk_execution_persistence
# lane for MVP (review: no new file_access lane until lanes are
# taxonomy-aware). report_block_when_required=True only on that group so the
# report gate blocks exactly the ROCBA-shaped misses and WARNs everything else.
EXTRACTION_CATALOG: tuple[CatalogEntry, ...] = (
    # --- memory (analyzable only when the tool emits a CSV, e.g. scan_network) -
    CatalogEntry("scan_network", "memory", "memory"),
    # --- baseline / extended disk -------------------------------------------
    CatalogEntry("extract_mft_timeline", "timeline_correlation", "baseline"),
    CatalogEntry("extract_usn_journal", "timeline_correlation", "baseline"),
    CatalogEntry("summarize_evtx", "event_auth", "baseline"),
    CatalogEntry("extract_registry_run_keys", "disk_execution_persistence", "baseline"),
    CatalogEntry("get_amcache", "disk_execution_persistence", "baseline"),
    CatalogEntry("extract_prefetch", "disk_execution_persistence", "baseline"),
    CatalogEntry("extract_shimcache", "disk_execution_persistence", "extended"),
    CatalogEntry("extract_srum", "timeline_correlation", "extended"),
    CatalogEntry(
        "sigma_hunt", None, "extended",
        analyzable_outputs=frozenset({"json"}),
    ),
    # --- file-access bundle (taxonomy-conditional BLOCK tier) ----------------
    CatalogEntry("extract_shellbags", "disk_execution_persistence", "file_access", report_block_when_required=True),
    CatalogEntry("extract_lnk_files", "disk_execution_persistence", "file_access", report_block_when_required=True),
    CatalogEntry("extract_jump_lists", "disk_execution_persistence", "file_access", report_block_when_required=True),
    CatalogEntry("extract_browser_history", "disk_execution_persistence", "file_access", report_block_when_required=True),
    CatalogEntry("extract_registry_fileaccess", "disk_execution_persistence", "file_access", report_block_when_required=True),
    # --- taxonomy-conditional-REQUIRED file-access extractors (review
    # 2026-06-07 AMEND-THEN-APPROVE): promoted from extended/OPTIONAL to the
    # file_access group so the coverage gate enforces them on file-centric
    # Windows cases. Documented-absence (incl. tool_incompatible) still satisfies
    # the gate, so non-Windows/mount-less hosts do not brick.
    CatalogEntry("extract_recycle_bin", "disk_execution_persistence", "file_access", report_block_when_required=True),
    CatalogEntry("extract_powershell_history", "disk_execution_persistence", "file_access", report_block_when_required=True),
    CatalogEntry("extract_scheduled_tasks", "disk_execution_persistence", "file_access", report_block_when_required=True),
)

_CATALOG_BY_SUFFIX: dict[str, CatalogEntry] = {e.tool_suffix: e for e in EXTRACTION_CATALOG}

# Derived view consumed by reporting.py (back-compat; one source of truth).
FILE_ACCESS_TOOL_SUFFIXES: tuple[str, ...] = tuple(
    e.tool_suffix for e in EXTRACTION_CATALOG if e.taxonomy_group == "file_access"
)


# ---------------------------------------------------------------------------
# Self-contained path helpers (pure; no server.py dependency)
# ---------------------------------------------------------------------------
def _resolve(path: Any) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    try:
        return str(Path(text).resolve())
    except Exception:
        return text


def _is_transient(path: str) -> bool:
    p = path.lower()
    return p.startswith("/tmp/savvydfir_") or p.startswith("/var/tmp/savvydfir_")


# report/state/audit/graph artifacts are NOT analyzable handles even though they
# live under the case dir (design review denylist).
_DENY_BASENAMES = frozenset({
    "report.json", "report.html", "graph.json", "graph.html",
    "state.json", "audit.jsonl",
})
_DENY_SUFFIXES = (".plaso", ".html", ".log")


def _suffix_kind(path: str) -> Optional[str]:
    low = path.lower()
    if low.endswith(".csv"):
        return "csv"
    if low.endswith(".json"):
        return "json"
    return None


def _under_roots(path: str, roots: tuple[str, ...]) -> bool:
    if not roots:
        # No roots configured -> accept any non-transient durable-looking path.
        return True
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def _is_analyzable_handle(path: str, allowed_kinds: frozenset[str], roots: tuple[str, ...]) -> bool:
    if not path or _is_transient(path):
        return False
    name = Path(path).name.lower()
    if name in _DENY_BASENAMES:
        return False
    if any(name.endswith(s) for s in _DENY_SUFFIXES):
        return False
    kind = _suffix_kind(path)
    if kind is None or kind not in allowed_kinds:
        return False
    return _under_roots(path, roots)


# ---------------------------------------------------------------------------
# Ledger interpretation helpers
# ---------------------------------------------------------------------------
def tool_suffix(tool_name: Any) -> str:
    tn = str(tool_name or "").strip()
    return tn.rsplit(".", 1)[-1] if "." in tn else tn


_SCHEMA_ONLY_RE = re.compile(
    r"^\s*df\s*\.\s*(dtypes|shape|columns|info\s*\(|head\s*\(|describe\s*\(|tail\s*\()",
    re.IGNORECASE,
)

_ABSENCE_TOKENS = (
    "no_windows_volume_at_image_path",
    "no_windows_volume",
    "artifact_absent",
    "no_data",
    "documented_absence",
    "tool_incompatible",
)


def _is_substantive_query(query: Any) -> bool:
    q = str(query or "").strip()
    if not q:
        return False
    return _SCHEMA_ONLY_RE.match(q) is None


def _is_documented_negative(execution: dict[str, Any]) -> bool:
    summary = str(execution.get("outputs_summary") or "").lower()
    return any(tok in summary for tok in _ABSENCE_TOKENS)


def _is_analyst_finding(f: dict[str, Any]) -> bool:
    """True iff the finding came through submit_finding (analyst provenance).

    Auto-emitted extraction observations carry tool_name == the extraction tool
    and no assigned_agent -- they must NOT clear debt (signed invariant #2).
    """
    if str(f.get("tool_name") or "").strip().lower().endswith("submit_finding"):
        return True
    return bool(str(f.get("assigned_agent") or "").strip())


def _execution_handles(execution: dict[str, Any], entry: CatalogEntry, roots: tuple[str, ...]) -> list[str]:
    """Resolved, deduped durable analyzable handle paths produced by *execution*."""
    candidates: list[Any] = []
    refs = execution.get("raw_evidence_refs")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                role = str(ref.get("role") or "").strip().lower()
                # inputs (disk image, mount) are not analyzable derived handles
                if role in {"input"}:
                    continue
                candidates.append(ref.get("path"))
    for key in ("csv_path", "suppressed_csv_path", "output_path", "storage_path", "artifact_path"):
        candidates.append(execution.get(key))

    seen: set[str] = set()
    handles: list[str] = []
    for cand in candidates:
        resolved = _resolve(cand)
        if not resolved or resolved in seen:
            continue
        if _is_analyzable_handle(resolved, entry.analyzable_outputs, roots):
            seen.add(resolved)
            handles.append(resolved)
    return handles


@dataclass
class Debt:
    handle_path: str
    execution_id: str
    tool_suffix: str
    lane_id: Optional[str]
    taxonomy_group: str
    run_analysis_seen: bool
    required_evidence: str = "finding|documented_negative"

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle_path": self.handle_path,
            "execution_id": self.execution_id,
            "tool_suffix": self.tool_suffix,
            "lane_id": self.lane_id,
            "taxonomy_group": self.taxonomy_group,
            "run_analysis_seen": self.run_analysis_seen,
            "required_evidence": self.required_evidence,
        }


def compute_analysis_debt(
    executions: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    selector: Optional[dict[str, Any]] = None,
    *,
    analysis_roots: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Pure ledger-derived analysis-debt computation.

    Parameters
    ----------
    executions:
        state.executions rows (each: tool_name, execution_id, parameters,
        outputs_summary, raw_evidence_refs, csv_path/output_path/...).
    findings:
        state.findings rows.
    selector:
        file-access selector snapshot; only ``file_access_bundle_required`` is read.
    analysis_roots:
        Resolved durable roots (OUTPUT_BASE, /cases/<case>/artifacts, analysis dir).
        Empty -> accept any non-transient durable path.

    Returns
    -------
    {blocking: [Debt.dict], warning: [Debt.dict], by_lane: {lane: [...]},
     next_required_actions: [...]}
    """
    executions = executions or []
    findings = findings or []
    bundle_required = bool((selector or {}).get("file_access_bundle_required"))

    # --- index: run_analysis executions by resolved data_path ----------------
    ra_paths: set[str] = set()              # any run_analysis target
    ra_substantive_paths: set[str] = set()  # query beyond schema-inspect
    ra_exec_for_path: dict[str, set[str]] = {}
    for ex in executions:
        if tool_suffix(ex.get("tool_name")) != "run_analysis":
            continue
        params = ex.get("parameters") if isinstance(ex.get("parameters"), dict) else {}
        dp = _resolve(params.get("data_path"))
        if not dp:
            continue
        ra_paths.add(dp)
        ra_exec_for_path.setdefault(dp, set()).add(str(ex.get("execution_id") or ""))
        if _is_substantive_query(params.get("query")):
            ra_substantive_paths.add(dp)

    # --- index: analyst-finding clearance keys -------------------------------
    analyst_exec_ids: set[str] = set()
    analyst_artifact_paths: set[str] = set()
    for f in findings:
        if not _is_analyst_finding(f):
            continue
        for key in ("source_execution_id", "execution_id"):
            val = str(f.get(key) or "").strip()
            if val:
                analyst_exec_ids.add(val)
        ap = _resolve(f.get("artifact_path"))
        if ap:
            analyst_artifact_paths.add(ap)

    def _handle_cleared(handle: str, exec_id: str) -> bool:
        # analyst finding citing the extraction execution directly
        if exec_id and exec_id in analyst_exec_ids:
            return True
        # analyst finding citing a run_analysis execution that targeted this handle
        if analyst_exec_ids & ra_exec_for_path.get(handle, set()):
            return True
        # analyst finding whose artifact_path resolves to this handle
        if handle in analyst_artifact_paths:
            return True
        return False

    blocking: list[Debt] = []
    warning: list[Debt] = []
    by_lane: dict[str, list[dict[str, Any]]] = {}

    for ex in executions:
        suffix = tool_suffix(ex.get("tool_name"))
        entry = _CATALOG_BY_SUFFIX.get(suffix)
        if entry is None or not entry.is_extraction:
            continue
        # documented-negative clears every handle of this execution
        if _is_documented_negative(ex):
            continue
        exec_id = str(ex.get("execution_id") or "")
        handles = _execution_handles(ex, entry, analysis_roots)
        # tool ran but produced no durable analyzable handle -> nothing to mine
        if not handles:
            continue
        for handle in handles:
            if _handle_cleared(handle, exec_id):
                continue
            debt = Debt(
                handle_path=handle,
                execution_id=exec_id,
                tool_suffix=suffix,
                lane_id=entry.lane_id,
                taxonomy_group=entry.taxonomy_group,
                run_analysis_seen=handle in ra_substantive_paths,
            )
            is_blocking = bundle_required and entry.report_block_when_required
            (blocking if is_blocking else warning).append(debt)
            if entry.lane_id:
                by_lane.setdefault(entry.lane_id, []).append(debt.to_dict())

    def _actions(debts: list[Debt]) -> list[dict[str, Any]]:
        return [
            {
                "handle_path": d.handle_path,
                "execution_id": d.execution_id,
                "tool_suffix": d.tool_suffix,
                "lane_id": d.lane_id,
                "required_evidence": d.required_evidence,
                "tier": "blocking",
            }
            for d in debts
        ]

    return {
        "blocking": [d.to_dict() for d in blocking],
        "warning": [d.to_dict() for d in warning],
        "by_lane": by_lane,
        "next_required_actions": _actions(blocking),
    }


def lane_debt(by_lane: dict[str, list[dict[str, Any]]], lane_id: str) -> list[dict[str, Any]]:
    """Unmined handles owned by *lane_id* (for record_analysis_lane gating)."""
    return list((by_lane or {}).get(lane_id, []))


def data_gaps_fingerprint(data_gaps: Any) -> str:
    """Order-independent fingerprint of a lane's data_gaps list.

    The record_analysis_lane duplicate-noop guard compares status + execution_ids
    + finding_ids but NOT data_gaps -- so a COMPLETE_WITH_GAPS -> COMPLETE_WITH_GAPS
    resubmit that ADDS gaps (after a debt reject) was swallowed as a duplicate
    (review ship-blocker #2). Folding this fingerprint into the noop check makes a
    gap-only change a real write.
    """
    if not isinstance(data_gaps, list):
        return "0"
    parts: list[str] = []
    for gap in data_gaps:
        if isinstance(gap, dict):
            parts.append("|".join(
                f"{k}={gap.get(k)}" for k in sorted(gap.keys())
            ))
        else:
            parts.append(str(gap))
    return ";".join(sorted(parts))
