"""Evaluation-only FOR508/baseline report scorer.

This module intentionally does not import ``sift_mcp``. It scores finalized
``report.json`` artifacts only, so baseline expectations cannot leak into
runtime detectors or runners.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

FORBIDDEN_REPORT_NAMES = {"state.json", "audit.jsonl"}


def load_finalized_report(report_json: str | Path, *, archived_case_only: bool = False) -> dict[str, Any]:
    path = Path(report_json).resolve()
    if path.name in FORBIDDEN_REPORT_NAMES or path.name != "report.json":
        raise ValueError("Eval scorer accepts only finalized reports/{case_id}/report.json artifacts.")
    if not path.exists():
        raise FileNotFoundError(path)
    if not archived_case_only and any(part == "analysis" for part in path.parts):
        raise ValueError("Refusing live analysis paths; pass a finalized reports/{case_id}/report.json.")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise ValueError("report.json must be a finalized successful report payload.")
    return payload


def score_report(report: dict[str, Any], baseline_text: str = "") -> dict[str, Any]:
    detectors = set(report.get("sigma_scan", {}).get("detectors_run", []))
    required_sections = {
        "actionable_leads": bool(report.get("actionable_leads")),
        "artifact_coverage": bool(report.get("artifact_coverage") or report.get("coverage")),
        "triage_status": bool(report.get("triage_status")),
        "structured_pivots": all(
            isinstance(lead.get("next_pivot"), dict)
            and {"tool", "args", "human_readable"} <= set(lead.get("next_pivot", {}))
            for lead in report.get("actionable_leads", [])
        ),
    }
    high_signal = {
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
    return {
        "status": "ok",
        "detectors_present": sorted(detectors & high_signal),
        "detectors_missing": sorted(high_signal - detectors),
        "sections": required_sections,
        "baseline_terms_seen": _baseline_term_count(baseline_text),
    }


def _baseline_term_count(text: str) -> int:
    lowered = text.lower()
    return sum(1 for term in ("for508", "mft", "amcache", "prefetch", "defender") if term in lowered)


def main() -> int:
    parser = argparse.ArgumentParser(description="Score finalized SAVVYDFIR report.json artifacts.")
    parser.add_argument("report_json")
    parser.add_argument("--baseline", default=None)
    parser.add_argument("--archived-case-only", action="store_true")
    args = parser.parse_args()
    report = load_finalized_report(args.report_json, archived_case_only=args.archived_case_only)
    baseline_text = Path(args.baseline).read_text(encoding="utf-8") if args.baseline else ""
    print(json.dumps(score_report(report, baseline_text), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
