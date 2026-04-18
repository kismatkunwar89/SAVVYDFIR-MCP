"""Report-generation helpers that stay importable without FastMCP."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Callable


def _status_label(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


# Status precedence: CONFIRMED findings surface first, then HYPOTHESIS → OBSERVATION.
# REJECTED findings are demoted to last.
_STATUS_PRECEDENCE: dict[str, int] = {
    "CONFIRMED": 4,
    "HYPOTHESIS": 3,
    "ACTIVE": 2,
    "OBSERVATION": 1,
    "REJECTED": 0,
}


def _short_description(value: Any, limit: int = 140) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _rank_findings(findings: list[dict[str, Any]], *, limit: int = 25) -> list[dict[str, Any]]:
    def _sort_key(finding: dict[str, Any]) -> tuple[int, float, str]:
        status = _status_label(finding.get("finding_status"))
        precedence = _STATUS_PRECEDENCE.get(status, 1)
        confidence = float(finding.get("confidence", 0.0) or 0.0)
        recency = str(finding.get("updated_at") or finding.get("created_at") or "")
        return (precedence, confidence, recency)

    ranked = sorted(findings, key=_sort_key, reverse=True)
    return [dict(finding) for finding in ranked[:limit]]


def _split_findings_by_status(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Bucket findings by normalized status."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        status = _status_label(f.get("finding_status"))
        buckets.setdefault(status, []).append(f)
    return buckets


def _count_by_key(
    findings: list[dict[str, Any]], key: str,
) -> dict[str, int]:
    """Count findings grouped by a given key field."""
    counts: dict[str, int] = {}
    for f in findings:
        val = str(f.get(key) or "UNKNOWN").upper()
        counts[val] = counts.get(val, 0) + 1
    return counts


def _render_findings_rows(findings: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('finding_id', '')))}</td>"
            f"<td>{html.escape(_status_label(finding.get('finding_status')))}</td>"
            f"<td>{float(finding.get('confidence', 0.0) or 0.0):.3f}</td>"
            f"<td>{html.escape(str(finding.get('tool_name', '')))}</td>"
            f"<td>{html.escape(_short_description(finding.get('description', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='5'>No findings recorded.</td></tr>"


def _render_tactic_tags(tactics: list[dict[str, Any]], *, class_name: str) -> str:
    if not tactics:
        return "<span class='tag muted'>None</span>"
    return "".join(
        f"<span class='tag {class_name}'>{html.escape(tactic['id'])} — {html.escape(tactic['name'])}</span>"
        for tactic in tactics
    )


def _render_suggested_tools(suggestions: dict[str, list[str]]) -> str:
    if not suggestions:
        return "<li>No additional ATT&amp;CK blind-spot follow-up suggested.</li>"
    items: list[str] = []
    for tactic_id, tools in suggestions.items():
        items.append(
            f"<li><strong>{html.escape(tactic_id)}</strong>: {html.escape(', '.join(tools))}</li>"
        )
    return "\n".join(items)


def render_report_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    sigma = payload["sigma_scan"]
    coverage = payload["coverage"]
    top_findings = payload["top_findings"]
    open_questions = payload.get("open_questions", [])
    status_breakdown = payload.get("status_breakdown", {})
    evidence_kind_breakdown = payload.get("evidence_kind_breakdown", {})

    confirmed_count = status_breakdown.get("CONFIRMED", 0)
    hypothesis_count = status_breakdown.get("HYPOTHESIS", 0) + status_breakdown.get("ACTIVE", 0)

    # Split top findings into confirmed vs active leads
    confirmed_findings = [
        f for f in top_findings
        if _status_label(f.get("finding_status")) == "CONFIRMED"
    ]
    active_findings = [
        f for f in top_findings
        if _status_label(f.get("finding_status")) in ("HYPOTHESIS", "ACTIVE", "OBSERVATION")
    ]

    no_confirmed_banner = ""
    if confirmed_count == 0:
        no_confirmed_banner = (
            '<div class="card" style="border-color: var(--warn);">'
            '<h2 style="color: var(--warn);">No Structurally Confirmed Findings</h2>'
            "<p>No findings have been independently corroborated by multiple artifact sources. "
            "All findings below are hypotheses or observations that require further validation.</p>"
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAVVYDFIR-MCP Report — {html.escape(payload['case_id'])}</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #111827;
    --card: #1f2937;
    --border: #374151;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --good: #22c55e;
    --warn: #f59e0b;
    --danger: #ef4444;
    --mono: 'JetBrains Mono', 'Cascadia Code', monospace;
    --sans: 'Inter', system-ui, sans-serif;
  }}
  body {{ margin: 0; background: radial-gradient(circle at top, #172554, var(--bg)); color: var(--text); font-family: var(--sans); }}
  main {{ max-width: 1180px; margin: 0 auto; padding: 2rem; }}
  h1, h2 {{ margin: 0 0 0.75rem; }}
  p, li {{ color: var(--text); }}
  .subtitle {{ color: var(--muted); margin-bottom: 1.5rem; font-family: var(--mono); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ background: color-mix(in srgb, var(--card) 88%, black); border: 1px solid var(--border); border-radius: 16px; padding: 1rem 1.1rem; margin-bottom: 1.2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.18); }}
  .metric-label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  .metric-value {{ font-size: 1.8rem; font-weight: 700; margin-top: 0.3rem; }}
  .accent {{ color: var(--accent); }}
  .good {{ color: var(--good); }}
  .warn {{ color: var(--warn); }}
  .danger {{ color: var(--danger); }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 0.45rem; }}
  .tag {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 999px; font-size: 0.78rem; font-family: var(--mono); }}
  .tag.covered {{ background: rgba(34,197,94,0.15); color: #86efac; border: 1px solid rgba(34,197,94,0.25); }}
  .tag.uncovered {{ background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.25); }}
  .tag.muted {{ background: rgba(156,163,175,0.12); color: var(--muted); border: 1px solid rgba(156,163,175,0.18); }}
  pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: rgba(15,23,42,0.85); border: 1px solid var(--border); border-radius: 12px; padding: 1rem; font-family: var(--mono); color: #dbeafe; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th, td {{ text-align: left; padding: 0.7rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.08); vertical-align: top; }}
  th {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  ul {{ margin: 0.3rem 0 0; padding-left: 1.2rem; }}
</style>
</head>
<body>
<main>
  <h1>SAVVYDFIR-MCP Investigation Report</h1>
  <div class="subtitle">{html.escape(payload['case_id'])} · {html.escape(str(payload['report_path']))}</div>

  <section class="grid">
    <div class="card"><div class="metric-label">Case Status</div><div class="metric-value accent">{html.escape(summary.get('status', 'UNKNOWN'))}</div></div>
    <div class="card"><div class="metric-label">Findings</div><div class="metric-value">{summary.get('findings_count', 0)}</div></div>
    <div class="card"><div class="metric-label">Confirmed</div><div class="metric-value good">{summary.get('confirmed_count', 0)}</div></div>
    <div class="card"><div class="metric-label">Unresolved</div><div class="metric-value warn">{summary.get('unresolved_discrepancies', 0)}</div></div>
    <div class="card"><div class="metric-label">Sigma Hits</div><div class="metric-value danger">{sigma.get('total_hits', 0)}</div></div>
    <div class="card"><div class="metric-label">Coverage</div><div class="metric-value">{coverage.get('coverage_percent', 0):.1f}%</div></div>
  </section>

  <section class="card">
    <h2>Executive Summary</h2>
    <p>Case <strong>{html.escape(payload['case_id'])}</strong> contains <strong>{summary.get('findings_count', 0)}</strong> findings, of which <strong>{confirmed_count}</strong> are confirmed and <strong>{hypothesis_count}</strong> are hypotheses/active leads. The current unresolved discrepancy count is <strong>{summary.get('unresolved_discrepancies', 0)}</strong>. Sigma preflight reported <strong>{sigma.get('critical_count', 0)}</strong> CRITICAL and <strong>{sigma.get('high_count', 0)}</strong> HIGH anomalies.</p>
  </section>

  {no_confirmed_banner}

  <section class="card">
    <h2>Sigma Anomaly Summary</h2>
    <pre>{html.escape(str(sigma.get('summary_markdown', 'No anomalies detected.')))}</pre>
  </section>

  <section class="card">
    <h2>ATT&amp;CK Coverage</h2>
    <p>Coverage is currently <strong>{coverage.get('coverage_percent', 0):.1f}%</strong>.</p>
    <div class="metric-label">Covered Tactics</div>
    <div class="tags">{_render_tactic_tags(coverage.get('covered_tactics', []), class_name='covered')}</div>
    <div class="metric-label" style="margin-top: 1rem;">Uncovered Tactics</div>
    <div class="tags">{_render_tactic_tags(coverage.get('uncovered_tactics', []), class_name='uncovered')}</div>
    <div class="metric-label" style="margin-top: 1rem;">Suggested Next Tools</div>
    <ul>{_render_suggested_tools(coverage.get('suggested_next_tools', {}))}</ul>
  </section>

  <section class="card">
    <h2>Open Questions</h2>
    <ul>
      {''.join(f"<li>{html.escape(str(question))}</li>" for question in open_questions) if open_questions else '<li>No open questions recorded.</li>'}
    </ul>
  </section>

  <section class="card">
    <h2>Top Confirmed Findings</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Status</th><th>Confidence</th><th>Tool</th><th>Description</th></tr>
      </thead>
      <tbody>
        {_render_findings_rows(confirmed_findings) if confirmed_findings else "<tr><td colspan='5'>No confirmed findings — all evidence requires further corroboration.</td></tr>"}
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>Top Active Leads</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Status</th><th>Confidence</th><th>Tool</th><th>Description</th></tr>
      </thead>
      <tbody>
        {_render_findings_rows(active_findings)}
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>Findings Status Breakdown</h2>
    <div class="grid">
      {''.join(f'<div class="card"><div class="metric-label">{html.escape(k)}</div><div class="metric-value">{v}</div></div>' for k, v in sorted(status_breakdown.items()))}
    </div>
  </section>
</main>
</body>
</html>
"""


def generate_report_payload(
    *,
    case_id: str,
    state_manager: Any,
    sigma_scan_fn: Callable[[str], dict[str, Any]],
    coverage_fn: Callable[[str], dict[str, Any]],
    reports_root: str = "./reports",
) -> dict[str, Any]:
    """Build the final report payload, write HTML, and then mark the case complete."""
    sigma_result = sigma_scan_fn(case_id)
    if sigma_result.get("status") == "error":
        return {
            "status": "error",
            "tool": "generate_report",
            "error": sigma_result.get("error", "sigma_scan preflight failed"),
            "sigma_scan": sigma_result,
        }

    coverage_result = coverage_fn(case_id)
    if coverage_result.get("status") == "error":
        return {
            "status": "error",
            "tool": "generate_report",
            "error": coverage_result.get("error", "coverage_report failed"),
            "sigma_scan": sigma_result,
            "coverage": coverage_result,
        }

    findings = state_manager.get_findings()
    pre_summary = state_manager.to_summary()
    report_dir = (Path(reports_root) / case_id).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.html"

    status_breakdown = _count_by_key(findings, "finding_status")
    evidence_kind_breakdown = _count_by_key(findings, "evidence_kind")

    payload = {
        "status": "ok",
        "case_id": case_id,
        "summary": {**pre_summary, "status": "COMPLETE"},
        "findings_count": pre_summary.get("findings_count", 0),
        "unresolved_count": pre_summary.get("unresolved_discrepancies", 0),
        "open_questions": pre_summary.get("open_questions", []),
        "sigma_scan": sigma_result,
        "coverage": coverage_result,
        "top_findings": _rank_findings(findings),
        "status_breakdown": status_breakdown,
        "evidence_kind_breakdown": evidence_kind_breakdown,
        "report_path": str(report_path),
    }
    payload["top_confirmed_findings"] = [
        dict(finding)
        for finding in payload["top_findings"]
        if _status_label(finding.get("finding_status")) == "CONFIRMED"
    ][:10]
    payload["top_active_leads"] = [
        dict(finding)
        for finding in payload["top_findings"]
        if _status_label(finding.get("finding_status")) in {"HYPOTHESIS", "ACTIVE", "OBSERVATION"}
    ][:10]

    report_path.write_text(render_report_html(payload), encoding="utf-8")

    state_manager.set_status("COMPLETE")
    summary = state_manager.to_summary()
    payload["summary"] = summary
    payload["findings_count"] = summary.get("findings_count", 0)
    payload["unresolved_count"] = summary.get("unresolved_discrepancies", 0)
    payload["open_questions"] = summary.get("open_questions", [])
    return payload
