#!/usr/bin/env python3
"""
build_index.py — Generates reports/index.html for SAVVYDFIR-MCP.

Scans the reports directory for per-host ``graph.json`` files, reads
investigation metadata from each, and produces a self-contained HTML index
page listing all investigations with status, finding counts, and links.

Usage
-----
::

    python3 scripts/build_index.py \\
        [--reports-dir ./reports]

The index is always written to ``<reports-dir>/index.html``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["main"]


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAVVYDFIR-MCP — Investigation Reports</title>
<style>
  :root {
    --bg:        #0f172a;
    --surface:   #1e293b;
    --border:    #334155;
    --text:      #e2e8f0;
    --muted:     #94a3b8;
    --accent:    #3b82f6;
    --green:     #22c55e;
    --yellow:    #eab308;
    --orange:    #f97316;
    --red:       #ef4444;
    --violet:    #8b5cf6;
    --font:      'Inter', system-ui, sans-serif;
    --mono:      'JetBrains Mono', 'Cascadia Code', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
  }
  h1 {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
    color: #fff;
  }
  .subtitle { color: var(--muted); margin-bottom: 2rem; font-size: 0.9rem; }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    margin-bottom: 1rem;
    overflow: hidden;
  }
  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    gap: 1rem;
  }
  .case-id {
    font-family: var(--mono);
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--accent);
  }
  .status-badge {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .status-complete  { background: #14532d; color: var(--green); }
  .status-progress  { background: #1c3461; color: #60a5fa; }
  .status-failed    { background: #450a0a; color: var(--red); }
  .status-unknown   { background: #1e293b; color: var(--muted); }
  .card-body {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 0;
  }
  .stat {
    padding: 0.75rem 1rem;
    border-right: 1px solid var(--border);
  }
  .stat:last-child { border-right: none; }
  .stat-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; }
  .stat-value { font-size: 1.1rem; font-weight: 700; margin-top: 0.1rem; }
  .card-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 1rem;
    border-top: 1px solid var(--border);
    font-size: 0.8rem;
    color: var(--muted);
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .btn {
    display: inline-block;
    padding: 0.3rem 0.8rem;
    border-radius: 0.3rem;
    font-size: 0.8rem;
    font-weight: 600;
    text-decoration: none;
    background: var(--accent);
    color: #fff;
    transition: opacity 0.15s;
  }
  .btn:hover { opacity: 0.85; }
  .btn-unified {
    background: var(--violet);
  }
  .tactic-bar {
    display: flex;
    gap: 0.3rem;
    flex-wrap: wrap;
    padding: 0.5rem 1rem 0.75rem;
  }
  .tactic-tag {
    background: #1e3a5f;
    color: #60a5fa;
    border-radius: 999px;
    padding: 0.1rem 0.55rem;
    font-size: 0.7rem;
    font-family: var(--mono);
  }
  .unified-section {
    margin-bottom: 2rem;
  }
  .unified-card {
    background: #1a1040;
    border: 1px solid var(--violet);
  }
  .unified-card .card-header {
    border-bottom-color: var(--violet);
  }
  .section-title {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
    margin-bottom: 0.5rem;
    margin-top: 1.5rem;
  }
  .ts { font-family: var(--mono); }
  .empty { color: var(--muted); padding: 2rem; text-align: center; }
  .header-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  .logo {
    font-size: 1.8rem;
    line-height: 1;
    filter: drop-shadow(0 0 8px #3b82f680);
  }
</style>
</head>
<body>
<div class="header-row">
  <div class="logo">&#128269;</div>
  <div>
    <h1>SAVVYDFIR-MCP &mdash; Investigation Reports</h1>
    <div class="subtitle">
      Generated <span class="ts">{{GENERATED_AT}}</span>
      &bull; {{HOST_COUNT}} host(s) investigated
    </div>
  </div>
</div>

{{UNIFIED_SECTION}}

<div class="section-title">Per-host Investigations</div>
{{CARDS}}

</body>
</html>
"""

_UNIFIED_BLOCK = """\
<div class="section-title">Unified Cross-host Graph</div>
<div class="unified-section">
  <div class="card unified-card">
    <div class="card-header">
      <span class="case-id">&#x25c6; UNIFIED — All Hosts</span>
      <a class="btn btn-unified" href="unified/graph.html">Open Unified Graph &rarr;</a>
    </div>
    <div class="card-body">
      <div class="stat">
        <div class="stat-label">Hosts</div>
        <div class="stat-value" style="color:#a78bfa">{{UNIFIED_HOSTS}}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value">{{UNIFIED_FINDINGS}}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Shared IOC Nodes</div>
        <div class="stat-value" style="color:#8b5cf6">{{UNIFIED_IOCS}}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Cross-host Edges</div>
        <div class="stat-value" style="color:#f43f5e">{{UNIFIED_EDGES}}</div>
      </div>
    </div>
  </div>
</div>
"""

_CARD_BLOCK = """\
<div class="card">
  <div class="card-header">
    <span class="case-id">{{CASE_ID}}</span>
    <span class="status-badge {{STATUS_CLASS}}">{{STATUS}}</span>
  </div>
  <div class="card-body">
    <div class="stat">
      <div class="stat-label">Findings</div>
      <div class="stat-value">{{TOTAL_FINDINGS}}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Confirmed</div>
      <div class="stat-value" style="color:var(--green)">{{CONFIRMED}}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Hypothesis</div>
      <div class="stat-value" style="color:var(--yellow)">{{HYPOTHESIS}}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Rejected</div>
      <div class="stat-value" style="color:var(--red)">{{REJECTED}}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Nodes</div>
      <div class="stat-value" style="color:var(--muted)">{{NODE_COUNT}}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Executions</div>
      <div class="stat-value" style="color:var(--muted)">{{EXEC_COUNT}}</div>
    </div>
  </div>
  {{TACTIC_BAR}}
  <div class="card-footer">
    <span class="ts" title="Investigation started">&#128344; {{STARTED_AT}}</span>
    <a class="btn" href="{{GRAPH_HREF}}">Open Graph &rarr;</a>
  </div>
</div>
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _status_class(status: str) -> str:
    s = status.upper()
    if s == "COMPLETE":
        return "status-complete"
    if s == "IN_PROGRESS":
        return "status-progress"
    if s == "FAILED":
        return "status-failed"
    return "status-unknown"


def _tactic_bar(findings_by_tactic: dict[str, int]) -> str:
    attack_tactics: dict[str, str] = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command & Control",
        "TA0040": "Impact",
    }
    if not findings_by_tactic:
        return ""
    tags = "".join(
        f'<span class="tactic-tag" title="{attack_tactics.get(tac, tac)} ({count})">'
        f"{attack_tactics.get(tac, tac)}"
        f"</span>"
        for tac, count in sorted(findings_by_tactic.items())
        if count > 0
    )
    return f'<div class="tactic-bar">{tags}</div>'


def _fmt_ts(ts: str) -> str:
    """Return a shortened timestamp: 2026-04-08 15:29 UTC"""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return ts[:19]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="build_index.py",
        description="Generate reports/index.html for SAVVYDFIR-MCP.",
    )
    p.add_argument(
        "--reports-dir",
        default="./reports",
        metavar="PATH",
        help="Path to the reports directory. Default: ./reports",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    reports_dir = Path(args.reports_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    cards_html = ""
    host_count = 0

    for graph_json_path in sorted(reports_dir.glob("*/graph.json")):
        dir_name = graph_json_path.parent.name
        if dir_name == "unified":
            continue

        try:
            data: dict[str, Any] = json.loads(graph_json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"WARNING: Cannot read {graph_json_path}: {exc}", file=sys.stderr)
            continue

        meta = data.get("meta", {})
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        # Derive finding-level stats from node list
        finding_nodes = [n for n in nodes if n.get("type") == "finding"]
        confirmed  = sum(1 for n in finding_nodes
                         if (n.get("details", {}).get("finding_status") or "").upper() == "CONFIRMED")
        hypothesis = sum(1 for n in finding_nodes
                         if (n.get("details", {}).get("finding_status") or "").upper() in ("HYPOTHESIS", "INFERRED"))
        rejected   = sum(1 for n in finding_nodes
                         if (n.get("details", {}).get("finding_status") or "").upper() == "REJECTED")

        case_id        = meta.get("case_id", dir_name)
        status         = meta.get("status", "unknown")
        total_findings = meta.get("total_findings", len(finding_nodes))
        exec_count     = meta.get("total_executions", 0)
        started_at     = meta.get("generated_at", "")
        by_tactic      = meta.get("findings_by_tactic", {})

        graph_href = f"{dir_name}/graph.html"

        card = _CARD_BLOCK
        card = card.replace("{{CASE_ID}}",       case_id)
        card = card.replace("{{STATUS}}",        status.replace("_", " ").title())
        card = card.replace("{{STATUS_CLASS}}",  _status_class(status))
        card = card.replace("{{TOTAL_FINDINGS}}", str(total_findings))
        card = card.replace("{{CONFIRMED}}",     str(confirmed))
        card = card.replace("{{HYPOTHESIS}}",    str(hypothesis))
        card = card.replace("{{REJECTED}}",      str(rejected))
        card = card.replace("{{NODE_COUNT}}",    str(len(nodes)))
        card = card.replace("{{EXEC_COUNT}}",    str(exec_count))
        card = card.replace("{{STARTED_AT}}",    _fmt_ts(started_at))
        card = card.replace("{{GRAPH_HREF}}",    graph_href)
        card = card.replace("{{TACTIC_BAR}}",    _tactic_bar(by_tactic))

        cards_html += card
        host_count += 1

    # Unified section
    unified_json = reports_dir / "unified" / "graph.json"
    unified_section = ""
    if unified_json.exists():
        try:
            udata = json.loads(unified_json.read_text(encoding="utf-8"))
            umeta = udata.get("meta", {})
            block = _UNIFIED_BLOCK
            block = block.replace("{{UNIFIED_HOSTS}}",    str(umeta.get("host_count", "?")))
            block = block.replace("{{UNIFIED_FINDINGS}}", str(umeta.get("total_findings", "?")))
            block = block.replace("{{UNIFIED_IOCS}}",     str(umeta.get("shared_ioc_nodes", "?")))
            block = block.replace("{{UNIFIED_EDGES}}",    str(umeta.get("cross_host_edges", "?")))
            unified_section = block
        except (json.JSONDecodeError, OSError):
            pass

    if not cards_html:
        cards_html = '<div class="empty">No investigations found. Run <code>run_investigation.py</code> to start one.</div>'

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = _HTML_TEMPLATE
    html = html.replace("{{GENERATED_AT}}", generated_at)
    html = html.replace("{{HOST_COUNT}}",   str(host_count))
    html = html.replace("{{UNIFIED_SECTION}}", unified_section)
    html = html.replace("{{CARDS}}",        cards_html)

    output_path = reports_dir / "index.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"[build_index] Wrote: {output_path}  ({host_count} investigation(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
