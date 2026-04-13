#!/usr/bin/env python3
"""
merge_graphs.py — Cross-host investigation graph merger for SAVVYDFIR-MCP.

Loads all per-host ``graph.json`` files from the reports directory, detects
shared IOCs (IPs, hashes, domains, accounts) across hosts, and emits a
single unified graph showing lateral movement paths and attacker infrastructure
reuse across the enterprise.

Usage
-----
::

    python3 scripts/merge_graphs.py \\
        --reports-dir ./reports \\
        [--output ./reports/unified/graph.html]

Cross-host node types
---------------------
    host            Cluster node representing one physical/virtual host.
    case            Root node per host investigation (from per-host graph.json).
    evidence_source Disk image or memory dump node.
    finding         Individual forensic finding.
    ioc             Synthesised shared-IOC node (IP, hash, domain, account).

Cross-host edge types
---------------------
    lateral_movement    TA0008 finding on one host shares IOC with a finding
                        on another host.  Directed: src_host → dst_host.
    shared_ioc          Same IP, hash, or domain appears in findings across
                        two hosts.
    shared_account      Same Windows account (domain\\user or local user)
                        appears in findings across two hosts.
    contains            host → case (grouping).
    (all per-host edges are preserved as-is)

IOC extraction
--------------
The algorithm is purely heuristic and case-agnostic.  It scans each
finding's ``supporting_indicators`` list and ``description`` for:

* IPv4 addresses     ``\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}``
* MD5 hashes         32 hex characters
* SHA1 hashes        40 hex characters
* SHA256 hashes      64 hex characters
* Windows accounts   ``DOMAIN\\\\user`` or bare usernames in indicators

Noise filters: RFC-1918 local broadcast (255.x, .255), loopback (127.x),
all-zeros, and very short tokens are excluded.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["main"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MITRE ATT&CK tactic display names (ordered by kill chain)
ATTACK_TACTICS: dict[str, str] = {
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

LATERAL_MOVEMENT_TACTIC = "TA0008"

# Node colours
COLORS: dict[str, str] = {
    "host":             "#1e40af",   # dark blue  — host cluster
    "case":             "#0f172a",   # near-black — case root
    "evidence_source":  "#3b82f6",   # blue
    "ioc":              "#7c3aed",   # violet     — shared IOC hub
    "OBSERVATION":      "#22c55e",
    "INFERENCE":        "#eab308",
    "HYPOTHESIS":       "#f97316",
    "REJECTED":         "#ef4444",
    "CORRECTION":       "#dc2626",
    "lateral_movement": "#f43f5e",   # rose       — cross-host lateral edge
    "shared_ioc":       "#8b5cf6",   # purple     — cross-host IOC edge
    "shared_account":   "#06b6d4",   # cyan       — cross-host account edge
}

# ---------------------------------------------------------------------------
# Regex patterns for IOC extraction (case-agnostic, heuristic)
# ---------------------------------------------------------------------------

_RE_IPV4    = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_RE_MD5     = re.compile(r"\b([0-9a-fA-F]{32})\b")
_RE_SHA1    = re.compile(r"\b([0-9a-fA-F]{40})\b")
_RE_SHA256  = re.compile(r"\b([0-9a-fA-F]{64})\b")
_RE_ACCOUNT = re.compile(r"\b([A-Za-z0-9_\-]{3,}\\[A-Za-z0-9_\-]{2,})\b")  # DOMAIN\user

# IPv4 exclusion: loopback, broadcast, link-local, all-zeros
_NOISE_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "169.254.0.1",
}


def _is_noise_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    if parts[3] == "0" or parts[3] == "255":
        return True
    return ip in _NOISE_IPS


def _extract_iocs(text: str) -> set[str]:
    """Return a set of IOC strings extracted from *text*.

    The strings are normalised (lowercased for accounts, uppercased for
    hashes) so duplicates from different letter cases collapse.
    """
    iocs: set[str] = set()
    for m in _RE_SHA256.finditer(text):
        iocs.add(f"sha256:{m.group(1).lower()}")
    for m in _RE_SHA1.finditer(text):
        iocs.add(f"sha1:{m.group(1).lower()}")
    for m in _RE_MD5.finditer(text):
        iocs.add(f"md5:{m.group(1).lower()}")
    for m in _RE_IPV4.finditer(text):
        ip = m.group(1)
        if not _is_noise_ip(ip):
            iocs.add(f"ip:{ip}")
    for m in _RE_ACCOUNT.finditer(text):
        iocs.add(f"account:{m.group(1).lower()}")
    return iocs


def _finding_iocs(finding: dict[str, Any]) -> set[str]:
    """Extract IOCs from a finding node's details dict."""
    iocs: set[str] = set()
    details = finding.get("details", {})

    # supporting_indicators list
    for ind in details.get("supporting_indicators", []):
        iocs |= _extract_iocs(str(ind))

    # description and embedding_text
    iocs |= _extract_iocs(details.get("description", ""))
    iocs |= _extract_iocs(details.get("embedding_text", ""))

    return iocs


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


class UnifiedGraphBuilder:
    """Merges per-host graph.json files into a single cross-host graph.

    Attributes
    ----------
    nodes : list[dict]
    edges : list[dict]
    _node_ids : set[str]
    _edge_keys : set[tuple]
    """

    def __init__(self) -> None:
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self._node_ids: set[str] = set()
        self._edge_keys: set[tuple[str, str, str]] = set()

    # ------------------------------------------------------------------
    # Node / edge helpers
    # ------------------------------------------------------------------

    def _add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        color: str,
        details: dict[str, Any],
        size: Optional[int] = None,
    ) -> None:
        if node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        n: dict[str, Any] = {
            "id":      node_id,
            "label":   label,
            "type":    node_type,
            "color":   color,
            "details": details,
        }
        if size is not None:
            n["size"] = size
        self.nodes.append(n)

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        label: str,
        style: str = "solid",
        color: Optional[str] = None,
    ) -> None:
        key = (source, target, edge_type)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        e: dict[str, Any] = {
            "source": source,
            "target": target,
            "type":   edge_type,
            "label":  label,
            "style":  style,
        }
        if color:
            e["color"] = color
        self.edges.append(e)

    # ------------------------------------------------------------------
    # Main build
    # ------------------------------------------------------------------

    def build(self, host_graphs: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
        """Build the unified graph.

        Parameters
        ----------
        host_graphs:
            List of (case_id, graph_dict) tuples, one per host.

        Returns
        -------
        dict
            ``{nodes, edges, meta}`` ready for JSON serialisation.
        """
        # IOC index: ioc_string → list of (case_id, finding_node_id, tactic)
        ioc_index: dict[str, list[tuple[str, str, str]]] = {}

        all_case_ids: list[str] = []
        total_findings = 0

        # ---- Pass 1: ingest all per-host nodes + build IOC index --------
        for case_id, graph in host_graphs:
            host_name = self._host_from_case(case_id)
            all_case_ids.append(case_id)

            # Host cluster node
            host_node_id = f"host:{host_name}"
            self._add_node(
                node_id=host_node_id,
                label=host_name,
                node_type="host",
                color=COLORS["host"],
                details={
                    "hostname":  host_name,
                    "case_id":   case_id,
                    "type_desc": "Physical or virtual host",
                },
                size=50,
            )

            # Import all nodes from the per-host graph, prefixed with host
            for node in graph.get("nodes", []):
                orig_id: str = node["id"]
                # Case and evidence source nodes: keep as-is (they're already unique)
                # Finding nodes: prefix with host to avoid ID collision across hosts
                if node["type"] == "finding":
                    new_id = f"{host_name}:{orig_id}"
                    node = dict(node)
                    node["id"] = new_id
                    # Tag which host this finding belongs to
                    node["details"] = dict(node.get("details", {}))
                    node["details"]["host"] = host_name
                    node["details"]["case_id"] = case_id

                    # Build IOC index for cross-host edge detection
                    tactic = node["details"].get("mitre_tactic", "")
                    for ioc in _finding_iocs(node):
                        ioc_index.setdefault(ioc, []).append((case_id, new_id, tactic))

                    total_findings += 1

                elif node["type"] == "correction":
                    new_id = f"{host_name}:{orig_id}"
                    node = dict(node)
                    node["id"] = new_id
                else:
                    new_id = orig_id

                self._add_node(
                    node_id=new_id,
                    label=node.get("label", new_id),
                    node_type=node.get("type", "finding"),
                    color=node.get("color", "#94a3b8"),
                    details=node.get("details", {}),
                    size=node.get("size"),
                )

            # Connect host → case root
            self._add_edge(host_node_id, case_id, "contains", "contains")

            # Re-wire edges with prefixed node IDs
            for edge in graph.get("edges", []):
                src = edge["source"]
                tgt = edge["target"]

                # Finding and correction nodes were prefixed — update references
                def _maybe_prefix(nid: str) -> str:
                    # Only prefix nodes that are not case/evidence_source roots
                    for n in graph.get("nodes", []):
                        if n["id"] == nid and n["type"] in ("finding", "correction"):
                            return f"{host_name}:{nid}"
                    return nid

                src_new = _maybe_prefix(src)
                tgt_new = _maybe_prefix(tgt)

                self._add_edge(
                    src_new, tgt_new,
                    edge["type"], edge.get("label", edge["type"]),
                    style=edge.get("style", "solid"),
                )

        # ---- Pass 2: cross-host edges from IOC index --------------------
        # For each IOC shared by findings on 2+ different hosts, create edges.
        for ioc, appearances in ioc_index.items():
            # Group by case_id
            by_case: dict[str, list[tuple[str, str]]] = {}
            for (case_id, finding_id, tactic) in appearances:
                by_case.setdefault(case_id, []).append((finding_id, tactic))

            if len(by_case) < 2:
                continue  # IOC only seen on one host — no cross-host edge

            # Determine IOC type and display label
            ioc_type, ioc_value = ioc.split(":", 1)
            ioc_node_id = f"ioc:{ioc}"
            ioc_label = f"{ioc_type.upper()}: {ioc_value[:32]}"

            # Add a shared IOC hub node
            self._add_node(
                node_id=ioc_node_id,
                label=ioc_label,
                node_type="ioc",
                color=COLORS["ioc"],
                details={
                    "ioc_type":    ioc_type,
                    "ioc_value":   ioc_value,
                    "seen_on":     list(by_case.keys()),
                    "description": f"Shared {ioc_type} observed across {len(by_case)} hosts",
                },
                size=22,
            )

            # Connect each finding to the IOC hub with typed edge
            for case_id, finding_tactics in by_case.items():
                for finding_id, tactic in finding_tactics:
                    if finding_id not in self._node_ids:
                        continue

                    # Choose edge type based on MITRE tactic
                    if tactic == LATERAL_MOVEMENT_TACTIC:
                        etype  = "lateral_movement"
                        elabel = "lateral movement"
                        estyle = "solid"
                        ecolor = COLORS["lateral_movement"]
                    elif ioc_type == "account":
                        etype  = "shared_account"
                        elabel = "shared account"
                        estyle = "solid"
                        ecolor = COLORS["shared_account"]
                    else:
                        etype  = "shared_ioc"
                        elabel = f"shared {ioc_type}"
                        estyle = "dashed"
                        ecolor = COLORS["shared_ioc"]

                    self._add_edge(
                        finding_id, ioc_node_id,
                        etype, elabel,
                        style=estyle,
                        color=ecolor,
                    )

        # ---- Meta -------------------------------------------------------
        ioc_count = sum(
            1 for n in self.nodes if n["type"] == "ioc"
        )
        cross_host_edges = sum(
            1 for e in self.edges
            if e["type"] in ("lateral_movement", "shared_ioc", "shared_account")
        )

        meta: dict[str, Any] = {
            "graph_type":         "unified_multi_host",
            "host_count":         len(all_case_ids),
            "case_ids":           all_case_ids,
            "total_findings":     total_findings,
            "shared_ioc_nodes":   ioc_count,
            "cross_host_edges":   cross_host_edges,
            "generated_at":       datetime.now(tz=timezone.utc).isoformat(),
            "attack_tactics":     ATTACK_TACTICS,
        }

        return {"nodes": self.nodes, "edges": self.edges, "meta": meta}

    @staticmethod
    def _host_from_case(case_id: str) -> str:
        """Extract the host portion from a case_id (last hyphen-token)."""
        parts = case_id.split("-")
        # e.g. SRL-2018-WKSTN01 → WKSTN01
        return parts[-1] if parts else case_id


# ---------------------------------------------------------------------------
# HTML injection (reuse investigation_graph logic)
# ---------------------------------------------------------------------------


def _inject_graph_data(html: str, graph_data: dict[str, Any]) -> str:
    placeholder = "/*GRAPH_DATA_PLACEHOLDER*/null"
    if placeholder not in html:
        placeholder = "/*GRAPH_DATA_PLACEHOLDER*/"
    if placeholder not in html:
        raise ValueError(
            "Template missing /*GRAPH_DATA_PLACEHOLDER*/null marker."
        )
    json_payload = json.dumps(graph_data, indent=2, default=str)
    return html.replace(placeholder, json_payload, 1)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="merge_graphs.py",
        description=(
            "Cross-host investigation graph merger for SAVVYDFIR-MCP.\n"
            "Detects shared IOCs and lateral movement across enterprise hosts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--reports-dir",
        default="./reports",
        metavar="PATH",
        help="Directory containing per-host report subdirectories. Default: ./reports",
    )
    p.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help=(
            "Output path for the unified graph.html. "
            "Default: <reports-dir>/unified/graph.html"
        ),
    )
    p.add_argument(
        "--template",
        default=None,
        metavar="PATH",
        help=(
            "Path to graph.html template. "
            "Default: <script_dir>/../templates/graph.html"
        ),
    )
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    reports_dir = Path(args.reports_dir).resolve()
    output_path = (
        Path(args.output).resolve()
        if args.output
        else reports_dir / "unified" / "graph.html"
    )
    template_path = (
        Path(args.template).resolve()
        if args.template
        else project_root / "templates" / "graph.html"
    )

    # ---- Discover per-host graph.json files ---------------------------------
    host_graphs: list[tuple[str, dict[str, Any]]] = []

    for graph_json_path in sorted(reports_dir.glob("*/graph.json")):
        # Skip the unified dir itself
        if graph_json_path.parent.name == "unified":
            continue
        try:
            graph = json.loads(graph_json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(
                f"WARNING: Cannot read {graph_json_path}: {exc}",
                file=sys.stderr,
            )
            continue

        case_id = graph.get("meta", {}).get("case_id", graph_json_path.parent.name)
        host_graphs.append((case_id, graph))
        print(f"  Loaded: {graph_json_path.parent.name}  "
              f"({len(graph.get('nodes', []))} nodes, "
              f"{len(graph.get('edges', []))} edges)")

    if not host_graphs:
        print(
            f"ERROR: No graph.json files found under {reports_dir}/*/graph.json",
            file=sys.stderr,
        )
        print("Run per-host investigations first:", file=sys.stderr)
        print("  python3 scripts/run_investigation.py --scenario ... --host ...", file=sys.stderr)
        return 1

    print(f"\nMerging {len(host_graphs)} host graph(s) …")

    # ---- Build unified graph ------------------------------------------------
    builder = UnifiedGraphBuilder()
    graph_data = builder.build(host_graphs)

    print(
        f"  Unified graph: {len(graph_data['nodes'])} nodes, "
        f"{len(graph_data['edges'])} edges, "
        f"{graph_data['meta']['shared_ioc_nodes']} shared IOC nodes, "
        f"{graph_data['meta']['cross_host_edges']} cross-host edges"
    )

    # ---- Write graph.json ---------------------------------------------------
    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_out = output_path.with_name("graph.json")
    json_out.write_text(
        json.dumps(graph_data, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\nWrote: {json_out}")

    # ---- Load template and inject -------------------------------------------
    if template_path.exists():
        html_template = template_path.read_text(encoding="utf-8")
    else:
        print(
            f"WARNING: Template not found at {template_path} — using fallback.",
            file=sys.stderr,
        )
        html_template = (
            "<!DOCTYPE html><html><body>"
            "<script>const GRAPH_DATA = /*GRAPH_DATA_PLACEHOLDER*/null;</script>"
            "</body></html>"
        )

    try:
        html_out = _inject_graph_data(html_template, graph_data)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output_path.write_text(html_out, encoding="utf-8")
    print(f"Wrote: {output_path}")
    print(
        f"\nDone. Open in a browser or serve with:\n"
        f"  cd {output_path.parent} && python3 -m http.server 8081"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
