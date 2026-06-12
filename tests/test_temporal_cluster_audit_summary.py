"""Regression test for the temporal-cluster audit-summary key mismatch.

Bug: the ``find_temporal_clusters`` server wrapper logged its audit
``outputs_summary`` from ``result.get('total_clusters', 0)``, but the tool
(``sift_mcp/tools/correlation.py``) returns the count under ``cluster_count``.
``total_clusters`` was never present, so EVERY successful cluster run logged
"0 clusters found" regardless of how many clusters it actually returned. The
finding objects were correct (the agent read the live tool response), but the
hash-chained ``audit.jsonl`` summary string was wrong on all committed cases.

These tests pin both sides of the contract so the key cannot drift again. They
read source as text so they run without importing the server (which needs
``fastmcp``, present only on the SIFT workstation).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "sift_mcp" / "server.py"
CORRELATION = ROOT / "sift_mcp" / "tools" / "correlation.py"


def test_tool_returns_cluster_count_key():
    """The tool's return contract must expose the count under cluster_count."""
    src = CORRELATION.read_text(encoding="utf-8")
    assert '"cluster_count": len(clusters)' in src, (
        "find_temporal_clusters must return the count under 'cluster_count'."
    )


def test_wrapper_audit_summary_uses_cluster_count():
    """The server wrapper's outputs_summary must read cluster_count, not the
    non-existent total_clusters key (the original bug)."""
    src = SERVER.read_text(encoding="utf-8")

    # The corrected line must be present.
    assert "result.get('cluster_count', 0)" in src or \
           'result.get("cluster_count", 0)' in src, (
        "find_temporal_clusters wrapper must derive outputs_summary from "
        "result.get('cluster_count', 0)."
    )

    # The buggy key must not be used to build any 'clusters found' summary.
    bad = re.search(r"result\.get\(\s*['\"]total_clusters['\"]", src)
    assert bad is None, (
        "server.py still references result['total_clusters'] for the cluster "
        "audit summary; that key is never set by the tool and logs 0 always."
    )
