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
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "sift_mcp" / "server.py"
CORRELATION = ROOT / "sift_mcp" / "tools" / "correlation.py"

sys.path.insert(0, str(ROOT))

# Stub fastmcp so sift_mcp.server imports where fastmcp is absent (it ships on
# the SIFT workstation, not necessarily a dev box). Pattern matches the existing
# tests/test_w17_revised_plan.py stub.
if "fastmcp" not in sys.modules:
    _fastmcp = types.ModuleType("fastmcp")

    class _StubFastMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            def _w(fn):
                return fn
            return _w

        def resource(self, *a, **k):
            def _w(fn):
                return fn
            return _w

        def run(self, *a, **k):
            pass

    _fastmcp.FastMCP = _StubFastMCP
    sys.modules["fastmcp"] = _fastmcp


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


def test_wrapper_logs_real_cluster_count_behaviorally():
    """Behavioral: when the tool returns cluster_count=5, the audit
    outputs_summary must read '5 clusters found' (not '0 clusters found').
    This is the exact bug: the summary must track the returned count."""
    pytest.importorskip("pydantic")
    import sift_mcp.server as srv

    captured = {}

    class _FakeAudit:
        def next_execution_id(self):
            return "E-TEST"

        def log_execution(self, **k):
            return {"execution_id": "E-TEST", "event_type": "started"}

        def log_result(self, **k):
            captured["outputs_summary"] = k.get("outputs_summary")
            return {"execution_id": "E-TEST", "event_type": "completed"}

    orig_audit = getattr(srv, "_audit_logger", None)
    orig_tool = srv._find_temporal_clusters
    orig_parity = srv._record_execution_parity
    orig_finalize = srv._finalize_tool_response
    try:
        srv._audit_logger = _FakeAudit()
        srv._find_temporal_clusters = lambda **k: {
            "status": "ok", "cluster_count": 5, "clusters": [{}] * 5,
        }
        srv._record_execution_parity = lambda **k: None
        srv._finalize_tool_response = lambda _tool, result: result

        srv.find_temporal_clusters("CASE-X", window_seconds=300, min_sources=2, min_events=3)
    finally:
        srv._find_temporal_clusters = orig_tool
        srv._record_execution_parity = orig_parity
        srv._finalize_tool_response = orig_finalize
        if orig_audit is not None:
            srv._audit_logger = orig_audit

    assert captured.get("outputs_summary") == "5 clusters found", (
        f"audit summary must reflect cluster_count=5, got "
        f"{captured.get('outputs_summary')!r}"
    )
