"""Regression tests for tool-response context-budget discipline.

Run-7 lessons: a full 7-phase investigation must fit in ~80-100k tokens
of parent context. Heavy tools must return HANDLES (csv_path, counts,
inventory stats) — never raw data arrays or per-record dicts.

These tests assert:
  1. summarize_evtx evtx_inventory in response is STATS-ONLY, not the
     full per-channel dict (which can be ~46 KB for 307 channels).
  2. Memory tools (scan_network, detect_injection, list_dlls) accept
     response_format="summary" and strip the heavy ``data`` array.
  3. _strip_data_for_summary helper drops data + preserves counts.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_HAS_FASTMCP = False
try:
    import fastmcp  # noqa: F401
    _HAS_FASTMCP = True
except ImportError:
    pass
_requires_fastmcp = pytest.mark.skipif(
    not _HAS_FASTMCP,
    reason="fastmcp not installed locally (runs on SIFT server only)",
)


def _read_function_source(file_path: str, func_name: str) -> str:
    src = Path(file_path).read_text()
    marker = f"\ndef {func_name}("
    i = src.find(marker)
    if i < 0:
        return ""
    j = src.find("\ndef ", i + 1)
    k = src.find("\n@mcp.tool()", i + 1)
    candidates = [x for x in (j, k) if x > 0]
    end = min(candidates) if candidates else len(src)
    return src[i:end]


# ---------------------------------------------------------------------------
# Source-text checks (run anywhere — no MCP import required)
# ---------------------------------------------------------------------------

def test_summarize_evtx_returns_inventory_stats_not_full_channels_dict():
    """summarize_evtx response must reference evtx_inventory_summary
    (stats only) — NOT the full evtx_inventory dict whose .channels
    field is ~46 KB for a typical 307-channel inventory."""
    src = _read_function_source("sift_mcp/tools/disk.py", "summarize_evtx")
    assert src, "summarize_evtx not found in tools/disk.py"
    # The summary variant must be defined and used in response
    assert "evtx_inventory_summary" in src, (
        "summarize_evtx must build evtx_inventory_summary (stats-only) "
        "and return that in the response — not the full inventory dict. "
        "Returning the full dict bloats context by ~46 KB per call."
    )
    # The response sites must reference the summary, not the full var.
    # We check by counting occurrences in the response-construction area.
    inventory_lines = [l for l in src.split("\n") if '"evtx_inventory":' in l]
    assert len(inventory_lines) >= 1, "expected at least one evtx_inventory return site"
    for line in inventory_lines:
        assert "evtx_inventory_summary" in line, (
            f"Response site still returns full inventory dict: {line.strip()}"
        )


def test_memory_tools_have_response_format_param():
    """scan_network, detect_injection, list_dlls must accept
    response_format so callers can request handle-only responses."""
    src = Path(ROOT / "sift_mcp" / "server.py").read_text()
    for fn in ("scan_network", "detect_injection", "list_dlls"):
        # Find the @mcp.tool def
        marker = f"\ndef {fn}("
        i = src.find(marker)
        assert i >= 0, f"{fn} not found in server.py"
        # The signature must include response_format
        sig_end = src.find(") -> dict", i)
        signature = src[i:sig_end]
        assert "response_format" in signature, (
            f"{fn} must accept response_format='summary' kwarg "
            f"so it can return handle-only output. Found signature: {signature[:200]}"
        )


def test_memory_tools_apply_strip_helper():
    """The 3 memory tools must call _strip_data_for_summary on their
    response before returning, otherwise response_format is ignored."""
    src = Path(ROOT / "sift_mcp" / "server.py").read_text()
    for fn, count_key in (
        ("scan_network", "connection_count"),
        ("detect_injection", "injection_count"),
        ("list_dlls", "dll_count"),
    ):
        func_src = _read_function_source(str(ROOT / "sift_mcp" / "server.py"), fn)
        assert "_strip_data_for_summary" in func_src, (
            f"{fn} must call _strip_data_for_summary(...) before _finalize_tool_response"
        )
        assert f'count_key="{count_key}"' in func_src, (
            f"{fn} must pass count_key='{count_key}' so the stripped response "
            f"records the array length under a domain-appropriate field name"
        )


# ---------------------------------------------------------------------------
# Behavior tests for _strip_data_for_summary (no MCP runtime needed)
# ---------------------------------------------------------------------------

@_requires_fastmcp
def test_strip_data_for_summary_drops_data_keeps_count():
    """summary mode drops data array, records count, keeps small preview."""
    from sift_mcp.server import _strip_data_for_summary
    resp = {"status": "success", "data": [{"x": i} for i in range(50)]}
    stripped = _strip_data_for_summary(resp, "summary", count_key="row_count")
    assert "data" not in stripped, "summary mode must drop the data array"
    assert stripped["row_count"] == 50
    assert len(stripped.get("preview", [])) == 3  # tiny preview only
    assert stripped["response_format"] == "summary"


@_requires_fastmcp
def test_strip_data_for_summary_detailed_keeps_everything():
    """detailed mode preserves the data array unchanged."""
    from sift_mcp.server import _strip_data_for_summary
    resp = {"status": "success", "data": [{"x": i} for i in range(50)]}
    detailed = _strip_data_for_summary(resp, "detailed", count_key="row_count")
    assert detailed["data"] == resp["data"]


@_requires_fastmcp
def test_strip_data_for_summary_passes_through_when_no_data():
    """If the response has no data array, the helper is a no-op (except
    setting response_format)."""
    from sift_mcp.server import _strip_data_for_summary
    resp = {"status": "success", "csv_path": "/tmp/x.csv"}
    stripped = _strip_data_for_summary(resp, "summary")
    assert stripped["csv_path"] == "/tmp/x.csv"
    assert "data" not in stripped
    assert "count" not in stripped or stripped["count"] == "count"  # count_key default
    assert stripped["response_format"] == "summary"


# ---------------------------------------------------------------------------
# Approximate-size sanity check
# ---------------------------------------------------------------------------

def test_evtx_inventory_summary_field_set_is_bounded():
    """The evtx_inventory_summary dict must only contain bounded-size
    fields. baseline_present and high_value_present are short lists of
    channel stems; total/present/empty are integers. Adding the full
    channels dict here would regress the bloat."""
    src = _read_function_source("sift_mcp/tools/disk.py", "summarize_evtx")
    # Find the evtx_inventory_summary assignment
    idx = src.find("evtx_inventory_summary = {")
    assert idx > 0, "evtx_inventory_summary dict not defined in summarize_evtx"
    # Slice the dict body (until the closing brace at column 4)
    body_start = idx
    body_end = src.find("\n    }", body_start)
    body = src[body_start:body_end] if body_end > 0 else src[body_start:body_start + 1000]
    # No reference to inventory['channels'] in the summary — that's the unbounded field
    assert '"channels"' not in body, (
        "evtx_inventory_summary must NOT include the channels dict — "
        "that's the field we're stripping for context budget."
    )
    assert "inventory[\"channels\"]" not in body, (
        "evtx_inventory_summary must not iterate channels — that's also bloat."
    )
