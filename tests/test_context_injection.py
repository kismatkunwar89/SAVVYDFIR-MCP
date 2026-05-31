"""Regression tests for Phase 2 — pre-compute context for playbook specialists.

peer reviewer consensus 2026-05-22: extraction tools should return enriched metadata
(schema, timestamp_bounds, attack_window) in their result. As a fallback that
ALSO works for legacy tools and any drift, ``agent_trigger.py`` does a
bounded local CSV inspect (NEVER an MCP callback — peer reviewer specifically
forbade hook→MCP recursion).

Tests cover:
  1. _bounded_csv_inspect returns schema + timestamp_bounds for a CSV
  2. The inspect is cached so repeat calls don't re-scan
  3. _load_manifest_attack_window reads manifest.json correctly
  4. _augment_instruction injects schema + bounds + window + execution_id
  5. result_data-supplied schema wins over CSV-inspect fallback (preferred path)
  6. Hook never calls MCP — source-text guard
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _import_agent_trigger():
    if "agent_trigger" in sys.modules:
        del sys.modules["agent_trigger"]
    import agent_trigger
    return agent_trigger


@pytest.fixture()
def sample_csv(tmp_path):
    """A small, realistic forensic CSV with a timestamp column."""
    csv = tmp_path / "mft_timeline.csv"
    df = pd.DataFrame({
        "EntryNumber": [10, 11, 12, 13],
        "Path": [r"\Windows\foo.exe", r"\Users\Public\bar.exe",
                 r"\Windows\Temp\baz.exe", r"\Windows\quux.dll"],
        "Created": [
            "2021-09-15T22:00:00",
            "2021-09-16T03:01:57",
            "2021-09-16T03:01:59",
            "2018-04-10T00:00:00",
        ],
        "InUse": [True, True, False, True],
    })
    df.to_csv(csv, index=False)
    return str(csv)


# ---------------------------------------------------------------------------
# _bounded_csv_inspect
# ---------------------------------------------------------------------------

def test_bounded_csv_inspect_returns_schema(sample_csv):
    at = _import_agent_trigger()
    # Clear cache to avoid stale entries from other tests
    at._CONTEXT_CACHE.clear()
    result = at._bounded_csv_inspect(sample_csv)
    assert "schema" in result
    cols = [c["column"] for c in result["schema"]]
    assert {"EntryNumber", "Path", "Created", "InUse"}.issubset(set(cols))


def test_bounded_csv_inspect_returns_timestamp_bounds(sample_csv):
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    result = at._bounded_csv_inspect(sample_csv)
    assert "timestamp_bounds" in result
    bounds = result["timestamp_bounds"]
    assert "min" in bounds and "max" in bounds
    # 2018 < 2021 — min must be the oldest
    assert "2018" in bounds["min"]
    assert "2021" in bounds["max"]


def test_bounded_csv_inspect_caches(sample_csv, monkeypatch):
    """Second call with same csv_path must hit the cache, not re-read."""
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    first = at._bounded_csv_inspect(sample_csv)
    # Sabotage pandas — second call should NOT need it
    monkeypatch.setattr(
        "pandas.read_csv",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("should not be called")),
    )
    second = at._bounded_csv_inspect(sample_csv)
    assert second == first, "cache miss on repeat invocation"


def test_bounded_csv_inspect_handles_missing_file():
    """Non-existent CSV returns empty dict, not an exception."""
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    result = at._bounded_csv_inspect("/nonexistent/path.csv")
    assert result == {}


def test_bounded_csv_inspect_handles_no_timestamp_column(tmp_path):
    """A CSV with no recognizable timestamp column returns schema only."""
    csv = tmp_path / "no_ts.csv"
    pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]}).to_csv(csv, index=False)
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    result = at._bounded_csv_inspect(str(csv))
    assert "schema" in result
    # Either no timestamp_bounds key, or it's empty
    assert "timestamp_bounds" not in result or not result["timestamp_bounds"]


# ---------------------------------------------------------------------------
# _load_manifest_attack_window
# ---------------------------------------------------------------------------

def test_load_manifest_attack_window_reads_top_level(tmp_path):
    manifest_dir = tmp_path / "case-templates"
    manifest_dir.mkdir()
    manifest = manifest_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "case_id": "TEST-CASE",
        "attack_window": {"start": "2021-09-16T02:00:00", "end": "2021-09-16T04:00:00"},
    }))
    at = _import_agent_trigger()
    result = at._load_manifest_attack_window(cwd=str(tmp_path))
    assert result == {"start": "2021-09-16T02:00:00", "end": "2021-09-16T04:00:00"}


def test_load_manifest_attack_window_reads_alt_names(tmp_path):
    """Manifest may use incident_window or from/to keys."""
    manifest_dir = tmp_path / "case-templates"
    manifest_dir.mkdir()
    manifest = manifest_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "case_id": "TEST-CASE",
        "incident_window": {"from": "2021-09-16T02:00:00", "to": "2021-09-16T04:00:00"},
    }))
    at = _import_agent_trigger()
    result = at._load_manifest_attack_window(cwd=str(tmp_path))
    assert result["start"] == "2021-09-16T02:00:00"
    assert result["end"] == "2021-09-16T04:00:00"


def test_load_manifest_attack_window_missing(tmp_path):
    """No manifest → empty dict, no exception."""
    at = _import_agent_trigger()
    result = at._load_manifest_attack_window(cwd=str(tmp_path))
    assert result == {}


def test_load_manifest_attack_window_no_window_field(tmp_path):
    """Manifest exists but has no attack_window — returns empty dict."""
    manifest_dir = tmp_path / "case-templates"
    manifest_dir.mkdir()
    manifest = manifest_dir / "manifest.json"
    manifest.write_text(json.dumps({"case_id": "TEST"}))
    at = _import_agent_trigger()
    result = at._load_manifest_attack_window(cwd=str(tmp_path))
    assert result == {}


# ---------------------------------------------------------------------------
# _augment_instruction with Phase 2 context
# ---------------------------------------------------------------------------

def test_augment_instruction_injects_schema_from_result_data(sample_csv):
    """When the extraction tool's result_data already has schema, use it."""
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    instruction = at._augment_instruction(
        "Analyze the MFT.",
        {
            "csv_path": sample_csv,
            "schema": [
                {"column": "EntryNumber", "dtype": "int64"},
                {"column": "Path", "dtype": "object"},
                {"column": "Created", "dtype": "datetime64[ns]"},
            ],
        },
    )
    assert "Schema columns: EntryNumber, Path, Created" in instruction


def test_augment_instruction_falls_back_to_csv_inspect(sample_csv, tmp_path):
    """When result_data lacks schema, fall back to bounded local CSV inspect."""
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    instruction = at._augment_instruction(
        "Analyze.",
        {"csv_path": sample_csv},
    )
    # Schema discovered via fallback
    assert "Schema columns:" in instruction
    assert "EntryNumber" in instruction


def test_augment_instruction_injects_timestamp_bounds(sample_csv):
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    instruction = at._augment_instruction("Analyze.", {"csv_path": sample_csv})
    assert "Timestamp bounds:" in instruction
    assert "2018" in instruction
    assert "2021" in instruction


def test_augment_instruction_injects_manifest_attack_window(sample_csv, tmp_path):
    manifest_dir = tmp_path / "case-templates"
    manifest_dir.mkdir()
    (manifest_dir / "manifest.json").write_text(json.dumps({
        "attack_window": {"start": "2021-09-16T02:00:00", "end": "2021-09-16T04:00:00"},
    }))
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    instruction = at._augment_instruction(
        "Analyze.",
        {"csv_path": sample_csv},
        cwd=str(tmp_path),
    )
    assert "Manifest attack window:" in instruction
    assert "2021-09-16T02:00:00" in instruction


def test_augment_instruction_injects_originating_execution_id(sample_csv):
    at = _import_agent_trigger()
    at._CONTEXT_CACHE.clear()
    instruction = at._augment_instruction(
        "Analyze.",
        {"csv_path": sample_csv},
        originating_execution_id="E-014",
    )
    assert "Originating execution_id: E-014" in instruction


# ---------------------------------------------------------------------------
# Source-text guards — peer reviewer hard requirement: NO MCP callback from hook
# ---------------------------------------------------------------------------

def test_hook_does_not_call_mcp():
    """peer reviewer consensus required: agent_trigger.py must NOT call back into
    MCP tools (subprocess.run on the MCP server, requests to MCP endpoints,
    re-importing the MCP server from inside the hook, etc.).

    Verifies the bounded-local-inspect path uses pandas directly, not MCP."""
    src = (SCRIPTS / "agent_trigger.py").read_text()
    # The hook should NOT import or invoke any sift_mcp tool functions
    for forbidden in (
        "from sift_mcp.tools",
        "from sift_mcp.server import",
        "subprocess.run.*sift_mcp",
        "mcp__savvydfir__run_analysis",
        "_state_manager",
    ):
        assert forbidden not in src, (
            f"agent_trigger.py contains {forbidden!r} — peer reviewer consensus "
            f"forbade MCP callbacks from the PostToolUse hook (recursion + latency risk)."
        )
    # And it MUST use pandas directly for the fallback
    assert "import pandas" in src or "_pd" in src, (
        "Bounded CSV inspect must use pandas directly, not an MCP callback."
    )


def test_augment_instruction_has_phase2_markers():
    """Source-text guard: the augmentation function has the Phase 2 injection logic."""
    src = (SCRIPTS / "agent_trigger.py").read_text()
    fn_idx = src.find("def _augment_instruction(")
    end = src.find("\ndef ", fn_idx + 1)
    body = src[fn_idx:end if end > 0 else fn_idx + 6000]
    assert "schema" in body
    assert "timestamp_bounds" in body
    assert "attack_window" in body
    assert "csv_path" in body
