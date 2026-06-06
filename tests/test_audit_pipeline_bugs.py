"""Regression tests for the 3 audit-pipeline bugs identified during Run7.

These bugs cost ~30-45 min of manual state.json surgery on a successful
investigation. Tests guarantee they don't regress:

Bug 1 — extract_srum success path never called _record_execution_parity.
        Gate saw the tool as never run even after a clean 25k-entry run.

Bug 2 — extract_shimcache "No CSV" error path returned a bare dict without
        going through the audit pipeline. Gate saw the tool as never run.

Bug 3 — correlation._read_artifact_csv_rows() was defined with only one
        positional argument but callers passed required_cols=[...] as
        kwarg, raising TypeError on every compare_disk_and_memory call.
"""
from __future__ import annotations

import inspect
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Bug 3 regression — _read_artifact_csv_rows must accept required_cols kwarg
# ---------------------------------------------------------------------------

def test_bug3_read_artifact_csv_rows_accepts_required_cols_kwarg():
    """compare_disk_and_memory passes required_cols=[...]. The signature
    must accept it without raising TypeError, otherwise every 10-check
    correlation engine call crashes."""
    from sift_mcp.tools.correlation import _read_artifact_csv_rows
    sig = inspect.signature(_read_artifact_csv_rows)
    assert "required_cols" in sig.parameters, (
        "_read_artifact_csv_rows must accept required_cols kwarg — "
        "this regression crashes compare_disk_and_memory."
    )
    # required_cols must be keyword-only (it's used by callsite as kwarg)
    assert sig.parameters["required_cols"].kind in (
        inspect.Parameter.KEYWORD_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )


def test_bug3_read_artifact_csv_rows_returns_empty_when_required_cols_missing(tmp_path: Path):
    """When the CSV header doesn't include the required columns, the
    function must return an empty list (not raise, not return rows that
    would NoneError on caller's .get(col) accesses)."""
    from sift_mcp.tools.correlation import _read_artifact_csv_rows
    csv = tmp_path / "test.csv"
    csv.write_text("col_a,col_b\nval1,val2\n", encoding="utf-8")
    # Required column "missing_col" not in header → empty list
    rows = _read_artifact_csv_rows(str(csv), required_cols=["missing_col"])
    assert rows == [], "required_cols mismatch must return empty rowset"


def test_bug3_read_artifact_csv_rows_returns_rows_when_required_cols_present(tmp_path: Path):
    """Happy path: when all required columns ARE in the header, rows are returned."""
    from sift_mcp.tools.correlation import _read_artifact_csv_rows
    csv = tmp_path / "test.csv"
    csv.write_text("Timestamp,FileName,Reason\n2021-09-16,foo.exe,Created\n", encoding="utf-8")
    rows = _read_artifact_csv_rows(str(csv), required_cols=["Timestamp", "FileName"])
    assert len(rows) == 1
    assert rows[0]["FileName"] == "foo.exe"


def test_bug3_actual_callsite_does_not_typeerror():
    """The exact callsite signatures from correlation.py:559 and 715 must
    not raise TypeError. Catches the original symptom."""
    from sift_mcp.tools.correlation import _read_artifact_csv_rows
    # Use a non-existent path so we don't need fixture files — the bug
    # was TypeError on signature, which fires before file-open.
    try:
        _read_artifact_csv_rows("/nonexistent.csv", required_cols=["Timestamp", "FileName"])
        _read_artifact_csv_rows("/nonexistent.csv", required_cols=["ProcessName", "BytesSent"])
    except TypeError as exc:
        pytest.fail(f"Bug 3 regressed: TypeError on required_cols kwarg: {exc}")


# ---------------------------------------------------------------------------
# Bugs 1 & 2 regression — audit pipeline coverage on monolithic tool paths
# ---------------------------------------------------------------------------
# These tests inspect the source code rather than running the heavy MCP
# tools end-to-end. The contract: every success and every error/absence
# return in extract_srum / extract_shimcache MUST be preceded by a call
# to either _record_tool_success_audit or _record_artifact_absent_audit.

def _get_function_source(func_name: str) -> str:
    """Read the source of a top-level function in sift_mcp/server.py.

    Reads from the file directly (no import) so the test runs without
    requiring fastmcp/runtime deps. The slice runs from `def <name>(` up
    to the next top-level `def ` or `@mcp.tool()` line.
    """
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    marker = f"\ndef {func_name}("
    i = src.find(marker)
    if i < 0:
        return ""
    j = src.find("\ndef ", i + 1)
    k = src.find("\n@mcp.tool()", i + 1)
    candidates = [x for x in (j, k) if x > 0]
    end = min(candidates) if candidates else len(src)
    return src[i:end]


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


def test_bug1_extract_srum_success_path_calls_audit_helper():
    """Bug 1 regression: extract_srum's success path (the long happy path
    that returns status="success") must call _record_tool_success_audit
    before returning, otherwise state.json:executions never gets a row
    and the hook gate blocks generate_report forever."""
    src = _get_function_source("extract_srum")
    assert src, "extract_srum source not located"
    # The success return is the one with status: "success".
    # Both _record_tool_success_audit and the success return must coexist.
    assert "_record_tool_success_audit" in src, (
        "extract_srum must call _record_tool_success_audit on the success "
        "path. Without it, the hook gate stays blocked forever."
    )
    assert 'tool_name="disk.extract_srum"' in src, (
        "extract_srum must record execution under tool_name=disk.extract_srum "
        "so the hook gate matches state.json:executions entries."
    )


def test_bug2_extract_shimcache_no_csv_path_calls_audit_helper():
    """Bug 2 regression: extract_shimcache's 'No CSV output produced' path
    must call _record_artifact_absent_audit (or _record_tool_success_audit)
    instead of bare returning {status: error}. Otherwise the gate stays
    blocked even after 3 attempts."""
    src = _get_function_source("extract_shimcache")
    assert src, "extract_shimcache source not located"
    # The 'No CSV output produced' phrase must NOT be the entirety of a
    # bare return — it must be followed by audit recording.
    assert 'return {"status": "error", "error": "No CSV output produced."}' not in src, (
        "Bug 2 regressed: extract_shimcache returns a bare error dict on "
        "the 'No CSV output produced' path. Route through "
        "_record_artifact_absent_audit() so the gate sees the gap."
    )


def test_bug2_extract_shimcache_no_csv_routes_to_absence_helper():
    """Positive assertion: the No-CSV branch references the absence helper."""
    src = _get_function_source("extract_shimcache")
    # Find the if-not-csv-files block and check it calls the audit helper
    no_csv_idx = src.find("if not csv_files")
    assert no_csv_idx > 0, "extract_shimcache must still check for missing CSV"
    # Look ahead 1000 chars; the audit helper should be called within this block
    window = src[no_csv_idx:no_csv_idx + 2000]
    assert "_record_artifact_absent_audit" in window, (
        "extract_shimcache 'No CSV' branch must call _record_artifact_absent_audit "
        "to register the documented gap with the hook gate."
    )


# ---------------------------------------------------------------------------
# Audit pipeline helper contract — both helpers must produce state.json row
# ---------------------------------------------------------------------------

@_requires_fastmcp
def test_record_artifact_absent_audit_produces_state_row(tmp_path: Path, monkeypatch):
    """Direct end-to-end: invoking _record_artifact_absent_audit must
    leave behind a row in state.json:executions whose outputs_summary
    contains 'artifact_absent' (the substring the hooks look for)."""
    monkeypatch.setenv("SAVVYDFIR_ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path / "cases"))
    (tmp_path / "cases").mkdir()

    # Re-import to pick up the new env (state files are written under ANALYSIS_DIR)
    import importlib
    import sift_mcp.state
    import sift_mcp.audit
    import sift_mcp.server
    importlib.reload(sift_mcp.state)
    importlib.reload(sift_mcp.audit)
    importlib.reload(sift_mcp.server)
    from sift_mcp.server import _record_artifact_absent_audit, _state_manager

    _state_manager.load("REGRESSION-TEST")
    resp = _record_artifact_absent_audit(
        tool_name="disk.extract_srum",
        artifact_name="SRUDB.dat",
        checked_paths=["/mnt/disk/Windows/System32/sru/SRUDB.dat"],
        reason="regression test absence",
        case_id="REGRESSION-TEST",
    )
    assert resp.get("status") == "artifact_absent"
    assert resp.get("execution_id"), "helper must return execution_id"

    state = json.loads((tmp_path / "state.json").read_text())
    execs = state.get("executions", [])
    matching = [e for e in execs if e.get("tool_name") == "disk.extract_srum"]
    assert matching, "state.json:executions must contain disk.extract_srum row"
    assert "artifact_absent" in (matching[0].get("outputs_summary") or ""), (
        "outputs_summary must contain 'artifact_absent' substring so the "
        "pre-hook + stop-hook gates classify the call as a documented gap."
    )


@_requires_fastmcp
def test_round2_item1_success_audit_links_csv_to_raw_evidence_refs(tmp_path: Path, monkeypatch):
    """design review round-2 ITEM-1: when _record_tool_success_audit is
    called with csv_path, the resulting state.json:executions row must
    have raw_evidence_refs that _latest_durable_csv_for_tool() can find.

    Without this linkage, the gate accepts the success row but correlation
    silently sees no CSV and misses evidence — the original HIGH bug.
    """
    monkeypatch.setenv("SAVVYDFIR_ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path / "cases"))
    (tmp_path / "cases").mkdir()

    import importlib
    import sift_mcp.state
    import sift_mcp.audit
    import sift_mcp.server
    import sift_mcp.tools.correlation
    importlib.reload(sift_mcp.state)
    importlib.reload(sift_mcp.audit)
    importlib.reload(sift_mcp.server)
    importlib.reload(sift_mcp.tools.correlation)
    from sift_mcp.server import _record_tool_success_audit, _state_manager
    from sift_mcp.tools.correlation import _latest_durable_csv_for_tool
    import sift_mcp.tools.correlation as _corr_mod
    import sift_mcp.server as _server_mod
    # Wire the correlation module's _state_mgr to the same state manager.
    _corr_mod.init_tools(
        state_manager=_state_manager,
        audit_logger=_server_mod._audit_logger,
    )

    _state_manager.load("ROUND2-TEST")
    # Create a real CSV the linker will reference
    csv_path = tmp_path / "fake_srum_network.csv"
    csv_path.write_text("ProcessName,BytesSent\nchrome.exe,1000\n")

    import time as _t
    start = _t.monotonic()
    _t.sleep(0.05)  # simulate real work
    eid = _record_tool_success_audit(
        tool_name="disk.extract_srum",
        outputs_summary="status=success entries=1 csv=/fake_srum_network.csv",
        parameters={"case_id": "ROUND2-TEST"},
        command_line="esedbexport ... && SrumECmd parse ...",
        start_time=start,
        csv_path=str(csv_path),
    )
    assert eid

    # Now correlation's lookup must find the CSV
    found = _latest_durable_csv_for_tool("disk.extract_srum")
    assert found == str(csv_path.resolve()), (
        f"Round-2 ITEM-1 regression: _latest_durable_csv_for_tool returned "
        f"{found!r} but expected {csv_path}. The success audit row did not "
        f"link the CSV via raw_evidence_refs."
    )


@_requires_fastmcp
def test_round2_item2_success_audit_captures_real_duration_and_command(tmp_path: Path, monkeypatch):
    """design review round-2 ITEM-2: success audit must record real
    duration (covering full subprocess+parsing) and a non-synthetic
    command_line. Fake placeholders weaken chain-of-custody."""
    monkeypatch.setenv("SAVVYDFIR_ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path / "cases"))
    (tmp_path / "cases").mkdir()

    import importlib
    import sift_mcp.state
    import sift_mcp.audit
    import sift_mcp.server
    importlib.reload(sift_mcp.state)
    importlib.reload(sift_mcp.audit)
    importlib.reload(sift_mcp.server)
    from sift_mcp.server import _record_tool_success_audit, _state_manager

    _state_manager.load("ROUND2-TEST")

    import time as _t
    start = _t.monotonic()
    _t.sleep(0.1)  # simulate 100ms of subprocess work
    real_command = "esedbexport -t /tmp/out /mnt/disk/Windows/System32/sru/SRUDB.dat && SrumECmd parse /tmp/out"
    _record_tool_success_audit(
        tool_name="disk.extract_srum",
        outputs_summary="status=success entries=1",
        parameters={"case_id": "ROUND2-TEST"},
        command_line=real_command,
        start_time=start,
    )

    state = json.loads((tmp_path / "state.json").read_text())
    execs = state.get("executions", [])
    assert execs, "execution must be recorded"
    row = execs[0]
    # Real duration: at least the 100ms sleep
    duration = row.get("duration_seconds") or 0
    assert duration >= 0.05, (
        f"Round-2 ITEM-2 regression: duration was {duration}s — must reflect "
        f"actual subprocess work (>=50ms in this synthetic test), not ~0ms."
    )
    # Real command — must NOT be the synthetic fallback
    cmd = row.get("command_line") or ""
    assert "esedbexport" in cmd and "SrumECmd parse" in cmd, (
        f"Round-2 ITEM-2 regression: command_line={cmd!r} — must contain "
        f"real subprocess invocation, not synthetic '<tool>(exit_code=0)' fallback."
    )
    assert "(exit_code=0)" not in cmd, (
        "command_line must not be the synthetic fallback placeholder."
    )


@_requires_fastmcp
def test_record_tool_success_audit_produces_state_row(tmp_path: Path, monkeypatch):
    """Same end-to-end check for the success-path helper."""
    monkeypatch.setenv("SAVVYDFIR_ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path / "cases"))
    (tmp_path / "cases").mkdir()

    import importlib
    import sift_mcp.state
    import sift_mcp.audit
    import sift_mcp.server
    importlib.reload(sift_mcp.state)
    importlib.reload(sift_mcp.audit)
    importlib.reload(sift_mcp.server)
    from sift_mcp.server import _record_tool_success_audit, _state_manager

    _state_manager.load("REGRESSION-TEST")
    eid = _record_tool_success_audit(
        tool_name="disk.extract_srum",
        outputs_summary="status=success network_entries=25000 flagged_processes=2",
        parameters={"case_id": "REGRESSION-TEST"},
    )
    assert eid, "helper must return execution_id"

    state = json.loads((tmp_path / "state.json").read_text())
    execs = state.get("executions", [])
    matching = [e for e in execs if e.get("tool_name") == "disk.extract_srum"]
    assert matching, "state.json:executions must contain disk.extract_srum row"
    assert matching[0].get("exit_code") == 0
    assert "status=success" in (matching[0].get("outputs_summary") or "")


# ---------------------------------------------------------------------------
# Hook-gate integration test — proves the bugs would have been caught
# ---------------------------------------------------------------------------

def test_pre_gate_allows_when_srum_success_audited(tmp_path: Path):
    """End-to-end: build a state.json where extract_srum has a success
    execution row, and verify workflow-enforce-pre.py ALLOWS generate_report.
    Without Bug 1 fix, this would have failed because state.json:executions
    would lack a row for disk.extract_srum entirely."""
    import subprocess

    clean_tools = [
        "memory.list_processes", "memory.scan_processes", "memory.detect_injection",
        "memory.scan_network", "memory.list_dlls",
        "disk.extract_mft_timeline", "disk.extract_usn_journal",
        "disk.summarize_evtx", "disk.extract_prefetch", "disk.get_amcache",
        "disk.extract_shimcache", "disk.extract_registry_run_keys",
        "disk.extract_srum",  # ← this is the row that Bug 1 was preventing
        "detection.sigma_hunt", "correlation.compare_disk_and_memory",
    ]
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "case_id": "TEST",
        "status": "IN_PROGRESS",
        "executions": [
            {"tool_name": t, "exit_code": 0,
             "outputs_summary": "status=success" if t == "disk.extract_srum" else "ok"}
            for t in clean_tools
        ],
    }))
    (tmp_path / "audit.jsonl").touch()

    env = {**os.environ, "SAVVYDFIR_ANALYSIS_DIR": str(tmp_path)}
    event = json.dumps({
        "tool_name": "mcp__savvydfir__generate_report",
        "cwd": str(tmp_path.parent),
        "tool_input": {"case_id": "TEST"},
    })
    r = subprocess.run(
        ["python3", str(ROOT / ".claude" / "hooks" / "workflow-enforce-pre.py")],
        input=event, capture_output=True, text=True, env=env, timeout=10,
    )
    # No stdout = no deny = allow
    assert not r.stdout.strip(), (
        f"Pre-gate must ALLOW when all mandatory tools (including extract_srum) "
        f"have success rows. Got: {r.stdout}"
    )
