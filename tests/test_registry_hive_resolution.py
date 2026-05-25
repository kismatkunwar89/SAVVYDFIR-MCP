"""Regression tests for the SAM-only RECmd bug (Run-8 item #3).

The bug had two compounding parts:

1. _durable_raw_artifact_path("registry") accepted ANY of
   (SYSTEM, SOFTWARE, SAM, NTUSER.DAT) as proof the registry dir was
   valid. So a SAM-only staging dir was happily returned, RECmd ran
   against SAM only, and persistence data (Run keys, services) was
   lost. The fix narrows the requirement to SYSTEM or SOFTWARE — the
   hives that actually carry persistence keys.

2. The existing data_gap warning for missing SYSTEM/SOFTWARE was buried
   inside state.data_gaps and never surfaced in the tool response. The
   agent saw status="success" and moved on. The fix elevates the
   response to status="warning" with explicit hives_present /
   hives_missing fields so the agent sees the gap immediately.
"""
from __future__ import annotations

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


@_requires_fastmcp
def test_durable_registry_path_rejects_sam_only_staging(tmp_path: Path, monkeypatch):
    """A staged registry dir containing ONLY SAM must NOT be returned as
    a valid durable registry path. Otherwise RECmd will produce SAM-only
    output and persistence data is silently lost."""
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path))
    # Fake a case dir with only SAM staged
    safe = "TESTCASE"
    reg_dir = tmp_path / safe / "artifacts" / "raw" / "registry"
    reg_dir.mkdir(parents=True)
    (reg_dir / "SAM").write_bytes(b"fake SAM hive contents")

    import sift_mcp.tools.disk as disk_mod
    # Patch _case_id() so _raw_artifact_base() builds the path under tmp_path.
    monkeypatch.setattr(disk_mod, "_case_id", lambda: safe)

    result = disk_mod._durable_raw_artifact_path("registry")
    # Post-fix: must return None because SYSTEM/SOFTWARE missing.
    assert result is None, (
        f"SAM-only staging dir must not be accepted as a registry source. "
        f"Got: {result}. This is the original Run-8 bug regression."
    )


@_requires_fastmcp
def test_durable_registry_path_accepts_system_only(tmp_path: Path, monkeypatch):
    """The function should accept SYSTEM-only as valid (still useful for
    services persistence + ControlSet)."""
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path))
    safe = "TESTCASE2"
    reg_dir = tmp_path / safe / "artifacts" / "raw" / "registry"
    reg_dir.mkdir(parents=True)
    (reg_dir / "SYSTEM").write_bytes(b"fake SYSTEM hive contents")

    import sift_mcp.tools.disk as disk_mod
    monkeypatch.setattr(disk_mod, "_case_id", lambda: safe)

    result = disk_mod._durable_raw_artifact_path("registry")
    assert result is not None, (
        f"SYSTEM-only staging should be accepted. tmp_path={tmp_path}, reg_dir={reg_dir}"
    )
    assert (Path(result) / "SYSTEM").is_file()


@_requires_fastmcp
def test_durable_registry_path_accepts_software_only(tmp_path: Path, monkeypatch):
    """SOFTWARE-only also accepted (Run keys live there)."""
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path))
    safe = "TESTCASE3"
    reg_dir = tmp_path / safe / "artifacts" / "raw" / "registry"
    reg_dir.mkdir(parents=True)
    (reg_dir / "SOFTWARE").write_bytes(b"fake SOFTWARE hive contents")

    import sift_mcp.tools.disk as disk_mod
    monkeypatch.setattr(disk_mod, "_case_id", lambda: safe)

    result = disk_mod._durable_raw_artifact_path("registry")
    assert result is not None
    assert (Path(result) / "SOFTWARE").is_file()


def test_durable_registry_path_source_check_is_narrow():
    """Source-text check: the function must require SYSTEM or SOFTWARE,
    not 'any of SAM/NTUSER.DAT'. Regression check against the original
    permissive code."""
    src = (ROOT / "sift_mcp" / "tools" / "disk.py").read_text()
    # Find the registry branch
    marker = 'if kind == "registry":'
    idx = src.find(marker)
    assert idx > 0, "registry branch in _durable_raw_artifact_path missing"
    # Slice ~500 chars after the marker — the loop body
    branch = src[idx:idx + 800]
    # The fix REMOVED SAM and NTUSER from the required-list. They must
    # not appear in the loop's tuple.
    # Find the loop tuple
    loop_start = branch.find('for required in (')
    assert loop_start > 0, "for required in (...) loop missing"
    loop_end = branch.find('):', loop_start)
    loop_tuple = branch[loop_start:loop_end]
    assert '"SAM"' not in loop_tuple, (
        "Run-8 SAM-only bug regressed: SAM is back in the 'required' "
        "tuple for _durable_raw_artifact_path('registry'). It must be "
        "removed — SAM alone is not enough for persistence analysis."
    )
    assert '"NTUSER.DAT"' not in loop_tuple, (
        "NTUSER.DAT alone is not enough for HKLM persistence analysis."
    )
    assert '"SYSTEM"' in loop_tuple
    assert '"SOFTWARE"' in loop_tuple


@_requires_fastmcp
def test_classify_raw_artifact_stages_registry_transaction_logs():
    """Run-8 root cause: registry hives were staged (SYSTEM 21MB, SOFTWARE
    100MB confirmed on remote) but their .LOG1/.LOG2 transaction logs were
    NOT — _classify_raw_artifact didn't match those names. Without LOG
    files, rla.exe can't replay pending transactions, dirty hives reach
    RECmd / AppCompatCacheParser, and output is empty/partial. This test
    locks in classifier coverage for transaction logs."""
    from sift_mcp.server import _classify_raw_artifact, _raw_artifact_target
    from pathlib import Path as _Path

    selected = {"registry"}
    # Hives themselves — sanity check, must still match
    assert _classify_raw_artifact("Windows/System32/config/SYSTEM", selected) == "registry"
    assert _classify_raw_artifact("Windows/System32/config/SOFTWARE", selected) == "registry"

    # Transaction logs — Run-8 root cause coverage
    for hive in ("SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"):
        for suffix in (".LOG1", ".LOG2", ".LOG"):
            path = f"Windows/System32/config/{hive}{suffix}"
            assert _classify_raw_artifact(path, selected) == "registry", (
                f"Registry transaction log {hive}{suffix} not classified as registry — "
                f"this is the Run-8 SAM-only / ShimCache-empty root cause."
            )

    # NTUSER.DAT logs
    assert _classify_raw_artifact("Users/alice/NTUSER.DAT.LOG1", selected) == "registry"
    assert _classify_raw_artifact("Users/alice/NTUSER.DAT.LOG2", selected) == "registry"

    # _raw_artifact_target preserves the suffix so rla.exe can find the log
    # files alongside the hive (it looks for "{hive_path.name}.LOG1" etc.)
    target = _raw_artifact_target(
        raw_base=_Path("/cases/X/artifacts/raw"),
        family="registry",
        source_path="Windows/System32/config/SYSTEM.LOG1",
    )
    assert str(target).endswith("/registry/SYSTEM.LOG1"), (
        f"target name must preserve .LOG1 suffix so rla.exe finds it next "
        f"to the SYSTEM hive. Got: {target}"
    )


def test_classify_raw_artifact_log_files_source_check():
    """Source-text guard: the registry classifier in server.py must include
    .log1/.log2/.log patterns for hive transaction logs. Without them,
    rla.exe transaction replay fails and dirty hives produce partial
    RECmd / AppCompatCacheParser output."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    # Find the registry branch in _classify_raw_artifact
    func_idx = src.find("def _classify_raw_artifact(")
    assert func_idx > 0
    next_def = src.find("\ndef ", func_idx + 1)
    body = src[func_idx:next_def if next_def > 0 else func_idx + 4000]
    # Must reference the .log1/.log2 transaction log pattern for registry hives.
    # The source uses an f-string `{hive}.log1` template, so check for those tokens.
    body_l = body.lower()
    assert "}.log1" in body_l and "}.log2" in body_l, (
        "Run-8 SAM-only / ShimCache-empty root cause regressed: "
        "_classify_raw_artifact must match registry hive .LOG1/.LOG2 transaction "
        "logs (the f-string template `{hive}.log1` / `{hive}.log2`). Without "
        "them, rla.exe can't replay pending transactions and dirty hives "
        "produce empty AppCompatCache / partial RECmd output."
    )
    # Must also handle NTUSER.DAT logs explicitly
    assert "ntuser.dat.log1" in body_l, (
        "_classify_raw_artifact must also stage NTUSER.DAT.LOG1/LOG2 for "
        "per-user persistence analysis."
    )


def test_extract_registry_response_carries_critical_hive_warning_source():
    """Source-text check: extract_registry_run_keys must compute and
    return hives_present / hives_missing in its response, and elevate
    status to 'warning' when SYSTEM or SOFTWARE is missing."""
    src = (ROOT / "sift_mcp" / "tools" / "disk.py").read_text()
    # Find the extract_registry_run_keys function
    func_idx = src.find("def extract_registry_run_keys(")
    assert func_idx > 0
    next_def = src.find("\ndef ", func_idx + 1)
    body = src[func_idx:next_def if next_def > 0 else len(src)]

    # Response must include hives_present + hives_missing
    assert '"hives_present"' in body or "'hives_present'" in body, (
        "Run-8 regression: extract_registry_run_keys must report "
        "hives_present in the response so the agent sees which hives RECmd actually had."
    )
    assert '"hives_missing"' in body or "'hives_missing'" in body, (
        "Run-8 regression: extract_registry_run_keys must report hives_missing."
    )
    # Must elevate status to 'warning' when critical hives are missing
    assert 'critical_hive_warning' in body, (
        "Run-8 regression: extract_registry_run_keys must escalate the "
        "response status to 'warning' with a critical_hive_warning field "
        "when SYSTEM or SOFTWARE is absent."
    )
    assert 'response["status"] = "warning"' in body or "response['status'] = 'warning'" in body, (
        "Run-8 regression: missing SYSTEM/SOFTWARE must elevate the "
        "response status — buried data_gaps alone don't reach the agent."
    )
