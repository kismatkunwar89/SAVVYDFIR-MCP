"""Regression guard for the Chainsaw Sigma mapping (review 2026-06-06).

Background: the Run-11 hand-authored ``rules/chainsaw-sigma-mapping.yml`` used the
``kind: !evtx`` + per-channel ``groups:`` format. It PARSED and loaded ~2284
rules but matched 0 events on known-malicious EVTX — a silent no-op that made
``sigma_hunt`` useless on every case. The fix replaces it with the official
Chainsaw ``sigma-event-logs-all.yml`` (``kind: evtx`` + ``rules: sigma``), which
matched 34 detections on the same 12-sample control.

Two layers, so this can never silently regress again:
  1. format guard (no deps)   - the mapping must be the official format, NOT the
                                 broken Run-11 ``!evtx`` format.
  2. positive control (chainsaw) - known-malicious EVTX must yield >0 detections;
                                 skipped when chainsaw / sigma rules / network absent.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MAPPING = REPO / "rules" / "chainsaw-sigma-mapping.yml"


def test_mapping_uses_official_format_not_broken_run11():
    """Format guard: the mapping must be the working official format."""
    assert MAPPING.is_file(), f"sigma mapping missing: {MAPPING}"
    text = MAPPING.read_text(encoding="utf-8")
    # Official working format markers.
    assert "kind: evtx" in text, "mapping must use official 'kind: evtx' format"
    assert "rules: sigma" in text, "mapping must declare 'rules: sigma'"
    # The broken Run-11 format markers must be ABSENT.
    assert "kind: !evtx" not in text, (
        "mapping reverted to the broken Run-11 'kind: !evtx' format which loads "
        "rules but matches nothing (silent sigma_hunt no-op)"
    )
    # Official mapping binds nested Event fields; the broken one used flat names.
    assert "Event.System" in text or "Event.EventData" in text, (
        "mapping must bind nested Event.System/Event.EventData fields (official "
        "format); flat 'to: EventID' bindings are the Run-11 no-op bug"
    )


def test_sigma_positive_control_matches_known_malicious():
    """Positive control: known-malicious EVTX must produce detections.

    Skips cleanly when chainsaw, the sigma rules dir, or network are unavailable
    (so CI without SIFT tooling stays green); runs for real on the SIFT VM /
    pre-release checklist.
    """
    if shutil.which("chainsaw") is None and not Path("/usr/local/bin/chainsaw").exists():
        pytest.skip("chainsaw not installed")
    script = REPO / "scripts" / "eval" / "sigma_positive_control.sh"
    assert script.is_file(), f"positive-control script missing: {script}"
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True, text=True, timeout=600,
    )
    # Exit 77 = environment skip (no chainsaw/sigma/samples); honor it.
    if proc.returncode == 77:
        pytest.skip(f"positive control unavailable: {proc.stdout.strip()[-200:]}")
    assert proc.returncode == 0, (
        "Sigma positive control FAILED — the mapping matched too few detections "
        f"on known-malicious EVTX (mapping is broken).\n{proc.stdout[-1000:]}"
    )
