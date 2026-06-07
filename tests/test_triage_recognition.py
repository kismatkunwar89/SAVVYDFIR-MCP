"""Tests for v1a triage-layout recognition (detect + Velociraptor normalizer).

Synthetic fixtures for every layout - no case specifics. Verified against the
real formats: CyLR uses the SOURCE drive letter (not C); Velociraptor URL-encodes
only the drive component (C%3A) and splits artifacts across auto/ntfs accessors.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sift_mcp.tools import disk


def _mk(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p


class DetectTriageLayoutTests(unittest.TestCase):
    def test_raw_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _mk(root / "Windows" / "System32")
            _mk(root / "Users" / "alpha")
            r = disk._detect_triage_layout(str(root))
            self.assertEqual(r["format"], "raw_mount")
            self.assertEqual(r["volume_roots"][0]["path"], str(root))
            self.assertFalse(r["requires_normalization"])

    def test_cylr_non_c_drive_letter(self):
        # VANKO-style: <name>.CYLR/G/Windows (drive G, NOT C).
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            drive = base / "vanko-c-drive.CYLR" / "G"
            _mk(drive / "Windows" / "System32")
            _mk(drive / "Users" / "PC User")
            _mk(base / "vanko-c-drive.CYLR")  # ensure wrapper exists
            r = disk._detect_triage_layout(str(base))
            self.assertEqual(r["format"], "cylr")
            self.assertEqual(r["drive_candidates"], ["G"])
            self.assertEqual(r["volume_roots"][0]["drive"], "G")
            self.assertTrue(r["artifact_paths"]["windows_root"].endswith("/G/Windows"))

    def test_kape_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            drive = base / "WKSTN01" / "C"
            _mk(drive / "Windows")
            _mk(drive / "Users")
            (base / "WKSTN01" / "WKSTN01_kape.cli").write_text("x", encoding="utf-8")
            r = disk._detect_triage_layout(str(base))
            self.assertEqual(r["format"], "kape")
            self.assertEqual(r["drive_candidates"], ["C"])

    def test_archive_not_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            arc = Path(tmp) / "host.CYLR.7z"
            arc.write_bytes(b"7z\x00")
            r = disk._detect_triage_layout(str(arc))
            self.assertEqual(r["format"], "archive_unextracted")
            self.assertEqual(r["volume_roots"], [])
            self.assertIn("extract", r["recommended_next"].lower())

    def test_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(Path(tmp) / "random" / "stuff")
            r = disk._detect_triage_layout(str(tmp))
            self.assertEqual(r["format"], "unknown")

    def test_path_not_found(self):
        r = disk._detect_triage_layout("/no/such/triage/path")
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["reason"], "path_not_found")


def _mk_velociraptor(base: Path, drives=("C",), with_ntfs=True):
    base.mkdir(parents=True, exist_ok=True)
    (base / "collection_context.json").write_text("{}", encoding="utf-8")
    for d in drives:
        auto = base / "uploads" / "auto" / f"{d}%3A"
        _mk(auto / "Windows" / "System32")
        _mk(auto / "Users" / "alpha")
        if with_ntfs:
            ntfs = base / "uploads" / "ntfs" / f"%5C%5C.%5C{d}%3A"
            _mk(ntfs / "$Extend")
            (ntfs / "$MFT").write_bytes(b"FILE0")
            (ntfs / "$Extend" / "$UsnJrnl%3A$J").write_bytes(b"USN")
    return base


def _mk_velociraptor_raw_tar(base: Path, drive="C"):
    r"""Real raw-collector-tar shape (verified on hunt_lab DFIR-RansomHub):
    NO collection_context.json; markers are upload_transactions.json/uploads.json/
    task.db; ONLY the ntfs accessor; the volume root is the encoded \\.\C: device."""
    base.mkdir(parents=True, exist_ok=True)
    for m in ("upload_transactions.json", "uploads.json", "task.db", "logs.json"):
        (base / m).write_text("{}", encoding="utf-8")
    root = base / "uploads" / "ntfs" / f"%5C%5C.%5C{drive}%3A"
    _mk(root / "Windows" / "System32")
    _mk(root / "Users" / "victim")
    _mk(root / "$Extend")
    (root / "$MFT").write_bytes(b"FILE0")
    return base


class VelociraptorTests(unittest.TestCase):
    # DETECT-ONLY: recognition + accessor reporting. Extraction/normalization is a
    # later, not-yet-shipped increment - these assert what detection reports.
    def test_detect_single_drive_reports_accessor_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _mk_velociraptor(base, drives=("C",))
            r = disk._detect_triage_layout(str(base))
            self.assertEqual(r["format"], "velociraptor")
            self.assertFalse(r["requires_drive_selection"])
            self.assertEqual(r["drive_candidates"], ["C"])
            accessors = {v["accessor"] for v in r["volume_roots"]}
            self.assertEqual(accessors, {"auto", "ntfs"})
            # auto root carries Windows/Users; ntfs carries $MFT
            self.assertTrue(r["artifact_paths"]["windows_root"].endswith("/Windows"))
            self.assertTrue(r["artifact_paths"]["mft_path"].endswith("/$MFT"))
            # internal normalizer keys are NOT leaked in the detector return
            # (the server tool also strips them; detector itself may carry them)

    def test_real_raw_collector_tar_shape_ntfs_only(self):
        # Regression for the hunt_lab real sample: no collection_context.json,
        # only the ntfs accessor, encoded \\.\C: device root. Must still detect.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _mk_velociraptor_raw_tar(base, drive="C")
            r = disk._detect_triage_layout(str(base))
            self.assertEqual(r["format"], "velociraptor")
            self.assertEqual(r["drive_candidates"], ["C"])
            accessors = {v["accessor"] for v in r["volume_roots"]}
            self.assertEqual(accessors, {"ntfs"})
            self.assertTrue(r["artifact_paths"]["windows_root"].endswith("/Windows"))
            self.assertTrue(r["artifact_paths"]["mft_path"].endswith("/$MFT"))

    def test_multi_drive_requires_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _mk_velociraptor(base, drives=("C", "D"))
            r = disk._detect_triage_layout(str(base))
            self.assertTrue(r["requires_drive_selection"])
            self.assertEqual(sorted(r["drive_candidates"]), ["C", "D"])
            self.assertEqual(r["volume_roots"], [])
            # selecting one resolves it and reports that drive's roots
            r2 = disk._detect_triage_layout(str(base), drive="D")
            self.assertFalse(r2["requires_drive_selection"])
            self.assertTrue(r2["volume_roots"])
            self.assertTrue(all(v["drive"] == "D" for v in r2["volume_roots"]))


if __name__ == "__main__":
    unittest.main()
