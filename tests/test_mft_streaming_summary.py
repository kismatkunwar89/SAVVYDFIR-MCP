"""Tests for the memory-bounded streaming MFT summary (review 2026-06-03).

extract_mft_timeline previously did _read_csv (whole $MFT CSV -> list[dict]) +
_build_mft_records (parallel list[MftEntry]) -- the same full-materialization
pattern that OOM-killed the server on a large EVTX CSV. MFT is the highest
residual crash twin. The fix streams the CSV in one pass, creating per-entry
timestomping findings INLINE (depth preserved) while retaining only a bounded
sample + aggregates, with the individual-finding count capped + an aggregate
overflow finding.

These tests prove:
  1. EQUIVALENCE (N<=cap) - legacy _build_mft_records vs _stream_mft_summary produce
     identical timestomping_candidates + identical timestomping findings (stable
     fields) + identical pivots.
  2. FINDING CAP - N=1000 (all individual, no aggregate) vs N=1001 (1000 individual
     + 1 aggregate, truncated flag) boundary.
  3. STRESS / no-crash - N=5000 candidates: exact count, individual capped at 1000,
     aggregate present, sample capped, completes.
  4. STRUCTURAL - extract_mft_timeline / _prefetch_mft_timestamp_lookup no longer
     call _read_csv / _build_mft_records.
"""

import csv
import inspect
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sift_mcp.tools import disk
from sift_mcp.tools._contracts import compact_unique


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _row(entry: int, *, timestomp: bool, path: str = None) -> dict[str, str]:
    """One MFTECmd row. timestomp=True => $SI Created precedes $FN Created."""
    if timestomp:
        si, fn = "2020-11-01T00:00:00.000000Z", "2020-11-10T00:00:00.000000Z"
    else:
        si, fn = "2020-11-10T00:00:00.000000Z", "2020-11-10T00:00:00.000000Z"
    return {
        "EntryNumber": str(entry),
        "FileName": path or f"C:\\Users\\fred\\file{entry}.txt",
        "Created0x10": si,
        "LastModified0x10": si,
        "Created0x30": fn,
        "LastModified0x30": fn,
        "InUse": "true",
        "IsDirectory": "false",
        "FileSize": "1024",
    }


class _FakeState:
    """Captures add_finding payloads so tests can compare findings across paths."""
    def __init__(self):
        self.added: list[dict] = []

    def add_finding(self, finding_dict: dict) -> str:
        self.added.append(finding_dict)
        return f"F-{len(self.added)}"


def _stable(fd: dict) -> tuple:
    """Stable, id-independent finding fields for equivalence comparison."""
    return (
        fd.get("finding_type"),
        fd.get("artifact_offset"),
        fd.get("description"),
        tuple(fd.get("supporting_indicators") or []),
        fd.get("timestamp_observed"),
        fd.get("mitre_technique"),
    )


class _PatchedStateMixin(unittest.TestCase):
    def setUp(self):
        self._orig_state = disk._state
        self._orig_case = disk._case_id
        self._orig_iter = disk._current_iteration
        disk._case_id = lambda: "CASE-MFT-TEST"
        disk._current_iteration = lambda: 1

    def tearDown(self):
        disk._state = self._orig_state
        disk._case_id = self._orig_case
        disk._current_iteration = self._orig_iter


class MftStreamingEquivalenceTest(_PatchedStateMixin):
    def test_legacy_vs_stream_identical_depth(self):
        # mix of timestomp candidates + normal entries
        rows = []
        for i in range(60):
            rows.append(_row(i, timestomp=(i % 3 == 0)))  # 20 candidates
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "mft_timeline.csv")
            _write_csv(Path(csv_path), rows)

            # legacy path
            fake_legacy = _FakeState(); disk._state = fake_legacy
            legacy_rows = disk._read_csv(csv_path)
            lrec, lfids, lcand = disk._build_mft_records(
                legacy_rows, mft_path="/mft", tool="disk.extract_mft_timeline",
                execution_id="E-001", create_findings=True,
            )
            legacy_findings = [_stable(f) for f in fake_legacy.added]
            legacy_pivots = {
                "file_paths": compact_unique(r.file_path for r in lrec),
                "entry_numbers": compact_unique(r.entry_number for r in lrec),
                "timestamps": compact_unique(
                    disk._dt_to_iso(r.fn_created) or disk._dt_to_iso(r.si_created)
                    for r in lrec
                ),
            }

            # streaming path
            fake_stream = _FakeState(); disk._state = fake_stream
            s = disk._stream_mft_summary(
                csv_path, mft_path="/mft", tool="disk.extract_mft_timeline",
                execution_id="E-001", create_findings=True,
            )
            stream_findings = [_stable(f) for f in fake_stream.added]
            _, stream_pivots = disk._mft_contract_inputs(s)

            self.assertEqual(s["timestomping_candidates"], lcand)
            self.assertEqual(s["timestomping_candidates"], 20)
            self.assertEqual(len(stream_findings), len(legacy_findings))
            self.assertEqual(stream_findings, legacy_findings)   # byte-identical findings
            self.assertEqual(stream_pivots, legacy_pivots)
            self.assertFalse(s["timestomping_findings_truncated"])
            self.assertEqual(s["raw_rows"], len(rows))

    def test_no_candidates(self):
        rows = [_row(i, timestomp=False) for i in range(30)]
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "mft_timeline.csv")
            _write_csv(Path(csv_path), rows)
            disk._state = _FakeState()
            s = disk._stream_mft_summary(
                csv_path, mft_path="/mft", tool="disk.extract_mft_timeline",
                execution_id="E-001", create_findings=True,
            )
            self.assertEqual(s["timestomping_candidates"], 0)
            self.assertEqual(s["finding_ids"], [])
            self.assertFalse(s["timestomping_findings_truncated"])


class MftFindingCapTest(_PatchedStateMixin):
    def _run(self, n_candidates: int):
        rows = [_row(i, timestomp=True) for i in range(n_candidates)]
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "mft_timeline.csv")
            _write_csv(Path(csv_path), rows)
            fake = _FakeState(); disk._state = fake
            s = disk._stream_mft_summary(
                csv_path, mft_path="/mft", tool="disk.extract_mft_timeline",
                execution_id="E-001", create_findings=True,
            )
            return s, fake

    def test_boundary_at_cap(self):
        cap = disk._MFT_TIMESTOMP_FINDING_CAP
        s, fake = self._run(cap)  # exactly at the cap
        self.assertEqual(s["timestomping_candidates"], cap)
        self.assertEqual(len(fake.added), cap)             # all individual, no aggregate
        self.assertFalse(s["timestomping_findings_truncated"])

    def test_boundary_over_cap(self):
        cap = disk._MFT_TIMESTOMP_FINDING_CAP
        s, fake = self._run(cap + 1)  # one over
        self.assertEqual(s["timestomping_candidates"], cap + 1)
        # cap individual + 1 aggregate
        self.assertEqual(len(fake.added), cap + 1)
        self.assertTrue(s["timestomping_findings_truncated"])
        agg = fake.added[-1]
        self.assertIn("not_individually_recorded=1", agg["supporting_indicators"])
        self.assertEqual(agg["mitre_technique"], "T1070.006")


class MftStressNoCrashTest(_PatchedStateMixin):
    def test_5000_candidates_bounded(self):
        n = 5000
        rows = [_row(i, timestomp=True) for i in range(n)]
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "mft_timeline.csv")
            _write_csv(Path(csv_path), rows)
            fake = _FakeState(); disk._state = fake
            s = disk._stream_mft_summary(
                csv_path, mft_path="/mft", tool="disk.extract_mft_timeline",
                execution_id="E-001", create_findings=True,
            )
            cap = disk._MFT_TIMESTOMP_FINDING_CAP
            # exact count preserved
            self.assertEqual(s["timestomping_candidates"], n)
            self.assertEqual(s["raw_rows"], n)
            # individual findings capped + 1 aggregate
            self.assertEqual(len(fake.added), cap + 1)
            self.assertEqual(len(s["finding_ids"]), cap + 1)
            self.assertTrue(s["timestomping_findings_truncated"])
            # retained sample hard-capped (memory bounded)
            self.assertEqual(len(s["sample"]), disk._MFT_SAMPLE_CAP)


class MftStructuralGuardTest(unittest.TestCase):
    def test_extract_mft_timeline_streams(self):
        src = inspect.getsource(disk.extract_mft_timeline)
        self.assertNotIn("_read_csv(", src)
        self.assertNotIn("_build_mft_records(", src)
        self.assertIn("_stream_mft_summary(", src)

    def test_prefetch_lookup_streams(self):
        src = inspect.getsource(disk._prefetch_mft_timestamp_lookup)
        self.assertNotIn("_read_csv(", src)
        self.assertIn("_iter_csv_rows(", src)


if __name__ == "__main__":
    unittest.main()
