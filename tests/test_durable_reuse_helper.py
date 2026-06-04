"""F-A durable-reuse helper + sidecar fingerprint (review 2026-06-04).

Reuse a prior dotnet-parsed CSV after state.json (cache index) is cleared, IF the
source evidence is unchanged. record_cache_hit rows must satisfy the report gate.
"""
import tempfile
import unittest
from pathlib import Path

from sift_mcp.tools import _cache as c


class FakeEntry(dict):
    pass


class FakeAudit:
    current_iteration = 1

    def __init__(self):
        self._n = 0

    def next_execution_id(self):
        self._n += 1
        return f"E-{self._n:03d}"

    def log_execution(self, **k):
        return FakeEntry(entry_hash="started_h")

    def log_result(self, **k):
        return FakeEntry(entry_hash="completed_h")


class FakeState:
    def __init__(self):
        self.rows = []

    def add_execution(self, row):
        self.rows.append(row)


def _gate(ex):  # mirrors reporting._execution_was_successful
    if ex.get("exit_code") is None or int(ex["exit_code"]) != 0:
        return False
    if float(ex.get("duration_seconds") or 0) <= 0:
        return False
    return bool(ex.get("audit_completed_entry_hash"))


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.f = self.base / "mft" / "$MFT"
        self.f.parent.mkdir(parents=True)
        self.f.write_bytes(b"RAWMFT")

    def test_file_fingerprint_match(self):
        fp = c.source_fingerprint(str(self.f))
        self.assertEqual(fp["kind"], "file")
        self.assertTrue(c.fingerprints_match(fp, c.source_fingerprint(str(self.f))))

    def test_file_fingerprint_changes_on_edit(self):
        fp = c.source_fingerprint(str(self.f))
        self.f.write_bytes(b"RAWMFT-BIGGER")
        self.assertFalse(c.fingerprints_match(fp, c.source_fingerprint(str(self.f))))

    def test_dir_manifest_detects_added_file(self):
        d = self.base / "evtx"
        d.mkdir()
        (d / "a.evtx").write_bytes(b"x")
        fp = c.source_fingerprint(str(d))
        self.assertEqual(fp["kind"], "dir")
        (d / "b.evtx").write_bytes(b"y")  # add a file
        self.assertFalse(c.fingerprints_match(fp, c.source_fingerprint(str(d))))


class TryDurableReuseTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.src = self.base / "raw" / "mft" / "$MFT"
        self.src.parent.mkdir(parents=True)
        self.src.write_bytes(b"RAWMFT")
        self.out = self.base / "CASE" / "artifacts" / "mft"
        self.out.mkdir(parents=True)
        (self.out / "mft_timeline.csv").write_text("a,b\n1,2\n")
        self.a, self.s = FakeAudit(), FakeState()

    def _reuse(self, **over):
        kw = dict(tool_name="disk.extract_mft_timeline",
                  parameters={"mft_path": str(self.src)},
                  output_base=str(self.base), case_id="CASE", subtype="mft",
                  canonical_filename="mft_timeline.csv", source_path=str(self.src))
        kw.update(over)
        return c.try_durable_reuse(self.a, self.s, **kw)

    def test_no_sidecar_legacy_unverified(self):
        r = self._reuse()
        self.assertEqual(r["reuse_confidence"], "legacy_unverified")
        self.assertTrue(_gate(self.s.rows[0]), "cache-hit row must satisfy report gate")

    def test_sidecar_match_fingerprint_verified(self):
        c.write_reuse_sidecar(str(self.out / "mft_timeline.csv"),
                              tool_name="disk.extract_mft_timeline", source_path=str(self.src))
        r = self._reuse()
        self.assertEqual(r["reuse_confidence"], "fingerprint_verified")

    def test_source_changed_forces_reparse(self):
        c.write_reuse_sidecar(str(self.out / "mft_timeline.csv"),
                              tool_name="disk.extract_mft_timeline", source_path=str(self.src))
        self.src.write_bytes(b"CHANGED-BIGGER")
        self.assertIsNone(self._reuse(), "changed source must reparse (None)")

    def test_force_reparse_returns_none_and_invalidates(self):
        c.write_reuse_sidecar(str(self.out / "mft_timeline.csv"),
                              tool_name="disk.extract_mft_timeline", source_path=str(self.src))
        self.assertIsNone(self._reuse(force_reparse=True))
        self.assertFalse(c._sidecar_path(str(self.out / "mft_timeline.csv")).exists())

    def test_missing_output_returns_none(self):
        (self.out / "mft_timeline.csv").unlink()
        self.assertIsNone(self._reuse())


if __name__ == "__main__":
    unittest.main()
