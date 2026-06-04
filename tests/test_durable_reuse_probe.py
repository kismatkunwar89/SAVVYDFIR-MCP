"""Durable-reuse MVP: content-aware probe tests (consensus 2026-06-03).

probe_durable_raw(raw_base, kind) is the parameterized, wrong-case-safe probe
that extract_windows_artifacts uses to skip re-staging. It rejects empty/partial
dirs (a prior bug let empty raw/evtx shadow a real mount) and SAM-only registry
(Run-8 lesson). The server-side short-circuit (full/partial cache hit, labels,
force_reextract) is fastmcp-only -> validated on the VM.
"""

import tempfile
from pathlib import Path

from sift_mcp.tools.disk import probe_durable_raw


def _rb():
    d = tempfile.mkdtemp()
    return Path(d) / "raw"


def test_empty_dirs_rejected():
    rb = _rb()
    for kind in ("evtx", "registry", "prefetch", "amcache", "mft", "srum", "usn"):
        assert probe_durable_raw(rb, kind) is None


def test_evtx_dir_with_files():
    rb = _rb()
    (rb / "evtx").mkdir(parents=True)
    (rb / "evtx" / "Security.evtx").write_bytes(b"x")
    assert probe_durable_raw(rb, "evtx") == str(rb / "evtx")


def test_registry_sam_only_rejected_system_accepted():
    rb = _rb()
    (rb / "registry").mkdir(parents=True)
    (rb / "registry" / "SAM").write_bytes(b"x")
    assert probe_durable_raw(rb, "registry") is None  # SAM alone insufficient
    (rb / "registry" / "SYSTEM").write_bytes(b"x")
    assert probe_durable_raw(rb, "registry") == str(rb / "registry")


def test_amcache_zero_size_rejected():
    rb = _rb()
    (rb / "amcache").mkdir(parents=True)
    (rb / "amcache" / "Amcache.hve").write_bytes(b"")
    assert probe_durable_raw(rb, "amcache") is None
    (rb / "amcache" / "Amcache.hve").write_bytes(b"data")
    assert probe_durable_raw(rb, "amcache") == str(rb / "amcache" / "Amcache.hve")


def test_srum_file_path():
    rb = _rb()
    (rb / "srum").mkdir(parents=True)
    (rb / "srum" / "SRUDB.dat").write_bytes(b"x")
    assert probe_durable_raw(rb, "srum") == str(rb / "srum" / "SRUDB.dat")


def test_usn_known_journal_name():
    rb = _rb()
    (rb / "usn").mkdir(parents=True)
    (rb / "usn" / "$J").write_bytes(b"x")
    assert probe_durable_raw(rb, "usn") == str(rb / "usn")


def test_usn_fallback_any_nonempty_file():
    rb = _rb()
    (rb / "usn").mkdir(parents=True)
    (rb / "usn" / "usn_journal_J").write_bytes(b"x")
    assert probe_durable_raw(rb, "usn") == str(rb / "usn")


def test_usn_empty_dir_rejected():
    rb = _rb()
    (rb / "usn").mkdir(parents=True)
    (rb / "usn" / "placeholder").write_bytes(b"")  # zero-size only
    assert probe_durable_raw(rb, "usn") is None


def test_prefetch_and_mft():
    rb = _rb()
    (rb / "prefetch").mkdir(parents=True)
    (rb / "prefetch" / "CMD.EXE-A.pf").write_bytes(b"x")
    assert probe_durable_raw(rb, "prefetch") == str(rb / "prefetch")
    (rb / "mft").mkdir(parents=True)
    (rb / "mft" / "$MFT").write_bytes(b"x")
    assert probe_durable_raw(rb, "mft") == str(rb / "mft" / "$MFT")


def test_wrapper_uses_module_base(monkeypatch):
    # back-compat wrapper delegates to probe_durable_raw under _raw_artifact_base()
    import sift_mcp.tools.disk as disk
    rb = _rb()
    (rb / "prefetch").mkdir(parents=True)
    (rb / "prefetch" / "X.pf").write_bytes(b"x")
    monkeypatch.setattr(disk, "_raw_artifact_base", lambda: rb)
    assert disk._durable_raw_artifact_path("prefetch") == str(rb / "prefetch")
