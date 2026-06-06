"""Regression: case-insensitive Windows path resolution (XP uppercase WINDOWS).

NIST Hacking Case (2026-06-06) edge case: ntfs-3g mounts case-SENSITIVELY, and XP
uses uppercase ``WINDOWS\\system32``. Tools hardcoding ``Windows/...`` missed the
path -> ``needs_extract_windows_artifacts`` -> the artifact_absent fix then FALSELY
reported present artifacts (81 Prefetch .pf, ShimCache) as absent. ``_ci_resolve``
walks each component case-insensitively so uppercase layouts resolve correctly.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sift_mcp.tools.disk import _ci_resolve


def test_ci_resolve_finds_uppercase_windows_prefetch():
    """A lowercase 'Windows/Prefetch' request resolves an uppercase WINDOWS dir."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "WINDOWS" / "Prefetch").mkdir(parents=True)
        (root / "WINDOWS" / "Prefetch" / "CMD.EXE-12345678.pf").write_text("x")
        resolved = _ci_resolve(root, "Windows", "Prefetch")
        assert resolved is not None
        assert resolved == root / "WINDOWS" / "Prefetch"


def test_ci_resolve_mixed_case_components():
    """Each component matches case-insensitively (system32 vs System32)."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "WINDOWS" / "system32" / "config").mkdir(parents=True)
        (root / "WINDOWS" / "system32" / "config" / "SYSTEM").write_text("hive")
        resolved = _ci_resolve(root, "Windows", "System32", "config", "SYSTEM")
        assert resolved is not None
        assert resolved.name == "SYSTEM"


def test_ci_resolve_exact_match_fast_path():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "Windows" / "Prefetch").mkdir(parents=True)
        resolved = _ci_resolve(root, "Windows", "Prefetch")
        assert resolved == root / "Windows" / "Prefetch"


def test_ci_resolve_genuinely_missing_returns_none():
    """Genuine absence (e.g. Amcache pre-Win8) returns None, not a false hit."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "WINDOWS" / "appcompat" / "Programs").mkdir(parents=True)
        # Amcache.hve absent -> None (parent resolves, leaf missing)
        assert _ci_resolve(root, "Windows", "appcompat", "Programs", "Amcache.hve") is None
        # but the parent dir DOES resolve (positive-absence can distinguish)
        assert _ci_resolve(root, "Windows", "appcompat", "Programs") is not None


def test_ci_resolve_no_windows_root_returns_none():
    with tempfile.TemporaryDirectory() as d:
        assert _ci_resolve(Path(d), "Windows", "Prefetch") is None
