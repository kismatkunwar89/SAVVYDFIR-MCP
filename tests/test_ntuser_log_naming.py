"""Regression tests for NTUSER hive + transaction-log target naming.

peer reviewer adversarial review of commit 435f261 (the .LOG1/.LOG2 staging fix)
identified a follow-up high-severity bug: _raw_artifact_target only
applied the per-user prefix to the hive itself (NTUSER.DAT → alice_NTUSER.DAT)
but not to its transaction logs (NTUSER.DAT.LOG1 stayed unprefixed).

Two downstream failures resulted:

  1. rla.exe replay miss: rla looks for logs as `hive_path.name + ".LOG1"`,
     i.e. `alice_NTUSER.DAT.LOG1` next to `alice_NTUSER.DAT`. With logs
     staged as the generic `NTUSER.DAT.LOG1`, the per-user replay fails —
     dirty per-user hives are parsed without transaction-log replay,
     losing user persistence artifacts.

  2. Multi-user collision: Alice's NTUSER.DAT.LOG1 and Bob's
     NTUSER.DAT.LOG1 both stage to the same generic path. seen_targets
     de-dupes by string → the second user's log is silently skipped.
     Alice's NTUSER.DAT and Bob's NTUSER.DAT keep distinct names (because
     the hive-only prefix worked), but their logs collide.

The fix extends the per-user prefix to ALL NTUSER variants:
  NTUSER.DAT, NTUSER.DAT.LOG, NTUSER.DAT.LOG1, NTUSER.DAT.LOG2

These tests lock that in.
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
def test_single_user_ntuser_artifacts_share_consistent_prefix(tmp_path: Path):
    """A single user's NTUSER.DAT + .LOG1 + .LOG2 must all map to targets
    with the same `{user}_` prefix, so rla.exe finds the logs next to the
    hive when discovering them via `hive_path.name + ".LOG1"`."""
    from sift_mcp.server import _raw_artifact_target

    raw_base = tmp_path / "raw"
    user = "alice"
    base_path = f"C:/Users/{user}"

    hive = _raw_artifact_target(
        raw_base=raw_base, family="registry",
        source_path=f"{base_path}/NTUSER.DAT",
    )
    log1 = _raw_artifact_target(
        raw_base=raw_base, family="registry",
        source_path=f"{base_path}/NTUSER.DAT.LOG1",
    )
    log2 = _raw_artifact_target(
        raw_base=raw_base, family="registry",
        source_path=f"{base_path}/NTUSER.DAT.LOG2",
    )
    log_no_num = _raw_artifact_target(
        raw_base=raw_base, family="registry",
        source_path=f"{base_path}/NTUSER.DAT.LOG",
    )

    assert hive.name == "alice_NTUSER.DAT", f"hive: {hive.name}"
    assert log1.name == "alice_NTUSER.DAT.LOG1", f"log1: {log1.name}"
    assert log2.name == "alice_NTUSER.DAT.LOG2", f"log2: {log2.name}"
    assert log_no_num.name == "alice_NTUSER.DAT.LOG", f"log: {log_no_num.name}"

    # Critical contract: rla.exe replay does `hive_path.name + ".LOG1"` —
    # that must resolve to the staged log target.
    assert log1.name == hive.name + ".LOG1", (
        "rla.exe replay contract broken: hive.name + '.LOG1' must equal "
        f"log1.name. Got hive={hive.name}, log1={log1.name}"
    )
    assert log2.name == hive.name + ".LOG2"
    assert log1.parent == hive.parent  # same directory


@_requires_fastmcp
def test_multi_user_ntuser_artifacts_do_not_collide(tmp_path: Path):
    """Two users' NTUSER.DAT + .LOG1/.LOG2 must produce 6 distinct target
    paths. Pre-fix: hives differed (alice_NTUSER.DAT vs bob_NTUSER.DAT)
    but logs collided (NTUSER.DAT.LOG1 from both), so seen_targets dedup
    silently dropped Bob's logs."""
    from sift_mcp.server import _raw_artifact_target

    raw_base = tmp_path / "raw"
    paths = []
    for user in ("alice", "bob"):
        for variant in ("NTUSER.DAT", "NTUSER.DAT.LOG1", "NTUSER.DAT.LOG2"):
            t = _raw_artifact_target(
                raw_base=raw_base, family="registry",
                source_path=f"C:/Users/{user}/{variant}",
            )
            paths.append(str(t))
    assert len(set(paths)) == len(paths), (
        f"Multi-user NTUSER collision: {len(paths)} sources produced "
        f"{len(set(paths))} distinct targets — duplicates would be skipped "
        f"by seen_targets. Paths: {paths}"
    )
    # Verify both users get all 3 artifacts
    alice_paths = [p for p in paths if "alice" in p]
    bob_paths = [p for p in paths if "bob" in p]
    assert len(alice_paths) == 3
    assert len(bob_paths) == 3


@_requires_fastmcp
def test_rla_replay_contract_holds_for_per_user_hives(tmp_path: Path):
    """End-to-end: simulate the rla.exe staging+discovery flow. After
    `_raw_artifact_target` maps the hive and its logs, write fake files
    at those targets, then verify the replay-discovery pattern
    (`hive_path.parent / (hive_path.name + ".LOG1")`) finds the staged log."""
    from sift_mcp.server import _raw_artifact_target

    raw_base = tmp_path / "raw"
    user = "alice"
    base = f"C:/Users/{user}"

    hive_target = _raw_artifact_target(raw_base=raw_base, family="registry",
                                       source_path=f"{base}/NTUSER.DAT")
    log1_target = _raw_artifact_target(raw_base=raw_base, family="registry",
                                       source_path=f"{base}/NTUSER.DAT.LOG1")
    log2_target = _raw_artifact_target(raw_base=raw_base, family="registry",
                                       source_path=f"{base}/NTUSER.DAT.LOG2")

    # Stage fake content
    hive_target.parent.mkdir(parents=True, exist_ok=True)
    hive_target.write_bytes(b"fake hive content")
    log1_target.write_bytes(b"fake log1 content")
    log2_target.write_bytes(b"fake log2 content")

    # rla.exe replay discovery contract (from _replay_hive_with_rla in disk.py)
    for suffix in (".LOG1", ".LOG2"):
        discovered = hive_target.parent / f"{hive_target.name}{suffix}"
        assert discovered.exists(), (
            f"rla.exe replay contract broken for user {user!r}: "
            f"`hive_path.parent / (hive_path.name + '{suffix}')` resolved to "
            f"{discovered}, which doesn't exist. The staged log is at a "
            f"different path — rla replay would silently skip it."
        )
        assert discovered.is_file()


@_requires_fastmcp
def test_relative_fls_path_triggers_prefix(tmp_path: Path):
    """peer reviewer follow-up regression: fls -r -p emits RELATIVE paths like
    "Users/alice/NTUSER.DAT" (no leading slash, no drive). The old
    "/Users/" substring guard missed these entirely, bypassing the
    per-user prefix branch for the actual extraction path."""
    from sift_mcp.server import _raw_artifact_target

    raw_base = tmp_path / "raw"
    # The exact shape _parse_fls_record produces — no leading slash, no drive
    relative_paths = [
        ("Users/alice/NTUSER.DAT",      "alice_NTUSER.DAT"),
        ("Users/alice/NTUSER.DAT.LOG1", "alice_NTUSER.DAT.LOG1"),
        ("Users/alice/NTUSER.DAT.LOG2", "alice_NTUSER.DAT.LOG2"),
        ("Users/bob/NTUSER.DAT",        "bob_NTUSER.DAT"),
        ("Users/bob/NTUSER.DAT.LOG1",   "bob_NTUSER.DAT.LOG1"),
    ]
    for source, expected_name in relative_paths:
        target = _raw_artifact_target(
            raw_base=raw_base, family="registry", source_path=source,
        )
        assert target.name == expected_name, (
            f"Relative fls path {source!r} should produce {expected_name!r} "
            f"but got {target.name!r}. The substring-based guard was the "
            f"original bug — peer reviewer follow-up. Path segment detection is required."
        )


@_requires_fastmcp
def test_relative_path_multi_user_no_collision(tmp_path: Path):
    """Multi-user collision via fls relative paths must NOT happen.
    Pre-fix: alice + bob NTUSER.DAT.LOG1 both produce generic 'NTUSER.DAT.LOG1'
    target → seen_targets dedup silently drops bob's log."""
    from sift_mcp.server import _raw_artifact_target

    raw_base = tmp_path / "raw"
    sources = [
        "Users/alice/NTUSER.DAT",
        "Users/alice/NTUSER.DAT.LOG1",
        "Users/alice/NTUSER.DAT.LOG2",
        "Users/bob/NTUSER.DAT",
        "Users/bob/NTUSER.DAT.LOG1",
        "Users/bob/NTUSER.DAT.LOG2",
    ]
    targets = [
        str(_raw_artifact_target(raw_base=raw_base, family="registry", source_path=s))
        for s in sources
    ]
    assert len(set(targets)) == len(targets), (
        f"Multi-user relative-path collision: {len(sources)} sources, only "
        f"{len(set(targets))} distinct targets. Bob's logs would be silently "
        f"skipped by seen_targets. Targets: {targets}"
    )


@_requires_fastmcp
def test_legacy_documents_and_settings_path_triggers_prefix(tmp_path: Path):
    """Older Windows (XP/2003) used 'Documents and Settings\\<user>\\' for
    user profile dirs. Per-user prefix should detect that path segment too
    so legacy images don't silently fall through."""
    from sift_mcp.server import _raw_artifact_target
    target = _raw_artifact_target(
        raw_base=tmp_path / "raw", family="registry",
        source_path="Documents and Settings/Administrator/NTUSER.DAT.LOG1",
    )
    assert target.name == "Administrator_NTUSER.DAT.LOG1"


def test_classifier_and_target_naming_source_check():
    """Source-text guard: the _raw_artifact_target NTUSER branch must
    handle all 4 variants — NTUSER.DAT, NTUSER.DAT.LOG, .LOG1, .LOG2 —
    via a shared variant set, not just the bare NTUSER.DAT name."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    # The fix introduces _NTUSER_VARIANTS constant
    assert "_NTUSER_VARIANTS" in src, (
        "peer reviewer consensus regression: _NTUSER_VARIANTS constant missing. "
        "The per-user prefix must cover all NTUSER transaction-log variants "
        "(NTUSER.DAT + .LOG + .LOG1 + .LOG2), not just the bare hive."
    )
    # Find the constant definition
    idx = src.find("_NTUSER_VARIANTS = frozenset({")
    assert idx > 0
    block = src[idx:idx + 300]
    for v in ('"NTUSER.DAT"', '"NTUSER.DAT.LOG"',
              '"NTUSER.DAT.LOG1"', '"NTUSER.DAT.LOG2"'):
        assert v in block, f"_NTUSER_VARIANTS must include {v}"
    # And the per-user branch must reference _NTUSER_VARIANTS, not the
    # old `== "NTUSER.DAT"` literal check.
    func_idx = src.find("def _raw_artifact_target(")
    assert func_idx > 0
    next_def = src.find("\ndef ", func_idx + 1)
    body = src[func_idx:next_def]
    assert "_NTUSER_VARIANTS" in body, (
        "_raw_artifact_target must check membership against _NTUSER_VARIANTS, "
        "not the old `safe_name.upper() == 'NTUSER.DAT'` literal."
    )
    # Negative assertion: the old narrow check must be gone
    assert 'safe_name.upper() == "NTUSER.DAT"' not in body, (
        "Old narrow `== \"NTUSER.DAT\"` check still present — the fix "
        "needs to broaden to the variant set."
    )
    # peer reviewer follow-up: the substring-based "/Users/" check missed relative
    # fls paths entirely. Must use path-segment detection now.
    assert '"/Users/" in normalized' not in body, (
        "peer reviewer follow-up regression: the substring-based '/Users/' check "
        "missed relative fls paths like 'Users/alice/NTUSER.DAT'. Path "
        "must be detected as a segment, not via substring."
    )
    # And the new segment-based detection must reference the lowercase
    # "users" path component
    assert '"users"' in body.lower() or "'users'" in body.lower(), (
        "Per-user detection must check 'users' as a lowercased path segment."
    )
