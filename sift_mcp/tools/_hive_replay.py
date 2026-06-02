"""Shared registry-hive transaction-log replay (rla.exe).

Single canonical implementation used by every tool that parses an offline
registry hive (shimcache, registry run keys, registry file-access, shellbags).
Offline hives copied from a disk image frequently carry uncommitted
transaction logs (.LOG1/.LOG2); replaying them with Eric Zimmerman's ``rla``
produces a clean hive so downstream parsers see committed state.

This module has NO dependency on ``server.py`` (which would be circular - the
server imports the tools package, not the reverse). It is intentionally tiny
and import-safe.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

# Eric Zimmerman's Registry Log Analyzer, shipped with the EZ Tools suite.
_RLA_BIN = Path("/opt/zimmermantools/rla.dll")


def replay_hive_with_rla(
    hive_path: Path, label: str, *, want_status: bool = False
):
    """Copy one hive plus its transaction logs to temp dirs and replay via rla.

    Parameters
    ----------
    hive_path:
        Path to the registry hive on the (read-only) evidence mount.
    label:
        Short slug used in the temp-directory prefix for debuggability.
    want_status:
        When ``False`` (default, back-compat) return the 3-tuple
        ``(cleaned_hive, tmp_in, tmp_out)``. When ``True`` return the 4-tuple
        ``(cleaned_hive, tmp_in, tmp_out, replay_ok)`` so the caller can tell a
        genuine replay FAILURE apart from a clean hive.

    Replay-success semantics
    ------------------------
    ``replay_ok`` is ``True`` iff the rla process returned exit code ``0``.
    An exit code of ``0`` with NO cleaned output is the COMMON case of an
    already-clean hive - that stays ``replay_ok=True`` (the original copy is
    returned as ``cleaned_hive``). Only a NON-ZERO exit code means the replay
    FAILED (``replay_ok=False``); the caller must then treat the source as a
    collection gap rather than a clean success.

    Returns
    -------
    tuple(cleaned_hive_path, tmp_in, tmp_out[, replay_ok])
        ``cleaned_hive_path`` is the replayed hive (or the original copy when
        the hive was already clean / rla produced no output). The caller MUST
        remove ``tmp_in`` and ``tmp_out`` in a ``finally`` block.
    """
    # Exception-safe: both temp dirs are owned by this helper. If anything raises
    # before we hand the paths back (missing dotnet -> FileNotFoundError, rla
    # exceeds the timeout -> TimeoutExpired, tmp_out.iterdir() -> OSError, or the
    # second mkdtemp fails after the first), the caller never receives the tuple
    # and cannot clean up. So we destroy whatever we allocated, then re-raise -
    # preserving each caller's intended fallback-vs-fatal handling while leaking
    # nothing (these copies are multi-MB hives, repeated per profile).
    tmp_in = Path(tempfile.mkdtemp(prefix=f"savvydfir_rla_in_{label}_"))
    tmp_out: Optional[Path] = None
    try:
        tmp_out = Path(tempfile.mkdtemp(prefix=f"savvydfir_rla_out_{label}_"))

        # Copy hive (read-only evidence -> writable temp) plus any transaction logs.
        shutil.copy2(str(hive_path), str(tmp_in / hive_path.name))
        # Transaction logs must be matched CASE-INSENSITIVELY: on a case-sensitive
        # Linux NTFS mount the hive can be ``NTUSER.DAT`` while its logs are the
        # lowercase ``ntuser.dat.LOG1`` / ``.LOG2`` the OS actually wrote. A
        # case-exact lookup misses them, rla replays nothing, and RECmd then aborts
        # on the dirty hive ("0 key/value pairs") - silently dropping that user's
        # evidence. Discover each log by case-folded name, and stage it under a name
        # matching the copied hive base so rla pairs them.
        want = {
            f"{hive_path.name.lower()}.log1": f"{hive_path.name}.LOG1",
            f"{hive_path.name.lower()}.log2": f"{hive_path.name}.LOG2",
        }
        try:
            for entry in hive_path.parent.iterdir():
                staged = want.get(entry.name.lower())
                if staged and entry.is_file():
                    shutil.copy2(str(entry), str(tmp_in / staged))
        except OSError:
            pass  # log directory unreadable -> proceed with hive only

        proc = subprocess.run(
            ["/usr/bin/dotnet", str(_RLA_BIN), "-d", str(tmp_in), "--out", str(tmp_out)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        # exit 0 = success (clean hive OR successful replay); exit != 0 = replay
        # FAILED. A None proc (e.g. patched-out subprocess in tests) is treated
        # as not-ok for the want_status path; the back-compat 3-tuple path never
        # inspects replay_ok so it is unaffected.
        replay_ok = bool(proc is not None and getattr(proc, "returncode", 1) == 0)

        # rla writes the cleaned hive with a path-flattened name; glob for it.
        cleaned_files = [candidate for candidate in tmp_out.iterdir() if candidate.is_file()]
        cleaned_hive = cleaned_files[0] if cleaned_files else (tmp_in / hive_path.name)
        if want_status:
            return cleaned_hive, tmp_in, tmp_out, replay_ok
        return cleaned_hive, tmp_in, tmp_out
    except BaseException:
        shutil.rmtree(tmp_in, ignore_errors=True)
        if tmp_out is not None:
            shutil.rmtree(tmp_out, ignore_errors=True)
        raise
