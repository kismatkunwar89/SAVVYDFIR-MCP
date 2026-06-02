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

# Eric Zimmerman's Registry Log Analyzer, shipped with the EZ Tools suite.
_RLA_BIN = Path("/opt/zimmermantools/rla.dll")


def replay_hive_with_rla(hive_path: Path, label: str) -> tuple[Path, Path, Path]:
    """Copy one hive plus its transaction logs to temp dirs and replay via rla.

    Parameters
    ----------
    hive_path:
        Path to the registry hive on the (read-only) evidence mount.
    label:
        Short slug used in the temp-directory prefix for debuggability.

    Returns
    -------
    tuple(cleaned_hive_path, tmp_in, tmp_out)
        ``cleaned_hive_path`` is the replayed hive (or the original copy when
        the hive was already clean / rla produced no output). The caller MUST
        remove ``tmp_in`` and ``tmp_out`` in a ``finally`` block.
    """
    tmp_in = Path(tempfile.mkdtemp(prefix=f"savvydfir_rla_in_{label}_"))
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

    subprocess.run(
        ["/usr/bin/dotnet", str(_RLA_BIN), "-d", str(tmp_in), "--out", str(tmp_out)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )

    # rla writes the cleaned hive with a path-flattened name; glob for it.
    cleaned_files = [candidate for candidate in tmp_out.iterdir() if candidate.is_file()]
    cleaned_hive = cleaned_files[0] if cleaned_files else (tmp_in / hive_path.name)
    return cleaned_hive, tmp_in, tmp_out
