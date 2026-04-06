"""
sift_mcp.runners
~~~~~~~~~~~~~~~~

Subprocess execution wrappers for SIFT Workstation forensic tools.

Every runner inherits from :class:`~sift_mcp.runners.base.SafeRunner`, which
enforces:

* ``shell=False`` on all subprocess calls (no injection possible)
* A deny-list of destructive binaries (``rm``, ``dd``, ``wget``, etc.)
* A deny-list of path prefixes that must never be touched (``/mnt/``,
  ``/dev/``, evidence subdirectories)

Exported classes
----------------
SafeRunner
    Base class with the ``run(cmd_parts)`` method.  Import this to write a
    custom runner for a tool not covered below.

RunResult
    Structured result dataclass returned by every ``run()`` call.

VolatilityRunner
    Wraps ``python3 /opt/volatility3-2.20.0/vol.py``.

SleuthKitRunner
    Wraps ``fls``, ``icat``, ``mmls``, ``istat``, ``ewfverify``,
    ``ewfinfo`` (all in PATH).

EZToolsRunner
    Wraps ``dotnet /opt/zimmermantools/<Tool>.dll`` for MFTECmd, PECmd,
    AmcacheParser, EvtxECmd, RECmd, AppCompatCacheParser.

PlasoRunner
    Wraps ``log2timeline.py``, ``psort.py``, ``pinfo.py`` (all in PATH).

YaraRunner
    Wraps ``yara`` (in PATH).
"""

from sift_mcp.runners.base import RunResult, SafeRunner
from sift_mcp.runners.eztools import EZToolsRunner
from sift_mcp.runners.plaso import PlasoRunner
from sift_mcp.runners.sleuthkit import SleuthKitRunner
from sift_mcp.runners.volatility import VolatilityRunner
from sift_mcp.runners.yara_runner import YaraRunner

__all__ = [
    "RunResult",
    "SafeRunner",
    "VolatilityRunner",
    "SleuthKitRunner",
    "EZToolsRunner",
    "PlasoRunner",
    "YaraRunner",
]
