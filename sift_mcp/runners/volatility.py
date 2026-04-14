"""
sift_mcp.runners.volatility
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

VolatilityRunner — subprocess wrapper for **Volatility 3** on SIFT Workstation.

Binary path (from Protocol SIFT's global/CLAUDE.md):
    python3 /opt/volatility3-2.20.0/vol.py

All plugins are invoked with ``-r json`` so output is machine-readable.
Callers receive a ``RunResult``; the tool layer is responsible for parsing
``RunResult.stdout`` as JSON and building ``Finding`` objects.

Typical usage
-------------
::

    from sift_mcp.runners.volatility import VolatilityRunner

    runner = VolatilityRunner()
    result = runner.pslist("/cases/SRL-2018/evidence/wkstn-01.raw")
    if result.ok:
        import json
        rows = json.loads(result.stdout)
"""

from __future__ import annotations

from typing import List, Optional

from sift_mcp.runners.base import RunResult, SafeRunner


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Invocation prefix exactly as specified in Protocol SIFT's CLAUDE.md.
# Auto-detect Volatility 3 path — try SIFT location first, fallback to common paths
import shutil as _shutil
_vol_candidates = [
    "/usr/local/bin/vol",
    "/usr/local/bin/vol3",
    "/usr/bin/vol",
    "/usr/bin/vol3",
]
VOL_PATH = next(
    (p for p in _vol_candidates if _shutil.which(p) or __import__('os').path.exists(p)),
    "/usr/local/bin/vol"  # default
)

#: Default timeout for Volatility 3 plugins.  Memory forensics on a 4 GB
#: dump can take several minutes; malfind on a large dump can take longer.
DEFAULT_TIMEOUT = 300  # seconds


# ---------------------------------------------------------------------------
# VolatilityRunner
# ---------------------------------------------------------------------------


class VolatilityRunner(SafeRunner):
    """Subprocess wrapper for Volatility 3 on SIFT Workstation.

    All methods build a command list of the form::

        ["python3", "/opt/volatility3-2.20.0/vol.py",
         "-f", <dump_path>,
         "-r", "json",       # request JSON renderer
         <plugin>,
         [--<flag> <value> ...]]

    and delegate to ``self.run()`` (inherited from ``SafeRunner``).

    Error classification
    --------------------
    ``classify_error()`` inspects ``RunResult.stderr`` and returns one of:

    * ``"missing_symbols"`` — ISF symbol tables not found (common with
      unfamiliar Windows builds); agent should try a different profile source.
    * ``"unsupported_plugin"`` — plugin name typo or version mismatch.
    * ``"corrupted_dump"`` — Volatility cannot validate the dump header.
    * ``"unknown"`` — anything else; inspect stderr manually.
    """

    VOL_PATH: str = VOL_PATH

    # ------------------------------------------------------------------
    # Generic plugin runner
    # ------------------------------------------------------------------

    def run_plugin(
        self,
        dump_path: str,
        plugin: str,
        extra_args: Optional[List[str]] = None,
        output_format: str = "json",
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Run any Volatility 3 plugin against *dump_path*.

        Parameters
        ----------
        dump_path:
            Absolute path to the raw memory dump (e.g. ``.raw``, ``.mem``,
            ``.lime``, ``.vmem``).
        plugin:
            Fully qualified Volatility 3 plugin name, e.g.
            ``"windows.pslist"`` or ``"windows.malfind"``.
        extra_args:
            Optional list of additional CLI tokens inserted **after** the
            plugin name, e.g. ``["--pid", "1234"]``.  Pass ``None`` or
            ``[]`` when no extra arguments are needed.
        output_format:
            Volatility output renderer to request via ``-r``.
            Defaults to ``"json"``; set to ``"text"`` for plugins that do
            not support the JSON renderer.
        timeout:
            Maximum seconds to wait before killing the process.

        Returns
        -------
        RunResult
            ``stdout`` contains the raw Volatility output (JSON when
            ``output_format="json"``).  ``stderr`` contains any warning or
            error messages emitted by Volatility.
        """
        # If VOL_PATH is a binary (not a .py script), invoke directly
        # vol3/vol on SIFT is a standalone binary, not a Python script
        if self.VOL_PATH.endswith(".py"):
            cmd: List[str] = ["python3", self.VOL_PATH, "-f", dump_path, "-r", output_format, plugin]
        else:
            cmd: List[str] = [self.VOL_PATH, "-f", dump_path, "-r", output_format, plugin]
        if extra_args:
            cmd.extend(extra_args)

        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    # ------------------------------------------------------------------
    # Convenience wrappers — one per commonly used plugin
    # ------------------------------------------------------------------

    def pslist(
        self,
        dump_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """List running processes (``windows.pslist``).

        Emits the PEB process list.  Compare against ``psscan()`` to detect
        DKOM-hidden processes.

        Returns
        -------
        RunResult
            JSON array of process objects (PID, PPID, name, create time, etc.)
        """
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.pslist",
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    def psscan(
        self,
        dump_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Scan physical memory for EPROCESS structures (``windows.psscan``).

        Unlike ``pslist()``, this scans the raw memory pages rather than
        walking the linked list, so it surfaces unlinked (DKOM-hidden)
        processes.

        Returns
        -------
        RunResult
            JSON array of EPROCESS records found in the memory image.
        """
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.psscan",
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    def netscan(
        self,
        dump_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Scan for network artifacts (``windows.netscan``).

        Finds TCP/UDP endpoints and connections in the memory image,
        including closed/unlinked socket structures that ``netstat`` would
        not show.

        Returns
        -------
        RunResult
            JSON array of socket/connection objects (local addr, remote addr,
            state, owner PID, create time).
        """
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.netscan",
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    def malfind(
        self,
        dump_path: str,
        pid: Optional[int] = None,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Detect injected code in process VAD regions (``windows.malfind``).

        Flags memory regions that are executable, writable, and anonymous
        (no backing file on disk) — a strong indicator of process injection
        or shellcode.

        Parameters
        ----------
        dump_path:
            Absolute path to the raw memory image.
        pid:
            When given, restrict the scan to a single process by PID.
            When ``None``, all processes are scanned.

        Returns
        -------
        RunResult
            JSON array of suspicious VAD regions with process context,
            virtual address, protection flags, and a hex dump of the first
            64 bytes.
        """
        extra: List[str] = []
        if pid is not None:
            extra = ["--pid", str(pid)]
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.malfind",
            extra_args=extra or None,
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    def dlllist(
        self,
        dump_path: str,
        pid: int,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """List DLLs loaded into a specific process (``windows.dlllist``).

        Parameters
        ----------
        dump_path:
            Absolute path to the raw memory image.
        pid:
            PID of the target process.  Use ``pslist()`` or ``psscan()``
            first to obtain a valid PID.

        Returns
        -------
        RunResult
            JSON array of DLL entries (base address, size, name, full path).
        """
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.dlllist",
            extra_args=["--pid", str(pid)],
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    def cmdline(
        self,
        dump_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Extract command-line arguments for all processes (``windows.cmdline``).

        Reads the ``PEB.ProcessParameters.CommandLine`` field from each
        process, which can reveal attacker-supplied arguments even for
        short-lived processes.

        Returns
        -------
        RunResult
            JSON array of ``{PID, process_name, args}`` objects.
        """
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.cmdline",
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    def windows_info(
        self,
        dump_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Detect the Windows version / ISF profile (``windows.info``).

        This should usually be the first plugin called on a new dump to
        confirm Volatility can parse it and to identify the OS build.

        Returns
        -------
        RunResult
            JSON object with kernel version, build number, system time,
            and processor architecture.
        """
        return self.run_plugin(
            dump_path=dump_path,
            plugin="windows.info",
            output_format="json",
            tool_name=tool_name,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Error classification
    # ------------------------------------------------------------------

    def classify_error(self, result: RunResult) -> str:
        """Classify a failed ``RunResult`` for the self-correction loop.

        Parameters
        ----------
        result:
            A ``RunResult`` where ``result.ok`` is ``False``.

        Returns
        -------
        str
            One of:

            * ``"missing_symbols"`` — ISF/symbol table not found.
            * ``"unsupported_plugin"`` — plugin name unknown to this build.
            * ``"corrupted_dump"`` — Volatility cannot validate the image.
            * ``"tool_not_found"`` — ``python3`` or ``vol.py`` is missing.
            * ``"timeout"`` — process exceeded the timeout.
            * ``"unknown"`` — inspect ``result.stderr`` directly.
        """
        if result.timed_out:
            return "timeout"
        if result.returncode == 127:
            return "tool_not_found"
        stderr = result.stderr.lower()
        if "symbol" in stderr or "isf" in stderr or "table not found" in stderr:
            return "missing_symbols"
        if "unsupported" in stderr or "no plugin" in stderr:
            return "unsupported_plugin"
        if "unable to validate" in stderr or "invalid" in stderr:
            return "corrupted_dump"
        return "unknown"
