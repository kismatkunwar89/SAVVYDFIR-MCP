"""
sift_mcp.runners.eztools
~~~~~~~~~~~~~~~~~~~~~~~~~

EZToolsRunner — subprocess wrapper for **Eric Zimmerman's Tools** on SIFT
Workstation.

Tool paths (from Protocol SIFT's global/CLAUDE.md):
    All EZ Tools are invoked via ``dotnet /opt/zimmermantools/<Tool>.dll``.
    Sub-directory exceptions:
        EvtxECmd  →  /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll
        RECmd     →  /opt/zimmermantools/RECmd/RECmd.dll

EZ Tools write their output to a directory specified by ``--csv <dir>``
together with ``--csvf <filename>``.  The caller is responsible for reading
the resulting CSV file; this runner only handles process execution.

Typical usage
-------------
::

    from sift_mcp.runners.eztools import EZToolsRunner

    runner = EZToolsRunner()

    # Extract MFT timeline
    result = runner.run_mftecmd(
        mft_path="/cases/SRL-2018/evidence/mnt/C/$MFT",
        csv_dir="/cases/SRL-2018/analysis/mft",
        csv_filename="mft_timeline.csv",
    )

    # Extract Prefetch entries
    result = runner.run_pecmd(
        prefetch_dir_or_file="/cases/SRL-2018/evidence/mnt/C/Windows/Prefetch",
        csv_dir="/cases/SRL-2018/analysis/prefetch",
        csv_filename="prefetch.csv",
    )
"""

from __future__ import annotations

from typing import List, Optional

from sift_mcp.runners.base import RunResult, SafeRunner


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Root directory for all EZ Tools DLLs on SIFT Workstation.
TOOLS_DIR = "/opt/zimmermantools"

# SIFT installs EZ Tools as wrapper scripts at /usr/local/bin/
# These are preferred over dotnet invocation
import shutil as _shutil

def _sift_bin(name: str) -> Optional[str]:
    """Return path to SIFT wrapper script if it exists, else None."""
    path = f"/usr/local/bin/{name}"
    return path if _shutil.which(path) or __import__('os').path.exists(path) else None

#: Default timeout for EZ Tools.  .NET startup adds latency; large MFT or
#: EVTX sets can take several minutes.
DEFAULT_TIMEOUT = 300  # seconds


# ---------------------------------------------------------------------------
# DLL path helpers
# ---------------------------------------------------------------------------

def _dll(name: str, subdir: Optional[str] = None) -> str:
    """Return the full path to an EZ Tools DLL.

    Parameters
    ----------
    name:
        DLL filename including extension, e.g. ``"MFTECmd.dll"``.
    subdir:
        Optional subdirectory inside ``TOOLS_DIR``, e.g. ``"EvtxeCmd"``
        for ``/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll``.
    """
    if subdir:
        return f"{TOOLS_DIR}/{subdir}/{name}"
    return f"{TOOLS_DIR}/{name}"


# ---------------------------------------------------------------------------
# EZToolsRunner
# ---------------------------------------------------------------------------


class EZToolsRunner(SafeRunner):
    """Subprocess wrapper for Eric Zimmerman's forensic tools on SIFT Workstation.

    All tools are invoked as::

        dotnet /opt/zimmermantools/<Tool>.dll [arguments]

    CSV output files
    ----------------
    Every method accepts ``csv_dir`` (output directory) and ``csv_filename``
    (output file name within that directory).  These correspond to the
    ``--csv`` and ``--csvf`` flags common to all EZ Tools.

    The caller is responsible for:
    1. Ensuring ``csv_dir`` exists before calling the runner.
    2. Reading and parsing the CSV file after a successful run.

    Encoding note
    -------------
    EZ Tools CSV files may contain a UTF-8 BOM.  Open them with
    ``encoding="utf-8-sig"`` or use ``csv.DictReader`` which handles this
    automatically when the file is opened with that encoding.

    EvtxECmd and RECmd subdirectories
    ----------------------------------
    These tools are installed in subdirectories of ``TOOLS_DIR``:

    * ``EvtxECmd`` → ``/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll``
    * ``RECmd``    → ``/opt/zimmermantools/RECmd/RECmd.dll``
    """

    TOOLS_DIR: str = TOOLS_DIR

    # ------------------------------------------------------------------
    # MFTECmd — Master File Table parser
    # ------------------------------------------------------------------

    def run_mftecmd(
        self,
        mft_path: str,
        csv_dir: str,
        csv_filename: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Parse the NTFS Master File Table with MFTECmd.

        Produces a CSV timeline of all MFT entries including standard
        information and filename attribute timestamps (useful for
        timestomping detection).

        Parameters
        ----------
        mft_path:
            Absolute path to the ``$MFT`` file extracted from the evidence
            image (e.g. ``/cases/SRL-2018/evidence/mnt/C/$MFT``).
        csv_dir:
            Directory where the output CSV will be written.  Must exist.
        csv_filename:
            Name of the output CSV file (e.g. ``"mft_timeline.csv"``).

        Returns
        -------
        RunResult
            Successful run produces a CSV at ``{csv_dir}/{csv_filename}``.
            ``stdout`` contains the MFTECmd progress/summary output.
        """
        _bin = _sift_bin("MFTECmd")
        cmd: List[str] = (
            [_bin] if _bin else ["dotnet", _dll("MFTECmd.dll")]
        ) + ["-f", mft_path, "--csv", csv_dir, "--csvf", csv_filename]
        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # PECmd — Prefetch parser
    # ------------------------------------------------------------------

    def run_pecmd(
        self,
        prefetch_dir_or_file: str,
        csv_dir: str,
        csv_filename: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Parse Windows Prefetch files with PECmd.

        Extracts execution timestamps, run counts, and referenced file/
        directory paths from ``.pf`` files.

        Parameters
        ----------
        prefetch_dir_or_file:
            Path to a single ``.pf`` file **or** the Prefetch directory
            (e.g. ``/cases/SRL-2018/evidence/mnt/C/Windows/Prefetch``).
            When a directory is given, all ``.pf`` files are processed.
        csv_dir:
            Directory where the output CSV will be written.
        csv_filename:
            Name of the output CSV file (e.g. ``"prefetch.csv"``).

        Returns
        -------
        RunResult
            ``stdout`` contains a per-file summary; the full data is in the
            CSV.
        """
        cmd: List[str] = [
            *([_sift_bin("PECmd")] if _sift_bin("PECmd") else ["dotnet", _dll("PECmd.dll")]),
            "-d", prefetch_dir_or_file,
            "--csv", csv_dir,
            "--csvf", csv_filename,
        ]
        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # AmcacheParser — Amcache.hve parser
    # ------------------------------------------------------------------

    def run_amcacheparser(
        self,
        hive_path: str,
        csv_dir: str,
        csv_filename: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Parse the Amcache.hve registry hive with AmcacheParser.

        Extracts SHA-1 hashes and metadata for executables that have been
        run on the system.  Useful for identifying malware by hash even
        after the binary has been deleted.

        Parameters
        ----------
        hive_path:
            Absolute path to the ``Amcache.hve`` file (typically at
            ``C:\\Windows\\appcompat\\Programs\\Amcache.hve`` in the mounted
            evidence image).
        csv_dir:
            Directory where the output CSV will be written.
        csv_filename:
            Name of the output CSV file (e.g. ``"amcache.csv"``).

        Returns
        -------
        RunResult
            ``stdout`` shows the number of entries parsed.  The full data is
            in the CSV.
        """
        cmd: List[str] = [
            *([_sift_bin("AmcacheParser")] if _sift_bin("AmcacheParser") else ["dotnet", _dll("AmcacheParser.dll")]),
            "-f", hive_path,
            "--csv", csv_dir,
            "--csvf", csv_filename,
        ]
        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # EvtxECmd — Windows Event Log parser
    # ------------------------------------------------------------------

    def run_evtxecmd(
        self,
        evtx_dir: str,
        csv_dir: str,
        csv_filename: str,
        maps_dir: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Parse Windows EVTX event log files with EvtxECmd.

        Processes all ``.evtx`` files in *evtx_dir* and writes a unified
        CSV timeline.  Optionally applies Eric Zimmerman's Maps for
        human-readable event descriptions.

        Parameters
        ----------
        evtx_dir:
            Directory containing ``.evtx`` files (e.g.
            ``/cases/SRL-2018/evidence/mnt/C/Windows/System32/winevt/Logs``).
        csv_dir:
            Directory where the output CSV will be written.
        csv_filename:
            Name of the output CSV file (e.g. ``"evtx_timeline.csv"``).
        maps_dir:
            Optional path to the EvtxECmd Maps directory.  When ``None``,
            EvtxECmd uses built-in descriptions.  Pass the path to a local
            copy of the Maps repo for richer descriptions.

        Returns
        -------
        RunResult
            ``stdout`` shows per-file parsing progress.

        Note
        ----
        EvtxECmd is in a subdirectory:
        ``/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll``
        """
        cmd: List[str] = [
            *([_sift_bin("EvtxECmd")] if _sift_bin("EvtxECmd") else ["dotnet", _dll("EvtxECmd.dll", subdir="EvtxeCmd")]),
            "-d", evtx_dir,
            "--csv", csv_dir,
            "--csvf", csv_filename,
        ]
        if maps_dir is not None:
            cmd.extend(["--maps", maps_dir])

        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # RECmd — Registry hive parser
    # ------------------------------------------------------------------

    def run_recmd(
        self,
        hive_dir: str,
        csv_dir: str,
        csv_filename: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Parse registry hives with RECmd.

        Processes all registry hive files in *hive_dir* using RECmd's
        batch-processing mode.  Extracts keys, values, and timestamps.

        Parameters
        ----------
        hive_dir:
            Directory containing registry hive files (SYSTEM, SOFTWARE,
            NTUSER.DAT, etc.).
        csv_dir:
            Directory where the output CSV will be written.
        csv_filename:
            Name of the output CSV file (e.g. ``"registry.csv"``).

        Returns
        -------
        RunResult
            ``stdout`` shows the number of hives and keys processed.

        Note
        ----
        RECmd is in a subdirectory:
        ``/opt/zimmermantools/RECmd/RECmd.dll``
        """
        cmd: List[str] = [
            *([_sift_bin("RECmd")] if _sift_bin("RECmd") else ["dotnet", _dll("RECmd.dll", subdir="RECmd")]),
            "-d", hive_dir,
            "--csv", csv_dir,
            "--csvf", csv_filename,
        ]
        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # AppCompatCacheParser — Shimcache / AppCompatCache parser
    # ------------------------------------------------------------------

    def run_appcompatcacheparser(
        self,
        system_hive: str,
        csv_dir: str,
        csv_filename: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Parse the Shimcache (AppCompatCache) from the SYSTEM hive.

        The Shimcache records executable metadata (path, last modified time,
        execution flag) for programs that have been present on the filesystem,
        regardless of whether they were actually executed.

        Parameters
        ----------
        system_hive:
            Absolute path to the SYSTEM registry hive extracted from the
            evidence image (e.g.
            ``/cases/SRL-2018/evidence/mnt/C/Windows/System32/config/SYSTEM``).
        csv_dir:
            Directory where the output CSV will be written.
        csv_filename:
            Name of the output CSV file (e.g. ``"shimcache.csv"``).

        Returns
        -------
        RunResult
            ``stdout`` shows the number of cache entries parsed.  The full
            dataset is in the CSV, with columns for executable path,
            last modified time (from the SYSTEM hive), and the execution
            flag (Windows XP / early Vista only).
        """
        cmd: List[str] = [
            *([_sift_bin("AppCompatCacheParser")] if _sift_bin("AppCompatCacheParser") else ["dotnet", _dll("AppCompatCacheParser.dll")]),
            "-f", system_hive,
            "--csv", csv_dir,
            "--csvf", csv_filename,
        ]
        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # Error classification
    # ------------------------------------------------------------------

    def classify_error(self, result: RunResult) -> str:
        """Classify a failed ``RunResult`` for the self-correction loop.

        Returns
        -------
        str
            One of:

            * ``"dotnet_not_found"`` — .NET runtime not installed.
            * ``"dll_not_found"`` — EZ Tool DLL not present at expected path.
            * ``"input_not_found"`` — Evidence file or directory not found.
            * ``"output_dir_missing"`` — CSV output directory does not exist.
            * ``"timeout"`` — process exceeded the timeout.
            * ``"unknown"`` — inspect ``result.stderr`` directly.
        """
        if result.timed_out:
            return "timeout"
        if result.returncode == 127:
            return "dotnet_not_found"
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        combined = stderr + stdout
        if "could not find" in combined and ".dll" in combined:
            return "dll_not_found"
        if (
            "no such file" in combined
            or "file not found" in combined
            or "does not exist" in combined
        ):
            return "input_not_found"
        if "output directory" in combined or "csv directory" in combined:
            return "output_dir_missing"
        return "unknown"
