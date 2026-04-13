"""
sift_mcp.runners.yara_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

YaraRunner — subprocess wrapper for **YARA** on SIFT Workstation.

Tool path (from Protocol SIFT's global/CLAUDE.md):
    ``yara`` is in ``$PATH`` on SIFT Workstation.

YARA is used in SAVVYDFIR-MCP for two purposes:

1. **File / directory scanning** — scan extracted files or a mounted
   filesystem for matches against known-malware or IOC rule sets.
2. **Memory dump scanning** — scan a raw memory image (e.g. ``.raw``,
   ``.vmem``) to find patterns that may not appear on disk (in-memory
   shellcode, reflectively loaded DLLs, etc.).

Typical usage
-------------
::

    from sift_mcp.runners.yara_runner import YaraRunner

    runner = YaraRunner()

    # Scan an extracted file
    result = runner.scan_file(
        rules_path="/cases/SRL-2018/iocs/cobalt_strike.yar",
        target_path="/cases/SRL-2018/analysis/extracted/suspicious.exe",
    )

    # Recursively scan a directory
    result = runner.scan_file(
        rules_path="/cases/SRL-2018/iocs/",
        target_path="/cases/SRL-2018/analysis/extracted/",
        recursive=True,
    )

    # Scan a raw memory dump
    result = runner.scan_memory(
        rules_path="/cases/SRL-2018/iocs/cobalt_strike.yar",
        dump_path="/cases/SRL-2018/evidence/wkstn-01.raw",
    )
"""

from __future__ import annotations

from typing import List

from sift_mcp.runners.base import RunResult, SafeRunner


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Default timeout for file/directory scans.
FILE_SCAN_TIMEOUT = 300  # seconds

#: Default timeout for memory dump scans (larger, slower).
MEMORY_SCAN_TIMEOUT = 600  # seconds


# ---------------------------------------------------------------------------
# YaraRunner
# ---------------------------------------------------------------------------


class YaraRunner(SafeRunner):
    """Subprocess wrapper for YARA on SIFT Workstation.

    YARA is expected to be on ``$PATH`` (``yara`` binary).

    Rule sets
    ---------
    *rules_path* can be:

    * A single ``.yar`` / ``.yara`` file.
    * A directory of rule files (YARA will process all ``.yar`` files
      in the directory if the ``-r`` flag is passed to the rule path
      argument — but note this is a YARA-side feature, not TSK-side).
    * A compiled rules file (``.yarc``).

    For a single compiled rule set with multiple signatures, compile them
    first with ``yarac`` and pass the ``.yarc`` file for faster scanning.

    Memory scanning
    ---------------
    Scanning a raw memory dump with YARA is a direct file scan — YARA
    treats the dump as a flat byte stream.  Matches will include virtual
    addresses relative to the dump file offset, not the original virtual
    memory address.  Cross-reference hits with Volatility 3 ``malfind``
    output for confirmation.

    Output format
    -------------
    YARA's default output is one line per match::

        RuleName /path/to/matched/file

    The ``-s`` flag (string matches) can be added via ``extra_args`` to
    show the specific pattern and offset.  See ``scan_file()`` and
    ``scan_memory()`` for details.
    """

    # ------------------------------------------------------------------
    # File / directory scanning
    # ------------------------------------------------------------------

    def scan_file(
        self,
        rules_path: str,
        target_path: str,
        recursive: bool = False,
        timeout: int = FILE_SCAN_TIMEOUT,
    ) -> RunResult:
        """Scan a file or directory for YARA rule matches.

        Parameters
        ----------
        rules_path:
            Absolute path to the YARA rules file (``.yar`` / ``.yara`` /
            ``.yarc``).
        target_path:
            Absolute path to the file or directory to scan.
        recursive:
            When ``True``, add ``-r`` to recursively scan all files in
            *target_path*.  Has no effect when *target_path* is a single
            file.
        timeout:
            Maximum seconds to wait.  Large directories with many files
            may need a higher value.

        Returns
        -------
        RunResult
            ``stdout`` contains one line per match in the format::

                RuleName TargetFilePath

            An empty ``stdout`` with ``returncode == 0`` means no matches
            were found.  A non-zero ``returncode`` indicates a YARA error
            (e.g. invalid rule syntax, unreadable target).

        Notes
        -----
        YARA exits with code 0 if scanning completed (even with zero
        matches).  It exits non-zero on errors.  Use ``result.ok`` to
        check for successful execution, then check ``result.stdout`` for
        actual matches.
        """
        cmd: List[str] = ["yara"]

        if recursive:
            cmd.append("-r")

        cmd.extend([rules_path, target_path])

        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # Memory dump scanning
    # ------------------------------------------------------------------

    def scan_memory(
        self,
        rules_path: str,
        dump_path: str,
        timeout: int = MEMORY_SCAN_TIMEOUT,
    ) -> RunResult:
        """Scan a raw memory dump for YARA rule matches.

        Treats the dump file as a flat byte stream and searches for YARA
        rule patterns.  This surfaces in-memory artifacts such as:

        * Reflectively loaded DLLs (no on-disk copy)
        * Shellcode stubs (Cobalt Strike, Meterpreter beacons)
        * Unpacked malware payloads
        * Credential scraping tool footprints

        Parameters
        ----------
        rules_path:
            Absolute path to the YARA rules file.
        dump_path:
            Absolute path to the raw memory dump (e.g. ``.raw``, ``.mem``,
            ``.lime``, ``.vmem``).  The file is treated as a flat binary
            blob — no memory structure parsing is performed by YARA itself.
            Use Volatility 3 for structured memory analysis; use this method
            for pattern-based hunting.

        Returns
        -------
        RunResult
            ``stdout`` contains one line per match::

                RuleName /path/to/dump.raw

            Because the entire dump is treated as one "file", all matches
            reference the same *dump_path*.  Cross-reference the match
            offset (available with ``-s``) against Volatility output to
            identify the process context.

        Notes
        -----
        Memory dumps can be several gigabytes.  The default timeout is
        600 seconds (10 minutes); increase for very large dumps.
        """
        cmd: List[str] = [
            "yara",
            rules_path,
            dump_path,
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

            * ``"tool_not_found"`` — ``yara`` binary missing from PATH.
            * ``"rule_syntax_error"`` — YARA rules file contains a syntax
              error; the agent should validate rules before re-scanning.
            * ``"target_not_found"`` — target file or directory not found.
            * ``"rules_not_found"`` — rules file not found.
            * ``"permission_denied"`` — OS-level read permission denied
              (distinct from SafeRunner's deny-list PermissionError).
            * ``"timeout"`` — process exceeded the timeout.
            * ``"unknown"`` — inspect ``result.stderr`` directly.
        """
        if result.timed_out:
            return "timeout"
        if result.returncode == 127:
            return "tool_not_found"
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        combined = stderr + stdout
        if "syntax error" in combined or "error compiling" in combined:
            return "rule_syntax_error"
        if "could not open file" in combined or "no such file" in combined:
            # Distinguish rules file from target
            if "rules" in combined or ".yar" in combined or ".yarc" in combined:
                return "rules_not_found"
            return "target_not_found"
        if "permission denied" in combined:
            return "permission_denied"
        return "unknown"
