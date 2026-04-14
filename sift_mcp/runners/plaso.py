"""
sift_mcp.runners.plaso
~~~~~~~~~~~~~~~~~~~~~~~

PlasoRunner — subprocess wrapper for **Plaso** (log2timeline / psort / pinfo)
on SIFT Workstation.

Tool paths (from Protocol SIFT's global/CLAUDE.md):
    Plaso is installed via the GIFT PPA; all binaries are in ``$PATH``:
    ``log2timeline.py``, ``psort.py``, ``pinfo.py``

Performance notes
-----------------
``log2timeline.py`` is the most time-intensive step in any DFIR workflow.
Processing a 100 GB disk image can take 30–120 minutes.  The default timeout
for ``log2timeline()`` is set to **7 200 seconds (2 hours)**.  For demo/test
purposes, pre-generate the ``.plaso`` storage file before the MCP session.

``psort.py`` is used to extract and filter events from the ``.plaso`` storage
file.  It is comparatively fast (seconds to minutes).

Typical usage
-------------
::

    from sift_mcp.runners.plaso import PlasoRunner

    runner = PlasoRunner()

    # Step 1 — build the super timeline (slow — pre-generate for demos)
    result = runner.log2timeline(
        source_path="/cases/SRL-2018/evidence/disk.E01",
        storage_file="/cases/SRL-2018/analysis/timeline.plaso",
    )

    # Step 2 — extract a time-sliced subset
    result = runner.psort(
        storage_file="/cases/SRL-2018/analysis/timeline.plaso",
        output_file="/cases/SRL-2018/analysis/events_may2026.csv",
        time_slice_start="2026-05-01T00:00:00",
        time_slice_end="2026-05-31T23:59:59",
    )

    # Step 3 — inspect storage metadata
    result = runner.pinfo("/cases/SRL-2018/analysis/timeline.plaso")
"""

from __future__ import annotations

from typing import List, Optional

from sift_mcp.runners.base import RunResult, SafeRunner


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Default parsers preset for Windows 10 images.
DEFAULT_PARSERS = "win10"

#: Default hashers for file hash computation during ingestion.
DEFAULT_HASHERS = "md5,sha256"

#: Default timezone for event timestamps.
DEFAULT_TIMEZONE = "UTC"

#: Default output format for psort.
DEFAULT_OUTPUT_FORMAT = "dynamic"

#: Default timeout for log2timeline (slow — up to 2 hours for large images).
LOG2TIMELINE_TIMEOUT = 7_200  # seconds

#: Default timeout for psort / pinfo.
PSORT_TIMEOUT = 600  # seconds


# ---------------------------------------------------------------------------
# PlasoRunner
# ---------------------------------------------------------------------------


class PlasoRunner(SafeRunner):
    """Subprocess wrapper for Plaso (log2timeline + psort + pinfo) on SIFT.

    Plaso is installed via the GIFT PPA on SIFT Workstation.  All three
    binaries are expected to be on ``$PATH``.

    Storage file workflow
    ---------------------
    Plaso operates in two stages:

    1. **Ingest** — ``log2timeline.py`` reads the source evidence (disk image,
       directory tree, or memory dump) and writes a binary ``.plaso`` SQLite
       storage file.  This step is slow.
    2. **Query** — ``psort.py`` reads the ``.plaso`` storage file, applies
       filters, and writes human-readable output (CSV, JSON, etc.).

    The ``.plaso`` file is immutable evidence — ``SafeRunner`` will block
    any attempt to write back to the evidence directory.
    """

    # ------------------------------------------------------------------
    # log2timeline
    # ------------------------------------------------------------------

    def log2timeline(
        self,
        source_path: str,
        storage_file: str,
        parsers: str = DEFAULT_PARSERS,
        hashers: str = DEFAULT_HASHERS,
        timezone: str = DEFAULT_TIMEZONE,
        tool_name: Optional[str] = None,
        timeout: int = LOG2TIMELINE_TIMEOUT,
    ) -> RunResult:
        """Build a Plaso super timeline from *source_path*.

        Invokes ``log2timeline.py`` to process all artefacts in the source
        and write events to a ``.plaso`` storage file.

        Parameters
        ----------
        source_path:
            Path to the evidence source.  Can be a raw/EWF disk image, a
            mounted directory, or a memory dump file.
        storage_file:
            Absolute path where the ``.plaso`` storage file will be written.
            Must be inside the case analysis directory, **not** inside the
            evidence directory.
        parsers:
            Plaso parser preset name (e.g. ``"win10"``, ``"win7"``,
            ``"linux"``) or a comma-separated list of individual parser
            names.  Defaults to ``"win10"``.
        hashers:
            Comma-separated list of hash algorithms to compute for each
            file artifact (e.g. ``"md5,sha256"``).  Set to ``"none"`` to
            disable hashing and speed up processing.
        timezone:
            Timezone for event timestamps in the storage file.
            Defaults to ``"UTC"``; change only if the source system used a
            known non-UTC timezone and your case template specifies it.
        timeout:
            Maximum seconds to wait.  Defaults to 7 200 (2 hours).
            Increase for very large evidence sets.

        Returns
        -------
        RunResult
            ``stdout`` contains log2timeline's progress output.
            On success, the ``.plaso`` file exists at *storage_file*.
            A non-zero ``returncode`` indicates an ingestion error; check
            ``stderr`` for parser-specific failure details.
        """
        cmd: List[str] = [
            "log2timeline.py",
            "--storage-file", storage_file,
            "--parsers", parsers,
            "--hashers", hashers,
            "--timezone", timezone,
            source_path,
        ]
        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    # ------------------------------------------------------------------
    # psort
    # ------------------------------------------------------------------

    def psort(
        self,
        storage_file: str,
        output_file: str,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        time_slice_start: Optional[str] = None,
        time_slice_end: Optional[str] = None,
        filter_expression: Optional[str] = None,
        timezone: str = DEFAULT_TIMEZONE,
        tool_name: Optional[str] = None,
        timeout: int = PSORT_TIMEOUT,
    ) -> RunResult:
        """Extract and filter events from a Plaso storage file with psort.

        Parameters
        ----------
        storage_file:
            Absolute path to the ``.plaso`` file produced by
            ``log2timeline()``.
        output_file:
            Absolute path for the output file (e.g. ``events.csv``).
            The output format determines the file content.
        output_format:
            Plaso output module name.  Common values:
            ``"dynamic"`` (CSV with dynamic columns, default),
            ``"json"``, ``"json_line"``, ``"l2tcsv"`` (legacy CSV).
        time_slice_start:
            ISO-8601 start timestamp for time-range filtering, e.g.
            ``"2026-05-01T00:00:00"``.  When ``None``, no lower bound
            is applied.
        time_slice_end:
            ISO-8601 end timestamp for time-range filtering, e.g.
            ``"2026-05-31T23:59:59"``.  When ``None``, no upper bound
            is applied.
        filter_expression:
            Plaso filter expression string for content-based filtering,
            e.g. ``"message contains 'cmd.exe'"``.  Appended after any
            time-slice filters.  When ``None``, no content filter is
            applied.
        timezone:
            Output timezone for event timestamps.  Defaults to ``"UTC"``.
        timeout:
            Maximum seconds to wait.

        Returns
        -------
        RunResult
            ``stdout`` shows psort's progress and event count.
            The filtered events are written to *output_file*.

        Notes
        -----
        When both *time_slice_start* and *time_slice_end* are provided,
        psort's ``--slice`` mechanism is used for efficient range filtering.
        When only a filter expression is provided, ``--filter`` is used.
        Both can be combined.
        """
        cmd: List[str] = [
            "psort.py",
            "--output-time-zone", timezone,
            "-o", output_format,
            "-w", output_file,
        ]

        # Build date/time range filters
        date_filters: List[str] = []
        if time_slice_start:
            date_filters.append(f"date >= '{time_slice_start}'")
        if time_slice_end:
            date_filters.append(f"date <= '{time_slice_end}'")

        # Combine date filters with any explicit filter expression
        all_filters: List[str] = date_filters[:]
        if filter_expression:
            all_filters.append(filter_expression)

        if all_filters:
            combined = " AND ".join(all_filters)
            cmd.extend(["--filter", combined])

        cmd.append(storage_file)

        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    # ------------------------------------------------------------------
    # pinfo
    # ------------------------------------------------------------------

    def pinfo(
        self,
        storage_file: str,
        tool_name: Optional[str] = None,
        timeout: int = PSORT_TIMEOUT,
    ) -> RunResult:
        """Display metadata about a Plaso storage file (``pinfo.py``).

        Reports the number of events, parsers used, source information,
        Plaso version, and processing statistics stored in the ``.plaso``
        file.  Use this to validate that ``log2timeline()`` completed
        successfully and to confirm which parsers ran.

        Parameters
        ----------
        storage_file:
            Absolute path to the ``.plaso`` file.

        Returns
        -------
        RunResult
            ``stdout`` contains a human-readable summary of the storage
            file contents and processing metadata.
        """
        cmd: List[str] = ["pinfo.py", storage_file]
        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    # ------------------------------------------------------------------
    # Error classification
    # ------------------------------------------------------------------

    def classify_error(self, result: RunResult) -> str:
        """Classify a failed ``RunResult`` for the self-correction loop.

        Returns
        -------
        str
            One of:

            * ``"tool_not_found"`` — Plaso binary missing from PATH.
            * ``"storage_file_missing"`` — ``.plaso`` file not found.
            * ``"source_not_found"`` — evidence source path not found.
            * ``"parser_error"`` — parser-level failure during ingestion.
            * ``"output_error"`` — cannot write output file.
            * ``"timeout"`` — process exceeded the timeout (common for
              large images with ``log2timeline``).
            * ``"unknown"`` — inspect ``result.stderr`` directly.
        """
        if result.timed_out:
            return "timeout"
        if result.returncode == 127:
            return "tool_not_found"
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        combined = stderr + stdout
        if "no such file" in combined or "not found" in combined:
            if ".plaso" in combined:
                return "storage_file_missing"
            return "source_not_found"
        if "parser" in combined and "error" in combined:
            return "parser_error"
        if "unable to write" in combined or "permission denied" in combined:
            return "output_error"
        return "unknown"
