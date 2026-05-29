"""
sift_mcp.runners.sleuthkit
~~~~~~~~~~~~~~~~~~~~~~~~~~~

SleuthKitRunner — subprocess wrapper for **The Sleuth Kit** on SIFT Workstation.

Tool paths (from Protocol SIFT's global/CLAUDE.md):
    All Sleuth Kit binaries are in ``$PATH`` on SIFT Workstation:
    ``fls``, ``icat``, ``mmls``, ``istat``, ``ewfverify``, ``ewfinfo``

Typical usage
-------------
::

    from sift_mcp.runners.sleuthkit import SleuthKitRunner

    runner = SleuthKitRunner()

    # 1. Verify image integrity
    verify = runner.ewfverify("/cases/SRL-2018/evidence/disk.E01")

    # 2. Find partition layout
    parts = runner.mmls("/cases/SRL-2018/evidence/disk.E01")

    # 3. List files (pass sector offset from mmls output)
    files = runner.fls("/cases/SRL-2018/evidence/disk.E01",
                       offset=2048, recursive=True, deleted_only=True)

    # 4. Extract a file by inode
    result = runner.icat("/cases/SRL-2018/evidence/disk.E01",
                         inode="12345-128-1", offset=2048,
                         output_path="/cases/SRL-2018/analysis/extracted.exe")
"""

from __future__ import annotations

from typing import List, Optional, Union

from sift_mcp.runners.base import RunResult, SafeRunner


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 120  # seconds — disk tools are usually fast


# ---------------------------------------------------------------------------
# SleuthKitRunner
# ---------------------------------------------------------------------------


class SleuthKitRunner(SafeRunner):
    """Subprocess wrapper for The Sleuth Kit (TSK) on SIFT Workstation.

    All TSK binaries (``fls``, ``icat``, ``mmls``, ``istat``, ``ewfverify``,
    ``ewfinfo``) are expected to be on ``$PATH``.  SIFT Workstation installs
    them via the ``sleuthkit`` package.

    Partition offsets
    -----------------
    TSK tools use **sector offsets** for the ``-o`` flag (not byte offsets).
    Call ``mmls()`` first to get the partition table, then pass the sector
    offset from the NTFS / FAT partition row to ``fls()`` and ``icat()``.

    EnCase / EWF images
    -------------------
    ``ewfverify`` and ``ewfinfo`` are from the ``libewf-tools`` package,
    also on ``$PATH`` on SIFT Workstation.  Pass the ``.E01`` file directly.
    For split EWF segments, pass only the first segment (``disk.E01``);
    TSK resolves the rest automatically.
    """

    # fls / mmls / istat all emit table data on stdout that callers parse
    # line-by-line (sift_mcp/tools/disk.py:3214, sift_mcp/server.py:6941, etc).
    # See SafeRunner.DROP_CAPTURED_OUTPUT_AFTER_AUDIT.
    DROP_CAPTURED_OUTPUT_AFTER_AUDIT: bool = False

    # ------------------------------------------------------------------
    # EWF (EnCase) image tools
    # ------------------------------------------------------------------

    def ewfverify(
        self,
        image_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Verify the integrity of an EnCase / EWF image (``ewfverify``).

        Computes and compares the stored MD5/SHA1 checksums against the
        actual data in the image segments.  This should always be the first
        step in evidence handling to confirm chain-of-custody.

        Parameters
        ----------
        image_path:
            Path to the ``.E01`` image (first segment for split images).

        Returns
        -------
        RunResult
            ``stdout`` contains the verification report.
            A non-zero ``returncode`` indicates checksum mismatch (evidence
            may have been modified or corrupted during transport).
        """
        cmd: List[str] = ["ewfverify", image_path]
        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    def ewfinfo(
        self,
        image_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Display metadata from an EnCase / EWF image header (``ewfinfo``).

        Reports acquisition date/time, examiner name, case description,
        MD5/SHA1 hashes, and media information stored in the EWF metadata.

        Parameters
        ----------
        image_path:
            Path to the ``.E01`` image.

        Returns
        -------
        RunResult
            ``stdout`` contains key-value metadata from the EWF header.
        """
        cmd: List[str] = ["ewfinfo", image_path]
        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    # ------------------------------------------------------------------
    # Partition tools
    # ------------------------------------------------------------------

    def mmls(
        self,
        device_path: str,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Display the partition table of a disk image (``mmls``).

        Works with MBR and GPT partition tables.  The output includes one
        row per partition with slot number, start sector, end sector, length,
        and filesystem type description.

        Parameters
        ----------
        device_path:
            Path to the raw disk image (``.dd``, ``.raw``) or EWF image
            (``.E01``).

        Returns
        -------
        RunResult
            ``stdout`` is human-readable text in the standard TSK mmls
            format.  Parse the "Start" column for the sector offset to pass
            to ``fls()`` and ``icat()``.

        Example output line::

            000:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
            001:  -----   0000000000   0000000000   0000000001   Unallocated
            002:  000     0000002048   0000206847   0000204800   NTFS (0x07)
        """
        cmd: List[str] = ["mmls", device_path]
        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    # ------------------------------------------------------------------
    # File system tools
    # ------------------------------------------------------------------

    def fls(
        self,
        device_path: str,
        inode: Optional[Union[str, int]] = None,
        recursive: bool = False,
        deleted_only: bool = False,
        offset: Optional[int] = None,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """List file and directory names in a disk image (``fls``).

        Parameters
        ----------
        device_path:
            Path to the disk image or EWF file.
        inode:
            Starting inode number.  When ``None``, listing starts from the
            root directory.  Pass a directory inode to list a subtree.
        recursive:
            When ``True``, add ``-r`` to recurse into subdirectories.
        deleted_only:
            When ``True``, add ``-d`` to show only deleted entries.
        offset:
            Sector offset of the target partition (from ``mmls()`` output).
            Required when working with a full-disk image that contains
            multiple partitions.  When ``None``, TSK assumes a single-
            partition image.

        Returns
        -------
        RunResult
            ``stdout`` contains lines in the format::

                r/r   12345-128-1: Windows/System32/cmd.exe
                r/r * 12346-128-1: temp/deleted_file.exe  (deleted)
                d/d   12347-128-1: Windows/System32/

            The ``*`` flag indicates a deleted entry.
        """
        cmd: List[str] = ["fls"]

        if recursive:
            cmd.append("-r")
        if deleted_only:
            cmd.append("-d")
        if offset is not None:
            cmd.extend(["-o", str(offset)])

        cmd.append(device_path)

        if inode is not None:
            cmd.append(str(inode))

        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    def icat(
        self,
        device_path: str,
        inode: Union[str, int],
        offset: Optional[int] = None,
        output_path: Optional[str] = None,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Extract the contents of a file by inode number (``icat``).

        Reads the file data directly from the disk image bypassing the
        filesystem driver, which recovers files even when their directory
        entry has been deleted.

        Parameters
        ----------
        device_path:
            Path to the disk image or EWF file.
        inode:
            Inode number of the target file (e.g. ``"12345-128-1"`` or
            ``12345``).  Obtain from ``fls()`` output.
        offset:
            Sector offset of the target partition (from ``mmls()``).
        output_path:
            When provided, the extracted bytes are written to this path
            using shell redirection emulated via ``stdout`` capture and a
            subsequent file write.  When ``None``, raw bytes appear in
            ``RunResult.stdout``.

            **Note:** This runner always captures stdout as text with UTF-8
            replacement.  For binary files (executables, archives) set
            ``output_path`` and the caller should handle the raw bytes from
            ``proc.stdout`` separately, or use ``subprocess`` directly.

        Returns
        -------
        RunResult
            When *output_path* is ``None``, ``stdout`` contains the raw file
            content.  When *output_path* is set, the content is written to
            disk and ``stdout`` is empty.

        Raises
        ------
        OSError
            If writing to *output_path* fails (permission denied, disk full).
        """
        cmd: List[str] = ["icat"]

        if offset is not None:
            cmd.extend(["-o", str(offset)])

        cmd.append(device_path)
        cmd.append(str(inode))

        if output_path:
            # Run icat, capture stdout, then write to output_path
            result = self.run(cmd, timeout=timeout, tool_name=tool_name)
            if result.ok and result.stdout:
                Path_obj = __import__("pathlib").Path
                Path_obj(output_path).write_text(result.stdout, encoding="utf-8")
            return result

        return self.run(cmd, timeout=timeout, tool_name=tool_name)

    def istat(
        self,
        device_path: str,
        inode: Union[str, int],
        offset: Optional[int] = None,
        tool_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RunResult:
        """Display metadata for a specific inode (``istat``).

        Returns MAC times (modified / accessed / changed), file size,
        allocation status, and data unit addresses.

        Parameters
        ----------
        device_path:
            Path to the disk image or EWF file.
        inode:
            Inode number (e.g. ``"12345-128-1"``).
        offset:
            Sector offset of the target partition (from ``mmls()``).

        Returns
        -------
        RunResult
            ``stdout`` contains inode metadata in TSK's human-readable format.
        """
        cmd: List[str] = ["istat"]

        if offset is not None:
            cmd.extend(["-o", str(offset)])

        cmd.append(device_path)
        cmd.append(str(inode))

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

            * ``"image_not_found"`` — the image file does not exist.
            * ``"invalid_image"`` — TSK cannot open or parse the image.
            * ``"inode_not_found"`` — inode does not exist in this filesystem.
            * ``"tool_not_found"`` — binary missing from PATH.
            * ``"timeout"`` — process exceeded the timeout.
            * ``"unknown"`` — inspect ``result.stderr`` directly.
        """
        if result.timed_out:
            return "timeout"
        if result.returncode == 127:
            return "tool_not_found"
        stderr = result.stderr.lower()
        if "no such file" in stderr or "cannot open" in stderr:
            return "image_not_found"
        if "invalid image" in stderr or "error opening" in stderr:
            return "invalid_image"
        if "inode" in stderr and ("not found" in stderr or "invalid" in stderr):
            return "inode_not_found"
        return "unknown"
