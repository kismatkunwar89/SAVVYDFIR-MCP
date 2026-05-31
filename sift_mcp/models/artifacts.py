"""
artifacts.py - Typed artifact response models for SAVVYDFIR-MCP.

Every MCP tool that wraps a forensic CLI command returns a list of one of
these models instead of raw stdout.  The models make tool output directly
consumable by the agent, eliminate the need for LLM-based text parsing, and
provide the type safety required to implement the cross-artifact correlation
engine (``compare_disk_and_memory``).

Model families
--------------
Memory artefacts (Volatility 3):
  ProcessRecord, InjectionIndicator, DllRecord, NetworkArtifact

Disk artefacts (EZ Tools / Sleuth Kit / Plaso):
  PrefetchRecord, AmcacheRecord, RegistryRunKey, EventRecord,
  TimelineEvent, DeletedFile, MftEntry

Integrity / profiling:
  IntegrityResult, ProfileResult

Correlation engine outputs:
  DiscrepancyAlert, CorrelationReport
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Memory artefacts
# ---------------------------------------------------------------------------


class ProcessRecord(BaseModel):
    """A single process entry from ``list_processes`` or ``scan_processes``.

    Populated from Volatility 3 ``windows.pslist.PsList`` (for live list) and
    ``windows.psscan.PsScan`` (for pool-tag scan).  Both plugins are run and
    their results are merged by the tool backend.

    Attributes:
        pid:             Process identifier.
        ppid:            Parent process identifier.
        name:            Process image name (e.g. 'svchost.exe').
        path:            Full executable path extracted from PEB ImagePathName
                         (may be None if the process is hiding it).
        command_line:    Command line as stored in PEB ProcessParameters
                         (None if not available or overwritten).
        create_time:     UTC time the process was created.
        exit_time:       UTC time the process exited (None if still running).
        num_threads:     Active thread count at time of acquisition.
        session_id:      Windows session ID (0 = system, ≥1 = user sessions).
        is_wow64:        True if 32-bit process running under WOW64 on 64-bit OS.
        suspicious:      True if the backend heuristics flagged this process.
        suspicion_reason: Free-text explanation of why the process is suspicious.
        offset:          Physical memory offset of the EPROCESS structure
                         (hex string, e.g. '0xffffb8012a3e0080').
        source:          Which Volatility plugin produced this record.
    """

    pid: int = Field(..., ge=0, description="Process identifier.")
    ppid: int = Field(..., ge=0, description="Parent process identifier.")
    name: str = Field(..., description="Process image name, e.g. 'svchost.exe'.")
    path: Optional[str] = Field(
        None, description="Full executable path from PEB ImagePathName."
    )
    command_line: Optional[str] = Field(
        None, description="Command line from PEB ProcessParameters."
    )
    create_time: Optional[datetime] = Field(
        None, description="UTC creation time of the process."
    )
    exit_time: Optional[datetime] = Field(
        None, description="UTC exit time (None if the process is still running)."
    )
    num_threads: Optional[int] = Field(
        None, ge=0, description="Thread count at time of memory acquisition."
    )
    session_id: Optional[int] = Field(
        None, ge=0, description="Windows session ID (0 = System session)."
    )
    is_wow64: bool = Field(
        default=False, description="True if running as 32-bit under WOW64."
    )
    suspicious: bool = Field(
        default=False,
        description="True if backend heuristics flagged this process as suspicious.",
    )
    suspicion_reason: Optional[str] = Field(
        None,
        description="Explanation of what made this process suspicious.",
    )
    offset: str = Field(
        ...,
        description="Physical memory offset of the EPROCESS structure (hex string).",
    )
    source: Literal["pslist", "psscan"] = Field(
        ..., description="Volatility 3 plugin that produced this record."
    )


class InjectionIndicator(BaseModel):
    """A suspicious memory region flagged by injection detection.

    Produced by ``detect_injection`` (``windows.malfind.Malfind``).  Each
    record represents a single VAD region with executable protection bits
    that the Malfind heuristic considers anomalous.

    Attributes:
        pid:                Process identifier.
        process_name:       Name of the owning process.
        vad_start:          Start virtual address of the suspicious VAD region
                            (hex string, e.g. '0x00000193b8c00000').
        vad_end:            End virtual address of the suspicious VAD region.
        protection:         VAD protection string, e.g. 'PAGE_EXECUTE_READWRITE'.
        has_mz_header:      True if an 'MZ' (PE) magic was detected at the start
                            of the region - strong indicator of a reflectively
                            loaded DLL or injected PE.
        dump_path:          Absolute path to the extracted region dump file
                            (None if extraction was not performed).
        suspicious_score:   Heuristic score assigned by the backend
                            (0.0 = benign, 1.0 = highly suspicious).
        disassembly_preview: First few disassembled instructions from the region
                            (None if disassembly was not attempted).
    """

    pid: int = Field(..., ge=0, description="Owning process identifier.")
    process_name: str = Field(..., description="Name of the owning process.")
    vad_start: str = Field(
        ..., description="Start virtual address of the VAD region (hex string)."
    )
    vad_end: str = Field(
        ..., description="End virtual address of the VAD region (hex string)."
    )
    protection: str = Field(
        ..., description="VAD protection string (e.g. 'PAGE_EXECUTE_READWRITE')."
    )
    has_mz_header: bool = Field(
        ...,
        description="True if MZ magic was found at the start of the region.",
    )
    dump_path: Optional[str] = Field(
        None,
        description="Absolute path to the extracted VAD dump file.",
    )
    suspicious_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Heuristic suspicion score (0.0 = benign, 1.0 = highly suspicious).",
    )
    disassembly_preview: Optional[str] = Field(
        None,
        description="First few disassembled instructions from the suspicious region.",
    )


class DllRecord(BaseModel):
    """A DLL loaded into a process's address space.

    Produced by ``list_dlls`` (``windows.dlllist.DllList``).

    Attributes:
        pid:          Owning process identifier.
        process_name: Name of the owning process.
        dll_path:     Full path to the DLL on disk.
        dll_name:     Base filename (e.g. 'kernel32.dll').
        base_address: Load address in the process's virtual address space
                      (hex string, e.g. '0x00007ffa3a200000').
        size:         Size of the mapped DLL in bytes.
        load_time:    UTC time the DLL was loaded (None if not available).
    """

    pid: int = Field(..., ge=0, description="Owning process identifier.")
    process_name: str = Field(..., description="Name of the owning process.")
    dll_path: str = Field(..., description="Full on-disk path of the DLL.")
    dll_name: str = Field(..., description="Base filename of the DLL.")
    base_address: str = Field(
        ...,
        description="Virtual base address at which the DLL is mapped (hex string).",
    )
    size: int = Field(..., ge=0, description="Mapped size of the DLL in bytes.")
    load_time: Optional[datetime] = Field(
        None, description="UTC time the DLL was loaded into the process."
    )


class NetworkArtifact(BaseModel):
    """A network connection or socket extracted from memory.

    Produced by ``scan_network`` (``windows.netstat.NetStat`` /
    ``windows.netscan.NetScan``).

    Attributes:
        protocol:      IP protocol (TCP or UDP).
        local_addr:    Local IP address.
        local_port:    Local port number (0-65535).
        remote_addr:   Remote IP address (None for listening sockets).
        remote_port:   Remote port number (None for listening sockets).
        state:         Connection state string (e.g. 'ESTABLISHED', 'LISTENING').
        pid:           PID of the owning process (0 if unknown).
        owner_process: Name of the owning process (None if unknown).
        offset:        Physical memory offset of the socket structure (hex string).
        create_time:   UTC time the socket was created (None if not available).
    """

    protocol: Literal["TCP", "UDP"] = Field(
        ..., description="IP protocol."
    )
    local_addr: str = Field(..., description="Local IP address.")
    local_port: int = Field(..., ge=0, le=65535, description="Local port number.")
    remote_addr: Optional[str] = Field(
        None, description="Remote IP address (None for listening sockets)."
    )
    remote_port: Optional[int] = Field(
        None, ge=0, le=65535, description="Remote port number."
    )
    state: Optional[str] = Field(
        None,
        description="Connection state, e.g. 'ESTABLISHED', 'LISTENING', 'CLOSE_WAIT'.",
    )
    pid: int = Field(
        default=0, ge=0, description="PID of the owning process (0 if unknown)."
    )
    owner_process: Optional[str] = Field(
        None, description="Name of the owning process."
    )
    offset: str = Field(
        ...,
        description="Physical memory offset of the socket/connection structure (hex string).",
    )
    create_time: Optional[datetime] = Field(
        None, description="UTC time the socket was created."
    )


# ---------------------------------------------------------------------------
# Disk artefacts
# ---------------------------------------------------------------------------


class PrefetchRecord(BaseModel):
    """A Windows Prefetch entry indicating a binary was executed.

    Produced by ``extract_prefetch``. The Prefetch structure itself records
    exact recent execution history in ``last_run_times``. Separate `.pf` file
    timestamps can also be surfaced as file metadata, but they are not the
    same thing as exact Prefetch-native execution timestamps.

    Attributes:
        executable_name:  Name of the executed binary (e.g. 'CMD.EXE').
        prefetch_path:    Absolute path to the .PF file on disk.
        run_count:        Number of times the binary was executed (as recorded
                          by Prefetch).
        last_run_times:   Up to 8 most recent execution timestamps (UTC),
                          latest first.  Prefetch v26+ stores 8; earlier
                          versions store 1.
        referenced_files: List of file paths opened by the binary at launch.
        volume_path:      Volume mount path (e.g. '\\Device\\HarddiskVolume3').
        volume_serial:    Volume serial number (hex string).
        pf_created_time:  `.pf` file metadata creation timestamp from MFT or
                          mounted NTFS-backed filesystem metadata. Useful
                          context, but not an exact execution timestamp.
        pf_modified_time: `.pf` file metadata modification timestamp from MFT
                          or mounted NTFS-backed filesystem metadata. Useful
                          context, but not an exact execution timestamp.
        pf_timestamp_source:
                          Provenance for the `.pf` file metadata fields.
    """

    executable_name: str = Field(
        ..., description="Name of the executed binary (e.g. 'CMD.EXE')."
    )
    prefetch_path: str = Field(
        ..., description="Absolute path to the .PF file on disk."
    )
    run_count: int = Field(
        ..., ge=1, description="Total recorded execution count."
    )
    last_run_times: list[datetime] = Field(
        default_factory=list,
        description=(
            "Up to 8 most recent UTC execution timestamps (latest first).  "
            "Prefetch v26+ records 8; earlier versions record 1."
        ),
        max_length=8,
    )
    referenced_files: list[str] = Field(
        default_factory=list,
        description="File paths opened by the binary during its first seconds of execution.",
    )
    volume_path: Optional[str] = Field(
        None,
        description="Volume device path, e.g. '\\\\Device\\\\HarddiskVolume3'.",
    )
    volume_serial: Optional[str] = Field(
        None, description="Volume serial number (hex string)."
    )
    pf_created_time: Optional[datetime] = Field(
        None,
        description=(
            "UTC `.pf` file creation timestamp from MFT or mounted NTFS-backed "
            "filesystem metadata. Useful `.pf` file metadata, but not an exact "
            "execution timestamp."
        ),
    )
    pf_modified_time: Optional[datetime] = Field(
        None,
        description=(
            "UTC `.pf` file modification timestamp from MFT or mounted "
            "NTFS-backed filesystem metadata. Useful `.pf` file metadata, but "
            "not an exact execution timestamp."
        ),
    )
    pf_timestamp_source: Optional[str] = Field(
        None,
        description=(
            "Source used to populate `.pf` file timestamps. "
            "Expected values: 'mft', 'mounted_ntfs_stat', or None."
        ),
    )


class AmcacheRecord(BaseModel):
    """An Amcache.hve entry proving a binary was present and executed.

    Produced by ``get_amcache`` (EZ Tools ``AmcacheParser``).  Amcache
    records the SHA-1 hash of the binary at first execution, which can be
    used to pivot into threat-intelligence lookups even after the binary is
    deleted from disk.

    Attributes:
        file_path:      Full path to the binary as recorded in Amcache.
        sha1_hash:      SHA-1 hash of the binary file at time of execution
                        (None if not recorded).
        file_size:      File size in bytes (None if not recorded).
        publisher:      Publisher / company name from the binary's version
                        resource (None if not available).
        product_name:   Product name from the binary's version resource.
        compile_time:   PE compilation timestamp (None if not available or
                        the binary was compiled with zeroed timestamp).
        install_time:   UTC time the binary was first recorded in Amcache.
        last_modified:  UTC last-write time of the Amcache key for this entry.
    """

    file_path: str = Field(
        ..., description="Full path to the binary as recorded in Amcache."
    )
    sha1_hash: Optional[str] = Field(
        None, description="SHA-1 hash of the binary at time of execution."
    )
    file_size: Optional[int] = Field(
        None, ge=0, description="File size in bytes."
    )
    publisher: Optional[str] = Field(
        None,
        description="Publisher / company name from the binary's version resource.",
    )
    product_name: Optional[str] = Field(
        None, description="Product name from the binary's version resource."
    )
    compile_time: Optional[datetime] = Field(
        None,
        description="PE compilation timestamp (UTC).  May be zeroed or falsified.",
    )
    install_time: Optional[datetime] = Field(
        None,
        description="UTC time the binary was first recorded in Amcache.",
    )
    last_modified: Optional[datetime] = Field(
        None,
        description="UTC last-write time of the Amcache key for this entry.",
    )


class RegistryRunKey(BaseModel):
    """A Windows registry persistence key pointing to a binary or script.

    Produced by ``extract_registry_run_keys`` (EZ Tools ``RECmd``).

    Attributes:
        hive:             Registry hive file (e.g. 'NTUSER.DAT', 'SOFTWARE').
        key_path:         Full registry key path.
        value_name:       Value name within the key.
        value_data:       Value data - the path to the binary or script that
                          will execute at the persistence trigger.
        last_write_time:  UTC last-write time of the registry key.
        persistence_type: Category of persistence mechanism.
    """

    hive: str = Field(
        ..., description="Registry hive file, e.g. 'NTUSER.DAT', 'SOFTWARE', 'SYSTEM'."
    )
    key_path: str = Field(..., description="Full registry key path.")
    value_name: str = Field(..., description="Registry value name.")
    value_data: str = Field(
        ...,
        description="Value data — the executable / script path that runs at the trigger.",
    )
    last_write_time: Optional[datetime] = Field(
        None, description="UTC last-write time of the registry key."
    )
    persistence_type: Literal[
        "run",
        "runonce",
        "appinit_dlls",
        "winlogon_shell",
        "winlogon_userinit",
        "services",
        "lsa_package",
        "session_manager",
        "browser_helper",
        "credential_provider",
        "shell_extension",
        "other",
    ] = Field(
        ...,
        description="Category of the persistence mechanism.",
    )


class EventRecord(BaseModel):
    """A Windows event log entry from EVTX parsing.

    Produced by ``summarize_evtx`` (EZ Tools ``EvtxECmd``).

    Attributes:
        event_id:         Windows Event ID (e.g. 4624, 4688, 7045).
        channel:          Event log channel (e.g. 'Security', 'System',
                          'Sysmon/Operational').
        provider:         Provider name (e.g. 'Microsoft-Windows-Security-Auditing').
        timestamp:        UTC time the event was recorded.
        level:            Event level string ('Information', 'Warning', 'Error',
                          'Critical', 'Verbose').
        computer:         Computer name from the event record.
        user_sid:         User SID from the event (None if not present).
        message_summary:  Human-readable summary of the event message
                          (full XML is saved to ``raw_xml_ref``).
        raw_xml_ref:      Absolute path to the saved raw XML for this event
                          (None if full XML was not captured).
        extra_fields:     Parsed event-specific fields (e.g. ``TargetUserName``,
                          ``NewProcessName``, ``CommandLine``).
    """

    event_id: int = Field(..., ge=0, description="Windows Event ID.")
    channel: str = Field(
        ...,
        description="Event log channel, e.g. 'Security', 'System', 'Sysmon/Operational'.",
    )
    provider: Optional[str] = Field(
        None, description="Provider name, e.g. 'Microsoft-Windows-Security-Auditing'."
    )
    timestamp: datetime = Field(..., description="UTC time the event was recorded.")
    level: Optional[str] = Field(
        None,
        description="Event level: 'Information', 'Warning', 'Error', 'Critical', 'Verbose'.",
    )
    computer: Optional[str] = Field(
        None, description="Computer name from the event record."
    )
    user_sid: Optional[str] = Field(
        None, description="User SID (e.g. 'S-1-5-21-…') from the event record."
    )
    message_summary: str = Field(
        ..., description="Human-readable summary of the event message."
    )
    raw_xml_ref: Optional[str] = Field(
        None,
        description="Absolute path to the saved raw XML file for this event.",
    )
    extra_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Parsed event-specific fields (e.g. TargetUserName, CommandLine).",
    )


class TimelineEvent(BaseModel):
    """A super-timeline entry produced by Plaso / ``log2timeline.py``.

    Produced by ``query_timeline`` (Plaso ``psort.py``).

    Attributes:
        timestamp:    UTC timestamp of the event.
        source:       Short Plaso source tag (e.g. 'FILE', 'REG', 'EVT').
        source_type:  Verbose Plaso source description.
        artifact_path: Path to the evidence file that contained this event.
        description:  Human-readable event description.
        extra_fields: Additional Plaso fields (parser-specific).
    """

    timestamp: datetime = Field(..., description="UTC timestamp of the event.")
    source: str = Field(
        ..., description="Short Plaso source tag (e.g. 'FILE', 'REG', 'EVT')."
    )
    source_type: Optional[str] = Field(
        None, description="Verbose Plaso source description."
    )
    artifact_path: Optional[str] = Field(
        None, description="Path to the evidence file that originated this event."
    )
    description: str = Field(..., description="Human-readable event description.")
    extra_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parser-specific fields from Plaso.",
    )


class DeletedFile(BaseModel):
    """A deleted file entry from the filesystem.

    Produced by ``list_deleted_files`` (Sleuth Kit ``fls -rd``).

    Attributes:
        inode:        Inode number (string to support NTFS-style 'NNN-NNN' format).
        file_path:    Full reconstructed path of the deleted file.
        file_type:    Whether the inode refers to a file or a directory.
        size:         File size in bytes at time of deletion (None if not recovered).
        deleted_time: UTC time the file was deleted (None if not determinable).
        parent_inode: Inode number of the parent directory.
    """

    inode: str = Field(
        ...,
        description="Inode number (may be 'NNN-NNN' format for NTFS attribute streams).",
    )
    file_path: str = Field(
        ..., description="Full reconstructed path of the deleted file."
    )
    file_type: Literal["file", "directory"] = Field(
        ..., description="Whether the entry is a regular file or directory."
    )
    size: Optional[int] = Field(
        None, ge=0, description="File size in bytes at time of deletion."
    )
    deleted_time: Optional[datetime] = Field(
        None, description="UTC time the file entry was deleted."
    )
    parent_inode: Optional[str] = Field(
        None, description="Inode number of the parent directory."
    )


class MftEntry(BaseModel):
    """A parsed $MFT entry from an NTFS volume.

    Produced by ``extract_mft_timeline`` (EZ Tools ``MFTECmd``).  The
    presence of both ``$STANDARD_INFORMATION`` (SI) and ``$FILE_NAME`` (FN)
    timestamps on each entry enables timestomping detection:
    SI timestamps can be modified at user level, but FN timestamps require
    kernel access.

    Attributes:
        entry_number:      MFT entry number.
        sequence:          Sequence number (incremented on reuse).
        file_path:         Full reconstructed file path.
        si_created:        $STANDARD_INFORMATION Created (UTC).
        si_modified:       $STANDARD_INFORMATION Modified (UTC).
        si_accessed:       $STANDARD_INFORMATION Accessed (UTC).
        si_entry_modified: $STANDARD_INFORMATION Entry Modified (UTC).
        fn_created:        $FILE_NAME Created (UTC).
        fn_modified:       $FILE_NAME Modified (UTC).
        fn_accessed:       $FILE_NAME Accessed (UTC).
        fn_entry_modified: $FILE_NAME Entry Modified (UTC).
        is_deleted:        True if the MFT entry is marked as deleted.
        is_directory:      True if the entry represents a directory.
        file_size:         Logical file size in bytes.
        parent_entry:      MFT entry number of the parent directory.
    """

    entry_number: int = Field(..., ge=0, description="MFT entry number.")
    sequence: Optional[int] = Field(
        None, ge=0, description="MFT sequence number (incremented on reuse)."
    )
    file_path: Optional[str] = Field(
        None, description="Full reconstructed file path."
    )
    # $STANDARD_INFORMATION timestamps
    si_created: Optional[datetime] = Field(
        None, description="$STANDARD_INFORMATION Created timestamp (UTC)."
    )
    si_modified: Optional[datetime] = Field(
        None, description="$STANDARD_INFORMATION Modified timestamp (UTC)."
    )
    si_accessed: Optional[datetime] = Field(
        None, description="$STANDARD_INFORMATION Accessed timestamp (UTC)."
    )
    si_entry_modified: Optional[datetime] = Field(
        None, description="$STANDARD_INFORMATION Entry Modified timestamp (UTC)."
    )
    # $FILE_NAME timestamps
    fn_created: Optional[datetime] = Field(
        None, description="$FILE_NAME Created timestamp (UTC)."
    )
    fn_modified: Optional[datetime] = Field(
        None, description="$FILE_NAME Modified timestamp (UTC)."
    )
    fn_accessed: Optional[datetime] = Field(
        None, description="$FILE_NAME Accessed timestamp (UTC)."
    )
    fn_entry_modified: Optional[datetime] = Field(
        None, description="$FILE_NAME Entry Modified timestamp (UTC)."
    )
    is_deleted: bool = Field(
        default=False, description="True if the MFT entry is marked as deleted."
    )
    is_directory: bool = Field(
        default=False, description="True if this entry represents a directory."
    )
    file_size: Optional[int] = Field(
        None, ge=0, description="Logical file size in bytes."
    )
    parent_entry: Optional[int] = Field(
        None, ge=0, description="MFT entry number of the parent directory."
    )


# ---------------------------------------------------------------------------
# Integrity / profiling
# ---------------------------------------------------------------------------


class IntegrityResult(BaseModel):
    """Hash verification result for an evidence image.

    Produced by ``verify_integrity`` (Sleuth Kit ``ewfverify`` / ``sha256sum``).

    Attributes:
        image_path:       Absolute path to the evidence file that was hashed.
        stored_hash:      Hash value embedded in the image (e.g. from E01
                          metadata) or provided by the investigator.
        computed_hash:    Hash value computed over the image at verification time.
        algorithm:        Hashing algorithm used.
        verified:         True if ``stored_hash == computed_hash`` (or if no
                          stored hash exists but the computation succeeded).
        verification_time: UTC timestamp when the verification was performed.
    """

    image_path: str = Field(
        ..., description="Absolute path to the evidence file that was hashed."
    )
    stored_hash: Optional[str] = Field(
        None,
        description=(
            "Hash value embedded in the image container or provided by the "
            "investigator.  None if no stored reference hash is available."
        ),
    )
    computed_hash: str = Field(
        ..., description="Hash value computed over the image during this run."
    )
    algorithm: Literal["sha256", "sha1", "md5"] = Field(
        ..., description="Hashing algorithm used."
    )
    verified: bool = Field(
        ...,
        description=(
            "True if the image is intact (stored_hash == computed_hash, or "
            "stored_hash is None and computation succeeded without error)."
        ),
    )
    verification_time: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when verification was performed.",
    )


class ProfileResult(BaseModel):
    """OS identification result from memory analysis.

    Produced by ``profile_memory`` (Volatility 3 ``windows.info.Info``).

    Attributes:
        os_name:      Operating system name (e.g. 'Windows').
        os_version:   Full OS version string (e.g. 'Windows 10 Enterprise').
        architecture: CPU architecture ('x64', 'x86', 'arm64').
        build_number: Windows build number string (e.g. '19041').
        kernel_base:  Kernel image base address in memory (hex string).
    """

    os_name: str = Field(..., description="Operating system name.")
    os_version: str = Field(
        ..., description="Full OS version string, e.g. 'Windows 10 Enterprise 21H2'."
    )
    architecture: Literal["x64", "x86", "arm64"] = Field(
        ..., description="CPU architecture."
    )
    build_number: Optional[str] = Field(
        None, description="Windows build number string, e.g. '19041'."
    )
    kernel_base: Optional[str] = Field(
        None,
        description="Kernel image base address in the memory dump (hex string).",
    )


# ---------------------------------------------------------------------------
# Correlation engine outputs
# ---------------------------------------------------------------------------


class DiscrepancyAlert(BaseModel):
    """A single cross-artifact discrepancy detected by the correlation engine.

    Produced by ``compare_disk_and_memory`` when one of the 6 specific
    correlation checks fires.

    Attributes:
        discrepancy_type:   The specific check that fired.
        severity:           Forensic significance of the discrepancy.
        description:        Human-readable explanation of what was found and
                            why it is significant.
        disk_finding_id:    F-NNN of the disk-side finding involved (None if
                            the discrepancy is memory-only).
        memory_finding_id:  F-NNN of the memory-side finding involved (None if
                            the discrepancy is disk-only).
        recommended_action: Free-text description of the recommended follow-up
                            investigation step.
        disk_evidence:      Raw evidence dict from the disk side (tool-specific
                            fields, for agent consumption).
        memory_evidence:    Raw evidence dict from the memory side.
    """

    discrepancy_type: Literal[
        "process_no_disk_binary",
        "prefetch_deleted_binary",
        "vad_anomaly_legitimate_path",
        "network_no_disk_artifact",
        "registry_missing_binary",
        "timestamp_mismatch",
    ] = Field(
        ..., description="The specific correlation check that produced this alert."
    )
    severity: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ..., description="Forensic significance: HIGH | MEDIUM | LOW."
    )
    description: str = Field(
        ...,
        min_length=10,
        description=(
            "Human-readable explanation of the discrepancy and its forensic significance."
        ),
    )
    disk_finding_id: Optional[str] = Field(
        None,
        pattern=r"^F-\d{3,}$",
        description="Finding ID of the disk-side finding, if applicable.",
    )
    memory_finding_id: Optional[str] = Field(
        None,
        pattern=r"^F-\d{3,}$",
        description="Finding ID of the memory-side finding, if applicable.",
    )
    recommended_action: str = Field(
        ...,
        description=(
            "Recommended follow-up action, e.g. 'Call detect_injection(pid=1234) "
            "to inspect the suspicious VAD region'."
        ),
    )
    disk_evidence: Optional[dict[str, Any]] = Field(
        None,
        description="Raw disk-side evidence fields for agent consumption.",
    )
    memory_evidence: Optional[dict[str, Any]] = Field(
        None,
        description="Raw memory-side evidence fields for agent consumption.",
    )


class CorrelationReport(BaseModel):
    """Full output of the cross-artifact correlation engine.

    Produced by ``compare_disk_and_memory``.  Summarises all 6 correlation
    checks and lists every discrepancy found.

    Attributes:
        case_id:               Parent case identifier.
        discrepancies:         List of ``DiscrepancyAlert`` records (may be
                               empty if no discrepancies were found).
        checked_at:            UTC timestamp when the correlation run completed.
        disk_findings_count:   Number of disk-domain findings that were
                               examined.
        memory_findings_count: Number of memory-domain findings that were
                               examined.
        confirmed_consistencies: Number of cross-artifact checks that found
                               matching evidence on both sides (no discrepancy).
        summary:               One-paragraph natural-language summary of the
                               correlation results for the agent to use in
                               its reasoning.
    """

    case_id: str = Field(..., description="Parent case identifier.")
    discrepancies: list[DiscrepancyAlert] = Field(
        default_factory=list,
        description="List of discrepancy alerts produced by the correlation checks.",
    )
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when the correlation run completed.",
    )
    disk_findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of disk-domain findings examined.",
    )
    memory_findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of memory-domain findings examined.",
    )
    confirmed_consistencies: int = Field(
        default=0,
        ge=0,
        description="Number of cross-artifact checks that found consistent evidence on both sides.",
    )
    summary: str = Field(
        default="",
        description=(
            "One-paragraph natural-language summary of the correlation results "
            "for the agent to include in its iterative reasoning."
        ),
    )
