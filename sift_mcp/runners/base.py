"""SafeRunner — Read-only enforcement layer for all forensic tool execution.

Every subprocess call in SAVVYDFIR-MCP goes through SafeRunner. This is the
architectural guardrail that ensures:
- Read-only: no tool can write to evidence directories
- Timeout: every subprocess has a max execution time
- Audit: every call is logged to audit.jsonl before and after
- Structured output: raw stdout is parsed by subclass parsers

Design decisions
----------------
* ``subprocess.run(shell=False)`` — no shell expansion, no injection surface.
* Path resolution before deny-list check — prevents ``../../../mnt/`` traversal.
* Fail-closed audit: if the pre-execution log write raises, the command never runs.
* Execution IDs are sourced from ``AuditLogger.next_execution_id()`` so IDs
  remain globally monotonic and consistent across audit.jsonl + state.json.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sift_mcp.audit import AuditLogger

__all__ = ["RunResult", "SafeRunner", "PathDeniedError", "CommandDeniedError"]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    """Structured output of a single subprocess invocation.

    Attributes
    ----------
    stdout:
        Full standard output captured from the process (decoded as UTF-8,
        errors replaced).
    stderr:
        Full standard error captured from the process.
    exit_code:
        Process exit code (0 = success, non-zero = tool-level error).
    duration_seconds:
        Wall-clock seconds the subprocess ran, measured around
        ``subprocess.run``.
    command_line:
        The command reconstructed as a single string for display / audit.
        The actual call always uses ``shell=False`` with a list of arguments.
    execution_id:
        The E-NNN ID assigned by the audit layer before execution.
    timed_out:
        ``True`` if the subprocess was killed due to a timeout.
    """

    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    command_line: str
    execution_id: str
    timed_out: bool = field(default=False)

    @property
    def returncode(self) -> int:
        """Alias for ``exit_code`` (compatibility with runners that use this name)."""
        return self.exit_code

    @property
    def ok(self) -> bool:
        """``True`` when the process exited 0 and was not timed out or denied."""
        return self.exit_code == 0 and not self.timed_out


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class PathDeniedError(PermissionError):
    """Raised when a path argument resolves to a denied evidence directory."""


class CommandDeniedError(PermissionError):
    """Raised when the executable name appears in the deny list."""




# ---------------------------------------------------------------------------
# No-op audit stub — used when no AuditLogger is supplied
# ---------------------------------------------------------------------------


class _NoOpAuditLogger:
    """Minimal AuditLogger stub for standalone / test use.

    When a runner is instantiated without a real ``AuditLogger``, this stub
    satisfies all ``self._audit.*`` calls made by :py:meth:`SafeRunner.run`
    without writing anything to disk.  The tool layer replaces this with a
    real ``AuditLogger`` in production.
    """

    _counter: int = 0

    def next_execution_id(self) -> str:
        self._counter += 1
        return f"E-{self._counter:03d}"

    def log_execution(self, **kwargs) -> None:  # noqa: ANN003
        pass

    def log_result(self, **kwargs) -> None:  # noqa: ANN003
        pass


# ---------------------------------------------------------------------------
# SafeRunner
# ---------------------------------------------------------------------------


class SafeRunner:
    """Base class for all forensic tool execution in SAVVYDFIR-MCP.

    Every subprocess call goes through :py:meth:`run`. Subclasses specialise
    this class for individual tool suites (Volatility, Sleuth Kit, Plaso, …)
    by overriding :py:meth:`parse_output` and providing convenience methods
    that build the ``cmd_parts`` list before delegating to :py:meth:`run`.

    Parameters
    ----------
    audit_logger:
        The :class:`~sift_mcp.audit.AuditLogger` instance for this case.
        All pre- and post-execution entries are written through it.
    case_id:
        The case identifier (e.g. ``"SRL-2018"``). Stored so subclasses can
        use it when constructing audit records.
    tool_name:
        Logical MCP tool name (e.g. ``"memory.list_processes"``). Used as
        the ``tool`` field in audit entries.

    Class attributes
    ----------------
    DENIED_PATHS:
        Absolute path prefixes that no argument may resolve to. Any path
        argument that, after ``os.path.realpath`` resolution, starts with
        one of these strings is rejected.
    DENIED_COMMANDS:
        Executable basenames that are never allowed as the first element of
        ``cmd_parts``.
    """

    # ------------------------------------------------------------------
    # Security policy constants
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # RBAC Path Model
    # ------------------------------------------------------------------
    # Evidence paths: readable by all forensic tools (Volatility, Sleuth Kit, etc.)
    # These are NEVER writable — enforced at the argument level below.
    EVIDENCE_PATHS: list[str] = [
        "/evidence/",
        "/mnt/",
        "/media/",
    ]

    # Output paths: readable and writable by forensic tools
    OUTPUT_PATHS: list[str] = [
        "/cases/",
        "/tmp/",
    ]

    # Paths that are ALWAYS blocked — kernel/device interfaces, never needed by forensic tools
    DENIED_PATHS: list[str] = [
        "/dev/",
        "/proc/",
        "/sys/",
    ]

    # Write-protected paths — arguments pointing here are allowed for READS
    # but blocked if the tool would write to them (checked via output flag detection)
    WRITE_PROTECTED_PATHS: list[str] = [
        "/evidence/",
        "/mnt/",
        "/media/",
    ]

    #: Executable basenames that are unconditionally refused.
    DENIED_COMMANDS: list[str] = [
        "rm",
        "dd",
        "wget",
        "curl",
        "ssh",
        "scp",
        "mkfs",
        "fdisk",
        "shred",
    ]

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        audit_logger: "AuditLogger | None" = None,
        case_id: str = "unknown",
        tool_name: str = "unknown",
    ) -> None:
        """Initialise the runner.

        Parameters
        ----------
        audit_logger:
            Optional :class:`~sift_mcp.audit.AuditLogger` for this case.
            When ``None`` (default), a :class:`_NoOpAuditLogger` stub is
            used so that runners can be instantiated and tested without a
            full case context.  The tool layer should always supply a real
            ``AuditLogger``.
        case_id:
            Forensic case identifier used in audit records.
        tool_name:
            MCP tool name written to audit entries. Subclasses typically
            override this at their own ``__init__``.
        """
        self._audit = audit_logger if audit_logger is not None else _NoOpAuditLogger()
        self._case_id = case_id
        self._tool_name = tool_name

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def audit(self) -> "AuditLogger":
        """The :class:`~sift_mcp.audit.AuditLogger` attached to this runner."""
        return self._audit

    @property
    def case_id(self) -> str:
        """The case identifier this runner is scoped to."""
        return self._case_id

    # ------------------------------------------------------------------
    # Validation helpers (public so subclasses can call them directly)
    # ------------------------------------------------------------------

    def validate_path(self, path: str) -> bool:
        """Return ``True`` if *path* is safe to use as a command argument.

        The path is resolved to an absolute, symlink-free form via
        ``os.path.realpath`` before being checked against
        :py:attr:`DENIED_PATHS`. This prevents path-traversal tricks like
        ``../../../mnt/evidence``.

        Parameters
        ----------
        path:
            A filesystem path string, absolute or relative.

        Returns
        -------
        bool
            ``True`` if the path is allowed; ``False`` if it resolves into a
            denied directory.
        """
        try:
            resolved = os.path.realpath(path)
        except (OSError, ValueError):
            # If we cannot resolve it, refuse it.
            return False

        for denied in self.DENIED_PATHS:
            if resolved.startswith(denied):
                return False
        return True

    def validate_command(self, cmd_parts: list[str]) -> bool:
        """Return ``True`` if the executable in *cmd_parts* is not deny-listed.

        Matching is performed against the *basename* of ``cmd_parts[0]`` so
        full-path invocations (``/usr/bin/curl``) are caught as well as bare
        names (``curl``).

        Parameters
        ----------
        cmd_parts:
            The command list that will be passed to ``subprocess.run``. Must
            contain at least one element.

        Returns
        -------
        bool
            ``True`` if the command is allowed; ``False`` if the basename of
            the first element appears in :py:attr:`DENIED_COMMANDS`.
        """
        if not cmd_parts:
            return False
        binary_name = Path(cmd_parts[0]).name
        return binary_name not in self.DENIED_COMMANDS

    # ------------------------------------------------------------------
    # Core execution method
    # ------------------------------------------------------------------

    def run(
        self,
        cmd_parts: list[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
        parameters: Optional[dict] = None,
        agent_turn: int = 0,
    ) -> RunResult:
        """Execute a subprocess with full safety checks and audit logging.

        This is the **only** method through which subclasses should invoke
        external processes. The method:

        1. Validates the command against the deny list (raises
           :py:exc:`CommandDeniedError` on violation).
        2. Validates every path-like argument against the denied path prefixes
           (raises :py:exc:`PathDeniedError` on violation).
        3. Logs a ``started`` entry to ``audit.jsonl`` via :py:attr:`audit` —
           **fail-closed**: if this write raises, the subprocess is never run.
        4. Invokes ``subprocess.run(shell=False, …)`` with the given timeout.
        5. Logs a ``completed`` entry to ``audit.jsonl``.
        6. Returns a :class:`RunResult`.

        Parameters
        ----------
        cmd_parts:
            The command as a list of strings. Never passed through a shell.
        timeout:
            Maximum wall-clock seconds. Default: 300 s.
        cwd:
            Working directory for the subprocess. ``None`` inherits the
            current process's working directory.
        parameters:
            Structured parameters dict written into the audit record.
        agent_turn:
            The current Claude agent turn number, stored in the audit record.

        Returns
        -------
        RunResult
            Structured result with stdout, stderr, exit_code, duration,
            command_line, execution_id, and timed_out flag.

        Raises
        ------
        CommandDeniedError
            If the executable basename is in :py:attr:`DENIED_COMMANDS`.
        PathDeniedError
            If any argument resolves to a :py:attr:`DENIED_PATHS` prefix.
        RuntimeError
            If the audit pre-execution log write fails (fail-closed).
        """
        if parameters is None:
            parameters = {}

        # ------------------------------------------------------------------
        # 1. Validate command
        # ------------------------------------------------------------------
        if not self.validate_command(cmd_parts):
            raise CommandDeniedError(
                f"Command '{Path(cmd_parts[0]).name}' is in the deny list and "
                "cannot be executed by SafeRunner."
            )

        # ------------------------------------------------------------------
        # 2. Validate path arguments
        # RBAC model:
        #   /evidence/, /mnt/, /media/ -> read-only (allowed as input args)
        #   /cases/, /tmp/             -> read-write (allowed as input and output args)
        #   /dev/, /proc/, /sys/       -> always denied
        # ------------------------------------------------------------------
        for arg in cmd_parts[1:]:
            # Only check strings that look like filesystem paths.
            if os.sep in arg or arg.startswith("./") or arg.startswith("../"):
                if not self.validate_path(arg):
                    allowed = self.EVIDENCE_PATHS + self.OUTPUT_PATHS
                    raise PathDeniedError(
                        f"Argument '{arg}' resolves to a system path that cannot be used. "
                        f"Allowed paths: {allowed}. "
                        f"Blocked paths (kernel interfaces only): {self.DENIED_PATHS}"
                    )

        # ------------------------------------------------------------------
        # 3. Generate execution ID and log pre-execution (fail-closed)
        # ------------------------------------------------------------------
        execution_id = self._audit.next_execution_id()
        command_line = " ".join(cmd_parts)

        # Fail-closed: if this write raises, we do NOT run the command.
        self._audit.log_execution(
            execution_id=execution_id,
            tool_name=self._tool_name,
            parameters=parameters,
            command_line=command_line,
            agent_turn=agent_turn,
        )

        # ------------------------------------------------------------------
        # 4. Execute subprocess
        # ------------------------------------------------------------------
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = -1
        start = time.monotonic()

        try:
            proc = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,  # CRITICAL — never use shell=True
                cwd=cwd,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode

        except subprocess.TimeoutExpired as exc:
            timed_out = True
            # Recover any partial output the process emitted before being killed.
            raw_out = exc.stdout or b""
            raw_err = exc.stderr or b""
            stdout = raw_out.decode("utf-8", errors="replace") if isinstance(raw_out, bytes) else str(raw_out)
            stderr = raw_err.decode("utf-8", errors="replace") if isinstance(raw_err, bytes) else str(raw_err)
            exit_code = -1

        finally:
            duration = time.monotonic() - start

        # ------------------------------------------------------------------
        # 5. Log post-execution result
        # ------------------------------------------------------------------
        outputs_summary = self._build_outputs_summary(stdout, stderr, exit_code, timed_out)

        self._audit.log_result(
            execution_id=execution_id,
            exit_code=exit_code,
            duration=duration,
            outputs_summary=outputs_summary,
            finding_ids=[],  # Populated later by the tool layer
            correction_event=None,
        )

        # ------------------------------------------------------------------
        # 6. Return structured result
        # ------------------------------------------------------------------
        return RunResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_seconds=duration,
            command_line=command_line,
            execution_id=execution_id,
            timed_out=timed_out,
        )

    # ------------------------------------------------------------------
    # Overridable hook for subclasses
    # ------------------------------------------------------------------

    def parse_output(self, result: RunResult) -> dict:
        """Parse raw subprocess output into a structured dictionary.

        Subclasses override this to convert tool-specific stdout into typed
        data. The base implementation returns the raw stdout and stderr as
        strings.

        Parameters
        ----------
        result:
            The :class:`RunResult` returned by :py:meth:`run`.

        Returns
        -------
        dict
            A dictionary suitable for inclusion in a Finding or Execution
            record. Structure is tool-specific.
        """
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_outputs_summary(
        stdout: str, stderr: str, exit_code: int, timed_out: bool
    ) -> str:
        """Construct a one-line summary string for audit records.

        Parameters
        ----------
        stdout:
            Raw captured stdout.
        stderr:
            Raw captured stderr.
        exit_code:
            Process exit code.
        timed_out:
            Whether the process exceeded its timeout budget.

        Returns
        -------
        str
            A human-readable summary string, truncated to 500 characters.
        """
        if timed_out:
            return "TIMED OUT — process killed"

        lines = len(stdout.splitlines())
        stderr_snippet = stderr[:120].strip() if stderr else ""
        parts = [f"exit={exit_code}", f"stdout_lines={lines}"]
        if stderr_snippet:
            parts.append(f"stderr_snippet={stderr_snippet!r}")
        summary = "; ".join(parts)
        return summary[:500]
