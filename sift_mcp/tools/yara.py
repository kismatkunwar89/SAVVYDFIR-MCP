"""
sift_mcp.tools.yara
~~~~~~~~~~~~~~~~~~~~

MCP tool functions for YARA signature-based scanning on SIFT Workstation.

Two tools are exposed:

* ``scan_files`` — Scan a file or directory tree against YARA rules.
* ``scan_memory`` — Scan a raw memory dump against YARA rules.

Both tools parse YARA's stdout into a list of match dicts with fields
``rule_name``, ``target_file``, and ``matched_strings``.

Both tools are synchronous because :class:`~sift_mcp.runners.base.SafeRunner`
uses ``subprocess.run()``, which is blocking.  FastMCP supports sync tool
functions.

Tool init
---------
Call :func:`init_tools` once at server startup, passing the
:class:`~sift_mcp.audit.AuditLogger` and :class:`~sift_mcp.state.CaseStateManager`
instances so the shared runner uses the same audit channel as the rest of the
server.
"""

from __future__ import annotations

from typing import Any, Optional

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.yara_runner import YaraRunner
from sift_mcp.state import CaseStateManager

__all__ = [
    "scan_files",
    "scan_memory",
    "init_tools",
]

# ---------------------------------------------------------------------------
# Module-level singletons (initialised by init_tools)
# ---------------------------------------------------------------------------

_audit: Optional[AuditLogger] = None
_state_mgr: Optional[CaseStateManager] = None
_runner: Optional[YaraRunner] = None


def init_tools(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
) -> None:
    """Wire the shared audit logger and state manager into this tool module.

    Must be called once at server startup before any tool function is invoked.

    Parameters
    ----------
    audit_logger:
        The process-wide :class:`~sift_mcp.audit.AuditLogger` instance.
    state_manager:
        The process-wide :class:`~sift_mcp.state.CaseStateManager` instance.
    """
    global _audit, _state_mgr, _runner
    _audit = audit_logger
    _state_mgr = state_manager
    _runner = YaraRunner(
        audit_logger=audit_logger,
        state_manager=state_manager,
        case_id="",
        tool_name="yara",
    )


# ---------------------------------------------------------------------------
# Tool 1: scan_files
# ---------------------------------------------------------------------------


def scan_files(
    rules_path: str,
    target_path: str,
    recursive: bool = False,
) -> dict[str, Any]:
    """Scan a file or directory for YARA rule matches.

    Runs the ``yara`` CLI against *target_path* using the rule set at
    *rules_path*.  When *recursive* is ``True``, the ``-r`` flag is passed
    to scan all files within the directory tree.

    Parameters
    ----------
    rules_path:
        Absolute path to the YARA rules file (``.yar`` / ``.yara`` /
        ``.yarc``).  Compiled rule sets (``.yarc``) scan faster than
        source rule files.
    target_path:
        Absolute path to the file or directory to scan.
    recursive:
        When ``True``, scan all files in *target_path* recursively (``-r``).
        Has no effect when *target_path* is a single file.

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "matches": [
                {
                  "rule_name": "CobaltStrikeSleep",
                  "target_file": "/path/to/file.exe",
                  "matched_strings": ["$a at 0x1f4"]   # only if -s used
                },
                ...
              ],
              "match_count": 1,
              "rules_path": "...",
              "target_path": "...",
              "recursive": false,
              "execution_id": "E-003"
            }

        On error::

            {
              "status": "error",
              "error": "...",
              "stderr": "...",
              "exit_code": 1,
              "execution_id": "E-003"
            }
    """
    tool = "yara.scan_files"
    if _runner is None:
        return {"status": "error", "error": "Tool module not initialised — call init_tools() first."}

    try:
        result = _runner.scan_file(
            rules_path=rules_path,
            target_path=target_path,
            recursive=recursive,
            tool_name=tool,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    if result.timed_out:
        return {
            "status": "error",
            "error": "yara scan timed out (300 s). Try a smaller target or a compiled rule set.",
            "execution_id": result.execution_id,
        }

    if not result.ok:
        error_class = _runner.classify_error(result)
        return {
            "status": "error",
            "error": f"yara failed ({error_class})",
            "stderr": result.stderr[:2000],
            "exit_code": result.exit_code,
            "execution_id": result.execution_id,
        }

    matches = _parse_yara_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation

    return {
        "status": "ok",
        "matches": matches,
        "match_count": len(matches),
        "rules_path": rules_path,
        "target_path": target_path,
        "recursive": recursive,
        "execution_id": result.execution_id,
    }


# ---------------------------------------------------------------------------
# Tool 2: scan_memory
# ---------------------------------------------------------------------------


def scan_memory(
    rules_path: str,
    dump_path: str,
) -> dict[str, Any]:
    """Scan a raw memory dump for YARA rule matches.

    Treats *dump_path* as a flat byte stream and searches for YARA rule
    patterns.  This surfaces in-memory artefacts that may not appear on disk:

    * Reflectively loaded DLLs (no on-disk copy)
    * Shellcode stubs (Cobalt Strike, Meterpreter beacons)
    * Unpacked malware payloads
    * Credential scraping tool footprints

    Cross-reference hits against Volatility 3 ``malfind`` output to identify
    the process context.

    Parameters
    ----------
    rules_path:
        Absolute path to the YARA rules file (``.yar`` / ``.yara`` /
        ``.yarc``).
    dump_path:
        Absolute path to the raw memory dump (``.raw``, ``.mem``, ``.lime``,
        ``.vmem``).  The file is treated as a binary blob — no memory
        structure parsing is performed by YARA itself.

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "matches": [
                {
                  "rule_name": "CobaltStrikeSleep",
                  "target_file": "/evidence/wkstn-01.raw",
                  "matched_strings": []
                },
                ...
              ],
              "match_count": 2,
              "rules_path": "...",
              "dump_path": "...",
              "execution_id": "E-004"
            }

        On error::

            {
              "status": "error",
              "error": "...",
              "stderr": "...",
              "exit_code": 1,
              "execution_id": "E-004"
            }
    """
    tool = "yara.scan_memory"
    if _runner is None:
        return {"status": "error", "error": "Tool module not initialised — call init_tools() first."}

    try:
        result = _runner.scan_memory(
            rules_path=rules_path,
            dump_path=dump_path,
            tool_name=tool,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    if result.timed_out:
        return {
            "status": "error",
            "error": "yara memory scan timed out (600 s). The dump may be too large.",
            "execution_id": result.execution_id,
        }

    if not result.ok:
        error_class = _runner.classify_error(result)
        return {
            "status": "error",
            "error": f"yara memory scan failed ({error_class})",
            "stderr": result.stderr[:2000],
            "exit_code": result.exit_code,
            "execution_id": result.execution_id,
        }

    matches = _parse_yara_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation

    return {
        "status": "ok",
        "matches": matches,
        "match_count": len(matches),
        "rules_path": rules_path,
        "dump_path": dump_path,
        "execution_id": result.execution_id,
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _parse_yara_output(stdout: str) -> list[dict[str, Any]]:
    """Parse YARA stdout into a list of match dicts.

    YARA's default output format is::

        RuleName /path/to/matched/file

    When the ``-s`` flag is used (string matches), additional lines appear::

        RuleName /path/to/matched/file
        0x1f4:$a: 4D 5A 90 00

    Both formats are handled.  The ``matched_strings`` field is populated only
    when string-level output is present.

    Parameters
    ----------
    stdout:
        Raw stdout from the ``yara`` CLI process.

    Returns
    -------
    list[dict[str, Any]]
        A list of match dicts, each with:

        * ``rule_name`` — the YARA rule that matched.
        * ``target_file`` — the file in which the match was found.
        * ``matched_strings`` — list of string-match lines (may be empty).
    """
    matches: list[dict[str, Any]] = []
    current_match: Optional[dict[str, Any]] = None

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # String match lines start with "0x<hex>:$..."
        if current_match is not None and (line.startswith("0x") and ":$" in line):
            current_match["matched_strings"].append(line)
            continue

        # New rule match line: "<RuleName> <path>"
        parts = line.split(None, 1)
        if len(parts) == 2:
            rule_name, target_file = parts
            current_match = {
                "rule_name": rule_name,
                "target_file": target_file,
                "matched_strings": [],
            }
            matches.append(current_match)
        # Lines with only one token may be continuation; skip gracefully
        # (This handles edge cases in YARA -s output)

    return matches
