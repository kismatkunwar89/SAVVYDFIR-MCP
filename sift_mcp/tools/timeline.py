"""
sift_mcp.tools.timeline
~~~~~~~~~~~~~~~~~~~~~~~

MCP tool functions for Plaso super-timeline construction and querying.

Two tools are exposed:

* ``build_timeline`` - Ingests an evidence source with ``log2timeline.py``
  and produces a ``.plaso`` storage file in ``./analysis/``.
* ``query_timeline`` - Queries a ``.plaso`` storage file with ``psort.py``,
  optionally filtering by time range and/or content expression.

Both tools are synchronous because :class:`~sift_mcp.runners.base.SafeRunner`
uses ``subprocess.run()``, which is blocking.  FastMCP supports sync tool
functions.

Tool init
---------
Call :func:`init_tools` once at server startup, passing the
:class:`~sift_mcp.audit.AuditLogger` and :class:`~sift_mcp.state.CaseStateManager`
instances so runners share the same audit channel as the rest of the server.
"""

from __future__ import annotations

import csv
import io
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.plaso import PlasoRunner
from sift_mcp.state import CaseStateManager
from sift_mcp.tools._cache import (
    build_cache_key,
    get_valid_cached_artifact,
    record_cache_hit,
)
from sift_mcp.tools._contracts import (
    build_contract_response,
    build_follow_up_option,
    build_handle,
    build_provenance,
    compact_unique,
    sanitize_payload_fields,
    state_path_for_manager,
)

__all__ = [
    "build_timeline",
    "query_timeline",
    "init_tools",
]

# ---------------------------------------------------------------------------
# Module-level singletons (initialised by init_tools)
# ---------------------------------------------------------------------------

_audit: Optional[AuditLogger] = None
_state_mgr: Optional[CaseStateManager] = None
_runner: Optional[PlasoRunner] = None


def init_tools(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
    runner: Optional[PlasoRunner] = None,
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
    if runner is not None:
        _runner = runner
    else:
        _runner = PlasoRunner(
            audit_logger=audit_logger,
            state_manager=state_manager,
            case_id="",          # Updated per-call via runner's case_id property
            tool_name="timeline",
        )


def _build_timeline_contract_payload(
    *,
    response: dict[str, Any],
    case_id: str,
    source_path: str,
    storage_path: str,
) -> dict[str, Any]:
    normalized = [
        {
            "case_id": case_id,
            "parser_preset": response.get("parser_preset"),
            "estimated_event_count": response.get("estimated_event_count"),
            "cache_hit": response.get("cache_hit", False),
        }
    ]
    return build_contract_response(
        response,
        case_id=case_id,
        execution_id=response.get("execution_id"),
        state_manager=_state_mgr,
        audit_logger=_audit,
        tool_name="timeline.build_timeline",
        summary=(
            f"Timeline storage ready for case {case_id}. "
            f"Use query_timeline() against {storage_path} instead of rebuilding."
        ),
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="timeline.build_timeline",
            execution_id=response.get("execution_id"),
            state_path=state_path_for_manager(_state_mgr),
            storage_path=storage_path,
            source_path=source_path,
            cache_hit=response.get("cache_hit"),
            cache_source_execution_id=response.get("cache_source_execution_id"),
            artifact_paths=[source_path, storage_path],
        ),
        pivot_entities={
            "case_ids": [case_id],
            "parser_presets": compact_unique([response.get("parser_preset")]),
            "source_paths": compact_unique([source_path]),
            "storage_paths": compact_unique([storage_path]),
        },
        follow_up_options=[
            build_follow_up_option(
                "query_timeline",
                reason="Start with a bounded timeline query instead of broad reruns.",
                parameters={"plaso_path": storage_path},
            ),
        ],
        handle=build_handle(
            kind="plaso_storage",
            path=storage_path,
            query_tool="query_timeline",
            description="Persisted Plaso storage file.",
            tool_name="timeline.build_timeline",
        ),
    )


def _query_timeline_contract_payload(
    *,
    response: dict[str, Any],
    events: list[dict[str, Any]],
    plaso_path: str,
    output_csv: str,
    start: Optional[str],
    end: Optional[str],
    filter_expr: Optional[str],
) -> dict[str, Any]:
    normalized = [
        {
            "timestamp": event.get("timestamp"),
            "source": event.get("source"),
            "artifact_path": event.get("artifact_path"),
        }
        for event in events[:20]
    ]
    evidence_excerpt = next(
        (
            event.get("description")
            for event in events
            if isinstance(event.get("description"), str) and event.get("description")
        ),
        None,
    )
    return build_contract_response(
        response,
        case_id=case_id,
        execution_id=response.get("execution_id"),
        state_manager=_state_mgr,
        audit_logger=_audit,
        tool_name="timeline.query_timeline",
        summary=(
            f"Timeline query returned {response.get('event_count', len(events))} events from {plaso_path}. "
            "Use the same storage handle with narrower constraints for deeper pivots."
        ),
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="timeline.query_timeline",
            execution_id=response.get("execution_id"),
            state_path=state_path_for_manager(_state_mgr),
            storage_path=plaso_path,
            csv_path=output_csv,
            artifact_paths=[plaso_path, output_csv],
        ),
        pivot_entities={
            "sources": compact_unique(event.get("source") for event in events),
            "artifact_paths": compact_unique(event.get("artifact_path") for event in events),
            "timestamps": compact_unique(event.get("timestamp") for event in events),
        },
        follow_up_options=[
            build_follow_up_option(
                "query_timeline",
                reason="Narrow the timeline further by time range or filter expression.",
                parameters={"plaso_path": plaso_path},
            ),
        ],
        handle=build_handle(
            kind="timeline_query_result",
            path=output_csv,
            description="CSV output from the current psort query.",
            tool_name="timeline.query_timeline",
        ),
        query_constraints={
            "start": start,
            "end": end,
            "filter_expr": filter_expr,
        },
        evidence_excerpt=evidence_excerpt,
    )


# ---------------------------------------------------------------------------
# Tool 1: build_timeline
# ---------------------------------------------------------------------------


def build_timeline(
    source_path: str,
    case_id: str,
    parsers: str = "win10",
) -> dict[str, Any]:
    """Build a Plaso super-timeline from an evidence source.

    Invokes ``log2timeline.py`` on the SIFT Workstation to process
    *source_path* and write a ``.plaso`` storage file into
    ``./analysis/<case_id>/`` (created if absent).  The parser preset
    controls which artefact types are ingested.

    This step is slow - 30-120 minutes for a 100 GB image.  For demos,
    pre-generate the ``.plaso`` file and call :func:`query_timeline` directly.

    Parameters
    ----------
    source_path:
        Absolute path to the evidence source (E01 image, raw image, mounted
        directory, or memory dump).
    case_id:
        Case identifier (e.g. ``"SRL-2018-WKSTN-01"``).  Used to derive the
        output storage file path.
    parsers:
        Plaso parser preset.  Common values:

        * ``"win10"`` (default) - Windows 10/11 artefacts
        * ``"win7"`` - Windows 7 / Server 2008 R2
        * ``"linux"`` - Linux system artefacts
        * A comma-separated list of individual parser names for targeted
          ingestion.

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "storage_path": "/abs/path/to/<case_id>.plaso",
              "parser_preset": "win10",
              "source_path": "...",
              "case_id": "...",
              "estimated_event_count": "<N from stdout or 'unknown'>",
              "duration_seconds": 42.7,
              "execution_id": "E-001"
            }

        On error::

            {
              "status": "error",
              "error": "<description>",
              "stderr": "...",
              "exit_code": 1,
              "execution_id": "E-001"
            }
    """
    tool = "timeline.build_timeline"
    if _runner is None:
        return {"status": "error", "error": "Tool module not initialised — call init_tools() first."}

    # Derive output path inside ./analysis/<case_id>/
    analysis_dir = Path("./analysis") / case_id
    try:
        analysis_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"status": "error", "error": f"Cannot create analysis directory: {exc}"}

    # Sanitise case_id for use in a filename (replace non-alnum with '_')
    safe_case = re.sub(r"[^A-Za-z0-9_.-]", "_", case_id)
    storage_path = str((analysis_dir / f"{safe_case}.plaso").resolve())
    cache_key = build_cache_key(
        tool,
        {
            "source_path": str(Path(source_path).resolve()),
            "parsers": parsers,
        },
    )
    cached = get_valid_cached_artifact(
        _state_mgr,
        cache_key,
        path_key="storage_path",
        required_keys=("storage_path", "source_execution_id"),
    )
    if cached is not None:
        cache_meta = record_cache_hit(
            _audit,
            _state_mgr,
            tool_name=tool,
            parameters={"source_path": source_path, "case_id": case_id, "parsers": parsers},
            cache_key=cache_key,
            artifact_path=str(cached["storage_path"]),
            cache_source_execution_id=str(cached.get("source_execution_id") or ""),
        )
        response = {
            "status": "ok",
            "storage_path": str(cached["storage_path"]),
            "parser_preset": cached.get("parser_preset", parsers),
            "source_path": cached.get("source_path", source_path),
            "case_id": case_id,
            "estimated_event_count": cached.get("estimated_event_count", "unknown"),
            "duration_seconds": 0.0,
            "execution_id": cache_meta["execution_id"],
            "cache_hit": True,
            "cache_source_execution_id": cached.get("source_execution_id"),
            "requires_agent": "@timeline-analyst",
            "agent_instruction": (
                f"Use {cached['storage_path']} to run narrow timeline pivots instead of rebuilding storage."
            ),
        }
        return _build_timeline_contract_payload(
            response=response,
            case_id=case_id,
            source_path=str(cached.get("source_path", source_path)),
            storage_path=str(cached["storage_path"]),
        )

    try:
        result = _runner.log2timeline(
            source_path=source_path,
            storage_file=storage_path,
            parsers=parsers,
            tool_name=tool,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    if result.timed_out:
        return {
            "status": "error",
            "error": "log2timeline timed out (default 7200 s). "
                     "Pre-generate the .plaso file or increase the timeout.",
            "execution_id": result.execution_id,
        }

    if not result.ok:
        error_class = _runner.classify_error(result)
        return {
            "status": "error",
            "error": f"log2timeline failed ({error_class})",
            "stderr": result.stderr[:2000],
            "exit_code": result.exit_code,
            "execution_id": result.execution_id,
        }

    # Try to extract event count from log2timeline stdout
    # OOM mitigation - plaso stdout can run hundreds of MB; release after parse.
    event_count: str = "unknown"
    for line in result.stdout.splitlines():
        # Plaso prints something like: "Completed processing ... 1234567 events"
        m = re.search(r"(\d[\d,]+)\s+event", line, re.IGNORECASE)
        if m:
            event_count = m.group(1).replace(",", "")
            break
    if hasattr(result, "release_stdout"): result.release_stdout()

    # B.3: Validate the .plaso file with pinfo.py before claiming success.
    # log2timeline can return exit 0 yet produce a storage file with zero
    # events (empty input, all parsers failed silently, corrupted source).
    # Without this check, the @timeline-analyst would be spawned to query
    # an empty timeline and burn tokens for no value.
    pinfo_event_count: Optional[int] = None
    pinfo_error: Optional[str] = None
    try:
        pinfo_result = _runner.pinfo(storage_file=storage_path, tool_name=tool)
        if pinfo_result.ok:
            # pinfo prints "Total number of events: N" - parse it
            for line in pinfo_result.stdout.splitlines():
                m = re.search(r"Total number of events[^\d]*([\d,]+)", line, re.IGNORECASE)
                if m:
                    pinfo_event_count = int(m.group(1).replace(",", ""))
                    break
            if hasattr(pinfo_result, "release_stdout"): pinfo_result.release_stdout()  # OOM mitigation
            if pinfo_event_count is None:
                # Couldn't parse - fall back to permissive (don't block on parse failure)
                pinfo_error = "pinfo.py succeeded but event count unparseable"
        else:
            pinfo_error = (
                f"pinfo.py validation failed (exit {pinfo_result.exit_code}): "
                f"{(pinfo_result.stderr or '')[:300]}"
            )
    except Exception as exc:
        pinfo_error = f"pinfo.py invocation raised: {type(exc).__name__}: {exc}"

    if pinfo_event_count == 0:
        return {
            "status": "error",
            "error": (
                f"log2timeline produced a Plaso file with zero events at {storage_path}. "
                "Source path is empty, parsers failed silently, or the source "
                "was unreadable. Inspect log2timeline stderr and re-run."
            ),
            "storage_path": storage_path,
            "exit_code": 0,
            "execution_id": result.execution_id,
            "pinfo_validated": True,
        }

    response = {
        "status": "ok",
        "storage_path": storage_path,
        "parser_preset": parsers,
        "source_path": source_path,
        "case_id": case_id,
        "estimated_event_count": event_count,
        # B.3: pinfo-verified event count (authoritative); event_count above
        # is the log2timeline stdout-scraped value (informational only).
        "verified_event_count": pinfo_event_count,
        "pinfo_validation_error": pinfo_error,
        "duration_seconds": round(result.duration_seconds, 2),
        "execution_id": result.execution_id,
        "cache_hit": False,
        "cache_source_execution_id": None,
        "requires_agent": "@timeline-analyst",
        "agent_instruction": (
            f"Use {storage_path} to run bounded timeline queries and correlate cross-artifact activity."
            + (
                f" Pinfo reports {pinfo_event_count} events."
                if pinfo_event_count is not None
                else ""
            )
        ),
    }

    # Fix 4: Record storage_path in execution record for coverage gate
    # The gate requires storage_path field to validate timeline completion.
    # Without this, build_timeline succeeds but gate still blocks.
    _state_mgr.augment_execution(
        execution_id=result.execution_id,
        storage_path=storage_path,
    )
    _state_mgr.cache_artifact(
        cache_key,
        {
            "source_execution_id": result.execution_id,
            "storage_path": storage_path,
            "parser_preset": parsers,
            "source_path": source_path,
            "case_id": case_id,
            "estimated_event_count": event_count,
        },
    )
    return _build_timeline_contract_payload(
        response=response,
        case_id=case_id,
        source_path=source_path,
        storage_path=storage_path,
    )


# ---------------------------------------------------------------------------
# Tool 2: query_timeline
# ---------------------------------------------------------------------------


def query_timeline(
    plaso_path: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    filter_expr: Optional[str] = None,
    output_format: str = "dynamic",
) -> dict[str, Any]:
    """Query a Plaso storage file and return structured timeline events.

    Invokes ``psort.py`` on *plaso_path* with optional time-range and
    content filters.  Output is written to a temporary CSV file in
    ``./analysis/``, parsed into :class:`~sift_mcp.models.artifacts.TimelineEvent`
    dicts, and returned to the caller.

    Parameters
    ----------
    plaso_path:
        Absolute path to the ``.plaso`` storage file produced by
        :func:`build_timeline`.
    start:
        ISO-8601 lower bound for time filtering, e.g.
        ``"2026-05-01T00:00:00"``.  ``None`` means no lower bound.
    end:
        ISO-8601 upper bound for time filtering, e.g.
        ``"2026-05-31T23:59:59"``.  ``None`` means no upper bound.
    filter_expr:
        Plaso filter expression for content-based filtering, e.g.
        ``"message contains 'cmd.exe'"``.  Combined with time filters
        using ``AND``.  ``None`` means no content filter.
    output_format:
        Plaso output module name.  Defaults to ``"dynamic"`` (CSV).
        Other supported values: ``"json_line"``, ``"l2tcsv"``.

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "events": [
                {
                  "timestamp": "2026-05-01T14:23:11+00:00",
                  "source": "FILE",
                  "source_type": "...",
                  "artifact_path": "...",
                  "description": "...",
                  "extra_fields": {}
                },
                ...
              ],
              "event_count": 42,
              "plaso_path": "...",
              "execution_id": "E-002"
            }

        On error::

            {
              "status": "error",
              "error": "...",
              "stderr": "...",
              "exit_code": 1,
              "execution_id": "E-002"
            }
    """
    tool = "timeline.query_timeline"
    if _runner is None:
        return {"status": "error", "error": "Tool module not initialised — call init_tools() first."}

    # Derive a unique output CSV path in ./analysis/
    analysis_dir = Path("./analysis")
    try:
        analysis_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"status": "error", "error": f"Cannot create analysis directory: {exc}"}

    ts_tag = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
    output_csv = str((analysis_dir / f"psort_out_{ts_tag}.csv").resolve())

    try:
        result = _runner.psort(
            storage_file=plaso_path,
            output_file=output_csv,
            output_format=output_format,
            time_slice_start=start,
            time_slice_end=end,
            filter_expression=filter_expr,
            tool_name=tool,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    if result.timed_out:
        return {
            "status": "error",
            "error": "psort timed out (600 s). Try narrowing the time range.",
            "execution_id": result.execution_id,
        }

    if not result.ok:
        error_class = _runner.classify_error(result)
        return {
            "status": "error",
            "error": f"psort failed ({error_class})",
            "stderr": result.stderr[:2000],
            "exit_code": result.exit_code,
            "execution_id": result.execution_id,
        }

    # Parse the CSV output into TimelineEvent-shaped dicts
    events: list[dict[str, Any]] = []
    if os.path.exists(output_csv):
        try:
            with open(output_csv, newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    event = _csv_row_to_event(row)
                    if event:
                        events.append(event)
        except Exception as exc:
            return {
                "status": "error",
                "error": f"Failed to parse psort CSV output: {exc}",
                "execution_id": result.execution_id,
            }

    response = {
        "status": "ok",
        "events": events,
        "event_count": len(events),
        "plaso_path": plaso_path,
        "query_result_path": output_csv,
        "filters_applied": {
            "start": start,
            "end": end,
            "filter_expr": filter_expr,
        },
        "execution_id": result.execution_id,
    }
    if response["events"]:
        response["events"] = [
            sanitize_payload_fields(event, "description", "extra_fields")
            for event in response["events"]
        ]
    return _query_timeline_contract_payload(
        response=response,
        events=response["events"],
        plaso_path=plaso_path,
        output_csv=output_csv,
        start=start,
        end=end,
        filter_expr=filter_expr,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _csv_row_to_event(row: dict[str, str]) -> Optional[dict[str, Any]]:
    """Convert a raw psort CSV row to a TimelineEvent-shaped dict.

    The exact column names depend on the psort output format.  This parser
    handles the common ``dynamic`` and ``l2tcsv`` formats.

    Returns ``None`` if the row is malformed or has no timestamp.
    """
    # Normalise column names to lowercase with underscores
    normalised: dict[str, str] = {
        k.strip().lower().replace(" ", "_"): (v or "").strip()
        for k, v in row.items()
    }

    # Extract timestamp - different column names across formats
    raw_ts = (
        normalised.get("datetime")
        or normalised.get("timestamp")
        or normalised.get("date_and_time")
        or ""
    )
    if not raw_ts:
        return None

    # Attempt to parse the timestamp into an ISO-8601 string
    parsed_ts: Optional[str] = None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw_ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed_ts = dt.isoformat()
            break
        except ValueError:
            continue

    if parsed_ts is None:
        # Store raw string if we cannot parse it
        parsed_ts = raw_ts

    # Extract core fields
    source = normalised.get("source", "") or normalised.get("type", "UNKNOWN")
    source_type = normalised.get("source_long", "") or normalised.get("source_type", "")
    artifact_path = normalised.get("filename", "") or normalised.get("display_name", "")
    description = normalised.get("message", "") or normalised.get("description", "")

    # Everything else goes into extra_fields
    known_keys = {"datetime", "timestamp", "date_and_time", "source", "type",
                  "source_long", "source_type", "filename", "display_name",
                  "message", "description"}
    extra: dict[str, Any] = {
        k: v for k, v in normalised.items()
        if k not in known_keys and v
    }

    return {
        "timestamp": parsed_ts,
        "source": source,
        "source_type": source_type or None,
        "artifact_path": artifact_path or None,
        "description": description,
        "extra_fields": extra,
    }
