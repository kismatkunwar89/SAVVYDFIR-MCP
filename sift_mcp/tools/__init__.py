"""
sift_mcp.tools
~~~~~~~~~~~~~~

Public re-export of all MCP tool functions and their ``init_tools`` hooks.

Tool modules
------------
Each sub-module owns a set of semantically-named tool functions that wrap
one or more SIFT forensic CLI tools.  All tool functions are synchronous
(``subprocess.run()``-based).

Namespaces
----------
* **evidence** — :mod:`sift_mcp.tools.evidence`
  ``verify_integrity``, ``get_provenance``

* **disk** — :mod:`sift_mcp.tools.disk`
  ``extract_prefetch``, ``get_amcache``, ``extract_mft_timeline``,
  ``list_deleted_files``, ``summarize_evtx``, ``extract_registry_run_keys``

* **memory** — :mod:`sift_mcp.tools.memory` *(loaded if available)*
  ``detect_profile``, ``list_processes``, ``scan_processes``,
  ``scan_network``, ``detect_injection``, ``list_dlls``

* **timeline** — :mod:`sift_mcp.tools.timeline`
  ``build_timeline``, ``query_timeline``

* **yara** — :mod:`sift_mcp.tools.yara`
  ``scan_files``, ``scan_memory``

* **correlation** — :mod:`sift_mcp.tools.correlation`
  ``compare_disk_and_memory``, ``flag_discrepancy``

* **state** — :mod:`sift_mcp.tools.state_tools`
  ``read_state``, ``export_trace``

Usage
-----
::

    from sift_mcp.tools import (
        verify_integrity, get_provenance,
        extract_prefetch, get_amcache,
        build_timeline, query_timeline,
        scan_files, scan_memory,
        compare_disk_and_memory, flag_discrepancy,
        read_state, export_trace,
    )
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Evidence tools
# ---------------------------------------------------------------------------

from sift_mcp.tools.evidence import (
    verify_integrity,
    get_provenance,
)
from sift_mcp.tools.evidence import init_tools as _init_evidence

# ---------------------------------------------------------------------------
# Disk tools
# ---------------------------------------------------------------------------

from sift_mcp.tools.disk import (
    extract_prefetch,
    get_amcache,
    extract_mft_timeline,
    list_deleted_files,
    summarize_evtx,
    extract_registry_run_keys,
)
from sift_mcp.tools.disk import init_tools as _init_disk

# ---------------------------------------------------------------------------
# Memory tools (optional — module may not exist yet)
# ---------------------------------------------------------------------------

try:
    from sift_mcp.tools.memory import (  # type: ignore[import]
        detect_profile,
        list_processes,
        scan_processes,
        scan_network,
        detect_injection,
        list_dlls,
    )
    from sift_mcp.tools.memory import init_tools as _init_memory  # type: ignore[import]
    _HAS_MEMORY = True
except ImportError:
    _HAS_MEMORY = False

    def detect_profile(*args, **kwargs):  # type: ignore[misc]
        return {"status": "error", "error": "memory tool module not available"}

    def list_processes(*args, **kwargs):  # type: ignore[misc]
        return {"status": "error", "error": "memory tool module not available"}

    def scan_processes(*args, **kwargs):  # type: ignore[misc]
        return {"status": "error", "error": "memory tool module not available"}

    def scan_network(*args, **kwargs):  # type: ignore[misc]
        return {"status": "error", "error": "memory tool module not available"}

    def detect_injection(*args, **kwargs):  # type: ignore[misc]
        return {"status": "error", "error": "memory tool module not available"}

    def list_dlls(*args, **kwargs):  # type: ignore[misc]
        return {"status": "error", "error": "memory tool module not available"}

    def _init_memory(*args, **kwargs):  # type: ignore[misc]
        pass

# ---------------------------------------------------------------------------
# Timeline tools
# ---------------------------------------------------------------------------

from sift_mcp.tools.timeline import (
    build_timeline,
    query_timeline,
)
from sift_mcp.tools.timeline import init_tools as _init_timeline

# ---------------------------------------------------------------------------
# YARA tools
# ---------------------------------------------------------------------------

from sift_mcp.tools.yara import (
    scan_files,
    scan_memory,
)
from sift_mcp.tools.yara import init_tools as _init_yara

# ---------------------------------------------------------------------------
# Correlation tools
# ---------------------------------------------------------------------------

from sift_mcp.tools.correlation import (
    compare_disk_and_memory,
    flag_discrepancy,
)
from sift_mcp.tools.correlation import init_tools as _init_correlation

# ---------------------------------------------------------------------------
# State tools
# ---------------------------------------------------------------------------

from sift_mcp.tools.state_tools import (
    read_state,
    export_trace,
)
from sift_mcp.tools.state_tools import init_tools as _init_state

# ---------------------------------------------------------------------------
# Bulk initialiser
# ---------------------------------------------------------------------------


def init_all_tools(audit_logger, state_manager) -> None:
    """Initialise every tool module with the shared audit and state instances.

    Called once at server startup by :mod:`sift_mcp.server`.

    W1.7 (Run 2 consensus 2026-05-24, peer reviewer Q1+C / peer reviewer amendment): also
    register runtime deps with sift_mcp.tools._contracts so the CONTRACT
    path (build_contract_response → _attach_heuristic_slice) has live
    singletons WITHOUT a lazy ``from sift_mcp.server import ...``. The
    lazy-import pattern caused Run 2's BUG-4 (silent state-write loss
    on 5 of 8 heuristic injections).

    Parameters
    ----------
    audit_logger:
        The process-wide :class:`~sift_mcp.audit.AuditLogger`.
    state_manager:
        The process-wide :class:`~sift_mcp.state.CaseStateManager`.
    """
    # W1.7 BUG-4 fix — register before per-module init so any tool
    # invoked during init can already use heuristic injection cleanly.
    from sift_mcp.tools._contracts import set_runtime_deps
    set_runtime_deps(state_manager=state_manager, audit_logger=audit_logger)

    _init_evidence(state_manager=state_manager, audit_logger=audit_logger)
    _init_disk(state_manager=state_manager, audit_logger=audit_logger)
    _init_memory(audit_logger=audit_logger, state_manager=state_manager)
    _init_timeline(audit_logger=audit_logger, state_manager=state_manager)
    _init_yara(audit_logger=audit_logger, state_manager=state_manager)
    _init_correlation(audit_logger=audit_logger, state_manager=state_manager)
    _init_state(audit_logger=audit_logger, state_manager=state_manager)


__all__ = [
    # Evidence
    "verify_integrity",
    "get_provenance",
    # Disk
    "extract_prefetch",
    "get_amcache",
    "extract_mft_timeline",
    "list_deleted_files",
    "summarize_evtx",
    "extract_registry_run_keys",
    # Memory
    "detect_profile",
    "list_processes",
    "scan_processes",
    "scan_network",
    "detect_injection",
    "list_dlls",
    # Timeline
    "build_timeline",
    "query_timeline",
    # YARA
    "scan_files",
    "scan_memory",
    # Correlation
    "compare_disk_and_memory",
    "flag_discrepancy",
    # State
    "read_state",
    "export_trace",
    # Init
    "init_all_tools",
]
