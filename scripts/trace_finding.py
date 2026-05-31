#!/usr/bin/env python3
"""
trace_finding.py - Trace a finding ID to its full provenance chain.

Reads from:
  ./analysis/audit.jsonl   (execution records, one JSON line each)
  ./analysis/state.json    (or findings.json - final finding state)

Usage:
  python3 scripts/trace_finding.py <finding_id>
  python3 scripts/trace_finding.py F-004
  python3 scripts/trace_finding.py F-004 --audit /cases/MY-CASE/analysis/audit.jsonl
  python3 scripts/trace_finding.py F-004 --state /cases/MY-CASE/analysis/state.json

Options:
  --audit PATH    Path to audit.jsonl  (default: ./analysis/audit.jsonl)
  --state PATH    Path to state.json or findings.json (default: ./analysis/state.json,
                  falls back to ./analysis/findings.json)
  --verbose       Show full raw parameters and outputs_summary for each execution
  --no-color      Disable colored output

Copyright (c) 2026 Kismat Kunwar - MIT License
"""

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
def _has_color(no_color: bool) -> bool:
    if no_color:
        return False
    return sys.stdout.isatty()


class Colors:
    def __init__(self, enabled: bool):
        if enabled:
            self.BOLD   = "\033[1m"
            self.RESET  = "\033[0m"
            self.GREEN  = "\033[32m"
            self.YELLOW = "\033[33m"
            self.RED    = "\033[31m"
            self.CYAN   = "\033[36m"
            self.ORANGE = "\033[38;5;208m"
            self.GRAY   = "\033[90m"
        else:
            self.BOLD = self.RESET = self.GREEN = self.YELLOW = ""
            self.RED = self.CYAN = self.ORANGE = self.GRAY = ""


# ---------------------------------------------------------------------------
# Evidence kind colors
# ---------------------------------------------------------------------------
EVIDENCE_KIND_COLORS = {
    "observation": "GREEN",
    "inference":   "YELLOW",
    "hypothesis":  "ORANGE",
    "rejected":    "RED",
}


def color_evidence_kind(kind: str, c: Colors) -> str:
    attr = EVIDENCE_KIND_COLORS.get(kind.lower(), "RESET")
    color_code = getattr(c, attr, c.RESET)
    return f"{c.BOLD}{color_code}{kind.upper()}{c.RESET}"


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------
def load_audit(path: Path) -> list[dict]:
    """Load all entries from audit.jsonl."""
    if not path.exists():
        print(f"ERROR: audit file not found: {path}", file=sys.stderr)
        sys.exit(1)
    entries = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(
                    f"WARNING: Skipping malformed JSON on line {lineno} of {path}: {e}",
                    file=sys.stderr,
                )
    return entries


def load_state(state_path: Path, findings_path: Path) -> dict | None:
    """Load case state or findings.json. Returns None if neither exists."""
    for path in (state_path, findings_path):
        if path.exists():
            with path.open(encoding="utf-8") as f:
                return json.load(f)
    return None


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------
def find_executions_for_finding(
    audit_entries: list[dict], finding_id: str
) -> list[dict]:
    """Return all audit entries that generated or reference this finding_id."""
    results = []
    for entry in audit_entries:
        generated = entry.get("finding_ids_generated") or []
        if finding_id in generated:
            results.append(entry)
    return results


def find_correction_references(
    audit_entries: list[dict], finding_id: str
) -> list[tuple[dict, dict]]:
    """Return (entry, correction_event) pairs where the finding_id appears in
    correction_event.affected_finding_ids."""
    results = []
    for entry in audit_entries:
        ce = entry.get("correction_event")
        if ce and finding_id in (ce.get("affected_finding_ids") or []):
            results.append((entry, ce))
    return results


def find_finding_record(state: dict | None, finding_id: str) -> dict | None:
    """Locate the finding record in state.json or findings.json."""
    if state is None:
        return None

    # state.json: {"findings": [...]}
    if isinstance(state, dict):
        findings_list = state.get("findings", [])
        if isinstance(findings_list, list):
            for f in findings_list:
                if isinstance(f, dict) and f.get("finding_id") == finding_id:
                    return f

    # findings.json may be a bare list
    if isinstance(state, list):
        for f in state:
            if isinstance(f, dict) and f.get("finding_id") == finding_id:
                return f

    return None


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
def print_separator(c: Colors, char: str = "─", width: int = 72) -> None:
    print(f"{c.GRAY}{char * width}{c.RESET}")


def print_finding_header(finding: dict | None, finding_id: str, c: Colors) -> None:
    print()
    print_separator(c, "═")
    if finding:
        kind = finding.get("evidence_kind", "unknown")
        confidence = finding.get("confidence")
        conf_str = f"  confidence={confidence:.2f}" if confidence is not None else ""
        kind_colored = color_evidence_kind(kind, c)
        print(
            f"  {c.BOLD}Finding:{c.RESET} {c.CYAN}{finding_id}{c.RESET}  "
            f"[{kind_colored}]{conf_str}"
        )
        if finding.get("finding_type"):
            print(f"  {c.BOLD}Type:{c.RESET}    {finding['finding_type']}")
        if finding.get("description"):
            print(f"  {c.BOLD}Desc:{c.RESET}    {finding['description']}")
        if finding.get("mitre_tactic") or finding.get("mitre_technique"):
            tactic = finding.get("mitre_tactic", "")
            technique = finding.get("mitre_technique", "")
            print(f"  {c.BOLD}MITRE:{c.RESET}   {tactic} / {technique}")
        if finding.get("artifact_path"):
            print(f"  {c.BOLD}Artifact:{c.RESET} {finding['artifact_path']}", end="")
            if finding.get("artifact_offset"):
                print(f"  @ {finding['artifact_offset']}", end="")
            print()
        corroborated = finding.get("corroborated_by") or []
        contradicted = finding.get("contradicted_by") or []
        if corroborated:
            print(f"  {c.BOLD}Corroborated by:{c.RESET} {', '.join(corroborated)}")
        if contradicted:
            print(
                f"  {c.BOLD}{c.RED}Contradicted by:{c.RESET} "
                f"{c.RED}{', '.join(contradicted)}{c.RESET}"
            )
    else:
        print(f"  {c.BOLD}Finding:{c.RESET} {c.CYAN}{finding_id}{c.RESET}  "
              f"{c.GRAY}(not found in state — showing audit log only){c.RESET}")
    print_separator(c, "═")


def print_execution(entry: dict, idx: int, total: int, c: Colors, verbose: bool) -> None:
    eid = entry.get("execution_id", "?")
    tool = entry.get("tool", "?")
    ts = entry.get("timestamp", "?")
    duration = entry.get("duration_seconds", "?")
    exit_code = entry.get("exit_code", "?")
    stdout_lines = entry.get("stdout_lines", "?")
    command = entry.get("command_line", "(not recorded)")
    agent_turn = entry.get("agent_turn", "?")
    iteration = entry.get("iteration", "?")
    outputs_summary = entry.get("outputs_summary", "")
    agent_reason = entry.get("agent_reason", "")

    exit_color = c.GREEN if exit_code == 0 else c.RED

    print()
    print(
        f"  {c.BOLD}Execution {idx}/{total}:{c.RESET}  "
        f"{c.CYAN}{eid}{c.RESET}  "
        f"(turn {agent_turn}, iter {iteration})"
    )
    print(f"  {c.BOLD}Tool:{c.RESET}      {tool}")
    print(f"  {c.BOLD}Time:{c.RESET}      {ts}  ({duration}s)")
    print(
        f"  {c.BOLD}Exit code:{c.RESET} "
        f"{exit_color}{exit_code}{c.RESET}  "
        f"({stdout_lines} output lines)"
    )
    print(f"  {c.BOLD}Command:{c.RESET}   {c.GRAY}{command}{c.RESET}")
    if agent_reason:
        print(f"  {c.BOLD}Reason:{c.RESET}    {agent_reason}")
    if outputs_summary and verbose:
        print(f"  {c.BOLD}Summary:{c.RESET}   {outputs_summary}")
    if verbose and entry.get("parameters"):
        try:
            params_str = json.dumps(entry["parameters"], indent=4)
            indented = "\n".join("    " + line for line in params_str.splitlines())
            print(f"  {c.BOLD}Parameters:{c.RESET}\n{c.GRAY}{indented}{c.RESET}")
        except Exception:
            pass


def print_correction(entry: dict, ce: dict, idx: int, c: Colors) -> None:
    eid = entry.get("execution_id", "?")
    tool = entry.get("tool", "?")
    ts = entry.get("timestamp", "?")
    prior = ce.get("prior_claim", "?")
    source = ce.get("contradiction_source", "?")
    revised = ce.get("revised_claim", "?")
    affected = ce.get("affected_finding_ids") or []
    delta = ce.get("confidence_delta", "?")
    ctype = ce.get("correction_type", "?")

    delta_str = ""
    if isinstance(delta, (int, float)):
        sign = "+" if delta >= 0 else ""
        delta_str = f"{sign}{delta:.2f}"
    else:
        delta_str = str(delta)

    print()
    print(
        f"  {c.BOLD}{c.RED}CORRECTION EVENT {idx}:{c.RESET}  "
        f"(via {c.CYAN}{eid}{c.RESET} — {tool}  @ {ts})"
    )
    print(f"  {c.BOLD}Type:{c.RESET}        {ctype}")
    print(f"  {c.BOLD}Source:{c.RESET}      {source}")
    print(f"  {c.BOLD}Affected:{c.RESET}    {', '.join(affected)}")
    print(f"  {c.BOLD}Prior claim:{c.RESET}")
    print(f"      {c.YELLOW}{prior}{c.RESET}")
    print(f"  {c.BOLD}Revised claim:{c.RESET}")
    print(f"      {c.GREEN}{revised}{c.RESET}")
    print(f"  {c.BOLD}Confidence Δ:{c.RESET} {delta_str}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Trace a finding ID to its full provenance chain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "finding_id",
        help="Finding ID to trace, e.g. F-004",
    )
    parser.add_argument(
        "--audit",
        type=Path,
        default=None,
        help="Path to audit.jsonl (default: ./analysis/audit.jsonl)",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=None,
        help="Path to state.json or findings.json (default: ./analysis/state.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full parameters and output summaries",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    args = parser.parse_args()
    c = Colors(enabled=_has_color(args.no_color))

    # Resolve paths
    audit_path = args.audit or Path("./analysis/audit.jsonl")
    state_path = args.state or Path("./analysis/state.json")
    findings_path = Path("./analysis/findings.json")

    # Load data
    audit_entries = load_audit(audit_path)
    state = load_state(state_path, findings_path)

    finding_id = args.finding_id.strip()
    if not finding_id:
        print("ERROR: finding_id is required.", file=sys.stderr)
        sys.exit(1)

    # Find executions that generated this finding
    executions = find_executions_for_finding(audit_entries, finding_id)

    # Find correction events that reference this finding
    corrections = find_correction_references(audit_entries, finding_id)

    # Find the finding record in state
    finding_record = find_finding_record(state, finding_id)

    # Print header
    print_finding_header(finding_record, finding_id, c)

    if not executions and not corrections:
        print(
            f"\n  {c.RED}Finding '{finding_id}' was not found in {audit_path}.{c.RESET}",
            file=sys.stderr,
        )
        print(
            f"  Check that the finding_id is correct and the audit file is complete.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # Print executions
    if executions:
        print(
            f"\n  {c.BOLD}Producing executions ({len(executions)}):{c.RESET}"
        )
        print_separator(c)
        for idx, entry in enumerate(executions, 1):
            print_execution(entry, idx, len(executions), c, args.verbose)
    else:
        print(
            f"\n  {c.GRAY}No producing execution found in audit log "
            f"(finding may have been generated outside the audit scope).{c.RESET}"
        )

    # Print corrections
    if corrections:
        print()
        print_separator(c)
        print(
            f"\n  {c.BOLD}{c.RED}Correction events affecting this finding "
            f"({len(corrections)}):{c.RESET}"
        )
        print_separator(c)
        for idx, (entry, ce) in enumerate(corrections, 1):
            print_correction(entry, ce, idx, c)
    else:
        print(
            f"\n  {c.GRAY}No correction events affected this finding.{c.RESET}"
        )

    print()
    print_separator(c)
    print(
        f"\n  Source: {c.CYAN}{audit_path}{c.RESET}  "
        f"({len(audit_entries)} entries)"
    )
    if finding_record is None and state is None:
        print(
            f"  {c.GRAY}State file not found at {state_path} or {findings_path} — "
            f"run investigation to generate it.{c.RESET}"
        )
    print()


if __name__ == "__main__":
    main()
