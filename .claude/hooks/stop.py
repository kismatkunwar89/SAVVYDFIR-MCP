#!/usr/bin/env python3
"""Stop hook for SAVVYDFIR-MCP.

Fires when Claude wants to stop the session. Checks if generate_report
was called during the investigation.
"""

import json
import os
import sys


def main():
    hook_input = json.loads(sys.stdin.read())

    # Check the hooks log to see if generate_report was called
    log_dir = os.environ.get("OUTPUT_BASE", "/cases")
    log_path = os.path.join(log_dir, "hooks.log")

    report_called = False
    try:
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                for line in f:
                    if "generate_report" in line or "generate_narrative" in line or "export_trace" in line:
                        report_called = True
                        break
    except OSError:
        pass

    # Also check if reports directory has any output
    reports_dir = os.path.join(log_dir, "reports")
    analysis_dir = os.path.join(log_dir, "analysis")
    has_report_files = False
    for d in [reports_dir, analysis_dir]:
        if os.path.isdir(d) and os.listdir(d):
            has_report_files = True
            break

    if not report_called and not has_report_files:
        print("WARNING: Investigation incomplete -- call generate_report before stopping.")
        print("The investigation should produce:")
        print("  - ./reports/narrative.md (investigation narrative)")
        print("  - ./analysis/findings.json (structured findings)")
        print("  - ./analysis/audit.jsonl (execution trace)")


if __name__ == "__main__":
    main()
