#!/usr/bin/env python3
"""Stop hook — ensures investigation is complete before ending session."""
import json, sys, os

def main():
    hook_data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    report_path = "/cases/report.json"

    if not os.path.exists(report_path):
        print("\nINVESTIGATION INCOMPLETE")
        print("No report found at /cases/report.json")
        print("Before stopping, call the 'generate_report' MCP tool to document findings.")
        print("Type 'continue' to resume the investigation.\n")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
