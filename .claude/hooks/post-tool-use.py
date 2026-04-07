#!/usr/bin/env python3
"""Post-tool-use hook for SAVVYDFIR-MCP.

Fires after every MCP tool call to:
- Suggest fixes if output contains errors
- Warn if output is empty (possible mount issue)
- Log every tool call to /cases/hooks.log
"""

import json
import os
import sys
from datetime import datetime, timezone


def main():
    hook_input = json.loads(sys.stdin.read())

    tool_name = hook_input.get("tool_name", "unknown")
    tool_input = hook_input.get("tool_input", {})
    tool_output = hook_input.get("tool_output", "")

    output_str = str(tool_output).lower() if tool_output else ""

    # Log every tool call
    log_dir = os.environ.get("OUTPUT_BASE", "/cases")
    log_path = os.path.join(log_dir, "hooks.log")
    try:
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        with open(log_path, "a") as f:
            f.write(f"{timestamp} | {tool_name} | input={json.dumps(tool_input)[:200]}\n")
    except OSError:
        pass

    # Check for errors in output
    if "error" in output_str or "failed" in output_str:
        suggestions = []
        if "no such file" in output_str or "not found" in output_str:
            suggestions.append("Check if evidence is mounted: ls /mnt/evidence/")
            suggestions.append("Verify the file path exists and is accessible")
        if "permission denied" in output_str:
            suggestions.append("Check mount permissions -- evidence should be mounted read-only")
        if "unsupported" in output_str or "invalid" in output_str:
            suggestions.append("Check if the file is compressed/zipped: file <path>")
            suggestions.append("Try extracting with: 7z x <file> -o<output_dir>")
        if "volatility" in output_str or "vol3" in output_str:
            suggestions.append("Verify memory dump is extracted (not still zipped)")
            suggestions.append("Check: file /evidence/memory/*.raw")
        if suggestions:
            print("HOOK: Tool output contains errors. Suggestions:")
            for s in suggestions:
                print(f"  - {s}")

    # Check for empty output
    if not output_str.strip() or output_str.strip() in ('""', '{}', '[]', 'none'):
        print("HOOK: Tool returned empty output. Check:")
        print("  - Is evidence mounted? Run: ls /mnt/evidence/")
        print("  - Is the disk image mounted? Run: mount | grep evidence")
        print("  - Is the file path correct?")


if __name__ == "__main__":
    main()
