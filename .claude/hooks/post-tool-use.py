#!/usr/bin/env python3
"""PostToolUse hook — validates MCP tool output and suggests fixes."""
import json, sys, os
from datetime import datetime

def main():
    hook_data = json.load(sys.stdin)
    tool_name = hook_data.get("tool_name", "")
    tool_output = str(hook_data.get("tool_response", ""))
    log_path = "/cases/hooks.log"

    os.makedirs("/cases", exist_ok=True)

    with open(log_path, "a") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] {tool_name}: {tool_output[:200]}\n")

    suggestions = []

    if any(err in tool_output.lower() for err in ["error", "failed", "not found", "no such file"]):
        if "ewf" in tool_output.lower() or "mount" in tool_output.lower():
            suggestions.append("Check if E01 is mounted: ls /mnt/evidence/ -- if empty, run ewfmount first")
        if "vol3" in tool_output.lower() or "volatility" in tool_output.lower():
            suggestions.append("Check if memory dump is extracted from ZIP -- run: file /evidence/memory/extracted/*")
        if "permission" in tool_output.lower():
            suggestions.append("Evidence directory is read-only by design -- write output to /cases/ instead")

    if not tool_output.strip() and tool_name not in ["generate_report"]:
        suggestions.append("Empty output -- verify evidence path exists and is accessible")

    if suggestions:
        print("\nAuto-fix suggestions:")
        for s in suggestions:
            print(f"  -> {s}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
