#!/usr/bin/env python3
"""Post-tool-use hook: validates MCP tool output and suggests auto-fixes."""
import json, sys

def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    output = data.get("tool_output", "")

    # Log to hooks.log
    try:
        with open("/cases/hooks.log", "a") as f:
            f.write(f"[{tool_name}] input={json.dumps(tool_input)[:200]}\n")
    except OSError:
        pass

    # Check for common errors in output
    if isinstance(output, str):
        output_lower = output.lower()
        error_patterns = {
            "not found": f"Tool output contains 'not found'. Check paths and tool availability.",
            "permission denied": "Permission denied. Check RBAC path model: evidence paths are read-only.",
            "timed out": "Tool timed out. Try with smaller dataset or increase timeout.",
            "no such file": "File not found. Verify evidence is mounted and paths are correct.",
        }
        for pattern, suggestion in error_patterns.items():
            if pattern in output_lower:
                result = {"decision": "block", "reason": suggestion}
                print(json.dumps(result))
                return

    # If sigma_scan found critical hits, suggest immediate investigation
    if tool_name == "sigma_scan" and isinstance(output, str):
        try:
            result_data = json.loads(output)
            if result_data.get("critical_count", 0) > 0:
                print(json.dumps({
                    "decision": "allow",
                    "reason": f"CRITICAL anomalies detected ({result_data['critical_count']}). Investigate immediately."
                }))
                return
        except (json.JSONDecodeError, TypeError):
            pass

if __name__ == "__main__":
    main()
