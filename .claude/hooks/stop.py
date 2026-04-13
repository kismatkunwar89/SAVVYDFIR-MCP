#!/usr/bin/env python3
"""Stop hook: ensures investigation is complete before ending session."""
import json, sys, os

def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        return

    # Check if generate_report was called
    stop_reason = data.get("stop_reason", "")
    transcript = data.get("transcript", "")

    warnings = []

    if isinstance(transcript, str):
        if "generate_report" not in transcript:
            warnings.append("generate_report() was not called. Investigation may be incomplete.")
        if "sigma_scan" not in transcript:
            warnings.append("sigma_scan() was not called. Universal anomaly detection was skipped.")
        if "compare_disk_and_memory" not in transcript:
            warnings.append("compare_disk_and_memory() was not called. Cross-artifact correlation was skipped.")

    if warnings:
        result = {
            "decision": "block",
            "reason": "Investigation incomplete: " + "; ".join(warnings)
        }
        print(json.dumps(result))
    else:
        print(json.dumps({"decision": "allow"}))

if __name__ == "__main__":
    main()
