#!/usr/bin/env python3
"""
PostToolUse hook: reads tool result from stdin, writes agent delegation
trigger to /tmp/savvydfir_delegate.json so CLAUDE.md rule can fire it.
Also adds requires_agent fields to memory tools output.
"""
import sys
import json
import os

# Map MCP tool → agent + instruction
TOOL_AGENT_MAP = {
    "mcp__savvydfir__extract_mft_timeline":       ("@mft-analyst",       "Analyze the MFT CSV for timestomping, attacker file drops, sequential entry clusters, and staging artifacts."),
    "mcp__savvydfir__summarize_evtx":             ("@evtx-analyst",      "Analyze the EVTX CSV for auth anomalies, lateral movement, NTLM attacks, persistence, and log clearing."),
    "mcp__savvydfir__extract_registry_run_keys":  ("@registry-analyst",  "Analyze the registry CSV for ASEP persistence, fileless malware, LSA packages, and credential theft."),
    "mcp__savvydfir__get_amcache":                ("@amcache-analyst",   "Analyze the Amcache CSV for renamed malware (SHA-1), loose executables, and BYOVD drivers."),
    "mcp__savvydfir__extract_prefetch":           ("@prefetch-analyst",  "Analyze prefetch records for multi-path execution, SysWOW64 LOLBins, and orphaned .pf files."),
    "mcp__savvydfir__detect_injection":           ("@memory-analyst",    "Analyze memory injection findings for confirmed code injection, DKOM hidden processes, and C2 indicators."),
    "mcp__savvydfir__list_dlls":                  ("@memory-analyst",    "Analyze loaded DLLs for unsigned modules, DLLs from staging paths, and unexpected network capability."),
    # New detection tools
    "mcp__savvydfir__sigma_hunt":                 ("@sigma-analyst",     "Analyze the Sigma rule hits: triage false positives, confirm ATT&CK techniques, cross-reference with existing findings. If EID 1102 (log cleared) appears in hits, call analyze_vss immediately."),
    "mcp__savvydfir__analyze_vss":                ("@evtx-analyst",      "Analyze VSS shadow copy inventory. If pre-incident shadows exist, extract Security.evtx from the closest shadow copy before the incident date and re-run summarize_evtx on the recovered log."),
    "mcp__savvydfir__extract_pca":                ("@prefetch-analyst",  "Analyze PCA execution artifacts: correlate with Amcache (via ProgramId), cross-reference timestamps with incident timeline, flag executables from staging directories."),
    # rla + shimcache + srum
    "mcp__savvydfir__extract_shimcache":          ("@registry-analyst",  "Analyze ShimCache entries: cross-reference with Amcache and Prefetch to confirm execution. Flag entries outside System32/Program Files. Absence of an expected entry indicates timestomping or binary deletion."),
    "mcp__savvydfir__extract_srum":               ("@srum-analyst",      "Analyze SRUM network usage: identify top data-sending processes by bytes_sent, flag unresolved AppIds (processes no longer on disk — anti-forensics indicator), cross-reference outbound volumes with known C2 IOCs and EVTX network connection events. Report exfiltration volume per process."),
}

def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = event.get("tool_name", "")
    tool_result = event.get("tool_result", {})

    if tool_name not in TOOL_AGENT_MAP:
        sys.exit(0)

    agent, base_instruction = TOOL_AGENT_MAP[tool_name]

    # Extract csv_path from tool result if available
    csv_path = None
    total_records = None
    if isinstance(tool_result, dict):
        # Tool result may be nested under "content"
        content = tool_result.get("content", tool_result)
        if isinstance(content, list) and content:
            try:
                data = json.loads(content[0].get("text", "{}"))
            except Exception:
                data = {}
        elif isinstance(content, dict):
            data = content
        else:
            data = {}
        csv_path = data.get("csv_path")
        total_records = data.get("total_records", data.get("records_count"))

    instruction = base_instruction
    if csv_path:
        instruction += f" CSV at: {csv_path}"
        if total_records:
            instruction += f" ({total_records} total rows)"

    trigger = {
        "agent": agent,
        "tool": tool_name,
        "instruction": instruction,
        "csv_path": csv_path,
        "processed": False
    }

    # Write trigger file
    trigger_path = "/tmp/savvydfir_delegate.json"
    try:
        with open(trigger_path, "w") as f:
            json.dump(trigger, f, indent=2)
    except Exception as e:
        pass

    # Output message to Claude's context — Claude Code displays hook stdout
    print(json.dumps({
        "message": f"SAVVYDFIR HOOK: {tool_name} completed. MANDATORY: invoke {agent} before proceeding. Instruction: {instruction}"
    }))

if __name__ == "__main__":
    main()
