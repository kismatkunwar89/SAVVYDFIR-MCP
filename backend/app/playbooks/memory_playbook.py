from app.models.state import InvestigationState
from app.parsers.volatility_parser import parse_pslist, parse_malfind

# A mock singleton to hold our current running state across MCP bounds natively
_GLOBAL_STATE = InvestigationState()

def execute_memory_triage(memory_image_path: str) -> dict:
    """
    The Macro-Tool Orchestrator. Completely deterministic. No OpenAI keys allowed.
    Claude calls this once, and the backend handles the multi-step Volatility execution.
    """
    print(f"[*] Starting Deterministic Memory Playbook on {memory_image_path}...")
    
    # 1. Execute Volatility pslist (Simulated subprocess.run)
    pslist_raw_output = "PID 4420 svchost.exe AppData"
    
    # 2. Extract heuristics (Regex/JQ filter equivalent)
    pslist_findings = parse_pslist(pslist_raw_output)
    for f in pslist_findings:
        _GLOBAL_STATE.append_finding(f)
        
    # 3. If suspicious PIDs found, run malfind natively (Parallel possible here)
    if pslist_findings:
        malfind_raw_output = "PID 4420 PAGE_EXECUTE_READWRITE MZ header"
        malfind_findings = parse_malfind(malfind_raw_output)
        for f in malfind_findings:
            _GLOBAL_STATE.append_finding(f)
            
    # Mark playbook complete
    _GLOBAL_STATE.executed_playbooks.append(f"MemoryTriage({memory_image_path})")
    
    # Send the Tiered Summary back to Claude (Context Preservation)
    return _GLOBAL_STATE.to_tiered_summary()

def get_current_investigation_state() -> dict:
    """
    MCP Explicit Checkpoint Getter.
    """
    return _GLOBAL_STATE.to_tiered_summary()

def reset_investigation():
    global _GLOBAL_STATE
    _GLOBAL_STATE = InvestigationState()
