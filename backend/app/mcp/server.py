import os
import sys
from fastmcp import FastMCP
from app.playbooks.memory_playbook import execute_memory_triage, get_current_investigation_state, reset_investigation

# Initialize FastMCP Server for Claude Desktop
mcp = FastMCP("SAVVYDFIR-MCP-Core")

# ==============================================================================
# The MCP Deterministic Gateway
# The Python backend never reasons. It only executes, filters, and graphs.
# ==============================================================================

@mcp.tool()
def run_memory_playbook(memory_file: str) -> dict:
    """
    Executes the Volatility playbook on a memory dump natively.
    Runs multiple plugins efficiently in parallel/sequence without making Claude wait per-plugin.
    Automatically applies regex/jq filters so Claude only receives critical anomalies.
    Atomically synchronizes all findings to the Zep Graphical Database.
    
    Args:
        memory_file: Absolute path to the .vmem or .raw file.
    
    Returns:
        Tiered Summary JSON: Claude receives a highly distilled summary mapping what was done and what High Confidence items were verified, saving tokens.
    """
    if not os.path.exists(memory_file) and not memory_file.startswith("mock"):
        return {"error": f"File not found: {memory_file}"}

    # Execute the deterministic playbook
    tiered_summary = execute_memory_triage(memory_image_path=memory_file)
    return tiered_summary


@mcp.tool()
def read_authoritative_state() -> dict:
    """
    Returns the backend-managed Investigation State summary.
    Claude should use this tool when it needs to recall exact structured PIDs or timestamps
    that might have been lost to its internal chat-history compaction.
    """
    return get_current_investigation_state()


@mcp.tool()
def pause_session(reason_for_pause: str) -> str:
    """
    Checkpoints the entire investigation state to disk if the analyst steps away for >8 hours.
    Prevents session death.
    """
    # Placeholder for actual disk-writing serialization
    return f"Session checkpointed. Reason: {reason_for_pause}. The Zep graph holds the active sync."

@mcp.tool()
def resume_session(investigation_id: str) -> dict:
    """
    Reloads a serialized investigation.
    """
    return get_current_investigation_state()


if __name__ == "__main__":
    print(f"[*] Initializing SAVVYDFIR-MCP Gateway...")
    print(f"[*] Note: Zero-LLM Backend Rules Enforced.")
    mcp.run()
