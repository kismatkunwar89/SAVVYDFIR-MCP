#!/bin/bash
# serve_graph.sh — Regenerate and serve the SAVVYDFIR-MCP investigation graph.
#
# Usage:
#   cd /cases/SRL-2018-WKSTN-01/  # or any case working directory
#   bash /path/to/savvydfir-mcp/scripts/serve_graph.sh
#
# The script regenerates graph.html from the current state.json and audit.jsonl,
# then starts a local HTTP server so you can open the report in a browser.
#
# Requirements:
#   - python3 in PATH
#   - ./analysis/state.json  (written by the MCP server)
#   - ./analysis/audit.jsonl (written by the MCP server)
#
# Optional environment variables:
#   SAVVYDFIR_PORT   TCP port to serve on (default: 8080)
#   SAVVYDFIR_STATE  Override path to state.json
#   SAVVYDFIR_AUDIT  Override path to audit.jsonl
#   SAVVYDFIR_OUT    Override path for graph.html output

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths relative to the script's own location so this script can be
# called from any working directory.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Configurable paths (override via environment variables)
# ---------------------------------------------------------------------------
PORT="${SAVVYDFIR_PORT:-8080}"
STATE_PATH="${SAVVYDFIR_STATE:-./analysis/state.json}"
AUDIT_PATH="${SAVVYDFIR_AUDIT:-./analysis/audit.jsonl}"
OUTPUT_PATH="${SAVVYDFIR_OUT:-./reports/graph.html}"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if [[ ! -f "$STATE_PATH" ]]; then
  echo "ERROR: state.json not found at: $STATE_PATH" >&2
  echo "       Run the SAVVYDFIR-MCP server on a case first, or set SAVVYDFIR_STATE." >&2
  exit 1
fi

if [[ ! -f "$AUDIT_PATH" ]]; then
  echo "ERROR: audit.jsonl not found at: $AUDIT_PATH" >&2
  echo "       Run the SAVVYDFIR-MCP server on a case first, or set SAVVYDFIR_AUDIT." >&2
  exit 1
fi

# Ensure the reports directory exists
REPORT_DIR="$(dirname "$OUTPUT_PATH")"
mkdir -p "$REPORT_DIR"

# ---------------------------------------------------------------------------
# Generate the graph
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         SAVVYDFIR-MCP  —  Investigation Graph Builder       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  State file : $STATE_PATH"
echo "  Audit file : $AUDIT_PATH"
echo "  Output     : $OUTPUT_PATH"
echo ""

python3 "$SCRIPT_DIR/investigation_graph.py" \
  --state  "$STATE_PATH"  \
  --audit  "$AUDIT_PATH"  \
  --output "$OUTPUT_PATH"

echo ""
echo "Graph generated at $OUTPUT_PATH"
echo ""

# ---------------------------------------------------------------------------
# Start HTTP server
# ---------------------------------------------------------------------------
ABS_REPORT_DIR="$(cd "$REPORT_DIR" && pwd)"
ABS_OUTPUT="$(cd "$REPORT_DIR" && pwd)/$(basename "$OUTPUT_PATH")"

echo "Serving at http://localhost:${PORT}"
echo "Open your browser to:"
echo "  http://localhost:${PORT}/$(basename "$OUTPUT_PATH")"
echo ""
echo "Press Ctrl+C to stop."
echo ""

cd "$ABS_REPORT_DIR"
exec python3 -m http.server "$PORT"
