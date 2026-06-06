#!/usr/bin/env bash
# ============================================================
# run-case.sh — investigation launch wrapper with auto agent-trace
# ============================================================
# Consensus C+D (peer reviewer+peer reviewer, 2026-06-06): the agent-session trace
# (reports/<case_id>/trace.html) must be produced for EVERY run, but
# render_session_trace.py is deliberately NOT auto-fired from generate_report
# (a render/redaction failure must not poison the report). This wrapper closes
# that gap WITHOUT touching the MCP server:
#   1. launch claude for the investigation
#   2. after claude EXITS (trace is only final post-session), resolve the
#      session JSONL (newest jsonl modified during this run — deterministic on a
#      single-run-at-a-time host; fail loud if none/ambiguous)
#   3. render the trace (best-effort; never blocks)
#   4. refresh generate_report so the "Agent Session Trace" link surfaces
#
# LEAK GUARD (consensus): redaction is best-effort + --detail low. EYEBALL the
# trace before publishing/serving it externally. reports/<case>/ is NOT auto-
# served by the framework's http server (that serves an explicit dir).
#
# Usage:
#   ./scripts/run-case.sh                       # default investigate prompt
#   ./scripts/run-case.sh "Read case-templates/manifest.json and investigate."
#   REPO=/path/to/repo ./scripts/run-case.sh    # override repo root
# ============================================================
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PY="${PY:-$REPO/venv/bin/python}"
[ -x "$PY" ] || PY="$REPO/.venv/bin/python"
PROMPT="${1:-Read case-templates/manifest.json and investigate.}"
PROJ_ROOT="$HOME/.claude/projects"

cd "$REPO" || { echo "[run-case] ERROR: cannot cd $REPO"; exit 2; }

START=$(date +%s)
echo "[run-case] launch @ $(date -u +%FT%TZ) — prompt: $PROMPT"
claude --allowedTools "mcp__savvydfir__*" --dangerously-skip-permissions -p "$PROMPT"
RC=$?
echo "[run-case] claude exited rc=$RC"

# --- resolve case_id from state ---
CASE=$("$PY" -c "import json;print(json.load(open('analysis/state.json')).get('case_id',''))" 2>/dev/null)
if [ -z "$CASE" ]; then echo "[run-case] ERROR: no case_id in analysis/state.json — trace skipped"; exit 3; fi

# --- resolve session jsonl: jsonl(s) modified during this run ---
mapfile -t SJS < <(find "$PROJ_ROOT" -name '*.jsonl' -newermt "@$START" -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-)
if [ "${#SJS[@]}" -eq 0 ]; then echo "[run-case] WARN: no session jsonl modified during run — trace NOT generated (trace_status stays not_generated)"; exit 0; fi
if [ "${#SJS[@]}" -gt 1 ]; then echo "[run-case] WARN: ${#SJS[@]} session jsonls touched during run — using newest (verify): ${SJS[0]}"; fi
SJ="${SJS[0]}"
echo "[run-case] case=$CASE  session=$SJ"

# --- render trace (best-effort; never blocks the pipeline) ---
if "$PY" scripts/render_session_trace.py --case-id "$CASE" --session-jsonl "$SJ"; then
  echo "[run-case] trace rendered: reports/$CASE/trace.html"
else
  echo "[run-case] WARN: trace render failed (claude-code-log installed? pip install claude-code-log==1.3.0)"
fi

# --- refresh report so the trace link surfaces ---
"$PY" -c "from sift_mcp import server; fn=getattr(server.generate_report,'fn',server.generate_report); print('[run-case] report refresh:', fn('$CASE', allow_partial=True).get('status'))" || echo "[run-case] WARN: report refresh failed"

echo "[run-case] DONE — EYEBALL reports/$CASE/trace.html before publishing (redaction is best-effort)."
