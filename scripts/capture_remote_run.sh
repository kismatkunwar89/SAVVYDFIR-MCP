#!/usr/bin/env bash
# Capture a remote SAVVYDFIR-MCP investigation run for post-hoc analysis.
#
# Pulls:
#   - Claude Code session JSONL (most-recent) from remote ~/.claude/projects/
#   - analysis/state.json
#   - analysis/audit.jsonl
#   - delegation_ledger.jsonl (if present)
#   - reports/<case_id>/ tree
#
# Then converts the JSONL → HTML via claude-code-transcripts.
#
# Usage:
#   scripts/capture_remote_run.sh <run_label>
#   e.g. scripts/capture_remote_run.sh run-1
#
# Writes to: runs/<run_label>/

set -euo pipefail

REMOTE_HOST="${SAVVYDFIR_REMOTE:-${SAVVYDFIR_REMOTE_HOST:-root@your-sift-box}}"
REMOTE_PASS="${SAVVYDFIR_REMOTE_PASS:?Set SAVVYDFIR_REMOTE_PASS env var}"
REMOTE_REPO="/opt/SAVVYDFIR-MCP"
REMOTE_USER="sansdfir"  # sessions live under sansdfir's ~/.claude

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <run_label>" >&2
    exit 2
fi

LABEL="$1"
LOCAL_DIR="$(git rev-parse --show-toplevel)/runs/${LABEL}"
mkdir -p "${LOCAL_DIR}"

echo "==> Capturing remote run to: ${LOCAL_DIR}"

# Pull repo-side analysis state (root-owned in repo, accessible)
echo "==> [1/4] state + audit + ledger"
sshpass -p "${REMOTE_PASS}" scp -q -r \
    "${REMOTE_HOST}:${REMOTE_REPO}/analysis" \
    "${LOCAL_DIR}/analysis" || echo "   (analysis dir missing — first run?)"
sshpass -p "${REMOTE_PASS}" scp -q \
    "${REMOTE_HOST}:/tmp/savvydfir/delegation_ledger.jsonl" \
    "${LOCAL_DIR}/delegation_ledger.jsonl" 2>/dev/null || echo "   (no delegation ledger)"

# Pull reports if any
echo "==> [2/4] reports tree"
sshpass -p "${REMOTE_PASS}" scp -q -r \
    "${REMOTE_HOST}:${REMOTE_REPO}/reports" \
    "${LOCAL_DIR}/reports" 2>/dev/null || echo "   (no reports yet)"

# Find + pull the most-recent Claude session JSONL on remote (under sansdfir)
echo "==> [3/4] Claude Code session JSONL (most-recent under sansdfir)"
JSONL_REMOTE=$(sshpass -p "${REMOTE_PASS}" ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" \
    "ls -1t /home/${REMOTE_USER}/.claude/projects/*/*.jsonl 2>/dev/null | head -1" || true)

if [[ -n "${JSONL_REMOTE}" ]]; then
    echo "   pulling ${JSONL_REMOTE}"
    sshpass -p "${REMOTE_PASS}" scp -q "${REMOTE_HOST}:${JSONL_REMOTE}" "${LOCAL_DIR}/session.jsonl"
else
    echo "   (no session JSONL found — was claude launched under ${REMOTE_USER}?)"
fi

# Convert to HTML
echo "==> [4/4] HTML transcript"
if [[ -f "${LOCAL_DIR}/session.jsonl" ]] && command -v claude-code-transcripts >/dev/null 2>&1; then
    claude-code-transcripts json "${LOCAL_DIR}/session.jsonl" \
        -o "${LOCAL_DIR}/transcript" \
        --json
    echo "   wrote ${LOCAL_DIR}/transcript/index.html"
else
    echo "   skipped (missing session.jsonl or claude-code-transcripts)"
fi

echo ""
echo "==> Done. Inspect:"
echo "   ${LOCAL_DIR}/transcript/index.html        # Claude reasoning + tool calls"
echo "   ${LOCAL_DIR}/analysis/state.json          # Findings, executions, lanes"
echo "   ${LOCAL_DIR}/analysis/audit.jsonl         # Tool-level execution provenance"
echo "   ${LOCAL_DIR}/reports/                     # Generated reports if Phase 7 reached"
