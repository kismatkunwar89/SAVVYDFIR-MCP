#!/bin/bash
# Autonomous E2E orchestrator for VANKO on v2 (durable-reuse) code.
# Launches the investigation; if a headless -p session ends before status=COMPLETE,
# relaunches a CONTINUATION that reads state + reuses staged artifacts (no re-extract)
# + finishes through generate_report. Loops until COMPLETE or attempt cap.
# Non-disruptive: same case, state persists, no code changes mid-run.
set -u
cd /home/referenceensics/SAVVYDFIR-MCP || exit 1
C=/home/referenceensics/.local/bin/claude
CASE=VANKO-ZEBRAFISH-2016
ORCH=run-logs/orch.log
RUNLOG=run-logs/e2e-v2.log
mkdir -p run-logs
: > "$ORCH"

status() { python3 -c 'import json;print(json.load(open("analysis/state.json")).get("status","NONE"))' 2>/dev/null || echo NONE; }
findings() { python3 -c 'import json;print(len(json.load(open("analysis/state.json")).get("findings",[])))' 2>/dev/null || echo 0; }
alive() { pgrep -f "claude.*dangerously" >/dev/null && echo Y || echo N; }
report_done() { [ -f "reports/$CASE/report.html" ] && echo Y || echo N; }
launch() { nohup "$C" --dangerously-skip-permissions --allowedTools "mcp__savvydfir__*" --verbose -p "$1" </dev/null >>"$RUNLOG" 2>&1 & }

P1='Read case-templates/manifest.json and investigate VANKO-ZEBRAFISH-2016 fully end-to-end following the 7-phase DFIR workflow in CLAUDE.md (disk-only case; memory tools record documented-absence). Run every mandatory tool and the 8 user-activity extractors including extract_recycle_bin, extract_powershell_history, extract_scheduled_tasks. Analyze each artifact inline (run_analysis + submit_finding), record every lane, form and resolve hypotheses, run sigma_hunt and compare_disk_and_memory, then complete through generate_report(case_id) and generate_graph(case_id). Do not stop until reports/VANKO-ZEBRAFISH-2016/report.html exists.'
PC='Resume the in-progress VANKO-ZEBRAFISH-2016 investigation: call read_state to see what is already done. Do NOT re-extract artifacts (staged outputs are reused automatically). Complete ONLY the remaining phases: Phase 5 compare_disk_and_memory + find_temporal_clusters, Phase 5.5 gap reconciliation, Phase 6 synthesis (promote CONFIRMED), close hypotheses, then generate_report(case_id) and generate_graph(case_id). Do not stop until reports/VANKO-ZEBRAFISH-2016/report.html exists.'

echo "[orch] $(date -u +%T) launch run1" >>"$ORCH"
launch "$P1"
attempts=0
for i in $(seq 1 50); do
  sleep 120
  st=$(status); al=$(alive); rd=$(report_done); fn=$(findings)
  echo "[orch] $(date -u +%T) t=$i status=$st alive=$al report=$rd findings=$fn attempts=$attempts" >>"$ORCH"
  if [ "$st" = "COMPLETE" ] || [ "$rd" = "Y" ]; then echo "[orch] $(date -u +%T) COMPLETE" >>"$ORCH"; break; fi
  if [ "$al" = "N" ]; then
    if [ "$attempts" -ge 6 ]; then echo "[orch] $(date -u +%T) GAVE UP after $attempts resumes" >>"$ORCH"; break; fi
    attempts=$((attempts+1))
    echo "[orch] $(date -u +%T) session ended (status=$st), resume #$attempts" >>"$ORCH"
    launch "$PC"
    sleep 25
  fi
done
echo "[orch] $(date -u +%T) FINAL status=$(status) findings=$(findings) report=$(report_done)" >>"$ORCH"
