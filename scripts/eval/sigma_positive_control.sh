#!/usr/bin/env bash
# ============================================================
# sigma_positive_control.sh — prove the Chainsaw Sigma mapping actually MATCHES
# ============================================================
# Review 2026-06-06: the Run-11 hand-authored mapping LOADED 2284 rules but
# matched 0 events on known-malicious EVTX (silent no-op). This control runs the
# REPO mapping against known-malicious samples and FAILS if detections fall below
# a baseline — so a mapping regression can never again masquerade as "0 = clean".
#
# Usage:
#   ./scripts/eval/sigma_positive_control.sh                 # default: min 30 hits
#   MIN_HITS=34 ./scripts/eval/sigma_positive_control.sh
#   SIGMA_DIR=/opt/sigma/rules/windows MAPPING=rules/chainsaw-sigma-mapping.yml ./...
#
# Exit 0 = mapping healthy (hits >= MIN_HITS). Exit 1 = mapping BROKEN.
# Requires: chainsaw, a sigma rules dir, internet (first run caches samples).
# ============================================================
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
MAPPING="${MAPPING:-$REPO/rules/chainsaw-sigma-mapping.yml}"
CHAINSAW="${CHAINSAW:-$(command -v chainsaw || echo /usr/local/bin/chainsaw)}"
MIN_HITS="${MIN_HITS:-30}"
CACHE="${SIGMA_PC_CACHE:-/tmp/sigma_pc_samples}"

# resolve sigma dir
SIGMA_DIR="${SIGMA_DIR:-}"
if [ -z "$SIGMA_DIR" ]; then
  for d in /opt/sigma/rules/windows /opt/sigma-rules/rules/windows /usr/share/chainsaw/rules; do
    [ -d "$d" ] && { SIGMA_DIR="$d"; break; }
  done
fi

echo "[sigma-pc] chainsaw=$CHAINSAW"
echo "[sigma-pc] mapping=$MAPPING"
echo "[sigma-pc] sigma_dir=$SIGMA_DIR"
[ -x "$CHAINSAW" ] || { echo "[sigma-pc] SKIP: chainsaw not found"; exit 77; }
[ -f "$MAPPING" ] || { echo "[sigma-pc] FAIL: mapping not found"; exit 1; }
[ -d "$SIGMA_DIR" ] || { echo "[sigma-pc] SKIP: sigma rules dir not found"; exit 77; }

# fetch + cache known-malicious EVTX (sbousseaden EVTX-ATTACK-SAMPLES)
mkdir -p "$CACHE"
if [ "$(ls "$CACHE"/*.evtx 2>/dev/null | wc -l)" -lt 6 ]; then
  echo "[sigma-pc] caching known-malicious samples -> $CACHE"
  for folder in "Execution" "Credential%20Access" "Lateral%20Movement"; do
    curl -s "https://api.github.com/repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/$folder" 2>/dev/null \
      | python3 -c "import json,sys
try: d=json.load(sys.stdin)
except: sys.exit()
[print(x['download_url']) for x in d if x.get('name','').endswith('.evtx')][:4]" 2>/dev/null
  done | while read -r u; do (cd "$CACHE" && curl -sL "$u" -O 2>/dev/null); done
fi
N=$(ls "$CACHE"/*.evtx 2>/dev/null | wc -l)
echo "[sigma-pc] sample EVTX available: $N"
[ "$N" -ge 1 ] || { echo "[sigma-pc] SKIP: no samples (offline?)"; exit 77; }

OUT=$(mktemp -d)
"$CHAINSAW" hunt "$CACHE" -s "$SIGMA_DIR" --mapping "$MAPPING" --json --output "$OUT/hits.json" --skip-errors 2>"$OUT/err.txt"
HITS=$(python3 -c "import json;h=json.load(open('$OUT/hits.json'));print(len(h) if isinstance(h,list) else 1)" 2>/dev/null || echo 0)
grep -iE "Loaded" "$OUT/err.txt" | head -2
echo "[sigma-pc] DETECTIONS=$HITS (min required=$MIN_HITS)"
rm -rf "$OUT"

if [ "$HITS" -ge "$MIN_HITS" ]; then
  echo "[sigma-pc] PASS — mapping is healthy"
  exit 0
else
  echo "[sigma-pc] FAIL — mapping matched $HITS (<$MIN_HITS) on known-malicious EVTX. The Sigma mapping is BROKEN (see rules/chainsaw-sigma-mapping.yml)."
  exit 1
fi
