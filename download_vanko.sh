#!/usr/bin/env bash
# ============================================================
# download_vanko.sh — SANS HACKATHON-2026 "Standard Forensics Case 2" (VANKO)
# ============================================================
# Egnyte folder (shared by Rob Lee, accessible until 2026-06-16):
#   https://sansorg.egnyte.com/fl/HhH7crTYT4JK#folder-link/HACKATHON-2026/Standard%20Forensics%20Case%202
# Files:
#   Vanko Student Scenario_D01_01.docx   23 KB   (read first — case scenario)
#   VANKO.zip                            40.7 GB (the evidence)
#
# Egnyte downloads each file via a per-file direct-download URL:
#   https://sansorg.egnyte.com/dd/HhH7crTYT4JK/?entryId=<ENTRY_ID>
# You must supply that URL (or just the entryId) — get it from the browser:
#   open the Egnyte folder, RIGHT-CLICK the file -> "Download" (or "Copy Download
#   Link"); if it just starts downloading, copy the resolved
#   https://sansorg.egnyte.com/dd/HhH7crTYT4JK/?entryId=... URL from the browser's
#   Downloads list or the Network tab. Pass it via env (below).
#
# Usage:
#   # size-check only (HEAD, no download):
#   VANKO_ZIP_URL="https://sansorg.egnyte.com/dd/HhH7crTYT4JK/?entryId=XXXX" ./download_vanko.sh test
#   # download (resumable):
#   VANKO_ZIP_URL="...?entryId=XXXX" DOCX_URL="...?entryId=YYYY" ./download_vanko.sh
#   # or pass just the GUIDs:
#   VANKO_ZIP_ENTRY=XXXX DOCX_ENTRY=YYYY ./download_vanko.sh
#   # override output dir (default /evidence/vanko):
#   OUTPUT_DIR=/evidence/vanko ./download_vanko.sh
# ============================================================
set -uo pipefail

TOKEN="HhH7crTYT4JK"
BASE="https://sansorg.egnyte.com/dd/${TOKEN}/?entryId="
OUT="${OUTPUT_DIR:-/evidence/vanko}"
MIN_FREE_GB="${MIN_FREE_GB:-110}"   # need room for 40.7GB zip + extracted evidence

# Provide either the full URL or just the entryId GUID, per file.
VANKO_ZIP_URL="${VANKO_ZIP_URL:-}"
DOCX_URL="${DOCX_URL:-}"
VANKO_ZIP_ENTRY="${VANKO_ZIP_ENTRY:-}"
DOCX_ENTRY="${DOCX_ENTRY:-}"
[ -z "$VANKO_ZIP_URL" ] && [ -n "$VANKO_ZIP_ENTRY" ] && VANKO_ZIP_URL="${BASE}${VANKO_ZIP_ENTRY}"
[ -z "$DOCX_URL" ]      && [ -n "$DOCX_ENTRY" ]      && DOCX_URL="${BASE}${DOCX_ENTRY}"

mkdir -p "$OUT"

free_gb() { df -BG --output=avail "$OUT" 2>/dev/null | tail -1 | tr -dc '0-9'; }

size_check() {  # name url
  local name="$1" url="$2"
  [ -z "$url" ] && { echo "  $name: (no URL provided)"; return; }
  local bytes; bytes=$(curl -sIL "$url" | grep -i '^content-length' | tail -1 | tr -dc '0-9')
  if [ -n "$bytes" ]; then
    printf "  %-34s %s bytes (~%s GB)\n" "$name" "$bytes" "$(echo "scale=2;$bytes/1073741824"|bc)"
  else
    echo "  $name: HEAD returned no content-length (URL wrong/expired?)"
  fi
}

download() {  # name url
  local name="$1" url="$2" out="$OUT/$1"
  [ -z "$url" ] && { echo "[skip] $name — no URL/entryId provided"; return; }
  if [ -f "$out" ]; then echo "[skip] $name already exists ($(du -h "$out"|cut -f1))"; return; fi
  local f; f=$(free_gb)
  if [ -n "$f" ] && [ "$f" -lt "$MIN_FREE_GB" ]; then
    echo "[abort] only ${f}GB free at $OUT (need >= ${MIN_FREE_GB}GB)"; exit 9
  fi
  echo "[dl]   $name -> $out"
  curl -L -C - --retry 5 --retry-delay 10 --progress-bar -o "$out" "$url"
  echo "[done] $name ($(du -h "$out"|cut -f1))"
}

case "${1:-all}" in
  test)
    echo "=== SIZE CHECK (HEAD only) ==="
    size_check "VANKO.zip" "$VANKO_ZIP_URL"
    size_check "Vanko_Student_Scenario.docx" "$DOCX_URL"
    echo "free at $OUT: $(free_gb)GB"
    ;;
  *)
    [ -z "$VANKO_ZIP_URL" ] && { echo "ERROR: set VANKO_ZIP_URL (or VANKO_ZIP_ENTRY). See header."; exit 2; }
    download "Vanko_Student_Scenario.docx" "$DOCX_URL"
    download "VANKO.zip" "$VANKO_ZIP_URL"
    echo "=== done. contents next: ==="
    echo "  unzip -l \"$OUT/VANKO.zip\" | head     # inspect for .E01 / memory image"
    echo "  (then extract, verify any MD5 in the .docx, and write case-templates/manifest.json)"
    df -h "$OUT" | tail -1
    ;;
esac
