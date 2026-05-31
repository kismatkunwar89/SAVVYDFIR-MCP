#!/usr/bin/env bash
# Render a SAVVYDFIR report.html to report.pdf using headless Chromium.
#
# The report is self-contained (no JS, no external assets), so the browser's
# own print engine produces a faithful PDF with no runtime PDF dependency in
# the MCP server. Chromium is the canonical renderer (Firefox page breaks differ).
#
# Usage:  scripts/render_report_pdf.sh <report.html> [output.pdf]
# Default output: alongside the HTML as report.pdf.
set -euo pipefail

HTML="${1:?usage: render_report_pdf.sh <report.html> [output.pdf]}"
OUT="${2:-$(dirname "$HTML")/report.pdf}"

if [[ ! -f "$HTML" ]]; then
  echo "error: report HTML not found: $HTML" >&2
  exit 1
fi

# Resolve a Chromium-family binary.
BROWSER=""
for b in chromium chromium-browser google-chrome google-chrome-stable; do
  if command -v "$b" >/dev/null 2>&1; then BROWSER="$b"; break; fi
done
if [[ -z "$BROWSER" ]]; then
  echo "error: no Chromium/Chrome binary found on PATH" >&2
  exit 1
fi

ABS_HTML="$(cd "$(dirname "$HTML")" && pwd)/$(basename "$HTML")"

"$BROWSER" --headless --no-sandbox --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$OUT" "file://${ABS_HTML}"

echo "wrote $OUT"
