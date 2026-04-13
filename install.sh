#!/usr/bin/env bash
# SAVVYDFIR-MCP Installer
# Installs Protocol SIFT (if not present), creates Python venv, and deploys Claude Code config.
#
# Usage: bash install.sh
#
# Copyright (c) 2026 Kismat Kunwar — MIT License

set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers (same style as Protocol SIFT)
# ---------------------------------------------------------------------------
_tput() { command -v tput &>/dev/null && tput "$@" 2>/dev/null || true; }
RED="$(_tput setaf 1)"
GREEN="$(_tput setaf 2)"
YELLOW="$(_tput setaf 3)"
CYAN="$(_tput setaf 6)"
BOLD="$(_tput bold)"
RESET="$(_tput sgr0)"

info()  { printf "%s[*]%s %s\n" "${CYAN}${BOLD}"  "${RESET}" "$*"; }
ok()    { printf "%s[+]%s %s\n" "${GREEN}${BOLD}" "${RESET}" "$*"; }
warn()  { printf "%s[!]%s %s\n" "${YELLOW}${BOLD}" "${RESET}" "$*" >&2; }
die()   { printf "%s[✗]%s %s\n" "${RED}${BOLD}"   "${RESET}" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
printf "\n%s%s" "${BOLD}${CYAN}" "
  ╔══════════════════════════════════════════════════════════╗
  ║           SAVVYDFIR-MCP Installer v1.0.0                ║
  ║  Autonomous DFIR Agent — Cross-Artifact Correlation      ║
  ║  FIND EVIL! Hackathon 2026                               ║
  ╚══════════════════════════════════════════════════════════╝
" && printf "%s\n" "${RESET}"

# ---------------------------------------------------------------------------
# 1. Prerequisite checks
# ---------------------------------------------------------------------------
info "Checking prerequisites..."

check_bin() {
    local bin="$1"
    local hint="${2:-}"
    if ! command -v "$bin" &>/dev/null; then
        if [[ -n "$hint" ]]; then
            die "Required tool not found: '$bin'. $hint"
        else
            die "Required tool not found: '$bin'. Please install it and re-run this script."
        fi
    fi
    ok "Found: $bin ($(command -v "$bin"))"
}

check_bin python3  "Install Python 3.8+ from https://www.python.org/"
check_bin pip3     "Install pip: python3 -m ensurepip --upgrade"
check_bin git      "Install git: sudo apt-get install git"

# Claude CLI check (non-fatal — warn if missing)
if ! command -v claude &>/dev/null; then
    warn "Claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-code"
    warn "You can continue the install, but you will need Claude Code before running investigations."
else
    ok "Found: claude ($(command -v claude))"
fi

# ---------------------------------------------------------------------------
# 2. Install Protocol SIFT (if not already installed)
# ---------------------------------------------------------------------------
PROTOCOL_SIFT_MARKER="$HOME/.claude/CLAUDE.md"

if [[ -f "$PROTOCOL_SIFT_MARKER" ]] && grep -q "Principal DFIR Orchestrator" "$PROTOCOL_SIFT_MARKER" 2>/dev/null; then
    ok "Protocol SIFT already installed — skipping."
else
    info "Installing Protocol SIFT (SANS Claude Code DFIR framework)..."
    info "Running: curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash"
    if curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash; then
        ok "Protocol SIFT installed successfully."
    else
        die "Protocol SIFT installation failed. Check network connectivity and retry."
    fi
fi

# ---------------------------------------------------------------------------
# 3. Create Python virtual environment and install dependencies
# ---------------------------------------------------------------------------
VENV_DIR="${SCRIPT_DIR}/venv"

info "Creating Python virtual environment at ${VENV_DIR}..."
if [[ -d "$VENV_DIR" ]]; then
    warn "venv directory already exists — skipping creation."
else
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created."
fi

info "Installing Python dependencies (fastmcp, pydantic>=2.0)..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${SCRIPT_DIR}/requirements.txt"
ok "Dependencies installed."

# ---------------------------------------------------------------------------
# 4. Deploy Claude Code configuration
# ---------------------------------------------------------------------------
CLAUDE_DIR="$HOME/.claude"
mkdir -p "$CLAUDE_DIR"

backup_if_exists() {
    local target="$1"
    if [[ -e "$target" ]]; then
        local backup="${target}.bak.$(date +%Y%m%d_%H%M%S)"
        warn "Backing up existing $(basename "$target") to $(basename "$backup")"
        cp -r "$target" "$backup"
    fi
}

# 4a. CLAUDE.md (global system prompt)
if [[ -f "${SCRIPT_DIR}/claude_config/CLAUDE.md" ]]; then
    info "Deploying CLAUDE.md to ${CLAUDE_DIR}/CLAUDE.md..."
    backup_if_exists "${CLAUDE_DIR}/CLAUDE.md"
    cp "${SCRIPT_DIR}/claude_config/CLAUDE.md" "${CLAUDE_DIR}/CLAUDE.md"
    ok "CLAUDE.md deployed."
else
    warn "claude_config/CLAUDE.md not found — skipping."
fi

# 4b. settings.json (permissions)
if [[ -f "${SCRIPT_DIR}/claude_config/settings.json" ]]; then
    info "Deploying settings.json to ${CLAUDE_DIR}/settings.json..."
    backup_if_exists "${CLAUDE_DIR}/settings.json"
    cp "${SCRIPT_DIR}/claude_config/settings.json" "${CLAUDE_DIR}/settings.json"
    ok "settings.json deployed."
else
    warn "claude_config/settings.json not found — skipping."
fi

# 4c. Skills directory
if [[ -d "${SCRIPT_DIR}/skills" ]]; then
    info "Deploying skills/ to ${CLAUDE_DIR}/skills/..."
    backup_if_exists "${CLAUDE_DIR}/skills"
    cp -r "${SCRIPT_DIR}/skills" "${CLAUDE_DIR}/skills"
    ok "Skills deployed."
else
    warn "skills/ directory not found — skipping."
fi

# ---------------------------------------------------------------------------
# 5. Create case directory structure
# ---------------------------------------------------------------------------
info "Creating case directories at /cases/..."
sudo mkdir -p /cases/{analysis,exports,reports} 2>/dev/null || \
    mkdir -p "${HOME}/cases/{analysis,exports,reports}" && \
    warn "Could not create /cases/ (no sudo). Created ${HOME}/cases/ instead."
ok "Case directories ready."

# ---------------------------------------------------------------------------
# 6. Verify installation
# ---------------------------------------------------------------------------
info "Verifying installation..."
"${VENV_DIR}/bin/python3" -c "import fastmcp; import pydantic; print('fastmcp + pydantic OK')" && \
    ok "Python environment verified."

# ---------------------------------------------------------------------------
# 7. Next steps
# ---------------------------------------------------------------------------
printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Installation complete!" "${RESET}"
printf "\n%sNext steps:%s\n" "${BOLD}" "${RESET}"
printf "  1. Set your Anthropic API key:\n"
printf "       export ANTHROPIC_API_KEY='sk-ant-...'\n\n"
printf "  2. Activate the virtual environment:\n"
printf "       source %s/venv/bin/activate\n\n" "${SCRIPT_DIR}"
printf "  3. Mount your evidence (read-only):\n"
printf "       sudo ewfmount /path/to/image.E01 /mnt/evidence\n\n"
printf "  4. Create a case directory:\n"
printf "       cp -r %s/case-templates/ /cases/MY-CASE-001/\n" "${SCRIPT_DIR}"
printf "       # Edit /cases/MY-CASE-001/CLAUDE.md and manifest.json\n\n"
printf "  5. Start an investigation:\n"
printf "       cd /cases/MY-CASE-001/\n"
printf "       claude\n\n"
printf "  6. Trace a finding:\n"
printf "       python3 %s/scripts/trace_finding.py F-004\n\n" "${SCRIPT_DIR}"
printf "  Documentation: %s/docs/\n" "${SCRIPT_DIR}"
printf "  Troubleshooting: %s/README.md#troubleshooting\n\n" "${SCRIPT_DIR}"
