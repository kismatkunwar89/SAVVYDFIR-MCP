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

check_bin python3  "Install Python 3.10+ from https://www.python.org/"
check_bin pip3     "Install pip: python3 -m ensurepip --upgrade"
check_bin git      "Install git: sudo apt-get install git"

# Claude CLI check (non-fatal — installer can fetch later)
if ! command -v claude &>/dev/null; then
    warn "Claude CLI not found — will install via native installer below."
    NEED_CLAUDE_INSTALL=1
else
    ok "Found: claude ($(command -v claude))"
    NEED_CLAUDE_INSTALL=0
fi

# ---------------------------------------------------------------------------
# 1b. APT prerequisites (Ubuntu/Debian — SIFT Workstation 2024 baseline)
# ---------------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    info "Installing apt prerequisites (python3-venv, tmux, libfuse2t64, build-essential, pipx)..."
    if ! sudo -n true 2>/dev/null; then
        warn "sudo will prompt for your password to install apt packages."
    fi
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || \
        warn "apt-get update returned non-zero — continuing anyway"
    # libfuse2t64 is the Ubuntu 24.04 name; libfuse2 is the older 22.04 name.
    APT_PKGS=(
        python3-venv python3-dev tmux libewf-dev build-essential pipx curl jq
    )
    if apt-cache show libfuse2t64 >/dev/null 2>&1; then
        APT_PKGS+=(libfuse2t64)
    elif apt-cache show libfuse2 >/dev/null 2>&1; then
        APT_PKGS+=(libfuse2)
    fi
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${APT_PKGS[@]}" >/dev/null 2>&1 || \
        warn "Some apt packages failed to install — re-run manually if needed"
    ok "APT prerequisites installed."
fi

# ---------------------------------------------------------------------------
# 1c. Volatility 3 (memory forensics; missing on SIFT 2024)
# ---------------------------------------------------------------------------
if ! command -v vol >/dev/null 2>&1 && ! command -v vol3 >/dev/null 2>&1; then
    info "Volatility 3 not found — installing via pipx..."
    if command -v pipx >/dev/null 2>&1; then
        pipx install volatility3 >/dev/null 2>&1 || \
            warn "pipx install volatility3 failed — install manually: pipx install volatility3"
        # Ensure pipx PATH is set
        pipx ensurepath >/dev/null 2>&1 || true
        export PATH="$HOME/.local/bin:$PATH"
        if command -v vol >/dev/null 2>&1; then
            ok "Volatility 3 installed: $(command -v vol)"
        else
            warn "vol still not on PATH — run 'source ~/.bashrc' after install completes"
        fi
    else
        warn "pipx not available — install Vol3 manually: pip install volatility3 (in venv) or pipx install volatility3"
    fi
else
    ok "Volatility 3 already present."
fi

# ---------------------------------------------------------------------------
# 1d. Chainsaw + Sigma rules (gate-mandatory for sigma_hunt)
# ---------------------------------------------------------------------------
if ! command -v chainsaw >/dev/null 2>&1; then
    info "Chainsaw not found — installing pre-built binary..."
    CHAINSAW_TMP="$(mktemp -d)"
    cd "$CHAINSAW_TMP"
    # Chainsaw publishes either musl or gnu Linux x86_64 builds depending on version.
    # Match both to survive future renames.
    CHAINSAW_URL="$(curl -s https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest \
        | jq -r '.assets[] | select(.name | test("x86_64-unknown-linux-(gnu|musl).tar.gz$")) | .browser_download_url' \
        | head -1)"
    if [[ -n "$CHAINSAW_URL" ]]; then
        curl -sL "$CHAINSAW_URL" -o chainsaw.tar.gz
        tar xzf chainsaw.tar.gz
        sudo install -m 755 chainsaw*/chainsaw /usr/local/bin/chainsaw 2>/dev/null || \
            warn "Could not install chainsaw to /usr/local/bin — copy chainsaw binary manually"
        ok "Chainsaw installed: $(command -v chainsaw)"
    else
        warn "Could not resolve Chainsaw download URL — install manually from https://github.com/WithSecureLabs/chainsaw/releases"
    fi
    cd "$SCRIPT_DIR"
    rm -rf "$CHAINSAW_TMP"
else
    ok "Chainsaw already present: $(command -v chainsaw)"
fi

if [[ ! -d /opt/sigma/rules/windows ]]; then
    info "Sigma rules not found at /opt/sigma — cloning..."
    sudo git clone --depth=1 https://github.com/SigmaHQ/sigma.git /opt/sigma >/dev/null 2>&1 && \
        ok "Sigma rules installed at /opt/sigma" || \
        warn "Sigma clone failed — clone manually: sudo git clone https://github.com/SigmaHQ/sigma.git /opt/sigma"
else
    ok "Sigma rules already present at /opt/sigma."
fi

# ---------------------------------------------------------------------------
# 1e. Claude Code (native installer, if missing)
# ---------------------------------------------------------------------------
if [[ "${NEED_CLAUDE_INSTALL:-0}" == "1" ]]; then
    info "Installing Claude Code (native installer)..."
    if curl -fsSL https://claude.ai/install.sh | bash; then
        export PATH="$HOME/.local/bin:$PATH"
        if command -v claude >/dev/null 2>&1; then
            ok "Claude Code installed: $(command -v claude)"
        else
            warn "claude not on PATH yet — add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to ~/.bashrc and re-source"
        fi
    else
        warn "Claude Code install failed — run manually: curl -fsSL https://claude.ai/install.sh | bash"
    fi
fi

# ---------------------------------------------------------------------------
# 1f. Ensure ~/.local/bin on PATH (for pipx + claude)
# ---------------------------------------------------------------------------
if ! echo ":$PATH:" | grep -q ":$HOME/.local/bin:"; then
    if ! grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        ok "Added ~/.local/bin to PATH in ~/.bashrc"
        warn "Run 'source ~/.bashrc' after install completes to pick up new PATH."
    fi
    export PATH="$HOME/.local/bin:$PATH"
fi

# ---------------------------------------------------------------------------
# 2. Install Protocol SIFT (if not already installed)
# ---------------------------------------------------------------------------
PROTOCOL_SIFT_MARKER="$HOME/.claude/CLAUDE.md"

if [[ "${SKIP_PROTOCOL_SIFT:-0}" == "1" ]]; then
    warn "SKIP_PROTOCOL_SIFT=1 — skipping Protocol SIFT (optional external framework)."
elif [[ -f "$PROTOCOL_SIFT_MARKER" ]] && grep -q "Principal DFIR Orchestrator" "$PROTOCOL_SIFT_MARKER" 2>/dev/null; then
    ok "Protocol SIFT already installed — skipping."
else
    info "Installing Protocol SIFT (optional SANS Claude Code DFIR framework)..."
    info "Skip with: SKIP_PROTOCOL_SIFT=1 bash install.sh"
    if curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash; then
        ok "Protocol SIFT installed successfully."
    else
        warn "Protocol SIFT install failed — continuing (it's optional). Re-run separately if you need it."
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

# 4c. Skills directory — repo has them at .claude/skills/ (user-invocable)
#     and .agents/skills/ (deferred-agent). Deploy the .claude/skills set to
#     ~/.claude/skills/ so the agent picks them up at session start.
if [[ -d "${SCRIPT_DIR}/.claude/skills" ]]; then
    info "Deploying .claude/skills/ to ${CLAUDE_DIR}/skills/..."
    backup_if_exists "${CLAUDE_DIR}/skills"
    cp -r "${SCRIPT_DIR}/.claude/skills" "${CLAUDE_DIR}/skills"
    ok "Skills deployed ($(ls "${CLAUDE_DIR}/skills" | wc -l) skill(s))."
elif [[ -d "${SCRIPT_DIR}/skills" ]]; then
    # Legacy path for older layouts
    info "Deploying skills/ to ${CLAUDE_DIR}/skills/..."
    backup_if_exists "${CLAUDE_DIR}/skills"
    cp -r "${SCRIPT_DIR}/skills" "${CLAUDE_DIR}/skills"
    ok "Skills deployed (legacy path)."
else
    warn "No skills directory found — investigation skill will not be available."
fi

# 4d. Hooks — agent_trigger + workflow-enforce-pre/post + stop hook + session-start
#     The repo ships these at .claude/hooks/ already, but for any user-level
#     hook overrides, mirror to ~/.claude/hooks/ here. Currently a no-op — the
#     .mcp.json at the repo root points hooks at the repo path.

# ---------------------------------------------------------------------------
# 5. Create case directory structure
# ---------------------------------------------------------------------------
info "Creating case + evidence directories..."
sudo mkdir -p /cases/{analysis,exports,reports} /evidence/{disk,memory} 2>/dev/null && \
    sudo chown -R "$USER:$USER" /cases /evidence && \
    ok "Created /cases/ and /evidence/ (owned by $USER)" || {
    mkdir -p "${HOME}/cases/"{analysis,exports,reports} "${HOME}/evidence/"{disk,memory}
    warn "Could not create /cases/ /evidence/ (no sudo). Used ${HOME}/cases/ and ${HOME}/evidence/ instead."
    warn "If you keep evidence at the home-relative paths, update case-templates/manifest.json image paths accordingly."
}

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
