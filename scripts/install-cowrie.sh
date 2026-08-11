#!/bin/bash
# =============================================================================
# install-cowrie.sh — Cowrie Honeypot Installation
# =============================================================================
# Automates docs/03-cowrie-install.md.
#
# Run as the COWRIE user (not root, not ubuntu):
#
#   sudo cp /opt/cowrie-honeypot/scripts/install-cowrie.sh /tmp/
#   sudo su - cowrie
#   bash /tmp/install-cowrie.sh
#
# Cowrie 3.x installs from PyPI and keeps all state in one self-contained
# directory. This replaces the old `git clone` + `requirements.txt` flow,
# which no longer produces a working `cowrie` command — upstream removed
# bin/cowrie and moved to a console-script entry point.
# =============================================================================

set -euo pipefail

# Where the honeypot lives: venv, config, logs, downloads, TTY recordings.
HONEYPOT_DIR="${HONEYPOT_DIR:-$HOME/honeypot}"
# Where this repo is checked out on the host (for configs/).
REPO_DIR="${REPO_DIR:-/opt/cowrie-honeypot}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error(){ echo -e "${RED}[x]${NC} $1" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
[ "$(whoami)" = "cowrie" ] || error "Run as the cowrie user: sudo su - cowrie"

command -v python3 >/dev/null || error "python3 not found. Run harden.sh first."

# Cowrie 3.x requires Python >= 3.10. Fail loudly now rather than mid-pip.
python3 - <<'PY' || error "Cowrie requires Python 3.10 or newer. Use Ubuntu 22.04+."
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY
log "Python $(python3 -V 2>&1 | cut -d' ' -f2) OK"

# -----------------------------------------------------------------------------
# Step 1: Create the state directory
# -----------------------------------------------------------------------------
log "Using honeypot directory: $HONEYPOT_DIR"
mkdir -p "$HONEYPOT_DIR"
cd "$HONEYPOT_DIR"

# -----------------------------------------------------------------------------
# Step 2: Virtual environment (lives inside the state dir, self-contained)
# -----------------------------------------------------------------------------
if [ -d cowrie-env ]; then
  warn "cowrie-env already exists — reusing it."
else
  log "Creating virtual environment..."
  python3 -m venv cowrie-env
fi
# shellcheck disable=SC1091
source cowrie-env/bin/activate

# -----------------------------------------------------------------------------
# Step 3: Install Cowrie from PyPI
# -----------------------------------------------------------------------------
log "Installing Cowrie (this pulls native wheels; takes 1-3 min)..."
python -m pip install --upgrade pip -q
python -m pip install --upgrade cowrie -q
log "Installed cowrie $(python -m pip show cowrie | awk '/^Version:/{print $2}')"

command -v cowrie >/dev/null \
  || error "cowrie command not on PATH after install — venv activation failed?"

# -----------------------------------------------------------------------------
# Step 4: Initialize state layout
# -----------------------------------------------------------------------------
# `cowrie init` is NOT idempotent: it exits non-zero if etc/cowrie.cfg exists.
# Guard it so re-running this script doesn't abort under `set -e`.
if [ -f etc/cowrie.cfg ]; then
  warn "etc/cowrie.cfg exists — skipping 'cowrie init' (it will not overwrite)."
else
  log "Initializing state directory..."
  cowrie init
fi

# -----------------------------------------------------------------------------
# Step 5: Apply our config overrides
# -----------------------------------------------------------------------------
# Our cowrie.cfg is an overrides-only file; the bundled defaults fill the rest.
if [ -f "$REPO_DIR/configs/cowrie.cfg" ]; then
  if [ -f etc/cowrie.cfg ] && ! cmp -s "$REPO_DIR/configs/cowrie.cfg" etc/cowrie.cfg; then
    cp etc/cowrie.cfg "etc/cowrie.cfg.bak.$(date +%Y%m%d%H%M%S)"
    warn "Backed up existing etc/cowrie.cfg"
  fi
  cp "$REPO_DIR/configs/cowrie.cfg" etc/cowrie.cfg
  log "Applied config from $REPO_DIR/configs/cowrie.cfg"
else
  warn "$REPO_DIR/configs/cowrie.cfg not found — keeping the stock config."
  warn "Telnet will bind 2223 by default, which COLLIDES with admin SSH."
fi

# -----------------------------------------------------------------------------
# Step 6: Start and verify
# -----------------------------------------------------------------------------
log "Starting Cowrie..."
cowrie start || error "Cowrie failed to start. Check $HONEYPOT_DIR/var/log/cowrie/cowrie.log"

# Give twistd a moment to bind its listeners before we ask about status.
sleep 3
cowrie status || warn "cowrie status reported non-zero — check the log."

echo ""
if ss -tlnp 2>/dev/null | grep -qE ':(2222|2323)\b'; then
  log "Listeners are up:"
  ss -tlnp 2>/dev/null | grep -E ':(2222|2323)\b' || true
else
  warn "Expected listeners on 2222/2323 not visible. Check:"
  echo "    tail -50 $HONEYPOT_DIR/var/log/cowrie/cowrie.log"
fi

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
log "Cowrie installed at $HONEYPOT_DIR"
echo ""
warn "NEXT — run these as a sudo-capable user (exit the cowrie shell first):"
echo ""
echo "  sudo cp $REPO_DIR/configs/cowrie.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now cowrie"
echo "  sudo systemctl status cowrie"
echo ""
warn "Then test from your laptop (port 22 redirects to Cowrie on 2222):"
echo "  ssh -p 22 root@YOUR_PUBLIC_IP        # any password is accepted"
echo "============================================================"
