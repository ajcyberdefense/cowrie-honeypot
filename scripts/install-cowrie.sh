#!/bin/bash
# =============================================================================
# install-cowrie.sh — Cowrie Honeypot Installation Script
# =============================================================================
# Automates all steps from docs/03-cowrie-install.md
# Run as the COWRIE user (not root, not ubuntu):
#
#   sudo su - cowrie
#   bash /tmp/install-cowrie.sh
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error(){ echo -e "${RED}[✗]${NC} $1"; exit 1; }

# -----------------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------------
if [ "$(whoami)" != "cowrie" ]; then
  error "Run this script as the cowrie user: sudo su - cowrie"
fi

log "Starting Cowrie installation..."

# -----------------------------------------------------------------------------
# Step 1: Clone Cowrie
# -----------------------------------------------------------------------------
if [ -d "$HOME/cowrie" ]; then
  warn "Cowrie directory already exists. Pulling latest changes..."
  cd "$HOME/cowrie" && git pull
else
  log "Cloning Cowrie repository..."
  git clone https://github.com/cowrie/cowrie "$HOME/cowrie"
  cd "$HOME/cowrie"
fi

# -----------------------------------------------------------------------------
# Step 2: Create virtual environment
# -----------------------------------------------------------------------------
log "Setting up Python virtual environment..."
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# -----------------------------------------------------------------------------
# Step 3: Install dependencies
# -----------------------------------------------------------------------------
log "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
log "Dependencies installed."

# -----------------------------------------------------------------------------
# Step 4: Create config file
# -----------------------------------------------------------------------------
if [ ! -f etc/cowrie.cfg ]; then
  log "Creating Cowrie config from template..."
  cp etc/cowrie.cfg.dist etc/cowrie.cfg

  # Apply settings
  sed -i "s/^#\?hostname = .*/hostname = svr04/" etc/cowrie.cfg

  # Enable Telnet — find [telnet] section and set enabled = true
  sed -i '/^\[telnet\]/,/^\[/ s/^#\?enabled = .*/enabled = true/' etc/cowrie.cfg

  log "Config created at etc/cowrie.cfg"
  warn "Review etc/cowrie.cfg to customize hostname and other settings."
else
  warn "etc/cowrie.cfg already exists. Skipping config creation."
fi

# -----------------------------------------------------------------------------
# Step 5: Test start
# -----------------------------------------------------------------------------
log "Starting Cowrie..."
cowrie start
sleep 2
cowrie status

# -----------------------------------------------------------------------------
# Step 6: Install systemd service (must be done as ubuntu/sudo)
# -----------------------------------------------------------------------------
log "Writing systemd service file to /tmp/cowrie.service..."
cat > /tmp/cowrie.service << 'EOF'
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment="PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "============================================================"
log "Cowrie installation complete!"
echo ""
warn "MANUAL STEP REQUIRED — run these as ubuntu user:"
echo ""
echo "  sudo cp /tmp/cowrie.service /etc/systemd/system/cowrie.service"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable cowrie"
echo "  sudo systemctl start cowrie"
echo "  sudo systemctl status cowrie"
echo ""
warn "Then test your honeypot:"
echo "  ssh -p 2222 root@YOUR_ELASTIC_IP"
echo "============================================================"
