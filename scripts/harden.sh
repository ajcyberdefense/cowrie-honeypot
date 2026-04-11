#!/bin/bash
# =============================================================================
# harden.sh — Cowrie Honeypot Instance Hardening Script
# =============================================================================
# Automates all hardening steps from docs/02-hardening.md
# Run as the ubuntu user with sudo privileges on a fresh Ubuntu 22.04 instance.
#
# Usage:
#   chmod +x harden.sh
#   ./harden.sh
# =============================================================================

set -e  # Exit immediately if any command fails

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# -----------------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------------
if [ "$EUID" -eq 0 ]; then
  error "Do not run this script as root. Run as ubuntu: ./harden.sh"
fi

log "Starting Cowrie honeypot instance hardening..."
echo ""

# -----------------------------------------------------------------------------
# Step 1: System update
# -----------------------------------------------------------------------------
log "Updating system packages..."
sudo apt update -qq && sudo apt upgrade -y -qq
log "System updated."

# -----------------------------------------------------------------------------
# Step 2: Configure SSH
# -----------------------------------------------------------------------------
log "Configuring SSH daemon..."

SSHD_CONFIG="/etc/ssh/sshd_config"
sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup"

# Apply hardened settings
sudo sed -i 's/^#\?Port .*/Port 2223/' "$SSHD_CONFIG"
sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' "$SSHD_CONFIG"
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
sudo sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
sudo sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' "$SSHD_CONFIG"

# Add AllowUsers if not already present
grep -q "^AllowUsers" "$SSHD_CONFIG" || echo "AllowUsers ubuntu" | sudo tee -a "$SSHD_CONFIG" > /dev/null

warn "SSH config updated. A backup was saved to ${SSHD_CONFIG}.backup"
warn "IMPORTANT: Open a second terminal and test port 2223 before restarting SSH."
warn "Press ENTER to restart SSH (or Ctrl+C to cancel and verify manually)."
read -r

sudo systemctl restart sshd
log "SSH restarted on port 2223."

# -----------------------------------------------------------------------------
# Step 3: Configure UFW firewall
# -----------------------------------------------------------------------------
log "Configuring UFW firewall..."

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2223/tcp comment 'Real admin SSH'
sudo ufw allow 2222/tcp comment 'Cowrie fake SSH'
sudo ufw allow 23/tcp   comment 'Cowrie fake Telnet'

echo "y" | sudo ufw enable
log "UFW enabled. Current rules:"
sudo ufw status

# -----------------------------------------------------------------------------
# Step 4: Lock root account
# -----------------------------------------------------------------------------
log "Locking root account..."
sudo passwd -l root
log "Root account locked."

# -----------------------------------------------------------------------------
# Step 5: Install and enable Fail2ban
# -----------------------------------------------------------------------------
log "Installing Fail2ban..."
sudo apt install fail2ban -y -qq
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
log "Fail2ban installed and running."

# -----------------------------------------------------------------------------
# Step 6: Create cowrie system user
# -----------------------------------------------------------------------------
if id "cowrie" &>/dev/null; then
  warn "User 'cowrie' already exists. Skipping."
else
  log "Creating 'cowrie' system user..."
  sudo adduser --disabled-password --gecos "" cowrie
  log "User 'cowrie' created."
fi

# -----------------------------------------------------------------------------
# Step 7: Install Cowrie dependencies
# -----------------------------------------------------------------------------
log "Installing Cowrie dependencies..."
sudo apt install -y -qq \
  python3-pip python3-venv git \
  libssl-dev libffi-dev build-essential \
  libpython3-dev python3-minimal authbind \
  virtualenv
log "Dependencies installed."

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
log "Hardening complete! Summary:"
echo "  - System updated"
echo "  - SSH moved to port 2223 (key auth only)"
echo "  - UFW active: ports 2223, 2222, 23 open"
echo "  - Root account locked"
echo "  - Fail2ban running"
echo "  - cowrie user created"
echo "  - Cowrie dependencies installed"
echo ""
warn "NEXT STEPS:"
echo "  1. Remove port 22 from your AWS Security Group"
echo "  2. Verify you can SSH on port 2223 from a new terminal"
echo "  3. Run: sudo -u cowrie bash scripts/install-cowrie.sh"
echo "============================================================"
