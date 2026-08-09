#!/bin/bash
# =============================================================================
# harden.sh — Honeypot Host Hardening
# =============================================================================
# Automates docs/02-hardening.md. Run as a sudo-capable user (NOT root) on a
# fresh Ubuntu 22.04 or 24.04 instance:
#
#   sudo apt install -y git
#   sudo git clone https://github.com/ajcyberdefense/cowrie-honeypot /opt/cowrie-honeypot
#   bash /opt/cowrie-honeypot/scripts/harden.sh
#
# WHAT THIS DOES TO YOUR PORTS
#   2223  real admin SSH        <- restricted to your IP
#     22  Cowrie fake SSH       <- redirected to 2222, open to the world
#     23  Cowrie fake Telnet    <- redirected to 2323, open to the world
#
# Exposing :22 is deliberate. Nearly all SSH scan traffic targets port 22;
# a honeypot that only listens on 2222 sees a small fraction of it.
#
# LOCKOUT SAFETY
# The script pauses before it moves SSH and refuses to continue until you
# confirm, from a SECOND terminal, that the new port works. Do not skip that.
# =============================================================================

set -euo pipefail

ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-2223}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"
COWRIE_TELNET_PORT="${COWRIE_TELNET_PORT:-2323}"
ADMIN_USER="${ADMIN_USER:-$(whoami)}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
error(){ echo -e "${RED}[x]${NC} $1" >&2; exit 1; }

confirm() {
  # $1 = prompt. Returns 0 on yes. Reads from the terminal even when the
  # script itself was piped in.
  local reply
  read -r -p "$(echo -e "${YELLOW}[?]${NC} $1 [y/N] ")" reply < /dev/tty
  [[ "$reply" =~ ^[Yy]$ ]]
}

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
[ "$EUID" -ne 0 ] || error "Do not run as root. Run as your normal sudo user."
sudo -n true 2>/dev/null || sudo true || error "This user needs sudo."

. /etc/os-release
info "Host: ${PRETTY_NAME:-unknown}"
[ "${ID:-}" = "ubuntu" ] || warn "Written for Ubuntu; ${ID:-unknown} may differ."

# Oracle Cloud images ship their own restrictive iptables ruleset that UFW
# does not manage. Detect so we can deal with it explicitly later.
IS_ORACLE=no
if grep -qi "oraclecloud" /sys/class/dmi/id/chassis_asset_tag 2>/dev/null; then
  IS_ORACLE=yes
  info "Oracle Cloud instance detected."
fi

log "Admin user: $ADMIN_USER  |  admin SSH will move to :$ADMIN_SSH_PORT"
echo ""

# -----------------------------------------------------------------------------
# Step 1: System update + dependencies
# -----------------------------------------------------------------------------
log "Updating packages (2-3 min)..."
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get update -qq
sudo -E apt-get upgrade -y -qq

# Pre-seed iptables-persistent: without this its debconf prompt hangs the run.
echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | sudo debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | sudo debconf-set-selections

log "Installing dependencies..."
sudo -E apt-get install -y -qq \
  python3-pip python3-venv python3-dev \
  libssl-dev libffi-dev build-essential \
  git ufw fail2ban iptables-persistent
log "Dependencies installed."

# -----------------------------------------------------------------------------
# Step 2: Create the cowrie service user
# -----------------------------------------------------------------------------
if id cowrie &>/dev/null; then
  warn "User 'cowrie' already exists — skipping."
else
  log "Creating 'cowrie' service user..."
  sudo adduser --disabled-password --gecos "" cowrie
fi

# -----------------------------------------------------------------------------
# Step 3: Harden sshd and move it off :22
# -----------------------------------------------------------------------------
log "Hardening SSH configuration..."
SSHD_CONFIG=/etc/ssh/sshd_config
sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d%H%M%S)"

sudo sed -i \
  -e "s/^#\?Port .*/Port ${ADMIN_SSH_PORT}/" \
  -e "s/^#\?PermitRootLogin .*/PermitRootLogin no/" \
  -e "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" \
  -e "s/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/" \
  -e "s/^#\?MaxAuthTries .*/MaxAuthTries 3/" \
  "$SSHD_CONFIG"

# Ubuntu's cloud images drop a 50-cloud-init.conf that re-enables password
# auth. Whether it wins depends on where Include sits, so neutralize it.
if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
  sudo sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' \
    /etc/ssh/sshd_config.d/50-cloud-init.conf
  info "Disabled password auth in 50-cloud-init.conf as well."
fi

# `Port` is the one keyword that ACCUMULATES instead of first-value-wins, so a
# Port line in any drop-in adds a SECOND listener rather than being overridden.
# Left alone, sshd keeps answering on :22 next to :2223. Verify with `sshd -T`.
if grep -rqs '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config.d/ 2>/dev/null; then
  sudo sed -i 's/^[[:space:]]*Port[[:space:]]/#&/' /etc/ssh/sshd_config.d/*.conf
  info "Commented out competing Port directives in sshd_config.d/."
fi

if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
  sudo sed -i "s/^AllowUsers .*/AllowUsers ${ADMIN_USER}/" "$SSHD_CONFIG"
else
  echo "AllowUsers ${ADMIN_USER}" | sudo tee -a "$SSHD_CONFIG" >/dev/null
fi

# --- Socket activation (Ubuntu 24.04+) --------------------------------------
# On 24.04 sshd is socket-activated and the listening port comes from
# ssh.socket, NOT from `Port` in sshd_config. Editing only sshd_config there
# silently leaves SSH on 22 — a classic way to think you are hardened and
# not be.
SOCKET_ACTIVATED=no
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  SOCKET_ACTIVATED=yes
  warn "ssh.socket is active — applying the port there (24.04 behaviour)."
  sudo mkdir -p /etc/systemd/system/ssh.socket.d
  # The bare ListenStream= clears the inherited :22 before setting ours.
  sudo tee /etc/systemd/system/ssh.socket.d/override.conf >/dev/null <<EOF
[Socket]
ListenStream=
ListenStream=${ADMIN_SSH_PORT}
EOF
  sudo systemctl daemon-reload
fi

# -----------------------------------------------------------------------------
# Step 4: Firewall — allow the new port BEFORE restarting SSH
# -----------------------------------------------------------------------------
log "Configuring UFW..."
sudo ufw --force reset >/dev/null
sudo ufw default deny incoming >/dev/null
sudo ufw default allow outgoing >/dev/null

# Keep :22 open for the session we are currently sitting in. It gets removed
# in the last step, once the new admin port is proven.
sudo ufw allow 22/tcp                        comment 'TEMP current session' >/dev/null
sudo ufw allow "${ADMIN_SSH_PORT}/tcp"       comment 'Admin SSH' >/dev/null
sudo ufw allow "${COWRIE_SSH_PORT}/tcp"      comment 'Cowrie SSH' >/dev/null
sudo ufw allow "${COWRIE_TELNET_PORT}/tcp"   comment 'Cowrie Telnet' >/dev/null
sudo ufw --force enable >/dev/null
log "UFW enabled."

# Oracle's preinstalled REJECT rules sit in the filter table underneath UFW
# and will drop traffic UFW believes it is allowing.
if [ "$IS_ORACLE" = yes ]; then
  if sudo iptables -S INPUT | grep -q "REJECT"; then
    warn "Oracle's default iptables REJECT rules are present."
    warn "They shadow UFW and will block Cowrie's ports."
    if confirm "Flush Oracle's filter rules and let UFW own filtering?"; then
      sudo iptables -F INPUT
      sudo iptables -F FORWARD
      log "Flushed. UFW is now the only filter ruleset."
    else
      warn "Left in place — expect Cowrie's ports to be unreachable."
    fi
  fi
fi

# -----------------------------------------------------------------------------
# Step 5: Restart SSH  ***LOCKOUT RISK***
# -----------------------------------------------------------------------------
echo ""
warn "================= READ THIS BEFORE CONTINUING ================="
warn "SSH is about to move to port ${ADMIN_SSH_PORT}."
warn "Your CURRENT session stays alive, but new logins move ports."
echo ""
info "After the restart, open a SECOND terminal and run:"
echo ""
echo "    ssh -i <your-key> -p ${ADMIN_SSH_PORT} ${ADMIN_USER}@<this-host-ip>"
echo ""
warn "Do not close this session until that succeeds."
warn "Also confirm your cloud firewall allows ${ADMIN_SSH_PORT} from your IP:"
warn "  Oracle: VCN > Security Lists > Ingress Rules"
warn "  AWS:    EC2 > Security Groups > Inbound Rules"
warn "==============================================================="
echo ""
# Validate before restarting — a syntax error here means sshd never comes back.
sudo sshd -t || error "sshd config is INVALID. Not restarting. Fix ${SSHD_CONFIG} first."
log "sshd config validates."

# `sshd -T` prints the settings sshd will actually use, drop-ins included.
EFFECTIVE_PORTS=$(sudo sshd -T 2>/dev/null | awk '/^port /{print $2}' | sort -u | tr '\n' ' ')
info "Ports sshd will listen on: ${EFFECTIVE_PORTS}"
if echo "$EFFECTIVE_PORTS" | grep -qw 22; then
  warn "sshd still lists port 22 — a drop-in is adding it back."
  warn "Real SSH would stay exposed on the port meant for the honeypot."
  confirm "Continue anyway?" || error "Aborted. Check /etc/ssh/sshd_config.d/"
fi

confirm "Restart SSH on port ${ADMIN_SSH_PORT} now?" || error "Aborted. Nothing restarted."

if [ "$SOCKET_ACTIVATED" = yes ]; then
  sudo systemctl restart ssh.socket
else
  sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd
fi
sleep 2

if ss -tlnp 2>/dev/null | grep -q ":${ADMIN_SSH_PORT}\b"; then
  log "sshd is listening on ${ADMIN_SSH_PORT}."
else
  error "sshd is NOT listening on ${ADMIN_SSH_PORT}. Do not log out. Check: sudo journalctl -u ssh -n 50"
fi

echo ""
confirm "Confirmed you can log in on port ${ADMIN_SSH_PORT} from a second terminal?" \
  || error "Stopping here so you keep your access. Re-run once ${ADMIN_SSH_PORT} works."

# -----------------------------------------------------------------------------
# Step 6: Hand :22 and :23 to Cowrie
# -----------------------------------------------------------------------------
log "Redirecting :22 -> :${COWRIE_SSH_PORT} and :23 -> :${COWRIE_TELNET_PORT}..."

sudo ufw delete allow 22/tcp >/dev/null 2>&1 || true

# REDIRECT rewrites the destination in PREROUTING, so the filter table (UFW)
# sees the *rewritten* port. That is why UFW allows 2222/2323, not 22/23.
add_redirect() {
  local from=$1 to=$2
  if sudo iptables -t nat -C PREROUTING -p tcp --dport "$from" -j REDIRECT --to-port "$to" 2>/dev/null; then
    info "Redirect :$from -> :$to already present."
  else
    sudo iptables -t nat -A PREROUTING -p tcp --dport "$from" -j REDIRECT --to-port "$to"
    log "Added redirect :$from -> :$to"
  fi
}
add_redirect 22 "$COWRIE_SSH_PORT"
add_redirect 23 "$COWRIE_TELNET_PORT"

sudo netfilter-persistent save >/dev/null 2>&1 \
  && log "iptables rules persisted across reboot." \
  || warn "Could not persist iptables rules — they will vanish on reboot."

# -----------------------------------------------------------------------------
# Step 7: Fail2ban on the real SSH port
# -----------------------------------------------------------------------------
log "Configuring Fail2ban..."
# Ubuntu 24.04 has no /var/log/auth.log — sshd logs to journald only, so the
# systemd backend is required or the jail silently watches nothing.
sudo tee /etc/fail2ban/jail.local >/dev/null <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled  = true
port     = ${ADMIN_SSH_PORT}
backend  = systemd
EOF
sudo systemctl enable fail2ban >/dev/null 2>&1
sudo systemctl restart fail2ban
sleep 2
sudo fail2ban-client status sshd >/dev/null 2>&1 \
  && log "Fail2ban is watching the sshd jail." \
  || warn "Fail2ban sshd jail not reporting — check: sudo fail2ban-client status"

# -----------------------------------------------------------------------------
# Step 8: Lock the root account
# -----------------------------------------------------------------------------
sudo passwd -l root >/dev/null && log "Root account locked."

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
log "Hardening complete."
echo ""
echo "  Admin SSH     : ${ADMIN_SSH_PORT}  (key auth only, user ${ADMIN_USER})"
echo "  Cowrie SSH    : 22 -> ${COWRIE_SSH_PORT}"
echo "  Cowrie Telnet : 23 -> ${COWRIE_TELNET_PORT}"
echo "  Root locked   : yes"
echo "  Fail2ban      : active on ${ADMIN_SSH_PORT}"
echo ""
sudo ufw status numbered 2>/dev/null || true
echo ""
warn "STILL TO DO IN YOUR CLOUD CONSOLE:"
echo "  - Allow 22, 23 from 0.0.0.0/0   (the honeypot's bait)"
echo "  - Allow ${ADMIN_SSH_PORT} from YOUR IP ONLY"
echo "  - Remove any other permissive rules"
echo ""
warn "NEXT: install Cowrie"
echo "  sudo cp /opt/cowrie-honeypot/scripts/install-cowrie.sh /tmp/"
echo "  sudo su - cowrie"
echo "  bash /tmp/install-cowrie.sh"
echo "============================================================"
