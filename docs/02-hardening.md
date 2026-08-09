# Part 2: Instance Hardening

Harden the host before Cowrie goes anywhere near the internet, and hand ports 22 and 23 over to the honeypot.

> **Prerequisites:** An Ubuntu 22.04 or 24.04 instance you can SSH into on port 22. See [Oracle setup](01-oracle-setup.md) or [AWS setup](01-aws-setup.md).

---

## The Port Plan

This is the part worth understanding before you type anything.

```
        Internet
           │
    ┌──────┴───────────────────────────────┐
    │                                      │
  :22 ─────► iptables REDIRECT ─────► :2222  Cowrie fake SSH
  :23 ─────► iptables REDIRECT ─────► :2323  Cowrie fake Telnet
                                              (open to the world)
  :2223 ──────────────────────────────────►  Real sshd
                                              (your IP only)
```

**Why redirect port 22 instead of leaving it closed?** Effectively all SSH scanning targets port 22. A honeypot listening only on 2222 sees a small fraction of the traffic — it works, but you wait days for data instead of hours.

**Why 2323 for Telnet and not 23 directly?** Cowrie runs unprivileged and cannot bind ports below 1024. And Cowrie's *default* telnet port is 2223 — the same port this guide uses for real admin SSH. Left unchanged, the two fight over it. The shipped `configs/cowrie.cfg` pins Telnet to 2323 for exactly this reason.

---

## Automated Path (recommended)

```bash
sudo apt update && sudo apt install -y git
sudo git clone https://github.com/ajcyberdefense/cowrie-honeypot /opt/cowrie-honeypot
bash /opt/cowrie-honeypot/scripts/harden.sh
```

The script does everything below, pauses before the risky step, and **refuses to continue until you confirm the new SSH port works from a second terminal.**

Skip to [Part 3](03-cowrie-install.md) when it finishes. The manual steps are documented below so you know what it did.

---

## Manual Path

### A: Update and Install

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv python3-dev \
  libssl-dev libffi-dev build-essential \
  git ufw fail2ban iptables-persistent
```

### B: Create the Cowrie Service User

Cowrie refuses to run as root, by design.

```bash
sudo adduser --disabled-password --gecos "" cowrie
id cowrie
```

### C: Harden sshd

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
sudo nano /etc/ssh/sshd_config
```

Set:

```
Port 2223
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers ubuntu
```

Cloud images also drop `/etc/ssh/sshd_config.d/50-cloud-init.conf`, which often re-enables password auth. Whether it wins depends on where the `Include` line sits, so fix it there too:

```bash
sudo sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' \
  /etc/ssh/sshd_config.d/50-cloud-init.conf
```

### C2: Ubuntu 24.04 — the socket activation trap

**On 24.04, `Port` in `sshd_config` is ignored.** sshd is socket-activated and the port comes from `ssh.socket`. Editing only `sshd_config` leaves SSH on 22 while you believe it moved — and then the port 22 redirect sends your admin traffic to the honeypot.

Check:

```bash
systemctl is-enabled ssh.socket
```

If that prints `enabled`:

```bash
sudo mkdir -p /etc/systemd/system/ssh.socket.d
sudo tee /etc/systemd/system/ssh.socket.d/override.conf <<'EOF'
[Socket]
ListenStream=
ListenStream=2223
EOF
sudo systemctl daemon-reload
```

The bare `ListenStream=` clears the inherited `:22` — without it you end up listening on **both** ports.

On 22.04 this does not apply.

### D: Firewall — allow the new port *first*

Order matters. Allow 2223 before restarting SSH, and keep 22 open until the new port is proven.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp          # TEMPORARY - current session
sudo ufw allow 2223/tcp        # admin SSH
sudo ufw allow 2222/tcp        # Cowrie SSH (post-redirect)
sudo ufw allow 2323/tcp        # Cowrie Telnet (post-redirect)
sudo ufw enable
```

> **Why allow 2222 and not 22?** `REDIRECT` rewrites the destination port in the `nat` PREROUTING chain, *before* the packet reaches the filter chain UFW controls. UFW therefore sees the rewritten port.

**On Oracle Cloud**, check for the preinstalled ruleset that shadows UFW:

```bash
sudo iptables -L INPUT -n --line-numbers
```

If you see `REJECT` rules, flush them so UFW is the only filter ruleset:

```bash
sudo iptables -F INPUT
sudo iptables -F FORWARD
```

### E: Restart SSH — lockout risk

```bash
sudo systemctl restart ssh        # 22.04
sudo systemctl restart ssh.socket # 24.04
```

Verify it bound:

```bash
sudo ss -tlnp | grep 2223
```

**Open a second terminal and confirm before going further:**

```bash
ssh -i ~/.ssh/cowrie_oracle -p 2223 ubuntu@YOUR_PUBLIC_IP
```

> Do not close your first session until this succeeds. If you are locked out, Oracle's **Console Connection** (Instance → Resources → Console Connection) and AWS's **EC2 Instance Connect** both give you out-of-band access.

### F: Hand 22 and 23 to Cowrie

Only after 2223 is confirmed:

```bash
sudo ufw delete allow 22/tcp

sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323

sudo netfilter-persistent save
```

Without that last line the rules disappear on reboot and the honeypot goes quiet.

> Redirect rules do not apply to loopback — test from another machine, not with `ssh localhost`.

### G: Fail2ban

On 24.04 there is no `/var/log/auth.log`; sshd logs to journald only, so the jail needs the systemd backend or it silently watches nothing.

```bash
sudo tee /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled  = true
port     = 2223
backend  = systemd
EOF

sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

Fail2ban protects **real** sshd on 2223 only. It never sees Cowrie's traffic — Cowrie keeps its own logs and must not be banned, since banning attackers is the opposite of the goal.

### H: Lock Root

```bash
sudo passwd -l root
```

---

## Hardening Checklist

- [ ] System updated, dependencies installed
- [ ] `cowrie` user created
- [ ] sshd on 2223, key-only, root login denied
- [ ] 24.04 only: `ssh.socket` override applied
- [ ] **Confirmed login on 2223 from a second terminal**
- [ ] UFW active: 2223, 2222, 2323 (22 removed)
- [ ] Oracle only: shadowing iptables REJECT rules flushed
- [ ] NAT redirects 22→2222 and 23→2323 added **and persisted**
- [ ] Fail2ban running with the correct backend
- [ ] Root account locked

---

## Troubleshooting

**Locked out after restarting SSH**
Oracle: Instance → Console Connection. AWS: EC2 Instance Connect. Both bypass sshd.

**SSH still answering on 22 after the change**
You are on 24.04 and skipped step C2. `sudo ss -tlnp | grep sshd` will show it.

**Cowrie's ports unreachable from outside, fine locally**
Three layers must all allow it: cloud firewall (Security List / Security Group) → host iptables → UFW. On Oracle it is nearly always the preinstalled iptables rules.

**Redirects gone after reboot**
`sudo netfilter-persistent save` was not run.

**Fail2ban banned your own IP**
```bash
sudo fail2ban-client set sshd unbanip YOUR_IP
```

---

Next: [Part 3: Installing Cowrie](03-cowrie-install.md)
