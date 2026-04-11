# Part 3: Installing and Configuring Cowrie

This guide covers installing Cowrie, configuring it, running it as a system service, and verifying it captures attacks.

> **Prerequisites:** Instance is hardened per [Part 2](02-hardening.md). You are SSH'd in on port 2223.

---

## A: Switch to the Cowrie User

All Cowrie work runs as the dedicated `cowrie` user — never as root:

```bash
sudo su - cowrie
```

Your prompt changes to `cowrie@ip-...` — that means it worked.

---

## B: Clone the Cowrie Repository

```bash
git clone https://github.com/cowrie/cowrie
cd cowrie
```

---

## C: Create a Python Virtual Environment

A virtual environment keeps Cowrie's dependencies isolated:

```bash
python3 -m venv cowrie-env
source cowrie-env/bin/activate
```

Your prompt will show `(cowrie-env)` — the environment is active.

---

## D: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This takes 1–2 minutes. You'll see a lot of output — that's normal.

---

## E: Create the Config File

```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
nano etc/cowrie.cfg
```

Find and update these settings (`Ctrl + W` to search):

```ini
# Hostname attackers see when they connect
hostname = svr04

# Fake SSH listener port
listen_endpoints = tcp:2222:interface=0.0.0.0

# Enable Telnet
[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0
```

> **Common mistake:** `enabled = enable` will crash Cowrie. It must be `enabled = true`.

Save with `Ctrl + X` → `Y` → `Enter`

---

## F: Test Start Cowrie Manually

```bash
cowrie start
cowrie status
```

Expected output:
```
cowrie is running (PID XXXXX)
```

Test it by connecting from your local machine:
```powershell
ssh -p 2222 root@YOUR_ELASTIC_IP
```

Try any password — Cowrie will fake a login. Type commands like `ls`, `whoami`, then `exit`.

---

## G: Set Up Cowrie as a System Service

Switch back to the ubuntu user:

```bash
exit
```

Create the systemd service file:

```bash
sudo nano /etc/systemd/system/cowrie.service
```

Paste:

```ini
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
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl start cowrie
sudo systemctl status cowrie
```

Look for `Active: active (running)` in green.

---

## H: Verify Logs Are Being Written

```bash
sudo su - cowrie
cd cowrie
tail -f var/log/cowrie/cowrie.log
```

Connect from your laptop to generate a log entry:
```powershell
ssh -p 2222 root@YOUR_ELASTIC_IP
```

You will see your connection appear live. Press `Ctrl + C` to stop watching.

---

## Cowrie Installation Checklist

- [ ] Cowrie cloned to `/home/cowrie/cowrie`
- [ ] Virtual environment created and activated
- [ ] Requirements installed
- [ ] `etc/cowrie.cfg` created from template
- [ ] Cowrie starts successfully (`cowrie status` shows running)
- [ ] Systemd service enabled and running
- [ ] Logs writing to `var/log/cowrie/cowrie.log`
- [ ] Test connection captured in logs

---

## Troubleshooting

**`ValueError: Not a boolean: enable`**
Open `etc/cowrie.cfg` and find `enabled = enable` in the `[telnet]` section. Change to `enabled = true`.

**`FileNotFoundError` in systemd**
The `Environment="PATH=..."` line is missing from the service file. The venv path must be explicitly set for systemd.

**Cowrie not capturing connections**
Check UFW allows port 2222: `sudo ufw status`
Check Cowrie is listening: `ss -tlnp | grep 2222`

---

Next: [Part 4: Monitoring and Analysis](04-monitoring.md)
