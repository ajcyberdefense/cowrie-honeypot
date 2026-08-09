# Part 4: Monitoring & Web Dashboard

Read the attack data — from the terminal, and from a browser dashboard that refreshes itself.

> **Prerequisites:** Cowrie running under systemd per [Part 3](03-cowrie-install.md).

---

## A: CLI Analyzer

Quickest way to see what you have caught:

```bash
sudo su - cowrie
~/honeypot/cowrie-env/bin/python3 /opt/cowrie-honeypot/scripts/analyze.py
```

It finds `~/honeypot/var/log/cowrie/cowrie.json` on its own. Override the path if your layout differs:

```bash
COWRIE_JSON_LOG=/path/to/cowrie.json python3 analyze.py
# or
python3 analyze.py /path/to/cowrie.json
```

Output covers totals, unique source IPs, and ranked tables of attacking IPs, usernames, passwords, and commands — plus every successful login and any malware the attackers pulled down.

---

## B: Web Dashboard

Same data, charted, auto-refreshing every 30 seconds.

### Install Flask

Into Cowrie's venv:

```bash
sudo -u cowrie /home/cowrie/honeypot/cowrie-env/bin/pip install flask
```

### Test It by Hand

```bash
sudo su - cowrie
DASHBOARD_PORT=8080 ~/honeypot/cowrie-env/bin/python3 \
  /opt/cowrie-honeypot/scripts/dashboard.py
```

It prints the log path it resolved and the address it bound. Visit `http://YOUR_PUBLIC_IP:8080`, then `Ctrl + C`.

> Open 8080 in the cloud firewall **from your IP only** while testing. The dashboard has no authentication — anyone who reaches it sees your attack data.

### Run It as a Service

```bash
exit
sudo cp /opt/cowrie-honeypot/configs/dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dashboard
sudo systemctl status dashboard
```

The unit serves on port **80**. Ports below 1024 are privileged, and the older approach — running the whole dashboard as root — is unnecessary. The unit grants exactly one capability instead:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

The process still runs as `cowrie`, with permission to bind a low port and nothing else.

### Restrict Access

```bash
sudo ufw allow from YOUR_HOME_IP to any port 80
sudo ufw status
```

Add the matching cloud rule (Oracle Security List / AWS Security Group) for port 80 from your IP only.

Configuration comes from the environment, so no code edits are needed:

| Variable | Default | Purpose |
|---|---|---|
| `COWRIE_JSON_LOG` | auto-detected | Path to `cowrie.json` |
| `DASHBOARD_PORT` | `8080` | Port to bind |
| `DASHBOARD_HOST` | `0.0.0.0` | Interface to bind |

---

## C: Verify Everything Is Up

```bash
sudo systemctl status cowrie dashboard --no-pager
sudo ss -tlnp | grep -E ':(2222|2323|80)\b'
```

Expected:

```
LISTEN 0.0.0.0:2222   twistd     # Cowrie SSH   (:22 redirects here)
LISTEN 0.0.0.0:2323   twistd     # Cowrie Telnet (:23 redirects here)
LISTEN 0.0.0.0:80     python3    # dashboard
```

Confirm the redirects are still in place:

```bash
sudo iptables -t nat -L PREROUTING -n --line-numbers
```

---

## D: Watch Live

```bash
sudo su - cowrie
tail -f ~/honeypot/var/log/cowrie/cowrie.log
```

Just the login attempts:

```bash
tail -f ~/honeypot/var/log/cowrie/cowrie.log | grep "login attempt"
```

Structured events as they land:

```bash
tail -f ~/honeypot/var/log/cowrie/cowrie.json | grep --line-buffered eventid
```

---

## E: Replay Attacker Sessions

The best feature in Cowrie, and the one most people miss. Every session is recorded as a TTY log and replays keystroke by keystroke, in real time:

```bash
sudo su - cowrie
cd ~/honeypot
ls var/lib/cowrie/tty/
cowrie-env/bin/playlog var/lib/cowrie/tty/<file>
```

You watch the attacker type — including their typos and their pauses. This is the single most compelling artifact to put in a writeup or show in an interview.

---

## Monitoring Checklist

- [ ] `analyze.py` runs and finds the log
- [ ] Flask installed in Cowrie's venv
- [ ] Dashboard reachable, restricted to your IP
- [ ] `dashboard` service enabled and active
- [ ] Both services show `active (running)`
- [ ] NAT redirects confirmed present
- [ ] A session replayed with `playlog`

---

## What You Will See

Leave it running overnight. Bots sweep the entire IPv4 space for open SSH continuously; with port 22 redirected to Cowrie, the first hits usually arrive within an hour.

**Passwords:** `123456`, `admin`, `password`, `root`, `1234`, `test`

**Every attacker fails once before getting in.** The honeypot is configured to reject the first credential pair from any new source IP and admit the second (`auth_class = AuthRandom`, see [Part 3](03-cowrie-install.md)). So a normal successful intrusion looks like this in the log:

```
cowrie.login.failed    45.9.148.99  root/123456
cowrie.login.success   45.9.148.99  root/admin
cowrie.session.connect ...
cowrie.command.input   uname -a
```

If you see a `login.success` with no preceding `login.failed` from that IP, the attacker reused credentials that already worked for them earlier.

**Commands, in a recognizable order:**

| Command | What they are doing |
|---|---|
| `uname -a` | Fingerprinting the kernel |
| `cat /proc/cpuinfo` | Sizing the box for cryptomining |
| `wget http://…` / `curl -O …` | Pulling second-stage malware |
| `chmod +x …` | Making it executable |
| `crontab -l` | Establishing persistence |

None of it executes. Cowrie emulates the shell — the filesystem is fake and the commands are simulated.

> **One real behaviour to know about:** when an attacker runs `wget`, Cowrie genuinely fetches the file so it can capture the sample to `var/lib/cowrie/downloads/`. That is real outbound traffic to malware infrastructure. It is normal for a honeypot, but it is why you keep this on a disposable host, and `download_limit_size` in `cowrie.cfg` caps what gets stored.

---

## Where to Take It Next

- **Submit hashes to VirusTotal** — Cowrie has an `[output_virustotal]` plugin
- **Ship to Elasticsearch or Splunk** — `[output_elasticsearch]`, `[output_splunk]`
- **Feed threat intel** — `[output_dshield]`, `[output_abuseipdb]`
- **Report to AbuseIPDB** — turns your honeypot into a contribution to community blocklists

All are configured in `etc/cowrie.cfg`; see the `cowrie.cfg.dist` reference for the full list.
