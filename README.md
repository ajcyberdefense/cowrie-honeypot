# Cowrie SSH/Telnet Honeypot

A fully documented deployment of the [Cowrie](https://github.com/cowrie/cowrie) honeypot on a hardened cloud instance, with traffic redirection, session recording, and attacker analysis.

Runs on **Oracle Cloud's Always Free tier** at no cost, or on AWS EC2.

---

## What Is a Honeypot?

A honeypot is a deliberately exposed decoy server. Instead of keeping attackers out, it lets them in and records everything they do. Cowrie emulates a Linux shell convincingly enough that automated attacks run to completion — and every keystroke is captured.

This deployment captures:

- Brute-force login attempts (source IP, username, password)
- Full session recordings, replayable keystroke by keystroke
- Commands attackers run once "inside"
- Malware they attempt to download

---

## Architecture

```
                        Internet (scanners, botnets)
                                    │
                    ┌───────────────┴────────────────┐
                    │   Cloud Firewall               │
                    │   (Security List / Group)      │
                    └───────────────┬────────────────┘
                                    │
   ┌────────────────────────────────┴─────────────────────────────────┐
   │  Ubuntu 22.04 / 24.04                                            │
   │                                                                  │
   │   :22  ──iptables REDIRECT──►  :2222  Cowrie SSH      ◄── world  │
   │   :23  ──iptables REDIRECT──►  :2323  Cowrie Telnet   ◄── world  │
   │                                                                  │
   │   :2223 ─────────────────────►  real sshd             ◄── my IP  │
   │   :80   ─────────────────────►  Flask dashboard       ◄── my IP  │
   │                                                                  │
   │   UFW · Fail2ban · root locked · cowrie runs unprivileged        │
   └────────────────────────────────┬─────────────────────────────────┘
                                    │
                   var/log/cowrie/cowrie.json  (structured events)
                   var/lib/cowrie/tty/         (session recordings)
                                    │
                    ┌───────────────┴────────────────┐
                    │  analyze.py  ·  dashboard.py   │
                    └────────────────────────────────┘
```

**Port 22 is redirected to the honeypot on purpose.** Nearly all SSH scanning targets port 22 — a honeypot listening only on 2222 sees a fraction of the traffic. Real admin access moves to 2223, restricted to a single IP.

---

## Setup Guide

Follow in order. Part 1 depends on your cloud; everything after is identical.

1. **[Oracle Cloud Setup](docs/01-oracle-setup.md)** — Always Free, permanent, $0 *(recommended)*
   or [AWS Setup](docs/01-aws-setup.md) — EC2, Elastic IP
2. **[Instance Hardening](docs/02-hardening.md)** — SSH relocation, UFW, Fail2ban, port redirects
3. **[Cowrie Installation](docs/03-cowrie-install.md)** — install, configure, systemd
4. **[Monitoring & Dashboard](docs/04-monitoring.md)** — analysis, web dashboard, session replay

### Quick Start

Once your instance is up and you can SSH in:

```bash
sudo apt update && sudo apt install -y git
sudo git clone https://github.com/ajcyberdefense/cowrie-honeypot /opt/cowrie-honeypot

# Harden the host and hand :22 / :23 to the honeypot.
# Pauses before moving SSH; will not continue until you confirm the new port.
bash /opt/cowrie-honeypot/scripts/harden.sh

# Install Cowrie
sudo cp /opt/cowrie-honeypot/scripts/install-cowrie.sh /tmp/
sudo su - cowrie
bash /tmp/install-cowrie.sh
```

---

## Repository Structure

```
cowrie-honeypot/
├── docs/
│   ├── 01-oracle-setup.md      # Oracle Cloud Always Free (recommended)
│   ├── 01-aws-setup.md         # AWS EC2 alternative
│   ├── 02-hardening.md         # Host hardening + port redirects
│   ├── 03-cowrie-install.md    # Cowrie install and systemd
│   └── 04-monitoring.md        # Analysis, dashboard, session replay
│
├── scripts/
│   ├── harden.sh               # Host hardening (lockout-safe, prompts to confirm)
│   ├── install-cowrie.sh       # Cowrie install via pip
│   ├── analyze.py              # CLI log parser and attack summary
│   └── dashboard.py            # Flask dashboard with charts
│
├── configs/
│   ├── sshd_config             # Hardened sshd for the host
│   ├── cowrie.cfg              # Cowrie overrides (layered on bundled defaults)
│   ├── cowrie.service          # Systemd unit for Cowrie
│   └── dashboard.service       # Systemd unit for the dashboard
│
├── logs/                       # Gitignored — local log copies
└── analysis/                   # Analysis outputs
```

---

## On-Host Layout

```
/opt/cowrie-honeypot/           this repo
/home/cowrie/honeypot/          honeypot state directory
├── cowrie-env/                 virtualenv (cowrie installed here)
├── etc/cowrie.cfg              active config
└── var/
    ├── log/cowrie/cowrie.json  structured events
    ├── log/cowrie/cowrie.log   runtime log
    ├── lib/cowrie/tty/         session recordings
    └── lib/cowrie/downloads/   captured malware samples
```

---

## Tech Stack

| Component | Tool |
|---|---|
| Cloud | Oracle Cloud (Always Free) or AWS EC2 |
| OS | Ubuntu 22.04 / 24.04 LTS |
| Honeypot | Cowrie 3.x (`pip install cowrie`) |
| Firewall | UFW + iptables NAT redirects |
| Intrusion Prevention | Fail2ban |
| Dashboard | Flask + Chart.js |
| Process Management | systemd |

---

## Notes on Cowrie 3.x

Cowrie changed its install model, and most guides online are now out of date:

- It installs **from PyPI** (`pip install cowrie`), not from a git checkout
- The `bin/cowrie` launcher was **removed upstream**
- `pip install -r requirements.txt` installs dependencies *only* — it never creates the `cowrie` command
- State is initialized with `cowrie init` in a directory of your choosing
- Python **3.10+** is required

The scripts and configs here target this model. See [Part 3](docs/03-cowrie-install.md) for the full comparison.

---

## Security Notice

> This project intentionally exposes services to the public internet. The honeypot runs as an unprivileged user and emulates commands rather than executing them — an attacker never reaches a real shell.
>
> Run it on a **disposable host with no sensitive data and no production services**. Note that Cowrie really does fetch files an attacker tries to `wget`, in order to capture the sample; that is real outbound traffic to malware infrastructure.

---

## License

MIT License — see [LICENSE](LICENSE).
