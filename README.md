# Cowrie SSH Honeypot on AWS

A fully documented deployment of the [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot on a hardened AWS EC2 instance, with traffic monitoring and attacker session analysis.

---

## What Is a Honeypot?

A honeypot is a deliberately exposed decoy server designed to attract attackers. Instead of defending against intrusion, it lets attackers in — and records everything they do. This project uses **Cowrie**, one of the most widely used open-source honeypots, to:

- Capture brute-force login attempts
- Record full attacker sessions (every command they type)
- Log malware download attempts
- Analyze attacker behavior and origin

---

## Architecture

```
Internet (attackers)
        │
        ▼
  AWS Security Group
        │
  ┌─────┴──────────────────────┐
  │   EC2 Ubuntu 22.04 LTS     │
  │                            │
  │  Port 2222 ──► Cowrie      │  ← attackers land here (fake SSH)
  │  Port 23   ──► Cowrie      │  ← attackers land here (fake Telnet)
  │                            │
  │  Port 2223 ──► Real SSH    │  ← admin only (your IP)
  │                            │
  │  UFW Firewall              │
  │  Fail2ban                  │
  └────────────────────────────┘
        │
        ▼
  Logs & Session Recordings
        │
        ▼
  Analysis & Visualization
```

---

## Repository Structure

```
cowrie-honeypot/
├── README.md                   # This file
├── .gitignore                  # Excludes sensitive data and logs
│
├── docs/
│   ├── 01-aws-setup.md         # EC2 instance, security groups, Elastic IP
│   ├── 02-hardening.md         # SSH hardening, UFW, Fail2ban, users
│   ├── 03-cowrie-install.md    # Installing and configuring Cowrie
│   └── 04-monitoring.md        # Log analysis and traffic monitoring
│
├── scripts/
│   ├── harden.sh               # Automated instance hardening script
│   ├── install-cowrie.sh       # Automated Cowrie installation script
│   ├── analyze.py              # CLI log parser and attack summary
│   └── dashboard.py            # Flask web dashboard (real-time attack visualization)
│
├── configs/
│   ├── sshd_config             # Hardened SSH daemon configuration
│   ├── cowrie.cfg              # Cowrie honeypot configuration
│   ├── cowrie.service          # Systemd service for Cowrie
│   └── dashboard.service       # Systemd service for web dashboard
│
├── logs/                       # Gitignored — local log storage only
│   └── .gitkeep
│
└── analysis/                   # Attack analysis outputs
    └── .gitkeep
```

---

## Setup Guide

Follow the docs in order:

1. [AWS Instance Setup](docs/01-aws-setup.md)
2. [Instance Hardening](docs/02-hardening.md)
3. [Cowrie Installation](docs/03-cowrie-install.md)
4. [Monitoring & Web Dashboard](docs/04-monitoring.md)

---

## Tech Stack

| Component | Tool |
|-----------|------|
| Cloud Provider | AWS EC2 |
| OS | Ubuntu 22.04 LTS |
| Honeypot | Cowrie |
| Firewall | UFW |
| Intrusion Prevention | Fail2ban |
| Web Dashboard | Flask + Chart.js |
| Language | Python 3 |
| Process Management | Systemd |

---

## Security Notice

> This project intentionally exposes services to the public internet for research purposes. The honeypot is isolated and runs as an unprivileged user. Never run a honeypot on a machine with sensitive data or production services.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
