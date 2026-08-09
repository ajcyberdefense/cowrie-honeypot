# Part 3: Installing and Configuring Cowrie

Install Cowrie, run it under systemd, and confirm it captures attacks.

> **Prerequisites:** Host hardened per [Part 2](02-hardening.md). You are SSH'd in on port 2223.

---

## What Changed in Cowrie 3.x

If you followed an older guide, the install looked like this:

```bash
git clone https://github.com/cowrie/cowrie
pip install -r requirements.txt
bin/cowrie start
```

**That no longer works.** Cowrie 3.0 ships as a package on PyPI, `bin/cowrie` was removed upstream, and `requirements.txt` installs Cowrie's *dependencies* without installing Cowrie itself — so no `cowrie` command is ever created. The current path is below.

| | Old | Current |
|---|---|---|
| Source | `git clone` | `pip install cowrie` |
| Launcher | `bin/cowrie` | `cowrie` console script |
| Setup | copy `cowrie.cfg.dist` | `cowrie init` |
| State dir | the git checkout | any directory you choose |

Cowrie 3.x requires **Python 3.10+**. Ubuntu 22.04 ships 3.10; 24.04 ships 3.12.

---

## Automated Path (recommended)

```bash
sudo cp /opt/cowrie-honeypot/scripts/install-cowrie.sh /tmp/
sudo su - cowrie
bash /tmp/install-cowrie.sh
```

Then skip to [section F](#f-run-cowrie-under-systemd).

---

## Manual Path

### A: Switch to the Cowrie User

```bash
sudo su - cowrie
```

Your prompt changes to `cowrie@...`.

### B: Create the Honeypot Directory

Everything — venv, config, logs, downloads, TTY recordings — lives in one self-contained directory.

```bash
mkdir -p ~/honeypot && cd ~/honeypot
```

### C: Virtual Environment

```bash
python3 -m venv cowrie-env
source cowrie-env/bin/activate
```

Your prompt shows `(cowrie-env)`.

### D: Install Cowrie

```bash
python -m pip install --upgrade pip
python -m pip install cowrie
```

Takes 1–3 minutes; several dependencies have native components. Verify:

```bash
cowrie --help
python -m pip show cowrie | grep Version
```

If `cowrie: command not found`, the venv is not active — re-run `source cowrie-env/bin/activate`.

### E: Initialize and Configure

```bash
cowrie init
```

That writes `etc/cowrie.cfg` and creates `var/log/cowrie`, `var/lib/cowrie`, `var/run`.

> `cowrie init` is **not** idempotent — it exits non-zero rather than overwrite an existing config.

Apply this repo's config:

```bash
cp /opt/cowrie-honeypot/configs/cowrie.cfg ~/honeypot/etc/cowrie.cfg
```

Cowrie layers its configuration — bundled defaults first, then your `etc/cowrie.cfg` on top — so that file only needs the keys being changed. The important ones:

```ini
[honeypot]
hostname = svr04
# Fail the 1st login attempt, admit on the 2nd. See below.
auth_class = AuthRandom
auth_class_parameters = 2, 2, 0

[shell]
# Note: the fake-system keys live in [shell], not [honeypot].
arch = linux-x64-lsb
kernel_version = 5.15.0-119-generic

[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
# NOT the default 2223 - that collides with admin SSH.
listen_endpoints = tcp:2323:interface=0.0.0.0
```

### Why the first login fails

A honeypot that accepts the very first credential offered is an obvious tell — a real box with a weak password still rejects the other guesses in a bot's list. `AuthRandom` admits a source IP once its attempt counter reaches a target drawn from `randint(<min try>, <max try>)`. Setting both bounds to `2` makes that target exactly 2, every time:

```
172.18.0.3   root/123456  ->  cowrie.login.failed
172.18.0.3   root/admin   ->  cowrie.login.success
```

Counters are tracked **per source IP**, so every new attacker fails once first.

The third parameter is a cross-IP cache of pairs already known to work. It is `0` deliberately: with a non-zero cache, a brand-new IP whose *first* guess matches a cached pair is admitted immediately, breaking the rule. Set it to `10` if you would rather model a botnet sharing a known-good password.

Three behaviours to expect:

| Situation | Result |
|---|---|
| Bot repeats the **same** username:password | Counter never advances — it never gets in |
| Attacker returns later with the **same** pair that worked | Admitted again |
| Attacker returns with a **different** pair | Rejected |

State lives in `var/lib/cowrie/auth_random.json`. Delete it to reset every attacker's counter.

> This replaces `etc/userdb.txt` entirely — with `AuthRandom`, *any* username and password works on the second try. Set `auth_class = UserDB` to control exactly which credentials succeed, at the cost of admitting on the first matching guess.

The full reference is the `cowrie.cfg.dist` that `cowrie init` materializes alongside your config.

### F: Start and Verify

```bash
cowrie start
sleep 3
cowrie status
```

Expected: `cowrie is running (PID: NNNNN).`

Confirm both listeners bound:

```bash
ss -tlnp | grep -E ':(2222|2323)'
```

```
LISTEN 0 50 0.0.0.0:2222 users:(("twistd",pid=4072,fd=11))
LISTEN 0 50 0.0.0.0:2323 users:(("twistd",pid=4072,fd=12))
```

Test from your laptop — port 22 redirects to Cowrie:

```powershell
ssh -p 22 root@YOUR_PUBLIC_IP
```

Any password works. Try `ls`, `whoami`, `uname -a`, then `exit`.

> Connecting from the host itself will not work — `REDIRECT` rules skip loopback. Test from another machine.

---

## F: Run Cowrie Under Systemd

Leave the cowrie user:

```bash
exit
```

Install the unit:

```bash
sudo cp /opt/cowrie-honeypot/configs/cowrie.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
sudo systemctl status cowrie
```

Look for `Active: active (running)`.

The unit differs from the usual copy-paste versions in two ways that matter:

- **`PIDFile=` is declared.** `cowrie start` daemonizes via twistd. With `Type=forking` and no `PIDFile`, systemd guesses the main process and gets it wrong — the service looks dead, or restarts in a loop.
- **`Environment="PATH=…/cowrie-env/bin:…"`.** `cowrie` is a console script inside the venv, not a system binary. Without the venv on `PATH`, systemd cannot find it.

---

## G: Verify Logging

```bash
sudo su - cowrie
tail -f ~/honeypot/var/log/cowrie/cowrie.log
```

Connect from your laptop again; the session appears live. `Ctrl + C` to stop.

Two log files, different jobs:

| File | What it is |
|---|---|
| `var/log/cowrie/cowrie.log` | Twisted's runtime log — read this when debugging startup |
| `var/log/cowrie/cowrie.json` | Structured events — what `analyze.py` and the dashboard parse |

Confirm JSON events are landing:

```bash
grep -c eventid ~/honeypot/var/log/cowrie/cowrie.json
```

---

## Installation Checklist

- [ ] Python 3.10+ confirmed
- [ ] `~/honeypot` created with venv inside
- [ ] `pip install cowrie` succeeded, `cowrie --help` works
- [ ] `cowrie init` run
- [ ] Repo config copied to `etc/cowrie.cfg`
- [ ] Listeners bound on **2222 and 2323**
- [ ] Test connection from an external machine captured
- [ ] Systemd service enabled and active
- [ ] `cowrie.json` receiving events

---

## Troubleshooting

**`cowrie: command not found`**
The venv is not active, or `pip install -r requirements.txt` was used instead of `pip install cowrie` — that installs dependencies only and never creates the command.

**`ERROR: cowrie is not initialized`**
Wrong working directory. `cd ~/honeypot` first — Cowrie resolves `etc/` and `var/` relative to CWD.

**Telnet listener missing, or sshd behaving strangely**
Port collision: Cowrie's default telnet port is 2223, the same as admin SSH. Pin `listen_endpoints = tcp:2323:...` in `[telnet]`.

**Service fails, but `cowrie start` works by hand**
Almost always the missing `PATH` or `PIDFile` in the unit. Check `sudo journalctl -u cowrie -n 50`.

**`Not a boolean: enable`**
`enabled = enable` in the config. It must be `true`.

**Nothing in the logs after hours**
Verify the redirect survived: `sudo iptables -t nat -L PREROUTING -n`. If empty, run `sudo netfilter-persistent save` after re-adding.

**`No moduli, no diffie-hellman-group-exchange-sha1` at startup**
Harmless. Cowrie logs it when no moduli file is present; connections still work.

---

Next: [Part 4: Monitoring and Analysis](04-monitoring.md)
