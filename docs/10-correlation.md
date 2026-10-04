# Part 10: Correlation Rules

Detections that need more than one event — written for the gaps Parts 6 and 8 named, checked against Python like everything in [Part 9](09-siem.md), and then measured for whether they actually add anything.

> **Prerequisites:** the Elastic stack and loaded history from Part 9.

---

## A: The Gaps

Every Part 6 rule looks at one command line. Three blind spots were documented:

1. **No commands at all.** Part 8's largest logged-in population logs in, asks the SSH server to tunnel a TCP connection to a mail server, and leaves. Command rules have nothing to look at.
2. **Chains split across commands.** `wget x` in one command, `chmod 777 x` in the next. The single-line `download_execute_chain` rule sees neither half as suspicious.
3. **Recon is only suspicious in bulk.** `uname`, `free` and `lscpu` are admin commands; nine of them in two seconds is a script.

Each gets the Kibana rule type that fits it:

| Rule | Kibana type | Logic |
|---|---|---|
| `smtp_tunnel` | query | `cowrie.direct-tcpip.request` to port 25, 465 or 587 |
| `split_download_chmod` | EQL sequence | by session, within 2 min: a `wget`/`curl`/`tftp`/`ftpget` command, then a *later* `chmod +x` / `7xx` |
| `recon_burst` | threshold | per session, ≥ 6 *distinct* fingerprint commands (`uname`, `whoami`, `w`, `crontab -l`, `top`, `lscpu`, `free`, `df`, `cat /proc/cpuinfo`, …) |

```bash
python3 scripts/siem_correlation.py                       # parity check vs Python
python3 scripts/siem_correlation.py --install --backfill  # create rules, look back 90 days once
python3 scripts/siem_correlation.py --install             # live mode
python3 scripts/test_siem_correlation.py                  # offline self-check
```

---

## B: Thresholds Come From the Data

None of the numbers was picked by feel:

- **Split window: 2 minutes.** Across all 784 sessions with a split chain, the longest gap between download and chmod was 107 s (99th percentile: 46 s).
- **Recon threshold: 6.** Distinct fingerprint commands per session are bimodal — 52,884 sessions ran none, 911 ran one, 52 ran three, then **nothing until 6**, and 548 ran exactly nine. Any threshold from 4 to 6 separates the populations; 6 leaves the most room for an admin who checks a few things at once.
- **Mail ports: 25, 465, 587.** Observed tunnel destinations were port 25 (691), 443 (155), 80 (33), 2535 (23) and 587 (4). The rule takes all three mail ports, because 465 and 587 serve the same purpose as 25.

---

## C: One Pattern, Three Engines

Part 9 found two rules that Python and Elasticsearch read differently, and fixed them by translating. This time each pattern is written once, in the regex subset that **Python, Lucene and EQL** all read the same way:

- no `\s`, `\b`, `\d` — explicit classes instead, with word boundaries written as `[^A-Za-z0-9_]`
- matched against the **whole** field (Python uses `re.fullmatch` with `re.S`)
- no backslash escapes — EQL strings reject `\+`, so `[+]` instead

```
DOWNLOAD = (.*[^A-Za-z0-9_])?(wget|curl|tftp|ftpget)([^A-Za-z0-9_].*)?
CHMOD    = (.*[^A-Za-z0-9_])?chmod[ \t]+([+]x|[0-7]?[0-7][0-7]7)([^A-Za-z0-9_].*)?
```

Parity on the first run:

| Rule | Python | Elastic | |
|---|---:|---:|---|
| `smtp_tunnel` (events) | 695 | 695 | exact |
| `split_download_chmod` (sessions) | 784 | 784 | exact |
| `recon_burst` (sessions) | 554 | 554 | exact |

All three fired in Kibana's Security app on their backfill run, then were reinstalled in live mode. (The EQL rule shows 300 alerts for 100 sequences: Kibana also records each event in a sequence as a *building block* alert.)

---

## D: Do They Add Anything?

A new rule is only worth its alert volume if it catches something the existing rules don't. Measured against **all nine** Part 6 rules:

| Rule | Sessions | Source IPs | Caught by no Part 6 rule |
|---|---:|---:|---:|
| `smtp_tunnel` | 695 | 689 | **695 sessions, 689 IPs** |
| `split_download_chmod` | 784 | 453 | 5 sessions, 3 IPs |
| `recon_burst` | 554 | 554 | 0 |

**`smtp_tunnel` closes a real blind spot.** Every one of its 695 sessions was invisible before.

**`split_download_chmod` mostly doesn't.** Against the single-line download rule alone it finds 87 more sessions, but 82 of those were already flagged by *another* Part 6 rule in the same session — mostly `ssh_key_implant` (61) and `pipe_to_shell` (19). Its real value is a second, independent signal on the same intrusion: an attacker who changes the key-planting step still trips this one.

**`recon_burst` adds nothing here.** All 554 sessions also trip `ssh_key_implant`, and in every one of them the recon runs *after* the key is planted — so it is not even an earlier warning. It stays, at `medium`, for a variant that fingerprints without planting a key. On this data it is redundant, and the honest thing is to say so.

---

## E: Lessons

- **Measure a rule's marginal value, not just its hits.** 784 matches sounded like a strong new detection. 5 new sessions is the real number.
- **The biggest gap was the event type nobody watched.** The highest-value rule here has no regex at all — it's a port number on an event the command rules never looked at.
- **Let the distribution pick the threshold.** A bimodal histogram makes the choice obvious and defensible; a guessed "5" would have been neither.
- **Write portable patterns instead of translating.** One pattern in the shared regex subset gave exact parity on the first run; translating in Part 9 took two rounds of fixes.
