# Part 9: SIEM — Same Answers, Different Tool

Replay the honeypot's full history into Elasticsearch + Kibana, rebuild `analyze.py`'s report as a dashboard, port the Part 6 Sigma rules into Kibana's detection engine — and prove every number matches the Python that came before.

> **Prerequisites:** Docker, ~4 GB of free RAM, the log history in `logs/` (Part 6), and optionally `analysis/intel.json` from [Part 8](08-threat-intel.md) for ASN/country/tier fields.

The point of this part isn't the stack. The answers are already known from Parts 5–8, which turns a SIEM into something it rarely is: a system you can **check**. Every query, dashboard panel and detection here is compared with a Python count of the same log. When they disagree, one of them is wrong — and finding out which taught more than anything else in the project.

```
logs/cowrie.json* ──► siem_load.py ──► Elasticsearch ──► Kibana dashboard  (siem_dashboard.py)
   + intel.json         (stdlib bulk,   index "cowrie"  └► detection rules  (siem_rules.py)
                         stable _ids)                         │
                                    parity checks vs Python ◄─┘
```

---

## A: Stand Up the Stack

`siem/docker-compose.yml` runs single-node Elasticsearch 8.17 and Kibana. Lab-grade on purpose: plain HTTP, but **both ports bound to 127.0.0.1**, so nothing off this machine can reach them. Security stays on — Kibana's detection engine refuses to run without it.

Create `siem/.env` (git-ignored) with three random values, then start it:

```bash
cd siem
python3 -c "import secrets; print('ELASTIC_PASSWORD='+secrets.token_urlsafe(18)); print('KIBANA_PASSWORD='+secrets.token_urlsafe(18)); print('KIBANA_ENCRYPTION_KEY='+secrets.token_hex(24))" > .env
docker compose up -d          # ~2 min; Kibana at http://127.0.0.1:5601, user "elastic"
```

Both services use `restart: unless-stopped`. That was learned the hard way: Docker Desktop auto-updated itself mid-load, restarted the engine, and killed both containers with exit code 255.

---

## B: Load the History

```bash
python3 scripts/siem_load.py          # 2,216,698 events in ~10 min
```

Stdlib-only, standing in for Filebeat. Every event gets `@timestamp`, the Part 8 enrichment under `src.*` (ASN, AS name, country, hosting flag, activity tier), and an `_id` that is a hash of the raw line — so a crashed or repeated load never duplicates anything. Result: **2,216,698 events sent, 0 rejected.**

**The `localhost` trap.** The first run indexed ~15,000 events a minute. Elasticsearch had spent 7 seconds of CPU on 155,000 documents — it was idle. On Windows, `localhost` tries IPv6 `::1` first and every request stalled before falling back. Pointing at `127.0.0.1` made the same load **16× faster** (~240,000/min). When a pipeline is slow, check whether the server is actually busy before tuning it.

---

## C: analyze.py as a Dashboard

```bash
python3 scripts/siem_dashboard.py --check      # SIEM totals vs Python
python3 scripts/siem_dashboard.py --install    # data view + 12 panels + dashboard
```

The dashboard *Cowrie Honeypot — analyze.py in the SIEM* answers everything `analyze.py` prints — event totals, top source IPs, usernames, passwords, commands, download URLs and payloads — plus what the CLI never had: activity over time, attacker networks, registry countries, activity tiers, and SSH client fingerprints. Each panel is generated from a table in the script, so it is rebuilt from code rather than clicked together.

**Parity:**

| | Python | Elastic | |
|---|---:|---:|---|
| Total sessions | 368,495 | 368,495 | exact |
| Failed login attempts | 353,894 | 353,894 | exact |
| Successful logins | 57,038 | 57,038 | exact |
| Commands executed | 224,492 | 224,492 | exact |
| File downloads | 3,557 | 3,557 | exact |
| Unique source IPs | 12,208 | 12,208 | exact |

The first run said **12,206** unique IPs. Nothing was lost: Elasticsearch's `cardinality` aggregation is a HyperLogLog *estimate*, and it came out two short. An exact count (paging a `composite` aggregation) gives 12,208. Kibana's "Unique count" metric uses the same estimator — fine for a chart, wrong for a number in a report.

---

## D: Porting the Sigma Rules

```bash
python3 scripts/siem_rules.py                        # parity: Python regex vs Elastic, per rule
python3 scripts/siem_rules.py --install --backfill   # create rules, look back 90 days once
python3 scripts/siem_rules.py --install              # live mode: each run sees the last 6 min
python3 scripts/siem_rules.py --alerts               # alerts raised, per rule
```

The Part 6 rules are PCRE-flavored regexes; Elasticsearch speaks **Lucene** regex. The differences don't throw errors — they make rules quietly match less, or nothing:

| PCRE (Sigma, Python) | Lucene (Elasticsearch) | Handling |
|---|---|---|
| `\s` `\S` `\d` | not supported | translated to `[ \t\n\r]`, `[^ \t\n\r]`, `[0-9]` |
| `\b` | not supported | dropped — makes a rule slightly broader; parity measures it |
| `(?i)` | not supported | becomes the query's `case_insensitive` flag |
| finds a match anywhere | must match the **whole** field | pattern wrapped in `.*( … ).*` |
| `& < > @ ~ # "` are literals | operators, by default | **`&&` or `>` silently matches nothing** — query with `flags: NONE` |

The last row is the trap. A `writable_dir_probe` pattern (`>/x && chmod …`) with default flags matched **0** documents; with `flags: NONE`, it matched 312 in the same partly loaded index. A rule that silently never fires looks exactly like an environment where the attack never happens.

`to_lucene()` in `scripts/siem_rules.py` does the translation. Kibana rules use a KQL query on `eventid` plus a custom DSL `regexp` filter (with `flags: NONE`), since KQL itself has no regex.

### Parity, and two bugs it found

| Rule | Python | Elastic | |
|---|---:|---:|---|
| `download_execute_chain` | 2,660 | 2,660 | exact |
| `pipe_to_shell` | 339 | 339 | exact |
| `busybox_applet_marker` | 23,633 | 23,633 | exact |
| `hex_echo_marker` | 2,821 | 2,821 | exact |
| `writable_dir_probe` | 15,012 | 15,012 | exact |
| `elf_self_read` | 1,030 | 1,030 | exact |
| `ssh_key_implant` | 1,326 | 1,326 | exact |
| `competitor_cleanup` | 215 | 215 | exact |
| `passwd_read` | 85 | 85 | exact |

(Counts are matching *events*; Part 6's table counts *sessions*.)

The first run was not exact:

- **`download_execute_chain`: Elastic +56. Elastic was right.** The extra hits were multi-line downloader scripts (`#!/bin/sh` … `wget` … `chmod` … `./x`). Python's `.` stops at a newline; Lucene's doesn't. The *original Part 6 rule* had been missing real download-and-execute chains all along. Fixed at the source with the `(?s)` flag; Part 6's count rose from 872 to 878 sessions.
- **`hex_echo_marker`: Elastic −5. Python was right.** The five missed commands used an uppercase hex digit (`\x6F`). The rule's `[0-9a-f]` leaned on the case-insensitive flag — which in Python covers character ranges and in Lucene **does not**. Fixed at the source by spelling out `[0-9a-fA-F]`.

Neither bug was visible from either tool alone. Each tool was wrong once, and the disagreement found both.

### The rules fire

Installed with `--backfill` (look back 90 days), all nine raised alerts in Kibana's Security app on their first run — 100 each (the per-run cap) and 85 for `passwd_read`, its full count. They were then reinstalled in live mode (`now-6m`); otherwise a 90-day window keeps raising 100 more historical alerts every 5 minutes until all ~47,000 matches have alerted.

---

## E: Lessons

- **A SIEM you can't check is a SIEM you can't trust.** Every number here was compared against an independent count. Two of nine detections were wrong on the first try — one in each tool.
- **Regex dialects fail silently.** Nothing errors; the rule just matches less. Never port a detection without counting its hits before and after.
- **Approximate by design is still approximate.** `cardinality` is an estimate. Know which metrics are before a number goes in a report.
- **The slow part may not be the database.** Check where the time goes before tuning anything.
- **Single-line rules miss multi-line attacks.** Part 6 predicted the limit for chains split across separate commands; it also bit inside a single command.
