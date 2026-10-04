# Part 8: Threat Intelligence

Turn 12,208 source IP strings into an intelligence product: who owns the infrastructure, how the attackers group into campaigns, and how confident each judgment is.

> **Prerequisites:** the log history from [Part 6](06-detection-engineering.md) and the payload triage from [Part 7](07-malware-triage.md) (used to describe what each IP actually dropped). Period covered: 2026-08-10 through 2026-10-04.

---

## A: Method

```
cowrie.json ──► intel_enrich.py ──► profile per IP ──► enrich ──► group by shared artifact ──► intel.json
                                    (tier, first/last,  (Cymru,     (planted key, payload,
                                     HASSH, payloads)    ip-api,     download server, command
                                                         DShield)    script, SSH client)
```

```bash
python3 scripts/intel_enrich.py                      # profile, enrich, cluster (~15 min first run)
python3 scripts/intel_enrich.py --offline            # re-cluster from cache, no network
python3 scripts/intel_enrich.py --abuseipdb          # preview AbuseIPDB reports (dry run)
python3 scripts/intel_enrich.py --abuseipdb --submit # post them (ABUSEIPDB_KEY in .env)
python3 scripts/test_intel_enrich.py                 # offline self-check
```

| Source | What it gives | Coverage | Key |
|---|---|---|---|
| Team Cymru bulk whois | ASN, AS name, prefix, registry country | all 12,226 IPs, one TCP query | none |
| ip-api.com batch | hosting / proxy / mobile flags | all IPs, ~8 min at the free rate limit | none |
| DShield (SANS ISC) | prior reports, attack counts | 278 busiest droppers + infrastructure | none |

Only IP addresses leave the machine. Results are cached in `analysis/intel_cache.json`, so reruns fetch only new IPs.

**Activity tiers** sort every IP by the deepest thing it did: *scanned/guessed* → *logged in* → *ran commands* → *dropped files*. **Campaigns** are groups of 5+ IPs sharing a concrete artifact — the same planted SSH key, payload hash, download server, normalized command script, or SSH client fingerprint ([HASSH](https://github.com/salesforce/hassh)). A shared artifact is evidence of shared tooling; whether it means a shared *operator* is a judgment, and the confidence language says which.

**Confidence language** follows the usual intelligence convention: *high confidence* — multiple independent artifacts agree and alternatives are implausible; *moderate* — credible evidence with a plausible alternative; *low* — a single indicator or an inference.

---

## B: The Population

| Tier | IPs | Hosting share | Top networks |
|---|---:|---:|---|
| Scanned / guessed | 7,614 | 23% | Google Cloud, Cybernet (PK), China Unicom |
| Logged in | 1,977 | 8% | Rostelecom, Google Cloud, Chinanet |
| Ran commands | 1,380 | 37% | Korea Telecom, BanatSync (RO), SION (AR) |
| Dropped files | 1,237 | 24% | SION (AR), Chinanet, Microsoft |

Registry countries: US 2,446 · CN 1,280 · AR 942 · UA 719 · RU 667 · PK 478 · BR 431 · KR 385 · GB 308 · IN 261.

**Most attackers are not the attackers' machines.** Three quarters of the IPs that dropped files are residential, mobile or business lines, not rented servers. We assess with **high confidence** that most malware delivery comes from already-compromised devices propagating the infection rather than from operator-controlled infrastructure: the Mirai loader in campaign 2 below is fetched by 288 victims across 141 networks, 99% of them non-hosting. Country counts therefore describe *where infected devices are*, not where operators are, and should not be read as attribution.

**Low outside visibility.** Of 278 dropper IPs checked against DShield, only **33 (12%)** had any prior reports. Either DShield's sensors were not targeted by these IPs, or the activity is short-lived enough to escape them. Either way, most of what this honeypot saw was not already on record there.

---

## C: Campaigns

118 groups of 5+ IPs share an artifact. The six that matter most:

### 1. `mdrfckr` SSH-key persistence — 601 IPs

| | |
|---|---|
| Artifact | One attacker RSA public key (comment `mdrfckr`) written to `authorized_keys` |
| Scale | 601 IPs · 276 ASNs · 69 countries · 14,198 sessions |
| Window | First seen here 2026-09-18, still active 2026-10-04 |
| Tooling | 567 of 601 use `SSH-2.0-libssh_0.9.6` |
| Hosting share | 39% — Microsoft (41), UCloud HK (25), Oracle Cloud (20) lead |
| Outside visibility | 25 of 200 checked were known to DShield |

**Assessment — high confidence** that this is a single botnet: every member plants the identical key, uses the same client library, and runs the same command sequence (Part 6, `ssh_key_implant`). The 39% cloud share is high for a botnet, which suggests (**low confidence**) it spreads *through* the key it plants: compromised cloud VMs, now reachable by the key's owner, are used to compromise the next. The abrupt start on 2026-09-18 marks when this honeypot entered the target list, not when the campaign began — the `mdrfckr` key has been publicly documented for years.

### 2. Mirai loader at 185.93.89.72 — 288 victims

| | |
|---|---|
| Artifact | Download server 185.93.89.72 (its `wget` script `a6296a79…` alone reached 217 IPs) |
| Scale | 288 IPs · 141 ASNs · 37 countries |
| Victim profile | 1% hosting; SION S.A. (AR, 57), HiNet (TW, 17), China Unicom; AR 69 · BR 46 · CN 31 |
| Server | AS213790 *Limited Network LTD*, registered IR, hosting |

**Assessment — high confidence** that this is classic Mirai self-propagation: infected home routers and DVRs, overwhelmingly on South American consumer ISPs, log into the next victim and have it fetch the bot from one central loader. **Moderate confidence** that 77.90.185.66 — the download server in Part 6's motivating `download_execute_chain` session — belongs to the same operator: same ASN (AS213790), same role.

### 3. Storm Industries block — 176.65.139.0/24

Seven addresses in one /24, all **AS219502 Storm Industries LLC** (registered DE), served about 80 captured files: Mirai for many architectures, tampered-UPX builds, the miner-killing bots, a Gafgyt build, and downloader scripts. 141.11.88.114 is embedded in the 29 Mirai builds served from 176.65.139.196.

**Assessment — moderate confidence** that the /24 is one operator's rented staging infrastructure. One block serving every payload role is hard to explain otherwise, but a hosting provider renting adjacent addresses to unrelated abusive customers is a plausible alternative. **Low confidence** that 141.11.88.114 is the C2 for those builds: it is a single embedded address, not observed in traffic.

### 4. SMTP proxy validation — 1,162 IPs

| | |
|---|---|
| Artifact | SSH client fingerprint `acaa53e0…` (`SSH-2.0-OpenSSH_7.4`) |
| Scale | 1,162 IPs · 324 ASNs · 79 countries; 3% hosting |
| Behavior | 697 successful logins and **one** command between them — then 691 `direct-tcpip` tunnel requests, every one to **77.88.21.158 port 25 (SMTP)** |

These IPs never try to infect anything. They log in, ask the SSH server to open a TCP tunnel to a mail server, and leave. **Assessment — moderate confidence** that this is a spam operation validating stolen SSH credentials as mail relays: a working tunnel to port 25 means the host can send mail on someone else's IP reputation. The alternative — a generic proxy checker that happens to use an SMTP server as its test target — leads to the same conclusion about where the credentials end up. It is invisible to every command-based detection in Part 6, because there are no commands.

### 5. Go brute-forcer — 218 IPs, 178,075 sessions

| | |
|---|---|
| Artifact | Identical session script: `uname -s -v -n -r -m`, client `SSH-2.0-Go` |
| Scale | 218 IPs · 28 ASNs; **77% hosting** — BanatSync (RO, 112), TechTies (55), Alibaba |
| Volume | 178,075 sessions — by far the noisiest campaign |

**Assessment — high confidence** that this is rented infrastructure (concentrated in two small hosting networks) running one brute-force tool that records the system fingerprint of each successful login and does nothing else. **Low confidence** that it feeds an access broker: the fingerprint is what a buyer of SSH access wants to know, and nothing is installed that would burn the access — but nothing observed here shows a sale.

### 6. Research scanners — not adversaries

| HASSH | IPs | Network | Client |
|---|---:|---|---|
| `dd9bcf09…` | 198 | Google Cloud (1 ASN, 100% hosting) | `SSH-2.0-ZGrab ZGrab SSH Survey` |
| `873a5fb5…` | 96 | Censys (3 ASNs) | `SSH-2.0-Go` |

Internet-measurement scanners that never log in. They inflate the Google Cloud line in the population table, and none of them reached the *dropped files* tier, so none is reported anywhere.

---

## D: Infrastructure Summary

| Address | ASN | Role | Confidence |
|---|---|---|---|
| 185.93.89.72 | AS213790 Limited Network LTD (IR) | Mirai loader, 288 victims | high |
| 77.90.185.66 | AS213790 Limited Network LTD | Mirai download server | moderate (same operator as above) |
| 176.65.139.0/24 | AS219502 Storm Industries LLC (DE) | Multi-payload staging | moderate |
| 5.182.210.174 | AS62068 SpectraIP B.V. (NL) | Self-referencing downloader stager (Part 7) | high (role) |
| 141.11.88.114 | — | Embedded in 29 Mirai builds | low (as C2) |
| 77.88.21.158:25 | AS208398 (prefix 77.88.0.0/18, RU registry) | Tunnel *target*, not attacker infrastructure | — |

---

## E: AbuseIPDB Reporting

Only IPs in the *dropped files* tier are reported: they logged in with guessed credentials and then wrote to disk, so no reading of the evidence makes them benign. Each report states only what the log shows that IP doing:

| Report wording | IPs |
|---|---:|
| `…brute-force login, then downloaded malware (sha256 …)` | 532 |
| `…brute-force login, then planted an attacker SSH key in authorized_keys` | 601 |
| `…brute-force login, then ran commands and wrote files to disk` | 104 |

Categories: 18 (Brute-Force), plus 22 (SSH) or 23 (IoT Targeted) for Telnet. The honeypot's own address appears in no report. The free tier allows 1,000 reports per day, so 1,237 go out over two runs; reported IPs are tracked in the cache and skipped on the next run.

The first draft of the wording said every dropper "downloaded and attempted to run malware". The triage from Part 7 showed 601 of those files were an SSH key and others were 1-byte marker files — so the wording was rebuilt from what each IP actually wrote. A public report under your name has to survive someone checking it.

---

## F: Lessons

- **IPs are victims more often than villains.** Most delivery comes from compromised consumer devices. Blocklisting them helps defenders; it says nothing about who runs the operation.
- **Group on artifacts, not addresses.** IPs churn; a planted key, a payload hash, a loader address and an SSH client fingerprint persist — and none of the campaigns above is visible one IP at a time.
- **Not every intrusion wants the box.** The largest logged-in population (campaign 4) ran one command between them. They wanted the network path to port 25.
- **Separate tooling evidence from operator claims.** A shared HASSH proves shared software. It took a shared key (campaign 1) or a shared loader (campaign 2) to argue for a shared operator.
