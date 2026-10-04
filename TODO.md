# Analysis Roadmap

The deployment side of this project is done: the honeypot collects, the report
publishes. What follows is the analysis side — turning the captured data into
four distinct security disciplines.

Work these in order. Each phase produces an artifact that stands on its own.

Status key: `TODO` · `IN PROGRESS` · `DONE`

---

## Phase 1 — Detection Engineering `DONE`

**Why first:** `cowrie.json` is a labeled dataset. Every command in it is known
malicious, which is ground truth most people learning detection never get.

- [x] Cluster captured command sequences into candidate detections
- [x] Write Sigma rules for the recurring chains (`wget → chmod +x → execute`,
      busybox probing, `/etc/passwd` reads)
- [x] For each rule, write the false-positive analysis — would it fire on a
      normal admin session?
- [x] Add `scripts/sigma_from_cowrie.py` (stdlib-only, auto-resolves the log
      path, matching existing script conventions)
- [x] New `detections/` directory: one rule per file, each paired with the
      session that motivated it
- [x] Document as `docs/06-detection-engineering.md`

Result: 9 rules in `detections/`; they cover 98.9% of sessions that delivered
a file. Write-up: [docs/06-detection-engineering.md](docs/06-detection-engineering.md).

**Lesson to capture:** which links in an attack chain are actually detectable.
`uname -a` is worthless as a signal; `curl | sh` is hard; the download-and-execute
chain is the chokepoint.

---

## Phase 2 — Malware Triage `DONE`

Payloads are already captured in `/home/cowrie/honeypot/var/lib/cowrie/downloads/`,
hashed by SHA-256. 95 downloads as of the first report.

- [x] Isolated analysis — **static only, never execute**; runs on the honeypot
      VM itself (already disposable and isolated), only JSON leaves the box
- [x] Hash lookup against MalwareBazaar for family attribution
      (expect Mirai and Gafgyt variants)
- [x] `file` + `strings` on each unique sample: target architectures, hardcoded
      C2 addresses, embedded credential lists
- [x] Compare each binary's embedded credential list against the passwords the
      honeypot actually logged — overlap shows how botnets propagate their own
      dictionaries
- [x] Write up family attribution with the evidence that supports it
- [ ] Submit the 105 samples MalwareBazaar didn't know (needs the files,
      so do it from the honeypot; review MalwareBazaar's terms first)

Result: 268 files, 159 ELF across 12 CPU architectures; 100 Mirai, 19
cryptominers, 40 unattributed. 56 binaries carry passwords the honeypot
logged (`xc3511`: 43 binaries, tried 3,009 times). Write-up:
[docs/07-malware-triage.md](docs/07-malware-triage.md).

---

## Phase 3 — Threat Intel Production `IN PROGRESS`

Source IPs are currently just strings. Turn them into an intel product.

- [x] Enrich: ASN, geolocation, first/last seen, residential vs. hosting
      (hosting = rented VPS = disposable infrastructure)
- [x] Cross-reference against DShield / AbuseIPDB
- [x] Infrastructure clustering — do the same IPs reuse credential lists,
      download URLs, or timing patterns? Look for campaigns, not events
- [x] Write with analytic confidence language ("assessed with moderate
      confidence") — a distinct skill from the technical work
- [ ] Submit confirmed malicious IPs to AbuseIPDB — 1,237 droppers, wording
      reviewed; free tier is 1,000/day so it takes two runs of
      `intel_enrich.py --abuseipdb --submit`

Result: 12,208 IPs in four activity tiers, 118 artifact-sharing groups, six
campaigns assessed with confidence levels (incl. a 1,162-IP SMTP proxy
validation operation that runs no commands). Write-up:
[docs/08-threat-intel.md](docs/08-threat-intel.md).

---

## Phase 4 — SIEM Reps `TODO`

- [ ] Stand up Wazuh or Elastic in the home lab
- [ ] Ship `cowrie.json` in as a log source
- [ ] Rebuild the existing `analyze.py` output as SIEM queries and dashboards
- [ ] Port the Phase 1 Sigma rules into live SIEM detections and confirm they
      fire against the historical data

Same answers, different tool — that is the point. It converts the honeypot into
unlimited SOC-analyst practice on data already well enough understood to catch a
wrong query.

---

## Known Issues

- [x] `generate_report.py` — the top source IP table reports per-IP session
      counts that exceed the total session count (e.g. ~7,700 against a 4,293
      total). It counted login attempts, not sessions; now counts sessions.
- [x] Report reset to zero at midnight UTC — it read only the live
      `cowrie.json`, not Cowrie's daily rotations. Now all-time + last 24h.
- [ ] `dashboard.py` still reads only today's `cowrie.json` (deliberate: it
      re-parses on every request, and all-time takes ~95s on the Oracle micro).
