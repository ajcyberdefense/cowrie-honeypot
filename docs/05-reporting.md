# Part 5: ATT&CK Mapping & Public Threat Report

Turn the raw log into a MITRE ATT&CK-mapped threat report, and publish it to your own domain as a static site.

> **Prerequisites:** Cowrie running under systemd per [Part 3](03-cowrie-install.md), and enough captured traffic to be worth reading — see [Part 4](04-monitoring.md).

The dashboard from Part 4 is for *you*: it is unauthenticated and firewalled to your own IP. This part is the opposite — a read-only snapshot, safe to hand to anyone.

```
cowrie.json ──► mitre_map.py ──► generate_report.py ──► publish-report.sh ──► gh-pages ──► your domain
                (techniques)      (static HTML)          (git push, outbound)
```

Nothing inbound is opened on the honeypot. The box pushes out; the web host serves.

---

## A: ATT&CK Mapping

`mitre_map.py` classifies what attackers actually did against you into ATT&CK techniques — 30 are mapped, spanning Credential Access, Discovery, Execution, Persistence, Defense Evasion, and Impact.

```bash
sudo su - cowrie
~/honeypot/cowrie-env/bin/python3 /opt/cowrie-honeypot/scripts/mitre_map.py
```

It resolves `~/honeypot/var/log/cowrie/cowrie.json` on its own. No third-party packages — Python 3.6+ only.

| Flag | Purpose |
|---|---|
| *(positional)* | Path to `cowrie.json` |
| `--layer FILE` | Write an ATT&CK Navigator layer |
| `--json` | Print the analysis as JSON |
| `--name NAME` | Layer name (default `Cowrie Honeypot`) |

### View It in ATT&CK Navigator

```bash
python3 mitre_map.py --layer /tmp/cowrie-layer.json
```

Open [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) → **Open Existing Layer** → **Upload from local**. Your captured techniques appear heat-mapped by frequency across the matrix.

This is the artifact worth putting in a writeup. It reframes "my honeypot got hit a lot" as coverage against a framework an interviewer already knows.

---

## B: Generate the Static Report

`generate_report.py` renders the findings to a single self-contained HTML file — no JavaScript, no external assets, no server.

```bash
python3 /opt/cowrie-honeypot/scripts/generate_report.py --out ./site
```

| Flag | Default | Purpose |
|---|---|---|
| `--out DIR` | `./site` | Output directory |
| `--log FILE` | auto-detected | Path to `cowrie.json` |
| `--redact` | off | Mask the last octet of attacker IPs |

Three files land in `--out`:

| File | Contents |
|---|---|
| `index.html` | The report |
| `cowrie-attack-layer.json` | ATT&CK Navigator layer |
| `data.json` | Raw analysis, for anything downstream |

### On Redaction

The report lists attacker IPs in full unless you pass `--redact`. Publishing them is normal practice for a threat report and is what community blocklists are built from.

Do check the list once before it goes on a domain with your name on it, though. Your own admin IP should never appear — you reach the host on the relocated SSH port, not through Cowrie — but cloud-internal addresses from your provider's own ranges sometimes show up in scan traffic, and it is worth knowing which is which before you publish.

---

## C: Publish to GitHub Pages

`publish-report.sh` renders the report and pushes it to an orphan `gh-pages` branch. Orphan keeps the published site out of your source history entirely.

### Deploy Key

The key does **not** go in the cowrie user's home directory. Cowrie is the deliberately-attacked process on this host; anything it can read is reachable from a Cowrie compromise. It lives root-only in `/etc/honeypot-report/`:

```bash
sudo mkdir -p /etc/honeypot-report
sudo chmod 700 /etc/honeypot-report
sudo ssh-keygen -t ed25519 -N "" -C "honeypot-report" \
  -f /etc/honeypot-report/deploy_key
sudo chmod 600 /etc/honeypot-report/deploy_key
sudo cat /etc/honeypot-report/deploy_key.pub
```

Add that public key at **repo → Settings → Deploy keys → Add deploy key**, with **Allow write access** ticked.

> Use a per-repo deploy key, never an account-wide personal access token. A deploy key that leaks costs you one repository; a PAT costs you the account.

### Config

```bash
sudo tee /etc/honeypot-report/config >/dev/null <<'EOF'
CUSTOM_DOMAIN=honeypot.ajcyberdefense.com
EOF
sudo chmod 600 /etc/honeypot-report/config
```

Everything is environment-overridable, so no script edits:

| Variable | Default | Purpose |
|---|---|---|
| `CUSTOM_DOMAIN` | *(none)* | Domain to serve the report on |
| `WRITE_CNAME` | `yes` | Write a `CNAME` file — required for GitHub Pages custom domains |
| `REDACT` | `no` | `yes` masks the last IP octet |
| `REPO_SSH` | this repo | Push target |
| `BRANCH` | `gh-pages` | Publish branch |
| `WORKDIR` | `/var/lib/honeypot-report` | Working copy |
| `DEPLOY_KEY` | `/etc/honeypot-report/deploy_key` | SSH key |
| `SCRIPTS` | `/opt/cowrie-honeypot/scripts` | Script location |
| `COWRIE_JSON_LOG` | Cowrie's default | Path to `cowrie.json` |

### First Run

```bash
sudo /opt/cowrie-honeypot/scripts/publish-report.sh
```

It creates the `gh-pages` branch if absent, renders, and pushes. On a run with no new attacks it reports `No changes since last run` and exits cleanly.

Then enable Pages: **repo → Settings → Pages → Source: Deploy from a branch → `gh-pages` / root**. The report appears at `https://<user>.github.io/<repo>/`.

`.nojekyll` is written automatically — without it GitHub runs the output through Jekyll and mangles it.

---

## D: Bind Your Subdomain

**Order matters.** Create the DNS record *first*. If GitHub validates the domain before DNS resolves, it flags an error and will not issue a certificate.

### 1. DNS Record

Wherever the zone for your domain is hosted, add:

| Type | Name | Value |
|---|---|---|
| `CNAME` | `honeypot` | `<user>.github.io` |

The value is the **user** subdomain with no repo path and no trailing URL — `ajcyberdefense.github.io`, not `ajcyberdefense.github.io/cowrie-honeypot`.

> If your domain is on Netlify DNS (nameservers `dns1–4.p0X.nsone.net`), add it there rather than at your registrar — Netlify is authoritative for the zone. A `CNAME` record pointing at GitHub is fine; hosting the zone at Netlify does not mean the site has to be hosted there.

Confirm it resolves before continuing:

```bash
nslookup honeypot.ajcyberdefense.com
```

### 2. Bind It

With `CUSTOM_DOMAIN` set and `WRITE_CNAME` at its default, the next publish writes the `CNAME` file and GitHub picks up the domain by itself:

```bash
sudo /opt/cowrie-honeypot/scripts/publish-report.sh
```

Check **Settings → Pages** shows the custom domain with a green check, then tick **Enforce HTTPS** once the Let's Encrypt certificate finishes provisioning — usually a few minutes, occasionally up to an hour.

### 3. Verify

```bash
curl -sI https://honeypot.ajcyberdefense.com | head -3
```

`HTTP/2 200` and `server: GitHub.com` means done. The old `github.io` URL now redirects to the custom domain.

---

## E: Refresh It Automatically

```bash
sudo cp /opt/cowrie-honeypot/configs/report-publish.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now report-publish.timer
systemctl list-timers report-publish
```

The timer runs hourly with a randomized delay of up to five minutes, so every honeypot running this does not hit GitHub at exactly `:00`. `Persistent=true` catches up one missed run after downtime instead of skipping it.

Hourly costs nothing here: GitHub Pages serves the branch directly with no build step. A host that bills build minutes per deploy would want a longer interval.

Test the unit by hand and read its output:

```bash
sudo systemctl start report-publish.service
sudo journalctl -u report-publish -n 40 --no-pager
```

The service runs as root solely so the deploy key can stay outside the cowrie account, and is confined with `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, and a single `ReadWritePaths` exception for its working directory.

---

## Reporting Checklist

- [ ] `mitre_map.py` runs and reports techniques
- [ ] Navigator layer loads in ATT&CK Navigator
- [ ] Attacker IP list reviewed, redaction decided
- [ ] Deploy key created root-only, added to GitHub with write access
- [ ] `/etc/honeypot-report/config` written with `CUSTOM_DOMAIN`
- [ ] First publish succeeded; `gh-pages` branch exists
- [ ] Pages source set to `gh-pages` / root
- [ ] DNS `CNAME` resolves
- [ ] Custom domain green-checked, **Enforce HTTPS** on
- [ ] `report-publish.timer` enabled and listed

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Deploy key not found` | Key missing, or `DEPLOY_KEY` points elsewhere |
| `Cowrie log not found` | Cowrie has not written events yet, or `COWRIE_JSON_LOG` is wrong |
| Push rejected | Deploy key lacks **Allow write access** |
| Page 404s | Pages source is not `gh-pages` / root |
| Raw Markdown or broken layout | `.nojekyll` missing from the branch |
| Domain shows "improperly configured" | DNS added after GitHub validated — re-save the domain in Settings → Pages |
| No HTTPS option | Certificate still provisioning; wait, then re-check |
| Report never updates | Timer not enabled — `systemctl list-timers report-publish` |

---

## Where to Take It Next

- **Publish the Navigator layer** alongside the report — `cowrie-attack-layer.json` is already deployed next to `index.html`
- **Report to AbuseIPDB** — `[output_abuseipdb]` in `cowrie.cfg` turns captures into community blocklist contributions
- **Submit samples to VirusTotal** — `[output_virustotal]`
- **Diff reports over time** — `data.json` is stable and machine-readable; archiving it per run gives you trend data
