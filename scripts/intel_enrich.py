#!/usr/bin/env python3
# =============================================================================
# intel_enrich.py — Turn attacker IPs into threat intelligence
# =============================================================================
# Builds a profile of every source IP from the Cowrie log (activity tier,
# first/last seen, SSH client fingerprint, what it ran and dropped), enriches
# it with ownership data, and groups IPs into campaigns by the artifacts they
# share — a payload, a download server, a planted SSH key, an identical
# command script.
#
# Enrichment sources (free, no keys; only IP addresses are sent):
#   Team Cymru bulk whois  ASN, AS name, country, registry — all IPs, one query
#   ip-api.com batch       hosting / proxy / mobile flags   — all IPs, ~8 min
#   DShield (SANS ISC)     reports and attack counts        — busiest droppers
# Results are cached in analysis/intel_cache.json; reruns only fetch new IPs.
#
# Usage:
#   python3 intel_enrich.py                     # profile, enrich, cluster
#   python3 intel_enrich.py --offline           # cached enrichment only
#   python3 intel_enrich.py /path/to/cowrie.json --out analysis/intel.json
#   python3 intel_enrich.py --abuseipdb            # preview reports (dry run)
#   python3 intel_enrich.py --abuseipdb --submit   # post them (ABUSEIPDB_KEY)
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

from mitre_map import iter_events, resolve_log_file

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(REPO, "analysis", "intel_cache.json")
UA = {"User-Agent": "cowrie-honeypot threat-intel research"}

CAMPAIGN_MIN_IPS = 5      # smaller groups are reported as noise, not campaigns
DSHIELD_LIMIT = 300       # DShield asks for gentle use: ~1 request per second

# Command lines too generic to tie IPs together (every Mirai scanner sends them).
TRIVIAL_SCRIPT = re.compile(r"^((sh|shell|system|enable|linuxshell|ping ;?sh|"
                            r"enablelinuxshell|busybox|/bin/busybox)\s*;;\s*)*"
                            r"(sh|shell|system|enable|uname -a)?$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# -----------------------------------------------------------------------------
# Profile every source IP from the log
# -----------------------------------------------------------------------------
def normalize(cmd):
    """Strip what varies per victim or per run, keep the script's shape."""
    cmd = re.sub(r"(https?|tftp|ftp)://\S+", "<URL>", cmd)
    cmd = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<IP>", cmd)
    cmd = re.sub(r"[A-Za-z0-9+/=]{40,}", "<B64>", cmd)
    return " ".join(cmd.split())


def url_host(url):
    m = re.match(r"\w+://([^/:]+)", url)
    return m.group(1) if m else None


def profile(events):
    ips = defaultdict(lambda: {
        "sessions": 0, "first_seen": None, "last_seen": None,
        "logins_ok": 0, "logins_failed": 0, "commands": 0, "files": 0,
        "protocols": Counter(), "hassh": Counter(), "client": Counter(),
        "payloads": set(), "download_hosts": set(), "ssh_keys": set(),
        "scripts": Counter()})
    session_cmds = defaultdict(list)
    session_ip = {}

    for e in events:
        src, sid, eid = e.get("src_ip"), e.get("session"), e.get("eventid", "")
        if not src:
            continue
        p = ips[src]
        ts = e.get("timestamp")
        if ts:
            if p["first_seen"] is None or ts < p["first_seen"]:
                p["first_seen"] = ts
            if p["last_seen"] is None or ts > p["last_seen"]:
                p["last_seen"] = ts
        if eid == "cowrie.session.connect":
            p["sessions"] += 1
            p["protocols"][e.get("protocol", "?")] += 1
            session_ip[sid] = src
        elif eid == "cowrie.login.success":
            p["logins_ok"] += 1
        elif eid == "cowrie.login.failed":
            p["logins_failed"] += 1
        elif eid == "cowrie.client.kex" and e.get("hassh"):
            p["hassh"][e["hassh"]] += 1
        elif eid == "cowrie.client.version" and e.get("version"):
            p["client"][e["version"]] += 1
        elif eid == "cowrie.command.input":
            p["commands"] += 1
            line = e.get("input", "")
            session_cmds[sid].append(normalize(line))
            for key in re.findall(r"ssh-(?:rsa|ed25519)\s+([A-Za-z0-9+/=]{40,})", line):
                p["ssh_keys"].add(hashlib.sha256(key.encode()).hexdigest()[:16])
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            p["files"] += 1
            if e.get("shasum"):
                p["payloads"].add(e["shasum"])
            host = url_host(e.get("url") or "")
            if host:
                p["download_hosts"].add(host)

    for sid, cmds in session_cmds.items():
        src = session_ip.get(sid)
        script = " ;; ".join(cmds)
        if src and not TRIVIAL_SCRIPT.match(script):
            ips[src]["scripts"][hashlib.sha256(script.encode()).hexdigest()[:16]] += 1
    return ips


def tier(p):
    if p["files"]:
        return "dropped files"
    if p["commands"]:
        return "ran commands"
    if p["logins_ok"]:
        return "logged in"
    return "scanned / guessed"


# -----------------------------------------------------------------------------
# Enrichment
# -----------------------------------------------------------------------------
def load_cache():
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as fh:
            return json.load(fh)
    return {"cymru": {}, "ipapi": {}, "dshield": {}}


def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, "w", encoding="utf-8") as fh:
        json.dump(cache, fh)


def cymru(ips):
    """Team Cymru bulk whois over TCP/43: one connection for any number of IPs."""
    body = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    with socket.create_connection(("whois.cymru.com", 43), timeout=120) as s:
        s.sendall(body.encode())
        out = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    result = {}
    for line in out.decode("utf-8", "replace").splitlines()[1:]:
        f = [x.strip() for x in line.split("|")]
        if len(f) == 7 and IPV4.match(f[1]):
            result[f[1]] = {"asn": f[0], "prefix": f[2], "cc": f[3],
                            "registry": f[4], "as_name": f[6]}
    return result


def ipapi(ips, into, retries=3):
    """ip-api.com batch: 100 IPs per request, 15 requests per minute (free).
    Writes into `into` as it goes, so a dropped connection loses one batch."""
    url = ("http://ip-api.com/batch?fields=status,query,countryCode,isp,"
           "hosting,proxy,mobile")
    for i in range(0, len(ips), 100):
        req = urllib.request.Request(url, data=json.dumps(ips[i:i + 100]).encode(),
                                     headers=dict(UA, **{"Content-Type": "application/json"}))
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    remaining = int(resp.headers.get("X-Rl", "1"))
                    wait = int(resp.headers.get("X-Ttl", "60"))
                    batch = json.load(resp)
                break
            except OSError:
                if attempt == retries - 1:
                    raise
                time.sleep(60)          # back off a full rate-limit window
        for r in batch:
            if r.get("status") == "success":
                into[r["query"]] = {k: r.get(k) for k in
                                    ("isp", "hosting", "proxy", "mobile")}
        print("  ip-api %d/%d" % (min(i + 100, len(ips)), len(ips)), file=sys.stderr)
        if remaining == 0:
            time.sleep(wait + 1)


def dshield(ip):
    req = urllib.request.Request("https://isc.sans.edu/api/ip/%s?json" % ip, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as resp:
        d = json.load(resp).get("ip", {})
    return {k: d.get(k) for k in ("count", "attacks", "mindate", "maxdate", "maxrisk")}


def enrich(ips, cache, priority, offline):
    """Fill the cache for every IP; DShield only for the `priority` list."""
    if not offline:
        todo = [ip for ip in ips if ip not in cache["cymru"]]
        if todo:
            print("Team Cymru: %d IPs" % len(todo), file=sys.stderr)
            cache["cymru"].update(cymru(todo))
            save_cache(cache)
        todo = [ip for ip in ips if ip not in cache["ipapi"]]
        if todo:
            print("ip-api: %d IPs" % len(todo), file=sys.stderr)
            try:
                ipapi(todo, cache["ipapi"])
            finally:
                save_cache(cache)
        todo = [ip for ip in priority if ip not in cache["dshield"]]
        for i, ip in enumerate(todo, 1):
            try:
                cache["dshield"][ip] = dshield(ip)
            except OSError as exc:
                print("  DShield stopped at %d/%d: %s" % (i, len(todo), exc),
                      file=sys.stderr)
                break
            if i % 50 == 0:
                print("  DShield %d/%d" % (i, len(todo)), file=sys.stderr)
                save_cache(cache)
            time.sleep(1)
        save_cache(cache)
    return {ip: {"cymru": cache["cymru"].get(ip), "ipapi": cache["ipapi"].get(ip),
                 "dshield": cache["dshield"].get(ip)} for ip in ips}


# -----------------------------------------------------------------------------
# Campaigns
# -----------------------------------------------------------------------------
# (label, profile field). Each distinct value shared by enough IPs is a
# candidate campaign: these IPs used the same artifact.
CAMPAIGN_FEATURES = [
    ("planted SSH key", "ssh_keys"),
    ("payload (SHA-256)", "payloads"),
    ("download server", "download_hosts"),
    ("command script", "scripts"),
    ("SSH client (HASSH)", "hassh"),
]


def campaigns(ips, intel):
    out = []
    for label, field in CAMPAIGN_FEATURES:
        members = defaultdict(set)
        for ip, p in ips.items():
            for v in p[field]:
                members[v].add(ip)
        for value, group in members.items():
            if len(group) < CAMPAIGN_MIN_IPS:
                continue
            asns = Counter((intel[ip]["cymru"] or {}).get("as_name", "?") for ip in group)
            ccs = Counter((intel[ip]["cymru"] or {}).get("cc", "?") for ip in group)
            known = [intel[ip]["ipapi"] for ip in group if intel[ip]["ipapi"]]
            seen = sorted(t for ip in group for t in
                          (ips[ip]["first_seen"], ips[ip]["last_seen"]) if t)
            out.append({
                "feature": label, "value": value, "ips": len(group),
                "sessions": sum(ips[ip]["sessions"] for ip in group),
                "asns": len(asns), "countries": len(ccs),
                "top_asns": asns.most_common(3), "top_countries": ccs.most_common(3),
                "hosting_share": round(sum(1 for k in known if k["hosting"])
                                       / len(known), 2) if known else None,
                "first_seen": seen[0] if seen else None,
                "last_seen": seen[-1] if seen else None,
                "members": sorted(group),
            })
    out.sort(key=lambda c: -c["ips"])
    return out


# -----------------------------------------------------------------------------
# AbuseIPDB reporting (droppers only)
# -----------------------------------------------------------------------------
# Only IPs that logged in AND dropped a file are reported: evidence a reviewer
# can't mistake for a misconfigured scanner. 18 Brute-Force, 22 SSH, 23 IoT.
ABUSE_CATEGORIES = {"ssh": "18,22", "telnet": "18,23"}


def env_key(name):
    key = os.environ.get(name)
    path = os.path.join(REPO, ".env")
    if not key and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip().startswith(name + "="):
                    key = line.split("=", 1)[1].strip().strip("'\"")
    return key


def payload_kinds():
    """sha256 -> file kind from triage_downloads.py's report, if present."""
    path = os.path.join(REPO, "analysis", "triage.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return {s["sha256"]: s["kind"] for s in json.load(fh)["samples"]}


def abuse_reports(ips):
    """(ip, categories, comment, timestamp) for every dropper. The comment
    states only what the log shows this IP doing."""
    kinds = payload_kinds()
    out = []
    for ip, p in sorted(ips.items()):
        if p["tier"] != "dropped files":
            continue
        proto = max(p["protocols"], key=p["protocols"].get) if p["protocols"] else "ssh"
        malware = [h for h in p["payloads"] if kinds.get(h) in ("elf", "script")]
        if malware:
            action = "downloaded malware (sha256 %s)" % malware[0]
        elif p["ssh_keys"]:
            action = "planted an attacker SSH key in authorized_keys"
        else:
            action = "ran commands and wrote files to disk"
        comment = ("Cowrie honeypot: %s brute-force login, then %s. "
                   "%d sessions %s to %s UTC."
                   % (proto.upper(), action, p["sessions"],
                      p["first_seen"][:16].replace("T", " "),
                      p["last_seen"][:16].replace("T", " ")))
        out.append((ip, ABUSE_CATEGORIES.get(proto, "18"), comment, p["last_seen"]))
    return out


def abuseipdb(report_path, submit):
    with open(report_path, encoding="utf-8") as fh:
        ips = json.load(fh)["ips"]
    cache = load_cache()
    done = cache.setdefault("abuseipdb", {})
    todo = [r for r in abuse_reports(ips) if r[0] not in done]
    print("%d droppers, %d already reported, %d to report"
          % (len(todo) + len(done), len(done), len(todo)))
    if not submit:
        for r in todo[:3]:
            print("\n  %s  categories %s\n  %s" % (r[0], r[1], r[2]))
        print("\nDry run. Add --submit to post these to AbuseIPDB.")
        return
    key = env_key("ABUSEIPDB_KEY")
    if not key:
        sys.exit("[!] No ABUSEIPDB_KEY in the environment or .env")
    for i, (ip, cats, comment, ts) in enumerate(todo, 1):
        body = urllib.parse.urlencode({"ip": ip, "categories": cats,
                                       "comment": comment, "timestamp": ts}).encode()
        req = urllib.request.Request("https://api.abuseipdb.com/api/v2/report", data=body,
                                     headers={"Key": key, "Accept": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=30).close()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                print("Daily limit reached after %d reports; rerun tomorrow." % (i - 1))
                break
            if exc.code == 422:        # rejected (e.g. reported <15 min ago): skip
                print("  skipped %s: HTTP 422" % ip)
                continue
            raise
        finally:
            save_cache(cache)
        done[ip] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if i % 100 == 0:
            print("  reported %d/%d" % (i, len(todo)))
    save_cache(cache)
    print("Reported so far: %d" % len(done))


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def share(xs):
    xs = [x for x in xs if x is not None]
    return "%3.0f%%" % (100.0 * sum(xs) / len(xs)) if xs else "  - "


def print_summary(ips, intel, camps):
    tiers = defaultdict(list)
    for ip, p in ips.items():
        tiers[tier(p)].append(ip)
    print("%-18s %6s %8s %7s  top ASNs" % ("tier", "IPs", "hosting", "mobile"))
    for t in ("scanned / guessed", "logged in", "ran commands", "dropped files"):
        group = tiers[t]
        api = [intel[ip]["ipapi"] or {} for ip in group]
        asns = Counter((intel[ip]["cymru"] or {}).get("as_name", "?")[:28] for ip in group)
        print("%-18s %6d %8s %7s  %s" % (
            t, len(group), share([a.get("hosting") for a in api]),
            share([a.get("mobile") for a in api]),
            ", ".join("%s (%d)" % kv for kv in asns.most_common(3))))

    cc = Counter((intel[ip]["cymru"] or {}).get("cc", "?") for ip in ips)
    print("\nCountries (registry):", ", ".join("%s %d" % kv for kv in cc.most_common(10)))
    print("\nCampaigns (%d+ IPs sharing an artifact): %d" % (CAMPAIGN_MIN_IPS, len(camps)))
    print("%-20s %5s %5s %4s %8s  %-10s %-10s  %s" % (
        "feature", "IPs", "ASNs", "CCs", "hosting", "first", "last", "value"))
    for c in camps[:25]:
        print("%-20s %5d %5d %4d %8s  %-10s %-10s  %s" % (
            c["feature"], c["ips"], c["asns"], c["countries"],
            "-" if c["hosting_share"] is None else "%d%%" % (100 * c["hosting_share"]),
            (c["first_seen"] or "")[:10], (c["last_seen"] or "")[:10], c["value"][:40]))


def jsonable(p):
    return {k: (sorted(v) if isinstance(v, set) else
                dict(v.most_common()) if isinstance(v, Counter) else v)
            for k, v in p.items()}


def main():
    ap = argparse.ArgumentParser(description="Enrich and cluster attacker IPs")
    ap.add_argument("log", nargs="?", help="path to cowrie.json")
    ap.add_argument("--out", default=os.path.join(REPO, "analysis", "intel.json"))
    ap.add_argument("--offline", action="store_true",
                    help="use cached enrichment only, make no network requests")
    ap.add_argument("--abuseipdb", action="store_true",
                    help="list AbuseIPDB reports for droppers in --out (dry run)")
    ap.add_argument("--submit", action="store_true",
                    help="with --abuseipdb: actually post the reports")
    args = ap.parse_args()

    if args.abuseipdb:
        abuseipdb(args.out, args.submit)
        return

    log_file = resolve_log_file(args.log)
    if not os.path.exists(log_file):
        sys.exit("[!] Log file not found: %s" % log_file)

    ips = profile(iter_events(log_file))
    infra = sorted({h for p in ips.values() for h in p["download_hosts"] if IPV4.match(h)})
    droppers = sorted((ip for ip, p in ips.items() if p["files"]),
                      key=lambda ip: -ips[ip]["sessions"])
    priority = (infra + droppers)[:DSHIELD_LIMIT]
    intel = enrich(sorted(set(ips) | set(infra)), load_cache(), priority, args.offline)
    camps = campaigns(ips, intel)

    print_summary(ips, intel, camps)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"log": log_file,
                   "ips": {ip: dict(jsonable(p), tier=tier(p), **intel[ip])
                           for ip, p in ips.items()},
                   "infrastructure": {ip: intel[ip] for ip in infra},
                   "campaigns": camps}, fh)
    print("\nWrote %s" % os.path.abspath(args.out))


if __name__ == "__main__":
    main()
