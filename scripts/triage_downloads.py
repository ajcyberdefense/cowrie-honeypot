#!/usr/bin/env python3
# =============================================================================
# triage_downloads.py — Static triage of the payloads Cowrie captured
# =============================================================================
# STATIC ONLY. Nothing here executes a sample. Files are read as bytes; UPX
# packed samples are decompressed (if `upx` is installed) into a temporary
# copy that is deleted afterwards. The originals are never modified.
#
# For every captured file this records: hashes, file kind and CPU
# architecture, packing, family evidence (plain strings and Mirai's XOR-0x22
# string table), network indicators, any credentials it shares with the
# passwords the honeypot logged, and how it arrived (URL, source IPs, first
# seen) from the Cowrie log.
#
# Usage (on the honeypot, as the cowrie user or root):
#   python3 triage_downloads.py --out triage.json
#   python3 triage_downloads.py /path/to/downloads --log /path/to/cowrie.json
#
# Then, anywhere with a MalwareBazaar key (MB_AUTH_KEY in the environment or
# in a .env file at the repo root) — only SHA-256 hashes are sent:
#   python3 triage_downloads.py --lookup triage.json
#
# Requirements: Python 3.6+, no third-party packages. `upx` optional.
# =============================================================================

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

from mitre_map import iter_events, resolve_log_file

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_DOWNLOAD_DIRS = [
    os.path.expanduser("~/honeypot/var/lib/cowrie/downloads"),
    "/home/cowrie/honeypot/var/lib/cowrie/downloads",
    os.path.join(os.getcwd(), "var", "lib", "cowrie", "downloads"),
]

ELF_MACHINES = {2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 20: "PowerPC",
                21: "PowerPC64", 40: "ARM", 42: "SuperH", 62: "x86-64", 93: "ARC",
                183: "AArch64", 243: "RISC-V"}

# Mirai obfuscates its string table (and its credential list) by XOR with the
# bytes of 0xDEADBEEF, which collapses to a single-byte XOR with 0x22.
MIRAI_XOR = 0x22

# (family, where, regex). `where` is "plain" or "xor" (the 0x22-decoded bytes).
# Evidence is a literal string found in the sample, so every attribution can
# be checked by hand.
FAMILY_MARKERS = [
    ("Mirai", "xor", rb"TSource Engine Query|/bin/busybox [A-Z]{4,}|/dev/watchdog"),
    ("Mirai", "plain", rb"TSource Engine Query|dvrHelper"),
    ("Gafgyt", "plain", rb"Self Rep Fucking NeTiS|GAYFGT|KILLATTK|LOLNOGTFO"),
    ("Gafgyt", "xor", rb"LOLNOGTFO|KILLATTK"),
    ("XMRig", "plain", rb"xmrig"),
    # Bots that hunt rival miners carry "xmrig" too, next to the command-line
    # flag they look for in running processes. verdict() drops XMRig for them.
    ("miner-killer", "plain", rb"--donate-level"),
    ("Tsunami", "plain", rb"NOTICE %s :|KAITEN"),
]
HTTP_FLOOD_UA_MIN = 10   # this many Mozilla/ UA strings = HTTP flood module

IP_RX = re.compile(rb"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
                   rb"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?::(\d{2,5}))?(?![\d.])")
URL_RX = re.compile(rb"(?:https?|tftp|ftp)://[\x21-\x7e]{4,200}")
STR_RX = re.compile(rb"[\x20-\x7e]{3,}")


# -----------------------------------------------------------------------------
# Per-sample analysis
# -----------------------------------------------------------------------------
def classify(data):
    """('elf', arch description) | ('script', interpreter) | ('other', '')"""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        bits = {1: "32", 2: "64"}.get(data[4], "?")
        order = "little" if data[5] == 1 else "big"
        machine = int.from_bytes(data[18:20], order)
        name = ELF_MACHINES.get(machine, "machine %d" % machine)
        return "elf", "%s %s-bit %s-endian" % (name, bits, order)
    if data[:2] == b"#!":
        return "script", data[2:80].split(b"\n")[0].strip().decode("ascii", "replace")
    # Cowrie also saves files the attacker wrote with `echo >`, not just fetched.
    if re.match(rb"\s*(ssh-(rsa|ed25519|dss)|ecdsa-sha2-)", data):
        return "ssh-key", "authorized_keys content"
    if re.match(rb"\s*<(!DOCTYPE|html)", data, re.I):
        return "html", "error or landing page"
    # Scripts piped to `sh` or `python3` need no #! line.
    if re.match(rb"\s*(import|from)\s+\w+", data):
        return "script", "python (no #!)"
    if re.search(rb"\b(wget|curl|busybox|chmod|cd)\b", data[:2048]) \
            and re.fullmatch(rb"[\x09\x0a\x0d\x20-\x7e]*", data[:2048]):
        return "script", "shell (no #!)"
    return "other", ""


def unpack_upx(path, workdir):
    """Decompress a UPX copy into workdir. Returns (bytes or None, status)."""
    if not shutil.which("upx"):
        return None, "packed (upx not installed)"
    out = os.path.join(workdir, os.path.basename(path) + ".unpacked")
    r = subprocess.run(["upx", "-d", "-q", "-o", out, path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        # Mirai builders commonly corrupt the UPX header so `upx -d` refuses it.
        return None, "packed, header tampered (upx -d refused)"
    with open(out, "rb") as fh:
        data = fh.read()
    os.remove(out)
    return data, "unpacked"


def public_ip(ip):
    a, b = (int(x) for x in ip.split(".")[:2])
    return not (a in (0, 10, 127) or a >= 224 or (a, b) == (192, 168)
                or (a == 172 and 16 <= b <= 31) or (a, b) == (169, 254))


def analyze_sample(path, workdir, logged_creds):
    with open(path, "rb") as fh:
        raw = fh.read()
    kind, detail = classify(raw)
    rec = {"sha256": hashlib.sha256(raw).hexdigest(),
           "md5": hashlib.md5(raw).hexdigest(),
           "size": len(raw), "kind": kind, "detail": detail,
           "packing": "none", "families": {}, "ips": [], "urls": [],
           "http_flood_uas": 0, "shared_credentials": []}

    data = raw
    if kind == "elf" and b"UPX!" in raw:
        unpacked, rec["packing"] = unpack_upx(path, workdir)
        if unpacked:
            data = unpacked
    xored = bytes(b ^ MIRAI_XOR for b in data) if kind == "elf" else b""

    for family, where, rx in FAMILY_MARKERS:
        m = re.search(rx, xored if where == "xor" else data)
        if m:
            rec["families"].setdefault(family, []).append(
                "%s: %s" % (where, m.group().decode("ascii", "replace")))

    ips = set()
    for blob in (data, xored):
        for m in IP_RX.finditer(blob):
            ip = m.group(1).decode()
            if public_ip(ip):
                ips.add(ip + (":" + m.group(2).decode() if m.group(2) else ""))
        rec["urls"] += [u.decode("ascii", "replace") for u in URL_RX.findall(blob)]
    rec["ips"] = sorted(ips)
    rec["urls"] = sorted(set(rec["urls"]))
    rec["http_flood_uas"] = len(re.findall(rb"Mozilla/\d\.\d \(", data))

    # A logged password must appear as a whole string, plain or XOR-decoded
    # (most builds here ship the brute-force list in plaintext; classic Mirai
    # encodes it). logged_creds is pre-filtered to distinctive passwords.
    strings = {s.decode() for blob in (data, xored) for s in STR_RX.findall(blob)}
    rec["shared_credentials"] = sorted(strings & logged_creds)
    return rec


def verdict(rec):
    fams = sorted(rec["families"])
    if "miner-killer" in fams:
        fams = [f for f in fams if f not in ("XMRig", "miner-killer")]
        fams.append("bot with miner kill list")
    if rec["http_flood_uas"] >= HTTP_FLOOD_UA_MIN:
        fams.append("HTTP-flood UA list")
    if fams:
        return " + ".join(fams)
    if rec["kind"] == "script":
        return "downloader script" if rec["urls"] or rec["ips"] else "script"
    if "tampered" in rec["packing"]:
        return "unknown (packed, tampered UPX)"
    if rec["kind"] in ("ssh-key", "html"):
        return rec["kind"]
    if rec["kind"] == "other" and rec["size"] < 64:
        return "marker file (<64 bytes)"
    return "unknown"


# -----------------------------------------------------------------------------
# Log correlation
# -----------------------------------------------------------------------------
def distinctive(password):
    """Letters and digits, 5+ chars. Plain words ("bash", "admin") turn up in
    any binary by accident; `xc3511` or `admin1234` does not."""
    return (len(password) >= 5 and re.search(r"\d", password) is not None
            and re.search(r"[A-Za-z]", password) is not None)


def scan_log(log_file):
    """Arrival details per sha256, plus how often each distinctive password
    was tried."""
    arrivals = defaultdict(lambda: {"urls": set(), "src_ips": set(),
                                    "first_seen": None, "count": 0})
    creds = Counter()
    for e in iter_events(log_file):
        eid = e.get("eventid", "")
        if eid in ("cowrie.login.failed", "cowrie.login.success"):
            v = e.get("password")
            if isinstance(v, str) and distinctive(v):
                creds[v] += 1
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sha = e.get("shasum")
            if not sha:
                continue
            a = arrivals[sha]
            a["count"] += 1
            if e.get("url"):
                a["urls"].add(e["url"])
            if e.get("src_ip"):
                a["src_ips"].add(e["src_ip"])
            ts = e.get("timestamp")
            if ts and (a["first_seen"] is None or ts < a["first_seen"]):
                a["first_seen"] = ts
    return arrivals, creds


# -----------------------------------------------------------------------------
# MalwareBazaar lookup (hash only)
# -----------------------------------------------------------------------------
def load_key():
    key = os.environ.get("MB_AUTH_KEY")
    env = os.path.join(REPO, ".env")
    if not key and os.path.exists(env):
        with open(env, encoding="utf-8") as fh:
            for line in fh:
                if line.strip().startswith("MB_AUTH_KEY="):
                    key = line.split("=", 1)[1].strip().strip("'\"")
    return key


def mb_lookup(sha256, key):
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=body,
                                 headers={"Auth-Key": key})
    with urllib.request.urlopen(req, timeout=30) as resp:
        reply = json.load(resp)
    if reply.get("query_status") != "ok":
        return {"status": reply.get("query_status")}
    d = reply["data"][0]
    return {"status": "ok", "signature": d.get("signature"),
            "tags": d.get("tags") or [], "first_seen": d.get("first_seen")}


def lookup(report_path):
    key = load_key()
    if not key:
        sys.exit("[!] No MalwareBazaar key: set MB_AUTH_KEY or add it to %s"
                 % os.path.join(REPO, ".env"))
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    todo = [r for r in report["samples"] if "malwarebazaar" not in r]
    for i, rec in enumerate(todo, 1):
        try:
            rec["malwarebazaar"] = mb_lookup(rec["sha256"], key)
        except OSError as exc:      # keep what we have; re-run resumes
            print("[!] lookup failed at %d/%d: %s" % (i, len(todo), exc))
            break
        print("%3d/%d %s %s" % (i, len(todo), rec["sha256"][:16],
                                rec["malwarebazaar"].get("signature")
                                or rec["malwarebazaar"]["status"]))
        time.sleep(0.5)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def resolve_download_dir(explicit):
    if explicit:
        return explicit
    for d in DEFAULT_DOWNLOAD_DIRS:
        if os.path.isdir(d):
            return d
    return DEFAULT_DOWNLOAD_DIRS[0]


def triage(download_dir, log_file):
    arrivals, creds = scan_log(log_file) if os.path.exists(log_file) else ({}, Counter())
    workdir = tempfile.mkdtemp(prefix="triage-")
    try:
        samples = []
        for name in sorted(os.listdir(download_dir)):
            path = os.path.join(download_dir, name)
            if not os.path.isfile(path):
                continue
            rec = analyze_sample(path, workdir, set(creds))
            rec["verdict"] = verdict(rec)
            a = arrivals.get(rec["sha256"])
            if a:
                rec["arrival"] = {"urls": sorted(a["urls"]),
                                  "src_ips": sorted(a["src_ips"]),
                                  "first_seen": a["first_seen"],
                                  "count": a["count"]}
            samples.append(rec)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return {"download_dir": download_dir, "log": log_file,
            "password_tries": {c: creds[c] for c in
                               {c for r in samples for c in r["shared_credentials"]}},
            "samples": samples}


def print_summary(report):
    s = report["samples"]
    print("%d samples" % len(s))
    for label, key in (("kind", "kind"), ("verdict", "verdict"),
                       ("architecture", "detail"), ("packing", "packing")):
        print("\nBy %s:" % label)
        for v, n in Counter(r[key] for r in s
                            if key != "detail" or r["kind"] == "elf").most_common(12):
            print("  %4d  %s" % (n, v))
    shared = Counter(c for r in s for c in r["shared_credentials"])
    print("\nSamples carrying credentials the honeypot saw: %d"
          % sum(1 for r in s if r["shared_credentials"]))
    print("  %7s %8s  password" % ("samples", "tried"))
    for c, n in shared.most_common(15):
        print("  %7d %8d  %s" % (n, report["password_tries"].get(c, 0), c))


def main():
    ap = argparse.ArgumentParser(description="Static triage of Cowrie downloads")
    ap.add_argument("downloads", nargs="?", help="Cowrie downloads directory")
    ap.add_argument("--log", help="path to cowrie.json (rotations are read too)")
    ap.add_argument("--out", default="triage.json", help="report file (JSON)")
    ap.add_argument("--lookup", metavar="REPORT",
                    help="add MalwareBazaar results to an existing report")
    args = ap.parse_args()

    if args.lookup:
        lookup(args.lookup)
        return

    download_dir = resolve_download_dir(args.downloads)
    if not os.path.isdir(download_dir):
        sys.exit("[!] Downloads directory not found: %s" % download_dir)
    report = triage(download_dir, resolve_log_file(args.log))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print_summary(report)
    print("\nWrote %s" % os.path.abspath(args.out))


if __name__ == "__main__":
    main()
