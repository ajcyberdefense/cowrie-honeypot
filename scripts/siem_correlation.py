#!/usr/bin/env python3
# =============================================================================
# siem_correlation.py — Detections that need more than one event
# =============================================================================
# Part 6's rules each look at one command line. Parts 6 and 8 named what that
# misses; these three rules close the gaps, each in the Kibana rule type that
# fits it:
#
#   smtp_tunnel           query      SSH login used as a TCP tunnel to a mail
#                                    port (Part 8 campaign 4: runs no commands)
#   split_download_chmod  eql        download in one command, chmod in a later
#                                    one, same session, within 2 minutes
#   recon_burst           threshold  6+ distinct system-fingerprint commands in
#                                    one session (the miner pre-check burst)
#
# Every pattern is written ONCE, in the regex subset that Python, Lucene and
# EQL all read the same way: no \s \b \d shorthands, explicit word boundaries,
# matched against the whole field. A Python reference implementation of each
# rule then checks the Elastic hit counts, as siem_rules.py does.
#
# Usage (stack running, history loaded):
#   python3 siem_correlation.py                       # parity check
#   python3 siem_correlation.py --install --backfill  # create rules, 90-day look-back
#   python3 siem_correlation.py --install             # live mode (last 6 minutes)
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import re
import sys
import uuid
from collections import defaultdict
from datetime import datetime

from mitre_map import iter_events, resolve_log_file
from siem_load import ES, INDEX, read_env
from siem_rules import RISK, kibana
from sigma_from_cowrie import UUID_NS

NW = "[^A-Za-z0-9_]"                       # "not a word character"
MAIL_PORTS = (25, 465, 587)
DOWNLOAD = "(.*%s)?(wget|curl|tftp|ftpget)(%s.*)?" % (NW, NW)
CHMOD = "(.*%s)?chmod[ \t]+([+]x|[0-7]?[0-7][0-7]7)(%s.*)?" % (NW, NW)
SPLIT_WINDOW = 120                         # seconds; longest observed gap was 107
RECON = ("[ \t]*(uname|whoami|w|id|crontab -l|top|lscpu|free|df|nproc|hostname|"
         "ifconfig|ip a|lspci|cat /proc/cpuinfo|cat /etc/os-release|"
         "ls -lh [$][(]which ls[)])(%s.*)?" % NW)
RECON_MIN = 6                              # data is bimodal: 0-3 or 9, nothing between

RULES = [
    {"name": "smtp_tunnel", "level": "high",
     "title": "SSH Session Used as a Tunnel to a Mail Server",
     "description": "A logged-in session asks the SSH server to forward a TCP "
                    "connection to port 25, 465 or 587. Stolen SSH access being "
                    "validated as a spam relay; no commands are run, so no "
                    "command-based rule sees it.",
     "falsepositives": ["Admins tunnelling to their own mail server for testing; "
                        "rare, and the destination will be a known host"],
     "tags": ["attack.command_and_control", "attack.t1090", "attack.t1572"]},
    {"name": "split_download_chmod", "level": "high",
     "title": "Download Then chmod in Separate Commands of One Session",
     "description": "A download command followed within 2 minutes by a chmod +x "
                    "or 7xx in a later command of the same session. Catches the "
                    "chains the single-line download_execute_chain rule cannot.",
     "falsepositives": ["Manual software installs (wget a release, then chmod +x "
                        "it). Common for admins; tune by user or host"],
     "tags": ["attack.command_and_control", "attack.t1105",
              "attack.defense_evasion", "attack.t1222.002"]},
    {"name": "recon_burst", "level": "medium",
     "title": "Burst of System Fingerprinting Commands",
     "description": "6 or more distinct host-fingerprint commands (uname, lscpu, "
                    "free, df, crontab -l, ...) in one session. Each is harmless; "
                    "the burst is a scripted resource check before a miner drop.",
     "falsepositives": ["Login scripts or tools such as neofetch that print system "
                        "facts; inventory agents running over SSH"],
     "tags": ["attack.discovery", "attack.t1082", "attack.t1033"]},
]


# -----------------------------------------------------------------------------
# Python reference implementations
# -----------------------------------------------------------------------------
def full(pattern, text):
    """Whole-field match with '.' crossing newlines: how Lucene and EQL match."""
    return re.fullmatch(pattern, text, re.S) is not None


def split_chain(events):
    """events: [(datetime, command)] in order. True if a download is followed by
    a chmod in a LATER command within SPLIT_WINDOW seconds."""
    for i, (t1, c1) in enumerate(events):
        if full(DOWNLOAD, c1) and any(
                full(CHMOD, c2) and 0 <= (t2 - t1).total_seconds() <= SPLIT_WINDOW
                for t2, c2 in events[i + 1:]):
            return True
    return False


def recon_burst(events):
    return len({c for _, c in events if full(RECON, c)}) >= RECON_MIN


def python_counts(log_file):
    tunnels = 0
    cmds = defaultdict(list)
    for e in iter_events(log_file):
        eid = e.get("eventid")
        if eid == "cowrie.direct-tcpip.request" and e.get("dst_port") in MAIL_PORTS:
            tunnels += 1
        elif eid == "cowrie.command.input":
            t = datetime.strptime(e["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")
            cmds[e.get("session")].append((t, e.get("input", "")))
    return {"smtp_tunnel": tunnels,
            "split_download_chmod": sum(split_chain(ev) for ev in cmds.values()),
            "recon_burst": sum(recon_burst(ev) for ev in cmds.values())}


# -----------------------------------------------------------------------------
# The same three, in Elasticsearch
# -----------------------------------------------------------------------------
def eql_query():
    def step(pattern):
        return ('[any where eventid == "cowrie.command.input" and input regex "%s"]'
                % pattern.replace("\t", "\\t"))
    return "sequence by session with maxspan=%ds %s %s" % (
        SPLIT_WINDOW, step(DOWNLOAD), step(CHMOD))


def recon_filter():
    return {"regexp": {"input": {"value": RECON, "flags": "NONE"}}}


def es_counts(es):
    tunnels = es.call("POST", "/%s/_count" % INDEX, {"query": {"bool": {"filter": [
        {"term": {"eventid": "cowrie.direct-tcpip.request"}},
        {"terms": {"dst_port": list(MAIL_PORTS)}}]}}})["count"]

    r = es.call("POST", "/%s/_eql/search" % INDEX, {"query": eql_query(), "size": 10000})
    split = len({s["join_keys"][0] for s in r["hits"].get("sequences", [])})

    r = es.call("POST", "/%s/_search" % INDEX, {"size": 0, "query": {"bool": {"filter": [
        {"term": {"eventid": "cowrie.command.input"}}, recon_filter()]}},
        "aggs": {"s": {"terms": {"field": "session", "size": 20000},
                       "aggs": {"n": {"cardinality": {"field": "input"}},
                                "keep": {"bucket_selector": {
                                    "buckets_path": {"n": "n"},
                                    "script": "params.n >= %d" % RECON_MIN}}}}}})
    recon = len(r["aggregations"]["s"]["buckets"])
    return {"smtp_tunnel": tunnels, "split_download_chmod": split, "recon_burst": recon}


# -----------------------------------------------------------------------------
# Kibana rules
# -----------------------------------------------------------------------------
def rule_body(d, lookback):
    body = {
        "rule_id": str(uuid.uuid5(UUID_NS, "correlation:" + d["name"])),
        "name": "Cowrie: " + d["title"], "description": d["description"],
        "false_positives": d["falsepositives"], "severity": d["level"],
        "risk_score": RISK[d["level"]], "tags": ["cowrie", "correlation"] + d["tags"],
        "index": [INDEX], "from": lookback, "interval": "5m", "max_signals": 100,
        "enabled": True,
    }
    if d["name"] == "smtp_tunnel":
        body.update(type="query", language="kuery", query=(
            'eventid : "cowrie.direct-tcpip.request" and dst_port : (%s)'
            % " or ".join(str(p) for p in MAIL_PORTS)))
    elif d["name"] == "split_download_chmod":
        body.update(type="eql", language="eql", query=eql_query())
    else:
        body.update(type="threshold", language="kuery",
                    query='eventid : "cowrie.command.input"',
                    filters=[{"meta": {"alias": "recon command", "type": "custom",
                                       "key": "query", "negate": False, "disabled": False},
                              "query": recon_filter()}],
                    threshold={"field": ["session"], "value": 1,
                               "cardinality": [{"field": "input", "value": RECON_MIN}]})
    return body


def install(kib, password, lookback):
    for d in RULES:
        body = rule_body(d, lookback)
        status, _ = kibana(kib, password, "GET",
                           "/api/detection_engine/rules?rule_id=" + body["rule_id"])
        method = "PUT" if status == 200 else "POST"
        status, resp = kibana(kib, password, method, "/api/detection_engine/rules", body)
        print("  %-22s %s %s" % (d["name"], method, "ok" if status == 200 else resp))


def main():
    ap = argparse.ArgumentParser(description="Multi-event detections for Cowrie in Elastic")
    ap.add_argument("log", nargs="?", help="path to cowrie.json, for the parity check")
    ap.add_argument("--es", default="http://127.0.0.1:9200")
    ap.add_argument("--kibana", default="http://127.0.0.1:5601")
    ap.add_argument("--install", action="store_true", help="create/update Kibana rules")
    ap.add_argument("--backfill", action="store_true",
                    help="with --install: look back 90 days instead of 6 minutes")
    args = ap.parse_args()

    password = read_env("ELASTIC_PASSWORD")
    if not password:
        sys.exit("[!] ELASTIC_PASSWORD not found in siem/.env")
    es = ES(args.es, password)

    py = python_counts(resolve_log_file(args.log))
    el = es_counts(es)
    print("%-22s %8s %8s  %s   (smtp_tunnel counts events; the others, sessions)"
          % ("rule", "python", "elastic", "parity"))
    for d in RULES:
        p, n = py[d["name"]], el[d["name"]]
        print("%-22s %8d %8d  %s" % (d["name"], p, n, "exact" if p == n else "%+d" % (n - p)))

    if args.install:
        print("\nKibana correlation rules:")
        install(args.kibana, password, "now-90d" if args.backfill else "now-6m")


if __name__ == "__main__":
    main()
