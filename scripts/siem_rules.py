#!/usr/bin/env python3
# =============================================================================
# siem_rules.py — Port Part 6's Sigma detections into Elastic and prove parity
# =============================================================================
# The detections in sigma_from_cowrie.py are PCRE-style regexes. Elasticsearch
# uses Lucene regex, which differs in ways that fail SILENTLY:
#   - no \s \S \d \b shorthands, no (?i) / (?s) inline flags
#   - the case_insensitive flag does not cover character ranges like [a-f]
#   - "." matches newlines (Python's does not without (?s))
#   - every pattern is anchored to the whole field
#   - with default flags, & < > @ ~ # " are operators: a pattern containing
#     "&&" or ">" quietly matches nothing at all
# to_lucene() translates each rule; the regexp query runs with flags NONE.
#
# Then, for every rule, the number of events Elasticsearch matches is compared
# with the number Python's original regex matches on the same log. A port
# that does not reproduce the original's hits is not a port.
#
# Usage (stack from siem/ running, history loaded with siem_load.py):
#   python3 siem_rules.py              # parity check only
#   python3 siem_rules.py --install    # also create/update Kibana detection rules
#   python3 siem_rules.py --install --backfill   # ...looking back 90 days, once
#   python3 siem_rules.py --alerts     # count alerts the installed rules raised
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid

from mitre_map import iter_events, resolve_log_file
from sigma_from_cowrie import DETECTIONS, UUID_NS
from siem_load import ES, INDEX, read_env

RISK = {"low": 21, "medium": 47, "high": 73, "critical": 99}

# PCRE shorthand -> Lucene equivalent. \b has no Lucene form; dropping it
# makes a rule slightly broader, which the parity check measures.
SHORTHANDS = [(r"\s", "[ \t\n\r]"), (r"\S", "[^ \t\n\r]"), (r"\d", "[0-9]"),
              (r"\b", ""), (r"\x5c", r"\\")]


def to_lucene(regex):
    """PCRE (as used by the Sigma rules) -> (Lucene pattern, case_insensitive)."""
    flags = re.match(r"\(\?([is]+)\)", regex)
    ci = bool(flags) and "i" in flags.group(1)
    if flags:               # Lucene's "." already matches newlines, so (?s) is free
        regex = regex[flags.end():]
    for pcre, lucene in SHORTHANDS:
        regex = regex.replace(pcre, lucene)
    return ".*(" + regex + ").*", ci


def es_query(d):
    pattern, ci = to_lucene(d["regex"])
    return {"bool": {"filter": [
        {"term": {"eventid": "cowrie.command.input"}},
        {"regexp": {"input": {"value": pattern, "flags": "NONE",
                              "case_insensitive": ci, "max_determinized_states": 100000}}}]}}


def python_counts(log_file):
    rx = [(d["name"], re.compile(d["regex"])) for d in DETECTIONS]
    counts = {name: 0 for name, _ in rx}
    for e in iter_events(log_file):
        if e.get("eventid") == "cowrie.command.input":
            line = e.get("input", "")
            for name, r in rx:
                if r.search(line):
                    counts[name] += 1
    return counts


# -----------------------------------------------------------------------------
# Kibana
# -----------------------------------------------------------------------------
def kibana(url, password, method, path, body=None):
    es = ES(url, password)
    req = urllib.request.Request(url.rstrip("/") + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": es.auth, "kbn-xsrf": "true",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def rule_body(d, lookback):
    pattern, ci = to_lucene(d["regex"])
    return {
        "rule_id": str(uuid.uuid5(UUID_NS, d["name"])),
        "name": "Cowrie: " + d["title"],
        "description": d["description"],
        "false_positives": d["falsepositives"],
        "severity": d["level"], "risk_score": RISK[d["level"]],
        "tags": ["cowrie", "sigma-port"] + d["tags"],
        "type": "query", "language": "kuery",
        "query": 'eventid : "cowrie.command.input"',
        "filters": [{
            "meta": {"alias": "input matches " + d["name"], "type": "custom",
                     "key": "query", "negate": False, "disabled": False},
            "query": {"regexp": {"input": {"value": pattern, "flags": "NONE",
                                           "case_insensitive": ci}}}}],
        "index": [INDEX],
        # now-6m: each 5-minute run sees only new events (plus overlap).
        # --backfill uses now-90d once, to prove the rules fire on history.
        "from": lookback, "interval": "5m", "max_signals": 100,
        "enabled": True,
    }


def install(kib, password, lookback):
    kibana(kib, password, "POST", "/api/detection_engine/index")   # alerts index
    for d in DETECTIONS:
        body = rule_body(d, lookback)
        status, _ = kibana(kib, password, "GET",
                           "/api/detection_engine/rules?rule_id=" + body["rule_id"])
        method = "PUT" if status == 200 else "POST"
        status, resp = kibana(kib, password, method, "/api/detection_engine/rules", body)
        print("  %-24s %s %s" % (d["name"], method, "ok" if status == 200 else resp))


def alerts(es):
    r = es.call("POST", "/.alerts-security.alerts-default/_search", {
        "size": 0, "aggs": {"r": {"terms": {"field": "kibana.alert.rule.name", "size": 50}}}})
    for b in r["aggregations"]["r"]["buckets"]:
        print("  %6d  %s" % (b["doc_count"], b["key"]))


def main():
    ap = argparse.ArgumentParser(description="Port Sigma detections into Elastic")
    ap.add_argument("log", nargs="?", help="path to cowrie.json, for the parity check")
    ap.add_argument("--es", default="http://127.0.0.1:9200")
    ap.add_argument("--kibana", default="http://127.0.0.1:5601")
    ap.add_argument("--install", action="store_true", help="create/update Kibana rules")
    ap.add_argument("--backfill", action="store_true",
                    help="with --install: look back 90 days instead of 6 minutes")
    ap.add_argument("--alerts", action="store_true", help="count raised alerts and exit")
    args = ap.parse_args()

    password = read_env("ELASTIC_PASSWORD")
    if not password:
        sys.exit("[!] ELASTIC_PASSWORD not found in siem/.env")
    es = ES(args.es, password)
    if args.alerts:
        alerts(es)
        return

    log_file = resolve_log_file(args.log)
    py = python_counts(log_file) if os.path.exists(log_file) else {}
    print("%-24s %9s %9s  %s" % ("rule", "python", "elastic", "parity"))
    for d in DETECTIONS:
        n = es.call("POST", "/%s/_count" % INDEX, {"query": es_query(d)})["count"]
        p = py.get(d["name"])
        verdict = "-" if p is None else "exact" if n == p else "%+d" % (n - p)
        print("%-24s %9s %9d  %s" % (d["name"], p if p is not None else "-", n, verdict))

    if args.install:
        print("\nKibana detection rules:")
        install(args.kibana, password, "now-90d" if args.backfill else "now-6m")


if __name__ == "__main__":
    main()
