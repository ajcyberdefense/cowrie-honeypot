#!/usr/bin/env python3
# =============================================================================
# siem_load.py — Ship cowrie.json (and its rotations) into Elasticsearch
# =============================================================================
# Stdlib-only replacement for a Filebeat pipeline, for replaying the honeypot's
# history into the lab stack in siem/. Each event gets:
#   @timestamp   from Cowrie's timestamp
#   src.*        ASN, AS name, country and hosting flag from Part 8's
#                analysis/intel.json, when that file exists
#   _id          a hash of the raw line, so re-running never duplicates
#
# Usage:
#   python3 siem_load.py                      # all history into index "cowrie"
#   python3 siem_load.py /path/to/cowrie.json --es http://localhost:9200
#
# Credentials come from siem/.env (ELASTIC_PASSWORD), user "elastic".
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from mitre_map import log_files, resolve_log_file

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = "cowrie"
BATCH = 5000

# Cowrie's fields, typed. Anything not listed is still kept, as keyword.
MAPPING = {
    "dynamic_templates": [{"strings": {
        "match_mapping_type": "string",
        "mapping": {"type": "keyword", "ignore_above": 1024}}}],
    "properties": {
        "@timestamp": {"type": "date"},
        "eventid": {"type": "keyword"},
        "session": {"type": "keyword"},
        "src_ip": {"type": "ip"},
        "src_port": {"type": "integer"},
        "dst_port": {"type": "integer"},
        "protocol": {"type": "keyword"},
        "username": {"type": "keyword"},
        "password": {"type": "keyword"},
        "input": {"type": "keyword", "ignore_above": 32766,
                  "fields": {"text": {"type": "text"}}},
        "message": {"type": "text"},
        "url": {"type": "keyword"},
        "shasum": {"type": "keyword"},
        "hassh": {"type": "keyword"},
        "version": {"type": "keyword"},
        "duration": {"type": "float"},
        "src": {"properties": {
            "asn": {"type": "keyword"}, "as_name": {"type": "keyword"},
            "cc": {"type": "keyword"}, "hosting": {"type": "boolean"},
            "tier": {"type": "keyword"}}},
    },
}


def read_env(name):
    path = os.path.join(REPO, "siem", ".env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(name + "="):
                    return line.split("=", 1)[1].strip()
    return os.environ.get(name)


class ES:
    def __init__(self, url, password):
        self.url = url.rstrip("/")
        token = base64.b64encode(("elastic:%s" % password).encode()).decode()
        self.auth = "Basic " + token

    def call(self, method, path, body=None, ndjson=False):
        data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": self.auth,
            "Content-Type": "application/x-ndjson" if ndjson else "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                return json.load(resp) if method != "HEAD" else True
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "HEAD":
                return None
            sys.exit("[!] %s %s -> %s: %s" % (method, path, exc.code, exc.read()[:500]))


def src_context():
    path = os.path.join(REPO, "analysis", "intel.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        ips = json.load(fh)["ips"]
    ctx = {}
    for ip, p in ips.items():
        cy, api = p.get("cymru") or {}, p.get("ipapi") or {}
        ctx[ip] = {"asn": cy.get("asn"), "as_name": cy.get("as_name"),
                   "cc": cy.get("cc"), "hosting": api.get("hosting"), "tier": p.get("tier")}
    return ctx


def actions(log_file, ctx):
    for path in log_files(log_file):
        with open(path, "rb") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                if "timestamp" not in e:
                    continue
                e["@timestamp"] = e.pop("timestamp")
                if e.get("src_ip") in ctx:
                    e["src"] = ctx[e["src_ip"]]
                yield hashlib.sha1(raw).hexdigest(), e


def main():
    ap = argparse.ArgumentParser(description="Load Cowrie logs into Elasticsearch")
    ap.add_argument("log", nargs="?", help="path to cowrie.json (rotations read too)")
    ap.add_argument("--es", default="http://127.0.0.1:9200")
    args = ap.parse_args()

    password = read_env("ELASTIC_PASSWORD")
    if not password:
        sys.exit("[!] ELASTIC_PASSWORD not found in siem/.env or the environment")
    log_file = resolve_log_file(args.log)
    if not os.path.exists(log_file):
        sys.exit("[!] Log file not found: %s" % log_file)

    es = ES(args.es, password)
    if es.call("HEAD", "/" + INDEX) is None:
        es.call("PUT", "/" + INDEX, {"mappings": MAPPING,
                                     "settings": {"number_of_replicas": 0}})

    total = errors = 0
    batch = []

    def flush():
        nonlocal total, errors
        body = "".join(json.dumps({"index": {"_index": INDEX, "_id": i}}) + "\n"
                       + json.dumps(doc) + "\n" for i, doc in batch).encode()
        r = es.call("POST", "/_bulk", body, ndjson=True)
        if r.get("errors"):
            bad = [it["index"] for it in r["items"] if it["index"].get("error")]
            if not errors:                      # show the first failure once
                print("  first error: %s" % json.dumps(bad[0]["error"])[:300])
            errors += len(bad)
        total += len(batch)
        batch.clear()
        if total % (BATCH * 40) == 0:
            print("  %d events" % total)

    for doc_id, doc in actions(log_file, src_context()):
        batch.append((doc_id, doc))
        if len(batch) >= BATCH:
            flush()
    if batch:
        flush()
    es.call("POST", "/%s/_refresh" % INDEX)
    count = es.call("GET", "/%s/_count" % INDEX)["count"]
    print("Sent %d events, %d rejected; index '%s' now holds %d" % (total, errors, INDEX, count))


if __name__ == "__main__":
    main()
