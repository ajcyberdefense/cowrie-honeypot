#!/usr/bin/env python3
# =============================================================================
# siem_dashboard.py — analyze.py's report, rebuilt as a Kibana dashboard
# =============================================================================
# Same questions analyze.py answers on the command line — totals, top source
# IPs, usernames, passwords, commands, downloads — answered by Elasticsearch
# aggregations instead, plus the Part 8 enrichment (ASN, country, tier).
#
#   --check    compare the SIEM's totals with Python's count of the same log.
#              Same answers, different tool: a mismatch means the pipeline
#              dropped or duplicated something.
#   --install  create the data view, visualizations and dashboard in Kibana
#              (idempotent: fixed ids, overwrite on import).
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid

from mitre_map import iter_events, resolve_log_file
from siem_load import ES, INDEX, read_env

NS = uuid.UUID("0c0ffee0-0000-4000-8000-00000000c0de")
DATA_VIEW = str(uuid.uuid5(NS, "data-view"))

# analyze.py's summary block: label -> event id.
TOTALS = [("Total sessions", "cowrie.session.connect"),
          ("Failed login attempts", "cowrie.login.failed"),
          ("Successful logins", "cowrie.login.success"),
          ("Commands executed", "cowrie.command.input"),
          ("File downloads", "cowrie.session.file_download")]

# (title, kuery filter, terms field, size). One table panel each.
TABLES = [
    ("Top source IPs (sessions)", 'eventid : "cowrie.session.connect"', "src_ip", 15),
    ("Top usernames tried", 'eventid : ("cowrie.login.failed" or "cowrie.login.success")', "username", 15),
    ("Top passwords tried", 'eventid : ("cowrie.login.failed" or "cowrie.login.success")', "password", 15),
    ("Top commands", 'eventid : "cowrie.command.input"', "input", 15),
    ("Download URLs", 'eventid : "cowrie.session.file_download"', "url", 15),
    ("Payloads (SHA-256)", 'eventid : "cowrie.session.file_download"', "shasum", 15),
    ("Attacker networks (ASN)", 'eventid : "cowrie.session.connect"', "src.as_name", 15),
    ("Attacker countries (registry)", 'eventid : "cowrie.session.connect"', "src.cc", 15),
    ("Sessions by IP activity tier", 'eventid : "cowrie.session.connect"', "src.tier", 5),
    ("SSH client fingerprints (HASSH)", 'eventid : "cowrie.client.kex"', "hassh", 10),
]


# -----------------------------------------------------------------------------
# Parity check
# -----------------------------------------------------------------------------
def distinct_ips(es):
    """Exact count by paging a composite aggregation. The `cardinality`
    aggregation is a HyperLogLog estimate: it came out 2 short of 12,208."""
    n, after = 0, None
    while True:
        comp = {"size": 10000, "sources": [{"ip": {"terms": {"field": "src_ip"}}}]}
        if after:
            comp["after"] = after
        r = es.call("POST", "/%s/_search" % INDEX, {
            "size": 0, "query": {"term": {"eventid": "cowrie.session.connect"}},
            "aggs": {"c": {"composite": comp}}})["aggregations"]["c"]
        n += len(r["buckets"])
        after = r.get("after_key")
        if not r["buckets"] or not after:
            return n


def check(es, log_file):
    py = {eid: 0 for _, eid in TOTALS}
    ips = set()
    for e in iter_events(log_file):
        if e.get("eventid") in py:
            py[e["eventid"]] += 1
        if e.get("eventid") == "cowrie.session.connect":
            ips.add(e.get("src_ip"))
    r = es.call("POST", "/%s/_search" % INDEX, {"size": 0, "aggs": {
        "eid": {"terms": {"field": "eventid", "size": 100}}}})
    siem = {b["key"]: b["doc_count"] for b in r["aggregations"]["eid"]["buckets"]}
    rows = [(label, py[eid], siem.get(eid, 0)) for label, eid in TOTALS]
    rows.append(("Unique source IPs", len(ips), distinct_ips(es)))
    print("%-24s %10s %10s  %s" % ("", "python", "elastic", "parity"))
    ok = True
    for label, p, s in rows:
        same = p == s
        ok &= same
        print("%-24s %10d %10d  %s" % (label, p, s, "exact" if same else "%+d" % (s - p)))
    return ok


# -----------------------------------------------------------------------------
# Kibana saved objects
# -----------------------------------------------------------------------------
def search_source(query):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})


def vis(title, vis_type, aggs, params, query=""):
    return {
        "type": "visualization", "id": str(uuid.uuid5(NS, title)),
        "attributes": {
            "title": title, "uiStateJSON": "{}", "description": "",
            "visState": json.dumps({"title": title, "type": vis_type,
                                    "aggs": aggs, "params": params}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": DATA_VIEW}]}


def table(title, query, field, size):
    return vis(title, "table", [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": field, "size": size, "order": "desc", "orderBy": "1",
                    "missingBucket": False, "otherBucket": False}}],
        {"perPage": size, "showPartialRows": False, "showMetricsAtAllLevels": False,
         "showTotal": False, "percentageCol": ""}, query)


def objects():
    """Data view, visualizations, and a dashboard laid out two panels per row
    (the time chart and the command table get a full row)."""
    view = {"type": "index-pattern", "id": DATA_VIEW,
            "attributes": {"title": INDEX, "name": "Cowrie honeypot",
                           "timeFieldName": "@timestamp"}, "references": []}
    timeline = vis("Activity over time", "histogram", [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "@timestamp", "interval": "d", "min_doc_count": 1}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "eventid", "size": 5, "order": "desc", "orderBy": "1"}}],
        {"type": "histogram", "addLegend": True, "legendPosition": "right",
         "addTooltip": True},
        'eventid : ("cowrie.session.connect" or "cowrie.login.success" or '
        '"cowrie.command.input" or "cowrie.session.file_download")')
    totals = table("Event totals", "eventid : (%s)" % " or ".join(
        '"%s"' % eid for _, eid in TOTALS), "eventid", 10)
    visuals = [timeline, totals] + [table(*t) for t in TABLES]

    panels, refs, x, y = [], [], 0, 0
    for i, o in enumerate(visuals):
        full = o["attributes"]["title"] in ("Activity over time", "Top commands")
        if full and x:                      # finish the half-filled row first
            x, y = 0, y + 15
        w = 48 if full else 24
        panels.append({"panelIndex": str(i), "panelRefName": "panel_%d" % i,
                       "gridData": {"x": x, "y": y, "w": w, "h": 15, "i": str(i)},
                       "embeddableConfig": {}})
        refs.append({"name": "panel_%d" % i, "type": "visualization", "id": o["id"]})
        x += w
        if x >= 48:
            x, y = 0, y + 15

    dashboard = {
        "type": "dashboard", "id": str(uuid.uuid5(NS, "dashboard")),
        "attributes": {
            "title": "Cowrie Honeypot — analyze.py in the SIEM",
            "description": "Totals, top IPs, credentials, commands and downloads, "
                           "plus ASN, country and activity tier from intel_enrich.py.",
            "panelsJSON": json.dumps(panels), "timeRestore": True,
            "timeFrom": "now-90d", "timeTo": "now",
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})}},
        "references": refs}
    return [view] + visuals + [dashboard]


def install(kib, es):
    ndjson = "\n".join(json.dumps(o) for o in objects()) + "\n"
    boundary = "----cowrie" + uuid.uuid4().hex
    body = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cowrie.ndjson\""
            "\r\nContent-Type: application/ndjson\r\n\r\n%s\r\n--%s--\r\n"
            % (boundary, ndjson, boundary)).encode()
    req = urllib.request.Request(
        kib.rstrip("/") + "/api/saved_objects/_import?overwrite=true", data=body,
        method="POST", headers={"Authorization": es.auth, "kbn-xsrf": "true",
                                "Content-Type": "multipart/form-data; boundary=" + boundary})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            r = json.load(resp)
    except urllib.error.HTTPError as exc:
        sys.exit("[!] import failed: %s %s" % (exc.code, exc.read()[:500]))
    if not r.get("success"):
        sys.exit("[!] import errors: %s" % json.dumps(r.get("errors"))[:800])
    print("Imported %d objects. Dashboard: %s/app/dashboards#/view/%s"
          % (r["successCount"], kib.rstrip("/"), uuid.uuid5(NS, "dashboard")))


def main():
    ap = argparse.ArgumentParser(description="analyze.py as a Kibana dashboard")
    ap.add_argument("log", nargs="?", help="path to cowrie.json, for --check")
    ap.add_argument("--es", default="http://127.0.0.1:9200")
    ap.add_argument("--kibana", default="http://127.0.0.1:5601")
    ap.add_argument("--check", action="store_true", help="SIEM vs Python totals")
    ap.add_argument("--install", action="store_true", help="import into Kibana")
    args = ap.parse_args()

    password = read_env("ELASTIC_PASSWORD")
    if not password:
        sys.exit("[!] ELASTIC_PASSWORD not found in siem/.env")
    es = ES(args.es, password)
    if args.check and not check(es, resolve_log_file(args.log)):
        print("[!] SIEM and Python disagree: the pipeline dropped or duplicated events")
    if args.install:
        install(args.kibana, es)
    if not (args.check or args.install):
        ap.print_help()


if __name__ == "__main__":
    main()
