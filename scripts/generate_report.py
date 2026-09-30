#!/usr/bin/env python3
# =============================================================================
# generate_report.py — Static, self-contained honeypot report
# =============================================================================
# Renders the honeypot's findings to a standalone HTML file plus an ATT&CK
# Navigator layer. No server, no JavaScript, no external assets — safe to
# publish anywhere (GitHub Pages, S3, any static host).
#
# Usage:
#   python3 generate_report.py --out ./site
#   python3 generate_report.py --out ./site --redact      # mask last IP octet
#   COWRIE_JSON_LOG=/path/to/cowrie.json python3 generate_report.py --out ./site
#
# Produces:
#   <out>/index.html                  the report
#   <out>/cowrie-attack-layer.json    ATT&CK Navigator layer
#   <out>/data.json                   raw analysis
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mitre_map  # noqa: E402


# NOTE: this constant is substituted with .replace(), never %-formatting.
# The CSS contains literal percent signs (width:100%;) that %-formatting
# would try to read as format specifiers and raise ValueError on.
_HEAD_HTML = """<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Honeypot Threat Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#21262d;--fg:#e6edf3;--mut:#8b949e;
      --acc:#58a6ff;--red:#f85149;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);
     font-family:system-ui,-apple-system,Segoe UI,sans-serif;
     line-height:1.5;padding:28px 18px 60px}
.wrap{max-width:1100px;margin:0 auto}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:26px}
h1{font-size:26px;letter-spacing:-.02em}
.sub{color:var(--mut);font-size:14px;margin-top:6px}
.badge{display:inline-block;background:var(--line);color:var(--mut);
       border-radius:20px;padding:2px 10px;font-size:12px;margin-right:6px}
h2{font-size:16px;margin:30px 0 12px;padding-bottom:8px;
   border-bottom:1px solid var(--line)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.tile .n{font-size:26px;font-weight:650}
.tile .l{color:var(--mut);font-size:12px;text-transform:uppercase;
         letter-spacing:.06em;margin-top:2px}
.tile .d{color:var(--acc);font-size:12px;margin-top:6px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px}
.panel h3{font-size:13px;color:var(--mut);text-transform:uppercase;
          letter-spacing:.06em;margin-bottom:12px}
.chart{width:100%;height:auto}
.bl{fill:var(--mut);font-size:11px;font-family:var(--mono)}
.bv{fill:var(--fg);font-size:11px;font-family:var(--mono)}
.tactics{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}
.tac{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.tac h3{display:flex;justify-content:space-between;align-items:center;
        font-size:12px;text-transform:uppercase;letter-spacing:.07em;
        color:var(--mut);margin-bottom:10px}
.tac h3 b{background:var(--line);color:var(--fg);border-radius:10px;
          padding:1px 8px;font-size:11px}
.tech{padding:7px 0;border-top:1px solid var(--bg)}
.tech:first-of-type{border-top:0}
.tid{font-family:var(--mono);color:var(--acc);font-size:12px}
.tct{float:right;color:var(--red);font-size:12px;font-weight:600}
.tnm{font-size:13px;margin-top:1px}
.teg{color:#6e7681;font-size:11px;font-family:var(--mono);margin-top:3px;
     overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;
   letter-spacing:.06em;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid var(--bg);
   font-family:var(--mono);font-size:12px}
.muted{color:var(--mut);font-size:13px}
a{color:var(--acc)}
footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);
       color:var(--mut);font-size:12px}
.scroll{overflow-x:auto}
</style>
<div class="wrap">
<header>
  <h1>SSH/Telnet Honeypot &mdash; Threat Report</h1>
  <div class="sub">Observed attacker behaviour against an internet-exposed
  Cowrie honeypot, mapped to MITRE ATT&amp;CK.</div>
  <div class="sub" style="margin-top:10px">
    <span class="badge">Generated __GENERATED__</span>
    <span class="badge">All-time since __SINCE__</span>
    <span class="badge">Static snapshot</span>
    <span class="badge">Cowrie 3.x</span>
  </div>
</header>"""


def redact_ip(ip, enabled):
    if not enabled or not ip:
        return ip
    parts = str(ip).split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["x"])
    return ip


class Tally:
    """Report-only aggregates, filled as events stream past mitre_map.analyze().

    All-time logs run to gigabytes and the host has under 1 GB of RAM, so
    events are counted on the fly and never held in a list.
    """

    def __init__(self, since):
        self.since = since          # "YYYY-MM-DDTHH:MM:SS"; at/after = last 24h
        self.first_ts = None
        self.session_ips = Counter()
        self.users = Counter()
        self.passwords = Counter()
        self.commands = Counter()
        self.downloads = {}         # sha256 -> url, first seen wins
        self.download_count = 0
        self.recent = Counter()
        self.recent_ips = set()

    def watch(self, events):
        for event in events:
            self.add(event)
            yield event

    def add(self, e):
        eid = e.get("eventid")
        src = e.get("src_ip")
        ts = (e.get("timestamp") or "")[:19]
        if ts and self.first_ts is None:
            self.first_ts = ts      # rotations are read oldest first
        recent = ts >= self.since

        if eid == "cowrie.session.connect":
            if src:
                self.session_ips[src] += 1
            if recent:
                self.recent["sessions"] += 1
                if src:
                    self.recent_ips.add(src)
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            if e.get("username"):
                self.users[e["username"]] += 1
            if e.get("password"):
                self.passwords[e["password"]] += 1
            if recent:
                self.recent["logins"] += 1
        elif eid == "cowrie.command.input":
            cmd = (e.get("input") or "").strip()
            if cmd:
                self.commands[cmd[:120]] += 1   # bound memory; display is 70
                if recent:
                    self.recent["commands"] += 1
        elif eid == "cowrie.session.file_download":
            self.download_count += 1
            self.downloads.setdefault(e.get("shasum", ""), e.get("url", ""))
            if recent:
                self.recent["downloads"] += 1


def bar_svg(rows, color="#f85149", width=420, row_h=26):
    """Inline SVG bar chart — avoids any JS or CDN dependency."""
    if not rows:
        return '<p class="muted">No data yet.</p>'
    peak = max(v for _, v in rows) or 1
    height = len(rows) * row_h + 6
    label_w = 160
    bar_max = width - label_w - 46
    out = ['<svg viewBox="0 0 %d %d" class="chart" role="img">' % (width, height)]
    for i, (label, value) in enumerate(rows):
        y = i * row_h + 4
        w = max(2, int(bar_max * value / peak))
        out.append(
            '<text x="0" y="%d" class="bl">%s</text>'
            '<rect x="%d" y="%d" width="%d" height="13" rx="3" fill="%s"/>'
            '<text x="%d" y="%d" class="bv">%d</text>'
            % (y + 12, html.escape(str(label)[:24]),
               label_w, y + 2, w, color,
               label_w + w + 6, y + 12, value)
        )
    out.append("</svg>")
    return "".join(out)


def build_html(analysis, tally, redact, now):
    # Sessions, not login attempts: one session carries many logins, so
    # counting logins per IP overshot the Sessions total (the old ~7,700
    # "per-IP" figure against 4,293 sessions).
    top_ips = [(redact_ip(ip, redact), n)
               for ip, n in tally.session_ips.most_common(10)]
    top_users = tally.users.most_common(10)
    top_pw = tally.passwords.most_common(10)
    top_cmds = tally.commands.most_common(12)

    tot = analysis["totals"]
    recent = tally.recent
    generated = now.strftime("%Y-%m-%d %H:%M UTC")
    since = (tally.first_ts or "")[:10] or "n/a"

    tiles = [
        ("Sessions", tot["sessions"], recent["sessions"]),
        ("Login attempts", tot["login_failed"] + tot["login_success"],
         recent["logins"]),
        ("Unique attacker IPs", len(tally.session_ips), len(tally.recent_ips)),
        ("Commands run", tot["commands"], recent["commands"]),
        ("Malware downloads", tally.download_count, recent["downloads"]),
        ("ATT&CK techniques", len(analysis["techniques"]), None),
    ]

    parts = []
    A = parts.append

    A(_HEAD_HTML.replace("__GENERATED__", html.escape(generated))
                .replace("__SINCE__", html.escape(since)))

    A('<div class="tiles">')
    for label, n, last24 in tiles:
        delta = ("" if last24 is None else
                 '<div class="d">+%s last 24h</div>' % format(last24, ","))
        A('<div class="tile"><div class="n">%s</div><div class="l">%s</div>%s</div>'
          % (format(n, ","), html.escape(label), delta))
    A("</div>")

    # --- ATT&CK -------------------------------------------------------------
    A("<h2>MITRE ATT&amp;CK Coverage</h2>")
    grouped = {}
    for t in analysis["techniques"]:
        grouped.setdefault(t["tactic"], []).append(t)

    if grouped:
        A('<p class="muted" style="margin-bottom:14px">%d technique(s) across '
          '%d tactic(s). <a href="cowrie-attack-layer.json">Download the '
          'ATT&amp;CK Navigator layer</a> and open it at '
          '<a href="https://mitre-attack.github.io/attack-navigator/">'
          'attack-navigator</a>.</p>'
          % (len(analysis["techniques"]), len(grouped)))
        A('<div class="tactics">')
        for tactic in mitre_map.TACTIC_ORDER:
            if tactic not in grouped:
                continue
            techs = sorted(grouped[tactic], key=lambda x: -x["count"])
            A('<div class="tac"><h3>%s <b>%d</b></h3>'
              % (html.escape(tactic), sum(t["count"] for t in techs)))
            for t in techs:
                A('<div class="tech"><span class="tct">%dx</span>'
                  '<span class="tid">%s</span><div class="tnm">%s</div>'
                  % (t["count"], html.escape(t["id"]), html.escape(t["name"])))
                if t["examples"]:
                    A('<div class="teg">%s</div>'
                      % html.escape(t["examples"][0][:70]))
                A("</div>")
            A("</div>")
        A("</div>")
    else:
        A('<p class="muted">No techniques observed yet.</p>')

    # --- Charts -------------------------------------------------------------
    A("<h2>Attack Volume</h2><div class='grid2'>")
    A('<div class="panel"><h3>Top source IPs (sessions)</h3>%s</div>'
      % bar_svg(top_ips))
    A('<div class="panel"><h3>Most-tried usernames</h3>%s</div>'
      % bar_svg(top_users, "#58a6ff"))
    A('<div class="panel"><h3>Most-tried passwords</h3>%s</div>'
      % bar_svg(top_pw, "#d29922"))
    A('<div class="panel"><h3>Most-run commands</h3>%s</div>'
      % bar_svg(top_cmds, "#3fb950"))
    A("</div>")

    # --- Malware ------------------------------------------------------------
    if tally.downloads:
        A("<h2>Malware Retrieved</h2><div class='panel scroll'><table>"
          "<tr><th>URL</th><th>SHA-256</th></tr>")
        for key, url in tally.downloads.items():
            A("<tr><td>%s</td><td>%s</td></tr>"
              % (html.escape(str(url)[:80]), html.escape(str(key)[:64])))
        A("</table></div>")

    # --- Commands -----------------------------------------------------------
    if top_cmds:
        A("<h2>Commands Executed by Attackers</h2><div class='panel scroll'>"
          "<table><tr><th>Count</th><th>Command</th>"
          "<th>Mapped technique(s)</th></tr>")
        for cmd, n in top_cmds:
            hits = mitre_map.classify_command(cmd)
            ids = ", ".join(sorted({h[0] for h in hits})) or "&mdash;"
            A("<tr><td>%d</td><td>%s</td><td>%s</td></tr>"
              % (n, html.escape(cmd[:70]), ids))
        A("</table></div>")

    A('<footer>Static snapshot generated from Cowrie\'s JSON event log. '
      'Cowrie emulates a Linux shell &mdash; attacker commands are recorded, '
      'never executed. Source and deployment automation: '
      '<a href="https://github.com/ajcyberdefense/cowrie-honeypot">'
      'github.com/ajcyberdefense/cowrie-honeypot</a>. %s</footer></div>'
      % ("Attacker IPs are partially redacted." if redact else ""))

    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Generate a static honeypot report")
    ap.add_argument("--out", default="./site", help="output directory")
    ap.add_argument("--log", help="path to cowrie.json")
    ap.add_argument("--redact", action="store_true",
                    help="mask the last octet of attacker IPs")
    args = ap.parse_args()

    log_file = mitre_map.resolve_log_file(args.log)
    now = datetime.now(timezone.utc)
    tally = Tally((now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S"))
    # ponytail: re-parses every rotation each run (~2s/day of logs on the
    # Oracle micro). Cache per-day aggregates of the immutable rotated files
    # if the hourly run gets too slow.
    analysis = mitre_map.analyze(
        log_file, events=tally.watch(mitre_map.iter_events(log_file)))
    analysis["data_since"] = tally.first_ts
    analysis["last_24h"] = dict(tally.recent, unique_ips=len(tally.recent_ips))

    # Render fully before touching disk, so a failure never leaves a
    # half-written or truncated index.html behind for the publisher to push.
    page = build_html(analysis, tally, args.redact, now)
    layer = mitre_map.build_layer(analysis, "Cowrie Honeypot")

    os.makedirs(args.out, exist_ok=True)
    written = []

    index_path = os.path.join(args.out, "index.html")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    written.append(index_path)

    layer_path = os.path.join(args.out, "cowrie-attack-layer.json")
    with open(layer_path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)
    written.append(layer_path)

    data_path = os.path.join(args.out, "data.json")
    with open(data_path, "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=2, default=str)
    written.append(data_path)

    print("Wrote:")
    for p in written:
        print("  %s (%d bytes)" % (p, os.path.getsize(p)))


if __name__ == "__main__":
    main()
