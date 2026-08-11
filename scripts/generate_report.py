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
from datetime import datetime, timezone

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


def load_events(log_file):
    events = []
    if not os.path.exists(log_file):
        print("[!] Log file not found: %s" % log_file, file=sys.stderr)
        sys.exit(1)
    with open(log_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


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


def build_html(analysis, events, redact):
    logins = [e for e in events
              if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")]
    cmds = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    downloads = [e for e in events
                 if e.get("eventid") == "cowrie.session.file_download"]

    top_ips = Counter(redact_ip(e.get("src_ip"), redact)
                      for e in logins if e.get("src_ip")).most_common(10)
    top_users = Counter(e.get("username") for e in logins
                        if e.get("username")).most_common(10)
    top_pw = Counter(e.get("password") for e in logins
                     if e.get("password")).most_common(10)
    top_cmds = Counter((e.get("input") or "").strip() for e in cmds
                       if (e.get("input") or "").strip()).most_common(12)

    tot = analysis["totals"]
    unique_ips = len({e.get("src_ip") for e in logins if e.get("src_ip")})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tiles = [
        ("Sessions", tot["sessions"]),
        ("Login attempts", tot["login_failed"] + tot["login_success"]),
        ("Unique attacker IPs", unique_ips),
        ("Commands run", tot["commands"]),
        ("Malware downloads", len(downloads)),
        ("ATT&CK techniques", len(analysis["techniques"])),
    ]

    parts = []
    A = parts.append

    A(_HEAD_HTML.replace("__GENERATED__", html.escape(generated)))

    A('<div class="tiles">')
    for label, n in tiles:
        A('<div class="tile"><div class="n">%s</div><div class="l">%s</div></div>'
          % (format(n, ","), html.escape(label)))
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
    A('<div class="panel"><h3>Top source IPs</h3>%s</div>' % bar_svg(top_ips))
    A('<div class="panel"><h3>Most-tried usernames</h3>%s</div>'
      % bar_svg(top_users, "#58a6ff"))
    A('<div class="panel"><h3>Most-tried passwords</h3>%s</div>'
      % bar_svg(top_pw, "#d29922"))
    A('<div class="panel"><h3>Most-run commands</h3>%s</div>'
      % bar_svg(top_cmds, "#3fb950"))
    A("</div>")

    # --- Malware ------------------------------------------------------------
    if downloads:
        A("<h2>Malware Retrieved</h2><div class='panel scroll'><table>"
          "<tr><th>URL</th><th>SHA-256</th></tr>")
        seen = set()
        for e in downloads:
            key = e.get("shasum", "")
            if key in seen:
                continue
            seen.add(key)
            A("<tr><td>%s</td><td>%s</td></tr>"
              % (html.escape(str(e.get("url", ""))[:80]),
                 html.escape(str(key)[:64])))
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
    analysis = mitre_map.analyze(log_file)
    events = load_events(log_file)

    # Render fully before touching disk, so a failure never leaves a
    # half-written or truncated index.html behind for the publisher to push.
    page = build_html(analysis, events, args.redact)
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
