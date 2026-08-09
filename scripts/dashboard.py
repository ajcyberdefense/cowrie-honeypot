#!/usr/bin/env python3
# =============================================================================
# dashboard.py — Cowrie Honeypot Web Dashboard
# =============================================================================
# A lightweight Flask web dashboard for visualizing Cowrie attack data.
#
# Usage:
#   pip install flask
#   python3 dashboard.py                       # binds 0.0.0.0:8080
#   DASHBOARD_PORT=80 python3 dashboard.py     # needs root or CAP_NET_BIND_SERVICE
#
# Environment:
#   COWRIE_JSON_LOG  path to cowrie.json   (default: auto-detect, see below)
#   DASHBOARD_PORT   port to bind          (default: 8080)
#   DASHBOARD_HOST   interface to bind     (default: 0.0.0.0)
#
# Then open in your browser: http://YOUR_PUBLIC_IP:8080
# =============================================================================

import json
import os
from collections import Counter
from datetime import datetime
from flask import Flask, render_template_string

app = Flask(__name__)

# Checked in order when $COWRIE_JSON_LOG is not set.
DEFAULT_LOG_PATHS = [
    os.path.expanduser("~/honeypot/var/log/cowrie/cowrie.json"),
    "/home/cowrie/honeypot/var/log/cowrie/cowrie.json",
    os.path.join(os.getcwd(), "var", "log", "cowrie", "cowrie.json"),
]


def resolve_log_file():
    """$COWRIE_JSON_LOG wins; otherwise take the first layout that exists."""
    env_path = os.environ.get("COWRIE_JSON_LOG")
    if env_path:
        return env_path
    for candidate in DEFAULT_LOG_PATHS:
        if os.path.exists(candidate):
            return candidate
    return DEFAULT_LOG_PATHS[0]


LOG_FILE = resolve_log_file()
TOP_N = 10

# -----------------------------------------------------------------------------
# Log parser
# -----------------------------------------------------------------------------
def parse_log():
    data = {
        "login_failed": [],
        "login_success": [],
        "commands": [],
        "downloads": [],
        "sessions": [],
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    if not os.path.exists(LOG_FILE):
        return data

    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                eid = event.get("eventid", "")
                if eid == "cowrie.login.failed":
                    data["login_failed"].append(event)
                elif eid == "cowrie.login.success":
                    data["login_success"].append(event)
                elif eid == "cowrie.command.input":
                    data["commands"].append(event)
                elif eid == "cowrie.session.file_download":
                    data["downloads"].append(event)
                elif eid == "cowrie.session.connect":
                    data["sessions"].append(event)
            except json.JSONDecodeError:
                continue

    return data


def get_stats():
    data = parse_log()

    top_ips       = Counter(e.get("src_ip") for e in data["login_failed"]).most_common(TOP_N)
    top_users     = Counter(e.get("username") for e in data["login_failed"]).most_common(TOP_N)
    top_passwords = Counter(e.get("password") for e in data["login_failed"]).most_common(TOP_N)
    top_commands  = Counter(
        e.get("input", "").strip() for e in data["commands"] if e.get("input", "").strip()
    ).most_common(TOP_N)

    recent_attacks = []
    for e in reversed(data["login_failed"][-50:]):
        recent_attacks.append({
            "time": e.get("timestamp", "")[:19].replace("T", " "),
            "ip": e.get("src_ip", ""),
            "user": e.get("username", ""),
            "password": e.get("password", ""),
        })

    return {
        "total_sessions":   len(data["sessions"]),
        "total_failed":     len(data["login_failed"]),
        "total_success":    len(data["login_success"]),
        "total_commands":   len(data["commands"]),
        "total_downloads":  len(data["downloads"]),
        "top_ips":          top_ips,
        "top_users":        top_users,
        "top_passwords":    top_passwords,
        "top_commands":     top_commands,
        # recent_attacks was built newest-first above; reversing it again here
        # would surface the OLDEST 20 of the last 50, not the newest 20.
        "recent_attacks":   recent_attacks[:20],
        "last_updated":     data["last_updated"],
        "unique_ips":       len(
            {e.get("src_ip") for e in data["login_failed"] + data["login_success"]}
        ),
    }


# -----------------------------------------------------------------------------
# HTML Template
# -----------------------------------------------------------------------------
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="30">
  <title>Cowrie Honeypot Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117;
      color: #e6edf3;
      min-height: 100vh;
    }
    header {
      background: #161b22;
      border-bottom: 1px solid #30363d;
      padding: 16px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    header h1 { font-size: 1.3rem; color: #58a6ff; letter-spacing: 1px; }
    header .subtitle { font-size: 0.8rem; color: #8b949e; }
    .updated { font-size: 0.75rem; color: #8b949e; }

    .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }

    /* Stat cards */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .stat-card .number {
      font-size: 2.2rem;
      font-weight: 700;
      color: #58a6ff;
    }
    .stat-card.danger .number { color: #f85149; }
    .stat-card.success .number { color: #3fb950; }
    .stat-card.warn .number { color: #d29922; }
    .stat-card .label {
      font-size: 0.78rem;
      color: #8b949e;
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* Charts row */
    .charts-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 28px;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
    }
    .card h2 {
      font-size: 0.9rem;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 16px;
      border-bottom: 1px solid #30363d;
      padding-bottom: 10px;
    }
    .chart-container { position: relative; height: 220px; }

    /* Tables */
    .tables-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 28px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th {
      text-align: left;
      color: #8b949e;
      font-size: 0.75rem;
      text-transform: uppercase;
      padding: 6px 8px;
      border-bottom: 1px solid #30363d;
    }
    td { padding: 8px; border-bottom: 1px solid #21262d; }
    tr:last-child td { border-bottom: none; }
    td:last-child { color: #58a6ff; font-weight: 600; text-align: right; }
    .bar-cell { display: flex; align-items: center; gap: 8px; }
    .bar {
      height: 6px;
      background: #58a6ff;
      border-radius: 3px;
      min-width: 4px;
    }

    /* Recent attacks */
    .recent-table td:last-child { color: #e6edf3; font-weight: normal; text-align: left; }
    .ip-cell { color: #f85149 !important; font-family: monospace; }
    .time-cell { color: #8b949e !important; font-size: 0.78rem; }

    /* Live indicator */
    .live-dot {
      display: inline-block;
      width: 8px; height: 8px;
      background: #3fb950;
      border-radius: 50%;
      margin-right: 6px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }

    @media (max-width: 768px) {
      .charts-grid, .tables-grid { grid-template-columns: 1fr; }
      .container { padding: 16px; }
    }
  </style>
</head>
<body>

<header>
  <div>
    <h1>🍯 Cowrie Honeypot Dashboard</h1>
    <div class="subtitle">AWS EC2 · Real-time SSH/Telnet Attack Monitor</div>
  </div>
  <div class="updated">
    <span class="live-dot"></span>
    Last updated: {{ stats.last_updated }} &nbsp;·&nbsp; Auto-refreshes every 30s
  </div>
</header>

<div class="container">

  <!-- Stat Cards -->
  <div class="stats-grid">
    <div class="stat-card danger">
      <div class="number">{{ stats.total_failed }}</div>
      <div class="label">Login Attempts</div>
    </div>
    <div class="stat-card">
      <div class="number">{{ stats.unique_ips }}</div>
      <div class="label">Unique Attackers</div>
    </div>
    <div class="stat-card">
      <div class="number">{{ stats.total_sessions }}</div>
      <div class="label">Total Sessions</div>
    </div>
    <div class="stat-card warn">
      <div class="number">{{ stats.total_commands }}</div>
      <div class="label">Commands Run</div>
    </div>
    <div class="stat-card warn">
      <div class="number">{{ stats.total_downloads }}</div>
      <div class="label">File Downloads</div>
    </div>
    <div class="stat-card success">
      <div class="number">{{ stats.total_success }}</div>
      <div class="label">Successful Logins</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts-grid">
    <div class="card">
      <h2>Top Attacking IPs</h2>
      <div class="chart-container">
        <canvas id="ipChart"></canvas>
      </div>
    </div>
    <div class="card">
      <h2>Top Usernames Tried</h2>
      <div class="chart-container">
        <canvas id="userChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Tables -->
  <div class="tables-grid">
    <div class="card">
      <h2>Top Passwords Tried</h2>
      <table>
        <tr><th>Password</th><th>Count</th></tr>
        {% set max_p = stats.top_passwords[0][1] if stats.top_passwords else 1 %}
        {% for pw, count in stats.top_passwords %}
        <tr>
          <td>
            <div class="bar-cell">
              <div class="bar" style="width:{{ (count / max_p * 120)|int }}px"></div>
              {{ pw or '(empty)' }}
            </div>
          </td>
          <td>{{ count }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
    <div class="card">
      <h2>Top Commands Executed</h2>
      <table>
        <tr><th>Command</th><th>Count</th></tr>
        {% set max_c = stats.top_commands[0][1] if stats.top_commands else 1 %}
        {% for cmd, count in stats.top_commands %}
        <tr>
          <td>
            <div class="bar-cell">
              <div class="bar" style="width:{{ (count / max_c * 120)|int }}px; background:#d29922"></div>
              <code style="font-size:0.8rem">{{ cmd[:40] }}</code>
            </div>
          </td>
          <td>{{ count }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <!-- Recent Attacks -->
  <div class="card">
    <h2>Recent Login Attempts (last 20)</h2>
    <table class="recent-table">
      <tr>
        <th>Time</th>
        <th>IP Address</th>
        <th>Username</th>
        <th>Password</th>
      </tr>
      {% for a in stats.recent_attacks %}
      <tr>
        <td class="time-cell">{{ a.time }}</td>
        <td class="ip-cell">{{ a.ip }}</td>
        <td>{{ a.user }}</td>
        <td>{{ a.password }}</td>
      </tr>
      {% endfor %}
      {% if not stats.recent_attacks %}
      <tr><td colspan="4" style="color:#8b949e; text-align:center; padding:20px">
        No attacks logged yet — check back soon!
      </td></tr>
      {% endif %}
    </table>
  </div>

</div><!-- /container -->

<script>
const chartDefaults = {
  plugins: { legend: { display: false } },
  scales: {
    x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
    y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
  }
};

// IP Chart
new Chart(document.getElementById('ipChart'), {
  type: 'bar',
  data: {
    labels: {{ stats.top_ips | map(attribute=0) | list | tojson }},
    datasets: [{
      data:  {{ stats.top_ips | map(attribute=1) | list | tojson }},
      backgroundColor: '#f85149aa',
      borderColor: '#f85149',
      borderWidth: 1,
      borderRadius: 4,
    }]
  },
  options: chartDefaults
});

// Username Chart
new Chart(document.getElementById('userChart'), {
  type: 'bar',
  data: {
    labels: {{ stats.top_users | map(attribute=0) | list | tojson }},
    datasets: [{
      data:  {{ stats.top_users | map(attribute=1) | list | tojson }},
      backgroundColor: '#58a6ffaa',
      borderColor: '#58a6ff',
      borderWidth: 1,
      borderRadius: 4,
    }]
  },
  options: chartDefaults
});
</script>

</body>
</html>
"""

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    stats = get_stats()
    return render_template_string(TEMPLATE, stats=stats)


@app.route("/api/stats")
def api_stats():
    """JSON endpoint for raw stats."""
    stats = get_stats()
    return {
        "total_sessions":  stats["total_sessions"],
        "total_failed":    stats["total_failed"],
        "total_success":   stats["total_success"],
        "total_commands":  stats["total_commands"],
        "unique_ips":      stats["unique_ips"],
        "top_ips":         stats["top_ips"],
        "top_users":       stats["top_users"],
        "top_passwords":   stats["top_passwords"],
        "last_updated":    stats["last_updated"],
    }


if __name__ == "__main__":
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("DASHBOARD_PORT", "8080"))

    print("\n  Cowrie Dashboard starting...")
    print(f"  Reading log : {LOG_FILE}")
    if not os.path.exists(LOG_FILE):
        print("  WARNING     : log file does not exist yet — stats will be empty.")
    print(f"  Listening on: http://{host}:{port}")
    print("  Press Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=False)
