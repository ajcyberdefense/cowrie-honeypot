#!/usr/bin/env python3
# =============================================================================
# analyze.py — Cowrie Honeypot Log Analyzer
# =============================================================================
# Parses Cowrie's JSON log and prints attack summaries.
#
# Usage (run as cowrie user from /home/cowrie/cowrie):
#   python3 ~/cowrie/analyze.py
#
# Requirements: Python 3.6+ (no extra packages needed)
# =============================================================================

import json
import os
import sys
from collections import Counter
from datetime import datetime

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
LOG_FILE = os.path.join(os.path.dirname(__file__), "../var/log/cowrie/cowrie.json")
TOP_N = 10  # How many results to show per category

# -----------------------------------------------------------------------------
# Parse the log
# -----------------------------------------------------------------------------
def parse_log(log_file):
    events = {
        "login_failed": [],
        "login_success": [],
        "commands": [],
        "downloads": [],
        "sessions": [],
    }

    if not os.path.exists(log_file):
        print(f"[!] Log file not found: {log_file}")
        print("    Make sure Cowrie has run and generated logs.")
        sys.exit(1)

    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                eid = event.get("eventid", "")

                if eid == "cowrie.login.failed":
                    events["login_failed"].append(event)

                elif eid == "cowrie.login.success":
                    events["login_success"].append(event)

                elif eid == "cowrie.command.input":
                    events["commands"].append(event)

                elif eid == "cowrie.session.file_download":
                    events["downloads"].append(event)

                elif eid == "cowrie.session.connect":
                    events["sessions"].append(event)

            except json.JSONDecodeError:
                continue

    return events


# -----------------------------------------------------------------------------
# Print helpers
# -----------------------------------------------------------------------------
def section(title):
    print(f"\n{'=' * 55}")
    print(f"  {title}")
    print(f"{'=' * 55}")

def top_n(items, label, n=TOP_N):
    counts = Counter(items).most_common(n)
    if not counts:
        print(f"  (no data yet)")
        return
    for item, count in counts:
        bar = "█" * min(count, 40)
        print(f"  {str(item):<35} {count:>5}x  {bar}")


# -----------------------------------------------------------------------------
# Main report
# -----------------------------------------------------------------------------
def main():
    log_file = os.path.abspath(LOG_FILE)
    print(f"\nCowrie Honeypot Attack Analysis")
    print(f"Log file : {log_file}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    events = parse_log(log_file)

    total_sessions    = len(events["sessions"])
    total_failed      = len(events["login_failed"])
    total_success     = len(events["login_success"])
    total_commands    = len(events["commands"])
    total_downloads   = len(events["downloads"])

    section("OVERVIEW")
    print(f"  Total sessions       : {total_sessions}")
    print(f"  Failed login attempts: {total_failed}")
    print(f"  Successful logins    : {total_success}")
    print(f"  Commands executed    : {total_commands}")
    print(f"  File downloads       : {total_downloads}")

    section(f"TOP {TOP_N} ATTACKING IPs")
    ips = [e.get("src_ip", "unknown") for e in events["login_failed"]]
    top_n(ips, "IP")

    section(f"TOP {TOP_N} USERNAMES TRIED")
    usernames = [e.get("username", "unknown") for e in events["login_failed"]]
    top_n(usernames, "Username")

    section(f"TOP {TOP_N} PASSWORDS TRIED")
    passwords = [e.get("password", "unknown") for e in events["login_failed"]]
    top_n(passwords, "Password")

    section(f"TOP {TOP_N} COMMANDS EXECUTED")
    cmds = [e.get("input", "").strip() for e in events["commands"] if e.get("input", "").strip()]
    top_n(cmds, "Command")

    if events["downloads"]:
        section(f"FILES DOWNLOADED BY ATTACKERS")
        for e in events["downloads"]:
            print(f"  URL : {e.get('url', 'unknown')}")
            print(f"  SHA : {e.get('shasum', 'unknown')}")
            print(f"  Size: {e.get('outfile', 'unknown')}")
            print()

    if events["login_success"]:
        section("SUCCESSFUL LOGINS (attacker got in!)")
        for e in events["login_success"]:
            print(f"  IP: {e.get('src_ip')}  User: {e.get('username')}  Pass: {e.get('password')}")

    print(f"\n{'=' * 55}")
    print(f"  Leave the honeypot running — real attackers")
    print(f"  typically find open SSH ports within hours.")
    print(f"{'=' * 55}\n")


if __name__ == "__main__":
    main()
