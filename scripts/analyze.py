#!/usr/bin/env python3
# =============================================================================
# analyze.py — Cowrie Honeypot Log Analyzer
# =============================================================================
# Parses Cowrie's JSON log and prints an attack summary.
#
# Usage:
#   python3 analyze.py                    # auto-detect the log
#   python3 analyze.py /path/to/cowrie.json
#   COWRIE_JSON_LOG=/path/to/cowrie.json python3 analyze.py
#
# Requirements: Python 3.6+ (no extra packages needed)
# =============================================================================

import json
import os
import sys
from collections import Counter
from datetime import datetime

TOP_N = 10  # How many results to show per category

# Checked in order when neither $COWRIE_JSON_LOG nor argv[1] is given.
DEFAULT_LOG_PATHS = [
    os.path.expanduser("~/honeypot/var/log/cowrie/cowrie.json"),
    os.path.join(os.getcwd(), "var", "log", "cowrie", "cowrie.json"),
    "/home/cowrie/honeypot/var/log/cowrie/cowrie.json",
]


# -----------------------------------------------------------------------------
# Locate the log
# -----------------------------------------------------------------------------
def resolve_log_file(argv):
    """Explicit argument wins, then $COWRIE_JSON_LOG, then the known layouts.

    An explicit path is returned even when it does not exist, so the error
    message names the file the user actually asked for.
    """
    if len(argv) > 1:
        return argv[1]

    env_path = os.environ.get("COWRIE_JSON_LOG")
    if env_path:
        return env_path

    for candidate in DEFAULT_LOG_PATHS:
        if os.path.exists(candidate):
            return candidate

    return DEFAULT_LOG_PATHS[0]


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
        print(f"\n[!] Log file not found: {log_file}")
        print("    Set the path explicitly if the honeypot lives elsewhere:")
        print("      COWRIE_JSON_LOG=/path/to/cowrie.json python3 analyze.py")
        sys.exit(1)

    interesting = {
        "cowrie.login.failed": "login_failed",
        "cowrie.login.success": "login_success",
        "cowrie.command.input": "commands",
        "cowrie.session.file_download": "downloads",
        "cowrie.session.connect": "sessions",
    }

    with open(log_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Cowrie can be mid-write on the last line; skip partial records.
                continue

            bucket = interesting.get(event.get("eventid", ""))
            if bucket:
                events[bucket].append(event)

    return events


# -----------------------------------------------------------------------------
# Print helpers
# -----------------------------------------------------------------------------
def section(title):
    print(f"\n{'=' * 55}")
    print(f"  {title}")
    print(f"{'=' * 55}")


def top_n(items, n=TOP_N):
    counts = Counter(i for i in items if i).most_common(n)
    if not counts:
        print("  (no data yet)")
        return
    # Scale bars to the largest value so one huge outlier doesn't flatten the rest.
    peak = counts[0][1]
    for item, count in counts:
        bar = "#" * max(1, int(30 * count / peak))
        print(f"  {str(item)[:35]:<35} {count:>5}x  {bar}")


# -----------------------------------------------------------------------------
# Main report
# -----------------------------------------------------------------------------
def main():
    log_file = os.path.abspath(resolve_log_file(sys.argv))

    print("\nCowrie Honeypot Attack Analysis")
    print(f"Log file : {log_file}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    events = parse_log(log_file)

    section("OVERVIEW")
    print(f"  Total sessions       : {len(events['sessions'])}")
    print(f"  Failed login attempts: {len(events['login_failed'])}")
    print(f"  Successful logins    : {len(events['login_success'])}")
    print(f"  Commands executed    : {len(events['commands'])}")
    print(f"  File downloads       : {len(events['downloads'])}")

    # Count attackers across every login attempt, not just the failures.
    all_logins = events["login_failed"] + events["login_success"]
    print(f"  Unique source IPs    : {len({e.get('src_ip') for e in all_logins})}")

    section(f"TOP {TOP_N} ATTACKING IPs")
    top_n([e.get("src_ip") for e in all_logins])

    section(f"TOP {TOP_N} USERNAMES TRIED")
    top_n([e.get("username") for e in all_logins])

    section(f"TOP {TOP_N} PASSWORDS TRIED")
    top_n([e.get("password") for e in all_logins])

    section(f"TOP {TOP_N} COMMANDS EXECUTED")
    top_n([e.get("input", "").strip() for e in events["commands"]])

    if events["downloads"]:
        section("FILES DOWNLOADED BY ATTACKERS")
        for e in events["downloads"]:
            print(f"  URL     : {e.get('url', 'unknown')}")
            print(f"  SHA-256 : {e.get('shasum', 'unknown')}")
            print(f"  Saved to: {e.get('outfile', 'unknown')}")
            print()

    if events["login_success"]:
        section("SUCCESSFUL LOGINS (attacker got a shell)")
        for e in events["login_success"]:
            print(
                f"  {e.get('timestamp', '')[:19]}  {e.get('src_ip'):<15} "
                f"{e.get('username')}/{e.get('password')}"
            )

    print(f"\n{'=' * 55}")
    print("  Leave the honeypot running — real scanners")
    print("  typically find an open SSH port within hours.")
    print(f"{'=' * 55}\n")


if __name__ == "__main__":
    main()
