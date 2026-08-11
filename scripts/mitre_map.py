#!/usr/bin/env python3
# =============================================================================
# mitre_map.py — Map Cowrie events to MITRE ATT&CK techniques
# =============================================================================
# Turns raw honeypot events into ATT&CK coverage: which techniques attackers
# actually used against you, how often, and with what commands.
#
# Usage:
#   python3 mitre_map.py                       # terminal report
#   python3 mitre_map.py --layer out.json      # ATT&CK Navigator layer
#   python3 mitre_map.py --json                # machine-readable
#   COWRIE_JSON_LOG=/path/to/cowrie.json python3 mitre_map.py
#
# Load a generated layer at https://mitre-attack.github.io/attack-navigator/
# via "Open Existing Layer -> Upload from local".
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

ATTACK_VERSION = "14"

DEFAULT_LOG_PATHS = [
    os.path.expanduser("~/honeypot/var/log/cowrie/cowrie.json"),
    "/home/cowrie/honeypot/var/log/cowrie/cowrie.json",
    os.path.join(os.getcwd(), "var", "log", "cowrie", "cowrie.json"),
]

# -----------------------------------------------------------------------------
# Technique table
# -----------------------------------------------------------------------------
# (pattern, technique_id, technique_name, tactic)
#
# Patterns run against the raw command line, case-insensitively. Order does not
# matter — every pattern that matches is recorded, because one command can
# legitimately represent several techniques (`wget x && chmod +x x` is both
# Ingress Tool Transfer and a permissions change).
COMMAND_TECHNIQUES = [
    # --- Discovery ----------------------------------------------------------
    (r"\buname\b|/proc/version|\blsb_release\b|\bhostnamectl\b|/etc/issue",
     "T1082", "System Information Discovery", "Discovery"),
    (r"/proc/cpuinfo|\blscpu\b|\bnproc\b|/proc/meminfo|\bfree\s|\bdf\s|\blsblk\b",
     "T1082", "System Information Discovery", "Discovery"),
    (r"\bwhoami\b|\bid\b\s*$|\bgroups\b|\blogname\b",
     "T1033", "System Owner/User Discovery", "Discovery"),
    (r"\bps\b|\btop\b|\bpidof\b|\bhtop\b|/proc/\d+",
     "T1057", "Process Discovery", "Discovery"),
    (r"\bifconfig\b|\bip\s+a(ddr)?\b|\bnetstat\b|\bss\s+-|\broute\b|/etc/resolv\.conf",
     "T1016", "System Network Configuration Discovery", "Discovery"),
    (r"\bw\b\s*$|\bwho\b\s*$|\blast\b|\butmp\b",
     "T1033", "System Owner/User Discovery", "Discovery"),
    (r"\bls\b|\bfind\b|\bpwd\b|\bdu\b\s",
     "T1083", "File and Directory Discovery", "Discovery"),
    (r"/etc/passwd",
     "T1087.001", "Account Discovery: Local Account", "Discovery"),
    (r"\barp\b|\bping\s+-c|\bnmap\b|\bmasscan\b",
     "T1018", "Remote System Discovery", "Discovery"),
    (r"\bcrontab\s+-l\b",
     "T1057", "Process Discovery", "Discovery"),

    # --- Credential Access --------------------------------------------------
    (r"/etc/shadow",
     "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "Credential Access"),
    (r"\.ssh/id_[rd]sa|\.ssh/id_ed25519|\bknown_hosts\b|\.pem\b",
     "T1552.004", "Unsecured Credentials: Private Keys", "Credential Access"),
    (r"\bhistory\b\s*$|\.bash_history",
     "T1552.003", "Unsecured Credentials: Bash History", "Credential Access"),

    # --- Command and Control / Ingress --------------------------------------
    (r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\bscp\b\s|\brsync\b",
     "T1105", "Ingress Tool Transfer", "Command and Control"),
    (r"\bnc\b\s|\bnetcat\b|\bncat\b|/dev/tcp/|/dev/udp/",
     "T1095", "Non-Application Layer Protocol", "Command and Control"),

    # --- Execution ----------------------------------------------------------
    (r"\b(ba)?sh\s+-c\b|\b/bin/(ba)?sh\b|\bperl\s+-e\b|\bpython3?\s+-c\b",
     "T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution"),
    (r"\bnohup\b|\bsetsid\b|\bscreen\s+-|\btmux\b|&\s*$",
     "T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution"),

    # --- Persistence --------------------------------------------------------
    (r"\bcrontab\b\s+(-e|[^-])|/etc/cron|@reboot",
     "T1053.003", "Scheduled Task/Job: Cron", "Persistence"),
    (r"authorized_keys|\bssh-keygen\b",
     "T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence"),
    (r"/etc/rc\.local|\bsystemctl\s+enable\b|\.bashrc|\.profile|/etc/init\.d",
     "T1037", "Boot or Logon Initialization Scripts", "Persistence"),
    (r"\buseradd\b|\badduser\b|\busermod\b",
     "T1136.001", "Create Account: Local Account", "Persistence"),

    # --- Defense Evasion ----------------------------------------------------
    (r"history\s+-c|unset\s+HISTFILE|HISTFILE=|rm\s+.*bash_history",
     "T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion"),
    (r"rm\s+-rf?\s+/var/log|>\s*/var/log|\btruncate\b.*log",
     "T1070.002", "Indicator Removal: Clear Linux or Mac System Logs",
     "Defense Evasion"),
    (r"\bchmod\b|\bchown\b|\bchattr\b",
     "T1222.002", "File and Directory Permissions Modification: Linux and Mac",
     "Defense Evasion"),
    (r"base64\s+-d|\bbase64\b\s+--decode|\bxxd\b|\buudecode\b|\bopenssl\s+enc\b",
     "T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    (r"\biptables\s+-F\b|\bufw\s+disable\b|\bsetenforce\s+0\b|selinux",
     "T1562.004", "Impair Defenses: Disable or Modify System Firewall",
     "Defense Evasion"),
    (r"\bkillall\b|\bpkill\b.*(clam|av|defend|falcon|osquery)",
     "T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    (r"\brm\s+-rf?\b.*(/tmp/|\./)",
     "T1070.004", "Indicator Removal: File Deletion", "Defense Evasion"),

    # --- Impact -------------------------------------------------------------
    (r"\bxmrig\b|\bminerd\b|cryptonight|stratum\+tcp|\bcpuminer\b|monero|\bnanopool\b",
     "T1496", "Resource Hijacking", "Impact"),
    (r"\bpkill\b|\bkill\s+-9\b|\bservice\s+\w+\s+stop\b|\bsystemctl\s+stop\b",
     "T1489", "Service Stop", "Impact"),
    (r"rm\s+-rf\s+/(\s|$)|\bmkfs\b|\bdd\s+if=/dev/zero",
     "T1485", "Data Destruction", "Impact"),

    # --- Lateral Movement ---------------------------------------------------
    (r"\bssh\b\s+\w+@|\bsshpass\b",
     "T1021.004", "Remote Services: SSH", "Lateral Movement"),
]

# Techniques inferred from event types rather than command text.
LOGIN_FAILED_TECHNIQUE = (
    "T1110.001", "Brute Force: Password Guessing", "Credential Access")
LOGIN_SUCCESS_TECHNIQUE = (
    "T1078", "Valid Accounts", "Initial Access")

_COMPILED = [(re.compile(p, re.IGNORECASE), t, n, tac)
             for p, t, n, tac in COMMAND_TECHNIQUES]

# Tactic ordering follows the ATT&CK enterprise kill chain.
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


# -----------------------------------------------------------------------------
# Core
# -----------------------------------------------------------------------------
def classify_command(command):
    """Return every (technique_id, name, tactic) a command matches."""
    hits = []
    for rx, tid, name, tactic in _COMPILED:
        if rx.search(command):
            hits.append((tid, name, tactic))
    return hits


def resolve_log_file(explicit=None):
    if explicit:
        return explicit
    env_path = os.environ.get("COWRIE_JSON_LOG")
    if env_path:
        return env_path
    for candidate in DEFAULT_LOG_PATHS:
        if os.path.exists(candidate):
            return candidate
    return DEFAULT_LOG_PATHS[0]


def analyze(log_file):
    """Walk the Cowrie JSON log and accumulate per-technique evidence."""
    techniques = defaultdict(lambda: {
        "id": "", "name": "", "tactic": "",
        "count": 0, "src_ips": set(), "examples": [], "first": None, "last": None,
    })
    totals = {"commands": 0, "login_failed": 0, "login_success": 0, "sessions": 0}
    unmapped = defaultdict(int)

    def record(tid, name, tactic, src_ip, ts, example=None):
        t = techniques[tid]
        t["id"], t["name"], t["tactic"] = tid, name, tactic
        t["count"] += 1
        if src_ip:
            t["src_ips"].add(src_ip)
        if ts:
            t["first"] = min(t["first"], ts) if t["first"] else ts
            t["last"] = max(t["last"], ts) if t["last"] else ts
        if example and len(t["examples"]) < 5 and example not in t["examples"]:
            t["examples"].append(example)

    if not os.path.exists(log_file):
        print(f"\n[!] Log file not found: {log_file}", file=sys.stderr)
        print("    COWRIE_JSON_LOG=/path/to/cowrie.json python3 mitre_map.py",
              file=sys.stderr)
        sys.exit(1)

    with open(log_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # partial trailing write

            eid = event.get("eventid", "")
            src = event.get("src_ip")
            ts = event.get("timestamp")

            if eid == "cowrie.session.connect":
                totals["sessions"] += 1

            elif eid == "cowrie.login.failed":
                totals["login_failed"] += 1
                record(*LOGIN_FAILED_TECHNIQUE, src, ts,
                       "%s / %s" % (event.get("username"), event.get("password")))

            elif eid == "cowrie.login.success":
                totals["login_success"] += 1
                record(*LOGIN_SUCCESS_TECHNIQUE, src, ts,
                       "%s / %s" % (event.get("username"), event.get("password")))

            elif eid == "cowrie.command.input":
                cmd = (event.get("input") or "").strip()
                if not cmd:
                    continue
                totals["commands"] += 1
                hits = classify_command(cmd)
                if hits:
                    for tid, name, tactic in hits:
                        record(tid, name, tactic, src, ts, cmd[:120])
                else:
                    unmapped[cmd[:120]] += 1

            elif eid == "cowrie.session.file_download":
                record("T1105", "Ingress Tool Transfer", "Command and Control",
                       src, ts, event.get("url", "")[:120])

    # Sets are not JSON-serializable and callers want a count anyway.
    for t in techniques.values():
        t["unique_ips"] = len(t["src_ips"])
        del t["src_ips"]

    return {
        "log_file": os.path.abspath(log_file),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "totals": totals,
        "techniques": sorted(
            techniques.values(),
            key=lambda t: (-t["count"], t["id"]),
        ),
        "unmapped": sorted(unmapped.items(), key=lambda kv: -kv[1])[:20],
    }


# -----------------------------------------------------------------------------
# ATT&CK Navigator layer
# -----------------------------------------------------------------------------
def build_layer(result, name="Cowrie Honeypot"):
    """Emit a Navigator v4.5 layer. Score = observation count per technique."""
    techs = result["techniques"]
    max_count = max((t["count"] for t in techs), default=1)

    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION, "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Techniques observed against a Cowrie SSH/Telnet honeypot. "
            "Score is the number of times each technique was observed. "
            "Generated %s" % result["generated"]
        ),
        "filters": {"platforms": ["Linux"]},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": True,
        "techniques": [
            {
                "techniqueID": t["id"],
                "score": t["count"],
                "enabled": True,
                "comment": "%s observation(s) from %d unique IP(s). e.g. %s"
                           % (t["count"], t["unique_ips"],
                              t["examples"][0] if t["examples"] else "n/a"),
                "metadata": [
                    {"name": "tactic", "value": t["tactic"]},
                    {"name": "unique source IPs", "value": str(t["unique_ips"])},
                    {"name": "first seen", "value": str(t["first"])[:19]},
                    {"name": "last seen", "value": str(t["last"])[:19]},
                ],
            }
            for t in techs
        ],
        "gradient": {
            "colors": ["#ffe766", "#ff8c42", "#f85149"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [
            {"label": "observed on this honeypot", "color": "#f85149"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#21262d",
        "selectTechniquesAcrossTactics": True,
    }


# -----------------------------------------------------------------------------
# Terminal report
# -----------------------------------------------------------------------------
def print_report(result):
    print("\nMITRE ATT&CK Mapping — Cowrie Honeypot")
    print("Log file : %s" % result["log_file"])
    print("Generated: %s" % result["generated"])

    tot = result["totals"]
    print("\n" + "=" * 68)
    print("  OVERVIEW")
    print("=" * 68)
    print("  Sessions           : %d" % tot["sessions"])
    print("  Failed logins      : %d" % tot["login_failed"])
    print("  Successful logins  : %d" % tot["login_success"])
    print("  Commands executed  : %d" % tot["commands"])
    print("  Techniques observed: %d" % len(result["techniques"]))

    by_tactic = defaultdict(list)
    for t in result["techniques"]:
        by_tactic[t["tactic"]].append(t)

    for tactic in TACTIC_ORDER:
        if tactic not in by_tactic:
            continue
        print("\n" + "=" * 68)
        print("  %s" % tactic.upper())
        print("=" * 68)
        for t in sorted(by_tactic[tactic], key=lambda x: -x["count"]):
            print("  %-12s %-52s %4dx" % (t["id"], t["name"][:52], t["count"]))
            if t["examples"]:
                print("               e.g. %s" % t["examples"][0][:60])

    if result["unmapped"]:
        print("\n" + "=" * 68)
        print("  UNMAPPED COMMANDS (candidates for new rules)")
        print("=" * 68)
        for cmd, n in result["unmapped"][:10]:
            print("  %4dx  %s" % (n, cmd[:60]))

    print()


def main():
    ap = argparse.ArgumentParser(description="Map Cowrie events to MITRE ATT&CK")
    ap.add_argument("log", nargs="?", help="path to cowrie.json")
    ap.add_argument("--layer", metavar="FILE",
                    help="write an ATT&CK Navigator layer to FILE")
    ap.add_argument("--json", action="store_true",
                    help="print the analysis as JSON")
    ap.add_argument("--name", default="Cowrie Honeypot", help="layer name")
    args = ap.parse_args()

    result = analyze(resolve_log_file(args.log))

    if args.layer:
        with open(args.layer, "w", encoding="utf-8") as fh:
            json.dump(build_layer(result, args.name), fh, indent=2)
        print("Wrote ATT&CK Navigator layer: %s" % os.path.abspath(args.layer))
        print("Load it at https://mitre-attack.github.io/attack-navigator/")
        print("  -> Open Existing Layer -> Upload from local")

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    elif not args.layer:
        print_report(result)


if __name__ == "__main__":
    main()
