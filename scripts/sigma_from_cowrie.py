#!/usr/bin/env python3
# =============================================================================
# sigma_from_cowrie.py — Turn recurring Cowrie attack chains into Sigma rules
# =============================================================================
# Every command in cowrie.json is known malicious, so it is a labeled dataset.
# This script holds a small table of detections, measures each one against the
# full log history (live log + daily rotations), and writes one Sigma rule per
# file into detections/, each annotated with how often it fired and the first
# session that motivated it.
#
# Usage:
#   python3 sigma_from_cowrie.py                  # scan, print, write rules
#   python3 sigma_from_cowrie.py --dry-run        # scan and print only
#   python3 sigma_from_cowrie.py /path/to/cowrie.json --out detections
#   COWRIE_JSON_LOG=/path/to/cowrie.json python3 sigma_from_cowrie.py
#
# The table below is the source of truth. Edit it and re-run; the YAML files
# are generated output.
#
# Requirements: Python 3.6+, no third-party packages.
# =============================================================================

import argparse
import os
import re
import sys
import uuid
from collections import defaultdict

from mitre_map import iter_events, resolve_log_file

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UUID_NS = uuid.UUID("6f1c1a52-6e0b-4c5e-9d7a-0c0ffee0c0de")
SESSION_LINES = 15      # commands kept from the motivating session
LINE_WIDTH = 160        # truncate long commands in the comment block

# -----------------------------------------------------------------------------
# Detections
# -----------------------------------------------------------------------------
# Each regex runs against one cowrie.command.input line (the `input` field),
# exactly as the generated Sigma rule's `input|re` will. Prefix (?i) for
# case-insensitive; Sigma regex is case-sensitive by default.
DETECTIONS = [
    {
        "name": "download_execute_chain",
        "title": "Download, Make Executable, and Run in One Command Line",
        "level": "high",
        "regex": r"(?i)\b(wget|curl|tftp|ftpget)\b.*\bchmod\s+(\+x|[0-7]?[0-7][0-7]7)\b.*(\./|\bsh\s+\S)",
        "tags": ["attack.command_and_control", "attack.t1105",
                 "attack.execution", "attack.t1059.004",
                 "attack.defense_evasion", "attack.t1222.002"],
        "description": "Fetches a file, sets it executable, and runs it in a single "
                       "line. This is the chokepoint of nearly every IoT botnet "
                       "infection: recon is optional, this step is not.",
        "falsepositives": [
            "Install one-liners that download a script, chmod it, and run it "
            "(rare in an interactive admin session, common in provisioning; "
            "scope by parent process or user if it fires on CI hosts)",
        ],
    },
    {
        "name": "pipe_to_shell",
        "title": "Remote Script Piped Straight Into a Shell",
        "level": "medium",
        "regex": r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(ba)?sh\b|\b(ba)?sh\s+<\(\s*(curl|wget)\b",
        "tags": ["attack.command_and_control", "attack.t1105",
                 "attack.execution", "attack.t1059.004"],
        "description": "Executes a remote script without it ever touching disk "
                       "as a file, which defeats file-based scanning.",
        "falsepositives": [
            "Vendor install instructions (rustup, Homebrew, Docker convenience "
            "script, nvm). An admin really does type these — tune with an "
            "allowlist of known installer domains rather than dropping the rule",
        ],
    },
    {
        "name": "busybox_applet_marker",
        "title": "BusyBox Called With an Uppercase Nonexistent Applet",
        "level": "high",
        "regex": r"/bin/busybox\s+[A-Z]{4,}\b",
        "tags": ["attack.discovery", "attack.t1082"],
        "description": "Mirai-family loaders run `/bin/busybox <TAG>` and look for "
                       "'<TAG>: applet not found' to confirm a real BusyBox shell. "
                       "The tag doubles as the botnet's name (BOTNET, HISILICON, "
                       "ECCHI, LZRD, UNSTABLE).",
        "falsepositives": [
            "None expected — BusyBox applets are lowercase and no admin types "
            "an uppercase one on purpose",
        ],
    },
    {
        "name": "hex_echo_marker",
        "title": "Hex-Escaped echo Used as a Shell Liveness Marker",
        "level": "high",
        # \x5c is a literal backslash: matches echo -e '\x47\x41\x59...'
        "regex": r"(?i)echo\s+-e\s+['\"]?(\x5cx[0-9a-f]{2}){4,}",
        "tags": ["attack.discovery", "attack.t1082",
                 "attack.defense_evasion", "attack.t1027"],
        "description": "Bots echo a hex-escaped string and check that the decoded "
                       "text comes back, proving a real shell that interprets "
                       "escapes. Encoding keeps the marker out of naive string "
                       "matches (\\x47\\x41\\x59\\x46\\x47\\x54 = GAYFGT, the Gafgyt tag).",
        "falsepositives": [
            "Scripts printing binary bytes or byte-exact test data with echo -e. "
            "ANSI color codes do not match: they are single \\x1b escapes, not "
            "runs of four or more",
        ],
    },
    {
        "name": "writable_dir_probe",
        "title": "Create and Execute an Empty File to Find a Usable Directory",
        "level": "high",
        "regex": r">\s*/\S+\s*&&\s*(chmod\s+777\s+/\S+\s*&&\s*/\S+|sh\s+/\S+)",
        "tags": ["attack.discovery", "attack.t1083",
                 "attack.defense_evasion", "attack.t1222.002"],
        "description": "Loader walks /tmp, /var, /dev/shm, /mnt ... truncating a "
                       "file and executing it (chmod 777 + run, or sh), to find a "
                       "directory that "
                       "is both writable and not mounted noexec before dropping "
                       "the payload.",
        "falsepositives": [
            "None expected — executing a freshly truncated empty file has no "
            "administrative purpose",
        ],
    },
    {
        "name": "elf_self_read",
        "title": "Reading a Binary's Own Bytes to Learn the CPU Architecture",
        "level": "high",
        "regex": r"cat\s+/proc/self/exe|busybox\s+cat\s+/bin/(echo|busybox)\b|done\s*<\s*/bin/busybox",
        "tags": ["attack.discovery", "attack.t1082"],
        "description": "Dumps an ELF binary to the terminal so the loader can parse "
                       "its header and pick the matching payload (arm, mips, x86). "
                       "Used instead of `uname -m`, which can be faked.",
        "falsepositives": [
            "Nobody cats a binary to a terminal on purpose; a mistyped "
            "`cat /bin/...` is the only realistic benign case",
        ],
    },
    {
        "name": "ssh_key_implant",
        "title": "SSH Key Written to authorized_keys With Attribute Tampering",
        "level": "high",
        "regex": r"(?i)ssh-(rsa|ed25519|dss)\s+\S+.*>>?\s*\S*authorized_keys|chattr\s+-ia\s+\S*\.ssh|\block(r)?\s+-ia\s+\S*\.ssh",
        "tags": ["attack.persistence", "attack.t1098.004",
                 "attack.defense_evasion", "attack.t1222.002"],
        "description": "Replaces authorized_keys with the attacker's key and uses "
                       "chattr to strip (then often re-add) the immutable flag so "
                       "the owner cannot remove it. Includes the long-running "
                       "'mdrfckr' campaign.",
        "falsepositives": [
            "An admin appending their own key with echo >> authorized_keys "
            "will match the first branch. The chattr -ia branch alone is rare "
            "and a stronger signal; split the rule if the echo branch is noisy",
        ],
    },
    {
        "name": "competitor_cleanup",
        "title": "Killing Rival Malware and Wiping hosts.deny",
        "level": "high",
        "regex": r"echo\s*>\s*/etc/hosts\.deny|pkill\s+-9\s+(secure|auth)\.sh",
        "tags": ["attack.defense_evasion", "attack.t1562.001",
                 "attack.impact", "attack.t1489"],
        "description": "Empties hosts.deny (undoing brute-force lockouts) and kills "
                       "scripts left by competing botnets so this one owns the box.",
        "falsepositives": [
            "Clearing hosts.deny by hand after locking yourself out — possible "
            "but rare, and worth a look anyway",
        ],
    },
    {
        "name": "passwd_read",
        "title": "Reading /etc/passwd",
        "level": "low",
        "regex": r"\bcat\s+/etc/passwd\b",
        "tags": ["attack.discovery", "attack.t1087.001"],
        "description": "Local account enumeration. Included to measure it, not "
                       "because it is a good signal.",
        "falsepositives": [
            "Constant — admins, scripts, and config management read /etc/passwd "
            "all day. Use only as context alongside a higher-level rule",
        ],
    },
]

_COMPILED = [(d, re.compile(d["regex"])) for d in DETECTIONS]


# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------
def scan(events):
    """Count sessions and source IPs per detection, and keep each detection's
    first matching session with its full command list."""
    src = {}
    commands = defaultdict(list)          # session -> [input, ...]
    hits = {d["name"]: {"sessions": set(), "ips": set(), "first": None}
            for d in DETECTIONS}

    for e in events:
        sid = e.get("session")
        eid = e.get("eventid")
        if eid == "cowrie.session.connect":
            src[sid] = e.get("src_ip")
        elif eid == "cowrie.command.input":
            line = e.get("input", "")
            commands[sid].append(line)
            for d, rx in _COMPILED:
                if rx.search(line):
                    h = hits[d["name"]]
                    h["sessions"].add(sid)
                    h["ips"].add(e.get("src_ip") or src.get(sid))
                    if h["first"] is None:
                        h["first"] = {"session": sid, "match": line,
                                      "src_ip": e.get("src_ip") or src.get(sid),
                                      "timestamp": e.get("timestamp", "")}

    for h in hits.values():
        if h["first"]:
            h["first"]["commands"] = commands[h["first"]["session"]]
    return hits, len(commands)


# -----------------------------------------------------------------------------
# Sigma output
# -----------------------------------------------------------------------------
def yq(s):
    """YAML single-quoted scalar: backslashes stay literal, ' doubles."""
    return "'" + s.replace("'", "''") + "'"


def comment(s):
    s = " ".join(s.split())               # newlines inside a command
    return s if len(s) <= LINE_WIDTH else s[:LINE_WIDTH - 3] + "..."


def to_sigma(d, h, total_sessions):
    first = h["first"]
    out = [
        "# Generated by scripts/sigma_from_cowrie.py — edit the table there, not here.",
        "#",
        "# Honeypot measurement: %d sessions from %d source IPs "
        "(of %d sessions that ran commands)."
        % (len(h["sessions"]), len(h["ips"]), total_sessions),
    ]
    if first:
        out += [
            "#",
            "# Motivating session %s from %s at %s"
            % (first["session"], first["src_ip"], first["timestamp"]),
            "#   matched: " + comment(first["match"]),
            "#   session commands:",
        ]
        cmds = first["commands"]
        out += ["#     $ " + comment(c) for c in cmds[:SESSION_LINES]]
        if len(cmds) > SESSION_LINES:
            out.append("#     ... %d more" % (len(cmds) - SESSION_LINES))
    date = first["timestamp"][:10].replace("-", "/") if first else ""

    out += [
        "title: " + d["title"],
        "id: %s" % uuid.uuid5(UUID_NS, d["name"]),
        "status: experimental",
        "description: " + yq(d["description"]),
        "author: cowrie-honeypot",
    ]
    if date:
        out.append("date: " + date)
    out.append("tags:")
    out += ["    - " + t for t in d["tags"]]
    out += [
        "logsource:",
        "    product: cowrie",
        "    service: cowrie",
        "detection:",
        "    selection:",
        "        eventid: cowrie.command.input",
        "        input|re: " + yq(d["regex"]),
        "    condition: selection",
        "fields:",
        "    - src_ip",
        "    - session",
        "    - input",
        "falsepositives:",
    ]
    out += ["    - " + yq(f) for f in d["falsepositives"]]
    out.append("level: " + d["level"])
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Generate Sigma rules from Cowrie logs")
    ap.add_argument("log", nargs="?", help="path to cowrie.json")
    ap.add_argument("--out", default=os.path.join(REPO, "detections"),
                    help="directory for the .yml rules (default: detections/)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the measurements, write nothing")
    args = ap.parse_args()

    log_file = resolve_log_file(args.log)
    if not os.path.exists(log_file):
        print("[!] Log file not found: %s" % log_file)
        print("    COWRIE_JSON_LOG=/path/to/cowrie.json python3 sigma_from_cowrie.py")
        sys.exit(1)

    hits, total = scan(iter_events(log_file))

    print("%-24s %8s %6s  level" % ("rule", "sessions", "ips"))
    for d in DETECTIONS:
        h = hits[d["name"]]
        print("%-24s %8d %6d  %s" % (d["name"], len(h["sessions"]),
                                     len(h["ips"]), d["level"]))
    print("(%d sessions ran at least one command)" % total)

    if args.dry_run:
        return
    os.makedirs(args.out, exist_ok=True)
    for d in DETECTIONS:
        path = os.path.join(args.out, d["name"] + ".yml")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(to_sigma(d, hits[d["name"]], total))
    print("Wrote %d rules to %s" % (len(DETECTIONS), os.path.abspath(args.out)))


if __name__ == "__main__":
    main()
