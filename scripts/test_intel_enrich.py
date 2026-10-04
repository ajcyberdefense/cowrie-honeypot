#!/usr/bin/env python3
# Self-check for intel_enrich.py, offline: activity tiers, campaign grouping
# by a shared artifact, and that trivial shell-probe scripts never link IPs.
# Run: python3 scripts/test_intel_enrich.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from intel_enrich import CAMPAIGN_MIN_IPS, campaigns, profile, tier  # noqa: E402

KEY = "AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1"


def session(ip, sid, *cmds, payload=None):
    ts = "2026-09-01T00:00:%02d.000000Z" % (int(sid[1:]) % 60)
    ev = [{"eventid": "cowrie.session.connect", "src_ip": ip, "session": sid,
           "protocol": "ssh", "timestamp": ts},
          {"eventid": "cowrie.login.success", "src_ip": ip, "session": sid,
           "timestamp": ts}]
    ev += [{"eventid": "cowrie.command.input", "src_ip": ip, "session": sid,
            "input": c, "timestamp": ts} for c in cmds]
    if payload:
        ev.append({"eventid": "cowrie.session.file_download", "src_ip": ip,
                   "session": sid, "shasum": payload, "timestamp": ts,
                   "url": "http://198.51.100.%s/bins.sh" % sid[1:]})
    return ev


def main():
    n = CAMPAIGN_MIN_IPS
    events = []
    # n IPs plant the same key with per-run noise in the IP: one campaign.
    for i in range(n):
        events += session("203.0.113.%d" % i, "s%d" % i,
                          'echo "ssh-rsa %s x" >> .ssh/authorized_keys' % KEY,
                          "ping -c1 192.0.2.%d" % i)
    # n IPs drop the same payload from different servers.
    for i in range(n):
        events += session("198.18.0.%d" % i, "s%d" % (100 + i), "cd /tmp",
                          payload="ab" * 32)
    # Many IPs send only the generic shell probe: must not form a campaign.
    for i in range(n * 3):
        events += session("192.0.2.%d" % i, "s%d" % (200 + i), "system", "shell", "sh")
    # One IP that only fails to log in.
    events.append({"eventid": "cowrie.session.connect", "src_ip": "198.51.100.200",
                   "session": "s999", "timestamp": "2026-09-02T00:00:00.000000Z"})

    ips = profile(events)
    assert tier(ips["203.0.113.0"]) == "ran commands"
    assert tier(ips["198.18.0.0"]) == "dropped files"
    assert tier(ips["198.51.100.200"]) == "scanned / guessed"
    assert not ips["192.0.2.0"]["scripts"], ips["192.0.2.0"]["scripts"]

    intel = {ip: {"cymru": {"as_name": "TEST-AS", "cc": "ZZ"},
                  "ipapi": {"hosting": ip.startswith("198.18.")}, "dshield": None}
             for ip in ips}
    camps = {(c["feature"], c["ips"]) for c in campaigns(ips, intel)}
    assert ("planted SSH key", n) in camps, camps
    assert ("command script", n) in camps, camps     # IP noise normalized away
    assert ("payload (SHA-256)", n) in camps, camps
    assert not any(f == "download server" for f, _ in camps), camps
    hosting = {c["feature"]: c["hosting_share"] for c in campaigns(ips, intel)}
    assert hosting["payload (SHA-256)"] == 1.0 and hosting["planted SSH key"] == 0.0
    print("ok")


if __name__ == "__main__":
    main()
