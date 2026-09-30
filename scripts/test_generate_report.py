#!/usr/bin/env python3
# Self-check for generate_report.py: rotated logs are included, the last-24h
# window is honoured, and per-IP session counts never exceed total sessions.
# Run: python3 scripts/test_generate_report.py

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def ev(ts, eid, **kw):
    return json.dumps(dict(timestamp=ts.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                           eventid=eid, **kw))


def main():
    now = datetime.now(timezone.utc)
    old, new = now - timedelta(days=3), now - timedelta(hours=1)
    with tempfile.TemporaryDirectory() as d:
        live = os.path.join(d, "cowrie.json")
        with open(live + ".2000-01-01", "w") as fh:          # rotated, old
            fh.write("\n".join([
                ev(old, "cowrie.session.connect", src_ip="1.1.1.1"),
                ev(old, "cowrie.login.failed", src_ip="1.1.1.1",
                   username="root", password="a"),
                ev(old, "cowrie.login.failed", src_ip="1.1.1.1",
                   username="root", password="b"),
            ]) + "\n")
        with open(live + ".bak", "w") as fh:                 # not a rotation
            fh.write(ev(new, "cowrie.session.connect", src_ip="9.9.9.9") + "\n")
        with open(live, "w") as fh:                          # live, recent
            fh.write("\n".join([
                ev(new, "cowrie.session.connect", src_ip="2.2.2.2"),
                ev(new, "cowrie.command.input", src_ip="2.2.2.2", input="uname -a"),
                ev(new, "cowrie.session.file_download", src_ip="2.2.2.2",
                   url="http://x/y", shasum="ab" * 32),
                '{"partial',
            ]) + "\n")

        out = os.path.join(d, "site")
        subprocess.run([sys.executable, os.path.join(HERE, "generate_report.py"),
                        "--out", out, "--log", live], check=True,
                       stdout=subprocess.DEVNULL)
        with open(os.path.join(out, "data.json")) as fh:
            data = json.load(fh)
        with open(os.path.join(out, "index.html"), encoding="utf-8") as fh:
            page = fh.read()

    assert data["totals"]["sessions"] == 2, data["totals"]
    assert data["totals"]["login_failed"] == 2, data["totals"]
    assert data["last_24h"] == {"sessions": 1, "commands": 1, "downloads": 1,
                                "unique_ips": 1}, data["last_24h"]
    assert data["data_since"].startswith(old.strftime("%Y-%m-%d")), data
    assert "9.9.9.9" not in page
    assert "+1 last 24h" in page
    print("ok")


if __name__ == "__main__":
    main()
