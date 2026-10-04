#!/usr/bin/env python3
# Self-check for siem_rules.to_lucene, offline: PCRE shorthands that Lucene
# lacks are gone, (?i) becomes a flag, and every Part 6 detection translates.
# The real proof is `siem_rules.py`'s parity check against a live index.
# Run: python3 scripts/test_siem_rules.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sigma_from_cowrie import DETECTIONS  # noqa: E402
from siem_rules import to_lucene  # noqa: E402


def main():
    assert to_lucene(r"(?i)\bcurl\s+\S+") == (".*(curl[ \t\n\r]+[^ \t\n\r]+).*", True)
    assert to_lucene(r"/bin/busybox\s+[A-Z]{4,}\b") == \
        (".*(/bin/busybox[ \t\n\r]+[A-Z]{4,}).*", False)
    assert to_lucene(r"x\d\x5cx") == (r".*(x[0-9]\\x).*", False)
    for d in DETECTIONS:
        pattern, _ = to_lucene(d["regex"])
        for leftover in (r"\s", r"\S", r"\d", r"\b", "(?i)", r"\x5c"):
            assert leftover not in pattern, (d["name"], leftover, pattern)
    print("ok")


if __name__ == "__main__":
    main()
