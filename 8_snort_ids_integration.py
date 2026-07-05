#!/usr/bin/env python3
"""
Intrusion Detection with Snort (Integration Helper)
======================================================
Two functions:
  1) parse_alerts()  - tails/parses Snort's alert log (fast alert format)
                        and summarizes triggered alerts by signature & source IP.
  2) generate_rule()  - helper to build a syntactically valid custom
                        Snort rule from simple parameters.

Assumes Snort is already installed & configured separately
(this script does not install/configure Snort itself).
Typical alert log location: /var/log/snort/alert

LEGAL: Deploying IDS rules and monitoring traffic should only be done
on networks you own or administer.

Usage:
    python3 8_snort_ids_integration.py parse /var/log/snort/alert
    python3 8_snort_ids_integration.py genrule --proto tcp --src any --sport any \\
        --dst any --dport 4444 --msg "Possible reverse shell port" --sid 1000001
"""

import argparse
import re
from collections import Counter

# Example fast-alert line:
# 06/30-14:22:01.123456  [**] [1:1000001:1] Possible reverse shell port [**] \
# [Priority: 1] {TCP} 10.0.0.5:51322 -> 10.0.0.9:4444
ALERT_RE = re.compile(
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.+?)\s*\[\*\*\].*?"
    r"\{(?P<proto>\w+)\}\s*(?P<src>[\d.]+):?(?P<sport>\d*)\s*->\s*(?P<dst>[\d.]+):?(?P<dport>\d*)"
)


def parse_alerts(path: str):
    sig_counter = Counter()
    src_counter = Counter()
    total = 0

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = ALERT_RE.search(line)
            if not m:
                continue
            total += 1
            sig_counter[m.group("msg")] += 1
            src_counter[m.group("src")] += 1

    print(f"=== Snort Alert Summary ({total} alerts parsed) ===\n")
    print("[Top triggered signatures]")
    for msg, count in sig_counter.most_common(10):
        print(f"  {count:<6} {msg}")

    print("\n[Top source IPs]")
    for ip, count in src_counter.most_common(10):
        print(f"  {count:<6} {ip}")

    return {"total": total, "signatures": sig_counter, "sources": src_counter}


def generate_rule(action, proto, src, sport, direction, dst, dport, msg, sid, rev=1, extra_options=None):
    """
    Builds a Snort rule string, e.g.:
    alert tcp any any -> any 4444 (msg:"Possible reverse shell port"; sid:1000001; rev:1;)
    """
    options = [f'msg:"{msg}"']
    if extra_options:
        options.extend(extra_options)
    options.append(f"sid:{sid}")
    options.append(f"rev:{rev}")

    options_str = "; ".join(options) + ";"
    rule = f"{action} {proto} {src} {sport} {direction} {dst} {dport} ({options_str})"
    return rule


def main():
    parser = argparse.ArgumentParser(description="Snort IDS integration helper")
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse", help="Parse a Snort alert log")
    p_parse.add_argument("logfile", help="Path to Snort alert log (fast format)")

    p_gen = sub.add_parser("genrule", help="Generate a custom Snort rule")
    p_gen.add_argument("--action", default="alert", choices=["alert", "log", "pass", "drop", "reject"])
    p_gen.add_argument("--proto", default="tcp", choices=["tcp", "udp", "icmp", "ip"])
    p_gen.add_argument("--src", default="any")
    p_gen.add_argument("--sport", default="any")
    p_gen.add_argument("--direction", default="->", choices=["->", "<>"])
    p_gen.add_argument("--dst", default="any")
    p_gen.add_argument("--dport", required=True)
    p_gen.add_argument("--msg", required=True)
    p_gen.add_argument("--sid", type=int, required=True, help="Use SIDs >= 1,000,000 for local/custom rules")
    p_gen.add_argument("--rev", type=int, default=1)
    p_gen.add_argument("--content", help="Optional content match string, e.g. a payload substring")

    args = parser.parse_args()

    if args.command == "parse":
        parse_alerts(args.logfile)
    else:
        extra = []
        if args.content:
            extra.append(f'content:"{args.content}"')
        rule = generate_rule(
            args.action, args.proto, args.src, args.sport, args.direction,
            args.dst, args.dport, args.msg, args.sid, args.rev, extra
        )
        print("\nGenerated Snort rule (append to local.rules):\n")
        print(rule)


if __name__ == "__main__":
    main()
