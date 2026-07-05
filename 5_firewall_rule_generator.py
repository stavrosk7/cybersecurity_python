#!/usr/bin/env python3
"""
Firewall Rule Generator
=========================
Generates iptables (and optionally nftables) rules from a simple
declarative JSON/YAML-like config describing allowed/blocked traffic.
Useful for quickly bootstrapping a host firewall policy.

LEGAL: Applying firewall rules affects live systems. Review generated
rules carefully and test in a safe environment before deploying, and
only manage firewalls on systems you own or administer.

Usage:
    python3 5_firewall_rule_generator.py config.json --format iptables
    python3 5_firewall_rule_generator.py config.json --format nftables
"""

import argparse
import json

EXAMPLE_CONFIG = {
    "default_policy": "DROP",
    "allow_loopback": True,
    "allow_established": True,
    "rules": [
        {"action": "ALLOW", "proto": "tcp", "port": 22, "source": "10.0.0.0/8", "comment": "SSH from internal net"},
        {"action": "ALLOW", "proto": "tcp", "port": 80, "source": "any", "comment": "HTTP"},
        {"action": "ALLOW", "proto": "tcp", "port": 443, "source": "any", "comment": "HTTPS"},
        {"action": "DENY", "proto": "tcp", "port": 23, "source": "any", "comment": "Block Telnet"},
        {"action": "ALLOW", "proto": "udp", "port": 53, "source": "any", "comment": "DNS"}
    ]
}


def generate_iptables(config: dict) -> str:
    lines = ["#!/bin/sh", "# Auto-generated iptables rules", "set -e", ""]
    lines.append("iptables -F")
    lines.append(f"iptables -P INPUT {config.get('default_policy', 'DROP')}")
    lines.append("iptables -P FORWARD DROP")
    lines.append("iptables -P OUTPUT ACCEPT")
    lines.append("")

    if config.get("allow_loopback"):
        lines.append("iptables -A INPUT -i lo -j ACCEPT")

    if config.get("allow_established"):
        lines.append("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    lines.append("")
    for rule in config.get("rules", []):
        action = "ACCEPT" if rule["action"].upper() == "ALLOW" else "DROP"
        proto = rule.get("proto", "tcp")
        port = rule.get("port")
        source = rule.get("source", "any")
        comment = rule.get("comment", "")

        parts = ["iptables -A INPUT"]
        if proto:
            parts.append(f"-p {proto}")
        if source and source != "any":
            parts.append(f"-s {source}")
        if port:
            parts.append(f"--dport {port}")
        parts.append(f"-j {action}")
        rule_line = " ".join(parts)
        if comment:
            rule_line += f"  # {comment}"
        lines.append(rule_line)

    lines.append("")
    lines.append("echo 'Firewall rules applied.'")
    return "\n".join(lines)


def generate_nftables(config: dict) -> str:
    lines = ["#!/usr/sbin/nft -f", "", "flush ruleset", "", "table inet filter {"]
    lines.append("    chain input {")
    lines.append(f"        type filter hook input priority 0; policy {config.get('default_policy', 'drop').lower()};")

    if config.get("allow_loopback"):
        lines.append("        iif lo accept")
    if config.get("allow_established"):
        lines.append("        ct state established,related accept")

    for rule in config.get("rules", []):
        action = "accept" if rule["action"].upper() == "ALLOW" else "drop"
        proto = rule.get("proto", "tcp")
        port = rule.get("port")
        source = rule.get("source", "any")
        comment = rule.get("comment", "")

        cond = []
        if source and source != "any":
            cond.append(f"ip saddr {source}")
        if port:
            cond.append(f"{proto} dport {port}")
        cond_str = " ".join(cond)
        line = f"        {cond_str} {action}".strip()
        if comment:
            line += f"  # {comment}"
        lines.append(line)

    lines.append("    }")
    lines.append("    chain forward { type filter hook forward priority 0; policy drop; }")
    lines.append("    chain output { type filter hook output priority 0; policy accept; }")
    lines.append("}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Firewall rule generator")
    parser.add_argument("config", nargs="?", help="Path to JSON config file (omit to print an example config)")
    parser.add_argument("--format", choices=["iptables", "nftables"], default="iptables")
    parser.add_argument("--out", help="Output file path (prints to stdout if omitted)")
    args = parser.parse_args()

    if not args.config:
        print("[*] No config provided. Example config structure:\n")
        print(json.dumps(EXAMPLE_CONFIG, indent=2))
        return

    with open(args.config, "r") as f:
        config = json.load(f)

    output = generate_iptables(config) if args.format == "iptables" else generate_nftables(config)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[*] Rules written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
