#!/usr/bin/env python3
"""
Vulnerability Detection with Scapy (Advanced)
================================================
Builds on the basic Scapy scanner with:
  - TCP OS fingerprinting via TTL / window size heuristics
  - Firewall/filtering detection (SYN vs no response vs RST vs ICMP unreachable)
  - Service banner analysis against a small "known-outdated" version list
  - Simple CVE-style hints for a handful of well-known old banners
    (illustrative only - not a substitute for a real CVE feed/scanner)

Requires: scapy (root/administrator privileges typically required)
    pip install scapy --break-system-packages

LEGAL: Only run against hosts you own or are explicitly authorized to
test. Crafted packet probing against third-party systems without
permission is illegal in many jurisdictions.

Usage:
    sudo python3 9_vuln_detect_scapy_advanced.py 192.168.1.10 --ports 21 22 80 443
"""

import argparse
import socket

from scapy.all import IP, TCP, ICMP, sr1

# Very rough TTL-based OS heuristic (initial TTLs before hops decrement them)
TTL_GUESS = [
    (64, "Linux / Unix / macOS"),
    (128, "Windows"),
    (255, "Cisco / network device / some Unix"),
]

# Illustrative-only outdated banner signatures. Not exhaustive; for real
# vulnerability matching use an updated CVE/NVD feed.
OUTDATED_BANNERS = [
    ("vsftpd 2.3.4", "Known backdoored version (CVE-2011-2523)"),
    ("openssh 4.", "Very old OpenSSH - multiple known CVEs, upgrade recommended"),
    ("openssh 5.", "Old OpenSSH - check for known CVEs, upgrade recommended"),
    ("apache/2.2", "Apache 2.2 is EOL - upgrade recommended"),
    ("microsoft-iis/6.0", "IIS 6.0 is EOL - known remote exploits exist"),
    ("proftpd 1.3.3", "Known backdoor incident version - verify integrity"),
]


def guess_os_from_ttl(ttl: int) -> str:
    closest = min(TTL_GUESS, key=lambda pair: abs(pair[0] - ttl) if ttl <= pair[0] else 999)
    return f"{closest[1]} (observed TTL={ttl}, baseline={closest[0]})"


def tcp_probe(ip: str, port: int, timeout: float = 1.5):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return {"state": "filtered (no response)", "ttl": None, "window": None}

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        ttl = resp[IP].ttl
        window = resp[TCP].window
        if flags == 0x12:  # SYN-ACK
            rst = IP(dst=ip) / TCP(dport=port, flags="R")
            sr1(rst, timeout=timeout, verbose=0)
            return {"state": "open", "ttl": ttl, "window": window}
        elif flags == 0x14:  # RST-ACK
            return {"state": "closed", "ttl": ttl, "window": window}

    if resp.haslayer(ICMP):
        icmp_type = resp[ICMP].type
        icmp_code = resp[ICMP].code
        if icmp_type == 3:
            return {"state": f"filtered (ICMP unreachable code={icmp_code})", "ttl": resp[IP].ttl, "window": None}

    return {"state": "unknown", "ttl": None, "window": None}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def check_outdated(banner: str):
    banner_lower = banner.lower()
    hits = []
    for sig, note in OUTDATED_BANNERS:
        if sig in banner_lower:
            hits.append(note)
    return hits


def scan_host(ip: str, ports):
    print(f"\n[*] Advanced scan of {ip}\n" + "-" * 50)
    os_guess_done = False
    findings = []

    for port in ports:
        result = tcp_probe(ip, port)
        line = f"Port {port:<6} state={result['state']}"

        if result["ttl"] and not os_guess_done:
            os_guess = guess_os_from_ttl(result["ttl"])
            print(f"[OS Fingerprint Guess] {os_guess}")
            os_guess_done = True

        banner = ""
        vuln_notes = []
        if result["state"] == "open":
            banner = grab_banner(ip, port)
            vuln_notes = check_outdated(banner)
            if banner:
                line += f" | banner: {banner}"
            if vuln_notes:
                line += f"  <-- {' | '.join(vuln_notes)}"

        print(line)
        findings.append({
            "port": port, "state": result["state"], "banner": banner, "notes": vuln_notes
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Advanced vulnerability detection with Scapy")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--ports", type=int, nargs="+", default=[21, 22, 23, 25, 80, 443, 445, 3389],
                         help="Ports to probe")
    args = parser.parse_args()

    findings = scan_host(args.target, args.ports)

    print("\n=== Summary ===")
    flagged = [f for f in findings if f["notes"]]
    if flagged:
        print(f"{len(flagged)} potential issue(s) found:")
        for f in flagged:
            print(f"  Port {f['port']}: {', '.join(f['notes'])}")
    else:
        print("No known outdated banners detected among open ports scanned.")
        print("Note: absence of findings here does NOT mean the host is secure -")
        print("this checks only a small illustrative signature list.")


if __name__ == "__main__":
    main()
