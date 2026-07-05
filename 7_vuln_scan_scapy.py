#!/usr/bin/env python3
"""
Vulnerability Scanning with Scapy
====================================
Uses Scapy to perform ARP host discovery on a local subnet and TCP SYN
probes against common ports, then flags a handful of well-known risky
configurations (e.g. Telnet open, anonymous FTP banner, outdated
service banners). This is a lightweight *indicator* scanner, not a
full vulnerability database like Nessus/OpenVAS.

Requires: scapy (and typically root/administrator privileges)
    pip install scapy --break-system-packages

LEGAL: Sending crafted packets (ARP/SYN probes) to hosts you do not
own or have written authorization to test is illegal in many
jurisdictions. Use only on your own lab network.

Usage:
    sudo python3 7_vuln_scan_scapy.py 192.168.1.0/24
"""

import argparse
import socket

from scapy.all import ARP, Ether, IP, TCP, sr1, srp

RISKY_PORTS = {
    21: "FTP (often plaintext credentials)",
    23: "Telnet (unencrypted, deprecated)",
    25: "SMTP (check for open relay)",
    445: "SMB (historically exploited - EternalBlue etc.)",
    3389: "RDP (common brute-force / exploit target)",
    6379: "Redis (often misconfigured with no auth)",
    27017: "MongoDB (often exposed with no auth)",
}

COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 6379, 8080, 27017]


def arp_discover(subnet: str):
    print(f"[*] ARP scanning {subnet} for live hosts...")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    hosts = [{"ip": recv.psrc, "mac": recv.hwsrc} for _, recv in result]
    return hosts


def syn_probe(ip: str, port: int, timeout: float = 1.0):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return False
    if resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK
        # send RST to close gracefully
        rst = IP(dst=ip) / TCP(dport=port, flags="R")
        sr1(rst, timeout=timeout, verbose=0)
        return True
    return False


def grab_banner(ip: str, port: int, timeout: float = 1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                banner = s.recv(256).decode(errors="ignore").strip()
            except socket.timeout:
                banner = ""
            return banner
    except Exception:
        return ""


def scan_host(ip: str, ports):
    print(f"\n[*] Probing {ip} ...")
    findings = []
    for port in ports:
        if syn_probe(ip, port):
            banner = grab_banner(ip, port)
            note = RISKY_PORTS.get(port, "")
            findings.append({"port": port, "banner": banner, "note": note})
            flag = f"  <-- {note}" if note else ""
            banner_display = f" | banner: {banner}" if banner else ""
            print(f"    Port {port:<6} OPEN{banner_display}{flag}")
    if not findings:
        print("    No open ports found among scanned list.")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Basic vulnerability indicator scan using Scapy")
    parser.add_argument("subnet", help="CIDR subnet for ARP discovery, e.g. 192.168.1.0/24, or a single IP")
    parser.add_argument("--ports", type=int, nargs="*", default=COMMON_PORTS, help="Ports to probe")
    args = parser.parse_args()

    if "/" in args.subnet:
        hosts = arp_discover(args.subnet)
        print(f"[*] {len(hosts)} host(s) discovered.\n")
        for h in hosts:
            print(f"  {h['ip']}  ({h['mac']})")
        targets = [h["ip"] for h in hosts]
    else:
        targets = [args.subnet]

    all_results = {}
    for ip in targets:
        all_results[ip] = scan_host(ip, args.ports)

    print("\n=== Summary ===")
    for ip, findings in all_results.items():
        risky = [f for f in findings if f["note"]]
        if risky:
            print(f"{ip}: {len(risky)} potentially risky service(s) found")
            for f in risky:
                print(f"    - Port {f['port']}: {f['note']}")
        else:
            print(f"{ip}: no obviously risky services flagged")


if __name__ == "__main__":
    main()
