#!/usr/bin/env python3
"""
Port Scanner with Nmap Integration
====================================
Wraps the `nmap` command-line tool (via python-nmap) to perform a
service/version scan against a target, then prints a clean summary.
Falls back to a basic raw socket connect-scan if nmap isn't installed.

Requires: nmap installed on the system, python-nmap python package
    sudo apt install nmap
    pip install python-nmap --break-system-packages

LEGAL: Only scan hosts you own or are explicitly authorized to test.
Port scanning third-party systems without permission may be illegal.

Usage:
    python3 4_port_scanner_nmap.py 192.168.1.10 --ports 1-1024
    python3 4_port_scanner_nmap.py 192.168.1.10 --ports 22,80,443 --sV
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False


def nmap_scan(target: str, ports: str, service_detection: bool):
    scanner = nmap.PortScanner()
    arguments = "-sT"  # TCP connect scan (no root required)
    if service_detection:
        arguments += " -sV"

    print(f"[*] Running nmap {arguments} on {target} (ports {ports}) ...\n")
    scanner.scan(target, ports=ports, arguments=arguments)

    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"\nProtocol: {proto}")
            print(f"{'Port':<8}{'State':<10}{'Service':<15}{'Version'}")
            print("-" * 55)
            lport = sorted(scanner[host][proto].keys())
            for port in lport:
                info = scanner[host][proto][port]
                version = f"{info.get('product', '')} {info.get('version', '')}".strip()
                print(f"{port:<8}{info['state']:<10}{info.get('name', ''):<15}{version}")


def fallback_socket_scan(target: str, ports: str, timeout: float = 0.6):
    print("[!] python-nmap or nmap binary not found. Falling back to basic TCP connect scan.\n")

    port_list = []
    for part in ports.split(","):
        if "-" in part:
            start, end = part.split("-")
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(part))

    open_ports = []

    def check_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                return port, service
        return None

    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(check_port, p) for p in port_list]
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort()
    print(f"{'Port':<8}{'Service'}")
    print("-" * 30)
    for port, service in open_ports:
        print(f"{port:<8}{service}")
    print(f"\n[*] {len(open_ports)} open port(s) found out of {len(port_list)} scanned.")


def main():
    parser = argparse.ArgumentParser(description="Port scanner with Nmap integration")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range or list, e.g. 1-1024 or 22,80,443")
    parser.add_argument("--sV", action="store_true", help="Enable service/version detection (requires nmap)")
    args = parser.parse_args()

    if HAS_NMAP:
        try:
            nmap_scan(args.target, args.ports, args.sV)
            return
        except Exception as e:
            print(f"[!] nmap scan failed ({e}), falling back to socket scan.\n")

    fallback_socket_scan(args.target, args.ports)


if __name__ == "__main__":
    main()
