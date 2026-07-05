#!/usr/bin/env python3
"""
Simple Network Scanner
=======================
Discovers live hosts on a local subnet using a threaded ping sweep,
then resolves hostnames where possible.

LEGAL: Only run this against networks/hosts you own or have explicit
written authorization to scan. Unauthorized scanning may be illegal.

Usage:
    python3 1_network_scanner.py 192.168.1.0/24
    python3 1_network_scanner.py 192.168.1.1-192.168.1.50
"""

import argparse
import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def ping_host(ip: str, timeout_ms: int = 800) -> bool:
    """Return True if host responds to a single ICMP ping."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        # -W expects seconds on Linux, so convert
        timeout_s = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), str(ip)]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "unknown"


def parse_targets(target: str):
    """Accepts CIDR (192.168.1.0/24) or range (192.168.1.1-192.168.1.50)."""
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    elif "-" in target:
        start_str, end_str = target.split("-")
        start = ipaddress.ip_address(start_str.strip())
        end = ipaddress.ip_address(end_str.strip())
        return [str(ipaddress.ip_address(ip)) for ip in range(int(start), int(end) + 1)]
    else:
        return [target]


def scan(target: str, max_workers: int = 100):
    targets = parse_targets(target)
    print(f"[*] Scanning {len(targets)} host(s) in {target} ...\n")

    live_hosts = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in targets}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    live_hosts.append(ip)
            except Exception:
                pass

    live_hosts.sort(key=lambda x: tuple(int(p) for p in x.split(".")))

    print(f"{'IP Address':<18}{'Hostname'}")
    print("-" * 50)
    for ip in live_hosts:
        hostname = resolve_hostname(ip)
        print(f"{ip:<18}{hostname}")

    print(f"\n[*] {len(live_hosts)} host(s) up out of {len(targets)} scanned.")
    return live_hosts


def main():
    parser = argparse.ArgumentParser(description="Simple Network Scanner (ping sweep)")
    parser.add_argument("target", help="CIDR (192.168.1.0/24) or range (192.168.1.1-192.168.1.50)")
    parser.add_argument("--workers", type=int, default=100, help="Number of concurrent threads")
    args = parser.parse_args()

    scan(args.target, args.workers)


if __name__ == "__main__":
    main()
