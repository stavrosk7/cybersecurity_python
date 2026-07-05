#!/usr/bin/env python3
"""
Log Analysis for Intrusion Detection
=======================================
Parses common log formats (SSH auth.log, Apache/Nginx access logs) to
flag suspicious activity: brute-force login attempts, port scans,
SQLi/XSS patterns in web requests, and unusual request rates.

Usage:
    python3 6_log_analyzer_ids.py /var/log/auth.log --type ssh
    python3 6_log_analyzer_ids.py /var/log/nginx/access.log --type web
"""

import argparse
import re
from collections import Counter, defaultdict

SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")

WEB_LOG_RE = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) \S+'
)

SUSPICIOUS_PATTERNS = [
    (re.compile(r"union\s+select", re.I), "SQL Injection (UNION SELECT)"),
    (re.compile(r"or\s+1\s*=\s*1", re.I), "SQL Injection (OR 1=1)"),
    (re.compile(r"<script", re.I), "XSS attempt"),
    (re.compile(r"\.\./\.\./", re.I), "Directory traversal"),
    (re.compile(r"/etc/passwd", re.I), "Sensitive file access attempt"),
    (re.compile(r"wp-admin|wp-login", re.I), "WordPress admin probing"),
    (re.compile(r"\bDROP\s+TABLE\b", re.I), "SQL Injection (DROP TABLE)"),
]

BRUTE_FORCE_THRESHOLD = 5   # failed attempts from one IP
SCAN_THRESHOLD = 20         # distinct 404/403 paths hit by one IP


def analyze_ssh_log(path: str):
    failed_by_ip = defaultdict(int)
    invalid_users = Counter()

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = SSH_FAIL_RE.search(line)
            if m:
                failed_by_ip[m.group("ip")] += 1
            m2 = SSH_INVALID_RE.search(line)
            if m2:
                invalid_users[m2.group("user")] += 1

    print("=== SSH Log Analysis ===\n")
    print("[Potential brute-force sources]")
    flagged = False
    for ip, count in sorted(failed_by_ip.items(), key=lambda x: -x[1]):
        if count >= BRUTE_FORCE_THRESHOLD:
            flagged = True
            print(f"  {ip:<18} {count} failed login attempts  -> SUSPICIOUS")
    if not flagged:
        print("  None found above threshold.")

    print("\n[Top invalid usernames attempted]")
    for user, count in invalid_users.most_common(10):
        print(f"  {user:<20} {count} attempts")


def analyze_web_log(path: str):
    requests_by_ip = defaultdict(int)
    errors_by_ip = defaultdict(set)
    pattern_hits = defaultdict(list)

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = WEB_LOG_RE.search(line)
            if not m:
                continue
            ip = m.group("ip")
            path_req = m.group("path")
            status = m.group("status")

            requests_by_ip[ip] += 1
            if status in ("403", "404"):
                errors_by_ip[ip].add(path_req)

            for regex, label in SUSPICIOUS_PATTERNS:
                if regex.search(path_req):
                    pattern_hits[label].append((ip, path_req))

    print("=== Web Log Analysis ===\n")
    print("[Potential scanning activity - many 403/404s from one IP]")
    flagged = False
    for ip, paths in sorted(errors_by_ip.items(), key=lambda x: -len(x[1])):
        if len(paths) >= SCAN_THRESHOLD:
            flagged = True
            print(f"  {ip:<18} {len(paths)} distinct not-found/forbidden paths -> SUSPICIOUS")
    if not flagged:
        print("  None found above threshold.")

    print("\n[Suspicious request patterns detected]")
    if not pattern_hits:
        print("  None found.")
    for label, hits in pattern_hits.items():
        print(f"  {label}: {len(hits)} occurrence(s)")
        for ip, p in hits[:5]:
            print(f"      {ip}  ->  {p}")

    print("\n[Top request volume by IP]")
    for ip, count in sorted(requests_by_ip.items(), key=lambda x: -x[1])[:10]:
        print(f"  {ip:<18} {count} requests")


def main():
    parser = argparse.ArgumentParser(description="Log analysis for intrusion detection")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--type", choices=["ssh", "web"], required=True, help="Log format type")
    args = parser.parse_args()

    if args.type == "ssh":
        analyze_ssh_log(args.logfile)
    else:
        analyze_web_log(args.logfile)


if __name__ == "__main__":
    main()
