#!/usr/bin/env python3
"""
Web Scraper / Crawler
======================
Depth-limited crawler that stays within the starting domain, extracts
page titles, links, and optionally saves page text.

Requires: requests, beautifulsoup4
    pip install requests beautifulsoup4 --break-system-packages

LEGAL: Respect robots.txt and each site's Terms of Service. Only crawl
sites you own or are authorized to crawl. Be gentle with request rates.

Usage:
    python3 2_web_crawler.py https://example.com --depth 2 --max-pages 50
"""

import argparse
import time
import urllib.robotparser
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "SimpleEducationalCrawler/1.0"}


def get_robot_parser(base_url: str):
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(robots_url)
    try:
        rp.read()
    except Exception:
        pass
    return rp


def same_domain(url: str, root_netloc: str) -> bool:
    return urlparse(url).netloc == root_netloc


def crawl(start_url: str, max_depth: int = 2, max_pages: int = 50, delay: float = 0.5):
    root_netloc = urlparse(start_url).netloc
    rp = get_robot_parser(start_url)

    visited = set()
    queue = deque([(start_url, 0)])
    results = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue

        if not rp.can_fetch(HEADERS["User-Agent"], url):
            print(f"[skip - robots.txt] {url}")
            continue

        try:
            resp = requests.get(url, headers=HEADERS, timeout=8)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"[error] {url} -> {e}")
            continue

        visited.add(url)
        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "(no title)"

        page_links = []
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if link.startswith("http") and same_domain(link, root_netloc):
                page_links.append(link)
                if link not in visited:
                    queue.append((link, depth + 1))

        results.append({"url": url, "title": title, "depth": depth, "links_found": len(page_links)})
        print(f"[{depth}] {url}  ->  {title}  ({len(page_links)} links)")

        time.sleep(delay)  # be polite

    print(f"\n[*] Crawled {len(results)} page(s).")
    return results


def main():
    parser = argparse.ArgumentParser(description="Depth-limited domain-scoped web crawler")
    parser.add_argument("url", help="Starting URL")
    parser.add_argument("--depth", type=int, default=2, help="Max crawl depth")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to visit")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    args = parser.parse_args()

    crawl(args.url, args.depth, args.max_pages, args.delay)


if __name__ == "__main__":
    main()
