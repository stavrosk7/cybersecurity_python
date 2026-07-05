#!/usr/bin/env python3
"""
Password Hash Auditor (dictionary attack against a known hash)
================================================================
Given a hash (md5/sha1/sha256/sha512) and a wordlist, attempts to find
a matching plaintext. This is intended for auditing your OWN password
hashes (e.g., checking if a hashed credential you're responsible for
is weak / present in a common wordlist), not for attacking accounts
you don't own or have authorization to test.

LEGAL: Only use against hashes/data you own or are authorized to audit.

Usage:
    python3 3_password_hash_auditor.py <hash> <wordlist.txt> --algo sha256
    python3 3_password_hash_auditor.py <hash> <wordlist.txt> --algo md5 --salt abc123 --salt-position prefix
"""

import argparse
import hashlib
import time


ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def hash_candidate(candidate: str, algo: str, salt: str = "", salt_position: str = "prefix") -> str:
    if salt:
        candidate = f"{salt}{candidate}" if salt_position == "prefix" else f"{candidate}{salt}"
    h = ALGOS[algo]()
    h.update(candidate.encode("utf-8"))
    return h.hexdigest()


def crack(target_hash: str, wordlist_path: str, algo: str, salt: str = "", salt_position: str = "prefix"):
    target_hash = target_hash.lower().strip()
    start = time.time()
    attempts = 0

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\n\r")
            if not word:
                continue
            attempts += 1
            if hash_candidate(word, algo, salt, salt_position) == target_hash:
                elapsed = time.time() - start
                print(f"\n[+] MATCH FOUND: '{word}'")
                print(f"[*] Attempts: {attempts:,}  |  Time: {elapsed:.2f}s")
                return word

            if attempts % 100000 == 0:
                print(f"[*] {attempts:,} attempts tried...")

    elapsed = time.time() - start
    print(f"\n[-] No match found after {attempts:,} attempts ({elapsed:.2f}s).")
    return None


def main():
    parser = argparse.ArgumentParser(description="Dictionary-based hash auditor")
    parser.add_argument("hash", help="Target hash (hex digest)")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--algo", choices=ALGOS.keys(), default="sha256", help="Hash algorithm")
    parser.add_argument("--salt", default="", help="Optional salt value")
    parser.add_argument("--salt-position", choices=["prefix", "suffix"], default="prefix")
    args = parser.parse_args()

    crack(args.hash, args.wordlist, args.algo, args.salt, args.salt_position)


if __name__ == "__main__":
    main()
