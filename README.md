# Security Tools Toolkit (Python)

⚠️ **Legal notice**: Όλα τα εργαλεία αυτού του φακέλου προορίζονται για εκπαιδευτική χρήση
και για testing σε δίκτυα/συστήματα που **σου ανήκουν** ή για τα οποία έχεις **ρητή γραπτή άδεια**.
Η χρήση τους σε τρίτα συστήματα χωρίς άδεια είναι παράνομη σε πολλές χώρες.

## Εγκατάσταση εξαρτήσεων

```bash
pip install requests beautifulsoup4 scapy python-nmap --break-system-packages
sudo apt install nmap snort   # αν χρειάζεται στο Linux
```

Τα scripts που στέλνουν raw πακέτα (Scapy) χρειάζονται συνήθως **root/sudo**.

## Λίστα εργαλείων

| # | Αρχείο | Περιγραφή | Παράδειγμα χρήσης |
|---|--------|-----------|---------------------|
| 1 | `1_network_scanner.py` | Ping sweep ανακάλυψης hosts σε subnet | `python3 1_network_scanner.py 192.168.1.0/24` |
| 2 | `2_web_crawler.py` | Depth-limited web crawler | `python3 2_web_crawler.py https://example.com --depth 2` |
| 3 | `3_password_hash_auditor.py` | Dictionary attack πάνω σε γνωστό hash (auditing) | `python3 3_password_hash_auditor.py <hash> rockyou.txt --algo sha256` |
| 4 | `4_port_scanner_nmap.py` | Port scanner με Nmap integration | `python3 4_port_scanner_nmap.py 192.168.1.10 --ports 1-1024 --sV` |
| 5 | `5_firewall_rule_generator.py` | Παράγει iptables/nftables rules από config | `python3 5_firewall_rule_generator.py config.json --format iptables` |
| 6 | `6_log_analyzer_ids.py` | Ανάλυση logs (SSH/web) για ύποπτη δραστηριότητα | `python3 6_log_analyzer_ids.py /var/log/auth.log --type ssh` |
| 7 | `7_vuln_scan_scapy.py` | ARP discovery + βασικός έλεγχος ευάλωτων services | `sudo python3 7_vuln_scan_scapy.py 192.168.1.0/24` |
| 8 | `8_snort_ids_integration.py` | Parse Snort alerts / δημιουργία custom rule | `python3 8_snort_ids_integration.py parse /var/log/snort/alert` |
| 9 | `9_vuln_detect_scapy_advanced.py` | OS fingerprinting + outdated banner detection | `sudo python3 9_vuln_detect_scapy_advanced.py 192.168.1.10` |

## Σημειώσεις

- Το `3_password_hash_auditor.py` κάνει **offline** dictionary attack πάνω σε ένα hash που ήδη
  κατέχεις (π.χ. για να ελέγξεις πόσο αδύναμος είναι ένας κωδικός) — δεν κάνει brute-force σε
  live login forms.
- Το `7` και το `9` απαιτούν Scapy και συνήθως root δικαιώματα επειδή φτιάχνουν raw πακέτα.
- Το `8` προϋποθέτει ότι το Snort είναι ήδη εγκατεστημένο και ρυθμισμένο ξεχωριστά.
- Η λίστα "outdated banners" στο #9 είναι ενδεικτική, όχι πλήρης CVE βάση.
