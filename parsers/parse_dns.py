"""
parse_dns.py
------------
SOC L1 Log Analysis — DNS Query Log Parser
Detects C2 beaconing, DNS tunneling, and suspicious domain activity.

Usage:
    python parse_dns.py --file ../logs/dns_queries.log
    python parse_dns.py --file ../logs/dns_queries.log --output report.json
"""

import re
import json
import argparse
from collections import defaultdict

# ── Regex Pattern ─────────────────────────────────────────────────────────────

DNS_PATTERN = re.compile(
    r"(?P<timestamp>\S+) client (?P<client_ip>\d+\.\d+\.\d+\.\d+)#(?P<port>\d+): "
    r"query: (?P<domain>\S+) (?P<record_type>\S+) IN"
)

# ── Threat Signatures ─────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = [".ru", ".cn", ".tk", ".xyz", ".top", ".pw", ".cc", ".su"]

SUSPICIOUS_KEYWORDS = [
    "evil", "c2", "malware", "botnet", "rat", "payload",
    "beacon", "cmd", "shell", "exfil", "tunnel",
]

HIGH_ENTROPY_THRESHOLD = 3.8     # Shannon entropy for DGA detection
BEACONING_THRESHOLD    = 3       # Same domain queried N+ times = beaconing
TUNNEL_LABEL_LENGTH    = 20      # Subdomain label > N chars = possible tunneling


# ── Helpers ───────────────────────────────────────────────────────────────────

def shannon_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a string."""
    import math
    if not domain:
        return 0.0
    freq = defaultdict(int)
    for c in domain:
        freq[c] += 1
    length = len(domain)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def get_base_domain(domain: str) -> str:
    """Extract base domain (last two labels)."""
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def has_long_subdomain(domain: str, threshold: int = TUNNEL_LABEL_LENGTH) -> bool:
    """Check if any subdomain label is unusually long (DNS tunneling indicator)."""
    parts = domain.rstrip(".").split(".")
    return any(len(part) > threshold for part in parts[:-2])


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_dns_log(filepath: str) -> dict:
    results = {
        "all_queries": [],
        "suspicious_tld": [],
        "suspicious_keyword": [],
        "high_entropy_domains": [],
        "possible_tunneling": [],
        "beaconing_candidates": [],
        "summary": {}
    }

    queries_by_client = defaultdict(int)
    domain_query_count = defaultdict(lambda: defaultdict(int))  # client → domain → count
    all_domains = set()

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = DNS_PATTERN.search(line)
            if not m:
                continue

            entry = m.groupdict()
            domain = entry["domain"].lower().rstrip(".")
            client = entry["client_ip"]
            base = get_base_domain(domain)

            entry["domain_clean"] = domain
            entry["base_domain"] = base
            results["all_queries"].append(entry)
            queries_by_client[client] += 1
            domain_query_count[client][base] += 1
            all_domains.add(domain)

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    results["suspicious_tld"].append({**entry, "matched_tld": tld})
                    break

            # Suspicious keyword
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in domain:
                    results["suspicious_keyword"].append({**entry, "matched_keyword": kw})
                    break

            # High entropy (DGA detection)
            entropy = shannon_entropy(domain.replace(".", ""))
            if entropy >= HIGH_ENTROPY_THRESHOLD:
                results["high_entropy_domains"].append({
                    **entry,
                    "entropy": round(entropy, 3)
                })

            # DNS tunneling (long subdomain labels)
            if has_long_subdomain(domain):
                results["possible_tunneling"].append({
                    **entry,
                    "flag": "Long subdomain label detected"
                })

    # Beaconing: same client querying same base domain many times
    for client, domains in domain_query_count.items():
        for base_domain, count in domains.items():
            if count >= BEACONING_THRESHOLD:
                results["beaconing_candidates"].append({
                    "client_ip": client,
                    "base_domain": base_domain,
                    "query_count": count,
                })

    results["summary"] = {
        "total_queries": len(results["all_queries"]),
        "unique_domains": len(all_domains),
        "suspicious_tld_count": len(results["suspicious_tld"]),
        "suspicious_keyword_count": len(results["suspicious_keyword"]),
        "high_entropy_count": len(results["high_entropy_domains"]),
        "possible_tunneling_count": len(results["possible_tunneling"]),
        "beaconing_candidates": len(results["beaconing_candidates"]),
        "top_clients_by_query_volume": dict(
            sorted(queries_by_client.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
    }

    return results


# ── Alert Detection ───────────────────────────────────────────────────────────

def detect_alerts(results: dict) -> list:
    alerts = []

    # C2 beaconing
    for beacon in results["beaconing_candidates"]:
        alerts.append({
            "alert": "POSSIBLE_C2_BEACONING",
            "severity": "CRITICAL",
            "client_ip": beacon["client_ip"],
            "domain": beacon["base_domain"],
            "query_count": beacon["query_count"],
            "recommendation": "Isolate host, block domain at DNS level, escalate to Tier 2"
        })

    # Suspicious TLD
    seen = set()
    for req in results["suspicious_tld"]:
        key = (req["client_ip"], req["base_domain"])
        if key not in seen:
            seen.add(key)
            alerts.append({
                "alert": "SUSPICIOUS_TLD_QUERY",
                "severity": "HIGH",
                "client_ip": req["client_ip"],
                "domain": req["domain_clean"],
                "tld": req["matched_tld"],
                "recommendation": "Investigate host, check for malware, block domain"
            })

    # DNS tunneling
    seen_tunnel = set()
    for req in results["possible_tunneling"]:
        ip = req["client_ip"]
        if ip not in seen_tunnel:
            seen_tunnel.add(ip)
            alerts.append({
                "alert": "POSSIBLE_DNS_TUNNELING",
                "severity": "HIGH",
                "client_ip": ip,
                "domain": req["domain_clean"],
                "recommendation": "Capture full DNS traffic, check for data exfiltration"
            })

    return alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(results: dict, alerts: list):
    print("\n" + "="*60)
    print("  DNS QUERY LOG ANALYSIS REPORT")
    print("="*60)
    s = results["summary"]
    print(f"  Total Queries         : {s['total_queries']}")
    print(f"  Unique Domains        : {s['unique_domains']}")
    print(f"  Suspicious TLD Hits   : {s['suspicious_tld_count']}")
    print(f"  Keyword Matches       : {s['suspicious_keyword_count']}")
    print(f"  High Entropy Domains  : {s['high_entropy_count']}")
    print(f"  Possible Tunneling    : {s['possible_tunneling_count']}")
    print(f"  Beaconing Candidates  : {s['beaconing_candidates']}")

    print("\n── Top Clients by Query Volume ───────────────────────────")
    for ip, count in s["top_clients_by_query_volume"].items():
        print(f"  {ip:<20} {count} queries")

    print("\n── Beaconing Candidates ──────────────────────────────────")
    if results["beaconing_candidates"]:
        for b in results["beaconing_candidates"]:
            print(f"  {b['client_ip']:<20} → {b['base_domain']}  ({b['query_count']} queries)")
    else:
        print("  None detected.")

    print("\n── High Entropy Domains (Possible DGA) ───────────────────")
    if results["high_entropy_domains"]:
        for d in results["high_entropy_domains"]:
            print(f"  {d['client_ip']:<20} → {d['domain_clean']}  [entropy: {d['entropy']}]")
    else:
        print("  None detected.")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in alerts:
            print(f"\n  [{alert['severity']}] {alert['alert']}")
            for k, v in alert.items():
                if k not in ("alert", "severity") and v:
                    print(f"  {k.capitalize():<16}: {v}")

    print("\n" + "="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - DNS Query Log Parser")
    parser.add_argument("--file", required=True, help="Path to DNS query log file")
    parser.add_argument("--output", help="Optional: save results to JSON file")
    args = parser.parse_args()

    results = parse_dns_log(args.file)
    alerts = detect_alerts(results)

    print_report(results, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"results": results, "alerts": alerts}, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
