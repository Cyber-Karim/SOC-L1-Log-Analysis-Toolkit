"""
abuseipdb_check.py
------------------
SOC L1 Log Analysis — AbuseIPDB IP Reputation Lookup
Check IP addresses against the AbuseIPDB database for abuse reports.

Usage:
    python abuseipdb_check.py --ip 203.0.113.42
    python abuseipdb_check.py --ip 203.0.113.42 --days 90
    python abuseipdb_check.py --bulk --file ../logs/auth.log
    python abuseipdb_check.py --ip 203.0.113.42 --output result.json
"""

import os
import re
import json
import time
import argparse
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
BASE_URL = "https://api.abuseipdb.com/api/v2"
HEADERS  = {"Key": API_KEY, "Accept": "application/json"}

RISK_THRESHOLDS = {
    "CRITICAL": 75,
    "HIGH":     50,
    "MEDIUM":   25,
    "LOW":      1,
}

# AbuseIPDB Category reference
ABUSE_CATEGORIES = {
    1:  "DNS Compromise",       2:  "DNS Poisoning",
    3:  "Fraud Orders",         4:  "DDoS Attack",
    5:  "FTP Brute-Force",      6:  "Ping of Death",
    7:  "Phishing",             8:  "Fraud VoIP",
    9:  "Open Proxy",           10: "Web Spam",
    11: "Email Spam",           12: "Blog Spam",
    13: "VPN IP",               14: "Port Scan",
    15: "Hacking",              16: "SQL Injection",
    17: "Spoofing",             18: "Brute-Force",
    19: "Bad Web Bot",          20: "Exploited Host",
    21: "Web App Attack",       22: "SSH Brute-Force",
    23: "IoT Targeted",
}

# ── API Call ──────────────────────────────────────────────────────────────────

def check_ip(ip: str, max_age_days: int = 30) -> dict:
    if not API_KEY:
        print(f"[!] No ABUSEIPDB_API_KEY set — using mock response for {ip}")
        return mock_response(ip)

    try:
        resp = requests.get(
            f"{BASE_URL}/check",
            headers=HEADERS,
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
            timeout=15
        )
        resp.raise_for_status()
        raw = resp.json().get("data", {})
        return parse_result(raw, ip)
    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": str(e), "severity": "UNKNOWN"}


# ── Response Parser ───────────────────────────────────────────────────────────

def parse_result(data: dict, ip: str) -> dict:
    score    = data.get("abuseConfidenceScore", 0)
    total    = data.get("totalReports", 0)
    distinct = data.get("numDistinctUsers", 0)
    country  = data.get("countryCode", "N/A")
    isp      = data.get("isp", "N/A")
    domain   = data.get("domain", "N/A")
    usage    = data.get("usageType", "N/A")
    is_white = data.get("isWhitelisted", False)
    last_rep = data.get("lastReportedAt", "N/A")
    is_tor   = data.get("isTor", False)

    # Category IDs from recent reports
    recent_reports = data.get("reports", [])[:5]
    seen_cats = set()
    for report in recent_reports:
        for cat_id in report.get("categories", []):
            seen_cats.add(cat_id)
    category_names = [ABUSE_CATEGORIES.get(c, f"Cat-{c}") for c in sorted(seen_cats)]

    # Severity
    severity = "CLEAN"
    for level, threshold in RISK_THRESHOLDS.items():
        if score >= threshold:
            severity = level
            break

    if is_tor:
        severity = max(severity, "HIGH",
                       key=lambda x: ["CLEAN","LOW","MEDIUM","HIGH","CRITICAL"].index(x))

    return {
        "ip":                   ip,
        "abuse_confidence_score": score,
        "severity":             severity,
        "total_reports":        total,
        "distinct_reporters":   distinct,
        "country":              country,
        "isp":                  isp,
        "domain":               domain,
        "usage_type":           usage,
        "is_tor":               is_tor,
        "is_whitelisted":       is_white,
        "last_reported_at":     last_rep,
        "abuse_categories":     category_names,
        "recent_reports":       [
            {
                "reported_at":  r.get("reportedAt"),
                "comment":      r.get("comment", "")[:120],
                "categories":   [ABUSE_CATEGORIES.get(c, str(c)) for c in r.get("categories", [])]
            }
            for r in recent_reports
        ],
        "queried_at": datetime.utcnow().isoformat() + "Z",
    }


# ── Bulk Scan from Log File ───────────────────────────────────────────────────

def extract_ips_from_log(filepath: str) -> list:
    """Extract unique IPs from any log file."""
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    # Exclude private/loopback
    private = ("10.", "192.168.", "172.", "127.", "0.")
    ips = set()
    with open(filepath) as f:
        for line in f:
            for ip in ip_pattern.findall(line):
                if not any(ip.startswith(p) for p in private):
                    ips.add(ip)
    return sorted(ips)


def bulk_check(filepath: str, max_age_days: int = 30, delay: float = 1.5) -> list:
    ips = extract_ips_from_log(filepath)
    print(f"[*] Found {len(ips)} unique external IPs in {filepath}")
    results = []
    for i, ip in enumerate(ips, 1):
        print(f"[{i}/{len(ips)}] Checking {ip}...", end=" ")
        result = check_ip(ip, max_age_days)
        print(f"Score: {result.get('abuse_confidence_score', '?')} — {result.get('severity', '?')}")
        results.append(result)
        time.sleep(delay)  # Rate limiting
    return results


# ── Mock Response ─────────────────────────────────────────────────────────────

def mock_response(ip: str) -> dict:
    mock_data = {
        "abuseConfidenceScore": 87,
        "totalReports": 142,
        "numDistinctUsers": 34,
        "countryCode": "RU",
        "isp": "Mock ISP LLC",
        "domain": "mockisp.example",
        "usageType": "Data Center/Web Hosting/Transit",
        "isWhitelisted": False,
        "isTor": False,
        "lastReportedAt": "2026-04-25T23:00:00+00:00",
        "reports": [
            {
                "reportedAt": "2026-04-25T22:00:00+00:00",
                "comment": "SSH brute force attack — 500+ attempts/min",
                "categories": [18, 22]
            },
            {
                "reportedAt": "2026-04-24T10:00:00+00:00",
                "comment": "Port scanning multiple hosts",
                "categories": [14]
            }
        ]
    }
    return parse_result(mock_data, ip)


# ── Print Result ──────────────────────────────────────────────────────────────

def print_result(result: dict):
    SEV_ICONS = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","CLEAN":"🟢","UNKNOWN":"⚪"}
    icon = SEV_ICONS.get(result.get("severity","UNKNOWN"), "⚪")

    print(f"\n{'='*60}")
    print(f"  AbuseIPDB Lookup Result")
    print(f"{'='*60}")
    print(f"  IP Address     : {result.get('ip')}")
    print(f"  Severity       : {icon} {result.get('severity')}")
    print(f"  Abuse Score    : {result.get('abuse_confidence_score')} / 100")
    print(f"  Total Reports  : {result.get('total_reports')}")
    print(f"  Distinct Users : {result.get('distinct_reporters')}")
    print(f"  Country        : {result.get('country')}")
    print(f"  ISP            : {result.get('isp')}")
    print(f"  Usage Type     : {result.get('usage_type')}")
    print(f"  Is TOR         : {'⚠️ YES' if result.get('is_tor') else 'No'}")
    print(f"  Last Reported  : {result.get('last_reported_at')}")

    if result.get("abuse_categories"):
        print(f"\n  ── Abuse Categories ──────────────────────────────────")
        for cat in result["abuse_categories"]:
            print(f"    • {cat}")

    if result.get("recent_reports"):
        print(f"\n  ── Recent Reports ────────────────────────────────────")
        for r in result["recent_reports"]:
            cats = ", ".join(r.get("categories", []))
            print(f"    [{r.get('reported_at','?')}] [{cats}]")
            if r.get("comment"):
                print(f"    Comment: {r['comment'][:80]}")

    print(f"\n  Queried at     : {result.get('queried_at')}")
    print(f"{'='*60}\n")


def print_bulk_summary(results: list):
    print(f"\n{'='*60}")
    print(f"  Bulk AbuseIPDB Scan — Summary")
    print(f"{'='*60}")
    by_severity = {}
    for r in results:
        sev = r.get("severity", "UNKNOWN")
        by_severity.setdefault(sev, []).append(r["ip"])

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","CLEAN","UNKNOWN"]:
        ips = by_severity.get(sev, [])
        if ips:
            print(f"  {sev:<10}: {len(ips)} IPs — {', '.join(ips)}")
    print(f"{'='*60}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - AbuseIPDB Lookup")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip",   help="Single IP to check")
    group.add_argument("--bulk", action="store_true", help="Bulk scan IPs from a log file")
    parser.add_argument("--file",   help="Log file path (for --bulk mode)")
    parser.add_argument("--days",   type=int, default=30, help="Max age of reports in days (default: 30)")
    parser.add_argument("--output", help="Optional: save results to JSON")
    args = parser.parse_args()

    if args.ip:
        result = check_ip(args.ip, args.days)
        print_result(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[+] Result saved to {args.output}")

    elif args.bulk:
        if not args.file:
            print("[!] --bulk requires --file <path>")
            return
        results = bulk_check(args.file, args.days)
        print_bulk_summary(results)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
