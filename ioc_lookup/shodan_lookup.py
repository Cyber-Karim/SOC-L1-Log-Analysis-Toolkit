"""
shodan_lookup.py
----------------
SOC L1 Log Analysis — Shodan Host Intelligence Lookup
Retrieve open ports, services, banners, CVEs, and geolocation for an IP.

Usage:
    python shodan_lookup.py --ip 203.0.113.42
    python shodan_lookup.py --ip 203.0.113.42 --output result.json
    python shodan_lookup.py --bulk --file ../logs/auth.log
"""

import os
import re
import json
import time
import argparse
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY", "")

# ── Shodan Query ──────────────────────────────────────────────────────────────

def check_ip(ip: str) -> dict:
    if not API_KEY:
        print(f"[!] No SHODAN_API_KEY set — using mock response for {ip}")
        return mock_response(ip)

    try:
        import shodan
        api  = shodan.Shodan(API_KEY)
        host = api.host(ip)
        return parse_result(host, ip)
    except ImportError:
        print("[!] shodan library not installed. Run: pip install shodan")
        return mock_response(ip)
    except Exception as e:
        return {"ip": ip, "error": str(e), "severity": "UNKNOWN"}


# ── Response Parser ───────────────────────────────────────────────────────────

def parse_result(host: dict, ip: str) -> dict:
    open_ports = host.get("ports", [])
    vulns      = list(host.get("vulns", {}).keys())
    hostnames  = host.get("hostnames", [])
    country    = host.get("country_name", "N/A")
    city       = host.get("city", "N/A")
    org        = host.get("org", "N/A")
    isp        = host.get("isp", "N/A")
    asn        = host.get("asn", "N/A")
    last_update = host.get("last_update", "N/A")
    tags       = host.get("tags", [])

    # Risky ports
    HIGH_RISK_PORTS = {21,22,23,25,53,80,443,445,1433,3306,3389,4444,5432,5900,6379,8080,27017}
    risky_open = [p for p in open_ports if p in HIGH_RISK_PORTS]

    # Service banners
    services = []
    for item in host.get("data", []):
        services.append({
            "port":      item.get("port"),
            "protocol":  item.get("transport", "tcp"),
            "product":   item.get("product", "N/A"),
            "version":   item.get("version", "N/A"),
            "banner":    item.get("data", "")[:120].strip(),
            "cpe":       item.get("cpe", []),
        })

    # Severity based on open risky ports + CVEs
    if vulns or 3389 in open_ports or 4444 in open_ports:
        severity = "CRITICAL"
    elif len(risky_open) >= 3:
        severity = "HIGH"
    elif risky_open:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "ip":            ip,
        "severity":      severity,
        "country":       country,
        "city":          city,
        "org":           org,
        "isp":           isp,
        "asn":           asn,
        "hostnames":     hostnames,
        "tags":          tags,
        "open_ports":    sorted(open_ports),
        "risky_ports":   sorted(risky_open),
        "cves":          vulns,
        "services":      services,
        "last_update":   last_update,
        "queried_at":    datetime.utcnow().isoformat() + "Z",
    }


# ── Mock Response ─────────────────────────────────────────────────────────────

def mock_response(ip: str) -> dict:
    return {
        "ip":           ip,
        "severity":     "HIGH",
        "country":      "Russia",
        "city":         "Moscow",
        "org":          "Mock Hosting LLC",
        "isp":          "Mock ISP",
        "asn":          "AS12345",
        "hostnames":    ["mock-host.example.ru"],
        "tags":         ["self-signed", "scanner"],
        "open_ports":   [22, 80, 443, 3306, 8080],
        "risky_ports":  [22, 3306],
        "cves":         [],
        "services": [
            {"port": 22,   "protocol": "tcp", "product": "OpenSSH",  "version": "7.4",
             "banner": "SSH-2.0-OpenSSH_7.4", "cpe": ["cpe:/a:openbsd:openssh:7.4"]},
            {"port": 80,   "protocol": "tcp", "product": "nginx",    "version": "1.14.0",
             "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0", "cpe": []},
            {"port": 3306, "protocol": "tcp", "product": "MySQL",    "version": "5.7.38",
             "banner": "5.7.38-log MySQL Community Server", "cpe": ["cpe:/a:mysql:mysql:5.7.38"]},
        ],
        "last_update": "2026-04-25T20:00:00",
        "queried_at":  datetime.utcnow().isoformat() + "Z",
    }


# ── Bulk Scan ─────────────────────────────────────────────────────────────────

def extract_ips_from_log(filepath: str) -> list:
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    private    = ("10.", "192.168.", "172.", "127.", "0.")
    ips = set()
    with open(filepath) as f:
        for line in f:
            for ip in ip_pattern.findall(line):
                if not any(ip.startswith(p) for p in private):
                    ips.add(ip)
    return sorted(ips)


def bulk_check(filepath: str, delay: float = 2.0) -> list:
    ips = extract_ips_from_log(filepath)
    print(f"[*] Found {len(ips)} unique external IPs")
    results = []
    for i, ip in enumerate(ips, 1):
        print(f"[{i}/{len(ips)}] Checking {ip} via Shodan...", end=" ")
        result = check_ip(ip)
        ports  = result.get("open_ports", [])
        cves   = result.get("cves", [])
        print(f"Ports: {len(ports)} | CVEs: {len(cves)} | {result.get('severity','?')}")
        results.append(result)
        time.sleep(delay)
    return results


# ── Print Result ──────────────────────────────────────────────────────────────

def print_result(result: dict):
    SEV_ICONS = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","UNKNOWN":"⚪"}
    icon = SEV_ICONS.get(result.get("severity","UNKNOWN"),"⚪")

    print(f"\n{'='*60}")
    print(f"  Shodan Host Intelligence Report")
    print(f"{'='*60}")
    print(f"  IP Address     : {result.get('ip')}")
    print(f"  Severity       : {icon} {result.get('severity')}")
    print(f"  Location       : {result.get('city')}, {result.get('country')}")
    print(f"  Organization   : {result.get('org')}")
    print(f"  ISP            : {result.get('isp')}")
    print(f"  ASN            : {result.get('asn')}")
    print(f"  Hostnames      : {', '.join(result.get('hostnames', [])) or 'None'}")
    print(f"  Tags           : {', '.join(result.get('tags', [])) or 'None'}")
    print(f"  Last Updated   : {result.get('last_update')}")

    ports = result.get("open_ports", [])
    risky = result.get("risky_ports", [])
    print(f"\n  ── Open Ports ({len(ports)}) ────────────────────────────────")
    print(f"  {ports}")
    if risky:
        print(f"  ⚠️  High-risk ports open: {risky}")

    cves = result.get("cves", [])
    if cves:
        print(f"\n  ── CVEs Detected ─────────────────────────────────────")
        for cve in cves:
            print(f"  🚨 {cve}")

    services = result.get("services", [])
    if services:
        print(f"\n  ── Services & Banners ────────────────────────────────")
        for svc in services:
            product = f"{svc.get('product','')} {svc.get('version','')}".strip()
            print(f"  Port {svc.get('port'):<6}/{svc.get('protocol'):<4} {product}")
            if svc.get("banner"):
                banner = svc["banner"].replace("\r\n", " | ")[:70]
                print(f"         Banner: {banner}")

    print(f"\n  Queried at     : {result.get('queried_at')}")
    print(f"{'='*60}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Shodan Host Lookup")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip",   help="Single IP to look up")
    group.add_argument("--bulk", action="store_true", help="Bulk lookup from log file")
    parser.add_argument("--file",   help="Log file for bulk mode")
    parser.add_argument("--output", help="Save results to JSON")
    args = parser.parse_args()

    if args.ip:
        result = check_ip(args.ip)
        print_result(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[+] Result saved to {args.output}")

    elif args.bulk:
        if not args.file:
            print("[!] --bulk requires --file <path>")
            return
        results = bulk_check(args.file)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
