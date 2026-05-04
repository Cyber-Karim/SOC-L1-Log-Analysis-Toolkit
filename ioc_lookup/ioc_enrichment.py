"""
ioc_enrichment.py
-----------------
SOC L1 Log Analysis — Unified IOC Enrichment Engine
Runs an IOC through ALL three threat intel sources simultaneously:
    - VirusTotal  (malware detections, engine verdicts)
    - AbuseIPDB   (abuse reports, confidence score)
    - Shodan      (open ports, services, CVEs)

Produces a single enriched report for incident documentation.

Usage:
    python ioc_enrichment.py --ip 203.0.113.42
    python ioc_enrichment.py --ip 203.0.113.42 --output enriched_report.json
    python ioc_enrichment.py --domain evil-c2-domain.ru
    python ioc_enrichment.py --hash d41d8cd98f00b204e9800998ecf8427e
    python ioc_enrichment.py --auto-scan --file ../logs/auth.log
"""

import os
import re
import json
import argparse
import concurrent.futures
from datetime import datetime
from dotenv import load_dotenv

# Import our individual lookup modules
from virustotal_check  import check_ip   as vt_ip,   check_domain, check_hash
from abuseipdb_check   import check_ip   as abuse_ip, extract_ips_from_log
from shodan_lookup     import check_ip   as shodan_ip

load_dotenv()

# ── Severity Ranking ──────────────────────────────────────────────────────────

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0, "UNKNOWN": 0}

def highest_severity(*severities) -> str:
    ranked = sorted(severities, key=lambda s: SEV_RANK.get(s, 0), reverse=True)
    return ranked[0] if ranked else "UNKNOWN"


# ── Enrichment ────────────────────────────────────────────────────────────────

def enrich_ip(ip: str) -> dict:
    """Query all three sources in parallel and merge results."""
    print(f"\n[*] Enriching IP: {ip}")
    print(f"    Querying VirusTotal, AbuseIPDB, and Shodan simultaneously...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        fut_vt    = executor.submit(vt_ip, ip)
        fut_abuse = executor.submit(abuse_ip, ip)
        fut_shodan= executor.submit(shodan_ip, ip)

        vt_result     = fut_vt.result()
        abuse_result  = fut_abuse.result()
        shodan_result = fut_shodan.result()

    overall_severity = highest_severity(
        vt_result.get("severity", "UNKNOWN"),
        abuse_result.get("severity", "UNKNOWN"),
        shodan_result.get("severity", "UNKNOWN"),
    )

    # Build verdict
    verdict_parts = []
    vt_det = vt_result.get("malicious_engines", 0)
    ab_score = abuse_result.get("abuse_confidence_score", 0)
    open_ports = shodan_result.get("open_ports", [])
    cves = shodan_result.get("cves", [])

    if vt_det > 0:
        verdict_parts.append(f"Flagged by {vt_det} AV engines on VirusTotal")
    if ab_score > 25:
        verdict_parts.append(f"AbuseIPDB score {ab_score}/100")
    if cves:
        verdict_parts.append(f"{len(cves)} CVE(s) found via Shodan")
    if shodan_result.get("risky_ports"):
        verdict_parts.append(f"Risky ports open: {shodan_result['risky_ports']}")
    if abuse_result.get("is_tor"):
        verdict_parts.append("TOR exit node")
    if not verdict_parts:
        verdict_parts.append("No significant threats detected")

    return {
        "ioc_type":           "ip",
        "ioc_value":          ip,
        "overall_severity":   overall_severity,
        "verdict":            " | ".join(verdict_parts),
        "enriched_at":        datetime.utcnow().isoformat() + "Z",
        "virustotal":         vt_result,
        "abuseipdb":          abuse_result,
        "shodan":             shodan_result,
        "recommendation":     get_recommendation(overall_severity, ab_score, vt_det, cves),
    }


def enrich_domain(domain: str) -> dict:
    """Domain: only VirusTotal (AbuseIPDB/Shodan are IP-focused)."""
    print(f"\n[*] Enriching domain: {domain}")
    vt_result = check_domain(domain)
    return {
        "ioc_type":         "domain",
        "ioc_value":        domain,
        "overall_severity": vt_result.get("severity", "UNKNOWN"),
        "verdict":          f"VirusTotal: {vt_result.get('malicious_engines',0)} malicious engines",
        "enriched_at":      datetime.utcnow().isoformat() + "Z",
        "virustotal":       vt_result,
        "recommendation":   get_recommendation(vt_result.get("severity","UNKNOWN")),
    }


def enrich_hash(file_hash: str) -> dict:
    """File hash: VirusTotal only."""
    print(f"\n[*] Enriching hash: {file_hash}")
    vt_result = check_hash(file_hash)
    return {
        "ioc_type":         "hash",
        "ioc_value":        file_hash,
        "overall_severity": vt_result.get("severity", "UNKNOWN"),
        "verdict":          f"VirusTotal: {vt_result.get('malicious_engines',0)} malicious engines",
        "enriched_at":      datetime.utcnow().isoformat() + "Z",
        "virustotal":       vt_result,
        "recommendation":   get_recommendation(vt_result.get("severity","UNKNOWN")),
    }


# ── Recommendation Engine ─────────────────────────────────────────────────────

def get_recommendation(severity: str, abuse_score: int = 0,
                        vt_detections: int = 0, cves: list = None) -> str:
    cves = cves or []
    if severity == "CRITICAL":
        actions = ["🔴 IMMEDIATE ACTION REQUIRED"]
        actions.append("1. Block IP at perimeter firewall and cloud WAF NOW")
        actions.append("2. Isolate any internal hosts that communicated with this IP")
        actions.append("3. Pull full session logs for the past 72 hours")
        actions.append("4. Escalate to Tier 2 / Incident Response team")
        if cves:
            actions.append(f"5. Review CVEs: {', '.join(cves[:3])}")
        return "\n".join(actions)
    elif severity == "HIGH":
        return ("Block IP at perimeter firewall. Review all traffic from this source. "
                "Check for successful connections. Monitor affected assets for 48h.")
    elif severity == "MEDIUM":
        return ("Add IP to watchlist. Investigate any successful connections. "
                "Consider temporary block. Review logs for related indicators.")
    elif severity == "LOW":
        return "Monitor IP. No immediate action required. Review if activity increases."
    else:
        return "No threat detected. Continue standard monitoring."


# ── Auto Scan from Log ────────────────────────────────────────────────────────

def auto_scan_log(filepath: str, max_ips: int = 10) -> list:
    ips = extract_ips_from_log(filepath)[:max_ips]
    print(f"[*] Auto-scanning {len(ips)} IPs from {filepath}")
    results = []
    for ip in ips:
        result = enrich_ip(ip)
        results.append(result)
    return results


# ── Print Report ──────────────────────────────────────────────────────────────

def print_enriched_report(result: dict):
    SEV_ICONS = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","CLEAN":"🟢","UNKNOWN":"⚪"}
    icon = SEV_ICONS.get(result.get("overall_severity","UNKNOWN"),"⚪")

    print(f"\n{'='*65}")
    print(f"  🔍 IOC ENRICHMENT REPORT")
    print(f"{'='*65}")
    print(f"  IOC Type         : {result.get('ioc_type','').upper()}")
    print(f"  IOC Value        : {result.get('ioc_value')}")
    print(f"  Overall Severity : {icon} {result.get('overall_severity')}")
    print(f"  Verdict          : {result.get('verdict')}")
    print(f"  Enriched At      : {result.get('enriched_at')}")

    # VirusTotal summary
    vt = result.get("virustotal", {})
    if vt:
        print(f"\n  ── VirusTotal ────────────────────────────────────────")
        print(f"  Malicious Engines : {vt.get('malicious_engines',0)} / {vt.get('total_engines',0)}")
        print(f"  Reputation Score  : {vt.get('reputation_score','N/A')}")
        for ev in vt.get("engine_verdicts", [])[:3]:
            print(f"  • {ev['engine']:<25} {ev['verdict']}")

    # AbuseIPDB summary
    ab = result.get("abuseipdb", {})
    if ab:
        print(f"\n  ── AbuseIPDB ─────────────────────────────────────────")
        print(f"  Confidence Score  : {ab.get('abuse_confidence_score','N/A')} / 100")
        print(f"  Total Reports     : {ab.get('total_reports','N/A')}")
        print(f"  Country / ISP     : {ab.get('country','N/A')} / {ab.get('isp','N/A')}")
        if ab.get("abuse_categories"):
            print(f"  Categories        : {', '.join(ab['abuse_categories'])}")
        if ab.get("is_tor"):
            print(f"  ⚠️  TOR Exit Node  : YES")

    # Shodan summary
    sh = result.get("shodan", {})
    if sh:
        print(f"\n  ── Shodan ────────────────────────────────────────────")
        print(f"  Location          : {sh.get('city','N/A')}, {sh.get('country','N/A')}")
        print(f"  Org / ASN         : {sh.get('org','N/A')} / {sh.get('asn','N/A')}")
        print(f"  Open Ports        : {sh.get('open_ports', [])}")
        if sh.get("risky_ports"):
            print(f"  ⚠️  Risky Ports    : {sh.get('risky_ports')}")
        if sh.get("cves"):
            print(f"  🚨 CVEs           : {', '.join(sh['cves'][:5])}")

    # Recommendation
    print(f"\n  ── Recommendation ────────────────────────────────────")
    for line in result.get("recommendation","").split("\n"):
        print(f"  {line}")

    print(f"\n{'='*65}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Unified IOC Enrichment")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip",        help="IP address to enrich")
    group.add_argument("--domain",    help="Domain to enrich")
    group.add_argument("--hash",      help="File hash to enrich")
    group.add_argument("--auto-scan", action="store_true", help="Auto-extract and scan IPs from log file")
    parser.add_argument("--file",     help="Log file for auto-scan mode")
    parser.add_argument("--max-ips",  type=int, default=10, help="Max IPs to scan in auto mode (default: 10)")
    parser.add_argument("--output",   help="Save results to JSON")
    args = parser.parse_args()

    if args.ip:
        result = enrich_ip(args.ip)
        print_enriched_report(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.domain:
        result = enrich_domain(args.domain)
        print_enriched_report(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.hash:
        result = enrich_hash(args.hash)
        print_enriched_report(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.auto_scan:
        if not args.file:
            print("[!] --auto-scan requires --file <path>")
            return
        results = auto_scan_log(args.file, args.max_ips)
        for r in results:
            print_enriched_report(r)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"[+] All results saved to {args.output}")


if __name__ == "__main__":
    main()
