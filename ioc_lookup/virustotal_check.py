"""
virustotal_check.py
-------------------
SOC L1 Log Analysis — VirusTotal IOC Lookup
Check IPs, domains, URLs, and file hashes against VirusTotal API v3.

Usage:
    python virustotal_check.py --ip 203.0.113.42
    python virustotal_check.py --domain evil-c2-domain.ru
    python virustotal_check.py --hash d41d8cd98f00b204e9800998ecf8427e
    python virustotal_check.py --url http://malicious.example.com/payload
    python virustotal_check.py --ip 203.0.113.42 --output result.json
"""

import os
import json
import argparse
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS  = {"x-apikey": API_KEY}

MALICIOUS_THRESHOLD = 3   # N+ engines flagging = HIGH severity

# ── API Calls ─────────────────────────────────────────────────────────────────

def vt_get(endpoint: str) -> dict:
    if not API_KEY:
        print("[!] No VIRUSTOTAL_API_KEY set in .env — using mock response")
        return mock_response(endpoint)
    try:
        resp = requests.get(f"{BASE_URL}/{endpoint}", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"error": "not_found"}
        raise


def check_ip(ip: str) -> dict:
    data = vt_get(f"ip_addresses/{ip}")
    return parse_result(data, ioc_type="ip", ioc_value=ip)


def check_domain(domain: str) -> dict:
    data = vt_get(f"domains/{domain}")
    return parse_result(data, ioc_type="domain", ioc_value=domain)


def check_hash(file_hash: str) -> dict:
    data = vt_get(f"files/{file_hash}")
    return parse_result(data, ioc_type="hash", ioc_value=file_hash)


def check_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = vt_get(f"urls/{url_id}")
    return parse_result(data, ioc_type="url", ioc_value=url)


# ── Response Parser ───────────────────────────────────────────────────────────

def parse_result(data: dict, ioc_type: str, ioc_value: str) -> dict:
    if "error" in data:
        return {
            "ioc_type":  ioc_type,
            "ioc_value": ioc_value,
            "status":    "NOT_FOUND",
            "severity":  "UNKNOWN",
            "summary":   "No data found in VirusTotal"
        }

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    # Severity
    if malicious >= MALICIOUS_THRESHOLD:
        severity = "CRITICAL"
    elif malicious > 0 or suspicious >= 2:
        severity = "HIGH"
    elif suspicious > 0:
        severity = "MEDIUM"
    else:
        severity = "CLEAN"

    result = {
        "ioc_type":         ioc_type,
        "ioc_value":        ioc_value,
        "severity":         severity,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "harmless_engines":  harmless,
        "total_engines":     total,
        "reputation_score":  attrs.get("reputation", "N/A"),
        "queried_at":        datetime.utcnow().isoformat() + "Z",
    }

    # Type-specific fields
    if ioc_type == "ip":
        result["country"]        = attrs.get("country", "N/A")
        result["asn"]            = attrs.get("asn", "N/A")
        result["as_owner"]       = attrs.get("as_owner", "N/A")
        result["network"]        = attrs.get("network", "N/A")

    elif ioc_type == "domain":
        result["registrar"]      = attrs.get("registrar", "N/A")
        result["creation_date"]  = attrs.get("creation_date", "N/A")
        result["categories"]     = attrs.get("categories", {})

    elif ioc_type == "hash":
        result["file_name"]      = attrs.get("meaningful_name", "N/A")
        result["file_type"]      = attrs.get("type_description", "N/A")
        result["file_size"]      = attrs.get("size", "N/A")
        result["first_seen"]     = attrs.get("first_submission_date", "N/A")

    # Grab top malicious engine verdicts
    engines = attrs.get("last_analysis_results", {})
    malicious_engines = [
        {"engine": name, "verdict": info.get("result", "N/A")}
        for name, info in engines.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:10]
    result["engine_verdicts"] = malicious_engines

    return result


# ── Mock Response (no API key) ────────────────────────────────────────────────

def mock_response(endpoint: str) -> dict:
    """Return realistic mock data when no API key is configured."""
    if "ip_addresses" in endpoint:
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 30, "undetected": 40},
            "reputation": -25, "country": "RU", "asn": 12345,
            "as_owner": "MOCK-ASN", "network": "203.0.113.0/24",
            "last_analysis_results": {
                "Avast":      {"category": "malicious", "result": "SSH-BruteForce"},
                "Kaspersky":  {"category": "malicious", "result": "Trojan.Brute"},
                "Bitdefender":{"category": "malicious", "result": "Malicious"},
            }
        }}}
    elif "domains" in endpoint:
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 20, "suspicious": 5, "harmless": 5, "undetected": 20},
            "reputation": -45, "registrar": "MockRegistrar",
            "categories": {"Forcepoint ThreatSeeker": "malware call-home"},
            "last_analysis_results": {
                "Avast":     {"category": "malicious", "result": "C2-Domain"},
                "Kaspersky": {"category": "malicious", "result": "Trojan.C2"},
            }
        }}}
    elif "files" in endpoint:
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 35, "suspicious": 3, "harmless": 0, "undetected": 12},
            "reputation": -80, "meaningful_name": "payload.exe",
            "type_description": "Win32 EXE", "size": 204800,
            "last_analysis_results": {
                "Avast":     {"category": "malicious", "result": "Win32:Malware-gen"},
                "Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Generic"},
            }
        }}}
    return {"error": "not_found"}


# ── Print Result ──────────────────────────────────────────────────────────────

def print_result(result: dict):
    SEV_COLORS = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "CLEAN":    "🟢",
        "UNKNOWN":  "⚪",
    }

    icon = SEV_COLORS.get(result["severity"], "⚪")
    print(f"\n{'='*60}")
    print(f"  VirusTotal Lookup Result")
    print(f"{'='*60}")
    print(f"  IOC Type     : {result['ioc_type'].upper()}")
    print(f"  IOC Value    : {result['ioc_value']}")
    print(f"  Severity     : {icon} {result['severity']}")

    if result.get("malicious_engines") is not None:
        total = result.get("total_engines", 1)
        mal   = result.get("malicious_engines", 0)
        sus   = result.get("suspicious_engines", 0)
        print(f"  Detections   : {mal} malicious, {sus} suspicious / {total} engines")
        print(f"  Reputation   : {result.get('reputation_score', 'N/A')}")

    # Type-specific
    for field in ["country", "asn", "as_owner", "registrar", "categories",
                  "file_name", "file_type", "file_size", "first_seen"]:
        if result.get(field) and result[field] != "N/A":
            print(f"  {field.replace('_',' ').capitalize():<15}: {result[field]}")

    if result.get("engine_verdicts"):
        print(f"\n  ── Engine Verdicts ──────────────────────────────────")
        for ev in result["engine_verdicts"]:
            print(f"    {ev['engine']:<25} {ev['verdict']}")

    print(f"\n  Queried at   : {result.get('queried_at', 'N/A')}")
    print(f"{'='*60}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - VirusTotal IOC Lookup")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip",     help="IP address to check")
    group.add_argument("--domain", help="Domain to check")
    group.add_argument("--hash",   help="File hash (MD5/SHA1/SHA256) to check")
    group.add_argument("--url",    help="URL to check")
    parser.add_argument("--output", help="Optional: save result to JSON")
    args = parser.parse_args()

    if args.ip:
        result = check_ip(args.ip)
    elif args.domain:
        result = check_domain(args.domain)
    elif args.hash:
        result = check_hash(args.hash)
    else:
        result = check_url(args.url)

    print_result(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Result saved to {args.output}")


if __name__ == "__main__":
    main()
