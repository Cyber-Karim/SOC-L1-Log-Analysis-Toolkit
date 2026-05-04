"""
web_attack.py
-------------
SOC L1 Log Analysis — Web Attack Detection Engine
Detects injection attacks, web scanning, and exploitation attempts
from Apache/Nginx access logs.

Detection Types:
    - SQL Injection           : SQLi payloads in URI/query strings
    - Cross-Site Scripting    : XSS payloads in requests
    - Path/Directory Traversal: Attempts to read files outside webroot
    - Web Scanner             : Known scanner user agents (sqlmap, Nikto, etc.)
    - Directory Enumeration   : High 404 rate from single IP
    - Sensitive File Access   : Attempts to read .env, configs, backups
    - Command Injection       : Shell metacharacters in parameters

Usage:
    python web_attack.py --file ../logs/apache_access.log
    python web_attack.py --file ../logs/apache_access.log --output report.json --threshold 5
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote

# ── Log Pattern ───────────────────────────────────────────────────────────────

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" (?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

# ── Attack Signatures ─────────────────────────────────────────────────────────

SQLI_SIGNATURES = [
    ("UNION SELECT",    "CRITICAL"),
    ("' OR '1'='1",     "CRITICAL"),
    ("OR 1=1",          "HIGH"),
    ("DROP TABLE",      "CRITICAL"),
    ("INSERT INTO",     "HIGH"),
    ("SLEEP(",          "HIGH"),
    ("BENCHMARK(",      "HIGH"),
    ("xp_cmdshell",     "CRITICAL"),
    ("INFORMATION_SCHEMA", "HIGH"),
    ("--",              "MEDIUM"),
    ("';",              "MEDIUM"),
    ("%27",             "MEDIUM"),
    ("1%3D1",           "MEDIUM"),
]

XSS_SIGNATURES = [
    ("<script",         "HIGH"),
    ("javascript:",     "HIGH"),
    ("onerror=",        "HIGH"),
    ("onload=",         "MEDIUM"),
    ("alert(",          "MEDIUM"),
    ("document.cookie", "CRITICAL"),
    ("eval(",           "HIGH"),
    ("<img src=",       "MEDIUM"),
    ("%3Cscript",       "HIGH"),
    ("vbscript:",       "HIGH"),
]

TRAVERSAL_SIGNATURES = [
    ("../",             "HIGH"),
    ("..\\",            "HIGH"),
    ("%2e%2e%2f",       "HIGH"),
    ("etc/passwd",      "CRITICAL"),
    ("etc/shadow",      "CRITICAL"),
    ("win.ini",         "HIGH"),
    ("boot.ini",        "HIGH"),
    ("/proc/self/environ", "CRITICAL"),
    ("%252e%252e",      "HIGH"),
]

CMD_INJECTION_SIGNATURES = [
    (";ls",             "CRITICAL"),
    (";id",             "CRITICAL"),
    (";cat ",           "CRITICAL"),
    ("|whoami",         "CRITICAL"),
    ("`id`",            "CRITICAL"),
    ("$(id)",           "CRITICAL"),
    ("%3Bls",           "HIGH"),
    ("&&id",            "HIGH"),
    (";wget ",          "CRITICAL"),
    (";curl ",          "CRITICAL"),
]

SUSPICIOUS_USER_AGENTS = {
    "sqlmap":       "CRITICAL",
    "nikto":        "HIGH",
    "nmap":         "HIGH",
    "masscan":      "HIGH",
    "nuclei":       "HIGH",
    "dirbuster":    "MEDIUM",
    "gobuster":     "MEDIUM",
    "wfuzz":        "MEDIUM",
    "hydra":        "HIGH",
    "metasploit":   "CRITICAL",
    "havij":        "CRITICAL",
    "acunetix":     "HIGH",
    "nessus":       "HIGH",
    "openvas":      "MEDIUM",
    "zgrab":        "MEDIUM",
}

SENSITIVE_PATHS = {
    "/.env":            "CRITICAL",
    "/.git":            "HIGH",
    "/wp-config.php":   "CRITICAL",
    "/config.php":      "HIGH",
    "/.htaccess":       "MEDIUM",
    "/backup":          "HIGH",
    "/phpmyadmin":      "HIGH",
    "/adminer":         "HIGH",
    "/server-status":   "MEDIUM",
    "/web.config":      "CRITICAL",
    "/.aws/credentials":"CRITICAL",
    "/id_rsa":          "CRITICAL",
    "/shadow":          "CRITICAL",
}

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_log_file(filepath: str) -> list:
    entries = []
    with open(filepath, "r") as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if m:
                d = m.groupdict()
                d["decoded_uri"] = unquote(d["uri"]).lower()
                d["status"]      = int(d["status"])
                entries.append(d)
    return entries


# ── Detection Helpers ─────────────────────────────────────────────────────────

def match_signatures(text: str, signatures: list) -> tuple[str, str] | None:
    for pattern, severity in signatures:
        if pattern.lower() in text:
            return pattern, severity
    return None


# ── Detections ────────────────────────────────────────────────────────────────

def detect_sqli(entries: list) -> list:
    alerts = []
    for e in entries:
        hit = match_signatures(e["decoded_uri"], SQLI_SIGNATURES)
        if hit:
            pattern, severity = hit
            alerts.append({
                "alert":          "SQL_INJECTION_ATTEMPT",
                "severity":       severity,
                "source_ip":      e["ip"],
                "method":         e["method"],
                "uri":            e["uri"],
                "decoded_uri":    e["decoded_uri"],
                "matched_pattern": pattern,
                "http_status":    e["status"],
                "timestamp":      e["timestamp"],
                "recommendation": "Review DB logs, check WAF rules, verify input sanitization"
            })
    return alerts


def detect_xss(entries: list) -> list:
    alerts = []
    for e in entries:
        hit = match_signatures(e["decoded_uri"], XSS_SIGNATURES)
        if hit:
            pattern, severity = hit
            alerts.append({
                "alert":          "XSS_ATTEMPT",
                "severity":       severity,
                "source_ip":      e["ip"],
                "uri":            e["uri"],
                "matched_pattern": pattern,
                "http_status":    e["status"],
                "timestamp":      e["timestamp"],
                "recommendation": "Verify output encoding, check CSP headers, review affected endpoint"
            })
    return alerts


def detect_path_traversal(entries: list) -> list:
    alerts = []
    for e in entries:
        hit = match_signatures(e["decoded_uri"], TRAVERSAL_SIGNATURES)
        if hit:
            pattern, severity = hit
            alerts.append({
                "alert":          "PATH_TRAVERSAL_ATTEMPT",
                "severity":       severity,
                "source_ip":      e["ip"],
                "uri":            e["uri"],
                "decoded_uri":    e["decoded_uri"],
                "matched_pattern": pattern,
                "http_status":    e["status"],
                "timestamp":      e["timestamp"],
                "recommendation": "Check if file was served (200), verify chroot/sandbox, patch immediately if successful"
            })
    return alerts


def detect_cmd_injection(entries: list) -> list:
    alerts = []
    for e in entries:
        hit = match_signatures(e["decoded_uri"], CMD_INJECTION_SIGNATURES)
        if hit:
            pattern, severity = hit
            alerts.append({
                "alert":          "COMMAND_INJECTION_ATTEMPT",
                "severity":       severity,
                "source_ip":      e["ip"],
                "uri":            e["uri"],
                "matched_pattern": pattern,
                "http_status":    e["status"],
                "timestamp":      e["timestamp"],
                "recommendation": "CRITICAL — Check server process list, review shell history, isolate if 200 response"
            })
    return alerts


def detect_web_scanners(entries: list) -> list:
    alerts = []
    seen = set()
    for e in entries:
        ua = e["user_agent"].lower()
        for tool, severity in SUSPICIOUS_USER_AGENTS.items():
            if tool in ua:
                key = (e["ip"], tool)
                if key not in seen:
                    seen.add(key)
                    alerts.append({
                        "alert":          "WEB_SCANNER_DETECTED",
                        "severity":       severity,
                        "source_ip":      e["ip"],
                        "scanner_tool":   tool,
                        "user_agent":     e["user_agent"],
                        "first_seen":     e["timestamp"],
                        "recommendation": f"Block IP immediately — active {tool} scan detected"
                    })
                break
    return alerts


def detect_sensitive_files(entries: list) -> list:
    alerts = []
    seen = set()
    for e in entries:
        uri_lower = e["decoded_uri"]
        for path, severity in SENSITIVE_PATHS.items():
            if path.lower() in uri_lower:
                key = (e["ip"], path)
                if key not in seen:
                    seen.add(key)
                    success = e["status"] == 200
                    alerts.append({
                        "alert":          "SENSITIVE_FILE_ACCESS",
                        "severity":       "CRITICAL" if success else severity,
                        "source_ip":      e["ip"],
                        "path_requested": path,
                        "http_status":    e["status"],
                        "was_successful": success,
                        "timestamp":      e["timestamp"],
                        "recommendation": ("FILE WAS SERVED — treat as data breach, rotate secrets immediately"
                                           if success else
                                           "Access was blocked — monitor for repeated attempts")
                    })
                break
    return alerts


def detect_directory_enum(entries: list, threshold: int) -> list:
    alerts = []
    not_found_by_ip = defaultdict(list)

    for e in entries:
        if e["status"] == 404:
            not_found_by_ip[e["ip"]].append(e)

    for ip, reqs in not_found_by_ip.items():
        if len(reqs) >= threshold:
            unique_paths = list({r["uri"] for r in reqs})
            alerts.append({
                "alert":          "DIRECTORY_ENUMERATION",
                "severity":       "MEDIUM",
                "source_ip":      ip,
                "total_404s":     len(reqs),
                "unique_paths":   len(unique_paths),
                "sample_paths":   unique_paths[:5],
                "recommendation": "Block IP, review what paths were attempted, check for follow-up exploitation"
            })

    return alerts


# ── Run All Detections ────────────────────────────────────────────────────────

def run_detections(entries: list, enum_threshold: int) -> list:
    all_alerts = []
    all_alerts += detect_web_scanners(entries)
    all_alerts += detect_sqli(entries)
    all_alerts += detect_xss(entries)
    all_alerts += detect_path_traversal(entries)
    all_alerts += detect_cmd_injection(entries)
    all_alerts += detect_sensitive_files(entries)
    all_alerts += detect_directory_enum(entries, enum_threshold)
    return all_alerts


# ── Summary ───────────────────────────────────────────────────────────────────

def build_summary(entries: list, alerts: list) -> dict:
    status_counts = defaultdict(int)
    ip_counts     = defaultdict(int)
    for e in entries:
        status_counts[str(e["status"])] += 1
        ip_counts[e["ip"]] += 1

    alert_type_counts = defaultdict(int)
    for a in alerts:
        alert_type_counts[a["alert"]] += 1

    return {
        "total_requests":    len(entries),
        "total_alerts":      len(alerts),
        "status_codes":      dict(status_counts),
        "alert_breakdown":   dict(alert_type_counts),
        "top_attacking_ips": dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(summary: dict, alerts: list):
    print("\n" + "="*60)
    print("  WEB ATTACK DETECTION REPORT")
    print("="*60)
    print(f"  Total Requests     : {summary['total_requests']}")
    print(f"  Total Alerts       : {summary['total_alerts']}")

    print("\n── Alert Type Breakdown ──────────────────────────────────")
    for alert_type, count in summary["alert_breakdown"].items():
        print(f"  {alert_type:<35} {count}")

    print("\n── HTTP Status Code Distribution ─────────────────────────")
    for code, count in sorted(summary["status_codes"].items()):
        print(f"  HTTP {code}   {count}")

    print("\n── Top Attacking IPs ─────────────────────────────────────")
    for ip, count in list(summary["top_attacking_ips"].items())[:5]:
        print(f"  {ip:<20} {count} requests")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in alerts:
            print(f"\n  [{alert['severity']}] {alert['alert']}")
            for k, v in alert.items():
                if k not in ("alert", "severity") and v is not None:
                    val = ", ".join(map(str, v)) if isinstance(v, list) else v
                    print(f"  {k.replace('_',' ').capitalize():<26}: {val}")
    else:
        print("\n  ✅ No web attacks detected.")

    print("\n" + "="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Web Attack Detector")
    parser.add_argument("--file",      required=True, help="Path to Apache/Nginx access log")
    parser.add_argument("--threshold", type=int, default=5, help="Directory enum 404 threshold (default: 5)")
    parser.add_argument("--output",    help="Optional: save alerts to JSON")
    args = parser.parse_args()

    entries = parse_log_file(args.file)
    alerts  = run_detections(entries, args.threshold)
    summary = build_summary(entries, alerts)

    print_report(summary, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"summary": summary, "alerts": alerts}, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
