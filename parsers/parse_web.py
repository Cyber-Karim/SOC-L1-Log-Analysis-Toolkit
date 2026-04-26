"""
parse_web.py
------------
SOC L1 Log Analysis — Apache / Nginx Access Log Parser
Detects web scanning, SQLi attempts, path traversal, and suspicious user agents.

Usage:
    python parse_web.py --file ../logs/apache_access.log
    python parse_web.py --file ../logs/apache_access.log --output report.json
"""

import re
import json
import argparse
from collections import defaultdict
from urllib.parse import unquote

# ── Regex Pattern ─────────────────────────────────────────────────────────────

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" (?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

# ── Threat Signatures ─────────────────────────────────────────────────────────

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
    "dirbuster", "gobuster", "wfuzz", "hydra", "metasploit",
    "python-requests", "curl", "wget", "scrapy", "libwww-perl",
]

SQLI_PATTERNS = [
    "' OR ", "1=1", "1 OR 1", "UNION SELECT", "DROP TABLE",
    "INSERT INTO", "--", "xp_cmdshell", "exec(", "SLEEP(",
    "BENCHMARK(", "'; --", "%27", "%3D",
]

PATH_TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e", "%2f", "etc/passwd", "etc/shadow",
    "win.ini", "boot.ini", "/proc/self",
]

XSS_PATTERNS = [
    "<script", "javascript:", "onerror=", "onload=", "alert(",
    "document.cookie", "eval(", "%3Cscript",
]

SENSITIVE_PATHS = [
    "/.env", "/config.php", "/wp-config.php", "/backup",
    "/.git", "/admin", "/phpmyadmin", "/.htaccess",
    "/server-status", "/web.config", "/.aws",
]

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_web_log(filepath: str) -> dict:
    results = {
        "all_requests": [],
        "suspicious_agents": [],
        "sqli_attempts": [],
        "path_traversal": [],
        "xss_attempts": [],
        "sensitive_path_access": [],
        "error_requests": [],
        "summary": {}
    }

    requests_by_ip = defaultdict(int)
    errors_by_ip = defaultdict(int)
    status_counts = defaultdict(int)
    not_found_by_ip = defaultdict(int)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = LOG_PATTERN.match(line)
            if not m:
                continue

            entry = m.groupdict()
            decoded_uri = unquote(entry["uri"]).lower()
            ua = entry["user_agent"].lower()
            status = int(entry["status"])

            requests_by_ip[entry["ip"]] += 1
            status_counts[str(status)] += 1

            results["all_requests"].append(entry)

            # Error tracking
            if status >= 400:
                errors_by_ip[entry["ip"]] += 1
                results["error_requests"].append(entry)

            if status == 404:
                not_found_by_ip[entry["ip"]] += 1

            # Suspicious user agent
            for sus_ua in SUSPICIOUS_USER_AGENTS:
                if sus_ua in ua:
                    results["suspicious_agents"].append({
                        **entry,
                        "matched_agent": sus_ua
                    })
                    break

            # SQLi detection
            for pattern in SQLI_PATTERNS:
                if pattern.lower() in decoded_uri:
                    results["sqli_attempts"].append({
                        **entry,
                        "matched_pattern": pattern,
                        "decoded_uri": decoded_uri
                    })
                    break

            # Path traversal detection
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.lower() in decoded_uri:
                    results["path_traversal"].append({
                        **entry,
                        "matched_pattern": pattern,
                        "decoded_uri": decoded_uri
                    })
                    break

            # XSS detection
            for pattern in XSS_PATTERNS:
                if pattern.lower() in decoded_uri:
                    results["xss_attempts"].append({
                        **entry,
                        "matched_pattern": pattern
                    })
                    break

            # Sensitive path access
            for path in SENSITIVE_PATHS:
                if path.lower() in decoded_uri:
                    results["sensitive_path_access"].append({
                        **entry,
                        "sensitive_path": path
                    })
                    break

    results["summary"] = {
        "total_requests": len(results["all_requests"]),
        "suspicious_agent_requests": len(results["suspicious_agents"]),
        "sqli_attempts": len(results["sqli_attempts"]),
        "path_traversal_attempts": len(results["path_traversal"]),
        "xss_attempts": len(results["xss_attempts"]),
        "sensitive_path_hits": len(results["sensitive_path_access"]),
        "total_errors": len(results["error_requests"]),
        "status_code_counts": dict(status_counts),
        "top_ips_by_requests": dict(sorted(requests_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_ips_by_errors": dict(sorted(errors_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_ips_by_404": dict(sorted(not_found_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]),
    }

    return results


# ── Alert Detection ───────────────────────────────────────────────────────────

def detect_alerts(results: dict, scan_threshold: int = 5) -> list:
    alerts = []

    # Web scanner detected
    seen_scanner_ips = set()
    for req in results["suspicious_agents"]:
        ip = req["ip"]
        if ip not in seen_scanner_ips:
            seen_scanner_ips.add(ip)
            alerts.append({
                "alert": "WEB_SCANNER_DETECTED",
                "severity": "HIGH",
                "source_ip": ip,
                "tool": req["matched_agent"],
                "recommendation": "Block IP, review all requests from this source"
            })

    # SQLi attempts
    sqli_ips = defaultdict(int)
    for req in results["sqli_attempts"]:
        sqli_ips[req["ip"]] += 1
    for ip, count in sqli_ips.items():
        alerts.append({
            "alert": "SQL_INJECTION_ATTEMPT",
            "severity": "CRITICAL",
            "source_ip": ip,
            "attempts": count,
            "recommendation": "Block IP, review DB logs, check WAF rules"
        })

    # Path traversal
    for req in results["path_traversal"]:
        alerts.append({
            "alert": "PATH_TRAVERSAL_ATTEMPT",
            "severity": "HIGH",
            "source_ip": req["ip"],
            "uri": req.get("decoded_uri", req["uri"]),
            "recommendation": "Verify input validation, check if access was successful"
        })

    # High 404 rate (scanning behavior)
    for ip, count in results["summary"]["top_ips_by_404"].items():
        if count >= scan_threshold:
            alerts.append({
                "alert": "DIRECTORY_SCANNING_DETECTED",
                "severity": "MEDIUM",
                "source_ip": ip,
                "404_count": count,
                "recommendation": "Monitor IP, consider temporary block"
            })

    return alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(results: dict, alerts: list):
    print("\n" + "="*60)
    print("  WEB ACCESS LOG ANALYSIS REPORT")
    print("="*60)
    s = results["summary"]
    print(f"  Total Requests        : {s['total_requests']}")
    print(f"  Suspicious Agents     : {s['suspicious_agent_requests']}")
    print(f"  SQLi Attempts         : {s['sqli_attempts']}")
    print(f"  Path Traversal        : {s['path_traversal_attempts']}")
    print(f"  XSS Attempts          : {s['xss_attempts']}")
    print(f"  Sensitive Path Hits   : {s['sensitive_path_hits']}")
    print(f"  Total Error Responses : {s['total_errors']}")

    print("\n── Status Code Breakdown ─────────────────────────────────")
    for code, count in sorted(s["status_code_counts"].items()):
        print(f"  HTTP {code}   {count} responses")

    print("\n── Top IPs by Request Volume ─────────────────────────────")
    for ip, count in list(s["top_ips_by_requests"].items())[:5]:
        print(f"  {ip:<20} {count} requests")

    print("\n── Top IPs by 404 Errors ─────────────────────────────────")
    for ip, count in list(s["top_ips_by_404"].items())[:5]:
        print(f"  {ip:<20} {count} not-found responses")

    print("\n── Sensitive Path Access Attempts ────────────────────────")
    for req in results["sensitive_path_access"]:
        print(f"  [{req['timestamp']}] {req['ip']} → {req['uri']}  (HTTP {req['status']})")

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
    parser = argparse.ArgumentParser(description="SOC L1 - Web Access Log Parser")
    parser.add_argument("--file", required=True, help="Path to Apache/Nginx access log")
    parser.add_argument("--threshold", type=int, default=5, help="404 scan threshold (default: 5)")
    parser.add_argument("--output", help="Optional: save results to JSON file")
    args = parser.parse_args()

    results = parse_web_log(args.file)
    alerts = detect_alerts(results, scan_threshold=args.threshold)

    print_report(results, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"results": results, "alerts": alerts}, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
