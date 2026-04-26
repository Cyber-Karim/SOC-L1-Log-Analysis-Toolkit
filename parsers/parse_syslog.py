"""
parse_syslog.py
---------------
SOC L1 Log Analysis — Linux Syslog Parser
Detects firewall blocks, service crashes, OOM kills, and unauthorized access attempts.

Usage:
    python parse_syslog.py --file ../logs/syslog.log
    python parse_syslog.py --file ../logs/syslog.log --output report.json
"""

import re
import json
import argparse
from collections import defaultdict

# ── Regex Patterns ────────────────────────────────────────────────────────────

PATTERNS = {
    "ufw_block": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*UFW BLOCK.*SRC=(?P<src_ip>\S+) "
        r"DST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\S+).*DPT=(?P<dst_port>\d+)"
    ),
    "ufw_allow": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*UFW ALLOW.*SRC=(?P<src_ip>\S+) "
        r"DST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\S+).*DPT=(?P<dst_port>\d+)"
    ),
    "service_failed": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*systemd.*"
        r"(?P<service>\S+\.service).*[Ff]ailed"
    ),
    "oom_kill": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*Killed process (?P<pid>\d+) "
        r"\((?P<process>[^)]+)\)"
    ),
    "cron_job": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*CRON\[\d+\].*CMD \((?P<command>.+)\)"
    ),
    "denied_command": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*sudo\[\d+\]: "
        r"(?P<user>\S+).*command not allowed.*COMMAND=(?P<command>.+)"
    ),
}

# ── Port Reference ────────────────────────────────────────────────────────────

COMMON_PORTS = {
    "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS",
    "80": "HTTP", "443": "HTTPS", "445": "SMB", "3306": "MySQL",
    "3389": "RDP", "5432": "PostgreSQL", "6379": "Redis",
    "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "27017": "MongoDB",
}

HIGH_RISK_PORTS = {"23", "445", "3389", "5432", "3306", "6379", "27017"}


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_syslog(filepath: str) -> dict:
    results = {
        "ufw_blocks": [],
        "ufw_allows": [],
        "service_failures": [],
        "oom_kills": [],
        "cron_jobs": [],
        "denied_commands": [],
        "summary": {}
    }

    blocked_by_ip = defaultdict(int)
    blocked_ports = defaultdict(int)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # UFW block
            m = PATTERNS["ufw_block"].search(line)
            if m:
                entry = m.groupdict()
                entry["service_name"] = COMMON_PORTS.get(entry["dst_port"], "Unknown")
                entry["high_risk"] = entry["dst_port"] in HIGH_RISK_PORTS
                results["ufw_blocks"].append(entry)
                blocked_by_ip[entry["src_ip"]] += 1
                blocked_ports[entry["dst_port"]] += 1
                continue

            # UFW allow
            m = PATTERNS["ufw_allow"].search(line)
            if m:
                results["ufw_allows"].append(m.groupdict())
                continue

            # Service failure
            m = PATTERNS["service_failed"].search(line)
            if m:
                results["service_failures"].append(m.groupdict())
                continue

            # OOM kill
            m = PATTERNS["oom_kill"].search(line)
            if m:
                results["oom_kills"].append(m.groupdict())
                continue

            # Cron job
            m = PATTERNS["cron_job"].search(line)
            if m:
                results["cron_jobs"].append(m.groupdict())
                continue

            # Denied sudo command
            m = PATTERNS["denied_command"].search(line)
            if m:
                results["denied_commands"].append(m.groupdict())
                continue

    results["summary"] = {
        "total_ufw_blocks": len(results["ufw_blocks"]),
        "total_ufw_allows": len(results["ufw_allows"]),
        "total_service_failures": len(results["service_failures"]),
        "total_oom_kills": len(results["oom_kills"]),
        "total_denied_commands": len(results["denied_commands"]),
        "top_blocked_ips": dict(sorted(blocked_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_blocked_ports": dict(sorted(blocked_ports.items(), key=lambda x: x[1], reverse=True)[:10]),
        "high_risk_port_blocks": [e for e in results["ufw_blocks"] if e.get("high_risk")],
    }

    return results


# ── Alert Detection ───────────────────────────────────────────────────────────

def detect_alerts(results: dict, block_threshold: int = 3) -> list:
    alerts = []

    # Port scan detection
    for ip, count in results["summary"]["top_blocked_ips"].items():
        if count >= block_threshold:
            alerts.append({
                "alert": "PORT_SCAN_DETECTED",
                "severity": "HIGH",
                "source_ip": ip,
                "blocked_attempts": count,
                "recommendation": "Block IP at perimeter firewall, review all traffic from this source"
            })

    # High-risk port access attempts
    seen_hrp = set()
    for block in results["summary"]["high_risk_port_blocks"]:
        key = (block["src_ip"], block["dst_port"])
        if key not in seen_hrp:
            seen_hrp.add(key)
            alerts.append({
                "alert": "HIGH_RISK_PORT_ACCESS_ATTEMPT",
                "severity": "HIGH",
                "source_ip": block["src_ip"],
                "port": block["dst_port"],
                "service": block["service_name"],
                "recommendation": f"Investigate why {block['service_name']} port is being probed"
            })

    # Service crashes
    for failure in results["service_failures"]:
        alerts.append({
            "alert": "SERVICE_CRASH",
            "severity": "MEDIUM",
            "service": failure.get("service"),
            "time": failure.get("timestamp"),
            "recommendation": "Check service logs, verify availability, investigate root cause"
        })

    # OOM kills
    for kill in results["oom_kills"]:
        alerts.append({
            "alert": "OUT_OF_MEMORY_PROCESS_KILLED",
            "severity": "MEDIUM",
            "process": kill.get("process"),
            "pid": kill.get("pid"),
            "time": kill.get("timestamp"),
            "recommendation": "Review memory usage, check for memory leaks or resource exhaustion attack"
        })

    # Denied commands
    for cmd in results["denied_commands"]:
        alerts.append({
            "alert": "UNAUTHORIZED_COMMAND_ATTEMPT",
            "severity": "HIGH",
            "user": cmd.get("user"),
            "command": cmd.get("command", "").strip(),
            "time": cmd.get("timestamp"),
            "recommendation": "Review user permissions, investigate intent, check for insider threat"
        })

    return alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(results: dict, alerts: list):
    print("\n" + "="*60)
    print("  SYSLOG ANALYSIS REPORT")
    print("="*60)
    s = results["summary"]
    print(f"  UFW Blocks            : {s['total_ufw_blocks']}")
    print(f"  UFW Allows            : {s['total_ufw_allows']}")
    print(f"  Service Failures      : {s['total_service_failures']}")
    print(f"  OOM Kills             : {s['total_oom_kills']}")
    print(f"  Denied Sudo Commands  : {s['total_denied_commands']}")

    print("\n── Top IPs Blocked by UFW ────────────────────────────────")
    for ip, count in s["top_blocked_ips"].items():
        print(f"  {ip:<20} {count} blocks")

    print("\n── Most Targeted Ports ───────────────────────────────────")
    for port, count in list(s["top_blocked_ports"].items())[:8]:
        service = COMMON_PORTS.get(port, "Unknown")
        risk = " ⚠️ HIGH RISK" if port in HIGH_RISK_PORTS else ""
        print(f"  Port {port:<6} ({service:<12}) {count} blocks{risk}")

    print("\n── Service Failures ──────────────────────────────────────")
    if results["service_failures"]:
        for f in results["service_failures"]:
            print(f"  [{f['timestamp']}] {f['service']}")
    else:
        print("  None.")

    print("\n── Unauthorized Command Attempts ─────────────────────────")
    if results["denied_commands"]:
        for cmd in results["denied_commands"]:
            print(f"  [{cmd['timestamp']}] {cmd['user']} attempted: {cmd['command'].strip()}")
    else:
        print("  None.")

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
    parser = argparse.ArgumentParser(description="SOC L1 - Syslog Parser")
    parser.add_argument("--file", required=True, help="Path to syslog file")
    parser.add_argument("--threshold", type=int, default=3, help="Block threshold for port scan detection (default: 3)")
    parser.add_argument("--output", help="Optional: save results to JSON file")
    args = parser.parse_args()

    results = parse_syslog(args.file)
    alerts = detect_alerts(results, block_threshold=args.threshold)

    print_report(results, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"results": results, "alerts": alerts}, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
