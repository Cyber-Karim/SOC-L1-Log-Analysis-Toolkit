"""
parse_auth.py
-------------
SOC L1 Log Analysis — Linux auth.log Parser
Parses SSH login attempts, sudo usage, and session events.

Usage:
    python parse_auth.py --file ../logs/auth.log
    python parse_auth.py --file ../logs/auth.log --output report.json
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

# ── Regex Patterns ────────────────────────────────────────────────────────────

PATTERNS = {
    "failed_password": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"Failed password for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    ),
    "accepted_password": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"Accepted (?:password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    ),
    "sudo_command": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+) \S+ sudo\[\d+\]: "
        r"(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)"
    ),
    "session_opened": re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"pam_unix.*session opened for user (?P<user>\S+)"
    ),
}

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_auth_log(filepath: str) -> dict:
    results = {
        "failed_logins": [],
        "successful_logins": [],
        "sudo_commands": [],
        "sessions": [],
        "summary": {}
    }

    failed_by_ip = defaultdict(int)
    failed_by_user = defaultdict(int)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Failed password
            m = PATTERNS["failed_password"].search(line)
            if m:
                entry = m.groupdict()
                results["failed_logins"].append(entry)
                failed_by_ip[entry["ip"]] += 1
                failed_by_user[entry["user"]] += 1
                continue

            # Accepted login
            m = PATTERNS["accepted_password"].search(line)
            if m:
                results["successful_logins"].append(m.groupdict())
                continue

            # Sudo command
            m = PATTERNS["sudo_command"].search(line)
            if m:
                results["sudo_commands"].append(m.groupdict())
                continue

            # Session opened
            m = PATTERNS["session_opened"].search(line)
            if m:
                results["sessions"].append(m.groupdict())
                continue

    # ── Summary ───────────────────────────────────────────────────────────────
    results["summary"] = {
        "total_failed_logins": len(results["failed_logins"]),
        "total_successful_logins": len(results["successful_logins"]),
        "total_sudo_commands": len(results["sudo_commands"]),
        "failed_logins_by_ip": dict(sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)),
        "failed_logins_by_user": dict(sorted(failed_by_user.items(), key=lambda x: x[1], reverse=True)),
    }

    return results


# ── Alert Detection ───────────────────────────────────────────────────────────

def detect_brute_force(results: dict, threshold: int = 5) -> list:
    alerts = []
    for ip, count in results["summary"]["failed_logins_by_ip"].items():
        if count >= threshold:
            alerts.append({
                "alert": "BRUTE_FORCE_DETECTED",
                "severity": "HIGH",
                "source_ip": ip,
                "failed_attempts": count,
                "recommendation": "Block IP immediately and escalate to Tier 2"
            })
    return alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(results: dict, alerts: list):
    print("\n" + "="*60)
    print("  AUTH.LOG ANALYSIS REPORT")
    print("="*60)
    print(f"  Total Failed Logins    : {results['summary']['total_failed_logins']}")
    print(f"  Total Successful Logins: {results['summary']['total_successful_logins']}")
    print(f"  Total Sudo Commands    : {results['summary']['total_sudo_commands']}")

    print("\n── Top IPs by Failed Logins ──────────────────────────────")
    for ip, count in list(results["summary"]["failed_logins_by_ip"].items())[:5]:
        print(f"  {ip:<20} {count} attempts")

    print("\n── Top Targeted Usernames ────────────────────────────────")
    for user, count in list(results["summary"]["failed_logins_by_user"].items())[:5]:
        print(f"  {user:<20} {count} attempts")

    print("\n── Successful Logins ─────────────────────────────────────")
    for entry in results["successful_logins"]:
        print(f"  [{entry['timestamp']}] {entry['user']} from {entry['ip']}")

    print("\n── Sudo Commands ─────────────────────────────────────────")
    for entry in results["sudo_commands"]:
        print(f"  [{entry['timestamp']}] {entry['user']} ran: {entry['command'].strip()}")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in alerts:
            print(f"  [{alert['severity']}] {alert['alert']}")
            print(f"  Source IP : {alert['source_ip']}")
            print(f"  Attempts  : {alert['failed_attempts']}")
            print(f"  Action    : {alert['recommendation']}")
            print()

    print("="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - auth.log Parser")
    parser.add_argument("--file", required=True, help="Path to auth.log file")
    parser.add_argument("--threshold", type=int, default=5, help="Brute force threshold (default: 5)")
    parser.add_argument("--output", help="Optional: save results to JSON file")
    args = parser.parse_args()

    results = parse_auth_log(args.file)
    alerts = detect_brute_force(results, threshold=args.threshold)

    print_report(results, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"results": results, "alerts": alerts}, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
