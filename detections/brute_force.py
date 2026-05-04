"""
brute_force.py
--------------
SOC L1 Log Analysis — Brute Force Detection Engine
Detects SSH brute force, credential stuffing, and password spraying
across auth.log and Windows Event Logs.

Detection Logic:
    - SSH Brute Force     : N failed logins from same IP in T seconds
    - Credential Stuffing : Same IP trying many different usernames
    - Password Spraying   : Same password attempt across many accounts
    - Distributed BF      : Many IPs failing against same account

Usage:
    python brute_force.py --file ../logs/auth.log --type linux
    python brute_force.py --file ../logs/windows_events.log --type windows
    python brute_force.py --file ../logs/auth.log --type linux --threshold 5 --window 60
"""

import re
import csv
import json
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

# ── Config Defaults ───────────────────────────────────────────────────────────

DEFAULT_THRESHOLD    = 5    # failed attempts to trigger alert
DEFAULT_WINDOW_SECS  = 120  # time window in seconds
SPRAY_THRESHOLD      = 3    # unique users targeted from same IP
DISTRIBUTED_THRESHOLD = 3   # unique IPs hitting same user

# ── Regex Patterns (Linux auth.log) ──────────────────────────────────────────

FAILED_AUTH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)

SUCCESS_AUTH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_syslog_time(month: str, day: str, time_str: str, year: int = 2026) -> datetime:
    return datetime(year, MONTH_MAP.get(month, 1), int(day),
                    *[int(x) for x in time_str.split(":")])


def severity_label(count: int, threshold: int) -> str:
    ratio = count / threshold
    if ratio >= 5:
        return "CRITICAL"
    elif ratio >= 2:
        return "HIGH"
    else:
        return "MEDIUM"


# ── Linux Auth Log Parser ─────────────────────────────────────────────────────

def parse_linux_events(filepath: str) -> tuple[list, list]:
    failed_events  = []
    success_events = []

    with open(filepath, "r") as f:
        for line in f:
            m = FAILED_AUTH_PATTERN.search(line)
            if m:
                d = m.groupdict()
                try:
                    ts = parse_syslog_time(d["month"], d["day"], d["time"])
                    failed_events.append({
                        "timestamp": ts,
                        "ip": d["ip"],
                        "user": d["user"],
                        "port": d["port"],
                        "raw": line.strip()
                    })
                except Exception:
                    pass
                continue

            m = SUCCESS_AUTH_PATTERN.search(line)
            if m:
                d = m.groupdict()
                try:
                    ts = parse_syslog_time(d["month"], d["day"], d["time"])
                    success_events.append({
                        "timestamp": ts,
                        "ip": d["ip"],
                        "user": d["user"],
                    })
                except Exception:
                    pass

    return failed_events, success_events


# ── Windows Event Log Parser ──────────────────────────────────────────────────

def parse_windows_events(filepath: str) -> tuple[list, list]:
    failed_events  = []
    success_events = []

    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get("EventID", "").strip()
            try:
                ts = datetime.fromisoformat(row.get("TimeCreated", "").replace("Z", ""))
            except Exception:
                continue

            ip   = row.get("IpAddress", "N/A").strip()
            user = row.get("TargetUserName", "N/A").strip()

            if event_id == "4625":
                failed_events.append({
                    "timestamp": ts,
                    "ip": ip,
                    "user": user,
                    "raw": str(row)
                })
            elif event_id == "4624":
                success_events.append({
                    "timestamp": ts,
                    "ip": ip,
                    "user": user,
                })

    return failed_events, success_events


# ── Detection: SSH / RDP Brute Force ─────────────────────────────────────────

def detect_brute_force(failed_events: list, threshold: int, window_secs: int) -> list:
    """Sliding window: N failures from same IP within T seconds."""
    alerts = []
    by_ip = defaultdict(list)

    for event in failed_events:
        by_ip[event["ip"]].append(event)

    for ip, events in by_ip.items():
        events.sort(key=lambda x: x["timestamp"])
        window = timedelta(seconds=window_secs)

        i = 0
        while i < len(events):
            window_events = [events[i]]
            j = i + 1
            while j < len(events) and (events[j]["timestamp"] - events[i]["timestamp"]) <= window:
                window_events.append(events[j])
                j += 1

            if len(window_events) >= threshold:
                users_targeted = list({e["user"] for e in window_events})
                alerts.append({
                    "alert":          "BRUTE_FORCE_DETECTED",
                    "severity":       severity_label(len(window_events), threshold),
                    "source_ip":      ip,
                    "attempt_count":  len(window_events),
                    "window_seconds": window_secs,
                    "start_time":     str(window_events[0]["timestamp"]),
                    "end_time":       str(window_events[-1]["timestamp"]),
                    "users_targeted": users_targeted,
                    "recommendation": "Block IP immediately, review account lockouts, escalate if ongoing"
                })
                i = j
                continue
            i += 1

    return alerts


# ── Detection: Credential Stuffing ───────────────────────────────────────────

def detect_credential_stuffing(failed_events: list, spray_threshold: int) -> list:
    """Same IP targeting many different usernames."""
    alerts = []
    ip_users = defaultdict(set)

    for event in failed_events:
        ip_users[event["ip"]].add(event["user"])

    for ip, users in ip_users.items():
        if len(users) >= spray_threshold:
            alerts.append({
                "alert":            "CREDENTIAL_STUFFING_DETECTED",
                "severity":         "HIGH",
                "source_ip":        ip,
                "unique_users":     len(users),
                "usernames_tried":  list(users),
                "recommendation":   "Block IP, force password resets on targeted accounts"
            })

    return alerts


# ── Detection: Password Spraying ─────────────────────────────────────────────

def detect_password_spraying(failed_events: list, dist_threshold: int) -> list:
    """Many IPs all targeting the same username (low-and-slow)."""
    alerts = []
    user_ips = defaultdict(set)

    for event in failed_events:
        user_ips[event["user"]].add(event["ip"])

    for user, ips in user_ips.items():
        if len(ips) >= dist_threshold:
            alerts.append({
                "alert":            "PASSWORD_SPRAYING_DETECTED",
                "severity":         "HIGH",
                "target_user":      user,
                "unique_source_ips": len(ips),
                "source_ips":       list(ips),
                "recommendation":   "Enable MFA, lock account temporarily, investigate sources"
            })

    return alerts


# ── Detection: Successful Login After Failures ───────────────────────────────

def detect_success_after_failures(failed_events: list, success_events: list) -> list:
    """Flags successful login from an IP that had previous failures."""
    alerts = []
    failed_ips = {e["ip"] for e in failed_events}

    for event in success_events:
        if event["ip"] in failed_ips:
            alerts.append({
                "alert":          "SUCCESS_AFTER_BRUTE_FORCE",
                "severity":       "CRITICAL",
                "source_ip":      event["ip"],
                "user":           event["user"],
                "login_time":     str(event["timestamp"]),
                "recommendation": "Treat as compromised account — isolate, reset credentials, review session activity"
            })

    return alerts


# ── Run All Detections ────────────────────────────────────────────────────────

def run_detections(failed: list, success: list, threshold: int,
                   window: int, spray: int, dist: int) -> list:
    all_alerts = []
    all_alerts += detect_brute_force(failed, threshold, window)
    all_alerts += detect_credential_stuffing(failed, spray)
    all_alerts += detect_password_spraying(failed, dist)
    all_alerts += detect_success_after_failures(failed, success)
    return all_alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(failed: list, success: list, alerts: list):
    print("\n" + "="*60)
    print("  BRUTE FORCE DETECTION REPORT")
    print("="*60)
    print(f"  Total Failed Attempts : {len(failed)}")
    print(f"  Total Successful Logins: {len(success)}")
    print(f"  Alerts Generated      : {len(alerts)}")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in alerts:
            print(f"\n  [{alert['severity']}] {alert['alert']}")
            for k, v in alert.items():
                if k not in ("alert", "severity") and v:
                    val = ", ".join(v) if isinstance(v, list) else v
                    print(f"  {k.replace('_',' ').capitalize():<22}: {val}")
    else:
        print("\n  ✅ No brute force activity detected.")

    print("\n" + "="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Brute Force Detector")
    parser.add_argument("--file",      required=True,  help="Path to log file")
    parser.add_argument("--type",      required=True,  choices=["linux", "windows"], help="Log type")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,   help="Failure threshold (default: 5)")
    parser.add_argument("--window",    type=int, default=DEFAULT_WINDOW_SECS, help="Time window in seconds (default: 120)")
    parser.add_argument("--spray",     type=int, default=SPRAY_THRESHOLD,     help="Credential stuffing unique-user threshold (default: 3)")
    parser.add_argument("--dist",      type=int, default=DISTRIBUTED_THRESHOLD, help="Spray unique-IP threshold (default: 3)")
    parser.add_argument("--output",    help="Optional: save alerts to JSON")
    args = parser.parse_args()

    if args.type == "linux":
        failed, success = parse_linux_events(args.file)
    else:
        failed, success = parse_windows_events(args.file)

    alerts = run_detections(failed, success, args.threshold, args.window, args.spray, args.dist)
    print_report(failed, success, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"[+] Alerts saved to {args.output}")


if __name__ == "__main__":
    main()
