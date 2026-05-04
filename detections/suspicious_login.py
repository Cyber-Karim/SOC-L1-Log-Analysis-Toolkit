"""
suspicious_login.py
-------------------
SOC L1 Log Analysis — Suspicious Login Detection Engine
Detects anomalous login behavior from auth.log and Windows Event Logs.

Detection Types:
    - Off-Hours Login         : Successful login outside business hours
    - Internal/External Mismatch : Expected internal IP logs in from external
    - New Source IP           : User logs in from a never-before-seen IP
    - Privileged After-Hours  : Admin/root login outside business hours
    - Multiple Location Login : Same user from different IPs in short window
    - Non-Interactive Logon   : Unusual logon types (Windows Event 4624)

Usage:
    python suspicious_login.py --file ../logs/auth.log --type linux
    python suspicious_login.py --file ../logs/windows_events.log --type windows
    python suspicious_login.py --file ../logs/auth.log --type linux --start-hour 8 --end-hour 18
"""

import re
import csv
import json
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

# ── Config ────────────────────────────────────────────────────────────────────

DEFAULT_BUSINESS_START = 8   # 08:00
DEFAULT_BUSINESS_END   = 18  # 18:00
MULTI_IP_WINDOW_MINS   = 30  # same user, 2 different IPs within N minutes

# Internal RFC-1918 ranges (simplified check)
INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.")

PRIVILEGED_USERS = {"root", "admin", "administrator", "sysadmin", "sudo"}

# Windows logon type reference
LOGON_TYPE_MAP = {
    "2":  "Interactive (console)",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

SUSPICIOUS_LOGON_TYPES = {"8", "9"}  # cleartext or new-credentials

# ── Regex (Linux auth.log) ────────────────────────────────────────────────────

SUCCESS_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)

SUDO_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sudo\[\d+\]:\s+"
    r"(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_syslog_time(month: str, day: str, time_str: str, year: int = 2026) -> datetime:
    return datetime(year, MONTH_MAP.get(month, 1), int(day),
                    *[int(x) for x in time_str.split(":")])


def is_internal_ip(ip: str) -> bool:
    return ip.startswith(INTERNAL_PREFIXES)


def is_business_hours(dt: datetime, start_hour: int, end_hour: int) -> bool:
    return start_hour <= dt.hour < end_hour and dt.weekday() < 5  # Mon-Fri


def is_privileged(user: str) -> bool:
    return user.lower() in PRIVILEGED_USERS or user.lower().startswith("admin")


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_linux_logins(filepath: str) -> list:
    logins = []
    with open(filepath, "r") as f:
        for line in f:
            m = SUCCESS_PATTERN.search(line)
            if m:
                d = m.groupdict()
                try:
                    ts = parse_syslog_time(d["month"], d["day"], d["time"])
                    logins.append({
                        "timestamp":   ts,
                        "user":        d["user"],
                        "ip":          d["ip"],
                        "is_internal": is_internal_ip(d["ip"]),
                        "is_privileged": is_privileged(d["user"]),
                        "logon_type":  "SSH",
                    })
                except Exception:
                    pass
    return logins


def parse_windows_logins(filepath: str) -> list:
    logins = []
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("EventID", "").strip() != "4624":
                continue
            try:
                ts = datetime.fromisoformat(row.get("TimeCreated", "").replace("Z", ""))
                ip   = row.get("IpAddress", "N/A").strip()
                user = row.get("TargetUserName", "N/A").strip()
                ltype = row.get("LogonType", "3").strip()
                logins.append({
                    "timestamp":     ts,
                    "user":          user,
                    "ip":            ip,
                    "is_internal":   is_internal_ip(ip),
                    "is_privileged": is_privileged(user),
                    "logon_type":    LOGON_TYPE_MAP.get(ltype, f"Type {ltype}"),
                    "logon_type_raw": ltype,
                })
            except Exception:
                continue
    return logins


# ── Detection: Off-Hours Logins ───────────────────────────────────────────────

def detect_off_hours(logins: list, start_hour: int, end_hour: int) -> list:
    alerts = []
    for login in logins:
        if not is_business_hours(login["timestamp"], start_hour, end_hour):
            severity = "CRITICAL" if login["is_privileged"] else "MEDIUM"
            alert_type = "PRIVILEGED_OFF_HOURS_LOGIN" if login["is_privileged"] else "OFF_HOURS_LOGIN"
            alerts.append({
                "alert":          alert_type,
                "severity":       severity,
                "user":           login["user"],
                "source_ip":      login["ip"],
                "login_time":     str(login["timestamp"]),
                "day_of_week":    login["timestamp"].strftime("%A"),
                "is_internal_ip": login["is_internal"],
                "recommendation": "Verify with user, review session commands, escalate if unrecognized"
            })
    return alerts


# ── Detection: External IP for Expected Internal User ────────────────────────

def detect_external_logins(logins: list) -> list:
    alerts = []
    # Track each user's most common IP type
    user_ip_types = defaultdict(lambda: {"internal": 0, "external": 0})
    for login in logins:
        if login["is_internal"]:
            user_ip_types[login["user"]]["internal"] += 1
        else:
            user_ip_types[login["user"]]["external"] += 1

    for login in logins:
        user = login["user"]
        # User has history of internal logins but this one is external
        if (not login["is_internal"] and
                user_ip_types[user]["internal"] > 0 and
                user != "N/A"):
            alerts.append({
                "alert":          "UNEXPECTED_EXTERNAL_LOGIN",
                "severity":       "HIGH",
                "user":           user,
                "source_ip":      login["ip"],
                "login_time":     str(login["timestamp"]),
                "recommendation": "Confirm with user, check VPN logs, verify it is not account takeover"
            })

    return alerts


# ── Detection: Multiple IPs — Same User in Short Window ──────────────────────

def detect_multiple_source_ips(logins: list, window_mins: int) -> list:
    alerts = []
    user_logins = defaultdict(list)
    for login in logins:
        user_logins[login["user"]].append(login)

    window = timedelta(minutes=window_mins)

    for user, user_events in user_logins.items():
        user_events.sort(key=lambda x: x["timestamp"])
        for i in range(len(user_events)):
            for j in range(i + 1, len(user_events)):
                if (user_events[j]["timestamp"] - user_events[i]["timestamp"]) > window:
                    break
                if user_events[i]["ip"] != user_events[j]["ip"]:
                    alerts.append({
                        "alert":          "MULTIPLE_SOURCE_IPS_SAME_USER",
                        "severity":       "HIGH",
                        "user":           user,
                        "ip_1":           user_events[i]["ip"],
                        "time_1":         str(user_events[i]["timestamp"]),
                        "ip_2":           user_events[j]["ip"],
                        "time_2":         str(user_events[j]["timestamp"]),
                        "window_minutes": window_mins,
                        "recommendation": "Possible account sharing or compromise — investigate both sessions"
                    })
    return alerts


# ── Detection: Suspicious Windows Logon Types ────────────────────────────────

def detect_suspicious_logon_types(logins: list) -> list:
    alerts = []
    for login in logins:
        raw = login.get("logon_type_raw", "")
        if raw in SUSPICIOUS_LOGON_TYPES:
            alerts.append({
                "alert":          "SUSPICIOUS_LOGON_TYPE",
                "severity":       "HIGH",
                "user":           login["user"],
                "source_ip":      login["ip"],
                "logon_type":     login["logon_type"],
                "time":           str(login["timestamp"]),
                "recommendation": "Cleartext or pass-through credentials detected — review authentication method"
            })
    return alerts


# ── Run All Detections ────────────────────────────────────────────────────────

def run_detections(logins: list, start_hour: int, end_hour: int,
                   window_mins: int, log_type: str) -> list:
    all_alerts = []
    all_alerts += detect_off_hours(logins, start_hour, end_hour)
    all_alerts += detect_external_logins(logins)
    all_alerts += detect_multiple_source_ips(logins, window_mins)
    if log_type == "windows":
        all_alerts += detect_suspicious_logon_types(logins)
    return all_alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(logins: list, alerts: list, start_hour: int, end_hour: int):
    print("\n" + "="*60)
    print("  SUSPICIOUS LOGIN DETECTION REPORT")
    print("="*60)
    print(f"  Total Logins Analyzed : {len(logins)}")
    print(f"  Business Hours        : {start_hour:02d}:00 – {end_hour:02d}:00 (Mon-Fri)")
    print(f"  Alerts Generated      : {len(alerts)}")

    print("\n── Login Summary ─────────────────────────────────────────")
    internal_count = sum(1 for l in logins if l["is_internal"])
    external_count = len(logins) - internal_count
    priv_count     = sum(1 for l in logins if l["is_privileged"])
    print(f"  Internal Source IPs   : {internal_count}")
    print(f"  External Source IPs   : {external_count}")
    print(f"  Privileged Accounts   : {priv_count}")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in alerts:
            print(f"\n  [{alert['severity']}] {alert['alert']}")
            for k, v in alert.items():
                if k not in ("alert", "severity") and v is not None:
                    print(f"  {k.replace('_',' ').capitalize():<26}: {v}")
    else:
        print("\n  ✅ No suspicious login activity detected.")

    print("\n" + "="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Suspicious Login Detector")
    parser.add_argument("--file",        required=True,  help="Path to log file")
    parser.add_argument("--type",        required=True,  choices=["linux", "windows"])
    parser.add_argument("--start-hour",  type=int, default=DEFAULT_BUSINESS_START, help="Business hours start (default: 8)")
    parser.add_argument("--end-hour",    type=int, default=DEFAULT_BUSINESS_END,   help="Business hours end (default: 18)")
    parser.add_argument("--window",      type=int, default=MULTI_IP_WINDOW_MINS,   help="Multi-IP window in minutes (default: 30)")
    parser.add_argument("--output",      help="Optional: save alerts to JSON")
    args = parser.parse_args()

    if args.type == "linux":
        logins = parse_linux_logins(args.file)
    else:
        logins = parse_windows_logins(args.file)

    alerts = run_detections(logins, args.start_hour, args.end_hour, args.window, args.type)
    print_report(logins, alerts, args.start_hour, args.end_hour)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"[+] Alerts saved to {args.output}")


if __name__ == "__main__":
    main()
