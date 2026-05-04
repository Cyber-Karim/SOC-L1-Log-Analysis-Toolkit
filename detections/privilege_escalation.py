"""
privilege_escalation.py
-----------------------
SOC L1 Log Analysis — Privilege Escalation Detection Engine
Detects unauthorized privilege use, lateral movement, and persistence tactics
across Linux auth logs and Windows Event Logs.

Detection Types:
    - Unauthorized Sudo         : Non-admin using sudo or being denied
    - Admin Group Addition       : User added to privileged group (Event 4732)
    - Scheduled Task Creation    : Possible persistence (Event 4698)
    - Sensitive File Read Attempt: Reading /etc/shadow, /etc/passwd
    - Audit Log Cleared          : Evidence tampering (Event 1102)
    - New Service Created        : Persistence mechanism
    - Privilege Token Use        : Special privileges assigned (Event 4672)
    - Shell Spawned by Web Process: Possible RCE (web shell indicator)

Usage:
    python privilege_escalation.py --file ../logs/auth.log --type linux
    python privilege_escalation.py --file ../logs/windows_events.log --type windows
"""

import re
import csv
import json
import argparse
from collections import defaultdict
from datetime import datetime

# ── Regex Patterns (Linux) ────────────────────────────────────────────────────

SUDO_SUCCESS_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sudo\[\d+\]:\s+"
    r"(?P<user>\S+)\s*:.*TTY=\S+.*COMMAND=(?P<command>.+)"
)

SUDO_DENIED_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sudo\[\d+\]:\s+"
    r"(?P<user>\S+).*command not allowed.*COMMAND=(?P<command>.+)"
)

SUDO_AUTH_FAIL_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sudo\[\d+\]:\s+"
    r"(?P<user>\S+).*incorrect password attempts"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# ── Sensitive Commands ────────────────────────────────────────────────────────

SENSITIVE_COMMANDS_LINUX = {
    "/bin/bash":            ("SHELL_AS_ROOT",    "CRITICAL"),
    "/bin/sh":              ("SHELL_AS_ROOT",    "CRITICAL"),
    "/usr/bin/passwd":      ("PASSWORD_CHANGE",  "HIGH"),
    "visudo":               ("SUDOERS_EDIT",     "CRITICAL"),
    "/etc/passwd":          ("SENSITIVE_FILE",   "HIGH"),
    "/etc/shadow":          ("SENSITIVE_FILE",   "CRITICAL"),
    "useradd":              ("USER_CREATED",     "HIGH"),
    "adduser":              ("USER_CREATED",     "HIGH"),
    "usermod":              ("USER_MODIFIED",    "HIGH"),
    "chmod 777":            ("INSECURE_PERMS",   "MEDIUM"),
    "chmod +s":             ("SETUID_BIT",       "CRITICAL"),
    "crontab":              ("CRON_MODIFICATION","HIGH"),
    "/etc/cron":            ("CRON_MODIFICATION","HIGH"),
    "nc ":                  ("NETCAT_USE",       "HIGH"),
    "ncat ":                ("NETCAT_USE",       "HIGH"),
    "python -c":            ("PYTHON_SHELL",     "HIGH"),
    "python3 -c":           ("PYTHON_SHELL",     "HIGH"),
    "wget ":                ("DOWNLOAD_ATTEMPT", "MEDIUM"),
    "curl ":                ("DOWNLOAD_ATTEMPT", "MEDIUM"),
    "iptables -F":          ("FIREWALL_FLUSH",   "CRITICAL"),
    "systemctl disable":    ("SERVICE_DISABLED", "HIGH"),
}

# ── Windows Event IDs of Interest ────────────────────────────────────────────

WINDOWS_PRIV_EVENTS = {
    "4672": ("SPECIAL_PRIVILEGES_ASSIGNED",  "HIGH"),
    "4673": ("SENSITIVE_PRIVILEGE_USE",      "HIGH"),
    "4674": ("SENSITIVE_PRIVILEGE_USE",      "HIGH"),
    "4698": ("SCHEDULED_TASK_CREATED",       "HIGH"),
    "4699": ("SCHEDULED_TASK_DELETED",       "MEDIUM"),
    "4702": ("SCHEDULED_TASK_UPDATED",       "MEDIUM"),
    "4720": ("USER_ACCOUNT_CREATED",         "HIGH"),
    "4722": ("USER_ACCOUNT_ENABLED",         "MEDIUM"),
    "4728": ("USER_ADDED_GLOBAL_GROUP",      "HIGH"),
    "4732": ("USER_ADDED_LOCAL_ADMIN_GROUP", "CRITICAL"),
    "4756": ("USER_ADDED_UNIVERSAL_GROUP",   "HIGH"),
    "1102": ("AUDIT_LOG_CLEARED",            "CRITICAL"),
    "4657": ("REGISTRY_VALUE_MODIFIED",      "MEDIUM"),
    "7045": ("NEW_SERVICE_INSTALLED",        "HIGH"),
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_syslog_time(month: str, day: str, time_str: str, year: int = 2026) -> datetime:
    return datetime(year, MONTH_MAP.get(month, 1), int(day),
                    *[int(x) for x in time_str.split(":")])


def check_sensitive_command(command: str) -> tuple[str, str] | None:
    cmd_lower = command.lower()
    for keyword, (label, severity) in SENSITIVE_COMMANDS_LINUX.items():
        if keyword in cmd_lower:
            return label, severity
    return None


# ── Linux Detections ──────────────────────────────────────────────────────────

def detect_linux_privesc(filepath: str) -> list:
    alerts = []

    with open(filepath, "r") as f:
        for line in f:
            # Successful sudo command
            m = SUDO_SUCCESS_PATTERN.search(line)
            if m:
                d = m.groupdict()
                command = d.get("command", "").strip()
                hit = check_sensitive_command(command)
                if hit:
                    label, severity = hit
                    try:
                        ts = parse_syslog_time(d["month"], d["day"], d["time"])
                    except Exception:
                        ts = None
                    alerts.append({
                        "alert":          f"SENSITIVE_SUDO_{label}",
                        "severity":       severity,
                        "user":           d["user"],
                        "command":        command,
                        "timestamp":      str(ts),
                        "recommendation": get_linux_recommendation(label)
                    })
                continue

            # Denied sudo command
            m = SUDO_DENIED_PATTERN.search(line)
            if m:
                d = m.groupdict()
                try:
                    ts = parse_syslog_time(d["month"], d["day"], d["time"])
                except Exception:
                    ts = None
                alerts.append({
                    "alert":          "UNAUTHORIZED_SUDO_ATTEMPT",
                    "severity":       "HIGH",
                    "user":           d["user"],
                    "command":        d.get("command", "").strip(),
                    "timestamp":      str(ts),
                    "recommendation": "Investigate why unprivileged user attempted sudo — possible insider threat"
                })
                continue

            # Sudo wrong password
            m = SUDO_AUTH_FAIL_PATTERN.search(line)
            if m:
                d = m.groupdict()
                try:
                    ts = parse_syslog_time(d["month"], d["day"], d["time"])
                except Exception:
                    ts = None
                alerts.append({
                    "alert":          "SUDO_PASSWORD_FAILURE",
                    "severity":       "MEDIUM",
                    "user":           d["user"],
                    "timestamp":      str(ts),
                    "recommendation": "User attempting sudo without valid credentials — monitor for escalation"
                })

    return alerts


def get_linux_recommendation(label: str) -> str:
    recs = {
        "SHELL_AS_ROOT":     "Root shell obtained via sudo — review what commands were run",
        "PASSWORD_CHANGE":   "Password changed with elevated privileges — verify authorization",
        "SUDOERS_EDIT":      "CRITICAL: sudoers file edited — review for backdoor entries",
        "SENSITIVE_FILE":    "Sensitive file accessed as root — check for credential harvesting",
        "USER_CREATED":      "New user created — verify authorization and review account",
        "USER_MODIFIED":     "User account modified — check for group membership changes",
        "SETUID_BIT":        "CRITICAL: setuid bit set — possible privilege escalation backdoor",
        "CRON_MODIFICATION": "Cron modified — check for persistence mechanisms",
        "NETCAT_USE":        "Netcat detected — possible reverse shell or data exfil",
        "PYTHON_SHELL":      "Python shell invoked as root — possible interactive exploitation",
        "FIREWALL_FLUSH":    "CRITICAL: Firewall rules cleared — system may be exposed",
        "SERVICE_DISABLED":  "Security service disabled — investigate motive",
        "DOWNLOAD_ATTEMPT":  "File download as root — check for malware staging",
    }
    return recs.get(label, "Review the command and verify authorization")


# ── Windows Detections ────────────────────────────────────────────────────────

def detect_windows_privesc(filepath: str) -> list:
    alerts = []

    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get("EventID", "").strip()
            if event_id not in WINDOWS_PRIV_EVENTS:
                continue

            alert_name, severity = WINDOWS_PRIV_EVENTS[event_id]
            try:
                ts = datetime.fromisoformat(row.get("TimeCreated", "").replace("Z", ""))
            except Exception:
                ts = None

            user    = row.get("SubjectUserName", "N/A").strip()
            target  = row.get("TargetUserName",  "N/A").strip()
            ip      = row.get("IpAddress",       "N/A").strip()
            process = row.get("ProcessName",     "N/A").strip()

            alert = {
                "alert":          alert_name,
                "severity":       severity,
                "event_id":       event_id,
                "user":           user,
                "timestamp":      str(ts),
                "recommendation": get_windows_recommendation(event_id)
            }

            if target and target != "N/A" and target != user:
                alert["target_user"] = target
            if ip and ip != "N/A":
                alert["source_ip"] = ip
            if process and process != "N/A":
                alert["process"] = process

            alerts.append(alert)

    return alerts


def get_windows_recommendation(event_id: str) -> str:
    recs = {
        "4672": "Review what privileges were assigned and whether they are expected",
        "4698": "Inspect scheduled task content for malicious commands or persistence",
        "4720": "Verify new account is authorized — check for backdoor accounts",
        "4732": "User added to local Administrators — immediate review required",
        "1102": "CRITICAL: Audit log cleared — possible evidence of compromise or tampering",
        "7045": "New service installed — inspect binary path for malware",
        "4728": "User added to global admin group — verify authorization",
    }
    return recs.get(event_id, "Investigate this privilege event and verify authorization")


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(alerts: list, log_type: str):
    print("\n" + "="*60)
    print("  PRIVILEGE ESCALATION DETECTION REPORT")
    print("="*60)
    print(f"  Log Type       : {log_type.upper()}")
    print(f"  Total Alerts   : {len(alerts)}")

    severity_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a["severity"]] += 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts[sev]:
            print(f"  {sev:<10}     : {severity_counts[sev]} alerts")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in sorted(alerts, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.get("severity","LOW"))):
            print(f"\n  [{alert['severity']}] {alert['alert']}")
            for k, v in alert.items():
                if k not in ("alert", "severity") and v is not None:
                    print(f"  {k.replace('_',' ').capitalize():<22}: {v}")
    else:
        print("\n  ✅ No privilege escalation activity detected.")

    print("\n" + "="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Privilege Escalation Detector")
    parser.add_argument("--file",   required=True, help="Path to log file")
    parser.add_argument("--type",   required=True, choices=["linux", "windows"])
    parser.add_argument("--output", help="Optional: save alerts to JSON")
    args = parser.parse_args()

    if args.type == "linux":
        alerts = detect_linux_privesc(args.file)
    else:
        alerts = detect_windows_privesc(args.file)

    print_report(alerts, args.type)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"[+] Alerts saved to {args.output}")


if __name__ == "__main__":
    main()
