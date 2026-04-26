"""
parse_evtx.py
-------------
SOC L1 Log Analysis — Windows Event Log Parser
Parses simulated Windows Security Event Logs (CSV format).

Key Event IDs monitored:
    4624  - Successful logon
    4625  - Failed logon
    4672  - Special privileges assigned (admin logon)
    4688  - New process created
    4698  - Scheduled task created
    4732  - Member added to local group
    1102  - Audit log cleared  ← HIGH PRIORITY

Usage:
    python parse_evtx.py --file ../logs/windows_events.log
    python parse_evtx.py --file ../logs/windows_events.log --output report.json
"""

import csv
import json
import argparse
from collections import defaultdict

# ── Event ID Reference ────────────────────────────────────────────────────────

EVENT_SEVERITY = {
    "4624": "INFO",
    "4625": "MEDIUM",
    "4672": "HIGH",
    "4688": "INFO",
    "4698": "HIGH",
    "4732": "CRITICAL",
    "1102": "CRITICAL",
    "4776": "MEDIUM",
    "4634": "INFO",
}

SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "net.exe", "net1.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "whoami.exe",
]

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_windows_events(filepath: str) -> dict:
    results = {
        "all_events": [],
        "failed_logons": [],
        "successful_logons": [],
        "privilege_use": [],
        "process_creation": [],
        "suspicious_processes": [],
        "critical_events": [],
        "summary": {}
    }

    failed_by_ip = defaultdict(int)
    failed_by_user = defaultdict(int)
    event_counts = defaultdict(int)

    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get("EventID", "").strip()
            event_counts[event_id] += 1
            results["all_events"].append(row)

            # Failed logon
            if event_id == "4625":
                results["failed_logons"].append(row)
                ip = row.get("IpAddress", "N/A").strip()
                user = row.get("TargetUserName", "N/A").strip()
                failed_by_ip[ip] += 1
                failed_by_user[user] += 1

            # Successful logon
            elif event_id == "4624":
                results["successful_logons"].append(row)

            # Privilege assigned
            elif event_id == "4672":
                results["privilege_use"].append(row)

            # Process creation
            elif event_id == "4688":
                results["process_creation"].append(row)
                proc = row.get("ProcessName", "").strip().lower()
                for sus in SUSPICIOUS_PROCESSES:
                    if sus in proc:
                        results["suspicious_processes"].append({
                            **row,
                            "flag": f"Suspicious process: {sus}"
                        })
                        break

            # Critical events: log cleared, group membership change, scheduled task
            if event_id in ("1102", "4732", "4698"):
                results["critical_events"].append({
                    **row,
                    "severity": EVENT_SEVERITY.get(event_id, "UNKNOWN"),
                    "note": get_event_note(event_id)
                })

    results["summary"] = {
        "total_events": len(results["all_events"]),
        "total_failed_logons": len(results["failed_logons"]),
        "total_successful_logons": len(results["successful_logons"]),
        "total_privilege_events": len(results["privilege_use"]),
        "total_process_creations": len(results["process_creation"]),
        "suspicious_process_count": len(results["suspicious_processes"]),
        "critical_event_count": len(results["critical_events"]),
        "event_id_counts": dict(event_counts),
        "failed_logons_by_ip": dict(sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)),
        "failed_logons_by_user": dict(sorted(failed_by_user.items(), key=lambda x: x[1], reverse=True)),
    }

    return results


def get_event_note(event_id: str) -> str:
    notes = {
        "1102": "⚠️  Audit log cleared — possible evidence tampering",
        "4732": "⚠️  User added to Administrators group — privilege escalation",
        "4698": "⚠️  Scheduled task created — possible persistence mechanism",
    }
    return notes.get(event_id, "")


# ── Alert Detection ───────────────────────────────────────────────────────────

def detect_alerts(results: dict, brute_threshold: int = 3) -> list:
    alerts = []

    # Brute force
    for ip, count in results["summary"]["failed_logons_by_ip"].items():
        if count >= brute_threshold:
            alerts.append({
                "alert": "WINDOWS_BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": ip,
                "failed_attempts": count,
                "recommendation": "Block IP at firewall, review account lockout policy"
            })

    # Critical events
    for event in results["critical_events"]:
        alerts.append({
            "alert": f"CRITICAL_EVENT_{event['EventID']}",
            "severity": event["severity"],
            "time": event.get("TimeCreated"),
            "user": event.get("SubjectUserName"),
            "note": event.get("note"),
            "recommendation": "Investigate immediately and escalate to Tier 2"
        })

    # Suspicious processes
    for proc in results["suspicious_processes"]:
        alerts.append({
            "alert": "SUSPICIOUS_PROCESS_EXECUTION",
            "severity": "HIGH",
            "time": proc.get("TimeCreated"),
            "user": proc.get("SubjectUserName"),
            "process": proc.get("ProcessName"),
            "flag": proc.get("flag"),
            "recommendation": "Check parent process, review user activity, consider isolation"
        })

    return alerts


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(results: dict, alerts: list):
    print("\n" + "="*60)
    print("  WINDOWS EVENT LOG ANALYSIS REPORT")
    print("="*60)
    s = results["summary"]
    print(f"  Total Events          : {s['total_events']}")
    print(f"  Failed Logons         : {s['total_failed_logons']}")
    print(f"  Successful Logons     : {s['total_successful_logons']}")
    print(f"  Privilege Events      : {s['total_privilege_events']}")
    print(f"  Process Creations     : {s['total_process_creations']}")
    print(f"  Suspicious Processes  : {s['suspicious_process_count']}")
    print(f"  Critical Events       : {s['critical_event_count']}")

    print("\n── Event ID Breakdown ────────────────────────────────────")
    for eid, count in sorted(s["event_id_counts"].items()):
        sev = EVENT_SEVERITY.get(eid, "INFO")
        print(f"  EventID {eid:<6} [{sev:<8}]  {count} occurrences")

    print("\n── Failed Logons by IP ───────────────────────────────────")
    for ip, count in s["failed_logons_by_ip"].items():
        print(f"  {ip:<20} {count} failures")

    print("\n── Suspicious Process Executions ─────────────────────────")
    if results["suspicious_processes"]:
        for p in results["suspicious_processes"]:
            print(f"  [{p.get('TimeCreated')}] {p.get('SubjectUserName')} → {p.get('ProcessName')}")
    else:
        print("  None detected.")

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
    parser = argparse.ArgumentParser(description="SOC L1 - Windows Event Log Parser")
    parser.add_argument("--file", required=True, help="Path to windows_events.log file")
    parser.add_argument("--threshold", type=int, default=3, help="Brute force threshold (default: 3)")
    parser.add_argument("--output", help="Optional: save results to JSON file")
    args = parser.parse_args()

    results = parse_windows_events(args.file)
    alerts = detect_alerts(results, brute_threshold=args.threshold)

    print_report(results, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"results": results, "alerts": alerts}, f, indent=2, default=str)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
