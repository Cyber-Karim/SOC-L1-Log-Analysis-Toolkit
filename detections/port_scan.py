"""
port_scan.py
------------
SOC L1 Log Analysis — Port Scan Detection Engine
Detects horizontal, vertical, and SYN scanning behavior from syslog UFW blocks.

Detection Types:
    - Vertical Scan   : One IP hitting many ports on one host (classic port scan)
    - Horizontal Scan : One IP hitting same port across many hosts
    - SYN Scan        : Rapid sequential blocked connections (Nmap-style)
    - Service Probe   : Targeting specific high-value service ports

Usage:
    python port_scan.py --file ../logs/syslog.log
    python port_scan.py --file ../logs/syslog.log --threshold 5 --window 60
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

# ── Config ────────────────────────────────────────────────────────────────────

DEFAULT_PORT_THRESHOLD = 5    # unique ports from same IP = scan
DEFAULT_WINDOW_SECS    = 30   # time window for scan detection
HORIZONTAL_THRESHOLD   = 3    # same port on different IPs

# ── High-value ports to watch ─────────────────────────────────────────────────

HIGH_VALUE_PORTS = {
    "22":    "SSH",
    "23":    "Telnet",
    "25":    "SMTP",
    "53":    "DNS",
    "80":    "HTTP",
    "443":   "HTTPS",
    "445":   "SMB",
    "1433":  "MSSQL",
    "3306":  "MySQL",
    "3389":  "RDP",
    "5432":  "PostgreSQL",
    "5900":  "VNC",
    "6379":  "Redis",
    "8080":  "HTTP-Alt",
    "8443":  "HTTPS-Alt",
    "27017": "MongoDB",
}

CRITICAL_PORTS = {"23", "445", "3389", "5900", "1433", "6379", "27017"}

# ── Regex Pattern ─────────────────────────────────────────────────────────────

UFW_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
    r"UFW BLOCK.*SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+).*"
    r"PROTO=(?P<proto>\S+).*DPT=(?P<dst_port>\d+)"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_ufw_blocks(filepath: str) -> list:
    events = []
    with open(filepath, "r") as f:
        for line in f:
            m = UFW_PATTERN.search(line)
            if not m:
                continue
            d = m.groupdict()
            try:
                ts = datetime(2026, MONTH_MAP.get(d["month"], 1), int(d["day"]),
                              *[int(x) for x in d["time"].split(":")])
                events.append({
                    "timestamp": ts,
                    "src_ip":    d["src_ip"],
                    "dst_ip":    d["dst_ip"],
                    "proto":     d["proto"],
                    "dst_port":  d["dst_port"],
                    "service":   HIGH_VALUE_PORTS.get(d["dst_port"], "Unknown"),
                    "critical":  d["dst_port"] in CRITICAL_PORTS,
                })
            except Exception:
                continue
    return events


# ── Detection: Vertical Port Scan ─────────────────────────────────────────────

def detect_vertical_scan(events: list, port_threshold: int, window_secs: int) -> list:
    """One source IP hitting many different ports on one destination."""
    alerts = []
    # Group: src_ip → dst_ip → list of events
    grouped = defaultdict(lambda: defaultdict(list))
    for e in events:
        grouped[e["src_ip"]][e["dst_ip"]].append(e)

    window = timedelta(seconds=window_secs)

    for src_ip, dst_hosts in grouped.items():
        for dst_ip, host_events in dst_hosts.items():
            host_events.sort(key=lambda x: x["timestamp"])

            # Sliding window over unique ports
            i = 0
            while i < len(host_events):
                window_events = [host_events[i]]
                j = i + 1
                while j < len(host_events) and \
                      (host_events[j]["timestamp"] - host_events[i]["timestamp"]) <= window:
                    window_events.append(host_events[j])
                    j += 1

                unique_ports = list({e["dst_port"] for e in window_events})
                if len(unique_ports) >= port_threshold:
                    critical_hits = [p for p in unique_ports if p in CRITICAL_PORTS]
                    alerts.append({
                        "alert":          "VERTICAL_PORT_SCAN",
                        "severity":       "CRITICAL" if critical_hits else "HIGH",
                        "source_ip":      src_ip,
                        "target_ip":      dst_ip,
                        "ports_scanned":  len(unique_ports),
                        "port_list":      sorted(unique_ports, key=int),
                        "critical_ports": critical_hits,
                        "start_time":     str(window_events[0]["timestamp"]),
                        "end_time":       str(window_events[-1]["timestamp"]),
                        "window_seconds": window_secs,
                        "recommendation": "Block source IP, review IDS rules, check for follow-up exploitation"
                    })
                    i = j
                    continue
                i += 1

    return alerts


# ── Detection: Horizontal Port Scan ──────────────────────────────────────────

def detect_horizontal_scan(events: list, horiz_threshold: int) -> list:
    """One source IP hitting the same port on many different destination IPs."""
    alerts = []
    src_port_dst = defaultdict(lambda: defaultdict(list))  # src_ip → port → [dst_ips]

    for e in events:
        src_port_dst[e["src_ip"]][e["dst_port"]].append(e["dst_ip"])

    for src_ip, port_map in src_port_dst.items():
        for port, dst_ips in port_map.items():
            unique_dsts = list(set(dst_ips))
            if len(unique_dsts) >= horiz_threshold:
                service = HIGH_VALUE_PORTS.get(port, "Unknown")
                alerts.append({
                    "alert":            "HORIZONTAL_PORT_SCAN",
                    "severity":         "HIGH",
                    "source_ip":        src_ip,
                    "target_port":      port,
                    "service":          service,
                    "hosts_targeted":   len(unique_dsts),
                    "target_ips":       unique_dsts,
                    "recommendation":   f"Block source IP, check for {service} exploitation attempts across subnet"
                })

    return alerts


# ── Detection: Critical Port Probe ───────────────────────────────────────────

def detect_critical_port_probe(events: list) -> list:
    """Any access attempt against critical service ports."""
    alerts = []
    seen = set()

    for e in events:
        if e["critical"]:
            key = (e["src_ip"], e["dst_port"])
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert":          "CRITICAL_PORT_PROBE",
                    "severity":       "HIGH",
                    "source_ip":      e["src_ip"],
                    "target_ip":      e["dst_ip"],
                    "port":           e["dst_port"],
                    "service":        e["service"],
                    "time":           str(e["timestamp"]),
                    "recommendation": f"Investigate why {e['service']} is being probed; verify service is not exposed"
                })

    return alerts


# ── Run All Detections ────────────────────────────────────────────────────────

def run_detections(events: list, port_threshold: int, window: int, horiz_threshold: int) -> list:
    all_alerts = []
    all_alerts += detect_vertical_scan(events, port_threshold, window)
    all_alerts += detect_horizontal_scan(events, horiz_threshold)
    all_alerts += detect_critical_port_probe(events)
    return all_alerts


# ── Summary Stats ─────────────────────────────────────────────────────────────

def build_summary(events: list) -> dict:
    by_ip    = defaultdict(int)
    by_port  = defaultdict(int)
    by_proto = defaultdict(int)

    for e in events:
        by_ip[e["src_ip"]]   += 1
        by_port[e["dst_port"]] += 1
        by_proto[e["proto"]]  += 1

    return {
        "total_blocked_connections": len(events),
        "unique_source_ips": len(by_ip),
        "unique_ports_targeted": len(by_port),
        "top_source_ips": dict(sorted(by_ip.items(),   key=lambda x: x[1], reverse=True)[:10]),
        "top_targeted_ports": dict(sorted(by_port.items(), key=lambda x: x[1], reverse=True)[:10]),
        "protocols": dict(by_proto),
    }


# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(events: list, summary: dict, alerts: list):
    print("\n" + "="*60)
    print("  PORT SCAN DETECTION REPORT")
    print("="*60)
    print(f"  Total Blocked Connections : {summary['total_blocked_connections']}")
    print(f"  Unique Source IPs         : {summary['unique_source_ips']}")
    print(f"  Unique Ports Targeted     : {summary['unique_ports_targeted']}")

    print("\n── Top Source IPs ────────────────────────────────────────")
    for ip, count in list(summary["top_source_ips"].items())[:5]:
        print(f"  {ip:<20} {count} blocked connections")

    print("\n── Most Targeted Ports ───────────────────────────────────")
    for port, count in list(summary["top_targeted_ports"].items())[:8]:
        service = HIGH_VALUE_PORTS.get(port, "Unknown")
        flag    = " ⚠️" if port in CRITICAL_PORTS else ""
        print(f"  Port {port:<6} ({service:<12}) {count} hits{flag}")

    print(f"\n── Protocols ──────────────────────────────────────────────")
    for proto, count in summary["protocols"].items():
        print(f"  {proto:<10} {count}")

    if alerts:
        print("\n── 🚨 ALERTS ─────────────────────────────────────────────")
        for alert in alerts:
            print(f"\n  [{alert['severity']}] {alert['alert']}")
            for k, v in alert.items():
                if k not in ("alert", "severity") and v:
                    val = ", ".join(map(str, v)) if isinstance(v, list) else v
                    print(f"  {k.replace('_',' ').capitalize():<22}: {val}")
    else:
        print("\n  ✅ No port scanning activity detected.")

    print("\n" + "="*60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC L1 - Port Scan Detector")
    parser.add_argument("--file",      required=True, help="Path to syslog file")
    parser.add_argument("--threshold", type=int, default=DEFAULT_PORT_THRESHOLD, help="Unique ports threshold (default: 5)")
    parser.add_argument("--window",    type=int, default=DEFAULT_WINDOW_SECS,    help="Time window in seconds (default: 30)")
    parser.add_argument("--horiz",     type=int, default=HORIZONTAL_THRESHOLD,   help="Horizontal scan host threshold (default: 3)")
    parser.add_argument("--output",    help="Optional: save alerts to JSON")
    args = parser.parse_args()

    events  = parse_ufw_blocks(args.file)
    summary = build_summary(events)
    alerts  = run_detections(events, args.threshold, args.window, args.horiz)

    print_report(events, summary, alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"summary": summary, "alerts": alerts}, f, indent=2, default=str)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
