# 🛡️ SOC L1 Log Analysis Toolkit

> A hands-on log analysis project simulating the day-to-day responsibilities of a **Security Operations Center (SOC) Level 1 Analyst** — covering log ingestion, threat detection, IOC lookups, and incident reporting.

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Log Types Covered](#log-types-covered)
- [Detection Rules](#detection-rules)
- [IOC Lookup Integrations](#ioc-lookup-integrations)
- [Sample Alerts](#sample-alerts)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## 🔍 Overview

This project replicates real-world workflows performed by a Tier 1 / Level 1 SOC Analyst. The goal is to build a practical toolkit for:

- Parsing and analyzing raw security logs
- Detecting common threats (brute force, port scans, suspicious logins, etc.)
- Enriching alerts with threat intelligence (VirusTotal, AbuseIPDB, Shodan)
- Documenting findings in structured incident reports

This is a portfolio/learning project designed to demonstrate blue team fundamentals.

---

## ✨ Features

- 📂 **Multi-format log parser** — supports Syslog, Windows Event Logs (EVTX), Apache/Nginx access logs, and auth logs
- 🔎 **Detection engine** — rule-based alerting for brute force, failed logins, port scans, and anomalous activity
- 🌐 **IOC Enrichment** — automated lookups via VirusTotal, AbuseIPDB, and Shodan APIs
- 📊 **Visual dashboards** — Kibana dashboards via Elastic Stack integration
- 📝 **Incident report generator** — auto-generates structured reports from triggered alerts
- 🐳 **Docker-ready** — spin up full ELK stack with a single command

---

## 📁 Project Structure

```
soc-log-analysis/
│
├── logs/                        # Sample log files for testing
│   ├── auth.log                 # Linux authentication logs
│   ├── syslog.log               # System logs
│   ├── windows_events.evtx      # Windows Event Logs
│   └── apache_access.log        # Web server access logs
│
├── parsers/                     # Log parsing modules
│   ├── parse_auth.py            # Parses Linux auth logs
│   ├── parse_evtx.py            # Parses Windows EVTX files
│   └── parse_web.py             # Parses Apache/Nginx logs
│
├── detections/                  # Detection rules & alert logic
│   ├── brute_force.py           # Detects failed login patterns
│   ├── port_scan.py             # Detects scanning behavior
│   └── suspicious_login.py      # Off-hours or geo-anomaly logins
│
├── ioc_lookup/                  # Threat intelligence integrations
│   ├── virustotal_check.py      # Hash/IP/domain lookup via VirusTotal
│   ├── abuseipdb_check.py       # IP reputation check via AbuseIPDB
│   └── shodan_lookup.py         # Host info via Shodan
│
├── reports/                     # Generated incident reports
│   └── incident_template.md     # Markdown template for reports
│
├── notebooks/                   # Jupyter notebooks for analysis
│   └── log_analysis_demo.ipynb
│
├── docker-compose.yml           # ELK stack setup
├── requirements.txt             # Python dependencies
├── .env.example                 # API key template
└── README.md
```

---

## ⚙️ Prerequisites

Make sure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.9+ | Core scripting |
| Docker & Docker Compose | Latest | Run ELK stack |
| Git | Any | Version control |
| jq | Any | CLI JSON log parsing |

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/soc-log-analysis.git
cd soc-log-analysis
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt includes:**
```
pandas
matplotlib
requests
python-dotenv
loguru
python-evtx
virustotal-python
shodan
elasticsearch
jupyter
```

### 3. Configure API Keys

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

> 🔑 Free API keys available at: [VirusTotal](https://www.virustotal.com), [AbuseIPDB](https://www.abuseipdb.com), [Shodan](https://www.shodan.io)

### 4. Spin Up ELK Stack (Optional)

```bash
docker-compose up -d
```

Access Kibana at: `http://localhost:5601`

---

## 🧪 Usage

### Run Log Parser

```bash
python parsers/parse_auth.py --file logs/auth.log
```

### Run Detection Engine

```bash
python detections/brute_force.py --file logs/auth.log --threshold 5
```

### IOC Lookup

```bash
python ioc_lookup/abuseipdb_check.py --ip 192.168.1.100
python ioc_lookup/virustotal_check.py --hash <md5_or_sha256>
```

### Launch Jupyter Notebook

```bash
jupyter notebook notebooks/log_analysis_demo.ipynb
```

---

## 📋 Log Types Covered

| Log Type | Source | Key Events Analyzed |
|----------|--------|---------------------|
| `auth.log` | Linux | SSH logins, sudo usage, failed auth |
| `syslog` | Linux | Service crashes, kernel messages |
| `.evtx` | Windows | Event IDs 4624, 4625, 4672, 4688 |
| `access.log` | Apache/Nginx | HTTP status codes, URI patterns, IPs |

---

## 🚨 Detection Rules

| Rule | Description | Trigger |
|------|-------------|---------|
| Brute Force | Multiple failed logins from same IP | 5+ failures in 60s |
| Port Scan | Sequential port connection attempts | 10+ ports in 10s |
| Off-Hours Login | Successful login outside business hours | Success between 11PM–6AM |
| Privilege Escalation | Sudo/admin use by non-admin account | Event ID 4672 |
| Web Scanning | High rate of 404s from single IP | 20+ 404s in 30s |

---

## 🌐 IOC Lookup Integrations

| Platform | What It Checks | API Docs |
|----------|---------------|----------|
| VirusTotal | IPs, domains, file hashes | [docs](https://developers.virustotal.com) |
| AbuseIPDB | IP reputation & abuse reports | [docs](https://docs.abuseipdb.com) |
| Shodan | Open ports, banners, geolocation | [docs](https://developer.shodan.io) |

---

## 📝 Sample Alerts

```
[ALERT] Brute Force Detected
  Source IP   : 203.0.113.42
  Target User : root
  Attempts    : 47 failed logins in 90 seconds
  Time        : 2025-04-26 02:14:33 UTC
  Action      : Escalate to Tier 2 / Block IP

[ALERT] Suspicious Off-Hours Login
  Source IP   : 10.0.0.15
  Username    : jsmith
  Login Time  : 03:22 AM
  AbuseIPDB   : Score 87/100 (High Risk)
  Action      : Investigate session activity
```

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-detection-rule`
3. Commit your changes: `git commit -m "Add: new detection for lateral movement"`
4. Push and open a Pull Request

Please follow the existing code style and include comments in your detection scripts.

---

## ⚠️ Disclaimer

This project is for **educational and portfolio purposes only**. All log samples are either synthetic or anonymized. Do not use any scripts against systems you do not own or have explicit permission to test.

---

*Built by a SOC L1 Analyst in training | Blue Team | Defensive Security*
