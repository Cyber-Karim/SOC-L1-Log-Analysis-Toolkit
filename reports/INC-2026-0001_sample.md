# 🛡️ Incident Report — INC-2026-0001

---

## Incident Metadata

| Field              | Value                               |
|--------------------|-------------------------------------|
| **Incident ID**    | INC-2026-0001                       |
| **Date Created**   | 2026-04-26 02:20 UTC                |
| **Date Closed**    | 2026-04-26 04:00 UTC                |
| **Analyst**        | SOC L1 Analyst                      |
| **Severity**       | HIGH                                |
| **Status**         | Closed — Escalated to Tier 2        |
| **Ticket Ref**     | JIRA-SEC-0042                       |

---

## 1. Executive Summary

On April 26, 2026 at 02:14 UTC, the SIEM detected a brute-force SSH attack targeting production server `10.0.0.1` from external IP `203.0.113.42`. The attacker made 47 failed login attempts over 90 seconds targeting the `root` account. AbuseIPDB confirmed the IP with a 87/100 abuse confidence score. The IP was blocked at the firewall and the incident was escalated to Tier 2.

---

## 2. Detection Details

| Field              | Value                          |
|--------------------|--------------------------------|
| **Detection Source**   | auth.log / SIEM alert      |
| **Alert Name**         | BRUTE_FORCE_DETECTED           |
| **Alert Time**         | 2026-04-26 02:14:33 UTC        |
| **Log Source**         | /var/log/auth.log              |
| **Detection Rule**     | brute_force.py (threshold=5)   |

---

## 3. Affected Assets

| Asset          | Type   | IP Address | Role        | OS               |
|----------------|--------|------------|-------------|------------------|
| server-prod-01 | Server | 10.0.0.1   | Web Server  | Ubuntu 22.04 LTS |

---

## 4. Timeline of Events

| Time (UTC)       | Event                                                      |
|------------------|------------------------------------------------------------|
| 2026-04-26 02:14 | First failed SSH login from `203.0.113.42`                 |
| 2026-04-26 02:14 | 47 failed logins in 90 seconds — threshold exceeded        |
| 2026-04-26 02:15 | SIEM alert triggered — BRUTE_FORCE_DETECTED                |
| 2026-04-26 02:20 | SOC L1 analyst acknowledged alert                          |
| 2026-04-26 02:25 | AbuseIPDB lookup: score 87/100                             |
| 2026-04-26 02:30 | IP blocked at perimeter firewall                           |
| 2026-04-26 02:35 | No successful login confirmed                              |
| 2026-04-26 02:40 | Escalated to Tier 2 — JIRA-SEC-0042 created                |
| 2026-04-26 04:00 | Tier 2 confirmed containment — incident closed             |

---

## 5. IOCs

### IP Addresses

| IP Address     | Score      | Source    | Notes                  |
|----------------|-----------|-----------|------------------------|
| 203.0.113.42   | 87/100    | AbuseIPDB | Known SSH brute forcer |

---

## 6. Log Evidence

```
Apr 26 02:14:33 ubuntu sshd[1240]: Failed password for root from 203.0.113.42 port 43210 ssh2
Apr 26 02:14:35 ubuntu sshd[1240]: Failed password for root from 203.0.113.42 port 43210 ssh2
Apr 26 02:14:37 ubuntu sshd[1240]: Failed password for root from 203.0.113.42 port 43210 ssh2
[47 total failed attempts logged]
```

---

## 7. MITRE ATT&CK Mapping

| Tactic            | Technique                      | ID        |
|-------------------|--------------------------------|-----------|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access    | External Remote Services       | T1133     |

**Impact:** No successful login. No data accessed. No availability impact.

---

## 8. Containment

- [x] Source IP `203.0.113.42` blocked at perimeter firewall
- [x] Confirmed no successful authentication from attacker IP
- [x] Escalated to Tier 2 for threat intelligence correlation

---

## 9. Recommendations

1. Enable SSH key-only authentication — disable password login
2. Implement Fail2Ban on all public SSH servers
3. Restrict SSH to VPN/trusted IP ranges only

---

*Classification: INTERNAL USE ONLY*
