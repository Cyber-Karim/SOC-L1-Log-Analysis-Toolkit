# 🛡️ Incident Report — SOC Level 1

---

## Incident Metadata

| Field              | Value                          |
|--------------------|--------------------------------|
| **Incident ID**    | INC-2026-XXXX                  |
| **Date Created**   | YYYY-MM-DD HH:MM UTC           |
| **Date Closed**    | YYYY-MM-DD HH:MM UTC           |
| **Analyst**        | [Your Name]                    |
| **Severity**       | CRITICAL / HIGH / MEDIUM / LOW |
| **Status**         | Open / In Progress / Closed    |
| **Ticket Ref**     | JIRA-XXXX / ServiceNow-XXXX    |

---

## 1. Executive Summary

> _Provide a 2–3 sentence plain-language summary of what happened, what systems were affected, and what action was taken. Write this as if explaining to a non-technical manager._

**Example:**
> On April 26, 2026 at 02:14 UTC, our SIEM detected a brute-force SSH attack against the production server `10.0.0.1` originating from external IP `203.0.113.42`. The attack resulted in 47 failed login attempts over 90 seconds. The source IP was blocked at the perimeter firewall and the incident was escalated to Tier 2 for further investigation.

---

## 2. Detection Details

| Field              | Value                          |
|--------------------|--------------------------------|
| **Detection Source**   | SIEM / IDS / Auth Log / Manual |
| **Alert Name**         | e.g., BRUTE_FORCE_DETECTED     |
| **Alert Time**         | YYYY-MM-DD HH:MM:SS UTC        |
| **Log Source**         | e.g., /var/log/auth.log        |
| **Detection Rule**     | e.g., brute_force.py           |

---

## 3. Affected Assets

| Asset          | Type       | IP Address     | Role              | OS / Version     |
|----------------|------------|----------------|-------------------|------------------|
| server-prod-01 | Server     | 10.0.0.1       | Web Server        | Ubuntu 22.04 LTS |
|                |            |                |                   |                  |

---

## 4. Timeline of Events

| Time (UTC)          | Event                                                     |
|---------------------|-----------------------------------------------------------|
| YYYY-MM-DD HH:MM    | First failed login detected from `<IP>`                   |
| YYYY-MM-DD HH:MM    | Brute force threshold exceeded (N attempts in T seconds)  |
| YYYY-MM-DD HH:MM    | Alert triggered in SIEM                                   |
| YYYY-MM-DD HH:MM    | SOC L1 analyst began investigation                        |
| YYYY-MM-DD HH:MM    | IOC lookup performed (VirusTotal / AbuseIPDB)             |
| YYYY-MM-DD HH:MM    | Source IP blocked at firewall                             |
| YYYY-MM-DD HH:MM    | Escalated to Tier 2 / Ticket created                      |
| YYYY-MM-DD HH:MM    | Incident closed / Monitoring resumed                      |

---

## 5. Indicators of Compromise (IOCs)

### IP Addresses

| IP Address      | Reputation Score | Source       | Notes                  |
|-----------------|-----------------|--------------|------------------------|
| 203.0.113.42    | 87/100 (High)   | AbuseIPDB    | Known SSH brute forcer |
|                 |                 |              |                        |

### File Hashes (if applicable)

| Hash (SHA256)   | VirusTotal Result | File Name    | Notes       |
|-----------------|-------------------|--------------|-------------|
|                 |                   |              |             |

### Domains / URLs (if applicable)

| Domain / URL    | Category      | First Seen   | Notes       |
|-----------------|---------------|--------------|-------------|
|                 |               |              |             |

---

## 6. Evidence Collected

- [ ] Raw log excerpt saved to `reports/evidence/INC-2026-XXXX_auth.log`
- [ ] Screenshot of SIEM alert
- [ ] IOC lookup output saved to `reports/evidence/INC-2026-XXXX_ioc.json`
- [ ] Network capture (if applicable)
- [ ] Memory dump (if applicable)

```
── Log Excerpt ────────────────────────────────────────────────────────────────
Apr 26 02:14:33 ubuntu sshd[1240]: Failed password for root from 203.0.113.42
Apr 26 02:14:35 ubuntu sshd[1240]: Failed password for root from 203.0.113.42
Apr 26 02:14:37 ubuntu sshd[1240]: Failed password for root from 203.0.113.42
[... continued ...]
───────────────────────────────────────────────────────────────────────────────
```

---

## 7. Analysis

### Attack Description

> _Describe the attack technique in detail. What was the attacker trying to do? What MITRE ATT&CK tactic/technique does this map to?_

**MITRE ATT&CK Mapping:**

| Tactic             | Technique                          | ID          |
|--------------------|------------------------------------|-------------|
| Credential Access  | Brute Force: Password Guessing     | T1110.001   |
| Initial Access     | External Remote Services           | T1133        |

### Root Cause

> _What allowed this to happen? Was a port unnecessarily exposed? Was there no account lockout policy?_

### Impact Assessment

| Category       | Impact     | Details                           |
|----------------|------------|-----------------------------------|
| Confidentiality | None / Low / High | Was any data accessed?    |
| Integrity       | None / Low / High | Were any files modified?  |
| Availability    | None / Low / High | Was any service disrupted?|

---

## 8. Containment Actions Taken

- [ ] Source IP blocked at perimeter firewall (`iptables -A INPUT -s <IP> -j DROP`)
- [ ] Affected user account locked / password reset
- [ ] SSH key rotated on affected server
- [ ] Session terminated
- [ ] System isolated from network (if compromise confirmed)
- [ ] Other: _______________

---

## 9. Recommendations

> _List short-term and long-term recommendations to prevent recurrence._

### Immediate (< 24 hours)

1. Block IP `203.0.113.42` at perimeter and cloud WAF
2. Enable account lockout after 5 failed attempts
3. Review all accounts for unauthorized access

### Short-Term (< 1 week)

1. Enforce SSH key-based authentication — disable password login
2. Implement Fail2Ban or equivalent on all public-facing SSH servers
3. Restrict SSH access to VPN/trusted IPs only via firewall rule

### Long-Term (< 1 month)

1. Deploy MFA on all privileged accounts
2. Review and harden firewall ruleset — principle of least privilege
3. Tune SIEM detection rules to reduce alert fatigue

---

## 10. Escalation

| Escalated To        | Time (UTC)       | Reason                        | Response |
|---------------------|------------------|-------------------------------|----------|
| Tier 2 Analyst      | YYYY-MM-DD HH:MM | Confirmed brute force pattern | Pending  |
| Security Manager    |                  |                               |          |
| IR Team             |                  |                               |          |

---

## 11. Lessons Learned

> _What went well? What could be improved? Any gaps in detection, process, or tooling?_

- **Went well:** Alert triggered within 90 seconds of attack onset
- **Improvement:** No automated IP blocking rule in place — added manually
- **Gap:** No geo-blocking rule for high-risk TLDs

---

## 12. Analyst Notes

```
[Free text area for additional notes, raw log lines, command outputs, etc.]



```

---

## Sign-Off

| Role              | Name            | Date             | Signature |
|-------------------|-----------------|------------------|-----------|
| SOC L1 Analyst    |                 | YYYY-MM-DD       |           |
| SOC L2 Reviewer   |                 | YYYY-MM-DD       |           |
| Team Lead         |                 | YYYY-MM-DD       |           |

---

*This report was generated using the SOC L1 Log Analysis Toolkit*
*Classification: INTERNAL USE ONLY*
