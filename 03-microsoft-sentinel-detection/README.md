# 🔍 Project 03 — Microsoft Sentinel Detection Rules Library

## Overview

A library of **15 production-ready KQL (Kusto Query Language) detection rules** for Microsoft Sentinel, covering the most common attack techniques seen in enterprise SOC environments. Each rule includes MITRE ATT&CK mapping, severity classification, threshold tuning, and recommended analyst response actions.

---

## Scenario

You are an L1 SOC analyst responsible for building and tuning detection rules in Microsoft Sentinel. The organization needs coverage for credential attacks, lateral movement, privilege escalation, data exfiltration, command-and-control activity, and ransomware indicators. Each rule must be production-ready with proper thresholds, false positive filtering, and actionable response guidance.

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    DATA SOURCES                             │
│  SecurityEvent │ SigninLogs │ DnsEvents │ OfficeActivity    │
│  CommonSecurityLog │ StorageFileLogs │ ThreatIntelIndicator │
└───────────────────────────┬────────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────────┐
│              MICROSOFT SENTINEL ANALYTICS                   │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  Credential  │  │   Lateral    │  │   Exfiltration   │ │
│  │   Attacks    │  │   Movement   │  │      & C2        │ │
│  │  Rules 1-3,6 │  │  Rules 7-8   │  │   Rules 9-10    │ │
│  └──────────────┘  └──────────────┘  └──────────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  Execution   │  │ Persistence  │  │   Impact         │ │
│  │   Rule 5     │  │  Rules 4,13  │  │   Rule 14        │ │
│  └──────────────┘  └──────────────┘  └──────────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  Identity    │  │  Collection  │  │  Threat Intel    │ │
│  │   Rule 11    │  │   Rule 12    │  │    Rule 15       │ │
│  └──────────────┘  └──────────────┘  └──────────────────┘ │
└───────────────────────────┬────────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────────┐
│              ALERT → INCIDENT → RESPONSE                    │
│  Severity Assignment │ MITRE Mapping │ Analyst Playbook     │
└────────────────────────────────────────────────────────────┘
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Microsoft Sentinel** | Cloud-native SIEM for log ingestion and analytics |
| **KQL (Kusto Query Language)** | Query language for detection rule logic |
| **MITRE ATT&CK Navigator** | Technique mapping and coverage visualization |
| **Azure Log Analytics** | Workspace for data collection and query execution |

---

## Methodology

1. **Identify** — Map MITRE ATT&CK techniques to organizational risk
2. **Design** — Write KQL queries targeting specific event patterns
3. **Tune** — Set thresholds to minimize false positives while catching true attacks
4. **Validate** — Test against sample data and known attack simulations
5. **Deploy** — Configure as Sentinel Analytics Rules with severity and automation
6. **Iterate** — Review false positive rates and refine detection logic

---

## Investigation Steps

For each triggered detection rule, the L1 analyst should follow this workflow:

| Step | Action | Tool |
|------|--------|------|
| 1 | Review the alert details — source IP, account, timestamp | Sentinel Incidents |
| 2 | Check if source IP is internal or external | IP Geolocation / CMDB |
| 3 | Correlate with other alerts for the same account/IP | Sentinel Investigation Graph |
| 4 | Check account history — is this normal behaviour? | Azure AD Sign-in Logs |
| 5 | Verify against known service accounts or automation | IT Asset Inventory |
| 6 | Classify as True Positive, Benign Positive, or False Positive | Analyst Judgment |
| 7 | If True Positive: execute containment playbook | IR Playbook |
| 8 | Document findings and escalate if HIGH/CRITICAL | Ticketing System |

---

## Rules Summary

| # | Rule | MITRE | Severity | Data Source |
|---|------|-------|----------|-------------|
| 01 | Brute Force Attack | T1110 | HIGH | SecurityEvent (4625) |
| 02 | Password Spray | T1110.003 | HIGH | SecurityEvent (4625) |
| 03 | Login After Brute Force | T1078 | CRITICAL | SecurityEvent (4625→4624) |
| 04 | Privilege Escalation — Admin Account Creation | T1136.001 | HIGH | SecurityEvent (4720, 4732) |
| 05 | Suspicious PowerShell Execution | T1059.001 | HIGH | SecurityEvent (4688) |
| 06 | LSASS Memory Dumping | T1003.001 | CRITICAL | SecurityEvent (4656) |
| 07 | Lateral Movement via RDP | T1021.001 | MEDIUM | SecurityEvent (4624) |
| 08 | Pass-the-Hash Detection | T1550.002 | HIGH | SecurityEvent (4624) |
| 09 | DNS Tunneling | T1048.001 | HIGH | DnsEvents |
| 10 | C2 Beaconing | T1071.001 | HIGH | CommonSecurityLog |
| 11 | Impossible Travel | T1078 | HIGH | SigninLogs |
| 12 | Mass File Access / Exfiltration | T1039 | HIGH | OfficeActivity |
| 13 | Scheduled Task Persistence | T1053.005 | MEDIUM | SecurityEvent (4698) |
| 14 | Ransomware — Mass File Encryption | T1486 | CRITICAL | StorageFileLogs |
| 15 | Threat Intel IP Match | T1190 | HIGH | CommonSecurityLog + TI Feed |

---

## MITRE ATT&CK Mapping

| Tactic | Techniques Covered |
|--------|-------------------|
| **Initial Access** | T1190, T1078 |
| **Credential Access** | T1110, T1110.003, T1003.001 |
| **Execution** | T1059.001 |
| **Persistence** | T1136.001, T1053.005 |
| **Lateral Movement** | T1021.001, T1550.002 |
| **Collection** | T1039 |
| **Exfiltration** | T1048.001 |
| **Command and Control** | T1071.001 |
| **Impact** | T1486 |

---

## Results

- **15 detection rules** covering 9 MITRE ATT&CK tactics
- Each rule includes severity classification, threshold tuning, and recommended response
- Rules designed to correlate across multiple data sources (SecurityEvent, SigninLogs, DnsEvents, OfficeActivity, CommonSecurityLog)
- False positive reduction through: machine account exclusion, threshold calibration, time-window scoping

---

## SOC Analyst Takeaways

- Rule 03 (Login After Brute Force) is the **highest-value detection** — it confirms account compromise, not just an attempt
- Always check Rule 06 (LSASS Dump) alerts immediately — this indicates active credential harvesting
- Rule 14 (Ransomware) should trigger an **immediate incident response** — do not wait for L2
- Combine Rule 01 + Rule 07 to detect attackers who brute force credentials then move laterally via RDP
- Impossible Travel (Rule 11) has the highest false positive rate — tune per organization's travel patterns

---

## Remediation

| Detection | Recommended Action |
|-----------|--------------------|
| Brute Force / Password Spray | Block source IP, enforce account lockout policy, enable MFA |
| Account Compromise | Reset credentials, revoke sessions, enable MFA, investigate lateral movement |
| Privilege Escalation | Disable unauthorized account, audit admin group membership |
| PowerShell Abuse | Isolate endpoint, collect forensic image, block script execution policy |
| LSASS Dumping | Isolate endpoint immediately, assume all credentials compromised, force org-wide reset |
| Lateral Movement | Disable compromised account, segment network, audit all accessed hosts |
| DNS Tunneling / C2 | Block domain at DNS, capture traffic, isolate source host |
| Ransomware | Invoke IR playbook, isolate all affected systems, notify management and legal |

---

## Files

```
03-microsoft-sentinel-detection/
├── README.md
├── kql-rules/
│   ├── rule-01-bruteforce.kql
│   ├── rule-02-password-spray.kql
│   ├── rule-03-compromise-after-bruteforce.kql
│   ├── rule-04-privilege-escalation.kql
│   ├── rule-05-suspicious-powershell.kql
│   ├── rule-06-lsass-dump.kql
│   ├── rule-07-rdp-lateral-movement.kql
│   ├── rule-08-pass-the-hash.kql
│   ├── rule-09-dns-tunneling.kql
│   ├── rule-10-c2-beaconing.kql
│   ├── rule-11-impossible-travel.kql
│   ├── rule-12-mass-file-access.kql
│   ├── rule-13-scheduled-task.kql
│   ├── rule-14-ransomware.kql
│   └── rule-15-threat-intel-match.kql
├── screenshots/
│   └── .gitkeep
└── documentation/
    ├── sentinel_detection_rules_full.kql
    └── rule_index.md
```

---

*All rules are designed for Microsoft Sentinel. Thresholds should be tuned based on organizational baseline before deployment to production.*
