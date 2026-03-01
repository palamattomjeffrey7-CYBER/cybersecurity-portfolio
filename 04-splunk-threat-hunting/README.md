# 📊 Project 04 — Splunk Threat Hunting

## Overview

A fully functional threat hunting framework that replicates **Splunk SPL query logic** to analyze Windows Security Event logs. Includes a Python-based threat hunter tool, 6 SPL-style detection queries, sample attack logs with a realistic 8-step attack chain, and automated hunt report generation. No Splunk license required — runs entirely on the included sample data.

---

## Scenario

The SOC receives a threat intelligence alert indicating that IP addresses `45.142.212.100` and `91.108.4.200` are associated with active APT campaigns targeting organizations in the region. As a threat hunter, your mission is to proactively search historical logs for evidence of compromise linked to these indicators and reconstruct the full attack chain if found.

**Simulated Attack Chain in Sample Logs:**

| Step | Activity | Event ID | MITRE |
|------|----------|----------|-------|
| 1 | Brute force against `jsmith` from malicious IP | 4625 | T1110 |
| 2 | Password spray targeting 8 accounts | 4625 | T1110.003 |
| 3 | Successful login after brute force (account compromise) | 4624 | T1078 |
| 4 | Lateral movement via RDP to 4 internal hosts | 4624 (Type 10) | T1021.001 |
| 5 | Encoded PowerShell execution on SQL server | 4688 | T1059.001 |
| 6 | LSASS memory dump attempt (Mimikatz pattern) | 4656 | T1003.001 |
| 7 | Backdoor admin account creation | 4720, 4732 | T1136.001 |
| 8 | Malicious scheduled task for C2 persistence | 4698 | T1053.005 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│             WINDOWS SECURITY EVENT LOGS                   │
│              (JSON — sample included)                      │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│              THREAT HUNTING ENGINE                        │
│                                                          │
│  Hunt 1: Brute Force Detection                           │
│  Hunt 2: Password Spray Detection                        │
│  Hunt 3: Post-Brute-Force Compromise                     │
│  Hunt 4: RDP Lateral Movement                            │
│  Hunt 5: Suspicious Process Execution                    │
│  Hunt 6: Privilege Escalation                            │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌────────────────────┐  ┌────────────────────┐
│  ATTACK CHAIN      │  │   HUNT REPORT      │
│  RECONSTRUCTION    │  │  (TXT + JSON)      │
└────────────────────┘  └────────────────────┘
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Splunk (SPL Logic)** | Threat hunting query design and correlation |
| **Python 3** | Threat hunter execution engine (standard library only) |
| **Windows Security Events** | Primary log source (Event IDs: 4624, 4625, 4656, 4688, 4698, 4720, 4732) |
| **MITRE ATT&CK** | Technique mapping for hunt hypotheses |

---

## Methodology

1. **Hypothesis** — Form a threat hunting hypothesis based on TI alerts or MITRE techniques
2. **Data Collection** — Identify required log sources (Windows Security Events, Sysmon)
3. **Query Design** — Write SPL queries to test each hypothesis
4. **Execution** — Run queries against historical log data
5. **Analysis** — Review results, identify anomalies, correlate across hunts
6. **Chain Reconstruction** — Link findings into a complete attack narrative
7. **Report** — Document findings with evidence and recommended actions

---

## Investigation Steps

| Step | Action | SPL Equivalent |
|------|--------|----------------|
| 1 | Search for brute force patterns against known target accounts | `stats count by Account where EventCode=4625 \| where count >= 5` |
| 2 | Check for password spray (single IP → many accounts) | `stats dc(Account) by src_ip \| where dc >= 20` |
| 3 | Correlate: did any brute-forced account later succeed? | `join` of EventCode 4625 → 4624 on Account |
| 4 | Hunt for RDP lateral movement from compromised accounts | `stats dc(Computer) by Account where LogonType=10 \| where dc >= 3` |
| 5 | Search for suspicious process execution (encoded PS, LSASS) | `search CommandLine IN (*enc*, *downloadstring*, *lsass*)` |
| 6 | Detect privilege escalation (new accounts, group changes) | `search EventCode IN (4720, 4732, 4698)` |
| 7 | Reconstruct full attack chain timeline | Automated by `threat_hunter.py` |
| 8 | Generate hunt report with findings and recommendations | Automated output (TXT + JSON) |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Hunt Coverage |
|--------------|------|---------------|
| T1110 | Brute Force | Hunt 1 — Failed login threshold detection |
| T1110.003 | Password Spray | Hunt 2 — Single IP targeting multiple accounts |
| T1078 | Valid Accounts | Hunt 3 — Successful login post-brute force |
| T1021.001 | Remote Desktop Protocol | Hunt 4 — RDP to 3+ hosts |
| T1059.001 | PowerShell | Hunt 5 — Encoded commands and download cradles |
| T1003.001 | LSASS Memory | Hunt 5 — LSASS access pattern detection |
| T1136.001 | Create Account: Local | Hunt 6 — Unauthorized account creation |
| T1053.005 | Scheduled Task | Hunt 6 — Persistence via task scheduler |

---

## Results

The threat hunter successfully:
- Detected **brute force** against `jsmith` (97 failed attempts from `45.142.212.100`)
- Identified **password spray** across 8 accounts from same source
- Confirmed **account compromise** — successful login after brute force
- Traced **lateral movement** via RDP to 4 internal hosts (DC01, SQL01, FS01, WS042)
- Flagged **encoded PowerShell** execution and **LSASS dump** attempt
- Detected **backdoor account** creation and **scheduled task** persistence
- Reconstructed the **complete 8-step attack chain** with timeline

---

## Quick Start

```bash
cd 04-splunk-threat-hunting

python scripts/threat_hunter.py --logs logs/windows_security_events.json
```

Results are saved to the `results/` directory as `.txt` (human-readable) and `.json` (machine-readable).

---

## SOC Analyst Takeaways

- Hunt 3 (Compromise After Brute Force) is the **most critical finding** — it confirms the adversary succeeded
- Always check for lateral movement immediately after confirming credential compromise
- LSASS dump detection means the adversary likely has credentials for multiple accounts — assume full domain compromise
- Scheduled tasks are a favourite persistence mechanism — check for unusual task creators
- The attack chain reconstruction shows how a single brute force leads to full compromise in minutes

---

## Remediation

| Finding | Recommended Action | Priority |
|---------|-------------------|----------|
| Brute Force Source IP | Block at perimeter firewall, add to deny list | Immediate |
| Compromised Account | Reset password, revoke sessions, enable MFA | Immediate |
| Lateral Movement | Isolate affected hosts, check for malware | Immediate |
| Encoded PowerShell | Forensic image of host, check for payloads | High |
| LSASS Dump | Assume domain compromise, force org-wide password reset | Critical |
| Backdoor Account | Disable immediately, audit all recent account creations | Immediate |
| Scheduled Task | Delete task, check for C2 callbacks, block C2 domain | High |

---

## Files

```
04-splunk-threat-hunting/
├── README.md
├── scripts/
│   ├── threat_hunter.py
│   ├── hunt-01-bruteforce.spl
│   ├── hunt-02-password-spray.spl
│   ├── hunt-03-post-bruteforce-compromise.spl
│   ├── hunt-04-rdp-lateral-movement.spl
│   ├── hunt-05-suspicious-processes.spl
│   └── hunt-06-privilege-escalation.spl
├── logs/
│   └── windows_security_events.json
├── results/
│   ├── HUNT-20260228-1454.json
│   ├── HUNT-20260301-1121.json
│   └── sample_hunt_report.md
└── evidence/
    └── .gitkeep
```

---

*Sample logs are synthetic/anonymized. The threat hunter replicates Splunk SPL logic without requiring a Splunk license.*
