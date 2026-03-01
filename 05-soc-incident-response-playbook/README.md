# 📋 Project 05 — SOC Incident Response Playbook

## Overview

A comprehensive SOC incident response runbook following the **NIST SP 800-61 Rev 2** framework, covering the 5 most common incident types handled in enterprise 24×7 SOC environments. Each playbook provides step-by-step procedures from detection through post-incident review, with SLA targets, escalation matrices, and MITRE ATT&CK alignment.

---

## Scenario

You are an L1 SOC analyst in a 24×7 Security Operations Center responsible for triaging, containing, and escalating security incidents. The SOC handles 200+ alerts per day across SIEM, EDR, email gateway, and firewall platforms. These playbooks define exactly what to do for each incident type — following them ensures consistent, SLA-compliant response regardless of which analyst is on shift.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ALERT SOURCES                         │
│  SIEM │ EDR │ Email Gateway │ Firewall │ Cloud Security  │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│              NIST SP 800-61 LIFECYCLE                     │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Preparation  │→│  Detection   │→│ Containment    │  │
│  │              │  │ & Analysis   │  │                │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
│                                            ↓             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │Post-Incident│←│   Recovery   │←│  Eradication   │  │
│  │   Review    │  │              │  │                │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Microsoft Sentinel** | SIEM — alert detection and correlation |
| **CrowdStrike Falcon** | EDR — endpoint detection and isolation |
| **Proofpoint / M365 Defender** | Email gateway — phishing detection |
| **Palo Alto / FortiGate** | Firewall — network containment |
| **VirusTotal / AbuseIPDB** | Threat intelligence lookups |
| **ServiceNow / Jira** | Incident ticketing and tracking |

---

## Methodology

Each playbook follows the **NIST SP 800-61 Rev 2** incident handling lifecycle:

1. **Preparation** — Tools, access, contact lists ready
2. **Detection & Analysis** — Identify, triage, classify severity
3. **Containment** — Stop the bleeding, prevent spread
4. **Eradication** — Remove the threat completely
5. **Recovery** — Restore normal operations
6. **Post-Incident** — Lessons learned, IOC sharing, report

---

## Playbooks Included

| # | Incident Type | Default Severity | Key MITRE | SLA (TTT) |
|---|---------------|------------------|-----------|-----------|
| 1 | Phishing Attack | HIGH | T1566.001, T1566.002 | 30 min |
| 2 | Brute Force / Credential Attack | HIGH | T1110, T1110.003, T1078 | 30 min |
| 3 | Malware / Ransomware | CRITICAL | T1486, T1059, T1204 | 15 min |
| 4 | Unauthorized Privilege Escalation | HIGH | T1078, T1136, T1053 | 30 min |
| 5 | DDoS Attack | HIGH | T1498, T1499 | 30 min |

---

## Investigation Steps (General Framework)

| Step | Action | Responsibility |
|------|--------|---------------|
| 1 | Alert received — open incident ticket | L1 Analyst |
| 2 | Triage — classify severity (CRITICAL/HIGH/MEDIUM/LOW) | L1 Analyst |
| 3 | Investigate — gather evidence using SIEM, EDR, TI tools | L1 Analyst |
| 4 | Classify — True Positive / Benign Positive / False Positive | L1 Analyst |
| 5 | Contain — execute immediate containment actions | L1 Analyst |
| 6 | Escalate — if HIGH/CRITICAL, escalate to L2 | L1 → L2 |
| 7 | Eradicate — remove threat (L2/L3 responsibility) | L2/L3 |
| 8 | Recover — restore systems and verify | L2/L3 |
| 9 | Document — complete incident ticket with full timeline | All |
| 10 | Review — conduct lessons learned session | SOC Lead |

---

## SLA Reference Table

| Severity | Time to Triage (TTT) | Time to Qualify (TTQ) | Escalation |
|----------|---------------------|-----------------------|------------|
| CRITICAL | 15 minutes | 30 minutes | L2 + CISO Immediate |
| HIGH | 30 minutes | 1 hour | L2 within 30 min |
| MEDIUM | 2 hours | 4 hours | L2 if confirmed |
| LOW | 4 hours | 8 hours | Document only |

---

## MITRE ATT&CK Mapping

| Playbook | Techniques Covered |
|----------|-------------------|
| Phishing | T1566.001, T1566.002, T1598, T1204.002, T1071.001 |
| Brute Force | T1110, T1110.001, T1110.003, T1078, T1021.001 |
| Malware/Ransomware | T1486, T1059.001, T1204.002, T1027, T1547.001, T1071 |
| Privilege Escalation | T1078, T1136.001, T1053.005, T1098 |
| DDoS | T1498, T1499, T1583 |

---

## Results

- **5 complete playbooks** covering the most common SOC incident types
- Each playbook includes detection triggers, investigation checklists, containment actions, and recovery procedures
- **SLA targets** defined for all severity levels
- **Escalation matrix** with clear L1 → L2 → L3 → CISO handoff points
- **Incident ticket template** for consistent documentation across all analysts
- Aligned to **NIST SP 800-61 Rev 2** framework throughout

---

## SOC Analyst Takeaways

- **Containment first** — stop the bleeding before investigating further
- Always **check for lateral movement** after confirming any credential compromise
- Ransomware = CRITICAL = **all hands on deck** — do not wait for L2 to start containment
- Document everything with timestamps — you're building an evidence chain
- After every significant incident, push for a **lessons learned session** — this is how the SOC improves
- Keep your escalation contacts updated — nothing worse than reaching a disconnected number during a CRITICAL incident

---

## Remediation

| Incident Type | Key Remediation Actions |
|---------------|------------------------|
| Phishing | Quarantine emails org-wide, block IOCs, reset compromised credentials, user awareness training |
| Brute Force | Enforce account lockout, enable MFA, block source IPs, review all access from compromised accounts |
| Malware/Ransomware | Isolate affected hosts, restore from clean backups, patch exploited vulnerability, full AV sweep |
| Privilege Escalation | Disable unauthorized accounts, audit admin groups, review audit logs for 30 days prior |
| DDoS | Enable cloud DDoS protection, rate limit, work with ISP for upstream filtering |

---

## Files

```
05-soc-incident-response-playbook/
├── README.md
├── templates/
│   ├── SOC_IR_Playbook.md              ← Full 5-playbook runbook
│   └── incident-ticket-template.md     ← Reusable incident ticket template
└── sample-incidents/
    ├── sample-incident-phishing.md
    ├── sample-incident-bruteforce.md
    └── sample-incident-ransomware.md
```

---

*Playbooks are designed for enterprise SOC environments. Adjust SLA targets and escalation contacts to match your organization's requirements.*
