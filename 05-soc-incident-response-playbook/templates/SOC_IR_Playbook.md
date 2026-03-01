# 📋 SOC Incident Response Playbook
### Author: Jeffrey Roshan Palamattom | L1 SOC Analyst
### Framework: NIST SP 800-61 Rev 2
### Last Updated: January 2024

---

## Overview

This playbook covers the 5 most common incident types handled in a 24×7 SOC environment. Each playbook follows the NIST SP 800-61 lifecycle:

```
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident
```

### SLA Reference Table

| Severity | Time to Triage (TTT) | Time to Qualify (TTQ) | Escalation |
|---|---|---|---|
| CRITICAL | 15 minutes | 30 minutes | L2 + CISO immediate |
| HIGH | 30 minutes | 1 hour | L2 within 30 min |
| MEDIUM | 2 hours | 4 hours | L2 if confirmed |
| LOW | 4 hours | 8 hours | Document only |

---

## Playbook 1 — Phishing Attack

**MITRE Techniques:** T1566.001, T1566.002, T1598  
**Default Severity:** HIGH (escalate to CRITICAL if credentials confirmed stolen)

### Detection Triggers
- User reports suspicious email
- Email gateway alert on malicious attachment/URL
- SIEM alert: known phishing domain in mail logs
- AV alert on email attachment

### Phase 1: Identification (TTT: 30 min)

| Step | Action | Tool |
|---|---|---|
| 1.1 | Obtain the reported email (raw headers + body) | Outlook/Gmail |
| 1.2 | Extract all IOCs: sender IP, reply-to, URLs, attachments | Phishing Analyzer |
| 1.3 | Check sender domain: typosquat? spoofed header? | MXToolbox |
| 1.4 | Check all URLs in VirusTotal and URLScan.io | VirusTotal |
| 1.5 | Check sender IP in AbuseIPDB | AbuseIPDB |
| 1.6 | Check file attachments — hash in VirusTotal | VirusTotal |
| 1.7 | Identify all recipients using email gateway search | Exchange/M365 |
| 1.8 | Check if any user clicked links (proxy/web gateway logs) | Proxy logs |
| 1.9 | Assign severity and create incident ticket | SIEM / Ticketing |

### Phase 2: Containment

| Step | Action | SLA |
|---|---|---|
| 2.1 | Quarantine email from ALL mailboxes (not just reporter) | Immediate |
| 2.2 | Block malicious URLs at web proxy | Immediate |
| 2.3 | Block sender domain at email gateway | Immediate |
| 2.4 | Block malicious IP at perimeter firewall | Within 15 min |
| 2.5 | If link clicked: isolate user's endpoint | Immediate |
| 2.6 | Reset password for any user who submitted credentials | Within 30 min |
| 2.7 | Revoke active sessions for affected accounts | Within 30 min |

### Phase 3: Eradication

- Remove malware from any infected endpoints
- Verify all instances of email removed from mail servers
- Confirm IOCs blocked across all security controls
- Run full AV scan on affected endpoints

### Phase 4: Recovery

- Restore from clean backup if endpoint was compromised
- Re-enable user accounts after password reset and MFA review
- Monitor for 48 hours for re-infection or callback activity

### Phase 5: Post-Incident

- Document full timeline in incident ticket
- Submit IOCs to threat intel platform (MISP, FS-ISAC)
- User awareness training referral
- Review email gateway rules to catch similar campaigns

### Escalation Criteria
- Credentials confirmed stolen → CRITICAL, escalate L2 + CISO
- Malware executed on endpoint → CRITICAL, escalate L2 + L3
- C-suite targeted (BEC) → CRITICAL, immediate management notification
- Multiple recipients across organization → HIGH, escalate L2

---

## Playbook 2 — Brute Force / Credential Attack

**MITRE Techniques:** T1110, T1110.003, T1078  
**Default Severity:** HIGH

### Detection Triggers
- SIEM alert: 10+ failed logins in 5 minutes (KQL Rule 01)
- SIEM alert: 1 IP targeting 20+ accounts (KQL Rule 02)
- Azure AD alert: Unusual sign-in activity
- User reports being locked out

### Phase 1: Identification

| Step | Action |
|---|---|
| 1.1 | Query SIEM for EventID 4625 — identify source IP and target accounts |
| 1.2 | Determine attack type: brute force (1 account) or spray (many accounts) |
| 1.3 | Check source IP in AbuseIPDB and threat intel feeds |
| 1.4 | Identify geographic location of source IP |
| 1.5 | Check if any login succeeded after the failures (KQL Rule 03) |
| 1.6 | Review account lockout status for targeted accounts |
| 1.7 | Check for simultaneous activity (lateral movement, data access) |

### Phase 2: Containment

| Step | Action | Priority |
|---|---|---|
| 2.1 | Block attacking IP at perimeter firewall | Immediate |
| 2.2 | Lock accounts under attack (if not auto-locked) | Immediate |
| 2.3 | Enable MFA for targeted accounts if not already active | High |
| 2.4 | If login succeeded: isolate the session, check for malicious activity | Immediate |
| 2.5 | Enable impossible travel detection in Azure AD | High |

### Phase 3: Eradication & Recovery

- Reset passwords for all targeted accounts
- Review and enable conditional access policies
- If account compromised: full review of account activity during compromise window
- Audit for any persistence mechanisms created during access

### Escalation Criteria
- Successful login after brute force → CRITICAL
- Service/admin account targeted → HIGH
- Domain admin credentials suspected → CRITICAL, escalate immediately

---

## Playbook 3 — Malware / Ransomware

**MITRE Techniques:** T1486, T1059, T1027, T1036  
**Default Severity:** CRITICAL

### ⚠ RANSOMWARE — ACTIVATE IMMEDIATELY

This is a **CRITICAL** incident. Time is the most important factor.

### Phase 1: Identification (TTT: 15 min)

| Step | Action |
|---|---|
| 1.1 | Confirm malware presence: AV alert, user reports, encrypted files |
| 1.2 | Identify affected host(s) and user(s) |
| 1.3 | Determine malware family if possible (file extension, ransom note) |
| 1.4 | Check if network shares are being encrypted (mass file rename alerts) |
| 1.5 | Identify patient zero — first infected system |
| 1.6 | Map network connections from infected host |

### Phase 2: Containment (IMMEDIATE — DO NOT DELAY)

| Step | Action |
|---|---|
| 2.1 | **IMMEDIATELY ISOLATE** all infected hosts — pull network cable or disable NIC |
| 2.2 | Disable affected user accounts |
| 2.3 | Block identified C2 IPs and domains at firewall |
| 2.4 | Isolate network segments if spread is detected |
| 2.5 | Take snapshot/memory dump BEFORE cleaning (forensics) |
| 2.6 | Alert IT to disable any affected backup jobs — protect clean backups |
| 2.7 | Preserve all logs before cleaning |

### Phase 3: Eradication

- Wipe and reimage affected systems — do NOT attempt to clean ransomware
- Remove malware from any non-encrypted systems if detected early
- Patch the vulnerability used for initial access
- Remove any persistence mechanisms (scheduled tasks, registry keys, startup items)

### Phase 4: Recovery

- Restore from **verified clean backups** — test before restoring
- Verify backups are not also encrypted before restoring
- Restore in isolated environment first, verify clean
- Gradually reconnect to production network with monitoring

### Do NOT:
- Pay the ransom without executive decision + legal counsel
- Restart infected systems (may trigger encryption completion)
- Remove logs or wipe systems before forensic image is taken

---

## Playbook 4 — Unauthorized Privilege Escalation

**MITRE Techniques:** T1078, T1136, T1053, T1003  
**Default Severity:** HIGH → CRITICAL

### Detection Triggers
- SIEM alert: New admin account created (KQL Rule 04)
- SIEM alert: LSASS access detected (KQL Rule 06)
- Threat hunt finding: unauthorized group membership change

### Phase 1: Identification

| Step | Action |
|---|---|
| 1.1 | Identify the account that was created or escalated |
| 1.2 | Identify the actor account that performed the action |
| 1.3 | Check EventID 4720, 4732, 4728, 4756 for group membership changes |
| 1.4 | Review timeline: what did the escalated account do after gaining access? |
| 1.5 | Check for credential dumping activity (EventID 4656 on lsass.exe) |
| 1.6 | Check for lateral movement from the account |
| 1.7 | Determine if this was authorized (change ticket, IT approval) |

### Phase 2: Containment

| Step | Action |
|---|---|
| 2.1 | Disable the unauthorized account immediately |
| 2.2 | Remove from all privileged groups |
| 2.3 | Revoke all active sessions for the account |
| 2.4 | Remove any scheduled tasks, startup items created by account |
| 2.5 | If credentials were dumped: assume ALL accounts on affected host compromised |

### Phase 3: Eradication & Recovery

- Full audit of all changes made by the unauthorized account
- Rotate ALL credentials on affected systems
- Review domain admin group membership
- Enable privileged access workstations (PAW) policy review

---

## Playbook 5 — DDoS Attack

**MITRE Techniques:** T1498, T1499  
**Default Severity:** HIGH

### Detection Triggers
- Network monitoring alert: traffic spike >500% baseline
- User reports: website/services unreachable
- ISP notification
- Firewall log: massive increase in connection attempts

### Phase 1: Identification

| Step | Action |
|---|---|
| 1.1 | Confirm DDoS: check bandwidth utilization, connection counts |
| 1.2 | Identify attack type: volumetric, protocol, or application layer |
| 1.3 | Identify source IPs (likely spoofed for volumetric) |
| 1.4 | Identify targeted service/port |
| 1.5 | Contact ISP/upstream provider — they may see more |
| 1.6 | Check if this is a smokescreen for another attack |

### Phase 2: Containment

| Step | Action |
|---|---|
| 2.1 | Activate DDoS mitigation service (Cloudflare, Akamai) |
| 2.2 | Implement rate limiting at firewall/WAF |
| 2.3 | Block malicious source IPs/ranges if identifiable |
| 2.4 | Enable geo-blocking if traffic from unexpected regions |
| 2.5 | Null-route targeted IP if service can fail over |
| 2.6 | Increase logging verbosity for full traffic analysis |

### Communication
- Notify management and business stakeholders of service impact
- Prepare customer communication if public-facing services affected
- Engage ISP for upstream filtering
- Log all business impact for post-incident report

---

## Incident Ticket Template

```
INCIDENT ID     : INC-YYYYMMDD-XXXX
DATE/TIME       : [UTC timestamp]
ANALYST         : [Name, Level]
CATEGORY        : [Phishing / Malware / Brute Force / Privesc / DDoS]
SEVERITY        : [CRITICAL / HIGH / MEDIUM / LOW]
STATUS          : [Open / Investigating / Contained / Closed]

DESCRIPTION:
[Brief description of the incident]

AFFECTED ASSETS:
- Users:    [list]
- Hosts:    [list]
- Services: [list]

IOCs IDENTIFIED:
- IPs:      [list]
- Domains:  [list]
- Hashes:   [list]

MITRE ATT&CK:
- [TID] — [Technique Name] — [Tactic]

TIMELINE:
[HH:MM] — [Action taken or event observed]
[HH:MM] — [Action taken or event observed]

ACTIONS TAKEN:
1. [Action]
2. [Action]

ESCALATION:
- Escalated to: [L2 / L3 / CISO / Management]
- Time:         [HH:MM UTC]
- Reason:       [Why escalated]

RESOLUTION:
[How the incident was resolved]

LESSONS LEARNED:
[What could be done better]
```

---

*This playbook is based on NIST SP 800-61 Rev 2 and practical SOC experience. Always follow your organization's specific escalation matrix and communication procedures.*
