# 🔍 KQL Detection Rules — Rule Index

## Quick Reference

| # | Rule Name | MITRE ID | Tactic | Severity | Data Source |
|---|---|---|---|---|---|
| 01 | Brute Force Attack | T1110 | Credential Access | HIGH | SecurityEvent |
| 02 | Password Spray Attack | T1110.003 | Credential Access | HIGH | SecurityEvent |
| 03 | Successful Login After Brute Force | T1078 | Initial Access | CRITICAL | SecurityEvent |
| 04 | Local Admin Account Creation | T1136.001 | Persistence | HIGH | SecurityEvent |
| 05 | Suspicious PowerShell Execution | T1059.001 | Execution | HIGH/CRITICAL | SecurityEvent |
| 06 | LSASS Memory Dumping | T1003.001 | Credential Access | CRITICAL | SecurityEvent |
| 07 | Lateral Movement via RDP | T1021.001 | Lateral Movement | MEDIUM/HIGH | SecurityEvent |
| 08 | Pass-the-Hash Detection | T1550.002 | Lateral Movement | HIGH | SecurityEvent |
| 09 | DNS Tunneling | T1048.001 | Exfiltration | HIGH/CRITICAL | DnsEvents |
| 10 | C2 Beaconing | T1071.001 | Command & Control | HIGH | CommonSecurityLog |
| 11 | Impossible Travel | T1078 | Initial Access | HIGH/CRITICAL | SigninLogs |
| 12 | Mass File Access / Exfiltration | T1039 | Collection | HIGH | OfficeActivity |
| 13 | Scheduled Task Persistence | T1053.005 | Persistence | MEDIUM/HIGH | SecurityEvent |
| 14 | Ransomware — Mass File Encryption | T1486 | Impact | CRITICAL | StorageFileLogs |
| 15 | TI Feed IP Match — Inbound | T1190 | Initial Access | HIGH/CRITICAL | CommonSecurityLog + TI |

---

## How to Deploy in Microsoft Sentinel

### Option 1: Analytics Rules UI
1. Open **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. Paste the KQL rule into the **Set rule logic** tab
3. Configure alert threshold and frequency
4. Map to MITRE ATT&CK in the **Incident settings** tab
5. Enable and save

### Option 2: ARM Template Deployment
```powershell
az deployment group create \
  --resource-group <your-rg> \
  --template-file sentinel-rules-arm.json
```

### Option 3: Sentinel API
```python
import requests

rule_payload = {
    "kind": "Scheduled",
    "properties": {
        "displayName": "Brute Force Attack",
        "query": "<paste KQL here>",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "severity": "High"
    }
}
```

---

## Tuning Guidelines

### Reducing False Positives

| Rule | Common FP | Tuning Suggestion |
|---|---|---|
| 01 — Brute Force | IT doing password resets | Whitelist IT admin IPs |
| 02 — Password Spray | Misconfigured service accounts | Whitelist service account names |
| 07 — RDP Lateral | Admins managing servers | Whitelist admin subnets |
| 11 — Impossible Travel | VPN users | Exclude known VPN exit IP ranges |
| 12 — Mass File Access | Backup jobs | Whitelist backup service accounts |

---

## Data Sources Required

| Data Source | Connector in Sentinel |
|---|---|
| Windows Security Events | Azure Monitor Agent or MMA |
| Azure AD Sign-in Logs | Azure Active Directory connector |
| DNS Events | DNS Analytics solution |
| Firewall Logs (CEF) | Common Security Log connector |
| Office 365 Audit | Microsoft 365 connector |
| Threat Intelligence | TI Platforms connector (TAXII) |
