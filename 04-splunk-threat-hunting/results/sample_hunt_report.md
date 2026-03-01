# Threat Hunt Report: HUNT-20240115-0854

**Generated:** 2024-01-15 08:54:00 UTC  
**Analyst:** Jeffrey Roshan Palamattom (L1 SOC)  
**Log File:** windows_security_events.json (37 events)  
**Hunt Queries:** 6 executed

---

## Executive Summary

| Metric | Value |
|---|---|
| Total Findings | 10 |
| Critical Alerts | 4 |
| Attack Chain | **FULL ATTACK CHAIN RECONSTRUCTED** |
| Overall Assessment | ⚠ **ACTIVE INTRUSION — IMMEDIATE IR REQUIRED** |

---

## Reconstructed Attack Chain (8 Steps)

```
STEP 1 — INITIAL ACCESS ATTEMPT: Brute force detected against jsmith (12 attempts in <5 min)
STEP 2 — CREDENTIAL ATTACK: Password spray from 2 IPs targeting 8 accounts
STEP 3 — ACCOUNT COMPROMISE: jsmith account compromised (login succeeded from attacking IP)
STEP 4 — LATERAL MOVEMENT: Attacker RDP'd into 4 hosts: WKSTN-01, WKSTN-07, SQL-SERVER-01, FILE-SERVER-01
STEP 5 — EXECUTION: Encoded PowerShell executed on SQL-SERVER-01 (download cradle + AMSI bypass)
STEP 6 — CREDENTIAL DUMPING: LSASS memory accessed by mimikatz.exe — all creds on host likely stolen
STEP 7 — PERSISTENCE: New account "svc_hidden_backdoor" created and added to Administrators group
STEP 8 — PERSISTENCE: Malicious scheduled task created on DC01 with encoded PowerShell payload
```

---

## Hunt Results

### Hunt 1 — Brute Force (T1110)
✗ **jsmith** | IP: `45.142.212.100` | 12 attempts | Known malicious IP: **YES**

### Hunt 2 — Password Spray (T1110.003)
✗ `45.142.212.100` → targeted **8 accounts**, 19 attempts  
✗ `91.108.4.200` → targeted **5 accounts**, 5 attempts

### Hunt 3 — Account Compromise (T1078)
✗ **jsmith** compromised — login succeeded from brute force IP `45.142.212.100`

### Hunt 4 — Lateral Movement via RDP (T1021.001)
✗ **jsmith** accessed **4 hosts** within 1 hour: WKSTN-01 → WKSTN-07 → SQL-SERVER-01 → FILE-SERVER-01

### Hunt 5 — Suspicious Processes (T1059.001)
✗ **[CRITICAL]** jsmith on SQL-SERVER-01: `powershell -nop -windowstyle hidden -encodedcommand ...`  
Indicators: Encoded command, AMSI bypass, hidden window, download cradle

### Hunt 6 — Privilege Escalation & Persistence (T1003, T1136, T1053)
✗ **[CRITICAL]** LSASS memory access by `mimikatz.exe` on SQL-SERVER-01  
✗ **[HIGH]** New account `svc_hidden_backdoor` created by jsmith on DC01  
✗ **[CRITICAL]** `svc_hidden_backdoor` added to Administrators group on DC01  
✗ **[CRITICAL]** Scheduled task `\Microsoft\Windows\Update\SystemUpdate` created with encoded PowerShell

---

## Recommended Immediate Actions

1. **ISOLATE** WKSTN-01, WKSTN-07, SQL-SERVER-01, FILE-SERVER-01, DC01
2. **RESET** jsmith credentials, revoke all sessions
3. **DISABLE** `svc_hidden_backdoor` account immediately
4. **REMOVE** scheduled task `\Microsoft\Windows\Update\SystemUpdate` from DC01
5. **BLOCK** `45.142.212.100`, `91.108.4.200`, `185.220.101.47` at perimeter firewall
6. **ESCALATE** to L2/L3 SOC and CISO — confirmed intrusion
7. **PRESERVE** memory dump of SQL-SERVER-01 and DC01 for forensics
8. **INITIATE** full Incident Response — Ransomware/APT playbook
