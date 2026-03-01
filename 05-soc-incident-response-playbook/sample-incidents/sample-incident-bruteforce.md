# Sample Incident — Brute Force / Account Compromise

## Incident Details

| Field | Value |
|-------|-------|
| **Ticket ID** | INC-20260220-1234 |
| **Date/Time** | 2026-02-20 12:34 UTC |
| **Analyst** | Jeffrey Roshan Palamattom |
| **Severity** | CRITICAL |
| **Status** | Closed |
| **Type** | Brute Force → Account Compromise → Lateral Movement |

## Alert Source

Microsoft Sentinel Rule 03 (Successful Login After Brute Force) triggered for account `svc-backup`. 47 failed logins followed by a successful login from IP `91.108.4.200` (Russia, AbuseIPDB 87/100).

## Investigation Summary

1. **12:34** — Sentinel alert received. Opened ticket. Severity: CRITICAL (auto).
2. **12:38** — Confirmed 47 failed logins (EventID 4625) in 3 minutes from `91.108.4.200`, then successful login (EventID 4624) at 12:31 UTC.
3. **12:42** — Checked lateral movement: account `svc-backup` made RDP connections to DC01, FS01, SQL01 within 8 minutes of compromise.
4. **12:45** — Escalated to L2 + L3. Containment: disabled `svc-backup`, blocked `91.108.4.200` at firewall, isolated DC01/FS01/SQL01.
5. **13:15** — L3 forensics: no evidence of data exfiltration or credential dumping. Attack was interrupted by rapid containment.
6. **14:00** — All 3 hosts verified clean. Services restored with new credentials.
7. **14:30** — Incident closed. Recommendation: enable MFA for all service accounts.

## Verdict

**True Positive — Account Compromise with Lateral Movement** (CRITICAL)

## SLA Compliance

| Metric | Target | Actual | Met? |
|--------|--------|--------|------|
| TTT | 15 min | 4 min | ✅ Yes |
| TTQ | 30 min | 8 min | ✅ Yes |
| Containment | Immediate | 11 min | ✅ Yes |
