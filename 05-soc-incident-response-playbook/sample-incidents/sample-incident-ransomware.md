# Sample Incident — Ransomware

## Incident Details

| Field | Value |
|-------|-------|
| **Ticket ID** | INC-20260225-0312 |
| **Date/Time** | 2026-02-25 03:12 UTC |
| **Analyst** | Jeffrey Roshan Palamattom |
| **Severity** | CRITICAL |
| **Status** | Closed |
| **Type** | Ransomware — File Encryption |

## Alert Source

CrowdStrike Falcon triggered a CRITICAL alert: mass file rename activity on endpoint `WS-FIN-042` (Finance department). 847 files renamed with `.locked` extension in 2 minutes. Simultaneously, Sentinel Rule 14 (Ransomware Indicator) fired.

## Investigation Summary

1. **03:12** — CrowdStrike alert received. Opened ticket. Severity: CRITICAL (immediate).
2. **03:14** — Endpoint `WS-FIN-042` isolated via CrowdStrike network containment. User `finance-mlee` account disabled.
3. **03:16** — Escalated to L2 + L3 + CISO. Ransomware IR playbook invoked.
4. **03:20** — Checked for lateral spread: no other endpoints showing encryption activity.
5. **03:25** — L3 identified ransomware variant as LockBit 3.0 via hash analysis. Entry point: malicious macro in Excel attachment received via email 2 hours prior.
6. **03:30** — Email quarantined org-wide. Malicious domain blocked.
7. **04:00** — Confirmed encryption limited to `WS-FIN-042` local drives only. Network shares not affected due to rapid isolation.
8. **06:00** — Endpoint wiped and rebuilt from gold image. Data restored from last night's backup (0 data loss).
9. **08:00** — Post-incident review scheduled. IOCs shared with industry ISAC.

## Verdict

**True Positive — LockBit 3.0 Ransomware** (CRITICAL)

## SLA Compliance

| Metric | Target | Actual | Met? |
|--------|--------|--------|------|
| TTT | 15 min | 2 min | ✅ Yes |
| Containment | Immediate | 2 min | ✅ Yes |
| Recovery | 4 hours | 2.8 hours | ✅ Yes |
