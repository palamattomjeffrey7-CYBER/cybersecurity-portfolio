# Sample Incident — Phishing Attack

## Incident Details

| Field | Value |
|-------|-------|
| **Ticket ID** | INC-20260215-0847 |
| **Date/Time** | 2026-02-15 08:47 UTC |
| **Analyst** | Jeffrey Roshan Palamattom |
| **Severity** | HIGH → Escalated to CRITICAL |
| **Status** | Closed |
| **Type** | Phishing — Credential Harvesting |

## Alert Source

Microsoft Defender for Office 365 flagged an inbound email to 12 users in the Finance department. The email impersonated a DocuSign notification with a link to `docusign-verify[.]com` (typosquat).

## Investigation Summary

1. **08:47** — Alert received from email gateway. Opened ticket.
2. **08:52** — Extracted IOCs: sender IP `185.220.101.47` (Tor exit node, AbuseIPDB 98/100), domain `docusign-verify[.]com` (VirusTotal 45/90 malicious).
3. **08:58** — Checked proxy logs: 3 users clicked the link. 1 user (`finance-jdoe`) submitted credentials on the phishing page.
4. **09:02** — Severity escalated to CRITICAL. Escalated to L2.
5. **09:05** — Containment: email quarantined from all 12 mailboxes, domain blocked at proxy, sender IP blocked at firewall.
6. **09:10** — Password reset for `finance-jdoe`, active sessions revoked, MFA re-enrolled.
7. **09:30** — L2 confirmed no further compromise. No lateral movement detected.
8. **09:45** — IOCs submitted to MISP. Incident closed.

## Verdict

**True Positive — Credential Harvesting Phishing** (CRITICAL)

## SLA Compliance

| Metric | Target | Actual | Met? |
|--------|--------|--------|------|
| TTT | 30 min | 5 min | ✅ Yes |
| TTQ | 1 hour | 11 min | ✅ Yes |
| Containment | Immediate | 18 min | ✅ Yes |
