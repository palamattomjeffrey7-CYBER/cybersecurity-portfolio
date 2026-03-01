# 🎫 SOC Incident Ticket Template

---

## Incident Details

| Field | Value |
|-------|-------|
| **Ticket ID** | INC-YYYYMMDD-XXXX |
| **Date/Time Opened** | YYYY-MM-DD HH:MM UTC |
| **Analyst** | [Your Name] |
| **Shift** | [Day / Night / Weekend] |
| **Severity** | [ ] CRITICAL  [ ] HIGH  [ ] MEDIUM  [ ] LOW |
| **Status** | [ ] Open  [ ] Investigating  [ ] Contained  [ ] Escalated  [ ] Closed |
| **Incident Type** | [ ] Phishing  [ ] Brute Force  [ ] Malware  [ ] Priv Esc  [ ] DDoS  [ ] Other |

---

## Alert Source

| Field | Value |
|-------|-------|
| **Source Tool** | [Sentinel / Splunk / CrowdStrike / Email Gateway / Firewall] |
| **Alert Name** | |
| **Alert ID** | |
| **Triggered At** | YYYY-MM-DD HH:MM UTC |
| **MITRE Technique** | |

---

## Affected Assets

| Asset | IP Address | Hostname | Owner | Status |
|-------|-----------|----------|-------|--------|
| | | | | [ ] Online  [ ] Isolated  [ ] Offline |
| | | | | [ ] Online  [ ] Isolated  [ ] Offline |

---

## Affected Accounts

| Account | Domain | Role | Status |
|---------|--------|------|--------|
| | | | [ ] Active  [ ] Locked  [ ] Reset  [ ] Disabled |
| | | | [ ] Active  [ ] Locked  [ ] Reset  [ ] Disabled |

---

## IOC Summary

| IOC Type | Value | TI Score | Source |
|----------|-------|----------|--------|
| IP Address | | | |
| Domain | | | |
| URL | | | |
| File Hash (MD5) | | | |
| File Hash (SHA256) | | | |
| Email Address | | | |

---

## Investigation Timeline

| Timestamp (UTC) | Action | Finding | Analyst |
|-----------------|--------|---------|---------|
| | Alert received | | |
| | Triage started | | |
| | IOC enrichment completed | | |
| | Classification determined | | |
| | Containment action taken | | |
| | Escalated to L2 | | |

---

## Classification

| | |
|---|---|
| **Verdict** | [ ] True Positive  [ ] Benign Positive  [ ] False Positive |
| **Confidence** | [ ] High  [ ] Medium  [ ] Low |
| **Justification** | |

---

## Containment Actions Taken

- [ ] Source IP blocked at firewall
- [ ] Malicious domain/URL blocked at proxy
- [ ] Affected account password reset
- [ ] Active sessions revoked
- [ ] Endpoint isolated via EDR
- [ ] Email quarantined from all mailboxes
- [ ] Other: _______________

---

## Escalation

| Field | Value |
|-------|-------|
| **Escalated To** | [ ] L2  [ ] L3  [ ] CISO  [ ] Legal  [ ] Management |
| **Escalation Time** | YYYY-MM-DD HH:MM UTC |
| **Reason** | |
| **L2 Analyst** | |

---

## SLA Compliance

| Metric | Target | Actual | Met? |
|--------|--------|--------|------|
| Time to Triage (TTT) | | | [ ] Yes  [ ] No |
| Time to Qualify (TTQ) | | | [ ] Yes  [ ] No |
| Time to Contain | | | [ ] Yes  [ ] No |
| Time to Resolve | | | [ ] Yes  [ ] No |

---

## Post-Incident Notes

**Root Cause:**


**Lessons Learned:**


**Recommendations:**


---

## Closure

| Field | Value |
|-------|-------|
| **Resolved By** | |
| **Resolution Date** | YYYY-MM-DD HH:MM UTC |
| **Resolution Summary** | |
| **IOCs Shared To TI Platform** | [ ] Yes  [ ] No |

---

*Template version 1.0 — Jeffrey Roshan Palamattom | SOC L1 Analyst*
