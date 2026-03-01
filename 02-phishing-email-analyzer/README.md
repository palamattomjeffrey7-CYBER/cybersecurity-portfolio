# 🎣 Project 02 — Phishing Email Analyzer

## Overview

A fully functional Python-based SOC L1 phishing triage tool that automates email analysis, IOC extraction, threat intelligence correlation, severity scoring, and incident ticket generation. Designed to replicate the exact workflow a SOC analyst follows when triaging phishing alerts.

---

## Scenario

A user reports a suspicious email to the SOC. As the L1 analyst on shift, you must triage the email within SLA (30 minutes for HIGH severity). This tool automates the critical first steps: extracting IOCs, checking them against threat intelligence, scoring severity, and generating a structured ticket for L2 escalation.

**Simulated Scenario Emails Included:**

| File | Scenario | Expected Severity |
|------|----------|-------------------|
| `phishing_sample_1.eml` | PayPal credential harvesting with typosquat domain + Tor exit node IP | CRITICAL |
| `phishing_sample_2.eml` | Microsoft 365 BEC with tracking pixel + phishkit infrastructure | HIGH |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    RAW .EML INPUT                        │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│               IOC EXTRACTION ENGINE                      │
│  ┌─────────┐ ┌──────┐ ┌────────┐ ┌───────┐ ┌────────┐ │
│  │   IPs   │ │ URLs │ │Domains │ │Hashes │ │Emails  │ │
│  └─────────┘ └──────┘ └────────┘ └───────┘ └────────┘ │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│           THREAT INTELLIGENCE CORRELATION                │
│  VirusTotal (simulated) │ AbuseIPDB (simulated)         │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│              SEVERITY SCORING ENGINE                     │
│     CRITICAL │ HIGH │ MEDIUM │ LOW                       │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌──────────────────┐  ┌──────────────────┐
│  INCIDENT TICKET │  │   JSON EXPORT    │
│  (L2 Escalation) │  │  (SIEM Ingest)   │
└──────────────────┘  └──────────────────┘
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Python 3** | Core analysis engine (standard library only — no pip installs) |
| **VirusTotal** | URL/domain/hash reputation lookup (simulated with built-in TI database) |
| **AbuseIPDB** | IP reputation and abuse scoring (simulated) |
| **MXToolbox** | SPF/DKIM/DMARC header validation concepts |
| **MITRE ATT&CK** | Technique mapping for incident classification |

---

## Methodology

1. **Parse** — Read raw `.eml` file including headers, body, and attachments
2. **Extract** — Pull all IOCs: IPs, URLs, domains, email addresses, file hashes, attachment names
3. **Enrich** — Correlate IOCs against threat intelligence databases (VirusTotal, AbuseIPDB)
4. **Score** — Calculate severity based on: known malicious indicators, sender reputation, urgency keywords, authentication failures
5. **Map** — Auto-map findings to MITRE ATT&CK techniques
6. **Report** — Generate structured incident ticket (Markdown) + machine-readable JSON export

---

## Investigation Steps

| Step | Action | Tool |
|------|--------|------|
| 1 | Obtain raw email (headers + body + attachments) | Email Gateway / User Report |
| 2 | Run phishing analyzer to extract all IOCs | `python phishing_analyzer.py` |
| 3 | Review extracted IPs — check AbuseIPDB scores | AbuseIPDB Lookup |
| 4 | Review URLs and domains — check VirusTotal | VirusTotal Lookup |
| 5 | Hash any attachments — check VirusTotal | VirusTotal Hash Lookup |
| 6 | Check SPF/DKIM/DMARC authentication results | Email Headers |
| 7 | Search for sender domain typosquatting patterns | Manual Review |
| 8 | Check if recipients clicked any links (proxy logs) | Web Gateway / SIEM |
| 9 | Assign severity and generate incident ticket | Analyzer Output |
| 10 | Escalate to L2 if severity ≥ HIGH | SOC Escalation Matrix |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1566.001 | Spearphishing Attachment | Malicious files attached to email |
| T1566.002 | Spearphishing Link | Credential harvesting URL in body |
| T1598.003 | Phishing for Information | BEC / social engineering attempts |
| T1071.001 | Application Layer Protocol: Web | C2 callback over HTTP/HTTPS |
| T1204.002 | User Execution: Malicious File | User opening attached payload |
| T1027 | Obfuscated Files or Information | Encoded payloads or redirectors |

---

## Results

**Sample 1 (PayPal Phishing):** Tool correctly identified typosquat domain (`paypa1-verification.com`), Tor exit node IP (abuse score: 98/100), extracted 3 malicious URLs, and scored as **CRITICAL**.

**Sample 2 (M365 BEC):** Tool identified phishkit infrastructure domain, tracking pixel, reply-to mismatch, and scored as **HIGH** with recommendation for immediate L2 escalation.

---

## Quick Start

```bash
# No pip installs needed — standard library only
cd 02-phishing-email-analyzer

python src/phishing_analyzer.py --email sample-emails/phishing_sample_1.eml
python src/phishing_analyzer.py --email sample-emails/phishing_sample_2.eml
```

See `output/sample_ticket_output.md` for example generated tickets.

---

## SOC Analyst Takeaways

- Always check **Reply-To mismatch** — the #1 indicator of phishing that bypasses gateway filters
- A single typosquat character (e.g., `paypa1` vs `paypal`) is enough to fool users
- Tor exit node IPs should be treated as CRITICAL regardless of other indicators
- Automate IOC extraction — manual analysis takes 15+ minutes; this tool does it in seconds
- Always generate machine-readable output (JSON) for SIEM correlation

---

## Remediation

| Action | Priority |
|--------|----------|
| Quarantine email from ALL mailboxes (not just reporter) | Immediate |
| Block sender domain + IP at email gateway and firewall | Immediate |
| Block malicious URLs at web proxy | Immediate |
| Reset passwords for any user who clicked links | Within 30 min |
| Revoke active sessions for affected accounts | Within 30 min |
| Run endpoint scan on machines that accessed phishing URLs | Within 1 hour |
| Submit IOCs to threat intel platform (MISP) | Within 2 hours |
| User awareness notification to organization | Within 24 hours |

---

*IOCs used are simulated for demonstration. In production, replace the built-in TI database with live VirusTotal and AbuseIPDB API integrations.*
