# 🚀 Portfolio Transformation Guide

## Quick Start — Push to GitHub

### Prerequisites
- Git installed on your machine
- GitHub account with repository created
- GitHub Personal Access Token (PAT) — [Create one here](https://github.com/settings/tokens)

### Step 1: Extract the ZIP

Extract `cybersecurity-portfolio-ready.zip` to a folder on your computer.

### Step 2: Open Terminal / Command Prompt

```bash
cd cybersecurity-portfolio
```

### Step 3: Initialize and Push

```bash
git init
git add .
git commit -m "Initial commit — Complete SOC Analyst Portfolio"
git branch -M main
git remote add origin https://github.com/palamattomjeffrey7-CYBER/cybersecurity-portfolio.git
git push -u origin main
```

When prompted for password, use your **Personal Access Token** (not your GitHub password).

### If Repository Already Has Content

```bash
git push -u origin main --force
```

---

## What's Included

| Item | Count | Description |
|------|-------|-------------|
| Project READMEs | 6 | Root + 5 project READMEs with full professional content |
| KQL Detection Rules | 15 | Individual `.kql` files for Microsoft Sentinel |
| SPL Hunt Scripts | 6 | Individual `.spl` files for Splunk threat hunting |
| Python Tools | 2 | Phishing analyzer + Threat hunter (fully functional) |
| Sample Data | 5+ | Sample emails, logs, and output reports |
| IR Playbook | 1 | Complete 5-scenario NIST SP 800-61 playbook |
| Incident Templates | 1 | Reusable SOC incident ticket template |
| Sample Incidents | 3 | Phishing, brute force, and ransomware examples |
| Evidence (AWS) | 110 | Dissertation screenshots from AWS pentest |
| Screenshot Checklist | 1 | Guide for remaining screenshots needed |

---

## Next Steps After Push

1. **Add screenshots** — Follow `SCREENSHOT-CHECKLIST.md` to add evidence screenshots for projects 02-05
2. **Pin the repository** — Go to your GitHub profile → click "Customize your pins" → select this repo
3. **Update LinkedIn** — Add the GitHub link to your LinkedIn profile under Projects
4. **Run the tools** — Execute the Python tools to generate fresh output and capture screenshots
5. **Customize** — Update contact information, add LinkedIn URL, adjust content as needed

---

## Repository Structure

```
cybersecurity-portfolio/
├── README.md                              ← Professional GitHub landing page
├── PORTFOLIO-TRANSFORMATION-GUIDE.md      ← This file
├── SCREENSHOT-CHECKLIST.md                ← Evidence screenshots needed
│
├── 01-aws-cloud-pentest/                  ← Award-winning MSc dissertation
│   ├── README.md                          ← Full writeup with 110 evidence images
│   ├── architecture/
│   ├── attack-chain/
│   ├── evidence/                          ← 110 dissertation screenshots
│   └── remediation/
│
├── 02-phishing-email-analyzer/            ← Python SOC triage tool
│   ├── README.md
│   ├── src/
│   │   └── phishing_analyzer.py           ← Fully functional Python tool
│   ├── sample-emails/
│   │   ├── phishing_sample_1.eml
│   │   └── phishing_sample_2.eml
│   ├── output/                            ← Pre-generated analysis reports
│   └── evidence/
│
├── 03-microsoft-sentinel-detection/       ← 15 KQL detection rules
│   ├── README.md
│   ├── kql-rules/
│   │   ├── rule-01-bruteforce.kql
│   │   ├── rule-02-password-spray.kql
│   │   ├── ... (15 rules total)
│   │   └── rule-15-threat-intel-match.kql
│   ├── screenshots/
│   └── documentation/
│       ├── sentinel_detection_rules_full.kql
│       └── rule_index.md
│
├── 04-splunk-threat-hunting/              ← SPL threat hunting framework
│   ├── README.md
│   ├── scripts/
│   │   ├── threat_hunter.py               ← Fully functional Python tool
│   │   ├── hunt-01-bruteforce.spl
│   │   ├── ... (6 hunts total)
│   │   └── hunt-06-privilege-escalation.spl
│   ├── logs/
│   │   └── windows_security_events.json   ← Sample attack data
│   ├── results/                           ← Pre-generated hunt reports
│   └── evidence/
│
├── 05-soc-incident-response-playbook/     ← NIST SP 800-61 IR runbook
│   ├── README.md
│   ├── templates/
│   │   ├── SOC_IR_Playbook.md             ← Full 5-scenario playbook
│   │   └── incident-ticket-template.md    ← Reusable ticket template
│   └── sample-incidents/
│       ├── sample-incident-phishing.md
│       ├── sample-incident-bruteforce.md
│       └── sample-incident-ransomware.md
│
├── assets/
│   └── images/
└── resume/
```

---

*Built by Jeffrey Roshan Palamattom — MSc Cyber Security (Distinction), CEH*
