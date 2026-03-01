╔══════════════════════════════════════════════════════════════════════════════╗
║              SOC INCIDENT TICKET — PHISHING ANALYSIS REPORT                ║
╚══════════════════════════════════════════════════════════════════════════════╝

TICKET ID    : INC-20240115-2784
CREATED      : 2024-01-15 09:45:23 UTC
ANALYST      : Jeffrey Roshan Palamattom (L1 SOC)
SOURCE       : Phishing Email Analyzer v1.0
EMAIL FILE   : phishing_sample_1.eml

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEVERITY ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠  SEVERITY : [CRITICAL]
  📊 SCORE    : 155/200
  🎯 VERDICT  : MALICIOUS — IMMEDIATE ACTION REQUIRED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXTRACTED IOCs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [IPs Found]: 1
    • 185.220.101.47

  [URLs Found]: 3
    • http://paypal-secure-verify.ru/login?ref=9f3a2b1c
    • http://www.paypal.com/verify-account  ← SPOOFED DISPLAY URL
    • http://cdn.paypa1-verification.com/files/account_statement.pdf.exe

  [Domains Found]: 3
    • paypal-secure-verify.ru
    • cdn.paypa1-verification.com
    • paypa1-verify.net

  [File Hashes Found]: 1
    • d41d8cd98f00b204e9800998ecf8427e  (MD5)

  [Suspicious Email Addresses]: 3
    • security-alert@paypa1-verification.com
    • bounce@paypa1-verification.com
    • documents@paypa1-verify.net

  [Attachments]: 1
    • account_statement.pdf.exe  ← DOUBLE EXTENSION — HIGH RISK

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [MALICIOUS IPs — AbuseIPDB]:
    ✗ 185.220.101.47 | Score: 98/100 | Country: NL | Reports: 847
      → Tor Exit Node — associated with credential theft campaigns

  [MALICIOUS DOMAINS — VirusTotal]:
    ✗ paypal-secure-verify.ru | VT: 71/90 | Category: Credential Harvesting
    ✗ paypa1-verification.com | VT: 45/90 | Category: Phishing

  [MALICIOUS FILE HASHES — VirusTotal]:
    ✗ d41d8cd98f00b204e9800998ecf8427e | VT: 32/70 | Threat: Trojan.GenericKD

  [SUSPICIOUS SENDER ANALYSIS]:
    ✗ paypa1-verification.com — typosquat of paypal.com (uses digit "1" for "l")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SOCIAL ENGINEERING INDICATORS (7 Found)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    • "urgent"
    • "account limited"
    • "suspended"
    • "unusual activity"
    • "action required"
    • "within 24 hours"
    • "permanently suspended"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MITRE ATT&CK MAPPING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [Initial Access]          T1566.001 — Phishing: Spearphishing Attachment
  [Initial Access]          T1566.002 — Phishing: Spearphishing Link
  [Reconnaissance]          T1598.003 — Phishing for Information
  [Command and Control]     T1071.001 — Application Layer Protocol: Web Protocols
  [Defense Evasion]         T1027     — Obfuscated Files or Information

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDED ACTIONS [CRITICAL]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. IMMEDIATELY block 185.220.101.47 at perimeter firewall
  2. Block domains: paypa1-verification.com, paypal-secure-verify.ru at DNS/proxy
  3. Quarantine email from ALL mailboxes via email gateway (search by Message-ID)
  4. Identify other recipients — run mail gateway search for same campaign
  5. Isolate any endpoint that clicked the links
  6. Escalate to L2/L3 SOC analyst within 15 minutes
  7. Initiate Phishing IR Playbook
  8. Notify CISO and management per escalation matrix
  9. Preserve full email headers as forensic evidence

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SLA TARGETS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Time to Triage (TTT)     : 15 min
  Time to Qualify (TTQ)    : 30 min
  Escalation Required      : YES — L2 + CISO

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
END OF TICKET: INC-20240115-2784
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
