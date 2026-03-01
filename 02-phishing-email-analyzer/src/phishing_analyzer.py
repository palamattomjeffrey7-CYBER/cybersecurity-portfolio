#!/usr/bin/env python3
"""
=============================================================================
SOC L1 Phishing Email Analyzer
Author: Jeffrey Roshan Palamattom
Role:   L1 SOC Analyst Portfolio Project
Tool:   Automates phishing triage — IOC extraction, threat scoring, ticketing
=============================================================================
"""

import re
import argparse
import hashlib
import json
import os
from datetime import datetime
from email import message_from_file, message_from_string
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────
# THREAT INTELLIGENCE SIMULATION
# In production: replace with live VirusTotal / AbuseIPDB API calls
# ─────────────────────────────────────────────────────────

KNOWN_MALICIOUS_IPS = {
    "185.220.101.47": {"abuse_score": 98, "country": "NL", "isp": "Tor Exit Node", "reports": 847},
    "91.108.4.200":   {"abuse_score": 87, "country": "RU", "isp": "Unknown Hosting", "reports": 312},
    "45.142.212.100": {"abuse_score": 76, "country": "UA", "isp": "BulletProof Hosting", "reports": 203},
}

KNOWN_MALICIOUS_DOMAINS = {
    "paypa1-verification.com": {"vt_score": "45/90", "category": "Phishing", "first_seen": "2024-01-10"},
    "paypa1-verify.net":       {"vt_score": "38/90", "category": "Phishing", "first_seen": "2024-01-12"},
    "micros0ft-helpdesk.com":  {"vt_score": "52/90", "category": "Phishing", "first_seen": "2024-01-14"},
    "phishkit.xyz":            {"vt_score": "67/90", "category": "Phishing/C2", "first_seen": "2023-12-01"},
    "paypal-secure-verify.ru": {"vt_score": "71/90", "category": "Credential Harvesting", "first_seen": "2024-01-08"},
    "m365-renew.phishkit.xyz": {"vt_score": "55/90", "category": "Phishing", "first_seen": "2024-01-15"},
}

KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {"vt_score": "32/70", "threat": "Trojan.GenericKD", "severity": "HIGH"},
    "5d41402abc4b2a76b9719d911017c592": {"vt_score": "28/70", "threat": "Dropper.Agent", "severity": "HIGH"},
}

SUSPICIOUS_KEYWORDS = [
    "urgent", "account limited", "verify immediately", "click here",
    "update payment", "suspended", "expires", "unusual activity",
    "confirm your identity", "your account will be", "action required",
    "immediately", "within 24 hours", "permanently suspended"
]

# ─────────────────────────────────────────────────────────
# IOC EXTRACTION
# ─────────────────────────────────────────────────────────

def extract_iocs(raw_text):
    """Extract all IOCs from raw email text."""
    iocs = {
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": [],
        "emails": [],
        "attachments": []
    }

    # IPs — avoid matching private ranges in final output
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ips_found = re.findall(ip_pattern, raw_text)
    private_ranges = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.2", "172.3", "127.", "0.")
    iocs["ips"] = list(set([ip for ip in ips_found if not ip.startswith(private_ranges)]))

    # URLs (http/https)
    url_pattern = r'https?://[^\s\'"<>)]+(?=["\s<>\)]|$)'
    iocs["urls"] = list(set(re.findall(url_pattern, raw_text)))

    # Domains from URLs and email headers
    for url in iocs["urls"]:
        parsed = urlparse(url)
        if parsed.netloc:
            iocs["domains"].append(parsed.netloc.replace("www.", ""))

    # Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    all_emails = re.findall(email_pattern, raw_text)
    # Filter out the victim's email; keep sender/suspicious
    iocs["emails"] = list(set(all_emails))

    # MD5 / SHA1 / SHA256 hashes
    hash_pattern = r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
    iocs["hashes"] = list(set(re.findall(hash_pattern, raw_text)))

    # Attachment filenames
    attach_pattern = r'filename=["\']?([^"\'>\s]+\.[a-zA-Z]{2,5})["\']?'
    iocs["attachments"] = re.findall(attach_pattern, raw_text)

    # Clean up duplicates in domains
    iocs["domains"] = list(set(iocs["domains"]))

    return iocs


def check_threat_intel(iocs):
    """Simulate threat intel lookups against known bad databases."""
    findings = {
        "malicious_ips": [],
        "malicious_domains": [],
        "malicious_hashes": [],
        "suspicious_emails": []
    }

    for ip in iocs["ips"]:
        if ip in KNOWN_MALICIOUS_IPS:
            info = KNOWN_MALICIOUS_IPS[ip]
            findings["malicious_ips"].append({
                "ioc": ip,
                "abuse_score": info["abuse_score"],
                "country": info["country"],
                "reports": info["reports"],
                "source": "AbuseIPDB [SIMULATED]"
            })

    for domain in iocs["domains"]:
        # Check full domain and base domain
        base = ".".join(domain.split(".")[-2:])
        hit = KNOWN_MALICIOUS_DOMAINS.get(domain) or KNOWN_MALICIOUS_DOMAINS.get(base)
        if hit:
            findings["malicious_domains"].append({
                "ioc": domain,
                "vt_score": hit["vt_score"],
                "category": hit["category"],
                "first_seen": hit["first_seen"],
                "source": "VirusTotal [SIMULATED]"
            })

    for h in iocs["hashes"]:
        if h.lower() in KNOWN_MALICIOUS_HASHES:
            info = KNOWN_MALICIOUS_HASHES[h.lower()]
            findings["malicious_hashes"].append({
                "ioc": h,
                "vt_score": info["vt_score"],
                "threat_name": info["threat"],
                "severity": info["severity"],
                "source": "VirusTotal [SIMULATED]"
            })

    # Flag emails with suspicious domain TLDs
    for email in iocs["emails"]:
        domain_part = email.split("@")[-1] if "@" in email else ""
        suspicious_tlds = [".ru", ".tk", ".xyz", ".top", ".click", ".loan"]
        for tld in suspicious_tlds:
            if domain_part.endswith(tld):
                findings["suspicious_emails"].append({
                    "ioc": email,
                    "reason": f"Suspicious TLD: {tld}"
                })

    return findings


def detect_suspicious_keywords(raw_text):
    """Detect social engineering keywords in email body."""
    found = []
    text_lower = raw_text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            found.append(keyword)
    return found


def calculate_severity(findings, suspicious_keywords, iocs):
    """Calculate overall severity score and return verdict."""
    score = 0

    score += len(findings["malicious_ips"]) * 30
    score += len(findings["malicious_domains"]) * 25
    score += len(findings["malicious_hashes"]) * 40
    score += len(findings["suspicious_emails"]) * 15
    score += len(suspicious_keywords) * 5
    score += len(iocs["attachments"]) * 20

    # Check for especially dangerous patterns
    for attachment in iocs["attachments"]:
        if any(attachment.lower().endswith(ext) for ext in [".exe", ".bat", ".vbs", ".ps1", ".js"]):
            score += 50  # Double extension / executable disguised as doc

    if score >= 100:
        return "CRITICAL", score
    elif score >= 60:
        return "HIGH", score
    elif score >= 30:
        return "MEDIUM", score
    else:
        return "LOW", score


def map_mitre_techniques(findings, iocs):
    """Map findings to MITRE ATT&CK techniques."""
    techniques = []

    if iocs["urls"]:
        techniques.append({
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access"
        })
        techniques.append({
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access"
        })

    if findings["malicious_ips"]:
        techniques.append({
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control"
        })

    if iocs["attachments"]:
        techniques.append({
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution"
        })

    if findings["malicious_hashes"]:
        techniques.append({
            "id": "T1027",
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        })

    if any("tracking" in url for url in iocs["urls"]):
        techniques.append({
            "id": "T1598.003",
            "name": "Phishing for Information: Spearphishing Link",
            "tactic": "Reconnaissance"
        })

    return techniques


# ─────────────────────────────────────────────────────────
# INCIDENT TICKET GENERATOR
# ─────────────────────────────────────────────────────────

def generate_ticket(email_path, iocs, findings, suspicious_keywords, severity, score, mitre):
    """Generate a structured L1 SOC incident ticket."""

    ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{abs(hash(email_path)) % 9999:04d}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Determine recommended actions based on severity
    actions = {
        "CRITICAL": [
            "IMMEDIATELY block all identified IPs and domains at perimeter firewall",
            "Quarantine the email from all mailboxes using email gateway",
            "Isolate any endpoint that may have clicked the link",
            "Escalate to L2/L3 SOC analyst within 15 minutes",
            "Initiate Incident Response Playbook: Phishing",
            "Notify CISO and management per escalation matrix",
            "Preserve email headers and attachments as forensic evidence",
        ],
        "HIGH": [
            "Block identified malicious IPs and domains at firewall",
            "Quarantine suspicious email from affected mailboxes",
            "Check email gateway logs for other recipients",
            "Escalate to L2 SOC analyst within 30 minutes",
            "Run endpoint AV scan on user's machine",
        ],
        "MEDIUM": [
            "Add domains/IPs to watchlist/blocklist",
            "Quarantine email and notify the user",
            "Review email gateway for similar campaigns",
            "Document findings and monitor for 24h",
        ],
        "LOW": [
            "Tag email as spam in email gateway",
            "Document for trend analysis",
            "No immediate escalation required",
        ]
    }

    ticket = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              SOC INCIDENT TICKET — PHISHING ANALYSIS REPORT                ║
╚══════════════════════════════════════════════════════════════════════════════╝

TICKET ID    : {ticket_id}
CREATED      : {timestamp}
ANALYST      : Jeffrey Roshan Palamattom (L1 SOC)
SOURCE       : Phishing Email Analyzer v1.0
EMAIL FILE   : {os.path.basename(email_path)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEVERITY ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠  SEVERITY : [{severity}]
  📊 SCORE    : {score}/200
  🎯 VERDICT  : {"MALICIOUS — IMMEDIATE ACTION REQUIRED" if severity in ["CRITICAL", "HIGH"] else "SUSPICIOUS — INVESTIGATION REQUIRED" if severity == "MEDIUM" else "LOW RISK — MONITOR"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXTRACTED IOCs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [IPs Found]: {len(iocs['ips'])}
{chr(10).join(f"    • {ip}" for ip in iocs['ips']) if iocs['ips'] else "    None"}

  [URLs Found]: {len(iocs['urls'])}
{chr(10).join(f"    • {url[:80]}..." if len(url) > 80 else f"    • {url}" for url in iocs['urls']) if iocs['urls'] else "    None"}

  [Domains Found]: {len(iocs['domains'])}
{chr(10).join(f"    • {d}" for d in iocs['domains']) if iocs['domains'] else "    None"}

  [File Hashes Found]: {len(iocs['hashes'])}
{chr(10).join(f"    • {h}" for h in iocs['hashes']) if iocs['hashes'] else "    None"}

  [Email Addresses Found]: {len(iocs['emails'])}
{chr(10).join(f"    • {e}" for e in iocs['emails']) if iocs['emails'] else "    None"}

  [Attachments Found]: {len(iocs['attachments'])}
{chr(10).join(f"    • {a}" for a in iocs['attachments']) if iocs['attachments'] else "    None"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [MALICIOUS IPs — AbuseIPDB]:
{chr(10).join(f"    ✗ {r['ioc']} | Score: {r['abuse_score']}/100 | Country: {r['country']} | Reports: {r['reports']}" for r in findings['malicious_ips']) if findings['malicious_ips'] else "    None identified"}

  [MALICIOUS DOMAINS — VirusTotal]:
{chr(10).join(f"    ✗ {r['ioc']} | VT: {r['vt_score']} | Category: {r['category']}" for r in findings['malicious_domains']) if findings['malicious_domains'] else "    None identified"}

  [MALICIOUS FILE HASHES — VirusTotal]:
{chr(10).join(f"    ✗ {r['ioc'][:20]}... | VT: {r['vt_score']} | Threat: {r['threat_name']}" for r in findings['malicious_hashes']) if findings['malicious_hashes'] else "    None identified"}

  [SUSPICIOUS SENDER ADDRESSES]:
{chr(10).join(f"    ⚠ {r['ioc']} — {r['reason']}" for r in findings['suspicious_emails']) if findings['suspicious_emails'] else "    None identified"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SOCIAL ENGINEERING INDICATORS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Keywords detected: {len(suspicious_keywords)}
{chr(10).join(f"    • \"{k}\"" for k in suspicious_keywords) if suspicious_keywords else "    None"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MITRE ATT&CK MAPPING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{chr(10).join(f"  [{t['tactic']}] {t['id']} — {t['name']}" for t in mitre) if mitre else "  No techniques mapped"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDED ACTIONS [{severity}]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{chr(10).join(f"  {i+1}. {action}" for i, action in enumerate(actions[severity]))}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SLA TARGETS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Time to Triage (TTT)     : {"15 min" if severity == "CRITICAL" else "30 min" if severity == "HIGH" else "2 hrs"}
  Time to Qualify (TTQ)    : {"30 min" if severity == "CRITICAL" else "1 hr" if severity == "HIGH" else "4 hrs"}
  Escalation Required      : {"YES — L2 + CISO" if severity == "CRITICAL" else "YES — L2" if severity == "HIGH" else "NO — Monitor"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
END OF TICKET: {ticket_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    return ticket, ticket_id


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def analyze_email(email_path):
    """Full pipeline: read → extract → check intel → score → ticket."""

    print(f"\n{'='*60}")
    print(f"  SOC PHISHING ANALYZER — Jeffrey Roshan Palamattom")
    print(f"{'='*60}")
    print(f"  [*] Analyzing: {email_path}")
    print(f"  [*] Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")

    # Read email
    try:
        with open(email_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read()
    except FileNotFoundError:
        print(f"  [ERROR] File not found: {email_path}")
        return

    print("  [1/5] Extracting IOCs...")
    iocs = extract_iocs(raw_text)
    print(f"        Found: {len(iocs['ips'])} IPs, {len(iocs['urls'])} URLs, "
          f"{len(iocs['domains'])} domains, {len(iocs['hashes'])} hashes")

    print("  [2/5] Querying threat intelligence databases...")
    findings = check_threat_intel(iocs)
    total_hits = sum(len(v) for v in findings.values())
    print(f"        Malicious hits: {total_hits}")

    print("  [3/5] Scanning for social engineering keywords...")
    suspicious_keywords = detect_suspicious_keywords(raw_text)
    print(f"        Keywords found: {len(suspicious_keywords)}")

    print("  [4/5] Calculating severity score...")
    severity, score = calculate_severity(findings, suspicious_keywords, iocs)
    print(f"        Severity: [{severity}] | Score: {score}")

    print("  [5/5] Mapping to MITRE ATT&CK...")
    mitre = map_mitre_techniques(findings, iocs)
    print(f"        Techniques identified: {len(mitre)}")

    ticket, ticket_id = generate_ticket(email_path, iocs, findings, suspicious_keywords, severity, score, mitre)

    # Print ticket to console
    print(ticket)

    # Save ticket to output folder
    output_dir = os.path.join(os.path.dirname(email_path), "..", "output")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{ticket_id}.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(ticket)
    print(f"  [✓] Ticket saved to: {output_path}\n")

    # Also save JSON for SIEM ingestion
    json_output = {
        "ticket_id": ticket_id,
        "severity": severity,
        "score": score,
        "iocs": iocs,
        "threat_intel": findings,
        "mitre_techniques": mitre
    }
    json_path = os.path.join(output_dir, f"{ticket_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=2)
    print(f"  [✓] JSON output saved to: {json_path}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SOC L1 Phishing Email Analyzer — Jeffrey Roshan Palamattom",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing_analyzer.py --email sample-emails/phishing_sample_1.eml
  python phishing_analyzer.py --email sample-emails/phishing_sample_2.eml
        """
    )
    parser.add_argument("--email", required=True, help="Path to the .eml file to analyze")
    args = parser.parse_args()
    analyze_email(args.email)


if __name__ == "__main__":
    main()
