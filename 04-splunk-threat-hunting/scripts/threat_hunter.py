#!/usr/bin/env python3
"""
=============================================================================
SOC L1 Threat Hunter — Splunk-Style Log Analyzer
Author: Jeffrey Roshan Palamattom
Role:   L1 SOC Analyst Portfolio Project
Tool:   Parses Windows Security Events, runs 6 SPL-style threat hunting
        queries, reconstructs attack chains, generates hunt report
=============================================================================
"""

import json
import argparse
import os
from datetime import datetime, timedelta
from collections import defaultdict

# ─────────────────────────────────────────────────────────
# EVENT ID REFERENCE
# ─────────────────────────────────────────────────────────

EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon with Explicit Credentials",
    4656: "Handle to Object Requested",
    4688: "Process Creation",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4732: "Member Added to Security Group",
    4776: "Credential Validation",
}

LOGON_TYPES = {
    2:  "Interactive (console)",
    3:  "Network (SMB/file share)",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    8:  "Network Cleartext",
    9:  "NewCredentials (runas)",
    10: "Remote Interactive (RDP)",
    11: "Cached Interactive",
}

KNOWN_MALICIOUS_IPS = {"45.142.212.100", "91.108.4.200", "185.220.101.47"}

# ─────────────────────────────────────────────────────────
# LOG LOADING
# ─────────────────────────────────────────────────────────

def load_logs(log_path):
    """Load Windows Security Event logs from JSON file."""
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        print(f"  [✓] Loaded {len(events)} events from {os.path.basename(log_path)}")
        return events
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [ERROR] Could not load logs: {e}")
        return []


def parse_time(ts):
    """Parse ISO 8601 timestamp string to datetime."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return datetime.min

# ─────────────────────────────────────────────────────────
# THREAT HUNTING QUERIES (SPL-style logic in Python)
# ─────────────────────────────────────────────────────────

def hunt_brute_force(events, threshold=5, window_minutes=5):
    """
    SPL equivalent:
    index=winsec EventCode=4625
    | bucket _time span=5m
    | stats count by TargetAccount, IpAddress, _time
    | where count >= 5
    """
    print("\n  [HUNT 1] Brute Force Attack Detection (EventID 4625)...")
    failed_logins = [e for e in events if e.get("EventID") == 4625]

    # Group by account + IP, bucket by 5-minute windows
    buckets = defaultdict(list)
    for event in failed_logins:
        key = (event.get("TargetAccount"), event.get("IpAddress"))
        buckets[key].append(parse_time(event.get("TimeGenerated", "")))

    findings = []
    for (account, ip), times in buckets.items():
        times.sort()
        # Sliding window check
        for i, start_time in enumerate(times):
            window_end = start_time + timedelta(minutes=window_minutes)
            count = sum(1 for t in times[i:] if t <= window_end)
            if count >= threshold:
                findings.append({
                    "account": account,
                    "source_ip": ip,
                    "attempts_in_window": count,
                    "first_seen": str(start_time),
                    "malicious_ip": ip in KNOWN_MALICIOUS_IPS
                })
                break

    return findings


def hunt_password_spray(events, account_threshold=4):
    """
    SPL equivalent:
    index=winsec EventCode=4625
    | stats dc(TargetAccount) as unique_accounts count by IpAddress
    | where unique_accounts >= 4
    """
    print("  [HUNT 2] Password Spray Detection (1 IP → many accounts)...")
    failed_logins = [e for e in events if e.get("EventID") == 4625]

    ip_accounts = defaultdict(set)
    ip_count = defaultdict(int)
    for event in failed_logins:
        ip = event.get("IpAddress", "")
        account = event.get("TargetAccount", "")
        if ip and account:
            ip_accounts[ip].add(account)
            ip_count[ip] += 1

    findings = []
    for ip, accounts in ip_accounts.items():
        if len(accounts) >= account_threshold:
            findings.append({
                "source_ip": ip,
                "unique_accounts_targeted": len(accounts),
                "total_attempts": ip_count[ip],
                "accounts": list(accounts),
                "malicious_ip": ip in KNOWN_MALICIOUS_IPS
            })

    return findings


def hunt_successful_after_failure(events, fail_threshold=3, window_minutes=10):
    """
    SPL equivalent:
    index=winsec EventCode IN (4624, 4625)
    | transaction TargetAccount maxspan=10m
    | where EventCode=4625 AND count >= 3 AND follow EventCode=4624
    """
    print("  [HUNT 3] Successful Login After Brute Force...")
    failed = defaultdict(list)
    successful = defaultdict(list)

    for event in events:
        account = event.get("TargetAccount") or event.get("TargetUserName", "")
        t = parse_time(event.get("TimeGenerated", ""))
        if event.get("EventID") == 4625:
            failed[account].append((t, event.get("IpAddress")))
        elif event.get("EventID") == 4624:
            successful[account].append((t, event.get("IpAddress")))

    findings = []
    for account, fail_list in failed.items():
        if len(fail_list) >= fail_threshold and account in successful:
            for success_time, success_ip in successful[account]:
                for fail_time, fail_ip in fail_list:
                    if 0 < (success_time - fail_time).total_seconds() < window_minutes * 60:
                        findings.append({
                            "account": account,
                            "failed_attempts": len(fail_list),
                            "failure_source_ip": fail_ip,
                            "success_source_ip": success_ip,
                            "success_time": str(success_time),
                            "verdict": "ACCOUNT LIKELY COMPROMISED"
                        })
                        break

    return findings


def hunt_lateral_movement_rdp(events, host_threshold=3):
    """
    SPL equivalent:
    index=winsec EventCode=4624 LogonType=10
    | stats dc(ComputerName) as unique_hosts by TargetAccount
    | where unique_hosts >= 3
    """
    print("  [HUNT 4] Lateral Movement via RDP (LogonType=10)...")
    rdp_events = [e for e in events
                  if e.get("EventID") == 4624 and e.get("LogonType") == 10]

    account_hosts = defaultdict(set)
    account_ips = defaultdict(set)
    for event in rdp_events:
        account = event.get("TargetAccount", "")
        host = event.get("Computer", "")
        ip = event.get("IpAddress", "")
        if account:
            account_hosts[account].add(host)
            account_ips[account].add(ip)

    findings = []
    for account, hosts in account_hosts.items():
        if len(hosts) >= host_threshold:
            findings.append({
                "account": account,
                "unique_hosts_accessed": len(hosts),
                "hosts": list(hosts),
                "source_ips": list(account_ips[account]),
                "severity": "HIGH" if len(hosts) >= 4 else "MEDIUM"
            })

    return findings


def hunt_suspicious_processes(events):
    """
    SPL equivalent:
    index=winsec EventCode=4688
    | search CommandLine IN (*encodedcommand*, *downloadstring*, *lsass*, *mimikatz*)
    """
    print("  [HUNT 5] Suspicious Process Creation (EventID 4688)...")
    process_events = [e for e in events if e.get("EventID") == 4688]

    suspicious_patterns = {
        "-encodedcommand": "PowerShell encoded command",
        "-enc ": "PowerShell encoded command (short)",
        "downloadstring": "PowerShell download cradle",
        "iex": "Invoke-Expression",
        "lsass": "LSASS access",
        "mimikatz": "Mimikatz credential dumper",
        "-nop": "PowerShell AMSI bypass indicator",
        "windowstyle hidden": "Hidden window execution",
        "base64": "Base64-encoded payload",
    }

    findings = []
    for event in process_events:
        cmd = event.get("CommandLine", "").lower()
        matched = []
        for pattern, description in suspicious_patterns.items():
            if pattern in cmd:
                matched.append(description)

        if matched:
            findings.append({
                "user": event.get("SubjectUserName", "unknown"),
                "computer": event.get("Computer", "unknown"),
                "process": event.get("NewProcessName", "unknown"),
                "command_line": event.get("CommandLine", "")[:120] + "...",
                "indicators": matched,
                "timestamp": event.get("TimeGenerated"),
                "severity": "CRITICAL" if len(matched) >= 2 else "HIGH"
            })

    return findings


def hunt_privilege_escalation(events):
    """
    SPL equivalent:
    index=winsec EventCode IN (4720, 4732, 4698, 4656)
    | where ObjectName LIKE "%lsass%" OR TargetGroup LIKE "%Admin%"
    """
    print("  [HUNT 6] Privilege Escalation & Persistence Indicators...")
    interesting_ids = {4656, 4720, 4732, 4698}
    relevant_events = [e for e in events if e.get("EventID") in interesting_ids]

    findings = []
    for event in relevant_events:
        finding = None
        eid = event.get("EventID")

        if eid == 4656:
            obj = event.get("ObjectName", "")
            if "lsass" in obj.lower():
                finding = {
                    "type": "LSASS Memory Access Attempt",
                    "user": event.get("SubjectUserName"),
                    "computer": event.get("Computer"),
                    "object": obj,
                    "process": event.get("ProcessName", ""),
                    "timestamp": event.get("TimeGenerated"),
                    "severity": "CRITICAL",
                    "mitre": "T1003.001"
                }

        elif eid == 4720:
            finding = {
                "type": "New User Account Created",
                "created_by": event.get("SubjectUserName"),
                "new_account": event.get("TargetAccount"),
                "computer": event.get("Computer"),
                "timestamp": event.get("TimeGenerated"),
                "severity": "HIGH",
                "mitre": "T1136.001"
            }

        elif eid == 4732:
            group = event.get("TargetGroup", "")
            if "admin" in group.lower():
                finding = {
                    "type": "Account Added to Admin Group",
                    "added_by": event.get("SubjectUserName"),
                    "account": event.get("TargetAccount"),
                    "group": group,
                    "computer": event.get("Computer"),
                    "timestamp": event.get("TimeGenerated"),
                    "severity": "CRITICAL",
                    "mitre": "T1078"
                }

        elif eid == 4698:
            task_content = event.get("TaskContent", "").lower()
            suspicious = any(kw in task_content for kw in ["powershell", "cmd", "enc", "base64", "download"])
            finding = {
                "type": "Scheduled Task Created",
                "created_by": event.get("SubjectUserName"),
                "task_name": event.get("TaskName", ""),
                "computer": event.get("Computer"),
                "suspicious_content": suspicious,
                "timestamp": event.get("TimeGenerated"),
                "severity": "CRITICAL" if suspicious else "MEDIUM",
                "mitre": "T1053.005"
            }

        if finding:
            findings.append(finding)

    return findings


# ─────────────────────────────────────────────────────────
# ATTACK CHAIN RECONSTRUCTION
# ─────────────────────────────────────────────────────────

def reconstruct_attack_chain(hunt_results):
    """Correlate findings across all hunts to tell the attack story."""
    chain = []

    bf = hunt_results.get("brute_force", [])
    spray = hunt_results.get("password_spray", [])
    compromise = hunt_results.get("success_after_failure", [])
    lateral = hunt_results.get("lateral_movement", [])
    processes = hunt_results.get("suspicious_processes", [])
    privesc = hunt_results.get("privilege_escalation", [])

    if bf:
        chain.append(f"STEP 1 — INITIAL ACCESS ATTEMPT: Brute force detected against {len(bf)} account(s)")
    if spray:
        chain.append(f"STEP 2 — CREDENTIAL ATTACK: Password spray from {len(spray)} IP(s) targeting {spray[0]['unique_accounts_targeted']} accounts")
    if compromise:
        accounts = [c['account'] for c in compromise]
        chain.append(f"STEP 3 — ACCOUNT COMPROMISE: {len(compromise)} account(s) compromised after brute force: {', '.join(accounts)}")
    if lateral:
        hosts = lateral[0]['hosts'] if lateral else []
        chain.append(f"STEP 4 — LATERAL MOVEMENT: Attacker moved to {len(hosts)} host(s) via RDP: {', '.join(hosts[:3])}")
    if processes:
        chain.append(f"STEP 5 — EXECUTION: {len(processes)} suspicious process(es) executed (PowerShell/credential dumping)")
    if any(f.get("type") == "LSASS Memory Access Attempt" for f in privesc):
        chain.append("STEP 6 — CREDENTIAL DUMPING: LSASS memory access detected — credentials likely stolen")
    if any(f.get("type") in ("New User Account Created", "Account Added to Admin Group") for f in privesc):
        chain.append("STEP 7 — PERSISTENCE: New admin account created — attacker establishing backdoor")
    if any(f.get("type") == "Scheduled Task Created" and f.get("suspicious_content") for f in privesc):
        chain.append("STEP 8 — PERSISTENCE: Malicious scheduled task created — likely C2 beacon setup")

    return chain


# ─────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────

def generate_hunt_report(log_path, hunt_results, attack_chain, total_events):
    """Generate a professional threat hunting report."""

    report_id = f"HUNT-{datetime.now().strftime('%Y%m%d-%H%M')}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count total findings
    total_findings = sum(len(v) for v in hunt_results.values())
    critical = sum(
        1 for group in hunt_results.values()
        for f in group
        if isinstance(f, dict) and f.get("severity") == "CRITICAL"
    )

    report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║            THREAT HUNTING REPORT — SOC ANALYST JEFFREY PALAMATTOM          ║
╚══════════════════════════════════════════════════════════════════════════════╝

REPORT ID    : {report_id}
GENERATED    : {timestamp}
ANALYST      : Jeffrey Roshan Palamattom (L1 SOC)
LOG FILE     : {os.path.basename(log_path)}
EVENTS PARSED: {total_events}
HUNT QUERIES : 6

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Total Findings  : {total_findings}
  Critical Alerts : {critical}
  Attack Chain    : {"FULL ATTACK CHAIN RECONSTRUCTED" if len(attack_chain) >= 4 else "PARTIAL INDICATORS FOUND"}
  
  OVERALL ASSESSMENT: {"⚠ ACTIVE INTRUSION — IMMEDIATE INCIDENT RESPONSE REQUIRED" if critical >= 2 else "⚠ SUSPICIOUS ACTIVITY — INVESTIGATE FURTHER"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECONSTRUCTED ATTACK CHAIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{chr(10).join(f"  {step}" for step in attack_chain) if attack_chain else "  No clear attack chain detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HUNT 1 — BRUTE FORCE ATTACK (EventID 4625)  |  MITRE: T1110
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings: {len(hunt_results['brute_force'])}
{chr(10).join(f"  ✗ Account: {f['account']} | IP: {f['source_ip']} | Attempts: {f['attempts_in_window']} | Known Bad IP: {f['malicious_ip']}" for f in hunt_results['brute_force']) if hunt_results['brute_force'] else "  None detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HUNT 2 — PASSWORD SPRAY (1 IP → Many Accounts)  |  MITRE: T1110.003
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings: {len(hunt_results['password_spray'])}
{chr(10).join(f"  ✗ IP: {f['source_ip']} | Targeted {f['unique_accounts_targeted']} accounts | Total attempts: {f['total_attempts']}" for f in hunt_results['password_spray']) if hunt_results['password_spray'] else "  None detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HUNT 3 — COMPROMISE: SUCCESS AFTER BRUTE FORCE  |  MITRE: T1078
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings: {len(hunt_results['success_after_failure'])}
{chr(10).join(f"  ✗ Account: {f['account']} | Failed from: {f['failure_source_ip']} | Success from: {f['success_source_ip']} | {f['verdict']}" for f in hunt_results['success_after_failure']) if hunt_results['success_after_failure'] else "  None detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HUNT 4 — LATERAL MOVEMENT VIA RDP  |  MITRE: T1021.001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings: {len(hunt_results['lateral_movement'])}
{chr(10).join(f"  ✗ Account: {f['account']} | Accessed {f['unique_hosts_accessed']} hosts: {', '.join(f['hosts'])}" for f in hunt_results['lateral_movement']) if hunt_results['lateral_movement'] else "  None detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HUNT 5 — SUSPICIOUS PROCESSES  |  MITRE: T1059.001, T1003.001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings: {len(hunt_results['suspicious_processes'])}
{chr(10).join(f"  ✗ [{f['severity']}] User: {f['user']} | Host: {f['computer']} | Indicators: {', '.join(f['indicators'])}" for f in hunt_results['suspicious_processes']) if hunt_results['suspicious_processes'] else "  None detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HUNT 6 — PRIVILEGE ESCALATION & PERSISTENCE  |  MITRE: T1003, T1136, T1053
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings: {len(hunt_results['privilege_escalation'])}
{chr(10).join(f"  ✗ [{f.get('severity','?')}] {f.get('type','?')} | {f.get('user','') or f.get('created_by','?')} on {f.get('computer','?')}" for f in hunt_results['privilege_escalation']) if hunt_results['privilege_escalation'] else "  None detected"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDED IMMEDIATE ACTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. ISOLATE all hosts identified in attack chain from the network
  2. RESET credentials for all compromised/targeted accounts
  3. DISABLE any newly created accounts (svc_hidden_backdoor)
  4. REMOVE the malicious scheduled task from DC01
  5. BLOCK external IPs: {', '.join(KNOWN_MALICIOUS_IPS)} at perimeter
  6. ESCALATE to L2/L3 SOC and management immediately
  7. PRESERVE event logs and memory dumps for forensic investigation
  8. INITIATE full IR playbook — this is a confirmed intrusion

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
END OF REPORT: {report_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    return report, report_id


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def run_threat_hunt(log_path):
    """Execute full threat hunt pipeline."""
    print(f"\n{'='*60}")
    print(f"  SOC THREAT HUNTER — Jeffrey Roshan Palamattom")
    print(f"  Splunk-Style Log Analyzer & Threat Hunter")
    print(f"{'='*60}")
    print(f"  [*] Log file: {log_path}")
    print(f"  [*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")

    events = load_logs(log_path)
    if not events:
        return

    print(f"\n  Running 6 threat hunting queries...\n")

    hunt_results = {
        "brute_force":          hunt_brute_force(events),
        "password_spray":       hunt_password_spray(events),
        "success_after_failure": hunt_successful_after_failure(events),
        "lateral_movement":     hunt_lateral_movement_rdp(events),
        "suspicious_processes": hunt_suspicious_processes(events),
        "privilege_escalation": hunt_privilege_escalation(events),
    }

    print("\n  Reconstructing attack chain...")
    attack_chain = reconstruct_attack_chain(hunt_results)

    report, report_id = generate_hunt_report(log_path, hunt_results, attack_chain, len(events))
    print(report)

    # Save report
    output_dir = os.path.join(os.path.dirname(log_path), "..", "output")
    os.makedirs(output_dir, exist_ok=True)

    txt_path = os.path.join(output_dir, f"{report_id}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  [✓] Report saved to: {txt_path}")

    json_path = os.path.join(output_dir, f"{report_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"report_id": report_id, "attack_chain": attack_chain, "findings": hunt_results}, f, indent=2, default=str)
    print(f"  [✓] JSON saved to : {json_path}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SOC Threat Hunter — Splunk-Style Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python threat_hunter.py --logs sample-logs/windows_security_events.json
        """
    )
    parser.add_argument("--logs", required=True, help="Path to Windows Security Events JSON file")
    args = parser.parse_args()
    run_threat_hunt(args.logs)


if __name__ == "__main__":
    main()
