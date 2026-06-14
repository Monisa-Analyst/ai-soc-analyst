import os
import json
from pathlib import Path
from openai import OpenAI
import anthropic
from dotenv import load_dotenv

# triage, mitre mappings, and playbooks

# Load environment variables from .env (keeps API keys out of source code)
load_dotenv(Path(__file__).parent / ".env")

_key = os.getenv("OPENAI_API_KEY")
_client = OpenAI(api_key=_key) if _key and _key.startswith("sk-") else None

_anthropic_key = os.getenv("ANTHROPIC_API_KEY")
_anthropic_client = anthropic.Anthropic(api_key=_anthropic_key) if _anthropic_key and not _anthropic_key.startswith("your_") else None


# map keyword patterns to mitre techniques

MITRE_RULES = [
    # ------ Initial Access ------
    (["phish", "spear", "email attachment"],       "T1566     – Phishing",                      "Initial Access"),
    (["exploit public", "sql inject", "rce"],       "T1190     – Exploit Public-Facing App",      "Initial Access"),
    (["valid account", "stolen cred", "hijack"],   "T1078     – Valid Accounts",                 "Initial Access"),
    (["supply chain", "dev dependency"],            "T1195     – Supply Chain Compromise",        "Initial Access"),

    # ------ Execution ------
    (["powershell", "invoke-expression"],           "T1059.001 – PowerShell",                     "Execution"),
    (["cmd", "command prompt", "batch"],            "T1059.003 – Windows Command Shell",          "Execution"),
    (["bash", "shell script", "/bin/sh"],           "T1059.004 – Unix Shell",                     "Execution"),
    (["wmi", "wmiprvse"],                           "T1047     – Windows Management Instrumentation","Execution"),
    (["macro", "excel", "word doc"],                "T1204.002 – Malicious File Execution",       "Execution"),
    (["malware", "trojan", "virus", "dropper"],    "T1204     – User Execution",                 "Execution"),

    # ------ Persistence ------
    (["registry", "run key", "hkcu"],              "T1547.001 – Registry Run Keys",              "Persistence"),
    (["startup", "autorun", "scheduled task"],      "T1053.005 – Scheduled Task",                 "Persistence"),
    (["service install", "new service"],            "T1543.003 – Windows Service",                "Persistence"),
    (["bootkit", "mbr", "rootkit"],                 "T1542     – Pre-OS Boot Compromise",         "Persistence"),

    # ------ Privilege Escalation ------
    (["uac bypass", "elevation", "admin priv"],     "T1548.002 – Bypass User Access Control",    "Privilege Escalation"),
    (["token imperson", "access token"],            "T1134     – Access Token Manipulation",      "Privilege Escalation"),

    # ------ Defense Evasion ------
    (["obfuscat", "base64", "encoded payload"],    "T1027     – Obfuscated Files / Info",        "Defense Evasion"),
    (["log clear", "event log deleted"],            "T1070.001 – Indicator Removal: Clear Logs",  "Defense Evasion"),
    (["disable antivirus", "tamper av"],            "T1562.001 – Disable Security Tools",         "Defense Evasion"),

    # ------ Credential Access ------
    (["brute", "password spray", "login fail"],    "T1110     – Brute Force",                   "Credential Access"),
    (["mimikatz", "lsass", "credential dump"],      "T1003     – OS Credential Dumping",          "Credential Access"),
    (["keylog", "credential harvest"],              "T1056     – Input Capture",                  "Credential Access"),
    (["kerberoast", "ticket request"],              "T1558.003 – Kerberoasting",                  "Credential Access"),

    # ------ Discovery ------
    (["scan", "nmap", "recon", "port sweep"],      "T1046     – Network Service Scanning",       "Discovery"),
    (["whoami", "net user", "enumerat"],            "T1087     – Account Discovery",              "Discovery"),
    (["arp scan", "host discover"],                 "T1018     – Remote System Discovery",        "Discovery"),

    # ------ Lateral Movement ------
    (["rdp", "remote desktop", "3389"],             "T1021.001 – Remote Desktop Protocol",        "Lateral Movement"),
    (["smb", "psexec", "wmiexec"],                  "T1021.002 – SMB / Windows Admin Shares",     "Lateral Movement"),
    (["ssh lateral", "pivot"],                      "T1021.004 – SSH Lateral Movement",           "Lateral Movement"),

    # ------ Collection ------
    (["data stage", "archive", "compress", "zip"], "T1560     – Archive Collected Data",         "Collection"),
    (["screenshot", "screen capture"],             "T1113     – Screen Capture",                 "Collection"),
    (["clipboard", "clip data"],                   "T1115     – Clipboard Data",                 "Collection"),

    # ------ Exfiltration ------
    (["exfil", "upload", "transfer", "c2 upload"], "T1041     – Exfiltration Over C2 Channel",   "Exfiltration"),
    (["dns tunnel", "dns exfil"],                   "T1048.003 – Exfiltration via DNS",           "Exfiltration"),
    (["ftp transfer", "sftp"],                      "T1048     – Exfiltration Over Alt Protocol", "Exfiltration"),

    # ------ Impact ------
    (["ransom", "encrypt file", "locked"],          "T1486     – Data Encrypted for Impact",      "Impact"),
    (["wipe", "disk destruct", "format drive"],     "T1561     – Disk Wipe",                      "Impact"),
    (["ddos", "flood", "dos attack"],               "T1498     – Network Denial of Service",      "Impact"),
    (["defac", "webpage alter"],                    "T1491     – Defacement",                     "Impact"),
]


# fallback triage profiles when offline

# Detailed profiles for every event type
_PROFILES = {
    "sql injection": {
        "summary_tmpl": (
            "The WAF flagged a sustained SQL injection campaign originating from {src} targeting the "
            "application layer on {dest}. The payloads embedded within POST request bodies contained UNION-based "
            "injection strings and time-delay probes (SLEEP / WAITFOR), indicating a semi-automated enumeration "
            "tool such as SQLMap. Immediate review of backend query logs is recommended to determine if any "
            "records were extracted prior to WAF interception."
        ),
        "indicators": [
            "UNION SELECT payloads in HTTP body",
            "Blind boolean injection patterns",
            "Error-based DB fingerprinting (MySQL / MSSQL)",
            "Automated scan signature (SQLMap v1.7 headers)"
        ],
        "iocs": ["185.220.101.0/24 (Tor exit node range)", "Payload: ' OR 1=1--", "User-Agent: sqlmap/1.7"],
    },
    "brute force": {
        "summary_tmpl": (
            "Rapid sequential authentication failures detected against {dest} from a single external host {src}. "
            "The rate of {80+} failed attempts per minute, combined with systematic username enumeration across "
            "privileged accounts (root, admin, svc-backup), is consistent with credential stuffing or dictionary "
            "brute-force tooling. The source IP has no prior legitimate access history and resolves to a known "
            "hosting range associated with botnet infrastructure."
        ),
        "indicators": [
            "Failed logins >50/min from single source",
            "Systematic account enumeration pattern",
            "No successful login in entire session",
            "Attempts across root, admin, svc accounts"
        ],
        "iocs": ["High-frequency auth failures", "SSH / RDP port saturation", "No MFA bypass attempts (Tier 1)"],
    },
    "reconnaissance": {
        "summary_tmpl": (
            "A comprehensive network reconnaissance sweep was detected from external host {src}. The scanning "
            "activity targeted a /24 subnet range with SYN probes to all 65535 ports on {dest}, consistent with "
            "Nmap OS fingerprinting and service version detection (-sV -O flags). The scan completed in under "
            "4 minutes, suggesting a tool-assisted sweep rather than manual investigation. Perimeter firewall "
            "rules should be reviewed to ensure administrative ports are not inadvertently exposed."
        ),
        "indicators": [
            "SYN probe sweep across all 65535 ports",
            "Rapid scan completion (<5 minutes)",
            "OS fingerprint probes (TTL, Window Size)",
            "Service banner grabbing on open ports"
        ],
        "iocs": ["Nmap signature in packet headers", "High packet rate from single source", "RST flood pattern"],
    },
    "malware": {
        "summary_tmpl": (
            "Endpoint protection alerted on a suspicious binary executed on {dest}. The file exhibits characteristics "
            "consistent with a dropper or loader component — it performs process hollowing into a legitimate Windows "
            "process (svchost.exe), creates persistence via HKCU Run key modification, and establishes an encrypted "
            "outbound channel to {src} over port 443 using a non-standard TLS certificate. Memory scan confirms "
            "presence of shellcode injection signatures in the process space."
        ),
        "indicators": [
            "Process hollowing into svchost.exe",
            "Registry persistence: HKCU\\Software\\Run",
            "Encrypted C2 beacon (10-second interval)",
            "Suspicious child process spawned by Office"
        ],
        "iocs": ["MD5: d41d8cd98f00b204e9800998ecf8427e", "C2 domain: malware-c2.xyz", "Rule: ET MALWARE Beacon"],
    },
    "data exfiltration": {
        "summary_tmpl": (
            "Anomalous outbound data transfer detected from internal host {dest} to unrecognized external endpoint "
            "{src}. Transfer volume (2.4 GB over 15 minutes) significantly exceeds the 95th percentile baseline for "
            "this network segment. The traffic is TLS-encrypted over port 443 but the destination certificate was "
            "issued 48 hours ago — a strong exfiltration indicator. DLP rules triggered on file-type signatures "
            "consistent with database dumps and compressed archive files (.sql.gz)."
        ),
        "indicators": [
            "Outbound volume 40x above daily baseline",
            "Destination domain: newly registered (48 hrs)",
            "TLS session to uncategorized host",
            "DLP: .sql.gz archive file detected"
        ],
        "iocs": ["Dest IP: recent Abuse.ch report", "Domain: exfil-bucket.s3-fake.com", "Port 443 sustained transfer"],
    },
    "phishing": {
        "summary_tmpl": (
            "An inbound phishing email was detected by the mail gateway targeting {dest}. The message masquerades "
            "as a routine IT department communication requesting urgent credential re-verification. The embedded "
            "hyperlink resolves to a lookalike domain registered through a privacy-protected registrar, hosting "
            "a cloned Outlook Web App login page. The originating SMTP server on {src} is not listed in the "
            "domain's SPF record, indicating direct forgery of the sender address."
        ),
        "indicators": [
            "SPF FAIL — sender IP not in SPF record",
            "Lookalike domain: secure-it-helpdesk.net",
            "HTML body contains obfuscated redirect URL",
            "Urgency language: 'account will be locked'"
        ],
        "iocs": ["URL: http://secure-it-helpdesk.net/owa", "Reply-To mismatch", "Zero-day domain (registered 3 days ago)"],
    },
}


def _get_smart_summary(alert: dict) -> str:
    """
    Generates a detailed, professional analyst summary using static profiles.
    Includes IOCs and indicators of compromise when available.

    Args:
        alert : The raw alert dictionary to analyze.

    Returns:
        A formatted multi-line analyst summary string.
    """
    etype = (alert.get("event_type") or alert.get("type") or "Security Event").lower()
    src   = alert.get("source_ip") or alert.get("src_ip") or "unknown source"
    dest  = alert.get("dest_ip") or alert.get("destination") or "internal asset"
    msg   = alert.get("message") or alert.get("msg") or ""

    # Find the best matching profile
    profile = None
    for key in _PROFILES:
        if key in etype or key in msg.lower():
            profile = _PROFILES[key]
            break

    if profile:
        summary = profile["summary_tmpl"].format(src=src, dest=dest)
        indicators = "\n".join(f"  • {ind}" for ind in profile["indicators"])
        iocs = "\n".join(f"  • {ioc}" for ioc in profile["iocs"])
        return (
            f"{summary}\n\n"
            f"Key Indicators:\n{indicators}\n\n"
            f"Observed IOCs:\n{iocs}"
        )

    # Generic fallback for unrecognized event types
    return (
        f"Security event of type '{etype}' was detected involving {src} and {dest}. "
        f"The observed activity deviates from the established baseline for this network segment. "
        f"Raw message: '{msg}'. "
        "Correlate against firewall, DNS, and endpoint logs to confirm scope. "
        "Escalate to Tier-2 if lateral movement indicators are found within the same time window."
    )


# alert triage
def triage_alert(alert_details: dict, provider: str = "Claude (Anthropic)") -> str:
    """run alert triage via Claude (Anthropic), OpenAI, or offline fallback profile"""
    prompt = f"""You are a senior SOC analyst at a Fortune 500 company.
Analyze the following security alert and produce a structured Tier-1 triage report.

Alert Data:
{json.dumps(alert_details, indent=2)}

Your response MUST follow this exact structure:
1. THREAT ASSESSMENT (2 sentences describing what is happening and why it is dangerous)
2. OBSERVABLE INDICATORS (3 bullet points of specific IOCs or behavioral patterns)
3. IMMEDIATE ACTIONS (2 specific, actionable steps for a Tier-1 analyst to take NOW)

Be specific, technical, and concise. Do not use vague language."""

    system_instruction = (
        "You are a concise, no-fluff SOC analyst. "
        "Write in technical language suitable for a cybersecurity incident report. "
        "Never use filler phrases like 'certainly' or 'I hope this helps'."
    )

    # Try Anthropic Claude if selected and client is initialized
    if provider == "Claude (Anthropic)" and _anthropic_client:
        try:
            resp = _anthropic_client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=400,
                temperature=0.3,
                system=system_instruction,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return resp.content[0].text.strip()
        except Exception as e:
            # Fall through to OpenAI if Claude fails and OpenAI is available
            pass

    # Try OpenAI if selected (or as fallback) and client is initialized
    if (provider == "GPT-3.5 (OpenAI)" or not _anthropic_client) and _client:
        try:
            resp = _client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=400,
                temperature=0.3,
                timeout=10
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            pass

    # Deterministic local fallback
    return _get_smart_summary(alert_details)


# mitre mapper
def map_mitre(alert_details: dict) -> str:
    """matches event keywords to MITRE techniques"""
    # Concatenate all string values from the alert into a single searchable blob
    blob = " ".join(str(v) for v in alert_details.values() if v).lower()

    matches = []
    for keywords, technique, tactic in MITRE_RULES:
        if any(kw in blob for kw in keywords):
            matches.append(f"{technique}  |  Tactic: {tactic}")

    if matches:
        # Return the first (most specific) match with any secondary matches noted
        primary = matches[0]
        if len(matches) > 1:
            secondary = "; ".join(m.split("|")[0].strip() for m in matches[1:3])
            return f"{primary}\n  Also see: {secondary}"
        return primary

    # Default fallback — most common catch-all technique
    return "T1059.003 – Windows Command Shell  |  Tactic: Execution"


def map_mitre_short(alert_details: dict) -> str:
    """
    Returns only the technique ID and name (no tactic) for compact display.
    Used in the Dashboard table view.

    Args:
        alert_details : Raw alert dictionary.

    Returns:
        Short technique string.
    """
    full = map_mitre(alert_details)
    # Extract just the first line to strip secondary matches
    return full.split("\n")[0].split("|")[0].strip()


# response playbook definitions
_RESPONSE_PLAYBOOKS = {
    "sql injection": [
        "IMMEDIATE: Block source IP at WAF and perimeter firewall (block /32 for 72h).",
        "INVESTIGATE: Pull full HTTP request logs for the past 24h from this source.",
        "FORENSICS: Check application DB query logs for any executed payloads or data reads.",
        "HARDEN: Review WAF rule set — enable paranoia level 2 or equivalent.",
        "NOTIFY: Alert the application security team for emergency code review.",
    ],
    "brute force": [
        "IMMEDIATE: Enforce account lockout after 5 failed attempts on all targeted accounts.",
        "BLOCK: Add source IP to firewall deny list and check ASN for broader block.",
        "AUDIT: Verify MFA is enabled on all administrative accounts.",
        "ALERT: Notify affected account owners and force password reset.",
        "MONITOR: Enable enhanced login audit trail for 7 days on targeted systems.",
    ],
    "malware": [
        "CONTAIN: Immediately isolate the affected endpoint from the network via EDR or VLAN ACL.",
        "PRESERVE: Capture a memory image before rebooting (Volatility or Magnet RAM Capture).",
        "FORENSICS: Hash and quarantine the suspicious binary — submit to sandbox (Any.Run).",
        "HUNT: Run YARA rule scan across other endpoints for lateral spread indicators.",
        "RESTORE: Coordinate with IT to restore from last known-good backup after forensics.",
    ],
    "data exfiltration": [
        "IMMEDIATE: Terminate the active network session at the firewall.",
        "BLOCK: Add destination IP and domain to DNS sinkhole and firewall deny list.",
        "FORENSICS: Enumerate what data was accessed — pull file access logs and DLP reports.",
        "NOTIFY: Initiate GDPR / data breach assessment protocol with legal and compliance team.",
        "HARDEN: Audit egress filtering rules and implement strict data loss prevention policies.",
    ],
    "phishing": [
        "CONTAIN: Pull the phishing email from all recipient mailboxes using mail admin tools.",
        "BLOCK: Add sender domain and IP to email gateway blocklist.",
        "USERS: Issue an urgent security awareness alert to all staff about the phishing campaign.",
        "INVESTIGATE: Check mail server logs — identify any users who clicked the embedded URL.",
        "CREDENTIAL: Force password reset for any accounts that submitted credentials.",
    ],
    "reconnaissance": [
        "BLOCK: Add scanning source IP to perimeter deny list for 30 days.",
        "MONITOR: Increase logging verbosity on all public-facing services for 48h.",
        "AUDIT: Review firewall exposure report — ensure only necessary ports are internet-facing.",
        "THREAT-HUNT: Correlate scan target list with internal asset inventory for exposure gaps.",
        "ALERT: Notify asset owners of scanned services — verify patching status.",
    ],
}

_CRITICAL_RESPONSE = [
    "🔴 CRITICAL — Execute Emergency Isolation Protocol:",
    "  1. Immediately isolate affected endpoint using EDR (CrowdStrike / SentinelOne).",
    "  2. Revoke all active sessions for involved accounts in AD and cloud IdP.",
    "  3. Initiate Tier-2 escalation — page on-call incident response lead NOW.",
    "  4. Preserve forensic artifacts: memory image, disk snapshot, and full packet capture.",
    "  5. Open P1 incident ticket and notify CISO within 30 minutes per IR policy.",
]

_STANDARD_RESPONSE = [
    "🟡 STANDARD — Investigate and Monitor:",
    "  1. Verify source IP against VPN, employee travel records, and corporate asset inventory.",
    "  2. Check if the event is part of a known authorized activity (pentest, IT maintenance).",
    "  3. Escalate to Tier-2 if a second related indicator is found within 4 hours.",
    "  4. Log and close with full documentation — include IOCs in the SOC weekly digest.",
]


def recommend_response(alert_details: dict, vt_result: dict) -> str:
    """build response recommendations based on severity and category"""
    sev     = str(alert_details.get("severity", "Medium")).lower()
    verdict = vt_result.get("verdict", "Clean")
    etype   = str(alert_details.get("event_type") or alert_details.get("type") or "").lower()

    # Check for escalation trigger conditions
    is_critical = verdict == "Malicious" or sev in ("critical", "high")

    # Find the most appropriate playbook for this event type
    playbook = None
    for key in _RESPONSE_PLAYBOOKS:
        if key in etype:
            playbook = _RESPONSE_PLAYBOOKS[key]
            break

    if is_critical and playbook:
        # Critical event with known type — combine escalation header with playbook
        header = "\n".join(_CRITICAL_RESPONSE)
        steps  = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(playbook))
        return f"{header}\n\nType-Specific Actions:\n{steps}"

    elif is_critical:
        # Critical but unrecognized type — generic escalation
        return "\n".join(_CRITICAL_RESPONSE)

    elif playbook:
        # Non-critical but known type — use type-specific playbook
        return "\n".join(f"{i+1}. {s}" for i, s in enumerate(playbook))

    else:
        # Unknown type, low severity — standard monitoring
        return "\n".join(_STANDARD_RESPONSE)
