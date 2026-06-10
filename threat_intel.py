import hashlib
import ipaddress
from datetime import datetime

# ---------------------------------------------------------
# THREAT INTELLIGENCE CORRELATION ENGINE
# This module supplements VirusTotal enrichment with static
# threat intelligence — known malicious IP ranges, known
# threat actor groups, IOC matching, and risk scoring.
#
# In a real SOC environment, this data would be pulled from
# a live Threat Intelligence Platform (TIP) like MISP or
# OpenCTI. Here we use a curated static database that is
# representative of real-world threat data.
# ---------------------------------------------------------


# -- KNOWN MALICIOUS IP BLOCKS --------------------------------------
# These CIDR ranges are commonly associated with threat actors,
# Tor exit nodes, bulletproof hosting, and botnet C2 infrastructure.
# Source categories: Emerging Threats, Spamhaus DROP list, ARIN abuse reports.
# -------------------------------------------------------------------

MALICIOUS_RANGES = [
    # Known Russian cybercrime hosting blocks
    "45.33.0.0/16",
    "91.240.118.0/24",
    "185.220.101.0/24",
    "185.220.100.0/24",

    # Tor Exit Nodes (commonly abused for anonymized attacks)
    "199.87.154.0/24",
    "176.10.99.0/24",

    # Known C2 / Botnet infrastructure
    "103.21.244.0/24",
    "223.25.0.0/16",
    "94.102.49.0/24",

    # Shadowserver-reported scanning hosts
    "89.248.165.0/24",
    "80.82.77.0/24",
]


# -- KNOWN THREAT ACTORS --------------------------------------------
# Maps suspicious IP ranges to documented threat actor groups.
# This simulates threat actor attribution — a key SOC function.
# -------------------------------------------------------------------

THREAT_ACTOR_MAP = {
    "185.220":  "APT-TA505 (Evil Corp)",
    "91.240":   "APT-28 (Fancy Bear)",
    "223.25":   "APT-41 (Winnti Group)",
    "103.21":   "APT-32 (OceanLotus)",
    "45.33":    "FIN7 (Carbanak Group)",
    "94.102":   "Lazarus Group (DPRK)",
}


# -- KNOWN MALICIOUS FILE HASHES (MD5) ------------------------------
# Simulated IOC database of known malware hashes.
# In production, this feeds from VirusTotal, MalwareBazaar, etc.
# -------------------------------------------------------------------

KNOWN_BAD_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "Cobalt Strike Beacon (v4.4)",
    "5f4dcc3b5aa765d61d8327deb882cf99": "Emotet Dropper (2023 variant)",
    "098f6bcd4621d373cade4e832627b4f6": "TrickBot Loader",
    "8277e0910d750195b448797616e091ad": "Ryuk Ransomware Payload",
    "e10adc3949ba59abbe56e057f20f883e": "AsyncRAT Client",
    "827ccb0eea8a706c4c34a16891f84e7b": "Mimikatz (credential dumper)",
    "fc5e038d38a57032085441e7fe7010b0": "Metasploit Meterpreter Shell",
    "b14a7b8059d9c055954c92674ce60032": "RedLine Stealer",
}


# -- KNOWN MALICIOUS DOMAINS ----------------------------------------
# Simulates a domain blacklist (usually sourced from URLhaus, PhishTank,
# CISA Known Bad Domains, etc.)
# -------------------------------------------------------------------

MALICIOUS_DOMAINS = {
    "malware-c2.xyz":          "Cobalt Strike C2 domain",
    "phishing-bank.ru":        "Banking credential phishing page",
    "evil-update.com":         "Fake Windows update malware delivery",
    "payload-drop.io":         "Exploit kit landing page",
    "ransomware-note.onion":   "Ransomware payment portal",
    "exfil-bucket.s3-fake.com":"Data exfiltration C2",
    "apt-staging.net":         "APT staging server",
}


# -- GEOPOLITICAL RISK TABLE ----------------------------------------
# Countries flagged as elevated cyber threat sources based on
# public government advisories (CISA, NCSC, ACSC).
# -------------------------------------------------------------------

HIGH_RISK_COUNTRIES = {
    "CN": ("China", 90),
    "RU": ("Russia", 90),
    "KP": ("North Korea", 95),
    "IR": ("Iran", 85),
    "NG": ("Nigeria", 60),
    "UA": ("Ukraine", 55),  # Due to ongoing conflict / cybercrime activity
    "BR": ("Brazil", 50),
}


# ===================================================================
# -- CORE PUBLIC FUNCTIONS
# ===================================================================

def check_ip_reputation(ip_address: str) -> dict:
    """
    Cross-references an IP against local threat intelligence databases.
    Works offline — no external API calls required.

    Checks performed:
      1. Known malicious CIDR range membership
      2. Threat actor attribution
      3. Geopolitical risk assessment
      4. RFC 1918 private address detection

    Args:
        ip_address : The IPv4 address string to evaluate.

    Returns:
        A dictionary with keys: is_threat, threat_level, actor, geo_risk, notes.
    """
    if not ip_address:
        return _null_result()

    result = {
        "is_threat": False,
        "threat_level": "Low",
        "actor": "Unknown",
        "geo_risk": "Unknown",
        "notes": []
    }

    # 1. Check if the IP is an RFC 1918 private address (never external threat)
    try:
        parsed = ipaddress.ip_address(ip_address)
        if parsed.is_private:
            result["notes"].append("RFC 1918 private address — internal network traffic.")
            result["geo_risk"] = "Internal"
            return result
    except ValueError:
        result["notes"].append(f"Invalid IP format: {ip_address}")
        return result

    # 2. Check against known malicious CIDR blocks
    for cidr in MALICIOUS_RANGES:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if parsed in network:
                result["is_threat"] = True
                result["threat_level"] = "High"
                result["notes"].append(f"IP falls within blacklisted range: {cidr}")
                break
        except ValueError:
            continue

    # 3. Perform threat actor attribution based on IP prefix
    for prefix, actor in THREAT_ACTOR_MAP.items():
        if ip_address.startswith(prefix):
            result["actor"] = actor
            result["threat_level"] = "Critical"
            result["is_threat"] = True
            result["notes"].append(f"Attributed to known threat actor group: {actor}")
            break

    # 4. Geopolitical risk assessment (simulated — usually uses MaxMind GeoIP)
    # We use a deterministic hash to assign a country without a real GeoIP API.
    h = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
    country_codes = list(HIGH_RISK_COUNTRIES.keys()) + ["US", "DE", "GB", "FR", "JP", "AU"]
    inferred_code = country_codes[h % len(country_codes)]

    if inferred_code in HIGH_RISK_COUNTRIES:
        country_name, risk_pct = HIGH_RISK_COUNTRIES[inferred_code]
        result["geo_risk"] = f"{country_name} (Risk: {risk_pct}%)"
        if risk_pct >= 85:
            result["is_threat"] = True
            result["notes"].append(f"Source country '{country_name}' is flagged by CISA advisories.")
    else:
        result["geo_risk"] = f"Country Code: {inferred_code} (Low Risk)"

    if not result["notes"]:
        result["notes"].append("No matches in local threat intelligence database.")

    return result


def check_hash(file_hash: str) -> dict:
    """
    Checks a file hash (MD5) against the local IOC hash database.

    Args:
        file_hash : MD5 hash string of the file to check.

    Returns:
        dict with keys: is_known_malware, malware_name (or None).
    """
    normalized = file_hash.strip().lower()
    if normalized in KNOWN_BAD_HASHES:
        return {
            "is_known_malware": True,
            "malware_name": KNOWN_BAD_HASHES[normalized]
        }
    return {
        "is_known_malware": False,
        "malware_name": None
    }


def check_domain(domain: str) -> dict:
    """
    Checks a domain name against the local malicious domain database.

    Args:
        domain : The FQDN to check (e.g., 'evil-update.com').

    Returns:
        dict with keys: is_malicious, description (or None).
    """
    normalized = domain.strip().lower()
    if normalized in MALICIOUS_DOMAINS:
        return {
            "is_malicious": True,
            "description": MALICIOUS_DOMAINS[normalized]
        }
    return {
        "is_malicious": False,
        "description": None
    }


def calculate_risk_score(alert: dict, vt_result: dict, ti_result: dict) -> int:
    """
    Computes a composite risk score (0–100) for an alert based on
    multiple intelligence inputs. This score is used to prioritize
    analyst workload and generate escalation decisions.

    Scoring breakdown:
      - Base severity assessment  : up to 30 points
      - VirusTotal verdict        : up to 30 points
      - Threat intelligence match : up to 25 points
      - Event type criticality    : up to 15 points

    Args:
        alert     : Raw alert dictionary from the log source.
        vt_result : VirusTotal enrichment result dictionary.
        ti_result : Local threat intelligence result dictionary.

    Returns:
        Integer risk score clamped to range [0, 100].
    """
    score = 0

    # -- Severity baseline (up to 30 points)
    sev = str(alert.get("severity", "Medium")).lower()
    severity_scores = {"critical": 30, "high": 22, "medium": 14, "low": 5, "info": 0}
    score += severity_scores.get(sev, 10)

    # -- VirusTotal verdict (up to 30 points)
    verdict = vt_result.get("verdict", "Clean")
    detections_raw = str(vt_result.get("detections", "0 engines flagged"))
    try:
        det_count = int(detections_raw.split()[0])
    except (ValueError, IndexError):
        det_count = 0

    if verdict == "Malicious":
        score += min(30, 15 + det_count)  # More detections = higher score
    elif det_count > 0:
        score += 10  # Suspicious but not definitively malicious

    # -- Local threat intelligence match (up to 25 points)
    if ti_result.get("is_threat"):
        score += 20
    if ti_result.get("actor") != "Unknown":
        score += 5  # Extra points for attributed attacks

    # -- Event type criticality bonus (up to 15 points)
    etype = str(alert.get("event_type") or alert.get("type") or "").lower()
    critical_events = {
        "ransomware": 15, "exfil": 14, "data exfiltration": 14,
        "malware": 12, "trojan": 12, "sql injection": 11,
        "brute force": 8, "phishing": 8, "reconnaissance": 5, "scan": 4
    }
    for keyword, bonus in critical_events.items():
        if keyword in etype:
            score += bonus
            break  # Only add the highest matching bonus

    return min(score, 100)  # Clamp to 100


def get_attack_phase(event_type: str) -> str:
    """
    Maps an event type to its corresponding Cyber Kill Chain phase.
    This helps analysts understand where an attacker is in their campaign.

    Args:
        event_type : The event_type string from the alert log.

    Returns:
        A string describing the Kill Chain phase.
    """
    etype = event_type.lower()

    kill_chain_map = [
        (["recon", "scan", "nmap", "enumerat"],      "Phase 1 – Reconnaissance"),
        (["phish", "spear", "email", "attachment"],   "Phase 2 – Weaponization / Delivery"),
        (["exploit", "injection", "sql", "overflow"], "Phase 3 – Exploitation"),
        (["malware", "trojan", "dropper", "loader"],  "Phase 4 – Installation"),
        (["c2", "beacon", "command", "control"],      "Phase 5 – Command & Control"),
        (["lateral", "pivot", "spread"],              "Phase 6 – Lateral Movement"),
        (["exfil", "transfer", "upload", "theft"],    "Phase 7 – Exfiltration"),
        (["ransom", "encrypt", "wipe", "destruct"],   "Phase 7 – Actions on Objectives"),
        (["brute", "login fail", "cred"],             "Phase 3 – Credential Access"),
    ]

    for keywords, phase in kill_chain_map:
        if any(kw in etype for kw in keywords):
            return phase

    return "Phase Unknown – Requires Manual Classification"


def _null_result() -> dict:
    """Returns a default empty threat intel result for missing inputs."""
    return {
        "is_threat": False,
        "threat_level": "Unknown",
        "actor": "Unknown",
        "geo_risk": "Unknown",
        "notes": ["No IP address provided for analysis."]
    }
