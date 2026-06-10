# Sentinel: SOC Incident Ingestion & Triage Platform

🌐 **[Live Web Application](https://share.streamlit.io/monisa-analyst/ai-soc-analyst/main/app.py)**  
*Try the live Sentinel app directly in your browser. The app runs fully offline using deterministic fallbacks if you don't configure API keys.*

---

## Project Overview

Sentinel is a Security Operations Center (SOC) triage automation platform designed to assist Tier-1 analysts. It automates the investigation pipeline for security event logs by parsing events, enriching them with external threat intelligence, mapping activity to MITRE ATT&CK techniques, calculating composite risk scores, and generating AI-assisted incident triage summaries.

I built this project to showcase:
1.  **Security Log Engineering:** Parsing CSV and JSON logs and normalizing security metrics.
2.  **Threat Intelligence Enrichment:** Integrating VirusTotal API v3 and correlating IPs against local threat databases.
3.  **Risk Modeling:** Building composite scoring algorithms using threat intelligence, severity, and event context.
4.  **Security Framework Mapping:** Mapping raw logs programmatically to MITRE ATT&CK techniques and Cyber Kill Chain phases.
5.  **LLM Security Orchestration:** Leveraging OpenAI GPT-3.5-turbo (with offline rule fallbacks) to generate incident briefs and response playbooks.
6.  **Compliance Audit Logging:** Structuring event tracking with compliance-ready logs in JSON Lines (JSONL).

---

## Tech Stack & Architecture

*   **UI Dashboard:** Streamlit (Custom Inter + JetBrains Mono stylesheet)
*   **Database:** SQLite (via standard Python sqlite3 library)
*   **Threat Enrichment:** VirusTotal API v3 (requests)
*   **AI Engine:** OpenAI API (`gpt-3.5-turbo`)
*   **Logging:** Python `logging` + JSONL structured event logs
*   **Languages:** Python 3.11+, Pandas

### Incident Triage Data Flow

```
Raw Alert Ingestion (CSV / JSON / Form Entry)
         │
         ▼
   [ DB Persistence ] ────► Save raw JSON payload to SQLite (raw_log)
         │
         ▼
   [ External Threat Intel ] ────► Query VirusTotal API v3 for IP verdicts
         │
         ▼
   [ Local Threat Intel ] ────► Cross-reference IP ranges, actors & geographies
         │
         ▼
   [ Composite Risk Engine ] ────► Calculate risk score (0-100)
         │
         ▼
   [ Framework Mapper ] ────► Map to MITRE ATT&CK and Cyber Kill Chain
         │
         ▼
   [ AI Triage Engine ] ────► Generate analyst brief & playbook steps
         │
         ▼
   [ Analyst Workspace ] ────► Display dashboard, update status & download reports
```

---

## Core Features

### 1. Multi-Source Alert Ingestion
Analysts can load data into the triage pipeline using three methods:
-   **Log Upload:** Drag-and-drop security CSV files or JSON log arrays.
-   **Demo Data:** Single-click load of pre-built sample datasets representing real-world attacks.
-   **Manual Entry:** A simple UI form to ingest and triage a single security event.

### 2. Dual-Layer Threat Intelligence
-   **VirusTotal API Integration:** Live lookup for IP verdicts, detection counts, country codes, and ASN owners.
-   **Local Intelligence Engine:** Fallback lookup validating RFC 1918 private scopes, blacklisted CIDR blocks, known threat actor groups (e.g. Fancy Bear, Lazarus Group, TA505), and geo-political risk databases.

### 3. MITRE ATT&CK & Cyber Kill Chain Mapping
Sentinel matches raw log signatures to over 40 rules across the enterprise threat matrix:
-   **Initial Access:** Phishing (T1566), Exploit Public-Facing App (T1190).
-   **Execution:** PowerShell (T1059.001), Command Shell (T1059.003), WMI (T1047).
-   **Persistence:** Registry Run Keys (T1547.001), Scheduled Tasks (T1053.005).
-   **Defense Evasion:** Clear Event Logs (T1070.001), Disable Antivirus (T1562.001).
-   **Credential Access:** Brute Force (T1110), OS Credential Dumping (T1003).
-   **Impact:** Data Encrypted for Impact (T1486), Disk Wipe (T1561).
-   Maps each event to one of the **7 Cyber Kill Chain** phases.

### 4. Composite Risk Score Engine
Calculates a weighted prioritisation score (0–100) based on:
-   **Event Severity (30%):** Low, Medium, High, or Critical log classification.
-   **VirusTotal Verdict (30%):** Scale based on engines flag counts.
-   **Threat Intelligence (25%):** Blacklist matches or known threat actor attribution.
-   **Event Type Criticality (15%):** Ransomware, Exfiltration, or Trojan indicators.

### 5. Structured Reports & Compliance Exports
-   **Text Report:** Plain-text formatted executive briefings showing severity distribution bars, risk summaries, and analytical logs.
-   **JSON Report:** Standardized incident reports ready for forwarding to SIEM collectors or ticketing queues.
-   **CSV Audit Trail:** Flat export of all triaged alert columns.
-   **JSONL Log File:** Machine-readable action trail recording every ingest, lookup, threat verdict, and status update.

---

## Local Setup & Installation

### 1. Clone & Set Up Directory
```bash
git clone https://github.com/Monisa-Analyst/ai-soc-analyst.git
cd ai-soc-analyst
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment (Optional)
Create a `.env` file in the root directory to enable live API integrations:
```env
OPENAI_API_KEY=sk-your-openai-api-key-here
VT_API_KEY=your-virustotal-api-key-here
```
*Note: If no keys are provided, the system runs locally using offline deterministic fallback modules.*

### 5. Launch the Dashboard
```bash
streamlit run app.py
```
Open `http://localhost:8501` to use the application locally.

---

## Project Structure

```
├── app.py                  # Main Streamlit dashboard (Dashboard, Ingest, Reports, Logs tabs)
├── analysis.py             # Incident triage briefs, MITRE mappings, and playbooks
├── database.py             # SQLite interface (schema setup, KPIs, data filters)
├── enrichment.py           # VirusTotal v3 API connection & deterministic mock fallback
├── threat_intel.py         # Local Threat Intel lookup (CIDR lists, Geo Risk, Risk Scoring)
├── report_generator.py     # Incident report formatter (Text and JSON generators)
├── logger.py               # Compliance Audit logger (outputs soc_audit.log & pipeline_events.jsonl)
├── sample_alerts.csv       # Preloaded test datasets (CSV format)
├── sample_alerts.json      # Preloaded test datasets (JSON format)
├── requirements.txt        # Python package listing
└── README.md               # Sentinel documentation
```

---

## License

This project is licensed under the MIT License.
