# Sentinel: SOC Incident Ingestion & Triage Platform

🌐 **[Live Web Application](https://share.streamlit.io/monisa-analyst/ai-soc-analyst/main/app.py)**  
*Try the live Sentinel app directly in your browser. The app runs fully offline using deterministic local fallbacks if you don't configure API keys.*

---

## Why I Built Sentinel

I built Sentinel because I wanted to solve a real, everyday bottleneck in Security Operations Centers: **alert fatigue**. Tier-1 analysts are constantly bombarded with raw logs, making it easy to miss actual threats. 

Sentinel is a triage automation platform that acts as an analyst's co-pilot. Instead of manually cross-referencing IPs and matching MITRE tactics, Sentinel automates the entire investigation pipeline. It ingests events, enriches them with threat intelligence, maps them to MITRE ATT&CK tactics, scores their risk, and coordinates with **Anthropic Claude 3.5 Sonnet** (or OpenAI GPT) to write plain-language briefs and response playbooks.

### Engineering Focus Areas
When building this project, I focused on three core production-grade principles:
1. **Multi-LLM Orchestration & Failover:** The system is decoupled from a single provider. It defaults to Anthropic Claude, but allows swapping to OpenAI. If both APIs are down or keys are absent, it seamlessly cascades to a deterministic local rule engine to ensure zero system downtime.
2. **Database Optimization:** I utilized SQLite and designed performance indexes on high-frequency query columns (`severity`, `status`, and `risk_score`) to make the dashboard responsive under load.
3. **Structured Telemetry & Audit Logs:** Every pipeline event is logged to a machine-readable JSONL file, creating a compliance-ready audit trail.

---

## Tech Stack & Architecture

*   **UI Dashboard:** Streamlit (customized with Inter & JetBrains Mono stylesheets for a premium dark theme)
*   **Database:** SQLite (with custom indexes for query performance)
*   **Threat Enrichment:** VirusTotal API v3 (live lookups via Python requests)
*   **AI Engine:** Anthropic Claude (`claude-3-5-sonnet`) & OpenAI API (`gpt-3.5-turbo`)
*   **Logging:** Structured JSON Lines (JSONL) + standard Python logging

### How Data Flows Through the Pipeline

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
   [ Composite Risk Engine ] ────► Calculate weighted risk score (0-100)
         │
         ▼
   [ Framework Mapper ] ────► Map programmatically to MITRE ATT&CK techniques
         │
         ▼
   [ AI Triage Engine ] ────► Dynamic briefings using Claude 3.5 Sonnet / OpenAI
         │
         ▼
   [ Analyst Workspace ] ────► Review dashboard, update status & download reports
```

---

## Core Features

### 1. Multi-Source Alert Ingestion
I wanted analysts to have flexibility in how they feed data into the triage pipeline:
- **Log Upload:** Drag-and-drop CSV log exports or JSON event arrays.
- **Demo Data:** Single-click load of pre-built attack simulation logs (covering SQL injection, lateral movement, brute force, etc.).
- **Manual Entry:** A simple UI form to quickly run a single alert through the threat analysis pipeline.

### 2. Dual-Layer Threat Intelligence
To optimize API usage and protect search privacy, I built a tiered lookup engine:
- **Local Threat Intel:** Validates private IP scopes (RFC 1918), checks known malicious CIDRs, matches known threat groups (e.g. Lazarus, Fancy Bear), and assesses geo-political risk factors.
- **VirusTotal API:** If the IP is public, the platform makes live API v3 calls to pull detection counts, ASN owner information, and country codes.

### 3. MITRE ATT&CK & Cyber Kill Chain Mapping
I mapped raw event logs programmatically against 40+ rules matching the Enterprise Matrix:
- **Initial Access:** T1190 (Exploit Public App), T1566 (Phishing).
- **Execution:** T1059.001 (PowerShell), T1059.003 (Command Shell).
- **Persistence:** T1547.001 (Registry Run Keys), T1053.005 (Scheduled Tasks).
- **Defense Evasion:** T1070.001 (Clear Event Logs), T1562.001 (Disable Antivirus).
- **Credential Access:** T1110 (Brute Force), T1003 (OS Credential Dumping).
- **Impact & Exfiltration:** T1486 (Data Encrypted for Impact), T1041 (Exfiltration over C2).
- Classifies each attack into its respective **Cyber Kill Chain** phase.

### 4. Custom Composite Risk Score Engine
Instead of just relying on static severity tags, I designed a multi-factor risk scoring engine (0-100) based on:
- **Event Severity (30%):** Log-level classification (Low to Critical).
- **VirusTotal Verdict (30%):** Flag counts from participating AV engines.
- **Local Threat Intel (25%):** Known threat actor correlation or geo-risk blacklist matches.
- **Payload Criticality (15%):** Specific keywords matching high-risk signatures (e.g., Ransomware, Exfiltration).

### 5. Multi-LLM Orchestration & Intelligent Fallbacks
I built an orchestration layer that lets the analyst choose the active LLM:
- **Anthropic Claude 3.5 Sonnet:** The default choice, producing highly analytical briefings and technical mitigation playbooks.
- **OpenAI GPT-3.5-turbo:** Integrated as a fast, alternative LLM.
- **Deterministic Local Engine:** If API keys are missing or requests fail, the pipeline falls back to offline template generators, ensuring that the platform remains completely functional offline.

### 6. Compliance Reporting & Audit Trails
- **Text & JSON Handovers:** Download plain-text shift handovers or SIEM-ready JSON reports.
- **JSONL Audit Logging:** Every ingest, lookup, threat verdict, and status update is logged to a structured event trail for audit and compliance.

---

## Local Setup & Installation

### 1. Clone & Navigate to Folder
```bash
git clone https://github.com/Monisa-Analyst/ai-soc-analyst.git
cd ai-soc-analyst
```

### 2. Set Up Virtual Environment
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

### 4. Configure Environment Secrets
Create a `.env` file in the root folder. You can configure any of the following keys:
```env
ANTHROPIC_API_KEY=sk-ant-your-actual-anthropic-key-here
OPENAI_API_KEY=sk-your-actual-openai-key-here
VT_API_KEY=your-actual-virustotal-key-here
```
*Note: If keys are absent, the application runs fully offline using deterministic fallbacks.*

### 5. Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
Open `http://localhost:8501` to view the local application.

---

## Codebase Walkthrough

*   `app.py` - Main Streamlit UI. Contains the tabs for Dashboard Analytics, Ingestion, Reports, and System Settings.
*   `analysis.py` - Core threat mapping logic. Handles the multi-LLM orchestrator (Claude 3.5 Sonnet / OpenAI) and the offline fallback engine.
*   `database.py` - SQLite helper file. Defines the schema, indexes, KPIs, and data operations.
*   `threat_intel.py` - Local reputation database and risk scoring math.
*   `enrichment.py` - VirusTotal API client code.
*   `report_generator.py` - Report formatting code (JSON & Text).
*   `logger.py` - Compliance-ready logging handlers.

---

## License

This project is open-source and licensed under the MIT License.
