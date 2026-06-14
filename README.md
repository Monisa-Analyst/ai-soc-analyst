# Sentinel: Risk-Prioritized Ingestion & SOC Triage Automation

🌐 **[Live Web Application](https://share.streamlit.io/monisa-analyst/ai-soc-analyst/main/app.py)**  
*Try the live Sentinel app directly in your browser. The app runs fully offline using deterministic local fallbacks if you don't configure API keys.*

---

## Project Purpose & Risk Philosophy

In modern security operations, the core challenge is not a lack of data—it is **alert fatigue** and the lack of a standardized framework to quantify threat severity. I developed Sentinel to demonstrate how security teams can transition from reactive alert management to a **proactive, risk-first triage model**. 

Sentinel is an automated triage and threat evaluation pipeline that ingests raw system logs, correlates them with threat intelligence, maps active tactics to security frameworks, calculates a composite risk index, and utilizes **Anthropic Claude 3.5 Sonnet** (or OpenAI) to generate incident briefs and response playbooks.

### Core Risk Analyst Focus Areas:
1. **Quantitative Risk Modeling:** Rather than relying on static, generic severity labels, Sentinel calculates a dynamic, 4-factor composite risk index (0–100) to bubble up maximum business risk.
2. **Control Mapping (MITRE ATT&CK & Cyber Kill Chain):** Translates raw security log behaviors into standardized industry techniques to identify defensive control gaps.
3. **Operational Resilience (Operational Risk Mitigation):** Designed with high-availability API failover architecture. If a primary LLM (like Claude) encounters API rate limits or network issues, the system automatically falls back to OpenAI, and finally to local offline templates—ensuring 100% triage uptime.
4. **Regulatory Auditing & Compliance:** Generates structured JSON Lines (JSONL) event trails to record every triage step, supporting SOC 2, ISO 27001, and GDPR compliance audit requirements.

---

## Tech Stack & Architecture

*   **UI Dashboard:** Streamlit (styled with Inter & JetBrains Mono for a premium analyst dashboard look)
*   **Database Engine:** SQLite (configured with performance indexing on `severity`, `status`, and `risk_score` for high-frequency queries)
*   **External Intelligence:** VirusTotal API v3 (live reputation lookups via Python requests)
*   **AI Orchestration:** Anthropic Claude (`claude-3-5-sonnet`) & OpenAI API (`gpt-3.5-turbo`)
*   **Compliance Logs:** Python `logging` + JSONL structured audit event trail

### Incident Triage Data & Risk Flow

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
   [ Composite Risk Engine ] ────► Calculate composite risk score (0-100)
         │
         ▼
   [ Control Mapper ] ────► Map to MITRE ATT&CK and Cyber Kill Chain
         │
         ▼
   [ AI Triage Engine ] ────► Generate briefings & playbooks (Claude 3.5 / OpenAI)
         │
         ▼
   [ Analyst Workspace ] ────► Review dashboard, update status & download reports
```

---

## Core Features & Risk Frameworks

### 1. Ingestion Pipeline
To simulate a multi-feed SIEM environment, analysts can load security event data in three ways:
- **Bulk CSV Upload:** Ingest formatted security logs from endpoints.
- **Bulk JSON Array Ingestion:** Parse structured JSON logs.
- **Manual Incident Entry:** A web form allowing analysts to input a single suspicious indicator for immediate assessment.

### 2. Multi-Factor Risk Scoring Engine (Quantitative Modeling)
Sentinel replaces qualitative judgment with a weighted composite risk model. The risk score (0–100) is calculated programmatically using the following allocation:
- **Event Severity (30% weight):** Low (10), Medium (40), High (70), Critical (100) raw log classification.
- **VirusTotal Reputation Verdict (30% weight):** Linear scaling based on the percentage of scanning engines flagging the IP.
- **Local Threat Intelligence (25% weight):** Flags geographical risk, known bad CIDRs, and specific attribution matching state-sponsored groups.
- **Payload Threat Level (15% weight):** Signature checks on log messages matching high-risk keywords (e.g. ransomware, exfiltration).

*Outcome: Allows risk managers to filter out noise, concentrate analyst resources on alerts with score >75, and substantially reduce Mean Time to Respond (MTTR).*

### 3. MITRE ATT&CK & Cyber Kill Chain Mapping
To evaluate control coverage, Sentinel programmatically maps log signatures against 40+ rules matching the Enterprise Matrix:
- **Initial Access:** T1190 (Exploit Public-Facing App), T1566 (Phishing).
- **Execution:** T1059.001 (PowerShell), T1059.003 (Command Shell).
- **Persistence:** T1547.001 (Registry Run Keys), T1053.005 (Scheduled Tasks).
- **Defense Evasion:** T1070.001 (Indicator Removal: Clear Logs), T1562.001 (Disable Security Tools).
- **Credential Access:** T1110 (Brute Force), T1003 (OS Credential Dumping).
- **Impact & Exfiltration:** T1486 (Data Encrypted for Impact), T1041 (Exfiltration Over C2).
- Places every matched alert in its appropriate **Cyber Kill Chain** phase (e.g., Delivery, Execution, Actions on Objectives).

### 4. Multi-LLM Orchestration (Operational Risk Management)
API availability is a core system risk. To mitigate vendor lock-in and API outage risks, I built an orchestration layer that dynamically routes requests:
- **Anthropic Claude 3.5 Sonnet:** The default, high-reasoning engine used to parse complex alerts, extract indicators of compromise (IOCs), and draft incident response playbooks.
- **OpenAI GPT-3.5-turbo:** Serves as a high-speed secondary backup.
- **Deterministic Local Engine:** If APIs fail or keys are absent, the platform uses local rule-based template generation to ensure the analyst dashboard never experiences service interruption.

### 5. Compliance Audit Logging
To support corporate governance and compliance requirements:
- **Audit Trails:** Generates structured JSON Lines (`pipeline_events.jsonl`) tracking every ingestion, API call, status change, and download.
- **Executive Reports:** Generates standardized incident briefs in plain text and structured JSON format, ready for forwarding to senior leadership or SIEM analytics systems.

---

## Local Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Monisa-Analyst/ai-soc-analyst.git
cd ai-soc-analyst
```

### 2. Set Up a Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### 3. Install Requirements
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Secrets
Create a `.env` file in the root directory to connect APIs:
```env
ANTHROPIC_API_KEY=sk-ant-your-actual-anthropic-key-here
OPENAI_API_KEY=sk-your-actual-openai-key-here
VT_API_KEY=your-actual-virustotal-key-here
```
*Note: If no keys are provided, the platform automatically switches to deterministic fallback mode.*

### 5. Run the Streamlit Application
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

---

## Codebase Walkthrough

*   `app.py` - Streamlit application frontend, dashboard visualization, and settings configuration.
*   `analysis.py` - Threat modeling module. Integrates the multi-LLM orchestrator (Claude / OpenAI) and the fallback analyzer.
*   `database.py` - Database schema, performance indexing, and transaction helpers.
*   `threat_intel.py` - Custom risk scoring algorithms and local threat reputational database lookup.
*   `enrichment.py` - VirusTotal API client logic.
*   `report_generator.py` - Text and JSON report compilers.
*   `logger.py` - Structured JSONL audit logger.

---

## License

This project is licensed under the MIT License.
