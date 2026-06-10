# Sentinel: SOC AI Triage Platform

👉 **[Web Application](https://share.streamlit.io/monisa-analyst/ai-soc-analyst/main/app.py)**

A locally-hosted, AI-assisted Security Operations Centre (SOC) triage system built with Python and Streamlit. Designed to automate Tier-1 analyst tasks including alert ingestion, threat enrichment, MITRE ATT&CK mapping, risk scoring, and incident response planning.

---

## Project Overview

Modern SOC teams are overwhelmed by high alert volumes and slow manual triage processes. This platform addresses that by automating the initial investigation pipeline — giving analysts a head start with AI-generated summaries, threat intelligence enrichment, and structured response playbooks for every incoming security event.

The system is fully functional without any external API keys (using built-in fallback engines), and can optionally integrate with OpenAI GPT-3.5 and VirusTotal for live intelligence.

---

## Features

| Feature | Description |
|---|---|
| **Alert Ingestion** | Upload CSV/JSON log files or enter alerts manually via the UI |
| **VirusTotal Enrichment** | Live IP reputation lookup (falls back to deterministic mock engine) |
| **Local Threat Intelligence** | CIDR-based blacklisting, threat actor attribution, geo risk scoring |
| **AI Triage Summary** | GPT-3.5 powered analyst notes (rule-based fallback if API unavailable) |
| **MITRE ATT&CK Mapping** | 40+ technique rules across all ATT&CK tactics |
| **Cyber Kill Chain** | Automatic Kill Chain phase identification per alert |
| **Risk Scoring** | Composite 0–100 risk score from severity, VT, TI, and event type |
| **Response Playbooks** | Detailed, step-by-step analyst response plans per threat category |
| **Analyst Workflow** | Status tracking (New → In Review → Escalated → Resolved) |
| **Report Export** | Plain-text and JSON incident reports + CSV data export |
| **Audit Logging** | Full pipeline action audit trail in `.log` and `.jsonl` formats |
| **Dashboard Analytics** | Severity charts, MITRE frequency, top source IPs, KPI cards |

---

## Project Structure

```
ai-soc-analyst/
│
├── app.py                  # Main Streamlit application — 4 tabs (Dashboard, Ingest, Reports, Logs)
├── analysis.py             # AI triage engine — GPT summaries, MITRE mapping, response playbooks
├── database.py             # SQLite persistence — schema, queries, analytics, CSV export
├── enrichment.py           # VirusTotal v3 API integration with offline mock fallback
├── threat_intel.py         # Local threat intelligence — IP blacklists, TI correlation, risk scoring
├── report_generator.py     # Incident report generation — plain text and JSON formats
├── logger.py               # Structured audit logging — .log and .jsonl audit trail
│
├── sample_alerts.csv       # 12-event sample dataset (CSV format)
├── sample_alerts.json      # 8-event sample dataset (JSON format)
│
├── requirements.txt        # Python package dependencies
├── .env                    # API keys (OpenAI, VirusTotal) — NOT committed to Git
├── .gitignore              # Excludes .env, __pycache__, soc_triage.db, logs/
│
├── .streamlit/
│   └── config.toml         # Streamlit theme configuration
│
├── logs/                   # Auto-created — stores soc_audit.log and pipeline_events.jsonl
├── reports/                # Auto-created — stores exported .txt and .json reports
└── soc_triage.db           # Auto-created SQLite database
```

---

## Architecture & Data Flow

```
Log Source (CSV / JSON / Manual)
         │
         ▼
  [ Alert Ingestion ]  ──► SQLite DB (raw_log)
         │
         ▼
  [ VirusTotal Enrichment ]  ──► IP verdict, detections, ASN, country
         │
         ▼
  [ Threat Intel Correlation ]  ──► Known IP ranges, actor attribution, geo risk
         │
         ▼
  [ Risk Score Engine ]  ──► Composite 0–100 score (severity + VT + TI + event type)
         │
         ▼
  [ MITRE ATT&CK Mapper ]  ──► Technique ID + Tactic (40+ rules)
         │
         ▼
  [ Kill Chain Identifier ]  ──► Cyber Kill Chain phase (1–7)
         │
         ▼
  [ AI Analysis Engine ]  ──► GPT-3.5 summary + IOCs (rule-based fallback)
         │
         ▼
  [ Response Planner ]  ──► Step-by-step analyst playbook
         │
         ▼
  SQLite DB (all intel fields updated)  ──►  Dashboard / Reports / Export
```

---

## Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/ai-soc-analyst.git
cd ai-soc-analyst
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys (optional)

Create a `.env` file in the project root:

```env
OPENAI_API_KEY=sk-your-openai-key-here
VT_API_KEY=your-virustotal-api-key-here
```

> **Note:** Both keys are optional. The system runs fully offline using built-in fallback engines.

### 5. Run the application

```bash
streamlit run app.py
```

The app will open at `http://localhost:8501`

---

## How to Use

### Ingesting Alerts

1. Open the **Ingest & Triage** tab
2. Choose one of three methods:
   - **File Upload** – Upload your own `.csv` or `.json` log file
   - **Sample Datasets** – Use the included realistic sample alert sets
   - **Manual Entry** – Fill in the form to triage a single alert on the spot
3. Click the **Process** button to run the full pipeline

### Viewing Results

Switch to the **Dashboard** tab to see:
- KPI cards (total alerts, critical count, avg risk score, malicious IP %)
- Severity and status distribution charts
- MITRE ATT&CK technique frequency bar chart
- Top source IPs by alert volume
- Full expandable alert cards with AI summary, MITRE tags, VT intel, and TI data

### Updating Alert Status

Inside each alert card on the Dashboard:
- Change the status dropdown (New → In Review → Escalated → Resolved → False Positive)
- Add an analyst note
- Click **Save Changes** to persist the update

### Exporting Reports

Open the **Reports** tab to:
- Generate a formatted plain-text incident report (downloadable `.txt`)
- Generate a structured JSON report (downloadable `.json`, suitable for SIEM forwarding)
- Export all alert data as a `.csv` spreadsheet

### Viewing Audit Logs

The **Logs & Settings** tab shows the last 50 audit log entries and system configuration status.

---

## Technology Stack

| Component | Technology |
|---|---|
| UI Framework | Streamlit |
| AI Analysis | OpenAI GPT-3.5-turbo |
| Threat Enrichment | VirusTotal API v3 |
| Database | SQLite (via Python stdlib) |
| Language | Python 3.11+ |
| Styling | Custom CSS (Inter + JetBrains Mono) |
| Logging | Python `logging` + JSONL structured log |

---

## MITRE ATT&CK Coverage

The system maps alerts across all major ATT&CK tactics:

- **Initial Access** — T1566 (Phishing), T1190 (Exploit Public App), T1078 (Valid Accounts)
- **Execution** — T1059.001 (PowerShell), T1059.003 (Cmd Shell), T1047 (WMI), T1204 (User Exec)
- **Persistence** — T1547 (Registry Run Keys), T1053 (Scheduled Task), T1543 (Service Install)
- **Credential Access** — T1110 (Brute Force), T1003 (Credential Dumping), T1558 (Kerberoasting)
- **Discovery** — T1046 (Network Scanning), T1087 (Account Discovery)
- **Lateral Movement** — T1021 (RDP, SMB, SSH)
- **Exfiltration** — T1041 (C2 Channel), T1048 (Alt Protocol), T1048.003 (DNS Tunneling)
- **Impact** — T1486 (Ransomware), T1561 (Disk Wipe), T1498 (DDoS)

---

## Security Notes

- API keys are stored in `.env` and excluded from version control via `.gitignore`
- The SQLite database is local-only and contains no credentials
- All external API calls have timeout handling and graceful fallbacks
- The system does not make any outbound network calls unless API keys are configured

---

## License

Internal use only. Not for redistribution.
