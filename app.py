import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime

# Import all SOC pipeline modules
from database import (
    init_db, insert_alert, get_all_alerts, update_alert, clear_all_alerts,
    update_alert_status, mark_false_positive, get_statistics,
    get_top_source_ips, get_mitre_frequency, get_high_risk_alerts,
    get_malicious_alerts, export_alerts_csv
)
from enrichment import lookup_ip
from analysis import triage_alert, map_mitre, recommend_response
from threat_intel import (
    check_ip_reputation, calculate_risk_score, get_attack_phase
)
from report_generator import (
    generate_text_report, generate_json_report,
    save_text_report, save_json_report, list_saved_reports
)
from logger import (
    log_ingestion, log_enrichment, log_analysis,
    log_status_change, log_error, log_report_generated,
    get_recent_logs
)


# page configuration


st.set_page_config(
    page_title="SOC AI Triage | Sentinel Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# styling overrides


st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0f172a;
    color: #e2e8f0;
}
section[data-testid="stSidebar"] * {
    color: #e2e8f0 !important;
}
section[data-testid="stSidebar"] .stButton > button {
    background: #1e293b;
    color: #94a3b8;
    border: 1px solid #334155;
    width: 100%;
    margin: 2px 0;
    border-radius: 6px;
    font-size: 0.85rem;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background: #334155;
    color: #f1f5f9;
    border-color: #475569;
}

/* Main metric cards */
.metric-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 18px 22px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.metric-card .metric-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 6px;
}
.metric-card .metric-value {
    font-size: 2rem;
    font-weight: 700;
    color: #0f172a;
    line-height: 1;
}
.metric-card .metric-sub {
    font-size: 0.78rem;
    color: #94a3b8;
    margin-top: 4px;
}

/* Alert cards */
.alert-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-left: 5px solid #64748b;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.alert-card.critical { border-left-color: #dc2626; }
.alert-card.high     { border-left-color: #ea580c; }
.alert-card.medium   { border-left-color: #d97706; }
.alert-card.low      { border-left-color: #16a34a; }

/* Severity badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.badge-critical { background: #fee2e2; color: #b91c1c; }
.badge-high     { background: #ffedd5; color: #c2410c; }
.badge-medium   { background: #fef3c7; color: #b45309; }
.badge-low      { background: #dcfce7; color: #15803d; }
.badge-malicious{ background: #fee2e2; color: #b91c1c; }
.badge-clean    { background: #dcfce7; color: #15803d; }
.badge-new      { background: #e0f2fe; color: #0369a1; }
.badge-resolved { background: #dcfce7; color: #15803d; }

/* Analysis sections */
.analysis-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 14px 16px;
    font-family: 'Inter', sans-serif;
    font-size: 0.875rem;
    line-height: 1.7;
    color: #1e293b;
    white-space: pre-wrap;
}

/* Section headers */
.section-label {
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #94a3b8;
    margin-bottom: 6px;
    margin-top: 14px;
}

/* VT intel container */
.intel-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    font-size: 0.83rem;
}
.intel-item {
    background: #f1f5f9;
    border-radius: 6px;
    padding: 8px 12px;
}
.intel-item .key {
    color: #64748b;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.intel-item .val {
    color: #0f172a;
    font-weight: 600;
    margin-top: 2px;
}

/* Code/log display */
.log-line {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #22d3ee;
    background: #0f172a;
    padding: 12px 14px;
    border-radius: 6px;
    line-height: 1.8;
    overflow-x: auto;
    white-space: pre;
}

/* Risk score bar */
.risk-bar-wrap { background: #f1f5f9; border-radius: 4px; height: 6px; margin-top: 6px; }
.risk-bar { height: 6px; border-radius: 4px; }

/* Tabs styling override */
.stTabs [data-baseweb="tab"] {
    font-size: 0.875rem;
    font-weight: 500;
    padding: 10px 20px;
}

hr { border-color: #e2e8f0; }

/* Hide default streamlit branding */
#MainMenu, footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# db init


init_db()



# sidebar layout


with st.sidebar:
    st.markdown("""
    <div style="padding: 12px 0 20px 0;">
        <div style="font-size:1.3rem; font-weight:700; color:#f1f5f9; letter-spacing:-0.5px;">🛡️ Sentinel</div>
        <div style="font-size:0.75rem; color:#64748b; margin-top:2px;">SOC Triage Platform v2.0</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div style="font-size:0.68rem;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px;">Quick Filters</div>', unsafe_allow_html=True)

    # Status selector
    status_filter = st.selectbox(
        "Alert Status",
        ["All", "New", "In Review", "Escalated", "Resolved", "False Positive"],
        key="status_filter"
    )

    severity_filter = st.selectbox(
        "Severity",
        ["All", "Critical", "High", "Medium", "Low"],
        key="severity_filter"
    )

    st.markdown("---")
    st.markdown('<div style="font-size:0.68rem;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px;">Actions</div>', unsafe_allow_html=True)

    if st.button("🗑️ Clear All Alerts", key="clear_btn"):
        clear_all_alerts()
        st.warning("Database cleared.")
        st.rerun()

    st.markdown("---")
    st.markdown('<div style="font-size:0.68rem;color:#64748b;margin-top:8px;">All analysis runs locally.<br>VirusTotal API optional.</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div style="font-size:0.68rem;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px;">Portfolio Links</div>', unsafe_allow_html=True)
    st.markdown("- 🐙 [GitHub Profile](https://github.com/Monisa-Analyst)")
    st.markdown("- 🛒 [Sales Insights Dashboard](https://share.streamlit.io/monisa-analyst/sales-insights-dashboard/main/src/app.py)")
    st.markdown("- 💼 [LinkedIn Profile](https://www.linkedin.com/in/monisa-l-333546366)")



# triage pipeline orchestration


def run_pipeline(logs_list: list, source: str = "Upload"):
    """
    Orchestrates the full SOC triage pipeline for a batch of alerts.

    For each alert in the list:
      1. Insert raw log into the database
      2. Enrich source IP via VirusTotal (or mock)
      3. Run local threat intelligence correlation
      4. Compute composite risk score (0-100)
      5. Map event to MITRE ATT&CK technique
      6. Identify Cyber Kill Chain phase
      7. Generate AI analyst summary
      8. Generate response plan
      9. Update the database with all intel fields
      10. Log each step to the audit trail
    """
    progress = st.progress(0, text="Starting triage pipeline...")
    total = len(logs_list)

    for i, log in enumerate(logs_list):
        event_type = log.get("event_type") or log.get("type") or "Unknown"
        severity   = log.get("severity", "Medium")
        src_ip     = log.get("source_ip") or log.get("src_ip") or ""

        progress.progress((i + 1) / total, text=f"Processing {event_type} ({i+1}/{total})...")

        try:
            # Step 1: Persist raw alert
            rid = insert_alert(log)
            log_ingestion(rid, source, event_type, severity)

            # Step 2: VirusTotal IP enrichment
            vt_info = lookup_ip(src_ip)
            log_enrichment(rid, src_ip, vt_info.get("verdict","N/A"), vt_info.get("detections","N/A"))

            # Step 3: Local threat intelligence correlation
            ti_info = check_ip_reputation(src_ip)

            # Step 4: Composite risk score
            risk_score = calculate_risk_score(log, vt_info, ti_info)

            # Step 5: MITRE ATT&CK mapping
            mitre      = map_mitre(log)

            # Step 6: Cyber Kill Chain phase
            kill_chain = get_attack_phase(event_type)

            # Step 7: AI analysis summary
            summary    = triage_alert(log)

            # Step 8: Response recommendation
            response   = recommend_response(log, vt_info)

            log_analysis(rid, mitre.split("\n")[0], risk_score)

            # Step 9: Write all intel back to the database
            update_alert(rid, {
                "vt_result":     json.dumps(vt_info),
                "ti_result":     json.dumps(ti_info),
                "mitre_tag":     mitre,
                "ai_summary":    summary,
                "response_plan": response,
                "risk_score":    risk_score,
                "kill_chain":    kill_chain,
            })

        except Exception as e:
            log_error(f"Pipeline error for alert #{i+1}", e)

    progress.empty()
    st.success(f"✅ Pipeline complete — {total} alert(s) triaged.")



# setup dashboard tabs


tabs = st.tabs(["📊 Dashboard", "📥 Ingest & Triage", "📋 Reports", "⚙️ Logs & Settings"])


# --- Tab 1: Dashboard Analytics ---

with tabs[0]:
    st.title("Triage Dashboard")
    st.caption(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Fetch all alerts and apply sidebar filters
    all_alerts = get_all_alerts()
    stats = get_statistics()

    # Apply filters
    display_alerts = all_alerts
    if status_filter != "All":
        display_alerts = [a for a in display_alerts if a.get("status") == status_filter]
    if severity_filter != "All":
        display_alerts = [a for a in display_alerts if a.get("severity") == severity_filter]

    # kpi cards
    st.markdown("### Key Performance Indicators")

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

    with kpi1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Alerts</div>
            <div class="metric-value">{stats['total']}</div>
            <div class="metric-sub">In database</div>
        </div>""", unsafe_allow_html=True)

    with kpi2:
        crit = stats['by_severity'].get('Critical', 0)
        high = stats['by_severity'].get('High', 0)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Critical / High</div>
            <div class="metric-value" style="color:#dc2626;">{crit + high}</div>
            <div class="metric-sub">{crit} Critical · {high} High</div>
        </div>""", unsafe_allow_html=True)

    with kpi3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Avg Risk Score</div>
            <div class="metric-value" style="color:#d97706;">{stats['avg_risk_score']}<span style="font-size:1rem;color:#94a3b8;">/100</span></div>
            <div class="metric-sub">Across all alerts</div>
        </div>""", unsafe_allow_html=True)

    with kpi4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Malicious IPs</div>
            <div class="metric-value" style="color:#dc2626;">{stats['malicious_pct']}%</div>
            <div class="metric-sub">VT-confirmed threats</div>
        </div>""", unsafe_allow_html=True)

    with kpi5:
        fp = stats['false_positive_count']
        new_count = stats['by_status'].get('New', 0)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Pending Review</div>
            <div class="metric-value" style="color:#0369a1;">{new_count}</div>
            <div class="metric-sub">{fp} false positive(s)</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # analytics charts
    if stats['total'] > 0:
        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            st.markdown("**Alert Distribution by Severity**")
            sev_data = pd.DataFrame(
                list(stats['by_severity'].items()),
                columns=["Severity", "Count"]
            )
            sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sev_data["_order"] = sev_data["Severity"].map(sev_order).fillna(99)
            sev_data = sev_data.sort_values("_order").drop(columns="_order")
            st.bar_chart(sev_data.set_index("Severity"), use_container_width=True)

        with col_chart2:
            st.markdown("**Alert Status Breakdown**")
            status_data = pd.DataFrame(
                list(stats['by_status'].items()),
                columns=["Status", "Count"]
            )
            st.bar_chart(status_data.set_index("Status"), use_container_width=True)

        # MITRE frequency view
        mitre_freq = get_mitre_frequency()
        if mitre_freq:
            st.markdown("**MITRE ATT&CK Technique Frequency**")
            mitre_df = pd.DataFrame(
                list(mitre_freq.items()),
                columns=["Technique", "Occurrences"]
            ).sort_values("Occurrences", ascending=False)
            st.bar_chart(mitre_df.set_index("Technique"), use_container_width=True)

        # Top source IPs
        top_ips = get_top_source_ips(5)
        if top_ips:
            st.markdown("**Top Source IPs by Alert Volume**")
            ip_df = pd.DataFrame(top_ips).rename(columns={
                "ip": "IP Address", "count": "Alert Count", "peak_risk": "Peak Risk Score"
            })
            st.dataframe(ip_df, use_container_width=True, hide_index=True)

    st.markdown("---")

    # alert detail cards
    st.markdown(f"### Alert Details ({len(display_alerts)} shown)")

    if not display_alerts:
        st.info("No alerts match the selected filters. Adjust filters in the sidebar or ingest data from the **Ingest & Triage** tab.")
    else:
        for a in display_alerts:
            sev = str(a.get("severity", "Medium"))
            sev_class = sev.lower() if sev.lower() in ("critical", "high", "medium", "low") else "low"

            # VT result parse
            vt = {}
            try:
                vt = json.loads(a.get("vt_result") or "{}")
            except (json.JSONDecodeError, TypeError):
                pass

            # TI result parse
            ti = {}
            try:
                ti = json.loads(a.get("ti_result") or "{}")
            except (json.JSONDecodeError, TypeError):
                pass

            verdict = vt.get("verdict", "Unknown")
            vt_color = "badge-malicious" if verdict == "Malicious" else "badge-clean"
            sev_badge = f"badge-{sev_class}"
            risk = a.get("risk_score", 0) or 0
            risk_color = "#dc2626" if risk >= 75 else "#d97706" if risk >= 50 else "#16a34a"

            with st.expander(
                f"#{a['id']}  ·  {a.get('event_type','?')}  ·  {a.get('source_ip','?')} → {a.get('dest_ip','?')}  ·  Risk: {risk}/100",
                expanded=False
            ):
                st.markdown(f"""
                <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap;">
                    <span class="badge {sev_badge}">{sev}</span>
                    <span class="badge {vt_color}">VT: {verdict}</span>
                    <span style="font-size:0.8rem;color:#64748b;">Status: <b>{a.get('status','New')}</b></span>
                    <span style="font-size:0.8rem;color:#64748b;">Kill Chain: <b>{a.get('kill_chain','Unknown')}</b></span>
                    <span style="font-size:0.8rem;color:#64748b;">Time: {a.get('timestamp','N/A')}</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                    <span style="font-size:0.75rem;color:{risk_color};font-weight:700;">Risk Score: {risk}/100</span>
                    <div class="risk-bar-wrap" style="flex:1;">
                        <div class="risk-bar" style="width:{risk}%;background:{risk_color};"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                col_main, col_intel = st.columns([3, 2])

                with col_main:
                    st.markdown('<div class="section-label">AI Triage Summary</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="analysis-box">{a.get("ai_summary") or "No summary available."}</div>', unsafe_allow_html=True)

                    st.markdown('<div class="section-label">MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
                    mitre_display = (a.get("mitre_tag") or "Not mapped").replace("\n", "\n  ")
                    st.info(f"🛡️ {mitre_display}")

                    st.markdown('<div class="section-label">Recommended Response</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="analysis-box">{a.get("response_plan") or "No response plan."}</div>', unsafe_allow_html=True)

                with col_intel:
                    st.markdown('<div class="section-label">VirusTotal Intelligence</div>', unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="intel-grid">
                        <div class="intel-item"><div class="key">Verdict</div><div class="val">{vt.get("verdict","N/A")}</div></div>
                        <div class="intel-item"><div class="key">Detections</div><div class="val">{vt.get("detections","N/A")}</div></div>
                        <div class="intel-item"><div class="key">Country</div><div class="val">{vt.get("country","N/A")}</div></div>
                        <div class="intel-item"><div class="key">ASN Owner</div><div class="val">{vt.get("owner","N/A")}</div></div>
                        <div class="intel-item"><div class="key">Reputation</div><div class="val">{vt.get("reputation","N/A")}</div></div>
                        <div class="intel-item"><div class="key">Category</div><div class="val">{vt.get("category","N/A")}</div></div>
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown('<div class="section-label">Threat Intelligence</div>', unsafe_allow_html=True)
                    ti_threat = "⚠️ YES" if ti.get("is_threat") else "✅ No"
                    st.markdown(f"""
                    <div class="intel-grid">
                        <div class="intel-item"><div class="key">Known Threat</div><div class="val">{ti_threat}</div></div>
                        <div class="intel-item"><div class="key">Threat Actor</div><div class="val">{ti.get("actor","Unknown")}</div></div>
                        <div class="intel-item"><div class="key">Geo Risk</div><div class="val">{ti.get("geo_risk","Unknown")}</div></div>
                        <div class="intel-item"><div class="key">Threat Level</div><div class="val">{ti.get("threat_level","Low")}</div></div>
                    </div>
                    """, unsafe_allow_html=True)

                    # TI Notes
                    notes = ti.get("notes", [])
                    if notes:
                        st.markdown('<div class="section-label">TI Notes</div>', unsafe_allow_html=True)
                        for note in notes:
                            st.caption(f"• {note}")

                # Analyst Actions
                st.markdown('<div class="section-label">Analyst Actions</div>', unsafe_allow_html=True)
                action_col1, action_col2, action_col3 = st.columns(3)
                with action_col1:
                    new_status = st.selectbox(
                        "Update Status",
                        ["New", "In Review", "Escalated", "Resolved", "False Positive"],
                        key=f"status_{a['id']}",
                        index=["New","In Review","Escalated","Resolved","False Positive"].index(a.get("status","New"))
                        if a.get("status") in ["New","In Review","Escalated","Resolved","False Positive"] else 0
                    )
                with action_col2:
                    analyst_note = st.text_input("Add Note", key=f"note_{a['id']}", placeholder="Optional analyst note...")
                with action_col3:
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("💾 Save Changes", key=f"save_{a['id']}"):
                        old_status = a.get("status", "New")
                        update_alert_status(a["id"], new_status, analyst_note)
                        log_status_change(a["id"], old_status, new_status)
                        st.success("Status updated.")
                        st.rerun()

    # Refresh button
    if st.button("🔄 Refresh Dashboard"):
        st.rerun()


# --- Tab 2: Alert Ingestion and Triage ---

with tabs[1]:
    st.title("Ingest & Triage")
    st.write("Upload raw log files or process our included sample datasets to trigger the full AI analysis pipeline.")

    ingest_tabs = st.tabs(["📁 File Upload", "🧪 Sample Datasets", "✏️ Manual Entry"])

    # file upload triage
    with ingest_tabs[0]:
        st.markdown("### Upload Log File")
        st.caption("Supported formats: CSV (with headers), JSON array of event objects")
        uploaded_file = st.file_uploader(
            "Drag and drop or browse for your log file",
            type=["csv", "json"],
            help="CSV files must have column headers. JSON files must be an array of objects."
        )

        if uploaded_file:
            try:
                if uploaded_file.name.endswith(".csv"):
                    df = pd.read_csv(uploaded_file)
                    data = df.to_dict(orient="records")
                    st.markdown(f"**Parsed {len(data)} records from CSV:**")
                else:
                    data = json.load(uploaded_file)
                    if isinstance(data, dict):
                        data = [data]
                    st.markdown(f"**Parsed {len(data)} records from JSON:**")

                st.dataframe(pd.DataFrame(data).head(10), use_container_width=True)

                if st.button(f"▶️ Process {len(data)} Record(s)", type="primary"):
                    run_pipeline(data, source=f"File Upload: {uploaded_file.name}")
                    st.rerun()

            except Exception as e:
                st.error(f"Error parsing file: {e}")
                log_error("File upload parse", e)

    # load sample data
    with ingest_tabs[1]:
        st.markdown("### Pre-loaded Sample Datasets")
        st.caption("These datasets simulate realistic enterprise log data for demonstration and testing.")

        sample_col1, sample_col2 = st.columns(2)

        with sample_col1:
            st.markdown("**Sample Set A: Network Alerts (CSV)**")
            st.caption("5 alerts covering SQL injection, brute force, reconnaissance, phishing, malware")
            if st.button("▶️ Load Sample Set A", key="sample_a"):
                try:
                    df = pd.read_csv("sample_alerts.csv")
                    data = df.to_dict(orient="records")
                    run_pipeline(data, source="Sample Set A (CSV)")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

        with sample_col2:
            st.markdown("**Sample Set B: Endpoint Events (JSON)**")
            st.caption("3 alerts covering SQL injection, brute force, data exfiltration from JSON logs")
            if st.button("▶️ Load Sample Set B", key="sample_b"):
                try:
                    with open("sample_alerts.json", "r") as f:
                        data = json.load(f)
                    run_pipeline(data, source="Sample Set B (JSON)")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

        if st.button("▶️ Load All Samples (A + B)", type="primary", key="sample_all"):
            try:
                df = pd.read_csv("sample_alerts.csv")
                csv_data = df.to_dict(orient="records")
                with open("sample_alerts.json", "r") as f:
                    json_data = json.load(f)
                run_pipeline(csv_data + json_data, source="Full Sample Dataset")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

    # manual alert ingestion
    with ingest_tabs[2]:
        st.markdown("### Manual Alert Entry")
        st.caption("Enter a single alert directly for quick triage testing.")

        m1, m2 = st.columns(2)
        with m1:
            me_event  = st.selectbox("Event Type", ["SQL Injection", "Brute Force", "Malware", "Phishing", "Data Exfiltration", "Reconnaissance", "Ransomware", "Other"])
            me_src    = st.text_input("Source IP", value="185.220.101.34")
            me_dest   = st.text_input("Destination", value="web-prod-01")
        with m2:
            me_sev    = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
            me_msg    = st.text_area("Message / Description", value="Suspicious activity detected.", height=100)

        if st.button("▶️ Triage This Alert", type="primary"):
            manual_alert = {
                "timestamp":  datetime.now().isoformat(),
                "event_type": me_event,
                "source_ip":  me_src,
                "dest_ip":    me_dest,
                "severity":   me_sev,
                "message":    me_msg,
            }
            run_pipeline([manual_alert], source="Manual Entry")
            st.rerun()


# --- Tab 3: Report Generation and Export ---

with tabs[2]:
    st.title("Reports & Export")

    all_alerts_for_report = get_all_alerts()

    if not all_alerts_for_report:
        st.info("No alerts in the database yet. Ingest some data first.")
    else:
        rep_col1, rep_col2 = st.columns(2)

        with rep_col1:
            st.markdown("### 📄 Text Incident Report")
            st.caption("Formatted plain-text report for shift handovers, email briefings, and documentation.")
            rep_title = st.text_input("Report Title", value="SOC Incident Triage Report", key="txt_title")

            if st.button("📄 Generate Text Report"):
                report_text = generate_text_report(all_alerts_for_report, title=rep_title)
                path = save_text_report(report_text)
                log_report_generated(path, len(all_alerts_for_report))
                st.success(f"Report saved: {path}")
                st.download_button(
                    "⬇️ Download Report (.txt)",
                    data=report_text,
                    file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
                with st.expander("Preview Report"):
                    st.text(report_text[:3000] + ("..." if len(report_text) > 3000 else ""))

        with rep_col2:
            st.markdown("### 🔷 JSON Structured Report")
            st.caption("Machine-readable JSON for SIEM integration, ticketing systems, or management dashboards.")

            if st.button("🔷 Generate JSON Report"):
                report_data = generate_json_report(all_alerts_for_report, title=rep_title)
                json_str    = json.dumps(report_data, indent=2)
                path        = save_json_report(report_data)
                log_report_generated(path, len(all_alerts_for_report))
                st.success(f"Report saved: {path}")
                st.download_button(
                    "⬇️ Download Report (.json)",
                    data=json_str,
                    file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
                with st.expander("Preview JSON"):
                    st.json(report_data)

        st.markdown("---")
        st.markdown("### 📊 CSV Export")
        st.caption("Download all alert data as a spreadsheet.")
        csv_data = export_alerts_csv()
        st.download_button(
            "⬇️ Download All Alerts (.csv)",
            data=csv_data,
            file_name=f"soc_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

        st.markdown("---")
        st.markdown("### 🗂️ Previously Generated Reports")
        saved = list_saved_reports()
        if saved:
            report_df = pd.DataFrame(saved).rename(columns={
                "name": "Filename", "size_kb": "Size (KB)", "modified": "Generated At", "path": "Path"
            })
            st.dataframe(report_df[["Filename", "Size (KB)", "Generated At"]], use_container_width=True, hide_index=True)
        else:
            st.caption("No saved reports yet.")


# --- Tab 4: System Logs and Configuration ---

with tabs[3]:
    st.title("System Logs & Settings")

    log_col, settings_col = st.columns([3, 2])

    with log_col:
        st.markdown("### 📟 Audit Log (Last 50 entries)")
        st.caption("Every pipeline action is logged here for compliance and traceability.")
        logs = get_recent_logs(50)
        log_display = "\n".join(logs) if logs else "No log entries yet."
        st.markdown(f'<div class="log-line">{log_display}</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh Logs"):
            st.rerun()

    with settings_col:
        st.markdown("### ⚙️ Configuration")
        st.markdown("""
        **Database**
        """)
        stats = get_statistics()
        st.markdown(f"- Total records: `{stats['total']}`")
        st.markdown(f"- Avg risk score: `{stats['avg_risk_score']}/100`")
        st.markdown(f"- False positives: `{stats['false_positive_count']}`")

        st.markdown("---")
        st.markdown("**API Keys**")
        st.caption("Set these in the `.env` file in the project root directory.")

        openai_key = os.getenv("OPENAI_API_KEY", "")
        vt_key     = os.getenv("VT_API_KEY", "")

        st.markdown(f"- OpenAI: {'✅ Set' if openai_key.startswith('sk-') else '⚠️ Not set (using fallback)'}")
        st.markdown(f"- VirusTotal: {'✅ Set' if vt_key and not vt_key.startswith('YOUR_') else '⚠️ Not set (using mock)'}")

        st.markdown("---")
        st.markdown("**System Information**")
        st.markdown(f"- Platform: `Streamlit {st.__version__}`")
        st.markdown(f"- Python: `{os.sys.version.split()[0]}`")
        st.markdown(f"- Timestamp: `{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}`")

        st.markdown("---")
        st.markdown("**Danger Zone**")
        if st.button("🗑️ Clear Database & Logs", type="secondary"):
            clear_all_alerts()
            st.warning("Database cleared. Logs preserved.")
            st.rerun()
