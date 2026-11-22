import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random


def show() -> None:
    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <div>
                <h1 style="color: #f8fafc; margin: 0;">🛡️ Banking SOC Telemetry & Overview</h1>
                <p style="color: #94a3b8; margin: 4px 0 0 0;">
                    Real-time monitoring across Core Banking, SWIFT Gateway, ATM Switch, and Cloud Edge
                </p>
            </div>
            <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); padding: 8px 16px; border-radius: 8px;">
                <span style="color: #38bdf8; font-weight: 600;">Environment: PRODUCTION-BANK-JKT</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Key Performance Indicators
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Events (24h)", "1,482,910", "+12.4% vs avg")
    with c2:
        st.metric("Active Incidents", "3 Open", "-2 contained")
    with c3:
        st.metric("Mean Time to Detect (MTTD)", "3.8 min", "-1.2 min (SLA: <15m)")
    with c4:
        st.metric("Mean Time to Respond (MTTR)", "18.4 min", "-6.1 min (SLA: <45m)")

    st.markdown("---")

    # Interactive Visualizations
    col_left, col_right = st.columns([7, 5])

    with col_left:
        st.subheader("📈 Ingestion Volume & Threat Anomaly Spikes")
        # Generate 24 hours of simulated time series
        now = datetime.now()
        timestamps = [now - timedelta(hours=23 - i) for i in range(24)]
        hours_str = [t.strftime("%H:00") for t in timestamps]
        
        normal_events = [random.randint(45000, 72000) for _ in range(24)]
        threat_spikes = [random.randint(10, 80) for _ in range(24)]
        # Add an anomalous spike at hour 14
        threat_spikes[14] = 420
        threat_spikes[15] = 310

        df_telemetry = pd.DataFrame({
            "Time": hours_str,
            "Total Ingested": normal_events,
            "Threat Events": threat_spikes,
        })

        fig_timeline = go.Figure()
        fig_timeline.add_trace(go.Scatter(
            x=df_telemetry["Time"],
            y=df_telemetry["Total Ingested"],
            name="Normal Logs",
            mode="lines+markers",
            line=dict(color="#38bdf8", width=2),
            fill="tozeroy",
            fillcolor="rgba(56, 189, 248, 0.1)"
        ))
        fig_timeline.add_trace(go.Bar(
            x=df_telemetry["Time"],
            y=df_telemetry["Threat Events"],
            name="Security Alerts",
            marker=dict(color="#ef4444"),
            yaxis="y2"
        ))
        fig_timeline.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15, 23, 42, 0.6)",
            font=dict(color="#94a3b8"),
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            yaxis=dict(title="Event Count", gridcolor="rgba(255,255,255,0.05)"),
            yaxis2=dict(title="Alerts", overlaying="y", side="right", showgrid=False)
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    with col_right:
        st.subheader("🎯 Threat Tactics (MITRE ATT&CK)")
        tactic_counts = {
            "Initial Access (T1566)": 24,
            "Credential Access (T1003)": 48,
            "Defense Evasion (T1059)": 18,
            "Command & Control (T1071)": 12,
            "Discovery (T1046)": 38,
            "Exfiltration (T1048)": 7,
        }
        df_tactics = pd.DataFrame(list(tactic_counts.items()), columns=["Tactic", "Count"])
        fig_tactics = px.pie(
            df_tactics,
            names="Tactic",
            values="Count",
            hole=0.45,
            color_discrete_sequence=["#38bdf8", "#f59e0b", "#ef4444", "#8b5cf6", "#10b981", "#ec4899"]
        )
        fig_tactics.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8"),
            margin=dict(l=10, r=10, t=20, b=20),
            legend=dict(orientation="v", yanchor="middle", y=0.5, font=dict(size=10))
        )
        st.plotly_chart(fig_tactics, use_container_width=True)

    st.markdown("---")

    # Real-Time Normalized Event Log Stream
    st.subheader("📋 Real-Time Normalized SIEM Event Stream")
    
    col_f1, col_f2, col_f3 = st.columns([3, 2, 2])
    with col_f1:
        search_query = st.text_input("🔍 Search Logs by IP, Host, or Action", placeholder="e.g. 192.168.1.50 or BRUTE_FORCE")
    with col_f2:
        filter_sev = st.multiselect("Filter Severity", ["critical", "high", "medium", "low"], default=["critical", "high"])
    with col_f3:
        filter_source = st.selectbox("Log Source", ["All Sources", "Core-Banking-GW", "SWIFT-Interface", "VPN-Perimeter", "WAF-Cloud"])

    sample_logs = [
        {"timestamp": "2026-11-22 10:14:22", "severity": "critical", "source": "VPN-Perimeter", "source_ip": "185.220.101.42", "dest_ip": "10.10.1.5", "event_type": "credential_access", "message": "Multiple failed logins followed by abnormal session escalation"},
        {"timestamp": "2026-11-22 10:13:05", "severity": "high", "source": "Core-Banking-GW", "source_ip": "10.20.4.112", "dest_ip": "10.10.1.100", "event_type": "anomaly", "message": "High-value batch transaction deviation: Z-score=4.2 > threshold"},
        {"timestamp": "2026-11-22 10:11:48", "severity": "high", "source": "WAF-Cloud", "source_ip": "45.33.32.156", "dest_ip": "10.0.0.80", "event_type": "reconnaissance", "message": "Rapid sequential port sweep across internal subnet ports (T1046)"},
        {"timestamp": "2026-11-22 10:08:12", "severity": "critical", "source": "SWIFT-Interface", "source_ip": "192.168.10.15", "dest_ip": "198.51.100.22", "event_type": "c2_beacon", "message": "Periodic SSL beaconing to untrusted external ASN detected (T1071)"},
        {"timestamp": "2026-11-22 10:05:30", "severity": "medium", "source": "WAF-Cloud", "source_ip": "103.25.12.8", "dest_ip": "10.0.0.443", "event_type": "authentication", "message": "Invalid API token credential presentation on e-channel gateway"},
        {"timestamp": "2026-11-22 09:58:19", "severity": "low", "source": "VPN-Perimeter", "source_ip": "10.10.5.21", "dest_ip": "10.10.0.1", "event_type": "connection", "message": "Standard internal employee TLS session initialized"},
    ]

    df_logs = pd.DataFrame(sample_logs)

    # Filter logic
    if filter_sev:
        df_logs = df_logs[df_logs["severity"].isin(filter_sev)]
    if filter_source != "All Sources":
        df_logs = df_logs[df_logs["source"] == filter_source]
    if search_query:
        mask = df_logs.apply(lambda row: search_query.lower() in row.to_string().lower(), axis=1)
        df_logs = df_logs[mask]

    st.dataframe(
        df_logs,
        column_config={
            "timestamp": st.column_config.TextColumn("Timestamp"),
            "severity": st.column_config.TextColumn("Severity"),
            "source": st.column_config.TextColumn("Component"),
            "source_ip": st.column_config.TextColumn("Source IP"),
            "dest_ip": st.column_config.TextColumn("Target IP"),
            "event_type": st.column_config.TextColumn("Detection Rule"),
            "message": st.column_config.TextColumn("Technical Telemetry Message", width="large"),
        },
        use_container_width=True,
        hide_index=True,
    )
