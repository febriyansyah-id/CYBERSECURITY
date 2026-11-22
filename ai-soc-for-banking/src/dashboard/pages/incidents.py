import streamlit as st
import pandas as pd
from datetime import datetime

# Import playbook definitions from response module
from src.response.playbooks import get_playbook, PLAYBOOKS


def show() -> None:
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="color: #f8fafc; margin: 0;">🚨 Incident Response & SOAR Playbook Execution</h1>
            <p style="color: #94a3b8; margin: 4px 0 0 0;">
                NIST SP 800-61 Rev 2 Aligned IR Workflows & Automated SOAR Containment Orchestration
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    incidents_data = [
        {
            "id": "INC-2026-0042",
            "type": "malware",
            "title": "Cobalt Strike Beacon on Core-Banking Staging Host",
            "severity": "Critical",
            "status": "In Containment",
            "host": "srv-banking-app02.corp.local",
            "source_ip": "185.220.101.42",
            "mitre": "T1071 (Application Layer Protocol)",
            "opened": "2026-11-22 09:45:10",
        },
        {
            "id": "INC-2026-0043",
            "type": "phishing",
            "title": "Spear Phishing with Credential Harvester against Treasury Officers",
            "severity": "High",
            "status": "Analyzing",
            "host": "mail-gw-inbound.bank.local",
            "source_ip": "194.26.29.11",
            "mitre": "T1566.002 (Spearphishing Link)",
            "opened": "2026-11-22 09:58:32",
        },
        {
            "id": "INC-2026-0044",
            "type": "ransomware",
            "title": "Early Canary File Renaming Detected on ATM Management File Share",
            "severity": "Critical",
            "status": "Identified",
            "host": "nas-atm-mgmt.internal.net",
            "source_ip": "10.14.88.204",
            "mitre": "T1486 (Data Encrypted for Impact)",
            "opened": "2026-11-22 10:02:15",
        },
        {
            "id": "INC-2026-0045",
            "type": "data_breach",
            "title": "Unauthorized Batch PII Query from Customer Support Terminal",
            "severity": "High",
            "status": "Resolved",
            "host": "ws-cs-jkt04.corp.local",
            "source_ip": "10.20.12.19",
            "mitre": "T1530 (Data from Cloud/Local Storage)",
            "opened": "2026-11-22 08:30:00",
        },
    ]

    # Incident Selection
    col_sel, col_stat = st.columns([8, 4])
    with col_sel:
        selected_id = st.selectbox(
            "Select Incident to Manage:",
            options=[f"{i['id']} - [{i['severity'].upper()}] {i['title']}" for i in incidents_data],
        )
        selected_incident = next(i for i in incidents_data if i["id"] == selected_id.split(" - ")[0])

    with col_stat:
        st.markdown(
            f"""
            <div style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px; margin-top: 10px;">
                <span style="color: #94a3b8; font-size: 0.8rem;">INCIDENT STATUS</span><br>
                <b style="color: #38bdf8; font-size: 1.1rem;">{selected_incident['status']}</b> | 
                <span style="color: {'#ef4444' if selected_incident['severity'] == 'Critical' else '#f97316'}; font-weight: bold;">{selected_incident['severity']}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Incident Detail Card
    st.markdown(
        f"""
        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 16px; margin: 15px 0;">
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;">
                <div><span style="color: #64748b; font-size: 0.75rem;">AFFECTED HOST</span><br><b style="color: #f8fafc;">{selected_incident['host']}</b></div>
                <div><span style="color: #64748b; font-size: 0.75rem;">ATTACKER / SRC IP</span><br><b style="color: #ef4444;">{selected_incident['source_ip']}</b></div>
                <div><span style="color: #64748b; font-size: 0.75rem;">MITRE ATT&CK</span><br><b style="color: #38bdf8;">{selected_incident['mitre']}</b></div>
                <div><span style="color: #64748b; font-size: 0.75rem;">DETECTION TIME</span><br><b style="color: #f8fafc;">{selected_incident['opened']}</b></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1-Click SOAR Quick Actions
    st.subheader("⚡ 1-Click SOAR Automated Containment Actions")
    btn_c1, btn_c2, btn_c3, btn_c4 = st.columns(4)
    with btn_c1:
        if st.button("🚫 Firewall Block Attacker IP", use_container_width=True):
            st.success(f"✅ SOAR Action Executed: IP `{selected_incident['source_ip']}` blocked on Palo Alto perimeter firewalls (48h lease).")
    with btn_c2:
        if st.button("🔒 EDR Network Isolation", use_container_width=True):
            st.warning(f"⚠️ SOAR Action Executed: Endpoint `{selected_incident['host']}` isolated from local subnets. Forensic tunnel active.")
    with btn_c3:
        if st.button("🎫 Open TheHive / Jira Ticket", use_container_width=True):
            st.info(f"📋 SOAR Action Executed: Case #{selected_incident['id']} created on TheHive with severity `{selected_incident['severity']}`.")
    with btn_c4:
        if st.button("📢 OJK/BI Regulatory Dispatch", use_container_width=True):
            st.error(f"📡 Dispatch: Incident alert draft queued for POJK No. 11/POJK.03/2022 notification protocol.")

    st.markdown("---")

    # Interactive NIST Playbook Steps
    playbook = get_playbook(selected_incident["type"])
    if playbook:
        st.subheader(f"📖 NIST SP 800-61 Incident Playbook: {playbook.name}")
        st.caption(f"Playbook ID: {playbook.id} | Severity: {playbook.severity.upper()} | Estimated completion: {len(playbook.steps) * 20} mins")

        # Organize steps by phase
        phases = {}
        for s in playbook.steps:
            phases.setdefault(s.phase.capitalize(), []).append(s)

        for phase_name, steps in phases.items():
            with st.expander(f"Phase: {phase_name} ({len(steps)} actions required)", expanded=(phase_name in ["Identification", "Containment"])):
                for idx, step in enumerate(steps):
                    col_step_info, col_step_action = st.columns([9, 3])
                    with col_step_info:
                        st.markdown(f"**{idx + 1}. {step.description}**")
                        st.caption(f"Action: `{step.action}` | Assignee Role: **{step.assignee.upper()}**")
                    with col_step_action:
                        key = f"step_{selected_incident['id']}_{step.phase}_{idx}"
                        done = st.checkbox("Mark Completed", key=key)
                        if done:
                            st.caption("✅ Step Verified")
    else:
        st.info("No predefined automated playbook found for this incident type.")
