import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Import GRC definitions
from sec_compliance.src.risk.assessment import calculate_score, risk_level


def show() -> None:
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="color: #f8fafc; margin: 0;">📋 Banking GRC & Risk Assessment Matrix</h1>
            <p style="color: #94a3b8; margin: 4px 0 0 0;">
                OJK Regulation (POJK No. 11/POJK.03/2022), ISO/IEC 27001:2022, NIST CSF 2.0 & PCI DSS v4.0
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_risk, tab_frameworks, tab_gaps = st.tabs(["🎯 Interactive 5x5 Risk Matrix", "📜 Regulatory Framework Coverage", "🔍 Gap Analysis"])

    with tab_risk:
        st.subheader("Dynamic 5x5 Likelihood × Impact Risk Calculator")
        st.caption("Calculate Inherent vs. Residual risk based on asset criticality, threat likelihood, and implemented control effectiveness.")

        col_in1, col_in2, col_in3 = st.columns(3)
        with col_in1:
            asset_choice = st.selectbox(
                "Select Banking Asset:",
                ["Core Banking System (CBS)", "Customer Financial Data (PII)", "ATM & E-Channel Switch", "SWIFT Payment Gateway", "Corporate Treasury Portal"]
            )
            likelihood = st.slider("Threat Likelihood (1 - Rare to 5 - Almost Certain)", 1, 5, 4)

        with col_in2:
            threat_choice = st.selectbox(
                "Select Threat Scenario:",
                ["Ransomware & Lateral Movement", "Internal Unauthorized PII Exfiltration", "DDoS on E-Banking API", "SWIFT Transaction Tampering", "Credential Stuffing & Takeover"]
            )
            impact = st.slider("Business Impact (1 - Negligible to 5 - Catastrophic)", 1, 5, 5)

        with col_in3:
            control_eff = st.slider("Implemented Control Effectiveness (%)", 0, 100, 60, step=5) / 100.0
            inherent, residual = calculate_score(likelihood, impact, control_effectiveness=control_eff)
            inh_lvl = risk_level(inherent)
            res_lvl = risk_level(residual)

            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 16px; margin-top: 5px;">
                    <span style="color: #94a3b8; font-size: 0.8rem;">INHERENT RISK</span><br>
                    <b style="color: {'#ef4444' if inherent >= 20 else '#f97316'}; font-size: 1.4rem;">{inherent:.1f} ({inh_lvl})</b>
                    <hr style="border-color: rgba(255,255,255,0.1); margin: 8px 0;">
                    <span style="color: #94a3b8; font-size: 0.8rem;">RESIDUAL RISK (After Controls)</span><br>
                    <b style="color: {'#10b981' if residual < 10 else '#eab308'}; font-size: 1.4rem;">{residual:.1f} ({res_lvl})</b>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # 5x5 Heatmap Matrix visualization
        st.markdown("#### 5x5 Risk Heatmap Matrix")
        # Build 5x5 matrix
        matrix_data = []
        for l in range(5, 0, -1):
            row = []
            for i in range(1, 6):
                row.append(l * i)
            matrix_data.append(row)

        fig_matrix = go.Figure(data=go.Heatmap(
            z=matrix_data,
            x=["1: Negligible", "2: Minor", "3: Moderate", "4: Major", "5: Critical"],
            y=["5: Frequent", "4: Likely", "3: Possible", "2: Unlikely", "1: Rare"],
            colorscale=[
                [0.0, "#10b981"],
                [0.3, "#84cc16"],
                [0.5, "#eab308"],
                [0.75, "#f97316"],
                [1.0, "#ef4444"],
            ],
            text=[[f"{val}" for val in row] for row in matrix_data],
            texttemplate="%{text}",
            showscale=False,
        ))

        # Add marker for current point
        fig_matrix.add_trace(go.Scatter(
            x=[impact - 1],
            y=[5 - likelihood],
            mode="markers+text",
            marker=dict(color="#ffffff", size=22, symbol="circle-dot", line=dict(color="#000", width=2)),
            text=["📍 Inherent Target"],
            textposition="top center",
            name="Current Inherent Position"
        ))

        fig_matrix.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8"),
            height=320,
            margin=dict(l=40, r=40, t=20, b=30),
            xaxis_title="Impact Scale",
            yaxis_title="Likelihood Scale"
        )
        st.plotly_chart(fig_matrix, use_container_width=True)

    with tab_frameworks:
        st.subheader("Framework Compliance Benchmarking")
        frameworks = [
            {"name": "POJK No. 11/POJK.03/2022 (Indonesian Banking IT Risk)", "score": 88, "status": "Compliant", "controls": "18/20", "desc": "Information Technology Risk Management for Commercial Banks"},
            {"name": "NIST Cybersecurity Framework 2.0", "score": 85, "status": "Substantially Compliant", "controls": "22/26", "desc": "Identify, Protect, Detect, Respond, Recover"},
            {"name": "ISO/IEC 27001:2022", "score": 82, "status": "Substantially Compliant", "controls": "20/24", "desc": "Annex A Organizational, People, Physical, and Technological Controls"},
            {"name": "PCI DSS v4.0 (Cardholder Data)", "score": 92, "status": "Certified", "controls": "18/20", "desc": "Payment Card Industry Data Security Standard"},
        ]

        for fw in frameworks:
            col_f_hdr, col_f_val = st.columns([8, 4])
            with col_f_hdr:
                st.markdown(f"**{fw['name']}**")
                st.caption(f"{fw['desc']} | Verified Controls: **{fw['controls']}**")
            with col_f_val:
                st.markdown(f"<span style='float: right; font-weight: bold; color: #38bdf8;'>{fw['score']}%</span>", unsafe_allow_html=True)
            st.progress(fw["score"] / 100.0)
            st.markdown("<br>", unsafe_allow_html=True)

    with tab_gaps:
        st.subheader("Actionable Compliance Gap Remediation")
        gaps_data = pd.DataFrame([
            {"Control ID": "POJK-5.1", "Framework": "POJK 11/2022", "Title": "Third-Party Vendor Risk Oversight", "Remediation Action": "Implement continuous cloud vendor posture assessment", "Priority": "High", "Deadline": "2026-12-15"},
            {"Control ID": "ISO-A.8.12", "Framework": "ISO 27001:2022", "Title": "Data Leakage Prevention (DLP)", "Remediation Action": "Deploy endpoint DLP on remote branch workstations", "Priority": "Medium", "Deadline": "2027-01-30"},
            {"Control ID": "NIST-RS-2", "Framework": "NIST CSF 2.0", "Title": "Incident Response Communications", "Remediation Action": "Automate crisis communication channel to BSSN / BI", "Priority": "High", "Deadline": "2026-12-31"},
            {"Control ID": "PCI-11.2", "Framework": "PCI DSS v4.0", "Title": "Internal Network Vulnerability Scans", "Remediation Action": "Schedule weekly automated authenticated scans for cardholder enclaves", "Priority": "Medium", "Deadline": "2027-02-15"},
        ])
        st.dataframe(gaps_data, use_container_width=True, hide_index=True)
