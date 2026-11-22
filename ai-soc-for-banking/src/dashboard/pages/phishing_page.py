import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from phishing_detector.src.classify import classify_url
from phishing_detector.src.features import extract_features


def show() -> None:
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="color: #f8fafc; margin: 0;">🎯 AI Phishing URL Inspector (ML Classifier)</h1>
            <p style="color: #94a3b8; margin: 4px 0 0 0;">
                Structural URL Heuristics & Content-Agnostic Random Forest Classification Model
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style="background: rgba(30, 41, 59, 0.5); border-left: 4px solid #38bdf8; padding: 12px 16px; border-radius: 4px; margin-bottom: 20px;">
            <span style="font-size: 0.9rem; color: #cbd5e1;">
                Unlike signature-based blocklists that fail on zero-day spear-phishing domains, this model evaluates <b>10 structural lexical indicators</b> directly from the URL string without downloading malicious payload.
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Preset Quick Test Buttons
    st.markdown("**⚡ Quick Test Presets:**")
    preset_cols = st.columns(4)
    preset_url = ""
    with preset_cols[0]:
        if st.button("🎣 Spoofed Bank Login", use_container_width=True):
            preset_url = "http://bank-secure-login.xyz/auth?client_id=98124"
    with preset_cols[1]:
        if st.button("🎣 Raw IP Credential Phish", use_container_width=True):
            preset_url = "http://192.168.1.1/login.php?verify=true"
    with preset_cols[2]:
        if st.button("🎣 Deep Subdomain Typosquat", use_container_width=True):
            preset_url = "http://verify-paypal.account-security.updates-center.com/action"
    with preset_cols[3]:
        if st.button("✅ Legitimate Bank Portal", use_container_width=True):
            preset_url = "https://www.bankmandiri.co.id/en/personal"

    # URL Input Field
    url_input = st.text_input(
        "Enter Target URL to Inspect:",
        value=preset_url if preset_url else "http://login.secure-bank.com.updates-alert.xyz/verify",
        placeholder="https://example.com/login",
    )

    if url_input:
        try:
            result = classify_url(url_input)
            features = extract_features(url_input)

            st.markdown("---")
            res_left, res_right = st.columns([5, 7])

            is_phish = result["prediction"] == "Phishing"
            confidence = result["confidence"]

            with res_left:
                st.subheader("Verdict & Risk Assessment")
                if is_phish:
                    st.markdown(
                        f"""
                        <div style="background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; border-radius: 12px; padding: 20px; text-align: center;">
                            <h2 style="color: #ef4444; margin: 0;">🚨 PHISHING DETECTED</h2>
                            <p style="color: #fca5a5; font-size: 1.1rem; margin-top: 8px;">Confidence: <b>{confidence:.1%}</b></p>
                            <p style="color: #cbd5e1; font-size: 0.85rem; margin-bottom: 0;">High malicious probability. Block on secure web gateways.</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"""
                        <div style="background: rgba(16, 185, 129, 0.15); border: 2px solid #10b981; border-radius: 12px; padding: 20px; text-align: center;">
                            <h2 style="color: #10b981; margin: 0;">✅ LEGITIMATE PATTERN</h2>
                            <p style="color: #6ee7b7; font-size: 1.1rem; margin-top: 8px;">Confidence: <b>{confidence:.1%}</b></p>
                            <p style="color: #cbd5e1; font-size: 0.85rem; margin-bottom: 0;">Conforms to standard enterprise domain heuristics.</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                # Gauge meter
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=confidence * 100 if is_phish else (1.0 - confidence) * 100,
                    title={"text": "Phishing Threat Index (0-100)"},
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": "#ef4444" if is_phish else "#10b981"},
                        "steps": [
                            {"range": [0, 40], "color": "rgba(16, 185, 129, 0.2)"},
                            {"range": [40, 75], "color": "rgba(245, 158, 11, 0.2)"},
                            {"range": [75, 100], "color": "rgba(239, 68, 68, 0.2)"},
                        ],
                    }
                ))
                fig_gauge.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#94a3b8"),
                    height=240,
                    margin=dict(l=20, r=20, t=30, b=10)
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

            with res_right:
                st.subheader("📊 Extracted Lexical Feature Vectors")
                
                df_feats = pd.DataFrame([
                    {"Feature": "URL Length", "Value": str(features["url_length"]), "Weight / Signal": "Long strings hide redirects (>75 is high)"},
                    {"Feature": "Dot Count", "Value": str(features["num_dots"]), "Weight / Signal": "Multiple subdomains (>3 is suspicious)"},
                    {"Feature": "Hyphen Count", "Value": str(features["num_hyphens"]), "Weight / Signal": "Brand typosquatting spoof"},
                    {"Feature": "Slash Count", "Value": str(features["num_slashes"]), "Weight / Signal": "Deep path obfuscation"},
                    {"Feature": "@ Presence", "Value": "YES" if features["num_at"] > 0 else "NO", "Weight / Signal": "Credential syntax injection"},
                    {"Feature": "HTTPS Enabled", "Value": "YES" if features["has_https"] == 1 else "NO", "Weight / Signal": "SSL validation status"},
                    {"Feature": "IP as Hostname", "Value": "YES" if features["has_ip"] == 1 else "NO", "Weight / Signal": "Direct IP connection indicator"},
                    {"Feature": "Subdomain Depth", "Value": str(features["num_subdomains"]), "Weight / Signal": "Hierarchy depth from root"},
                    {"Feature": "Special Characters", "Value": str(features["num_special_chars"]), "Weight / Signal": "#?&%= query string abuse"},
                ])

                st.dataframe(df_feats, use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Error analyzing URL: {e}")
