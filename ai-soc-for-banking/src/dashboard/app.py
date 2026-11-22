import sys
import os
from pathlib import Path

# Add paths to sys.path so modules from all subprojects can be imported
current_dir = Path(__file__).resolve().parent
ai_soc_root = current_dir.parent.parent
repo_root = ai_soc_root.parent

for p in [str(ai_soc_root), str(repo_root)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import streamlit as st

PAGE_NAMES = {
    "overview": "🛡️ SOC Overview & Telemetry",
    "incidents": "🚨 Incident Response & SOAR",
    "phishing": "🎯 AI Phishing URL Inspector",
    "compliance": "📋 Banking GRC & Risk Matrix",
    "settings": "⚙️ Detection Rules & Threat Intel",
}

CUSTOM_CSS = """
<style>
    /* Dark Cybersecurity Theme */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .metric-card {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(8px);
        margin-bottom: 12px;
    }
    .metric-title {
        font-size: 0.85rem;
        color: #94a3b8;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
        margin-top: 4px;
    }
    .metric-delta {
        font-size: 0.8rem;
        margin-top: 4px;
    }
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-high {
        background-color: #f97316;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-medium {
        background-color: #eab308;
        color: black;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-low {
        background-color: #10b981;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    /* Streamlit overrides */
    div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700;
    }
    .stSidebar {
        background-color: #0f172a !important;
        border-right: 1px solid rgba(56, 189, 248, 0.15);
    }
</style>
"""


def main() -> None:
    st.set_page_config(
        page_title="AI-SOC Command Center | Banking Cybersecurity",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    # Sidebar Header & Branding
    st.sidebar.markdown(
        """
        <div style="padding: 10px 0;">
            <h2 style="color: #38bdf8; margin: 0; font-size: 1.4rem;">🏛️ AI-SOC COMMAND</h2>
            <p style="color: #94a3b8; font-size: 0.8rem; margin: 2px 0 10px 0;">
                Tier-1/2/3 Security Operations & GRC
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("---")

    # Live SOC Metrics in Sidebar
    st.sidebar.markdown("**⚡ Live Telemetry Status**")
    col_sb1, col_sb2 = st.sidebar.columns(2)
    col_sb1.metric("Events / sec", "420", "+14%")
    col_sb2.metric("Threat Level", "ELEVATED")

    st.sidebar.markdown(
        """
        <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 8px; padding: 10px; margin: 10px 0;">
            <span style="color: #10b981; font-weight: 600; font-size: 0.85rem;">● DEFENSES ACTIVE</span><br>
            <span style="color: #94a3b8; font-size: 0.75rem;">POJK 11/2022 & NIST CSF Aligned</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("---")

    # Navigation
    page = st.sidebar.radio("Navigation", list(PAGE_NAMES.values()))

    st.sidebar.markdown("---")
    st.sidebar.caption("Bank Security Operations Platform v2.4")
    st.sidebar.caption("© 2026 Febriyansyah | MTI Cybersecurity")

    # Page Dispatcher
    if page == PAGE_NAMES["overview"]:
        from src.dashboard.pages.overview import show
        show()
    elif page == PAGE_NAMES["incidents"]:
        from src.dashboard.pages.incidents import show
        show()
    elif page == PAGE_NAMES["phishing"]:
        from src.dashboard.pages.phishing_page import show
        show()
    elif page == PAGE_NAMES["compliance"]:
        from src.dashboard.pages.compliance import show
        show()
    elif page == PAGE_NAMES["settings"]:
        from src.dashboard.pages.settings import show
        show()


if __name__ == "__main__":
    main()
