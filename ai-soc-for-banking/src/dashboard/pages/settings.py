import streamlit as st
import pandas as pd

# Import Sigma rules and IOC manager from soc-automation
from soc_automation.src.detection.sigma_rules import get_sigma_rules
from soc_automation.src.detection.ioc import get_sample_iocs


def show() -> None:
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="color: #f8fafc; margin: 0;">⚙️ Detection Rules & Threat Intelligence</h1>
            <p style="color: #94a3b8; margin: 4px 0 0 0;">
                MITRE ATT&CK Sigma Signatures, Indicator of Compromise (IOC) Feeds & SOAR Channels
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_sigma, tab_ioc, tab_soar = st.tabs(["🛡️ Sigma Detection Rules", "🔍 IOC Threat Intel Lookup", "📡 SOAR Channels & Tuning"])

    with tab_sigma:
        st.subheader("Active Sigma Detection Signatures")
        st.caption("Standardized cross-SIEM threat detection rules tagged with MITRE ATT&CK technique IDs.")

        sigma_rules = get_sigma_rules()
        rule_rows = []
        for r in sigma_rules:
            rule_rows.append({
                "Rule ID": r.id,
                "Signature Title": r.title,
                "Log Category": r.logsource.get("category", "any"),
                "Severity": r.level.upper(),
                "MITRE Tags": ", ".join(r.tags) if r.tags else "-",
                "Status": "ACTIVE",
            })

        df_sigma = pd.DataFrame(rule_rows)
        st.dataframe(df_sigma, use_container_width=True, hide_index=True)

        selected_rule_id = st.selectbox("Inspect Rule Definition:", [r.id for r in sigma_rules])
        selected_rule = next(r for r in sigma_rules if r.id == selected_rule_id)

        with st.expander(f"Inspect YAML / Logic for `{selected_rule.id}`: {selected_rule.title}", expanded=True):
            st.json({
                "title": selected_rule.title,
                "description": selected_rule.description,
                "logsource": selected_rule.logsource,
                "detection": selected_rule.detection,
                "level": selected_rule.level,
                "tags": selected_rule.tags,
            })

    with tab_ioc:
        st.subheader("Indicator of Compromise (IOC) Database")
        ioc_mgr = get_sample_iocs()
        all_iocs = ioc_mgr.list_all()

        ioc_rows = []
        for i in all_iocs:
            ioc_rows.append({
                "Observable Value": i.value,
                "Type": i.type.upper(),
                "Feed Source": i.source,
                "Confidence": i.confidence.upper(),
                "Tags": ", ".join(i.tags),
            })
        st.dataframe(pd.DataFrame(ioc_rows), use_container_width=True, hide_index=True)

        st.markdown("#### Live Observable Enrichment")
        test_val = st.text_input("Enter IP, Hash, or Domain to Query:", value="185.220.101.42")
        if test_val:
            found = ioc_mgr.search_ioc(test_val)
            if found:
                enriched = ioc_mgr.enrich(found)
                st.success(f"IOC Match Found! Reputation Score: **{enriched['reputation_score']}/100** (Confidence: {found.confidence.upper()})")
                st.json(enriched)
            else:
                st.info(f"Observable `{test_val}` not currently in local cache. External threat feed query queued.")

    with tab_soar:
        st.subheader("SOAR Connectors & Notification Endpoints")
        c1, c2 = st.columns(2)
        with c1:
            st.text_input("TheHive 5 API Endpoint", value="https://thehive.corp.bank.local:9000")
            st.text_input("Palo Alto Firewall API URL", value="https://panw-fw-cluster.bank.local/api")
            st.text_input("CrowdStrike Falcon FalconPy CID", value="******-DEFENSE-PROD")
        with c2:
            st.text_input("Slack / Microsoft Teams Webhook", value="https://hooks.slack.com/services/T00/B00/XXXXX")
            st.slider("Auto-Containment Severity Threshold", 1, 10, 8, help="Incidents scoring >= this threshold trigger automated firewall blocking.")
            st.checkbox("Enable Automated OJK CSIRT Escalation", value=True)
