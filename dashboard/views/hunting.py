import pandas as pd

import streamlit as st



from dashboard.utils.ui_helpers import page_intro, severity_badge





def render(client):

    page_intro(

        "🎯 Threat Hunting Workspace",

        "Search live alerts using simple filters or keyword-style queries.",

        "**Threat hunting** means actively looking for attackers before they cause damage. "

        "Use plain filters below, or type keywords like `critical` or an IP address.",

    )



    alerts = client.get_alerts(300)

    col1, col2, col3 = st.columns(3)

    with col1:

        sev_filter = st.multiselect("Severity", ["critical", "high", "medium", "low"], default=["high", "critical"])

    with col2:

        status_filter = st.multiselect("Status", list({a.get("status") for a in alerts if a.get("status")}), default=[])

    with col3:

        query = st.text_input("Keywords (title, IP, MITRE)", "")



    filtered = alerts

    if sev_filter:

        filtered = [a for a in filtered if a.get("severity") in sev_filter]

    if status_filter:

        filtered = [a for a in filtered if a.get("status") in status_filter]

    if query:

        q = query.lower()

        filtered = [

            a for a in filtered

            if q in (a.get("title") or "").lower()

            or q in (a.get("source_ip") or "")

            or q in (a.get("mitre_technique") or "").lower()

            or q in (a.get("threat_category") or "").lower()

        ]



    st.metric("Matches", len(filtered), help="Alerts matching your hunt criteria")

    if filtered:

        df = pd.DataFrame(filtered)

        show_cols = [c for c in ["title", "severity", "status", "threat_category", "source_ip", "mitre_technique", "risk_score", "created_at"] if c in df.columns]

        st.dataframe(df[show_cols].head(50), use_container_width=True)

        with st.expander("Plain-language summary"):

            for a in filtered[:10]:

                st.write(f"**{severity_badge(a.get('severity', ''))}** — {a.get('title')} (risk {a.get('risk_score', 0):.0f})")

    else:

        st.info("No matches. Try broadening filters or run **Refresh live data now** in the sidebar.")


