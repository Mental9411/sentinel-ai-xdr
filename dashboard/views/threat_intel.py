import streamlit as st




from dashboard.utils.ui_helpers import RISK_COLORS, page_intro, severity_badge







def render(client):

    page_intro(

        "🧠 Threat Intelligence Center",

        "IOC enrichment from threat feeds plus correlation with your live alerts and events.",

        "Look up suspicious **IPs, websites, or file fingerprints**. "

        "We check external threat databases (when configured) **and** your own security alerts "

        "so you see both global reputation and whether this indicator already appeared in your environment.",

    )



    summary = client.get_threat_intel_summary()

    if summary:

        s1, s2, s3 = st.columns(3)

        s1.metric("Alerts in environment", summary.get("total_alerts", 0))

        s2.metric("High-risk items", summary.get("high_risk_count", 0))

        s3.metric("Unique threat IPs", summary.get("unique_threat_ips", 0))



        recent = summary.get("recent_high_risk", [])

        if recent:

            st.subheader("Recent high-risk activity (plain language)")

            for item in recent:

                st.markdown(f"- **{item.get('plain_summary', item.get('title'))}** — IP: `{item.get('source_ip') or 'n/a'}`")



    st.divider()

    st.subheader("IOC lookup")

    col1, col2 = st.columns([3, 1])

    with col1:

        ioc = st.text_input("Indicator (IP, domain, or hash)", placeholder="e.g. 8.8.8.8 or evil.example.com")

    with col2:

        ioc_type = st.selectbox("Type (auto-detect if blank)", ["", "ip", "domain", "hash_sha256"])



    if st.button("Enrich IOC", type="primary") and ioc:

        with st.spinner("Checking threat feeds and your live data..."):

            result = client.enrich_ioc(ioc.strip(), ioc_type or None)

        if result.get("error"):

            st.error(result["error"])

            return



        risk = result.get("risk_level", "Low")

        color = RISK_COLORS.get(risk, "#00d4ff")

        st.markdown(

            f'<div style="background:#1a1a2e;border-left:4px solid {color};padding:16px;border-radius:8px;">'

            f'<h3 style="color:{color};margin:0;">{risk} risk</h3>'

            f'<p style="color:#ccc;">{result.get("risk_level_plain", "")}</p></div>',

            unsafe_allow_html=True,

        )



        st.metric("Reputation score", f"{result.get('reputation_score', 0):.2f}", help="0 = safe, 1 = dangerous")



        internal = result.get("internal", {})

        st.markdown(f"**Verdict:** {internal.get('verdict', 'unknown').title()}")

        st.info(internal.get("verdict_plain", ""))



        if result.get("external_sources"):

            st.success(f"External feeds consulted: {', '.join(result['external_sources'])}")

        else:

            st.caption("Add AbuseIPDB, OTX, VirusTotal, or GreyNoise API keys in `.env` for global enrichment. Internal correlation still applies.")



        if result.get("tags"):

            st.write("**Tags:**", ", ".join(result["tags"][:15]))



        related = internal.get("related_alerts", [])

        if related:

            st.subheader("Matching alerts in your environment")

            for a in related:

                sev = severity_badge(a.get("severity", ""))

                st.markdown(f"- [{sev}] **{a.get('title')}** — risk {a.get('risk_score', 0):.0f}")

        else:

            st.success("No matching alerts in your environment for this indicator.")



        with st.expander("Technical enrichment JSON"):

            st.json(result)



    st.markdown("---")

    st.caption("**Integrated feeds (when configured):** MISP · AlienVault OTX · AbuseIPDB · VirusTotal · GreyNoise")


