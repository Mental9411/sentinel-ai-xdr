import streamlit as st




from dashboard.utils.ui_helpers import page_intro







def render(client):

    page_intro(

        "✅ Compliance Dashboard",

        "Framework scores computed from live alerts, audit logs, and asset coverage.",

        "Shows how well your security program aligns with common standards (SOC 2, ISO 27001, etc.). "

        "Scores **change as real alerts are resolved**, audits are logged, and devices are approved — not fixed demo numbers.",

    )



    frameworks = client.get_compliance()

    if not frameworks:

        st.warning("Could not load compliance metrics. Check API connection.")

        return



    for fw in frameworks:

        pct = fw.get("score_percent", 0) / 100.0

        status = fw.get("status", "")

        st.progress(pct, text=f"{fw.get('framework')} — {status} ({fw.get('score_percent')}%)")

        st.caption(fw.get("status_plain", fw.get("description", "")))

        metrics = fw.get("metrics", {})

        if metrics:

            with st.expander(f"How {fw.get('framework')} score is calculated"):

                st.write(

                    f"Alerts: {metrics.get('alerts_total', 0)} total, "

                    f"{metrics.get('alerts_resolved', 0)} resolved · "

                    f"Audit events: {metrics.get('audit_events', 0)} · "

                    f"Devices: {metrics.get('devices_discovered', 0)} · "

                    f"Approved assets: {metrics.get('assets_approved', 0)}"

                )


