import streamlit as st

from dashboard.utils.theme import alert_card_html


def render(client):
    alerts = client.get_alerts(50)

    search = st.text_input("Search alerts", placeholder="Search by title, IP, description…")
    fc1, fc2, fc3 = st.columns([2, 2, 1])
    with fc1:
        sev_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low", "informational"],
            default=["critical", "high", "medium", "low", "informational"],
        )
    with fc2:
        status_filter = st.multiselect("Status", ["new", "acknowledged", "resolved", "in_progress"], default=["new", "acknowledged", "in_progress"])
    with fc3:
        st.write("")
        if st.button("↻ Refresh", use_container_width=True):
            st.rerun()

    filtered = alerts
    if search:
        q = search.lower()
        filtered = [
            a
            for a in filtered
            if q in (a.get("title") or "").lower()
            or q in (a.get("description") or "").lower()
            or q in (a.get("source_ip") or "").lower()
        ]
    filtered = [a for a in filtered if a.get("severity") in sev_filter]
    filtered = [a for a in filtered if (a.get("status") or "new") in status_filter]

    st.markdown(f"**Showing {len(filtered)} alerts**")
    critical = [a for a in filtered if a.get("severity") == "critical"]
    for a in critical[:3]:
        st.error(f"**{a.get('title')}** — immediate action")

    if not filtered:
        st.info("No alerts match filters. Run **Refresh live data** in the sidebar or wait for auto-collection.")
        return

    for alert in filtered[:25]:
        st.markdown(alert_card_html(alert), unsafe_allow_html=True)
        ac1, ac2, ac3 = st.columns(3)
        with ac1:
            st.button("Acknowledge", key=f"ack_{alert.get('id')}", disabled=True, help="Wire to API in production")
        with ac2:
            st.button("Resolve", key=f"res_{alert.get('id')}", disabled=True)
        with ac3:
            st.button("Create Incident", key=f"inc_{alert.get('id')}", disabled=True)
        st.markdown("<hr style='border-color:#1e293b;margin:8px 0;'>", unsafe_allow_html=True)
