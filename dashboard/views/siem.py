"""SIEM Dashboard — live events from API."""
import pandas as pd
import streamlit as st


def render(client):
    st.header("SIEM Dashboard")
    events = client.get_events(100)
    alerts = client.get_alerts(100)
    st.metric("Ingested events", len(events))
    st.metric("Correlated alerts", len(alerts))
    if events:
        st.subheader("Live security events")
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
    if alerts:
        st.subheader("Alerts")
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    if not events and not alerts:
        st.info("Click **Refresh live data now** in the sidebar to ingest real endpoint telemetry.")
