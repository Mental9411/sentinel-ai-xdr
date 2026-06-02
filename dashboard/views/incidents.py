import streamlit as st


def render(client):
    st.header("📋 Incident Response Center")
    st.button("Create Incident")
    alerts = [a for a in client.get_alerts(20) if a.get("status") != "resolved"]
    for a in alerts:
        with st.expander(a.get("title", "Alert")):
            st.write(a)
