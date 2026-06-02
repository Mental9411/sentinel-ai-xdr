import plotly.express as px
import pandas as pd
import streamlit as st


def render(client):
    st.header("⚔️ MITRE ATT&CK Dashboard")
    alerts = client.get_alerts(100)
    techniques = {}
    for a in alerts:
        t = a.get("mitre_technique") or "Unknown"
        techniques[t] = techniques.get(t, 0) + 1
    if techniques:
        df = pd.DataFrame(list(techniques.items()), columns=["Technique", "Count"])
        fig = px.treemap(df, path=["Technique"], values="Count", title="ATT&CK Technique Coverage")
        st.plotly_chart(fig, use_container_width=True)
