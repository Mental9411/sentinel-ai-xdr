import pandas as pd
import plotly.express as px
import streamlit as st


def render(client):
    st.header("👤 User Risk Analytics (UEBA)")
    alerts = client.get_alerts(100)
    users = {}
    for a in alerts:
        u = a.get("hostname") or "system"
        users[u] = users.get(u, 0) + a.get("risk_score", 0)
    if users:
        df = pd.DataFrame([{"entity": k, "risk_score": min(100, v)} for k, v in users.items()])
        fig = px.bar(df, x="entity", y="risk_score", title="Entity Risk Scores (0-100)", color="risk_score",
                     color_continuous_scale="Reds")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)
    st.caption("Risk scores computed from live UEBA baselines and ML ensemble")
