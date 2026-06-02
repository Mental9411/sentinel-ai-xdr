import pandas as pd
import plotly.express as px
import streamlit as st


def render(client):
    st.header("📅 Attack Timeline")
    alerts = client.get_alerts(100)
    if alerts:
        df = pd.DataFrame(alerts)
        if "created_at" in df.columns:
            fig = px.scatter(df, x="created_at", y="severity", color="threat_category", hover_data=["title"])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
