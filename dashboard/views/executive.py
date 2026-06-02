"""Executive / SOC Dashboard — SIEM Enterprise layout."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.utils.theme import soc_metric_card


def render(client):
    nav = st.session_state.get("live_nav") or client.get_stats()
    endpoint = st.session_state.get("live_endpoint") or {}
    stats = nav

    alerts = client.get_alerts(50)
    connections = len(endpoint.get("network_connections", [])) if endpoint else 0
    events_today = stats.get("events_total", 0)
    eps = round(nav.get("events_last_hour", 0) / 3600.0, 1)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.markdown(soc_metric_card("Critical Alerts", stats.get("critical_alerts", 0), "Needs immediate action", "#ef4444"), unsafe_allow_html=True)
    c2.markdown(soc_metric_card("Open Alerts", stats.get("alerts_total", len(alerts)), "Active threats", "#f97316"), unsafe_allow_html=True)
    c3.markdown(soc_metric_card("Events Today", events_today, "From all sources", "#38bdf8"), unsafe_allow_html=True)
    c4.markdown(soc_metric_card("Events / Sec", f"{eps:.1f}", "Real-time ingestion", "#00ff9d"), unsafe_allow_html=True)
    c5.markdown(soc_metric_card("Live Connections", connections, "Active network sessions", "#eab308"), unsafe_allow_html=True)

    chart1, chart2 = st.columns([2, 1])
    with chart1:
        st.markdown("#### Event Timeline — Last 24h")
        events = client.get_events(50)
        if events:
            df = pd.DataFrame(events)
            if "timestamp" in df.columns:
                df["hour"] = pd.to_datetime(df["timestamp"]).dt.floor("h")
                hourly = df.groupby("hour").size().reset_index(name="count")
                fig = go.Figure()
                fig.add_trace(
                    go.Scatter(
                        x=hourly["hour"],
                        y=hourly["count"],
                        fill="tozeroy",
                        line=dict(color="#00ff9d", width=2),
                        fillcolor="rgba(0,255,157,0.15)",
                    )
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="#0f1419",
                    font_color="#94a3b8",
                    height=280,
                    margin=dict(l=20, r=20, t=30, b=20),
                    xaxis=dict(gridcolor="#1e293b"),
                    yaxis=dict(gridcolor="#1e293b"),
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.bar_chart(df["source"].value_counts() if "source" in df.columns else pd.Series())
        else:
            st.info("No events yet — data appears after the first collection cycle.")

    with chart2:
        st.markdown("#### Severity Split")
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            sev = a.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1
        if any(severity_counts.values()):
            fig = px.pie(
                names=list(severity_counts.keys()),
                values=list(severity_counts.values()),
                color=list(severity_counts.keys()),
                color_discrete_map={
                    "critical": "#ef4444",
                    "high": "#f97316",
                    "medium": "#eab308",
                    "low": "#22c55e",
                },
                hole=0.55,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#94a3b8",
                height=280,
                showlegend=True,
                legend=dict(orientation="h", y=-0.1),
            )
            st.plotly_chart(fig, use_container_width=True)

    if endpoint and endpoint.get("top_processes"):
        st.markdown("#### Live Event Feed")
        st.dataframe(pd.DataFrame(endpoint["top_processes"]).head(15), use_container_width=True, hide_index=True)
