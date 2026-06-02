import json
import streamlit as st


def render(client):
    st.header("📄 Report Generation Center")
    fmt = st.selectbox("Format", ["PDF", "Excel", "CSV", "JSON"])
    if st.button("Generate Executive Report"):
        alerts = client.get_alerts(100)
        report = {
            "title": "Sentinel-AI XDR Executive Summary",
            "total_alerts": len(alerts),
            "critical": sum(1 for a in alerts if a.get("severity") == "critical"),
            "alerts": alerts[:50],
        }
        if fmt == "JSON":
            st.download_button("Download JSON", json.dumps(report, indent=2), "sentinel_report.json")
        else:
            st.info(f"{fmt} export — use API /api/v1/reports endpoint in production")
