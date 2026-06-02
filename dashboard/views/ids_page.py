import pandas as pd
import streamlit as st
from datetime import datetime

from dashboard.utils.live_data import refresh_live_cache


def render(client):
    summary = client.get_ids_summary()
    ids_alerts = client.get_alerts(100, detection_engine="ids")
    if len(ids_alerts) < summary.get("total", 0):
        all_alerts = client.get_alerts(100)
        ids_alerts = [
            a for a in all_alerts
            if a.get("detection_engine") in ("ids", "scapy")
            or (a.get("source") in ("network", "endpoint") and "ML Anomaly" not in (a.get("title") or ""))
        ]
    total = summary.get("total", len(ids_alerts))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("IDS Alerts", total)
    by_sev = summary.get("by_severity", {})
    c2.metric("Critical", by_sev.get("critical", 0))
    c3.metric("High", by_sev.get("high", 0))
    c4.metric("Last alert", (summary.get("latest") or "—")[:19] if summary.get("latest") else "—")

    st.caption(f"Updates every 30s with background collector · {datetime.now().strftime('%H:%M:%S')}")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button("Run collection now", type="primary", use_container_width=True, key="ids_run_collection"):
            with st.spinner("Analyzing endpoint and connections…"):
                result = client.trigger_collect()
                refresh_live_cache(client, force=True)
            if result.get("error"):
                st.error(result["error"])
            else:
                st.success(f"Done: {result.get('stats', {})}")
                st.rerun()
    with col_b:
        if st.button("Start live packet capture", use_container_width=True, key="ids_start_capture"):
            client.start_capture()
            st.success("Capture started (admin/Npcap may be required on Windows)")
    with col_c:
        if st.button("Refresh view", use_container_width=True):
            refresh_live_cache(client, force=True)
            st.rerun()

    if ids_alerts:
        df = pd.DataFrame(ids_alerts)
        show_cols = [c for c in ["created_at", "title", "severity", "source_ip", "dest_ip", "mitre_technique"] if c in df.columns]
        st.subheader("Recent IDS alerts")
        st.dataframe(df[show_cols] if show_cols else df, use_container_width=True)
    else:
        st.info(
            "No IDS alerts yet. Click **Run analysis now** — detections are built from "
            "live CPU, memory, processes, and network connections (no Npcap required)."
        )

    packets = client.get_packets(30)
    if packets:
        st.subheader("Live packet buffer")
        st.dataframe(pd.DataFrame(packets), use_container_width=True)

    st.markdown(
        "**Detections:** Port Scan · SYN Flood · DNS Tunneling · Brute Force · "
        "ARP Spoofing · C2 · Beaconing · Suspicious Process · High CPU/Memory"
    )
