"""Settings & Configuration — SIEM-style control panel."""
import streamlit as st

from dashboard.config import API_BASE_URL
from dashboard.utils.theme import soc_metric_card


def render(client):
    ips = client.get_ips_status()
    cloud = client.get_cloud_status()
    endpoint = client.get_endpoint_live()

    tab_platform, tab_detection, tab_cloud = st.tabs(["Platform", "Detection & IPS", "Cloud APIs"])

    with tab_platform:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### API connection")
            st.text_input("API base URL", value=API_BASE_URL, disabled=True)
            try:
                health = client.health()
                st.success(f"API status: **{health.get('status', 'unknown')}** · DB: {health.get('database', '—')}")
            except Exception as e:
                st.error(f"API unreachable: {e}")
        with c2:
            st.markdown("#### Collection")
            if st.button("Run live collection now", type="primary"):
                result = client.trigger_collect()
                st.success(str(result.get("stats", result)))
            st.caption("Background collector runs every **30 seconds** on the API.")

        if endpoint:
            st.markdown("#### Live system")
            ec1, ec2, ec3, ec4 = st.columns(4)
            ec1.markdown(soc_metric_card("CPU", f"{endpoint.get('cpu_percent', 0):.1f}%", endpoint.get("hostname", ""), "#00ff9d"), unsafe_allow_html=True)
            ec2.markdown(soc_metric_card("Memory", f"{endpoint.get('memory_percent', 0):.1f}%", "RAM usage", "#f472b6"), unsafe_allow_html=True)
            disk = endpoint.get("disk_percent")
            ec3.markdown(soc_metric_card("Disk", f"{disk:.1f}%" if disk is not None else "—", "Storage", "#eab308"), unsafe_allow_html=True)
            ec4.markdown(soc_metric_card("Connections", len(endpoint.get("network_connections", [])), "Active sessions", "#38bdf8"), unsafe_allow_html=True)
            st.caption(f"Host: {endpoint.get('hostname')} · {str(endpoint.get('platform', ''))[:80]}")

    with tab_detection:
        st.markdown("#### IDS / IPS mode")
        st.write(f"**Current mode:** `{ips.get('mode', 'monitor')}`")
        st.write(f"**Block approval required:** `{ips.get('require_approval', True)}`")
        new_mode = st.selectbox("Change mode", ["monitor", "prevention"], index=0 if ips.get("mode") == "monitor" else 1)
        if st.button("Apply IPS mode"):
            try:
                client.set_ips_mode(new_mode)
                st.success(f"Mode set to {new_mode}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        st.markdown("#### Detection rules (IDS engine)")
        rules = [
            ("Port Scan", "high", "15+ ports / 60s", "T1046"),
            ("SYN Flood", "high", "100+ SYN / 10s", "T1498"),
            ("DNS Tunneling", "high", "Long DNS queries", "T1071.004"),
            ("Brute Force", "high", "10+ failures / 5m", "T1110"),
            ("ARP Spoofing", "critical", "Duplicate MAC", "T1557.002"),
            ("Beaconing", "high", "Regular C2 intervals", "T1071"),
            ("Data Exfiltration", "critical", "Large outbound volume", "T1048"),
            ("C2 Traffic", "critical", "Known C2 patterns", "T1071"),
        ]
        import pandas as pd

        st.dataframe(
            pd.DataFrame(rules, columns=["Rule", "Severity", "Condition", "MITRE"]),
            use_container_width=True,
            hide_index=True,
        )

    with tab_cloud:
        st.markdown("#### Cloud credential status")
        cc1, cc2, cc3 = st.columns(3)
        cc1.metric("AWS", "Connected" if cloud.get("aws_configured") else "Not configured")
        cc2.metric("Azure", "Connected" if cloud.get("azure_configured") else "Not configured")
        cc3.metric("M365", "Coming soon")
        st.code(
            "# Add to .env\nAWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\nAZURE_TENANT_ID=\nAZURE_CLIENT_ID=\nAZURE_CLIENT_SECRET=",
            language="bash",
        )
        st.info("Restart the API after editing `.env` for cloud keys to take effect.")

    st.markdown("---")
    st.caption(f"Dashboard refresh interval: 12s global · User: {st.session_state.get('user', {}).get('email', '—')}")
