"""Live Network Discovery - WiFi IP discovery (netdiscover-style)."""
import pandas as pd
import plotly.express as px
import streamlit as st


def render(client):
    st.header("📡 Live Network Discovery")
    st.caption("ARP-based discovery of devices on your authorized WiFi/Ethernet network — real IPs, no demo data")

    col1, col2 = st.columns([2, 1])
    with col1:
        try:
            subnet_info = client.get_local_subnet()
            detected_subnet = subnet_info.get("subnet", "Auto-detect")
            st.info(f"**Detected Subnet:** `{detected_subnet}` (from active network interface)")
        except Exception as e:
            detected_subnet = None
            st.warning(f"Could not detect subnet: {e}")

        custom_subnet = st.text_input("Override Subnet (CIDR)", value=detected_subnet or "192.168.1.0/24")
        scan_ports = st.checkbox("Scan open ports (authorized assets only)", value=True)

    with col2:
        st.markdown("### Compliance")
        st.markdown("""
        - Only scan networks you are authorized to monitor
        - Discovered assets require admin approval
        - All scans are audit-logged
        """)

    if st.button("🔍 Start Network Discovery", type="primary", use_container_width=True):
        with st.spinner("ARP scanning network (netdiscover-style)..."):
            try:
                result = client.discover_network(custom_subnet if custom_subnet else None)
                st.session_state["discovery_result"] = result
                st.success(f"Found **{result.get('device_count', 0)}** devices on `{result.get('subnet')}`")
            except Exception as e:
                st.error(f"Discovery failed: {e}")

    result = st.session_state.get("discovery_result")
    if result and result.get("devices"):
        devices = result["devices"]
        df = pd.DataFrame(devices)
        st.subheader(f"Discovered Devices ({len(devices)})")
        st.dataframe(df, use_container_width=True, hide_index=True)

        if "ip_address" in df.columns:
            fig = px.scatter(
                df, x="ip_address", y="device_type", color="vendor",
                size=[10] * len(df), title="Network Device Map",
                hover_data=["mac_address", "hostname"],
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("### IP Address Inventory")
        for d in devices:
            cols = st.columns([2, 2, 2, 1])
            cols[0].code(d.get("ip_address", "N/A"))
            cols[1].write(d.get("mac_address", "—"))
            cols[2].write(d.get("hostname") or d.get("vendor", "Unknown"))
            cols[3].caption(d.get("device_type", ""))

    stored = client.get_devices()
    if stored:
        st.subheader("Stored Network Devices (Database)")
        st.dataframe(pd.DataFrame(stored), use_container_width=True)
