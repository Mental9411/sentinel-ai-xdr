import streamlit as st
from datetime import datetime

import networkx as nx


try:
    from pyvis.network import Network

    PYVIS = True
except ImportError:
    PYVIS = False

TOPOLOGY_GUIDE = {
    "star": "⭐ **Star** — Router/gateway at center; phones, PCs, and IoT connect as spokes (most home/office WiFi).",
    "flat_lan": "🔗 **Flat LAN** — All devices on one switch/VLAN segment; no central hub identified in scan.",
    "single_host": "🖥️ **Single host** — Only one device seen; run discovery on a larger subnet or check firewall.",
    "extended_lan": "🏢 **Extended LAN** — Large Layer-2 segment with many endpoints (campus, data center access layer).",
    "empty": "📡 **Empty** — Run discovery to classify your network and build the map.",
}


def render(client):
    topo = client.get_topology()
    st.caption(f"Auto-refresh every 20s · {datetime.now().strftime('%H:%M:%S')}")

    topo_type = topo.get("topology_type", "empty")
    type_label = topo.get("topology_type_label", "Unknown")

    st.markdown(f"**Detected type:** `{type_label}`")
    if topo_type in TOPOLOGY_GUIDE:
        st.markdown(TOPOLOGY_GUIDE[topo_type])
    if topo.get("topology_description"):
        st.caption(topo["topology_description"])

    if not topo.get("nodes"):
        st.info("No devices discovered yet. Use the button below or **Live Network Discovery** in the sidebar.")
        if st.button("Run network discovery now", type="primary"):
            try:
                with st.spinner("Scanning network…"):
                    result = client.discover_network()
                st.success(f"Found {result.get('device_count', 0)} devices — topology will appear on refresh.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        subnet = topo.get("subnet")
        if subnet:
            st.caption(f"Detected subnet on this machine: **{subnet}**")

        with st.expander("What topology types does Sentinel detect?"):
            st.markdown(
                """
| Type | When it applies |
|------|-----------------|
| **Star (Hub-and-Spoke)** | Router/gateway found; other devices hang off it |
| **Flat LAN** | 2–7 devices, no clear gateway in scan |
| **Extended LAN** | 8+ devices on one segment |
| **Single Host** | Only one IP discovered |
| **Empty** | No scan run yet |

Run discovery on your real subnet (e.g. `192.168.1.0/24`) to populate the graph.
                """
            )
        return

    st.subheader("Topology identity")
    st.markdown(f"### {topo.get('topology_name', 'Network')}")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Type", type_label)
    c2.metric("Devices", topo.get("node_count", 0))
    c3.metric("Connections", topo.get("edge_count", 0))
    c4.metric("Online", topo.get("devices_online", 0))
    gw = topo.get("gateway_ip")
    c5.metric("Gateway / hub", gw or "—")

    if topo.get("subnet"):
        st.caption(f"Subnet: `{topo['subnet']}`")

    G = nx.Graph()
    for node in topo.get("nodes", []):
        nid = node.get("id") or node.get("ip")
        label = node.get("label") or nid
        role = node.get("role", "endpoint")
        title = f"{label}\n{node.get('ip')}\n{node.get('vendor') or ''}\nRole: {role}"
        G.add_node(nid, label=label, title=title, group=role)

    for edge in topo.get("edges", []):
        G.add_edge(edge.get("source"), edge.get("target"))

    st.subheader("Topology graph")
    if PYVIS and G.number_of_nodes() > 0:
        net = Network(height="520px", bgcolor="#1a1a2e", font_color="white", notebook=False)
        net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=120)
        net.from_nx(G)
        gateway_ids = {n["id"] for n in topo.get("nodes", []) if n.get("role") == "gateway"}
        for node in net.nodes:
            if node.get("id") in gateway_ids:
                node["color"] = "#00d4ff"
                node["size"] = 28
        html = net.generate_html()
        st.components.v1.html(html, height=540, scrolling=True)
    else:
        st.write(f"Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")

    with st.expander("Device list (technical detail)"):
        import pandas as pd

        st.dataframe(pd.DataFrame(topo.get("nodes", [])), use_container_width=True)
