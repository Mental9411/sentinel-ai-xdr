import pandas as pd

import streamlit as st




from dashboard.utils.ui_helpers import page_intro







def render(client):

    page_intro(

        "💻 Asset Inventory",

        "Discovered network devices from ARP-based live discovery.",

        "Every row is a **real device** found on your network — IP, name, vendor, and online status. "

        "Approve assets in discovery workflow before full monitoring.",

    )



    devices = client.get_devices()

    stats = client.get_stats()

    c1, c2 = st.columns(2)

    c1.metric("Total devices", len(devices))

    c2.metric("Online", stats.get("devices_online", sum(1 for d in devices if d.get("is_online"))))

    if devices:

        df = pd.DataFrame(devices)

        df["plain_status"] = df["is_online"].map({True: "Online", False: "Offline"})

        cols = ["ip_address", "hostname", "vendor", "device_type", "plain_status", "last_seen"]

        show = [c for c in cols if c in df.columns]

        st.dataframe(df[show], use_container_width=True)

    else:

        st.info("No assets yet. Use **Live Network Discovery** to scan your authorized subnet.")


