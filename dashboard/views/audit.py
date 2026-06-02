import pandas as pd
from datetime import datetime

import streamlit as st




from dashboard.utils.ui_helpers import page_intro







def render(client):

    page_intro(

        "📝 Audit Center",

        "All discovery, IPS, and admin actions audit-logged in real time.",

        "A **tamper-evident activity log** for compliance and investigations. "

        "Each row is something a user or the system did (network scan, asset approval, etc.).",

    )



    logs = client.get_audit_logs(200)
    st.caption(f"Auto-refresh every 15s · loaded {datetime.now().strftime('%H:%M:%S')}")

    if not logs:

        st.info("No audit entries yet. Actions such as network discovery and asset approval will appear here.")

        return



    df = pd.DataFrame(logs)

    if "action_plain" in df.columns:

        display = df[["created_at", "action_plain", "action", "resource_id", "success"]].copy()

        display.columns = ["Time", "What happened", "Action code", "Resource", "OK"]

    else:

        display = df

    st.dataframe(display, use_container_width=True)

    st.caption(f"{len(logs)} audit records loaded from live database")


