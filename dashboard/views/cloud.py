import streamlit as st
from datetime import datetime



def render(client):
    cloud = client.get_cloud_status()
    stats = client.get_stats()
    endpoint = client.get_endpoint_live()
    devices = client.get_devices()

    st.caption(
        f"Auto-refresh · stats at {stats.get('updated_at', '—')[:19]} · "
        f"local time {datetime.now().strftime('%H:%M:%S')}"
    )

    tabs = st.tabs(["On-prem (live now)", "AWS", "Azure", "M365"])
    with tabs[0]:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Security events", stats.get("events_total", 0))
        c2.metric("Alerts", stats.get("alerts_total", 0))
        c3.metric("Network devices", stats.get("devices_total", len(devices)))
        c4.metric("Host CPU", f"{endpoint.get('cpu_percent', 0)}%" if endpoint else "—")
        if endpoint:
            st.write(f"**Monitoring host:** {endpoint.get('hostname')} — {endpoint.get('platform', '')[:80]}")
        if devices:
            import pandas as pd

            st.dataframe(pd.DataFrame(devices).head(30), use_container_width=True)
        else:
            st.info("Run **Live Network Discovery** to populate device inventory.")

        if st.button("Refresh live telemetry now"):
            result = client.trigger_collect()
            if result.get("error"):
                st.error(result["error"])
            else:
                st.success("Collection cycle completed")
                st.rerun()

    providers = [
        ("AWS", "aws_configured", "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION"),
        ("Azure", "azure_configured", "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET"),
        ("M365", "m365_configured", "M365 integration (coming soon)"),
    ]
    for tab, (name, key, env_hint) in zip(tabs[1:], providers):
        with tab:
            configured = cloud.get(key, False)
            if configured:
                st.success(f"{name} credentials detected — live ingestion can be enabled.")
                st.caption("CloudTrail · GuardDuty · Activity Logs · Defender (collector wiring)")
            else:
                st.info(f"Connect {name} API credentials in `.env` for live {name} ingestion.")
                st.code(env_hint, language="bash")
            st.caption(f"Status checked at {cloud.get('updated_at', '—')[:19]}")
