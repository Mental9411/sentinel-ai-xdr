import streamlit as st
from datetime import datetime


def render(client):
    status = client.get_ips_status()
    current = status.get("mode", "monitor")
    require_approval = status.get("require_approval", True)

    if require_approval:
        st.warning("Prevention mode requires administrator approval for all block actions")

    st.caption(f"Live status · {datetime.now().strftime('%H:%M:%S')}")

    mode = st.selectbox("IDS/IPS Mode", ["monitor", "prevention"], index=0 if current == "monitor" else 1)
    st.write(f"Current mode: **{current}**")

    if mode != current:
        if st.button("Apply mode change"):
            try:
                result = client.set_ips_mode(mode)
                st.success(result.get("message", f"Mode set to {mode}"))
                st.rerun()
            except Exception as e:
                st.error(str(e))

    pending = status.get("pending", [])
    if status.get("pending_block_requests", 0) > 0:
        st.subheader(f"Pending block requests ({status['pending_block_requests']})")
        for req in pending:
            st.write(f"- `{req.get('source_ip') or 'any'}` — {req.get('reason')} ({req.get('status')})")

    block_ip = st.text_input("Source IP to block (optional)")
    if st.button("Request Block Action (Requires Approval)"):
        try:
            result = client.request_ips_block(
                source_ip=block_ip.strip() or None,
                reason="IPS dashboard block request",
            )
            st.info(result.get("message", "Request submitted"))
            st.rerun()
        except Exception as e:
            st.error(str(e))
