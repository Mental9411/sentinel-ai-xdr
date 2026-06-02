"""Cached live API data — fewer calls, faster Streamlit reruns."""
import time
from typing import Any, Dict, Tuple

import streamlit as st

from dashboard.utils.api_client import APIClient

NAV_TTL_SEC = 25
ENDPOINT_TTL_SEC = 90


def refresh_live_cache(client: APIClient, force: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Return (nav_summary, endpoint_snapshot) from session cache when fresh.
    Endpoint is expensive (~1s+ on API) — fetched less often than nav.
    """
    now = time.time()
    nav = st.session_state.get("live_nav") or {}
    endpoint = st.session_state.get("live_endpoint") or {}
    nav_at = st.session_state.get("live_nav_at", 0.0)
    ep_at = st.session_state.get("live_endpoint_at", 0.0)

    need_nav = force or (now - nav_at) > NAV_TTL_SEC
    need_ep = force or (now - ep_at) > ENDPOINT_TTL_SEC

    if need_nav:
        try:
            nav = client.get_nav_summary() or {}
            st.session_state.live_nav = nav
            st.session_state.live_nav_at = now
        except Exception:
            pass

    if need_ep:
        try:
            endpoint = client.get_endpoint_live() or {}
            st.session_state.live_endpoint = endpoint
            st.session_state.live_endpoint_at = now
        except Exception:
            pass

    return st.session_state.get("live_nav") or {}, st.session_state.get("live_endpoint") or {}
