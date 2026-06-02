"""
Sentinel-AI XDR - Enterprise SOC Dashboard
Real-time data from live system collectors.
"""
import importlib
import os
import sys
from datetime import datetime

import streamlit as st
try:
    from streamlit_autorefresh import st_autorefresh
except ModuleNotFoundError:
    def st_autorefresh(*args, **kwargs):
        """Fallback no-op when streamlit-autorefresh isn't installed."""
        return None

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# One global refresh (30s) — pages must not add their own st_autorefresh

from dashboard.config import API_BASE_URL
from dashboard.utils.api_client import APIClient
from dashboard.utils.auth_ui import render_login_page
from dashboard.utils.nav_config import GOVERNANCE, OPERATIONS, PAGE_TITLES

# Pentest page removed from sidebar
REMOVED_MODULES = frozenset({"pentest"})
from dashboard.utils.live_data import refresh_live_cache
from dashboard.utils.theme import brand_sidebar, inject_theme, nav_group_label, page_header, user_profile_card

st.set_page_config(
    page_title="Sentinel-AI XDR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_theme()
st_autorefresh(interval=30000, limit=None, key="global_refresh")

_api_url = st.session_state.get("api_base_url") or API_BASE_URL
if "api_client" not in st.session_state or st.session_state.api_client.base_url != _api_url.rstrip("/"):
    st.session_state.api_client = APIClient(_api_url)
client = st.session_state.api_client

if not render_login_page(client):
    st.stop()

try:
    nav, endpoint = refresh_live_cache(client)
except Exception as e:
    nav, endpoint = {}, {}
    st.sidebar.error(f"Data refresh: {e}")

eps = round(nav.get("events_last_hour", 0) / 3600.0, 1) if nav else 0.0
brand_sidebar(eps)

if st.session_state.get("nav_module") is None:
    st.session_state.nav_module = "executive"
if st.session_state.get("nav_module") in REMOVED_MODULES:
    st.session_state.nav_module = "executive"


def _badge_count(badge_key: str | None) -> int:
    if not badge_key or not nav:
        return 0
    return int(nav.get(badge_key) or 0)


def _nav_button(label: str, module: str, badge_key: str | None = None) -> None:
    count = _badge_count(badge_key)
    text = f"{label} ({count})" if count and module in ("alerts", "siem") else label
    if count and module == "topology":
        text = f"{label} ({count} online)"
    active = st.session_state.nav_module == module
    if st.sidebar.button(
        text,
        key=f"nav_btn_{module}",
        use_container_width=True,
        type="primary" if active else "secondary",
    ):
        st.session_state.nav_module = module
        st.rerun()


nav_group_label("OPERATIONS")
for label, module, badge_key in OPERATIONS:
    if module not in REMOVED_MODULES:
        _nav_button(label, module, badge_key)

nav_group_label("GOVERNANCE")
for label, module, badge_key in GOVERNANCE:
    if module not in REMOVED_MODULES:
        _nav_button(label, module, badge_key)


user = st.session_state.get("user", {})
user_profile_card(user.get("username", "Guest"), user.get("role", "SOC Analyst").replace("_", " ").title())

if st.sidebar.button("Logout", use_container_width=True):
    for k in list(st.session_state.keys()):
        if k in ("authenticated", "token", "user", "discovery_result", "nav_module"):
            del st.session_state[k]
    st.rerun()

if st.sidebar.button("↻ Refresh live data", use_container_width=True):
    with st.spinner("Collecting…"):
        result = client.trigger_collect()
        if result.get("stats"):
            st.sidebar.success("Updated")
        refresh_live_cache(client, force=True)
    st.rerun()

module = st.session_state.nav_module
if module in REMOVED_MODULES:
    module = "executive"
    st.session_state.nav_module = module
title = PAGE_TITLES.get(module, "Sentinel-AI XDR")
alert_badge = nav.get("alerts_total", 0) if module == "alerts" else 0

col_title, col_actions = st.columns([4, 1])
with col_title:
    page_header(title, alert_count=alert_badge)
with col_actions:
    updated = nav.get("updated_at", "")
    if updated:
        try:
            ts = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            updated = ts.strftime("%H:%M:%S")
        except ValueError:
            pass
    st.caption(f"Updated {updated or 'now'}")

_PAGE_MODULES = {
    "executive": "executive",
    "siem": "siem",
    "user_risk": "user_risk",
    "insider": "insider",
    "alerts": "alerts_page",
    "ids": "ids_page",
    "ips": "ips_page",
    "threat_intel": "threat_intel",
    "hunting": "hunting",
    "incidents": "incidents",
    "mitre": "mitre",
    "timeline": "timeline",
    "assets": "assets",
    "topology": "topology",
    "cloud": "cloud",
    "compliance": "compliance",
    "audit": "audit",
    "users": "users",
    "reports": "reports",
    "discovery": "discovery",
    "settings": "settings",
}

mod_name = _PAGE_MODULES.get(module, "executive")
mod = importlib.import_module(f"dashboard.views.{mod_name}")
mod.render(client)
