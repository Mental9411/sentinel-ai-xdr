"""SIEM Enterprise-style theme for Sentinel-AI XDR (Streamlit)."""
from datetime import datetime
from html import escape
from typing import Any, Dict, List, Optional

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
}

.stApp {
    background: #070b12;
    background-image:
        linear-gradient(rgba(0, 255, 157, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 157, 0.03) 1px, transparent 1px);
    background-size: 48px 48px;
}

.block-container { padding-top: 1.2rem; max-width: 1400px; }

div[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a0e16 0%, #0d121c 100%) !important;
    border-right: 1px solid #1a2332;
}

/* Hide Streamlit auto-discovered pages (e.g. pentest_page.py from an old pages/ folder) */
[data-testid="stSidebarNav"],
[data-testid="stSidebarNavItems"],
[data-testid="stSidebarNavLink"],
nav[data-testid="stSidebarNav"] {
    display: none !important;
    height: 0 !important;
    overflow: hidden !important;
    visibility: hidden !important;
}

div[data-testid="stSidebar"] .stRadio > label { display: none; }
div[data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
    gap: 4px;
}
div[data-testid="stSidebar"] .stRadio label[data-baseweb="radio"] {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 8px 12px;
    margin: 0;
    color: #94a3b8;
    font-size: 0.85rem;
    width: 100%;
}
div[data-testid="stSidebar"] .stRadio label[data-baseweb="radio"]:has(input:checked) {
    background: rgba(0, 255, 157, 0.08);
    border-color: rgba(0, 255, 157, 0.45);
    color: #00ff9d;
    box-shadow: inset 3px 0 0 #00ff9d;
}

.brand-block { padding: 0.5rem 0 1rem 0; }
.brand-title {
    font-size: 1.05rem; font-weight: 700; color: #f1f5f9;
    display: flex; align-items: center; gap: 8px;
}
.brand-sub { font-size: 0.65rem; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; }
.live-pill {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(0, 255, 157, 0.12); border: 1px solid rgba(0, 255, 157, 0.35);
    color: #00ff9d; padding: 4px 10px; border-radius: 20px;
    font-size: 0.72rem; font-weight: 600;
}
.live-pill .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #00ff9d; box-shadow: 0 0 8px #00ff9d;
    animation: pulse 1.5s infinite;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

.nav-group-label {
    font-size: 0.65rem; font-weight: 700; color: #475569;
    letter-spacing: 0.12em; margin: 1rem 0 0.35rem 0;
}

.soc-metric {
    background: #0f1419; border: 1px solid #1e293b; border-radius: 12px;
    padding: 16px 18px; min-height: 100px;
}
.soc-metric .label { color: #64748b; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; }
.soc-metric .value { font-size: 1.75rem; font-weight: 700; margin: 6px 0; }
.soc-metric .sub { color: #475569; font-size: 0.75rem; }

.page-title-row {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 1rem; flex-wrap: wrap; gap: 12px;
}
.page-title { font-size: 1.5rem; font-weight: 700; color: #f8fafc; margin: 0; }

.header-live {
    background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444;
    color: #fca5a5; padding: 4px 12px; border-radius: 6px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em;
}

.alert-card {
    background: #0f1419; border: 1px solid #1e293b; border-left: 4px solid #f97316;
    border-radius: 10px; padding: 14px 16px; margin-bottom: 10px;
}
.alert-card.critical { border-left-color: #ef4444; }
.alert-card.high { border-left-color: #f97316; }
.alert-card.medium { border-left-color: #eab308; }
.alert-card.low { border-left-color: #22c55e; }

.sev-pill {
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em;
}
.sev-critical { background: rgba(239,68,68,0.2); color: #f87171; }
.sev-high { background: rgba(249,115,22,0.2); color: #fb923c; }
.sev-medium { background: rgba(234,179,8,0.2); color: #facc15; }
.sev-low { background: rgba(34,197,94,0.2); color: #4ade80; }
.status-pill {
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-size: 0.65rem; font-weight: 600; background: rgba(139,92,246,0.2); color: #c4b5fd;
}

.user-card {
    background: #0f1419; border: 1px solid #1e293b; border-radius: 10px;
    padding: 10px 12px; margin-top: 1rem;
}
.user-card .name { color: #f1f5f9; font-weight: 600; font-size: 0.9rem; }
.user-card .role { color: #64748b; font-size: 0.75rem; }

div[data-testid="stMetric"] {
    background: #0f1419; border: 1px solid #1e293b; border-radius: 10px;
    padding: 12px;
}

/* Auth pages - hide sidebar, center layout */
.auth-mode section[data-testid="stSidebar"] { display: none !important; }
.auth-mode .block-container { max-width: 1100px; padding-top: 2rem; }
.auth-mode header[data-testid="stHeader"] { background: transparent; }

.auth-hero {
    background: linear-gradient(135deg, #0f1419 0%, #0a1628 100%);
    border: 1px solid #1e293b; border-radius: 16px;
    padding: 2.5rem 2rem; min-height: 420px;
}
.auth-hero h2 { color: #00ff9d; font-size: 1.75rem; margin: 0 0 0.5rem 0; }
.auth-hero p { color: #94a3b8; font-size: 0.9rem; line-height: 1.6; }
.auth-card {
    background: #0f1419; border: 1px solid #1e293b; border-radius: 16px;
    padding: 2rem 2rem 1.5rem 2rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}
.auth-card h3 { color: #f8fafc; font-size: 1.35rem; margin: 0 0 0.25rem 0; }
.auth-card .subtitle { color: #64748b; font-size: 0.85rem; margin-bottom: 1.25rem; }
.auth-switch { text-align: center; margin-top: 1rem; color: #64748b; font-size: 0.85rem; }
.auth-switch a { color: #00ff9d; font-weight: 600; text-decoration: none; }
</style>
"""

AUTH_MODE_CSS = """
<style>
section[data-testid="stSidebar"] { display: none !important; }
header[data-testid="stHeader"] { background: rgba(7,11,18,0.8) !important; }
</style>
"""


def inject_theme() -> None:
    import streamlit as st

    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def inject_auth_mode() -> None:
    import streamlit as st

    st.markdown(AUTH_MODE_CSS, unsafe_allow_html=True)


def brand_sidebar(eps: float = 0.0) -> None:
    import streamlit as st

    st.sidebar.markdown(
        f"""
        <div class="brand-block">
            <div class="brand-title">🛡️ Sentinel-AI XDR</div>
            <div class="brand-sub">Security Platform · v2.0</div>
            <div style="margin-top:10px;">
                <span class="live-pill"><span class="dot"></span> Live Monitoring · {eps:.1f} eps</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def nav_group_label(title: str) -> None:
    import streamlit as st

    st.sidebar.markdown(f'<p class="nav-group-label">{title}</p>', unsafe_allow_html=True)


def soc_metric_card(label: str, value: Any, subtitle: str = "", color: str = "#00ff9d") -> str:
    return f"""
    <div class="soc-metric">
        <div class="label">{escape(str(label))}</div>
        <div class="value" style="color:{color};">{escape(str(value))}</div>
        <div class="sub">{escape(str(subtitle))}</div>
    </div>
    """


def page_header(title: str, alert_count: int = 0, show_live: bool = True) -> None:
    import streamlit as st

    live_html = '<span class="header-live">● LIVE</span>' if show_live else ""
    badge = f'<span style="margin-left:8px;background:#ef4444;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.7rem;">{alert_count}</span>' if alert_count else ""
    st.markdown(
        f"""
        <div class="page-title-row">
            <h1 class="page-title">{escape(title)}{badge}</h1>
            <div>{live_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_pill(severity: str) -> str:
    sev = (severity or "medium").lower()
    return f'<span class="sev-pill sev-{sev}">{escape(sev.upper())}</span>'


def alert_card_html(alert: Dict[str, Any]) -> str:
    sev = (alert.get("severity") or "medium").lower()
    title = escape(alert.get("title") or "Alert")
    desc = escape((alert.get("description") or "")[:200])
    created = escape((alert.get("created_at") or "")[:19])
    status = escape((alert.get("status") or "new").upper())
    src = escape(alert.get("detection_engine") or alert.get("source") or "AUTO_DETECT")
    risk = alert.get("risk_score", 0)
    mitre = escape(alert.get("mitre_technique") or "—")
    return f"""
    <div class="alert-card {sev}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;">
            <div>
                <div style="color:#f1f5f9;font-weight:600;font-size:1rem;">🚨 {title}</div>
                <div style="color:#94a3b8;font-size:0.85rem;margin-top:6px;">{desc}</div>
                <div style="color:#64748b;font-size:0.75rem;margin-top:8px;">
                    🕐 {created} · {mitre} · {src} · Risk {risk}
                </div>
            </div>
            <div style="text-align:right;">
                {severity_pill(sev)}
                <div style="margin-top:6px;"><span class="status-pill">{status}</span></div>
            </div>
        </div>
    </div>
    """


def user_profile_card(username: str, role: str) -> None:
    import streamlit as st

    st.sidebar.markdown(
        f"""
        <div class="user-card">
            <div class="name">👤 {escape(username or "Guest")}</div>
            <div class="role">{escape(role or "SOC Analyst")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
