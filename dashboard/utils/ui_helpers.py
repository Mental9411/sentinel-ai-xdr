"""Plain-language labels and severity styling for tech and non-tech users."""
from typing import Any, Dict, Optional

SEVERITY_PLAIN = {
    "critical": ("Critical", "Immediate action required — serious threat detected."),
    "high": ("High", "Important — investigate soon."),
    "medium": ("Medium", "Review when possible."),
    "low": ("Low", "Informational — low priority."),
    "informational": ("Info", "For awareness only."),
}

RISK_COLORS = {
    "High": "#ff5252",
    "Medium": "#ffb74d",
    "Low": "#69f0ae",
}


def severity_badge(severity: str) -> str:
    label, _ = SEVERITY_PLAIN.get((severity or "").lower(), (severity, ""))
    return label


def severity_help(severity: str) -> str:
    _, help_text = SEVERITY_PLAIN.get((severity or "").lower(), ("", ""))
    return help_text


def metric_card_html(label: str, value: Any, subtitle: str = "", color: str = "#00d4ff") -> str:
    return f"""
    <div style="background:#1a1a2e;border:1px solid #2d2d44;border-radius:8px;padding:12px 16px;margin:4px 0;">
        <div style="color:#8a8d91;font-size:0.75rem;">{label}</div>
        <div style="color:{color};font-size:1.5rem;font-weight:700;">{value}</div>
        <div style="color:#6a6d71;font-size:0.7rem;">{subtitle}</div>
    </div>
    """


def page_intro(title: str, technical: str, plain: str) -> None:
    import streamlit as st

    st.header(title)
    with st.expander("What does this mean? (for everyone)", expanded=False):
        st.markdown(plain)
    st.caption(technical)
