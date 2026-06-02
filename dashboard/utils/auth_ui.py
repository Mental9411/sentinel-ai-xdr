"""Dedicated Login and Sign Up pages for Sentinel-AI XDR."""
import streamlit as st

from dashboard.config import API_BASE_URL
from dashboard.utils.api_client import APIClient
from dashboard.utils.api_health import discover_api_url, probe_api
from dashboard.utils.theme import inject_auth_mode


def check_api_online(client: APIClient) -> tuple[bool, str]:
    ok, msg, _ = probe_api(client.base_url)
    if ok:
        return True, msg
    if client.reconnect():
        ok2, msg2, _ = probe_api(client.base_url)
        if ok2:
            st.session_state["api_base_url"] = client.base_url
            return True, msg2
    return False, msg


def _complete_login(client: APIClient, email: str, password: str) -> None:
    result = client.login(email.strip(), password)
    if result.get("mfa_required"):
        st.warning("MFA is enabled - contact your administrator.")
        return
    if result.get("access_token"):
        st.session_state["token"] = result["access_token"]
        st.session_state["authenticated"] = True
        client.token = result["access_token"]
        st.session_state["user"] = client.get_me()
        st.session_state["api_base_url"] = client.base_url
        st.session_state.pop("auth_page", None)
        st.rerun()


def _auth_brand_column() -> None:
    st.markdown(
        """
        <div class="auth-hero">
            <h2>Sentinel-AI XDR</h2>
            <p style="color:#64748b;font-size:0.7rem;letter-spacing:0.12em;text-transform:uppercase;">
                Security Platform v2.0
            </p>
            <p style="margin-top:1.5rem;">
                Enterprise <strong style="color:#00ff9d;">XDR</strong>,
                <strong style="color:#00ff9d;">SIEM</strong>, and
                <strong style="color:#00ff9d;">UEBA</strong> in one SOC console.
            </p>
            <ul style="color:#94a3b8;font-size:0.85rem;line-height:1.9;margin-top:1rem;">
                <li>Real-time alerts &amp; IDS/IPS</li>
                <li>Network topology discovery</li>
                <li>Threat hunting &amp; compliance</li>
                <li>Cloud security monitoring</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_api_gate(client: APIClient) -> bool:
    api_url = st.session_state.get("api_base_url") or client.base_url or API_BASE_URL
    client.base_url = api_url.rstrip("/")

    online, status_msg = check_api_online(client)
    if online:
        return True

    st.error("Cannot reach the API backend.")
    st.markdown(
        """
Run from the project folder:

```powershell
cd E:\\pp\\s\\Sen\\sentinel-ai-xdr
.\\scripts\\run_local.ps1
```

Wait for **Application startup complete** in the API window, then click **Retry**.
        """
    )
    with st.expander("Diagnostics"):
        _, detail = discover_api_url()
        st.code(detail or status_msg)
    if st.button("Retry API connection", type="primary", use_container_width=True):
        url, msg = discover_api_url()
        if url:
            st.session_state["api_base_url"] = url
            client.base_url = url
            st.success(f"Connected: {url}")
            st.rerun()
        else:
            st.warning("API still offline.")
    return False


def render_login_screen(client: APIClient) -> None:
    st.markdown(
        """
        <div class="auth-card">
            <h3>Sign in</h3>
            <p class="subtitle">Access your security operations dashboard</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Email address", placeholder="you@company.com", key="login_email")
        password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password")
        remember = st.checkbox("Keep me signed in on this device", value=True)
        submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

        if submitted:
            em = (email or "").strip()
            pw = password or ""
            if "@" not in em:
                st.error("Enter a valid email address.")
            elif not pw:
                st.error("Enter your password.")
            else:
                try:
                    _complete_login(client, em, pw)
                except Exception as e:
                    st.error(f"Sign in failed: {e}")

    if remember:
        st.caption("Session uses a secure JWT from the API.")


def render_signup_screen(client: APIClient) -> None:
    st.markdown(
        """
        <div class="auth-card">
            <h3>Create account</h3>
            <p class="subtitle">Register for Sentinel-AI XDR SOC access</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("signup_form", clear_on_submit=False):
        full_name = st.text_input("Full name", placeholder="Jane Analyst")
        email = st.text_input("Work email", placeholder="you@company.com")
        username = st.text_input("Username", placeholder="janalyst")
        password = st.text_input("Password", type="password", placeholder="Min. 12 characters")
        password2 = st.text_input("Confirm password", type="password", placeholder="Repeat password")
        agree = st.checkbox("I agree to authorized use of this security monitoring platform")
        submitted = st.form_submit_button("Create Account", use_container_width=True, type="primary")

        if submitted:
            em = (email or "").strip()
            user = (username or "").strip()
            if not agree:
                st.error("Please confirm authorized use.")
            elif "@" not in em:
                st.error("Enter a valid email.")
            elif len(user) < 3:
                st.error("Username must be at least 3 characters.")
            elif not password or len(password) < 12:
                st.error("Password must be at least 12 characters.")
            elif password != password2:
                st.error("Passwords do not match.")
            else:
                try:
                    client.register({
                        "email": em,
                        "username": user,
                        "password": password,
                        "full_name": full_name.strip() if full_name else None,
                    })
                    st.session_state["auth_page"] = "login"
                    st.session_state["signup_success_email"] = em
                    st.rerun()
                except Exception as e:
                    st.error(f"Registration failed: {e}")

    st.caption("Default roles are assigned by your administrator after registration.")


def render_login_page(client: APIClient) -> bool:
    """Full auth flow: login page or signup page. Returns True when authenticated."""
    if st.session_state.get("authenticated"):
        return True

    inject_auth_mode()

    if st.session_state.get("auth_page") not in ("login", "signup"):
        st.session_state.auth_page = "login"

    left, right = st.columns([1, 1], gap="large")

    with left:
        _auth_brand_column()

    with right:
        if not _render_api_gate(client):
            return False

        nav_login, nav_signup = st.columns(2)
        page = st.session_state.auth_page
        with nav_login:
            if st.button("Sign In", use_container_width=True, type="primary" if page == "login" else "secondary"):
                st.session_state.auth_page = "login"
                st.rerun()
        with nav_signup:
            if st.button("Sign Up", use_container_width=True, type="primary" if page == "signup" else "secondary"):
                st.session_state.auth_page = "signup"
                st.rerun()

        st.markdown("---")

        if page == "signup":
            render_signup_screen(client)
        else:
            if em := st.session_state.pop("signup_success_email", None):
                st.success(f"Account created for **{em}**. Sign in with your new credentials.")
            render_login_screen(client)

    return False


def require_auth() -> bool:
    return bool(st.session_state.get("authenticated"))
