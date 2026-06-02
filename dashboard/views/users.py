import streamlit as st


def render(client):
    st.header("👥 User Management")
    user = st.session_state.get("user", {})
    role = user.get("role", "")
    if role not in ("super_admin", "soc_manager"):
        st.warning("Admin or SOC Manager role required")
        return
    st.subheader("Invite New User")
    email = st.text_input("Email")
    inv_role = st.selectbox("Role", ["security_analyst", "threat_hunter", "incident_responder", "auditor", "read_only"])
    if st.button("Send Invitation"):
        try:
            inv = client.invite_user(email, inv_role)
            st.success(f"Invitation created! Share token: `{inv.get('id', 'check API')}`")
        except Exception as e:
            st.error(str(e))
    st.subheader("Create User (Admin)")
    with st.form("create_user"):
        c_email = st.text_input("Email", key="cu_email")
        c_user = st.text_input("Username", key="cu_user")
        c_pass = st.text_input("Password", type="password", key="cu_pass")
        c_role = st.selectbox("Role", ["security_analyst", "soc_manager", "threat_hunter"])
        if st.form_submit_button("Create"):
            try:
                client.create_user({"email": c_email, "username": c_user, "password": c_pass, "role": c_role})
                st.success("User created")
            except Exception as e:
                st.error(str(e))
