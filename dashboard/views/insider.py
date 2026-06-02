import streamlit as st




from dashboard.utils.ui_helpers import page_intro, severity_badge, severity_help





INSIDER_CATEGORIES = {

    "data_exfiltration": "Data Exfiltration",

    "credential_misuse": "Credential Misuse",

    "privilege_escalation": "Privilege Escalation",

    "unauthorized_access": "Unauthorized Access",

    "lateral_movement": "Lateral Movement",

}





def render(client):

    page_intro(

        "🔍 Insider Threat Center",

        "UEBA-style monitoring for risky user behavior from live alert stream.",

        "Tracks **threats that may come from inside your organization** — stolen credentials, "

        "unusual downloads, or access to systems someone should not use. Counts come from real alerts.",

    )



    alerts = client.get_alerts(200)

    insider = [

        a for a in alerts

        if a.get("is_insider_threat")

        or "insider" in (a.get("threat_category") or "").lower()

        or (a.get("threat_category") or "") in INSIDER_CATEGORIES

    ]

    st.metric("Insider-related alerts", len(insider), help="From live alert database")



    threats = [

        ("Data Exfiltration", "data_exfiltration", "Unusual outbound data transfers"),

        ("USB Abuse", "usb", "Removable media policy violations"),

        ("Credential Misuse", "credential_misuse", "Logins or tokens used abnormally"),

        ("Privilege Escalation", "privilege_escalation", "Attempts to gain higher access"),

        ("Unauthorized Access", "unauthorized_access", "Access to restricted resources"),

        ("Excessive Downloads", "excessive_downloads", "Higher than normal file retrieval"),

        ("Lateral Movement", "lateral_movement", "Moving between systems inside the network"),

        ("Shadow IT", "shadow_it", "Unapproved apps or cloud services"),

    ]



    for label, key, help_text in threats:

        count = sum(1 for a in insider if key in (a.get("threat_category") or "").lower())

        st.checkbox(f"{label} ({count} alerts)", value=count > 0, disabled=True, help=help_text)



    if insider:

        st.subheader("Recent insider-related alerts")

        for a in insider[:15]:

            sev = a.get("severity", "")

            st.markdown(

                f"- **{severity_badge(sev)}** {a.get('title')} — {severity_help(sev)}"

            )

    else:

        st.success("No insider-threat alerts in the live feed right now.")


