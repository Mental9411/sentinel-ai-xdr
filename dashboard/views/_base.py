"""Shared dashboard utilities."""
import pandas as pd
import plotly.express as px
import streamlit as st


def alerts_table(alerts, title="Alerts"):
    st.subheader(title)
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.info("No data yet — real-time collectors will populate this view.")
