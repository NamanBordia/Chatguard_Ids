from __future__ import annotations

import streamlit as st

st.set_page_config(page_title="ChatGuard IDS", page_icon=":shield:", layout="wide")

st.title("ChatGuard IDS - Streamlit Control Panel")
st.caption("Use the left sidebar to open Server Dashboard or Client Chat page.")

st.markdown(
    """
### What this app provides
- A dedicated server operations page (start/stop, users, stats, logs)
- A dedicated encrypted client chat page
- AES-GCM encrypted transport for all chat/auth payloads

### Run
1. streamlit run streamlit_app.py
2. Open Server Dashboard page and start server
3. Open Client Chat page (same browser tab is fine)
"""
)
