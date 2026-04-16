from __future__ import annotations

import streamlit as st

from ui.chat_runtime import ServerRuntime

st.set_page_config(page_title="Server Dashboard", page_icon=":desktop_computer:", layout="wide")

if "server_runtime" not in st.session_state:
    st.session_state.server_runtime = ServerRuntime()

runtime: ServerRuntime = st.session_state.server_runtime

st.title("Server Dashboard")
st.caption("Manage server lifecycle, users, online sessions, and IDS logs.")

with st.sidebar:
    st.subheader("Server Control")
    host = st.text_input("Host", value=runtime.host)
    port = st.number_input("Port", min_value=1024, max_value=65535, value=runtime.port, step=1)

    c1, c2 = st.columns(2)
    if c1.button("Start", use_container_width=True):
        ok, msg = runtime.start(host, int(port))
        (st.success if ok else st.error)(msg)

    if c2.button("Stop", use_container_width=True):
        ok, msg = runtime.stop()
        (st.success if ok else st.warning)(msg)

    st.markdown(f"**Status:** {'Running' if runtime.is_running else 'Stopped'}")

left, right = st.columns([1.2, 1.8])

with left:
    st.subheader("Live Stats")
    online = runtime.online_users()
    risk = runtime.risk_scores()
    pending = runtime.pending_approvals()

    m1, m2, m3 = st.columns(3)
    m1.metric("Online Users", len(online))
    m2.metric("Risk Entries", len(risk))
    m3.metric("Pending Approvals", len(pending))

    st.markdown("#### Online Users")
    if online:
        st.write(online)
    else:
        st.info("No users are online.")

    st.markdown("#### Risk Scores")
    if risk:
        st.json(risk)
    else:
        st.info("No risk scores available yet.")

    st.markdown("#### Pending Approvals")
    if pending:
        st.dataframe(pending, use_container_width=True)
    else:
        st.info("No pending approval requests.")

with right:
    st.subheader("User Operations")

    tab_add, tab_passwd, tab_delete, tab_list, tab_logs = st.tabs(
        ["Add User", "Change Password", "Delete User", "DB Users", "Logs"]
    )

    with tab_add:
        with st.form("add_user_form", clear_on_submit=True):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            r = st.selectbox("Role", ["user", "admin"])
            submitted = st.form_submit_button("Create User")
            if submitted:
                ok, msg = runtime.add_user(u, p, r)
                (st.success if ok else st.error)(msg)

    with tab_passwd:
        with st.form("passwd_form", clear_on_submit=True):
            u = st.text_input("Username", key="passwd_u")
            p = st.text_input("New Password", type="password")
            submitted = st.form_submit_button("Update Password")
            if submitted:
                ok, msg = runtime.change_password(u, p)
                (st.success if ok else st.error)(msg)

    with tab_delete:
        with st.form("delete_form", clear_on_submit=True):
            u = st.text_input("Username", key="delete_u")
            submitted = st.form_submit_button("Delete User")
            if submitted:
                ok, msg = runtime.remove_user(u)
                (st.success if ok else st.error)(msg)

    with tab_list:
        users = runtime.list_db_users()
        if users:
            st.dataframe(users, use_container_width=True)
        else:
            st.info("No users found in database.")

    with tab_logs:
        lines = st.slider("Log lines", min_value=10, max_value=300, value=50, step=10)
        logs = runtime.tail_logs(lines)
        if logs:
            st.code("\n".join(logs), language="text")
        else:
            st.info("No logs available.")

st.button("Refresh", use_container_width=True)
