from __future__ import annotations

import html
import socket

import streamlit as st

from ui.chat_runtime import SecureSocketClient, ServerRuntime

st.set_page_config(page_title="Client Chat", page_icon=":speech_balloon:", layout="wide")

if "chat_client" not in st.session_state:
    st.session_state.chat_client = SecureSocketClient()
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []
if "pending_requests" not in st.session_state:
    st.session_state.pending_requests = []
if "chat_username" not in st.session_state:
    st.session_state.chat_username = ""
if "server_runtime" not in st.session_state:
    st.session_state.server_runtime = ServerRuntime()

client: SecureSocketClient = st.session_state.chat_client
messages: list[dict] = st.session_state.chat_messages
pending_requests: list[dict] = st.session_state.pending_requests
server_runtime: ServerRuntime = st.session_state.server_runtime

st.title("Client Chat")
st.caption("Encrypted direct messaging UI. Your messages are on the right, received messages are on the left.")


def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

st.markdown(
    """
<style>
.chat-wrap {
    max-width: 980px;
    margin: 0 auto;
}
.bubble-row {
    display: flex;
    margin: 0.35rem 0;
}
.left {
    justify-content: flex-start;
}
.right {
    justify-content: flex-end;
}
.bubble {
    border-radius: 14px;
    padding: 10px 12px;
    max-width: 72%;
    line-height: 1.35;
    font-size: 0.95rem;
}
.left .bubble {
    background: #dff3ff;
    border: 1px solid #b8e3ff;
}
.right .bubble {
    background: #d9f8df;
    border: 1px solid #b9ecc3;
}
.meta {
    display: block;
    font-size: 0.72rem;
    color: #2f3d4a;
    margin-bottom: 4px;
    opacity: 0.75;
}
.body {
    display: block;
    color: #0f1720;
    white-space: normal;
    word-break: break-word;
}
.notice {
    text-align: center;
    margin: 0.4rem 0;
    color: #4d555f;
    font-size: 0.85rem;
}
</style>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.subheader("Connection")
    host = st.text_input("Host", value="127.0.0.1")
    port = st.number_input("Port", min_value=1024, max_value=65535, value=9009, step=1)

    port_reachable = is_port_open(host, int(port))
    managed_here = server_runtime.is_running and server_runtime.port == int(port) and server_runtime.host == host

    if port_reachable:
        if managed_here:
            st.success("Server is running for this host/port (managed by this app).")
        else:
            st.success("Server is running for this host/port.")
    else:
        st.warning("Server is not running on this host/port. Start it from Server Dashboard or use Quick Start.")
        if st.button("Quick Start Server", use_container_width=True):
            ok, msg = server_runtime.start(host, int(port))
            (st.success if ok else st.error)(msg)

    if not client.connected:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Connect", use_container_width=True):
            ok, msg = client.connect(host, int(port), username.strip(), password)
            if ok:
                st.session_state.chat_username = username.strip()
                st.success(msg)
            else:
                st.error(msg)
    else:
        st.success(f"Connected as {st.session_state.chat_username}")
        if st.button("Disconnect", use_container_width=True):
            client.disconnect()
            st.warning("Disconnected")

    if client.connected:
        st.divider()
        st.subheader("Quick Commands")
        if st.button("Refresh Online Users", use_container_width=True):
            client.send({"type": "list_online"})

for event in client.poll_events() if client.connected else []:
    etype = event.get("type")

    if etype == "approval_request":
        sender = str(event.get("from", ""))
        if sender and sender not in [r.get("from") for r in pending_requests]:
            pending_requests.append(event)

    if etype == "chat":
        current_user = st.session_state.chat_username
        from_user = str(event.get("from", ""))
        to_user = str(event.get("to", ""))
        text = str(event.get("message", ""))
        # Standard chat layout: own/sent messages on right, incoming on left.
        side = "right" if from_user == current_user else "left"
        messages.append({"side": side, "meta": f"{from_user} -> {to_user}", "text": text})
    elif etype == "user_list":
        online = ", ".join(event.get("online", [])) or "No users online."
        messages.append({"side": "notice", "text": f"Online users: {online}"})
    elif etype in {"system", "info", "alert", "auth_required", "auth_result"}:
        text = str(event.get("message", ""))
        messages.append({"side": "notice", "text": text})

st.markdown('<div class="chat-wrap">', unsafe_allow_html=True)

for msg in messages[-200:]:
    side = msg.get("side", "notice")
    if side == "notice":
        notice_text = html.escape(str(msg.get("text", ""))).replace("\n", "<br>")
        st.markdown(f'<div class="notice">{notice_text}</div>', unsafe_allow_html=True)
        continue

    meta = html.escape(str(msg.get("meta", "")))
    body_raw = str(msg.get("text", "")).strip()
    text = html.escape(body_raw).replace("\n", "<br>") if body_raw else "<i>(no message)</i>"
    st.markdown(
        f'<div class="bubble-row {side}"><div class="bubble"><span class="meta">{meta}</span><span class="body">{text}</span></div></div>',
        unsafe_allow_html=True,
    )

st.markdown("</div>", unsafe_allow_html=True)

if pending_requests:
    st.subheader("Approval Requests")
    for req in pending_requests[:]:
        sender = str(req.get("from", ""))
        preview = str(req.get("message_preview", ""))
        c1, c2, c3 = st.columns([4, 1, 1])
        c1.info(f"{sender} wants to message you: {preview}")
        if c2.button("Approve", key=f"ap_{sender}"):
            client.send({"type": "approval_response", "sender": sender, "approve": True})
            pending_requests.remove(req)
            st.rerun()
        if c3.button("Deny", key=f"dn_{sender}"):
            client.send({"type": "approval_response", "sender": sender, "approve": False})
            pending_requests.remove(req)
            st.rerun()

if client.connected:
    with st.form("send_form", clear_on_submit=True):
        receiver = st.text_input("Send to")
        text = st.text_area("Message", height=90)
        submitted = st.form_submit_button("Send Message")
        if submitted:
            if not receiver.strip() or not text.strip():
                st.warning("Receiver and message are required.")
            else:
                ok, msg = client.send({"type": "direct", "to": receiver.strip(), "message": text.strip()})
                if ok:
                    current_user = st.session_state.chat_username
                    messages.append(
                        {
                            "side": "right",
                            "meta": f"{current_user} -> {receiver.strip()}",
                            "text": text.strip(),
                        }
                    )
                else:
                    st.error(msg)

st.button("Refresh", use_container_width=True)
