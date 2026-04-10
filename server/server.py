"""Secure Chat Server with multi-layer IDS/IPS and approval-based direct messaging.

Run:
    python server/server.py
"""

from __future__ import annotations

import json
import socket
import threading
from collections import defaultdict
from typing import Dict, Tuple

from auth import (
    create_user,
    delete_user,
    get_user_role,
    init_db,
    list_known_users,
    list_users,
    update_user_password,
    verify_credentials,
)
from detection import detect_all, initialize_detection_engine
from logger import log_event

HOST = "127.0.0.1"
PORT = 9009

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 4}

clients: Dict[str, Tuple[socket.socket, threading.Lock, str]] = {}
clients_lock = threading.Lock()
state_lock = threading.Lock()

user_risk_scores = defaultdict(int)
approval_map = defaultdict(set)  # receiver -> set(sender)
pending_requests: Dict[Tuple[str, str], dict] = {}  # (sender, receiver) -> payload


def send_json(conn: socket.socket, payload: dict, lock: threading.Lock | None = None) -> None:
    data = (json.dumps(payload) + "\n").encode("utf-8")
    try:
        if lock:
            with lock:
                conn.sendall(data)
        else:
            conn.sendall(data)
    except OSError:
        pass


def send_to_user(username: str, payload: dict) -> bool:
    with clients_lock:
        record = clients.get(username)
    if not record:
        return False
    conn, conn_lock, _role = record
    send_json(conn, payload, conn_lock)
    return True


def evaluate_message(username: str, message: str) -> tuple[str, list[dict]]:
    bullying, spam, phishing, anomaly = detect_all(username, message)
    findings = [r for r in [bullying, spam, phishing, anomaly] if r.get("is_threat")]

    if not findings:
        return "allow", []

    finding_types = {str(item.get("type")) for item in findings}
    if finding_types == {"anomaly"}:
        # Behavior spikes alone are noisy and should not hard-block clean content.
        highest = max(findings, key=lambda r: SEVERITY_ORDER.get(str(r.get("severity", "low")), 1))
        highest_severity = str(highest.get("severity", "low"))
        if highest_severity in {"high", "medium"}:
            return "warn", findings
        return "allow_with_notice", findings

    highest = max(findings, key=lambda r: SEVERITY_ORDER.get(str(r.get("severity", "low")), 1))
    highest_severity = str(highest.get("severity", "low"))

    if highest_severity == "high":
        return "block", findings
    if highest_severity == "medium":
        return "warn", findings
    return "allow_with_notice", findings


def build_threat_summary(findings: list[dict]) -> tuple[str, str]:
    if not findings:
        return "none", "none"

    types = sorted({str(f.get("type", "unknown")) for f in findings})
    max_sev = max(findings, key=lambda r: SEVERITY_ORDER.get(str(r.get("severity", "low")), 1))
    return ",".join(types), str(max_sev.get("severity", "low"))


def update_risk(username: str, findings: list[dict]) -> int:
    if not findings:
        user_risk_scores[username] = max(0, user_risk_scores[username] - 1)
        return user_risk_scores[username]

    for item in findings:
        sev = str(item.get("severity", "low"))
        user_risk_scores[username] += SEVERITY_SCORE.get(sev, 1)
    return user_risk_scores[username]


def authenticate_client(conn: socket.socket, conn_lock: threading.Lock, reader) -> tuple[str | None, str]:
    send_json(
        conn,
        {
            "type": "auth_required",
            "message": "Login required. Send username and password.",
            "known_users": list_known_users(),
        },
        conn_lock,
    )

    line = reader.readline()
    if not line:
        return None, "user"

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        send_json(conn, {"type": "auth_result", "success": False, "message": "Invalid auth format."}, conn_lock)
        return None, "user"

    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))

    if not username or not password or not verify_credentials(username, password):
        send_json(conn, {"type": "auth_result", "success": False, "message": "Authentication failed."}, conn_lock)
        return None, "user"

    with clients_lock:
        if username in clients:
            send_json(conn, {"type": "auth_result", "success": False, "message": "User already connected."}, conn_lock)
            return None, "user"

    role = get_user_role(username)
    send_json(
        conn,
        {
            "type": "auth_result",
            "success": True,
            "message": f"Welcome, {username}!",
            "role": role,
        },
        conn_lock,
    )
    return username, role


def process_direct_message(sender: str, receiver: str, message: str) -> None:
    if sender == receiver:
        send_to_user(sender, {"type": "alert", "level": "warning", "message": "Cannot message yourself."})
        return

    with clients_lock:
        receiver_online = receiver in clients
    if not receiver_online:
        send_to_user(sender, {"type": "alert", "level": "warning", "message": f"{receiver} is not online."})
        return

    action, findings = evaluate_message(sender, message)
    threat_type, severity = build_threat_summary(findings)
    risk = update_risk(sender, findings)

    if action == "block":
        send_to_user(
            sender,
            {
                "type": "alert",
                "level": "danger",
                "message": "Message blocked by IDS/IPS.",
                "threats": findings,
                "risk_score": risk,
            },
        )
        print(f"[ALERT] BLOCKED | from={sender} | to={receiver} | threat={threat_type} | msg={message}")
        log_event(sender, f"to={receiver} | {message}", threat_type, "blocked", severity)
        return

    if action in {"warn", "allow_with_notice"}:
        send_to_user(
            sender,
            {
                "type": "alert",
                "level": "warning",
                "message": "Suspicious content detected. Activity has been logged.",
                "threats": findings,
                "risk_score": risk,
            },
        )
        print(f"[ALERT] FLAGGED | from={sender} | to={receiver} | threat={threat_type} | msg={message}")

    with state_lock:
        approved = sender in approval_map[receiver]

    if approved:
        send_to_user(
            receiver,
            {"type": "chat", "from": sender, "to": receiver, "message": message},
        )
        send_to_user(sender, {"type": "info", "message": f"Delivered to {receiver}."})
        action_label = "delivered_flagged" if findings else "delivered"
        log_event(sender, f"to={receiver} | {message}", threat_type if findings else "none", action_label, severity if findings else "none")
        return

    with state_lock:
        pending_requests[(sender, receiver)] = {
            "message": message,
            "findings": findings,
            "threat_type": threat_type,
            "severity": severity,
        }

    send_to_user(
        receiver,
        {
            "type": "approval_request",
            "from": sender,
            "message_preview": message[:120],
            "prompt": f"Approve messages from {sender}? Use /approve {sender} or /deny {sender}.",
        },
    )
    send_to_user(sender, {"type": "info", "message": f"Awaiting approval from {receiver}."})
    action_label = "pending_approval_flagged" if findings else "pending_approval"
    log_event(sender, f"to={receiver} | {message}", threat_type if findings else "none", action_label, severity if findings else "none")


def process_approval_response(receiver: str, sender: str, approve: bool) -> None:
    key = (sender, receiver)

    with state_lock:
        pending = pending_requests.pop(key, None)
        if approve:
            approval_map[receiver].add(sender)

    if not approve:
        send_to_user(sender, {"type": "info", "message": f"{receiver} denied your message request."})
        send_to_user(receiver, {"type": "info", "message": f"You denied {sender}."})
        if pending:
            log_event(sender, f"to={receiver} | {pending['message']}", pending["threat_type"], "approval_denied", pending["severity"])
        return

    send_to_user(sender, {"type": "info", "message": f"{receiver} approved your messages."})
    send_to_user(receiver, {"type": "info", "message": f"You approved {sender}."})

    if pending:
        send_to_user(receiver, {"type": "chat", "from": sender, "to": receiver, "message": pending["message"]})
        log_event(sender, f"to={receiver} | {pending['message']}", pending["threat_type"], "delivered_after_approval", pending["severity"])


def client_handler(conn: socket.socket, addr: tuple[str, int]) -> None:
    conn_lock = threading.Lock()
    username = None
    user_role = "user"
    reader = conn.makefile("r", encoding="utf-8")

    try:
        username, user_role = authenticate_client(conn, conn_lock, reader)
        if not username:
            conn.close()
            return

        with clients_lock:
            clients[username] = (conn, conn_lock, user_role)

        print(f"[JOIN] {username} ({user_role}) connected from {addr[0]}:{addr[1]}")
        log_event(username, "<joined>", "none", "accepted", "none")

        for line in reader:
            line = line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                send_json(conn, {"type": "alert", "level": "warning", "message": "Invalid message format."}, conn_lock)
                continue

            msg_type = str(payload.get("type", "")).strip()

            if msg_type == "quit":
                break

            if msg_type == "list_online":
                with clients_lock:
                    online = sorted(clients.keys())
                send_json(conn, {"type": "user_list", "online": online}, conn_lock)
                continue

            if msg_type == "direct":
                receiver = str(payload.get("to", "")).strip()
                message = str(payload.get("message", "")).strip()
                if not receiver or not message:
                    send_json(conn, {"type": "alert", "level": "warning", "message": "Use /to <username> <message>."}, conn_lock)
                    continue
                process_direct_message(username, receiver, message)
                continue

            if msg_type == "approval_response":
                sender = str(payload.get("sender", "")).strip()
                approve = bool(payload.get("approve", False))
                if not sender:
                    send_json(conn, {"type": "alert", "level": "warning", "message": "Invalid approval response."}, conn_lock)
                    continue
                process_approval_response(username, sender, approve)
                continue

            send_json(conn, {"type": "alert", "level": "warning", "message": "Unknown command type."}, conn_lock)

    except (ConnectionResetError, OSError):
        pass
    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
            print(f"[LEAVE] {username} disconnected")
            log_event(username, "<left>", "none", "disconnect", "none")
        try:
            conn.close()
        except OSError:
            pass


def dashboard_loop() -> None:
    help_text = (
        "Commands: stats | users | dbusers | adduser <u> <p> [role] | "
        "passwd <u> <newp> | deluser <u> | help"
    )
    print(f"[DASHBOARD] {help_text}")
    while True:
        try:
            raw = input().strip()
        except EOFError:
            return

        if not raw:
            continue
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd == "stats":
            with clients_lock:
                online = sorted(clients.keys())
            print("[STATS] Online users:", online)
            print("[STATS] Risk scores:", dict(sorted(user_risk_scores.items())))
        elif cmd == "users":
            with clients_lock:
                online = sorted(clients.keys())
            print("[USERS] Online:", online)
        elif cmd == "dbusers":
            print("[DB USERS]", list_users())
        elif cmd == "adduser" and len(parts) in {3, 4}:
            role = parts[3] if len(parts) == 4 else "user"
            ok, msg = create_user(parts[1], parts[2], role)
            print(f"[CRUD] {msg}")
        elif cmd == "passwd" and len(parts) == 3:
            ok, msg = update_user_password(parts[1], parts[2])
            print(f"[CRUD] {msg}")
        elif cmd == "deluser" and len(parts) == 2:
            username = parts[1]
            with clients_lock:
                online = username in clients
            if online:
                print("[CRUD] Cannot delete a currently connected user.")
                continue
            ok, msg = delete_user(username)
            print(f"[CRUD] {msg}")
        elif cmd == "help":
            print(f"[DASHBOARD] {help_text}")
        else:
            print("[DASHBOARD] Unknown command. Type help.")


def start_server() -> None:
    init_db()
    initialize_detection_engine()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"[STARTED] Secure IDS Chat Server listening on {HOST}:{PORT}")

    threading.Thread(target=dashboard_loop, daemon=True).start()

    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[STOPPED] Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
