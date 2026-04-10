"""Socket client for Secure Chat IDS system.

Run:
    python client/client.py
"""

from __future__ import annotations

import getpass
import json
import socket
import threading

HOST = "127.0.0.1"
PORT = 9009


def send_json(sock: socket.socket, payload: dict) -> None:
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def receiver_loop(reader) -> None:
    try:
        for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                print("[CLIENT] Received malformed data from server.")
                continue

            msg_type = payload.get("type")
            if msg_type == "chat":
                sender = payload.get("from")
                receiver = payload.get("to")
                print(f"[DM {sender} -> {receiver}] {payload.get('message')}")
            elif msg_type == "system":
                print(f"[SYSTEM] {payload.get('message')}")
            elif msg_type == "alert":
                print(f"[ALERT:{payload.get('level', 'info').upper()}] {payload.get('message')}")
                threats = payload.get("threats")
                if threats:
                    print(f"[ALERT] Details: {threats}")
                if "risk_score" in payload:
                    print(f"[ALERT] Your risk score: {payload['risk_score']}")
            elif msg_type == "approval_request":
                print(
                    f"[APPROVAL] {payload.get('from')} wants to message you. "
                    f"Preview: {payload.get('message_preview')}"
                )
                print(payload.get("prompt"))
            elif msg_type == "user_list":
                online = payload.get("online", [])
                print(f"[ONLINE] {', '.join(online) if online else 'No users online.'}")
            elif msg_type == "info":
                print(f"[INFO] {payload.get('message')}")
            elif msg_type == "auth_required":
                print(payload.get("message"))
                known = payload.get("known_users", [])
                if known:
                    print(f"Known users: {', '.join(known)}")
            elif msg_type == "auth_result":
                if payload.get("success"):
                    print(f"[AUTH] {payload.get('message')}")
                else:
                    print(f"[AUTH] Failed: {payload.get('message')}")
            else:
                print(f"[SERVER] {payload}")
    except (ConnectionResetError, OSError):
        pass
    finally:
        print("[CLIENT] Disconnected from server.")


def authenticate(sock: socket.socket, reader) -> bool:
    # Wait for auth_required prompt.
    line = reader.readline()
    if not line:
        print("[AUTH] Server closed connection before authentication.")
        return False

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        print("[AUTH] Unexpected auth response.")
        return False

    if payload.get("type") == "auth_required":
        print(payload.get("message"))
        known = payload.get("known_users", [])
        if known:
            print(f"Known users: {', '.join(known)}")

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    send_json(sock, {"username": username, "password": password})

    result_line = reader.readline()
    if not result_line:
        print("[AUTH] No auth result received.")
        return False

    try:
        result = json.loads(result_line)
    except json.JSONDecodeError:
        print("[AUTH] Invalid auth result format.")
        return False

    if result.get("type") != "auth_result" or not result.get("success"):
        print(f"[AUTH] Failed: {result.get('message', 'Unknown error')}" )
        return False

    role = result.get("role", "user")
    print(f"[AUTH] {result.get('message')} (role: {role})")
    return True


def start_client() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except OSError as exc:
        print(f"[CLIENT] Could not connect to server: {exc}")
        return

    try:
        reader = sock.makefile("r", encoding="utf-8")

        if not authenticate(sock, reader):
            sock.close()
            return

        receiver = threading.Thread(target=receiver_loop, args=(reader,), daemon=True)
        receiver.start()

        print("[CLIENT] Commands:")
        print("  /to <username> <message>  -> send direct message")
        print("  /approve <sender>         -> approve sender")
        print("  /deny <sender>            -> deny sender")
        print("  /users                    -> list online users")
        print("  /quit                     -> exit")
        while True:
            msg = input().strip()
            if not msg:
                continue

            if msg.lower() == "/quit":
                send_json(sock, {"type": "quit"})
                break

            if msg.lower() == "/users":
                send_json(sock, {"type": "list_online"})
                continue

            if msg.startswith("/approve "):
                sender = msg.split(maxsplit=1)[1].strip()
                if sender:
                    send_json(sock, {"type": "approval_response", "sender": sender, "approve": True})
                continue

            if msg.startswith("/deny "):
                sender = msg.split(maxsplit=1)[1].strip()
                if sender:
                    send_json(sock, {"type": "approval_response", "sender": sender, "approve": False})
                continue

            if msg.startswith("/to "):
                parts = msg.split(maxsplit=2)
                if len(parts) < 3:
                    print("[CLIENT] Usage: /to <username> <message>")
                    continue
                send_json(sock, {"type": "direct", "to": parts[1], "message": parts[2]})
                continue

            print("[CLIENT] Unknown command. Use /to, /approve, /deny, /users, /quit.")
    except KeyboardInterrupt:
        pass
    except (ConnectionResetError, OSError):
        print("[CLIENT] Connection lost.")
    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    start_client()
