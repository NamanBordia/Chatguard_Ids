"""Runtime helpers for Streamlit server/client pages."""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path
from queue import Empty, Queue
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

from secure_channel import decrypt_payload, encrypt_payload, get_shared_key

# Import server-side modules with package-compatible fallback.
try:
    from server import server as chat_server
except Exception as exc:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Could not import server module: {exc}") from exc

try:
    from server.auth import create_user, delete_user, init_db, list_users, update_user_password
    from server.detection import initialize_detection_engine
except Exception as exc:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Could not import auth/detection modules: {exc}") from exc


class ServerRuntime:
    """Lifecycle wrapper for socket server used by Streamlit dashboard."""

    def __init__(self) -> None:
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self.host = "127.0.0.1"
        self.port = 9009

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def start(self, host: str, port: int) -> tuple[bool, str]:
        if self.is_running:
            return False, "Server is already running."

        init_db()
        initialize_detection_engine()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            sock.listen()
            sock.settimeout(1.0)
        except OSError as exc:
            sock.close()
            return False, f"Could not start server: {exc}"

        self.host = host
        self.port = port
        self._socket = sock
        self._running.set()

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return True, f"Server started on {host}:{port}."

    def stop(self) -> tuple[bool, str]:
        if not self.is_running:
            return False, "Server is not running."

        self._running.clear()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

        return True, "Server stop requested."

    def _accept_loop(self) -> None:
        assert self._socket is not None
        while self._running.is_set():
            try:
                conn, addr = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=chat_server.client_handler, args=(conn, addr), daemon=True).start()

    def online_users(self) -> list[str]:
        with chat_server.clients_lock:
            return sorted(chat_server.clients.keys())

    def risk_scores(self) -> dict[str, int]:
        return dict(sorted(chat_server.user_risk_scores.items()))

    def pending_approvals(self) -> list[dict[str, str]]:
        with chat_server.state_lock:
            return [
                {
                    "sender": sender,
                    "receiver": receiver,
                    "preview": payload.get("message", "")[:120],
                }
                for (sender, receiver), payload in chat_server.pending_requests.items()
            ]

    def list_db_users(self) -> list[dict[str, Any]]:
        return list_users()

    def add_user(self, username: str, password: str, role: str) -> tuple[bool, str]:
        return create_user(username, password, role)

    def change_password(self, username: str, password: str) -> tuple[bool, str]:
        return update_user_password(username, password)

    def remove_user(self, username: str) -> tuple[bool, str]:
        with chat_server.clients_lock:
            if username in chat_server.clients:
                return False, "Cannot delete a currently connected user."
        return delete_user(username)

    def tail_logs(self, lines: int = 40) -> list[str]:
        log_file = ROOT / "logs" / "logs.txt"
        if not log_file.exists():
            return []
        content = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        if lines <= 0:
            return content
        return content[-lines:]


class SecureSocketClient:
    """Encrypted socket client wrapper for Streamlit chat UI."""

    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.reader = None
        self.send_lock = threading.Lock()
        self.queue: Queue[dict[str, Any]] = Queue()
        self.listen_thread: threading.Thread | None = None
        self.key: bytes | None = None
        self.username = ""
        self.connected = False

    def connect(self, host: str, port: int, username: str, password: str) -> tuple[bool, str]:
        if self.connected:
            return False, "Client is already connected."

        key = get_shared_key()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            reader = sock.makefile("r", encoding="utf-8")

            challenge = self._read_decrypted(reader, key)
            if challenge.get("type") != "auth_required":
                raise ValueError("Unexpected auth challenge from server.")

            self._send_encrypted(sock, {"username": username, "password": password}, key)
            result = self._read_decrypted(reader, key)
            if result.get("type") != "auth_result" or not result.get("success"):
                msg = str(result.get("message", "Authentication failed."))
                sock.close()
                return False, msg

            self.sock = sock
            self.reader = reader
            self.key = key
            self.username = username
            self.connected = True
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()
            return True, str(result.get("message", "Connected."))
        except Exception as exc:
            try:
                sock.close()
            except OSError:
                pass
            return False, f"Connection failed: {exc}"

    def disconnect(self) -> None:
        if not self.connected:
            return
        try:
            self.send({"type": "quit"})
        except Exception:
            pass
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.reader = None

    def send(self, payload: dict[str, Any]) -> tuple[bool, str]:
        if not self.connected or not self.sock or not self.key:
            return False, "Not connected."
        try:
            self._send_encrypted(self.sock, payload, self.key)
            return True, "Sent."
        except Exception as exc:
            self.connected = False
            return False, f"Send failed: {exc}"

    def _listen_loop(self) -> None:
        if not self.reader or not self.key:
            return
        while self.connected:
            try:
                payload = self._read_decrypted(self.reader, self.key)
            except Exception:
                self.connected = False
                self.queue.put({"type": "system", "message": "Disconnected from server."})
                return
            self.queue.put(payload)

    def poll_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while True:
            try:
                events.append(self.queue.get_nowait())
            except Empty:
                break
        return events

    def _send_encrypted(self, sock: socket.socket, payload: dict[str, Any], key: bytes) -> None:
        envelope = encrypt_payload(payload, key)
        wire = (json.dumps(envelope) + "\n").encode("utf-8")
        with self.send_lock:
            sock.sendall(wire)

    def _read_decrypted(self, reader, key: bytes) -> dict[str, Any]:
        line = reader.readline()
        if not line:
            raise ConnectionError("Connection closed by server.")
        envelope = json.loads(line)
        return decrypt_payload(envelope, key)
