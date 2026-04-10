"""SQLite-backed authentication and user CRUD for the secure chat server."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path

_ITERATIONS = 120_000
_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "users.db"

_SEED_USERS = [
    ("alice", "alice123", "user"),
    ("bob", "bob123", "user"),
    ("admin", "admin123", "admin"),
    ("naman", "naman123", "user"),
]


def _get_connection() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt_hex: str) -> str:
    """Return PBKDF2-HMAC-SHA256 hash in hex."""
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return derived.hex()


def init_db() -> None:
    """Initialize users table and seed default accounts once."""
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if existing == 0:
            for username, password, role in _SEED_USERS:
                salt_hex = secrets.token_hex(16)
                conn.execute(
                    "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)",
                    (username, salt_hex, hash_password(password, salt_hex), role),
                )


def get_user(username: str) -> dict | None:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, salt, password_hash, role, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def verify_credentials(username: str, password: str) -> bool:
    """Validate username/password against SQLite user records."""
    record = get_user(username)
    if not record:
        return False
    expected = record["password_hash"]
    actual = hash_password(password, record["salt"])
    return hmac.compare_digest(actual, expected)


def list_known_users() -> list[str]:
    with _get_connection() as conn:
        rows = conn.execute("SELECT username FROM users ORDER BY username ASC").fetchall()
    return [r["username"] for r in rows]


def list_users() -> list[dict]:
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY id ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def create_user(username: str, password: str, role: str = "user") -> tuple[bool, str]:
    if not username.strip() or not password:
        return False, "Username and password are required."
    if role not in {"user", "admin"}:
        return False, "Role must be 'user' or 'admin'."

    salt_hex = secrets.token_hex(16)
    password_hash = hash_password(password, salt_hex)

    try:
        with _get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)",
                (username.strip(), salt_hex, password_hash, role),
            )
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    return True, "User created."


def update_user_password(username: str, new_password: str) -> tuple[bool, str]:
    if not new_password:
        return False, "New password cannot be empty."

    salt_hex = secrets.token_hex(16)
    password_hash = hash_password(new_password, salt_hex)
    with _get_connection() as conn:
        cur = conn.execute(
            "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
            (salt_hex, password_hash, username),
        )
    if cur.rowcount == 0:
        return False, "User not found."
    return True, "Password updated."


def delete_user(username: str) -> tuple[bool, str]:
    if username == "admin":
        return False, "Cannot delete default admin account."
    with _get_connection() as conn:
        cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
    if cur.rowcount == 0:
        return False, "User not found."
    return True, "User deleted."


def get_user_role(username: str) -> str:
    record = get_user(username)
    if not record:
        return "user"
    return str(record.get("role", "user"))


init_db()
