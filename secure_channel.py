"""AES-GCM helpers for securing socket payloads.

This module provides a small symmetric encryption layer used by both
client and server. It encrypts each JSON payload independently with a
fresh nonce (AES-GCM), preserving message framing over newline-delimited
JSON.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "pycryptodome is required for AES encryption. Install it with: pip install pycryptodome"
    ) from exc


class SecureChannelError(ValueError):
    """Raised when encrypted payload processing fails."""


def _derive_key_from_passphrase(passphrase: str) -> bytes:
    # Stable KDF parameters shared by client/server for key derivation.
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        b"chatguard-aes-v1",
        200_000,
        dklen=32,
    )


def get_shared_key() -> bytes:
    """Load a 256-bit key from env or derive it from a shared passphrase."""
    key_b64 = os.getenv("CHAT_AES_KEY_B64", "").strip()
    if key_b64:
        try:
            raw = base64.b64decode(key_b64)
        except Exception as exc:  # pragma: no cover - defensive path
            raise SecureChannelError("CHAT_AES_KEY_B64 is not valid base64.") from exc
        if len(raw) != 32:
            raise SecureChannelError("CHAT_AES_KEY_B64 must decode to 32 bytes for AES-256.")
        return raw

    passphrase = os.getenv("CHAT_AES_PASSPHRASE", "chatguard-dev-secret-change-me")
    return _derive_key_from_passphrase(passphrase)


def encrypt_payload(payload: dict[str, Any], key: bytes) -> dict[str, str]:
    """Encrypt a JSON payload into a transport envelope."""
    try:
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SecureChannelError(f"Payload is not JSON serializable: {exc}") from exc

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "type": "secure",
        "nonce": base64.b64encode(cipher.nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_payload(envelope: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Decrypt and validate an encrypted transport envelope."""
    if envelope.get("type") != "secure":
        raise SecureChannelError("Expected encrypted payload of type='secure'.")

    try:
        nonce = base64.b64decode(str(envelope["nonce"]))
        ciphertext = base64.b64decode(str(envelope["ciphertext"]))
        tag = base64.b64decode(str(envelope["tag"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise SecureChannelError("Malformed encrypted payload.") from exc

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decoded = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise SecureChannelError("Encrypted payload verification failed.") from exc

    if not isinstance(decoded, dict):
        raise SecureChannelError("Decrypted payload must be a JSON object.")

    return decoded
