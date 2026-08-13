#!/usr/bin/env python3
"""AES-256-GCM encryption/decryption helpers for the MSP agent.

Replicates the pax-msp-portal's src/lib/crypto.ts logic so the agent can
decrypt Credential.passwordEnc / notesEnc values written by the portal.

The portal stores ciphertext as a single colon-delimited string:

    enc:v1:<ivBase64>:<authTagBase64>:<ciphertextBase64>

Key derivation (must match crypto.ts getKey()):
    1. If ENCRYPTION_KEY base64-decodes to exactly 32 bytes, use those bytes.
    2. Else if it is a 64-char hex string, use those 32 bytes.
    3. Else derive a 32-byte key via SHA-256 of the raw string.

Values that do not carry the "enc:v1:" prefix are treated as plaintext and
returned unchanged (graceful degradation for pre-encryption/legacy data).
"""

import base64
import hashlib
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc:v1:"
HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _load_key(raw: str) -> bytes:
    """Derive the 32-byte AES key from ENCRYPTION_KEY exactly like crypto.ts."""
    try:
        as_base64 = base64.b64decode(raw, validate=True)
    except Exception:
        as_base64 = b""
    as_hex = bytes.fromhex(raw) if HEX_KEY_RE.match(raw) else None
    if as_hex is not None and len(as_hex) == 32:
        return as_hex
    if len(as_base64) == 32:
        return as_base64
    return hashlib.sha256(raw.encode("utf-8")).digest()


class Cipher:
    """AES-256-GCM cipher bound to a 32-byte key."""

    def __init__(self, encryption_key: str):
        self.key = _load_key(encryption_key)

    @classmethod
    def from_env(cls, raw: str | None) -> "Cipher | None":
        """Build a Cipher from an ENCRYPTION_KEY string, or None if unset."""
        if not raw:
            return None
        return cls(raw)

    def encrypt(self, plaintext: str | None) -> str | None:
        if plaintext is None:
            return None
        if plaintext == "":
            return ""
        if plaintext.startswith(PREFIX):
            return plaintext  # already encrypted
        iv = os.urandom(12)
        ct = AESGCM(self.key).encrypt(iv, plaintext.encode("utf-8"), None)
        # AESGCM output is ciphertext || tag(16 bytes)
        ciphertext, auth_tag = ct[:-16], ct[-16:]
        return "{}{}:{}:{}".format(
            PREFIX,
            base64.b64encode(iv).decode("ascii"),
            base64.b64encode(auth_tag).decode("ascii"),
            base64.b64encode(ciphertext).decode("ascii"),
        )

    def decrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        if value == "":
            return ""
        if not value.startswith(PREFIX):
            return value  # plaintext / legacy
        try:
            _prefix, _v1, iv_b64, tag_b64, data_b64 = value.split(":")
            iv = base64.b64decode(iv_b64)
            auth_tag = base64.b64decode(tag_b64)
            ciphertext = base64.b64decode(data_b64)
            pt = AESGCM(self.key).decrypt(iv, ciphertext + auth_tag, None)
            return pt.decode("utf-8")
        except Exception:
            # Tampered ciphertext or key mismatch — never leak raw ciphertext.
            return None


def decrypt_credential(encryption_key: str, value: str | None) -> str | None:
    """Convenience: build a one-shot Cipher and decrypt a stored value."""
    return Cipher(encryption_key).decrypt(value)
