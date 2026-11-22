"""Versioned AEAD envelopes with scope binding and no plaintext fallback."""

import base64
import json
import os
import re
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr

MAGIC = b"JTOZ\x01"


class CipherError(ValueError):
    pass


def decode_key(value: SecretStr) -> bytes:
    try:
        key = base64.b64decode(
            value.get_secret_value().encode("ascii"), altchars=b"-_", validate=True
        )
        if len(key) != 32:
            raise ValueError("wrong key size")
        return key
    except (ValueError, UnicodeError):
        raise CipherError("encryption_key_must_be_base64_32_bytes") from None


class EnvelopeCipher:
    def __init__(self, keys: dict[str, bytes], active_key_id: str) -> None:
        if active_key_id not in keys or not keys:
            raise CipherError("active_encryption_key_missing")
        if any(
            not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name) or len(key) != 32
            for name, key in keys.items()
        ):
            raise CipherError("invalid_encryption_keyring")
        self._keys, self.active_key_id = dict(keys), active_key_id

    @staticmethod
    def context(scope: dict[str, Any]) -> bytes:
        try:
            value = json.dumps(
                scope, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
            if len(value) > 65536:
                raise ValueError("oversized context")
            return value
        except (ValueError, TypeError, RecursionError):
            raise CipherError("invalid_encryption_context") from None

    @staticmethod
    def overhead(key_id: str) -> int:
        return len(MAGIC) + 1 + len(key_id) + 16 + 12 + 16

    def seal(self, plaintext: bytes, scope: dict[str, Any]) -> bytes:
        context = self.context(scope)
        salt, nonce = os.urandom(16), os.urandom(12)
        name = self.active_key_id.encode("ascii")
        header = MAGIC + bytes([len(name)]) + name + salt + nonce
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt, info=b"jt-oz-bridge:envelope:v1"
        ).derive(self._keys[self.active_key_id])
        return header + AESGCM(key).encrypt(nonce, plaintext, header + context)

    def open(self, ciphertext: bytes, scope: dict[str, Any], *, max_plaintext_bytes: int) -> bytes:
        try:
            if not ciphertext.startswith(MAGIC) or len(ciphertext) < len(MAGIC) + 1:
                raise ValueError("unknown envelope")
            length = ciphertext[len(MAGIC)]
            if not 1 <= length <= 32:
                raise ValueError("invalid envelope")
            start = len(MAGIC) + 1
            name = ciphertext[start : start + length].decode("ascii")
            offset = start + length
            header_end = offset + 28
            if (
                len(ciphertext) < header_end + 16
                or len(ciphertext) - header_end - 16 > max_plaintext_bytes
            ):
                raise ValueError("invalid envelope size")
            master = self._keys[name]
            salt, nonce = ciphertext[offset : offset + 16], ciphertext[offset + 16 : header_end]
            header = ciphertext[:header_end]
            key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=salt, info=b"jt-oz-bridge:envelope:v1"
            ).derive(master)
            return AESGCM(key).decrypt(nonce, ciphertext[header_end:], header + self.context(scope))
        except (InvalidTag, ValueError, KeyError, UnicodeError):
            raise CipherError("encrypted_content_unavailable_or_invalid") from None
