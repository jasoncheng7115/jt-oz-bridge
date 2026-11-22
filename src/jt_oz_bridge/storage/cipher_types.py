"""Engine-scoped encrypted JSON columns; no global default key/plaintext fallback."""

import json
import threading
from dataclasses import dataclass
from typing import Any
from weakref import WeakKeyDictionary

from sqlalchemy.engine import Dialect
from sqlalchemy.types import LargeBinary, TypeDecorator

from jt_oz_bridge.security.cipher import EnvelopeCipher

MAX_PAYLOAD = 32 * 1024**2
KEY_CHECK = b"jt-oz-bridge:payload-key-check:v1"


class PayloadUnavailable(ValueError):
    pass


@dataclass
class KeyState:
    cipher: EnvelopeCipher
    _verified: bool = False
    _verification_generation: int = 0

    @property
    def verified(self) -> bool:
        with _LOCK:
            return self._verified

    @verified.setter
    def verified(self, value: bool) -> None:
        with _LOCK:
            if not value:
                # A later failed check or explicit migration reset must fence
                # every verification already reading an older database view.
                self._verification_generation += 1
            self._verified = value

    def verification_generation(self) -> int:
        with _LOCK:
            return self._verification_generation

    def complete_verification(self, generation: int) -> None:
        with _LOCK:
            if generation != self._verification_generation:
                raise PayloadUnavailable("payload_key_verification_superseded")
            self._verified = True


_KEYS: WeakKeyDictionary[Dialect, KeyState] = WeakKeyDictionary()
_LOCK = threading.RLock()


def register(dialect: Dialect, cipher: EnvelopeCipher) -> None:
    with _LOCK:
        _KEYS[dialect] = KeyState(cipher)


def unregister(dialect: Dialect) -> None:
    with _LOCK:
        _KEYS.pop(dialect, None)


def key_state(dialect: Dialect) -> KeyState:
    with _LOCK:
        state = _KEYS.get(dialect)
    if state is None:
        raise PayloadUnavailable("payload_encryption_key_unavailable")
    return state


def checked_json(value: Any) -> bytes:
    try:
        if not isinstance(value, dict):
            raise ValueError("payload object required")
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
        if len(encoded) > MAX_PAYLOAD:
            raise ValueError("oversized payload")
        return encoded
    except (TypeError, ValueError, RecursionError):
        raise PayloadUnavailable("invalid_or_oversized_payload") from None


def payload_scope(table: str, column: str) -> dict[str, str]:
    return {"purpose": "database_payload", "table": table, "column": column}


class EncryptedJSON(TypeDecorator[dict[str, Any]]):
    impl = LargeBinary
    cache_ok = True

    def __init__(self, table: str, column: str) -> None:
        super().__init__()
        self.table, self.column = table, column

    def process_bind_param(self, value: dict[str, Any] | None, dialect: Dialect) -> bytes | None:
        if value is None:
            return None
        state = key_state(dialect)
        if not state.verified:
            raise PayloadUnavailable("payload_key_verification_required")
        return state.cipher.seal(checked_json(value), payload_scope(self.table, self.column))

    def process_result_value(self, value: bytes | None, dialect: Dialect) -> dict[str, Any] | None:
        if value is None:
            return None
        try:
            if not isinstance(value, bytes):
                raise ValueError("legacy plaintext payload forbidden")
            raw = key_state(dialect).cipher.open(
                value, payload_scope(self.table, self.column), max_plaintext_bytes=MAX_PAYLOAD
            )
            decoded = json.loads(raw)
            checked_json(decoded)
            return decoded  # type: ignore[no-any-return]
        except (ValueError, TypeError, RecursionError):
            raise PayloadUnavailable("encrypted_payload_unavailable_or_invalid") from None
