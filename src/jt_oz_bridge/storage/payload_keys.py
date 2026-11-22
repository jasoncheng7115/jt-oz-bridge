"""Persistent key canaries, verified before any encrypted payload writes."""

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from jt_oz_bridge.storage.cipher_types import KEY_CHECK, PayloadUnavailable, key_state


def verify_keys(connection: Connection, *, initialize: bool = False) -> None:
    state = key_state(connection.dialect)
    generation = state.verification_generation()
    # Healthy rechecks preserve an existing verified writer. First checks stay
    # unverified; actual errors invalidate even an earlier successful state.
    try:
        if not inspect(connection).has_table("payload_key_checks"):
            if initialize:
                state.verified = False
                return
            raise PayloadUnavailable("payload_key_verification_required")
        rows = connection.execute(text("SELECT key_id, challenge FROM payload_key_checks")).all()
        found = set()
        try:
            for identity, challenge in rows:
                decoded = state.cipher.open(
                    challenge,
                    {"purpose": "database-key-check", "key_id": identity},
                    max_plaintext_bytes=len(KEY_CHECK),
                )
                if decoded != KEY_CHECK:
                    raise ValueError("invalid canary")
                found.add(identity)
        except (ValueError, TypeError):
            raise PayloadUnavailable("database_key_verification_failed") from None
        active = state.cipher.active_key_id
        if active not in found:
            if not initialize:
                raise PayloadUnavailable("active_database_key_not_initialized")
            challenge = state.cipher.seal(
                KEY_CHECK, {"purpose": "database-key-check", "key_id": active}
            )
            connection.execute(
                text(
                    "INSERT INTO payload_key_checks (key_id, challenge) VALUES (:key_id, :challenge)"
                ),
                {"key_id": active, "challenge": challenge},
            )
        if key_state(connection.dialect) is not state:
            raise PayloadUnavailable("payload_encryption_key_changed")
        state.complete_verification(generation)
    except BaseException:
        state.verified = False
        raise
