"""Encrypted ownDB identities for read-only original-session recovery."""

import time
from collections.abc import Mapping
from typing import Any

from sqlalchemy import CheckConstraint, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base

REGISTRATION_SEAL_FIELDS = (
    "key",
    "realm_id",
    "project_id",
    "payload_hash",
    "identity_hash",
    "state",
    "revision",
    "prepared_holder",
    "prepared_fencing",
    "activated_fencing",
    "created_at",
    "updated_at",
    "extension_count",
    "extension_tip_hash",
)


def registration_history_seal(values: Mapping[str, Any]) -> dict[str, Any]:
    """Authenticate head projections and the history tip without changing receipts."""
    return {
        "format": "original-registration-head-seal-v1",
        **{field: values[field] for field in REGISTRATION_SEAL_FIELDS},
    }


class SessionRegistration(Base):
    __tablename__ = "session_registrations"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(255), index=True)
    project_id: Mapped[str] = mapped_column(String(255), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("session_registrations", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    identity_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16))
    revision: Mapped[int] = mapped_column(Integer)
    prepared_holder: Mapped[str] = mapped_column(String(255))
    prepared_fencing: Mapped[int] = mapped_column(Integer)
    activated_fencing: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
    extension_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    extension_tip_hash: Mapped[str | None] = mapped_column(String(64))
    history_seal: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("session_registrations", "history_seal")
    )


class SessionRegistrationExtension(Base):
    """Append-only encrypted deltas, bounded by strictly added graph nodes."""

    __tablename__ = "session_registration_extensions"
    __table_args__ = (
        CheckConstraint(
            "sequence >= 1 AND sequence <= 999", name="ck_registration_extension_sequence"
        ),
        CheckConstraint(
            "added_count >= 1 AND added_count <= 999", name="ck_registration_extension_count"
        ),
        CheckConstraint(
            "predecessor_revision > 0 AND successor_revision = predecessor_revision + 1",
            name="ck_registration_extension_revision",
        ),
        UniqueConstraint(
            "registration_key", "successor_revision", name="uq_registration_extension_revision"
        ),
    )
    registration_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("session_registrations.key"), primary_key=True
    )
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    predecessor_revision: Mapped[int] = mapped_column(Integer)
    successor_revision: Mapped[int] = mapped_column(Integer)
    predecessor_identity_hash: Mapped[str] = mapped_column(String(64))
    successor_identity_hash: Mapped[str] = mapped_column(String(64))
    predecessor_payload_hash: Mapped[str] = mapped_column(String(64))
    successor_payload_hash: Mapped[str] = mapped_column(String(64))
    added_count: Mapped[int] = mapped_column(Integer)
    delta: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("session_registration_extensions", "delta")
    )
    delta_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
