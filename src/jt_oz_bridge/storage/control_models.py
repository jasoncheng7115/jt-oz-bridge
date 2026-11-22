import time
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base, uid


class EnrolledBackend(Base):
    __tablename__ = "backends"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    identity: Mapped[str] = mapped_column(String(255))
    contract_hash: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[str] = mapped_column(String(128))


class EnrolledProject(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    backend_id: Mapped[str] = mapped_column(String(255))
    realm_id: Mapped[str] = mapped_column(String(255))
    canonical_directory: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class Binding(Base):
    __tablename__ = "bindings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    realm_id: Mapped[str] = mapped_column(String(255), index=True)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    topic: Mapped[str] = mapped_column(Text)
    anchor_message_id: Mapped[int | None] = mapped_column(BigInteger)
    backend_id: Mapped[str] = mapped_column(String(255))
    backend_identity: Mapped[str] = mapped_column(String(255))
    session_id: Mapped[str] = mapped_column(String(255))
    project_id: Mapped[str] = mapped_column(String(255))
    canonical_directory: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[int] = mapped_column(BigInteger)
    locale: Mapped[str] = mapped_column(String(16), default="en")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(32), default="active")
    audience_revision: Mapped[str] = mapped_column(String(255))
    audience_user_ids: Mapped[list[int]] = mapped_column(JSON)
    session_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    topic_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    observed_cursor: Mapped[str] = mapped_column(Text)
    dispatch_paused: Mapped[bool] = mapped_column(Boolean, default=False)
    queue_revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class ControlToken(Base):
    __tablename__ = "control_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    realm_id: Mapped[str] = mapped_column(String(255))
    user_id: Mapped[int] = mapped_column(BigInteger)
    binding_id: Mapped[str | None] = mapped_column(String(36))
    binding_revision: Mapped[int | None] = mapped_column(Integer)
    context: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("control_tokens", "context"))
    context_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)

    payload_compacted_at: Mapped[float | None] = mapped_column(Float)


class PendingInteraction(Base):
    __tablename__ = "pending_interactions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    identity_key: Mapped[str] = mapped_column(String(64), unique=True)
    binding_id: Mapped[str] = mapped_column(String(36), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("pending_interactions", "snapshot")
    )
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    winner_user_id: Mapped[int | None] = mapped_column(BigInteger)
    action_id: Mapped[str | None] = mapped_column(String(36))
    expires_at: Mapped[float] = mapped_column(Float)
    version: Mapped[int] = mapped_column(Integer, default=1)
    # Metrics only; NULL predates schema37. Expiry, not age, decides validity.
    created_at: Mapped[float | None] = mapped_column(Float, default=time.time)


class FormDraft(Base):
    __tablename__ = "form_drafts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    interaction_id: Mapped[str] = mapped_column(String(36))
    user_id: Mapped[int] = mapped_column(BigInteger)
    answers: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("form_drafts", "answers"))
    progress: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("form_drafts", "progress"), default=lambda: {"skipped": []}
    )
    snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(Integer, default=1)
