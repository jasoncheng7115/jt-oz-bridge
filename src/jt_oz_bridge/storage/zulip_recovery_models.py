"""Durable message watermarks and exact recovered-source/action review links."""

import time
from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base, uid


class ZulipRecoveryCheckpoint(Base):
    __tablename__ = "zulip_recovery_checkpoints"
    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    channel_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(255))
    bot_user_id: Mapped[int] = mapped_column(BigInteger)
    message_id: Mapped[int] = mapped_column(BigInteger)
    coverage: Mapped[str] = mapped_column(String(32), default="unknown_before_anchor")
    binding_scopes: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("zulip_recovery_checkpoints", "binding_scopes")
    )
    run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("input_events.id"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)


class ZulipRecoveryItem(Base):
    __tablename__ = "zulip_recovery_items"
    __table_args__ = (UniqueConstraint("source", "message_id", "source_revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(64), index=True)
    message_id: Mapped[int] = mapped_column(BigInteger)
    source_revision: Mapped[int] = mapped_column(BigInteger)
    input_event_id: Mapped[str] = mapped_column(String(36), ForeignKey("input_events.id"))
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("input_events.id"))
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[int] = mapped_column(BigInteger)
    action_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("actions.id"), unique=True)
    state: Mapped[str] = mapped_column(String(32), default="captured", index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    review_receipt_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("input_events.id"))
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
