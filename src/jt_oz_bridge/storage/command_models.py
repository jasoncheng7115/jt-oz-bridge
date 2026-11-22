"""Immutable human command receipts, separate from agent actions."""

import time
from typing import Any

from sqlalchemy import BigInteger, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base, uid


class CommandReceipt(Base):
    __tablename__ = "command_receipts"
    __table_args__ = (UniqueConstraint("realm_id", "message_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    realm_id: Mapped[str] = mapped_column(String(255))
    message_id: Mapped[int] = mapped_column(BigInteger)
    actor_id: Mapped[int] = mapped_column(BigInteger)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    topic: Mapped[str] = mapped_column(String(255))
    source_revision: Mapped[int] = mapped_column(Integer)
    source_hash: Mapped[str] = mapped_column(String(64))
    command: Mapped[str] = mapped_column(String(32))
    binding_id: Mapped[str | None] = mapped_column(String(36))
    binding_revision: Mapped[int | None] = mapped_column(Integer)
    holder: Mapped[str] = mapped_column(String(36))
    fencing: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    response: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("command_receipts", "response"))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)

    payload_compacted_at: Mapped[float | None] = mapped_column(Float)
