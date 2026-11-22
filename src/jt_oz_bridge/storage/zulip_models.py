"""Numeric Zulip source scope; raw event bodies remain encrypted InputEvents."""

import time

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.models import Base


class ZulipQueue(Base):
    __tablename__ = "zulip_queues"
    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(255))
    bot_user_id: Mapped[int] = mapped_column(BigInteger)
    queue_id: Mapped[str] = mapped_column(String(255))
    event_id: Mapped[int] = mapped_column(BigInteger)
    enrolled_fencing: Mapped[int] = mapped_column(Integer)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(32), default="active")
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)


class ZulipMessageIndex(Base):
    __tablename__ = "zulip_message_index"
    realm_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    message_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    binding_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("bindings.id"))
    state: Mapped[str] = mapped_column(String(32))
    input_event_id: Mapped[str] = mapped_column(String(36), ForeignKey("input_events.id"))
    version: Mapped[int] = mapped_column(Integer, default=1)


class ZulipReceiptRetry(Base):
    __tablename__ = "zulip_receipt_retries"
    input_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("input_events.id"), primary_key=True
    )
    retry_at: Mapped[float] = mapped_column(Float, index=True)
