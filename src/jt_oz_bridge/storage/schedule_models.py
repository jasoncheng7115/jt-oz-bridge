"""Confirmed repeating prompts; each send is an ordinary prompt Action of the person."""

from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base, uid


class PromptSchedule(Base):
    __tablename__ = "prompt_schedules"
    __table_args__ = (
        CheckConstraint(
            "state IN ('active','completed','cancelled')", name="ck_prompt_schedule_state"
        ),
        CheckConstraint(
            "sent >= 0 AND skipped >= 0 AND sent + skipped <= total",
            name="ck_prompt_schedule_counts",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    # One schedule per confirmation token; a repeated `!confirm` finds this row.
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    binding_id: Mapped[str] = mapped_column(String(36), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    realm_id: Mapped[str] = mapped_column(String(255))
    actor_id: Mapped[int] = mapped_column(BigInteger)
    source_message_id: Mapped[int] = mapped_column(BigInteger)
    # The original Human source, the ask it gives and the reply language.
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("prompt_schedules", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))
    interval_seconds: Mapped[int] = mapped_column(Integer)
    starts_at: Mapped[float] = mapped_column(Float)
    ends_at: Mapped[float] = mapped_column(Float)
    next_at: Mapped[float] = mapped_column(Float, index=True)
    total: Mapped[int] = mapped_column(Integer)
    sent: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[str] = mapped_column(String(32), index=True)
    status_reason: Mapped[str | None] = mapped_column(String(128))
    last_action_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("actions.id"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[float] = mapped_column(Float)
