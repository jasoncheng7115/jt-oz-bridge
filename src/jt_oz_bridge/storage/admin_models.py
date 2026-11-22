"""Web administrative decisions, independent of Zulip Human receipts and tokens."""

import time
from typing import Any

from sqlalchemy import CheckConstraint, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base, uid


class AdminDecision(Base):
    __tablename__ = "admin_decisions"
    __table_args__ = (
        UniqueConstraint("admin_id", "client_action_id"),
        CheckConstraint("operation IN ('pause', 'unbind')", name="ck_admin_decision_operation"),
        CheckConstraint(
            "state IN ('pending', 'confirmed', 'cancelled')", name="ck_admin_decision_state"
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    admin_id: Mapped[str] = mapped_column(String(36), ForeignKey("admin_accounts.id"), index=True)
    session_hash: Mapped[str] = mapped_column(String(64))
    client_action_id: Mapped[str] = mapped_column(String(36))
    operation: Mapped[str] = mapped_column(String(16))
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    queue_revision: Mapped[int] = mapped_column(Integer)
    holder: Mapped[str] = mapped_column(String(36))
    fencing: Mapped[int] = mapped_column(Integer)
    confirmation_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("admin_decisions", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
