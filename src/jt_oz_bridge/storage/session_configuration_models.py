"""One authenticated configuration head per original Native Root, never per Binding."""

from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class SessionConfigurationHead(Base):
    __tablename__ = "session_configuration_heads"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="ck_configuration_head_revision"),
        CheckConstraint(
            "phase IN ('stable','dispatching','activation_prepared','quarantined',"
            "'external_unqualified')",
            name="ck_configuration_head_phase",
        ),
        CheckConstraint(
            "(phase IN ('stable','external_unqualified') AND active_action_id IS NULL) OR "
            "(phase IN ('dispatching','activation_prepared','quarantined') "
            "AND active_action_id IS NOT NULL)",
            name="ck_configuration_head_active_action",
        ),
    )
    root_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Prevent a changed origin digest from minting a second head for the same Root.
    # Neither this key nor root_key contains realm, Binding or queue revision.
    root_reference_hash: Mapped[str] = mapped_column(String(64), unique=True)
    revision: Mapped[int] = mapped_column(BigInteger)
    phase: Mapped[str] = mapped_column(String(32))
    active_action_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("actions.id"), unique=True
    )
    last_activation_action_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("actions.id"), unique=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("session_configuration_heads", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[float] = mapped_column(Float)
