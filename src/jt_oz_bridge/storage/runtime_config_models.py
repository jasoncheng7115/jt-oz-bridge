"""Own runtime configuration and independent administrative setting receipts."""

import time
from typing import Any

from sqlalchemy import CheckConstraint, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base, uid


class RuntimeConfigurationState(Base):
    __tablename__ = "runtime_configuration"
    __table_args__ = (
        CheckConstraint("id = 'site'", name="ck_runtime_configuration_singleton"),
        CheckConstraint("revision >= 1", name="ck_runtime_configuration_revision"),
    )
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("runtime_configuration", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))


class RuntimeSettingDecision(Base):
    __tablename__ = "runtime_setting_decisions"
    __table_args__ = (
        UniqueConstraint("admin_id", "client_action_id"),
        CheckConstraint(
            "setting_key IN ('i18n.default_locale','rendering.stream_update_min_interval_ms')",
            name="ck_runtime_setting_key",
        ),
        CheckConstraint(
            "state IN ('pending','confirmed','cancelled')", name="ck_runtime_setting_state"
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    admin_id: Mapped[str] = mapped_column(String(36), ForeignKey("admin_accounts.id"), index=True)
    session_hash: Mapped[str] = mapped_column(String(64))
    client_action_id: Mapped[str] = mapped_column(String(36))
    setting_key: Mapped[str] = mapped_column(String(64))
    configuration_revision: Mapped[int] = mapped_column(Integer)
    holder: Mapped[str] = mapped_column(String(36))
    fencing: Mapped[int] = mapped_column(Integer)
    confirmation_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("runtime_setting_decisions", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
