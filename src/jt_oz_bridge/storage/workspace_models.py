"""Reserved ordinary workspace bytes; independent from encrypted artifacts."""

import time
from typing import Any

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class WorkspaceBudget(Base):
    __tablename__ = "workspace_budgets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    reserved_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    object_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class WorkspacePublication(Base):
    __tablename__ = "workspace_publications"
    __table_args__ = (UniqueConstraint("namespace_sha256", "action_id", "artifact_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    namespace_sha256: Mapped[str] = mapped_column(String(64), index=True)
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("actions.id"), index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), ForeignKey("artifacts.id"), index=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    reserved_bytes: Mapped[int] = mapped_column(BigInteger)
    version: Mapped[int] = mapped_column(Integer, default=1)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("workspace_publications", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
