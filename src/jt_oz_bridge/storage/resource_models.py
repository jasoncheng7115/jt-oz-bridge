"""Bridge-owned resource result indices; ordinals are never Native cursors."""

import time
from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class ResourceResultRecord(Base):
    __tablename__ = "resource_result_records"
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("actions.id"), primary_key=True)
    ordinal: Mapped[int] = mapped_column(BigInteger, unique=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    source_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class ResourceTextRecord(Base):
    __tablename__ = "resource_text_records"
    __table_args__ = (UniqueConstraint("action_id", "part_index"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("resource_result_records.action_id"), index=True
    )
    ordinal: Mapped[int] = mapped_column(BigInteger, unique=True)
    part_index: Mapped[int] = mapped_column(Integer)
    source_hash: Mapped[str] = mapped_column(String(64))


class ResourcePublication(Base):
    __tablename__ = "resource_publications"
    action_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("resource_result_records.action_id"), primary_key=True
    )
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    source_hash: Mapped[str] = mapped_column(String(64))
    batch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), unique=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("resource_publications", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
