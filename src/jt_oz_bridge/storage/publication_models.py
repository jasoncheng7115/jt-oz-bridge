"""Immutable native publication and cross-batch positive-evidence dependencies."""

import time
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class NativePublication(Base):
    __tablename__ = "native_publications"
    __table_args__ = (
        CheckConstraint(
            "(state IN ('queued','needs_full_output') AND batch_id IS NOT NULL) OR (state IN ('history','empty','recovery') AND batch_id IS NULL AND previous_batch_id IS NULL)",
            name="ck_native_publication_output",
        ),
    )
    input_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("native_projection_records.input_event_id"), primary_key=True
    )
    ordinal: Mapped[int] = mapped_column(BigInteger, index=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    source_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32))
    batch_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), unique=True
    )
    previous_batch_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("delivery_batches.id")
    )
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("native_publications", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))


class BatchDependency(Base):
    __tablename__ = "batch_dependencies"
    __table_args__ = (
        CheckConstraint("batch_id <> before_batch_id", name="ck_batch_dependency_not_self"),
    )
    batch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), primary_key=True
    )
    before_batch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("batch_dependencies", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))


class ModelSettingPublication(Base):
    """Generic non-executing setting admission seal and atomic batch pointer.

    Historical SQL/class name is retained; model switches and session title
    changes share this structure, with strict operation-specific publishers.
    No raw model configuration or admission details are stored in this index.
    """

    __tablename__ = "model_setting_publications"
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("actions.id"), primary_key=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    source_hash: Mapped[str] = mapped_column(String(64))
    batch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), unique=True
    )
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
