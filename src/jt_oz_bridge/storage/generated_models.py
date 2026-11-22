"""Own encrypted generated-output intents, pinned before artifact storage."""

import time
from typing import Any

from sqlalchemy import Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class GeneratedOutputRecord(Base):
    __tablename__ = "generated_output_records"
    __table_args__ = (UniqueConstraint("action_id", "output_index"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("actions.id"), index=True)
    output_index: Mapped[int] = mapped_column(Integer)
    reserved_artifact_id: Mapped[str] = mapped_column(String(36), unique=True)
    transfer_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("file_transfers.id"), unique=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("generated_output_records", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class GeneratedCaptureJob(Base):
    __tablename__ = "generated_capture_jobs"
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("actions.id"), primary_key=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    holder: Mapped[str | None] = mapped_column(String(36))
    fencing: Mapped[int | None] = mapped_column(Integer)
    retry_at: Mapped[float] = mapped_column(Float, default=0)
    status_reason: Mapped[str | None] = mapped_column(String(96))
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("generated_capture_jobs", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
