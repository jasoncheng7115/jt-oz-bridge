"""One-attempt file uploads and their atomic, same-binding outbox plans."""

import time
from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class FileTransfer(Base):
    __tablename__ = "file_transfers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), unique=True)
    artifact_id: Mapped[str] = mapped_column(String(36), ForeignKey("artifacts.id"), index=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    realm_id: Mapped[str] = mapped_column(String(255))
    source_message_id: Mapped[int] = mapped_column(BigInteger)
    actor_id: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    holder: Mapped[str | None] = mapped_column(String(36))
    fencing: Mapped[int | None] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    retry_at: Mapped[float] = mapped_column(Float, default=0)
    status_reason: Mapped[str | None] = mapped_column(String(96))
    batch_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), unique=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("file_transfers", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
