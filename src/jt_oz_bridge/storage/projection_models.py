"""Bridge-owned ordered native capture and encrypted semantic projection."""

from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class NativeLogIndex(Base):
    __tablename__ = "native_log_index"
    __table_args__ = {"sqlite_autoincrement": True}
    ordinal: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    input_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("input_events.id"), unique=True
    )
    source: Mapped[str] = mapped_column(String(255), index=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    scope_key: Mapped[str] = mapped_column(String(64), index=True)
    native_sequence: Mapped[int | None] = mapped_column(BigInteger)
    capture_epoch: Mapped[str] = mapped_column(String(255))


class NativeProjection(Base):
    __tablename__ = "native_projections"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    binding_id: Mapped[str] = mapped_column(String(36), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(255))
    semantics_sha256: Mapped[str] = mapped_column(String(64))
    last_ordinal: Mapped[int] = mapped_column(BigInteger)
    version: Mapped[int] = mapped_column(Integer, default=1)
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("native_projections", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))


class NativeProjectionRecord(Base):
    __tablename__ = "native_projection_records"
    input_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("input_events.id"), primary_key=True
    )
    ordinal: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("native_log_index.ordinal"), unique=True
    )
    scope_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("native_projections.key"), index=True
    )
    native_type: Mapped[str] = mapped_column(String(255), index=True)
    native_inbox_id: Mapped[str | None] = mapped_column(String(255), index=True)
    window_key: Mapped[str | None] = mapped_column(String(64), index=True)
    assistant_message_id: Mapped[str | None] = mapped_column(String(255), index=True)
    part_ordinal: Mapped[int | None] = mapped_column(BigInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("native_projection_records", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
