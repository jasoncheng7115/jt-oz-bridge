"""Own encrypted live-source evidence, never the Native database or replay log."""

from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class NativeFeedReceipt(Base):
    __tablename__ = "native_feed_receipts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    connection_epoch: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("native_feed_receipts", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    # Own commit time, never a Native timestamp. NULL predates schema37 until the
    # retention sweep first observes the row; it then starts its full horizon.
    recorded_at: Mapped[float | None] = mapped_column(Float, index=True)


class NativeLiveCapture(Base):
    __tablename__ = "native_live_captures"
    __table_args__ = (UniqueConstraint("source_key", "revision"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_key: Mapped[str] = mapped_column(String(64), index=True)
    revision: Mapped[int] = mapped_column(BigInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("native_live_captures", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    # Plain copies of sealed payload scope so retention never decrypts to find a
    # dependency. NULL predates schema37; the sweep backfills from the payload.
    connection_epoch: Mapped[str | None] = mapped_column(String(64), index=True)
    receipt_key: Mapped[str | None] = mapped_column(String(64), index=True)
    recorded_at: Mapped[float | None] = mapped_column(Float, index=True)


class TranscriptLiveDraftPublication(Base):
    __tablename__ = "transcript_live_draft_publications"
    __table_args__ = (UniqueConstraint("live_capture_id", "record_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_version_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcript_versions.id"), index=True
    )
    live_capture_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("native_live_captures.id"), index=True
    )
    observation_revision: Mapped[int] = mapped_column(BigInteger)
    connection_epoch: Mapped[str] = mapped_column(String(64), index=True)
    record_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcript_messages.id"), index=True
    )
    scope_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("transcript_streams.key"), index=True
    )
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    retry_at: Mapped[float] = mapped_column(Float, default=0)
    batch_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), unique=True
    )
    candidate: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("transcript_live_draft_publications", "candidate")
    )
    candidate_hash: Mapped[str] = mapped_column(String(64))
    plan: Mapped[dict[str, Any] | None] = mapped_column(
        EncryptedJSON("transcript_live_draft_publications", "plan")
    )
    plan_hash: Mapped[str | None] = mapped_column(String(64))
