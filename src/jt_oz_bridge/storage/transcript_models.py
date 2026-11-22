"""Bridge-owned transcript observations; no Native database or event cursors."""

from typing import Any

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class TranscriptStream(Base):
    __tablename__ = "transcript_streams"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    binding_id: Mapped[str] = mapped_column(String(36), ForeignKey("bindings.id"), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("transcript_streams", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))


class TranscriptCandidate(Base):
    __tablename__ = "transcript_candidates"
    __table_args__ = (UniqueConstraint("scan_id", "offset"),)
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    native_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    scope_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("transcript_streams.key"), index=True
    )
    offset: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("transcript_candidates", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))


class TranscriptMessage(Base):
    __tablename__ = "transcript_messages"
    __table_args__ = (UniqueConstraint("scope_key", "native_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("transcript_streams.key"), index=True
    )
    native_id: Mapped[str] = mapped_column(String(255))
    ordinal: Mapped[int] = mapped_column(BigInteger, unique=True)
    current_version: Mapped[int] = mapped_column(Integer)
    current_hash: Mapped[str] = mapped_column(String(64))


class TranscriptVersion(Base):
    __tablename__ = "transcript_versions"
    __table_args__ = (UniqueConstraint("record_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    record_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcript_messages.id"), index=True
    )
    version: Mapped[int] = mapped_column(Integer)
    source_action_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("actions.id"))
    context_action_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("actions.id"))
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("transcript_versions", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))


class TranscriptPublication(Base):
    __tablename__ = "transcript_publications"
    version_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcript_versions.id"), primary_key=True
    )
    batch_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("delivery_batches.id"), unique=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("transcript_publications", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))


class TranscriptDraft(Base):
    __tablename__ = "transcript_drafts"
    record_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcript_messages.id"), primary_key=True
    )
    scope_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("transcript_streams.key"), index=True
    )
    finalized: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    terminal_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("transcript_versions.id")
    )
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("transcript_drafts", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))


class TranscriptDraftPublication(Base):
    __tablename__ = "transcript_draft_publications"
    __table_args__ = (UniqueConstraint("source_version_id", "record_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_version_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcript_versions.id"), index=True
    )
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
        EncryptedJSON("transcript_draft_publications", "candidate")
    )
    candidate_hash: Mapped[str] = mapped_column(String(64))
    plan: Mapped[dict[str, Any] | None] = mapped_column(
        EncryptedJSON("transcript_draft_publications", "plan")
    )
    plan_hash: Mapped[str | None] = mapped_column(String(64))
