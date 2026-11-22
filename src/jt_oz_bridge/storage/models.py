import time
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON


def uid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class InputEvent(Base):
    __tablename__ = "input_events"
    __table_args__ = (UniqueConstraint("source", "source_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(255))
    source_id: Mapped[str] = mapped_column(String(255))
    revision: Mapped[int] = mapped_column(Integer)
    payload_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("input_events", "payload"))
    state: Mapped[str] = mapped_column(String(32), default="received", index=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)

    payload_compacted_at: Mapped[float | None] = mapped_column(Float)
    retention_observed_at: Mapped[float | None] = mapped_column(Float)
    retention_fingerprint: Mapped[str | None] = mapped_column(String(64))


class Checkpoint(Base):
    __tablename__ = "checkpoints"
    source: Mapped[str] = mapped_column(String(255), primary_key=True)
    queue_id: Mapped[str] = mapped_column(String(255))
    event_id: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)


class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    binding_id: Mapped[str] = mapped_column(String(36), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[int] = mapped_column(BigInteger)
    operation_digest: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("actions", "payload"))
    admission: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("actions", "admission"), default=dict
    )
    native_result: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("actions", "native_result"), default=dict
    )
    operation: Mapped[str] = mapped_column(String(128), default="unknown", server_default="unknown")
    state: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    owner: Mapped[str] = mapped_column(String(32), default="bridge", server_default="bridge")
    upstream_id: Mapped[str | None] = mapped_column(String(255))
    status_reason: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)

    payload_compacted_at: Mapped[float | None] = mapped_column(Float)
    retention_observed_at: Mapped[float | None] = mapped_column(Float)
    retention_fingerprint: Mapped[str | None] = mapped_column(String(64))


class Delivery(Base):
    __tablename__ = "deliveries"
    __table_args__ = (
        Index("uq_delivery_batch_position", "batch_id", "batch_index", unique=True),
        CheckConstraint(
            "(destination_id IS NULL AND binding_id IS NOT NULL AND binding_revision IS NOT NULL) OR (destination_id IS NOT NULL AND binding_id IS NULL AND binding_revision IS NULL)",
            name="ck_delivery_authorization_source",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    binding_id: Mapped[str | None] = mapped_column(String(36), index=True)
    binding_revision: Mapped[int | None] = mapped_column(Integer)
    destination_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("output_destinations.id", name="fk_deliveries_output_destination"),
        index=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON("deliveries", "payload"))
    payload_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    posted_message_id: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    retry_at: Mapped[float] = mapped_column(Float, default=0, server_default="0", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")
    status_reason: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[float] = mapped_column(Float, default=time.time, server_default="0")
    batch_id: Mapped[str | None] = mapped_column(String(36))
    batch_index: Mapped[int | None] = mapped_column(Integer)

    payload_compacted_at: Mapped[float | None] = mapped_column(Float)


class DeliveryBatch(Base):
    __tablename__ = "delivery_batches"
    __table_args__ = (
        CheckConstraint(
            "(destination_id IS NULL AND binding_id IS NOT NULL AND binding_revision IS NOT NULL) OR (destination_id IS NOT NULL AND binding_id IS NULL AND binding_revision IS NULL)",
            name="ck_delivery_batch_authorization_source",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    binding_id: Mapped[str | None] = mapped_column(String(36))
    binding_revision: Mapped[int | None] = mapped_column(Integer)
    destination_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("output_destinations.id", name="fk_delivery_batches_output_destination"),
        index=True,
    )
    plan_hash: Mapped[str] = mapped_column(String(64))
    renderer_version: Mapped[str] = mapped_column(String(64))
    message_limit: Mapped[int] = mapped_column(Integer)
    topic_limit: Mapped[int] = mapped_column(Integer)
    page_count: Mapped[int] = mapped_column(Integer)
    priority: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class DeliveryLane(Base):
    __tablename__ = "delivery_lanes"
    realm_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    not_before: Mapped[float] = mapped_column(Float, default=0, server_default="0")
    backoff: Mapped[float] = mapped_column(Float, default=0, server_default="0")


class Grant(Base):
    __tablename__ = "grants"
    __table_args__ = (UniqueConstraint("realm_id", "user_id", "project_id", "role"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    realm_id: Mapped[str] = mapped_column(String(255))
    user_id: Mapped[int] = mapped_column(BigInteger)
    project_id: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class Preference(Base):
    __tablename__ = "preferences"
    principal: Mapped[str] = mapped_column(String(255), primary_key=True)
    locale: Mapped[str] = mapped_column(String(16), default="en")


class WorkerLease(Base):
    __tablename__ = "worker_leases"
    role: Mapped[str] = mapped_column(String(64), primary_key=True)
    holder: Mapped[str] = mapped_column(String(36))
    expires_at: Mapped[float] = mapped_column(Float)
    fencing: Mapped[int] = mapped_column(Integer, default=1)


class AdminAccount(Base):
    __tablename__ = "admin_accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    must_reset: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_id: Mapped[str] = mapped_column(String(36))
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float, index=True)


class AuthThrottle(Base):
    __tablename__ = "auth_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[float] = mapped_column(Float)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor: Mapped[str] = mapped_column(String(255))
    event: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[float] = mapped_column(Float, default=time.time, index=True)


class PayloadKeyCheck(Base):
    __tablename__ = "payload_key_checks"
    key_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary)


class MaintenanceFlag(Base):
    __tablename__ = "maintenance_flags"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    pending: Mapped[bool] = mapped_column(Boolean, default=True)
