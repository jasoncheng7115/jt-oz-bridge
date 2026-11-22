import time

from sqlalchemy import BigInteger, Boolean, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.models import Base, uid


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    binding_id: Mapped[str] = mapped_column(String(36), index=True)
    binding_revision: Mapped[int] = mapped_column(Integer)
    realm_id: Mapped[str] = mapped_column(String(255))
    project_id: Mapped[str] = mapped_column(String(255))
    actor_id: Mapped[int] = mapped_column(BigInteger)
    source_message_id: Mapped[int | None] = mapped_column(BigInteger)
    kind: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default="staging", index=True)
    reserved_bytes: Mapped[int] = mapped_column(BigInteger)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    checksum: Mapped[str | None] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(32))
    action_id: Mapped[str | None] = mapped_column(String(36), index=True)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    expires_at: Mapped[float] = mapped_column(Float, index=True)


class ArtifactBudget(Base):
    __tablename__ = "artifact_budgets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    reserved_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    object_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
