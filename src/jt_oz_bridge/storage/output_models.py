import time
from typing import Any

from sqlalchemy import Float, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class OutputDestination(Base):
    __tablename__ = "output_destinations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    realm_id: Mapped[str] = mapped_column(String(255), index=True)
    authorization: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("output_destinations", "authorization")
    )
    authorization_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="active", index=True)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)

    payload_compacted_at: Mapped[float | None] = mapped_column(Float)
