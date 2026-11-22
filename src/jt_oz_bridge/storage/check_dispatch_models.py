"""One immutable encrypted pre-send owner witness per existing check Action."""

import time
from typing import Any

from sqlalchemy import Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.models import Base


class CheckDispatchRecord(Base):
    __tablename__ = "check_dispatch_records"
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("actions.id"), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON("check_dispatch_records", "payload")
    )
    payload_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
