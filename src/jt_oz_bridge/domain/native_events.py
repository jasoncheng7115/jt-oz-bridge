"""Versioned local capture provenance, distinct from the native event object."""

import hashlib
import json
from typing import Any, Literal

from pydantic import Field, StrictInt

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef


class LogProvenance(ControlModel):
    binding_id: str = Field(min_length=1, max_length=255)
    binding_revision: StrictInt = Field(ge=1)
    realm_id: str = Field(min_length=1, max_length=255)
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_epoch: str = Field(min_length=1, max_length=255)
    ownership_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def scope_data(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python", exclude={"ownership_evidence_sha256", "session_info_sha256"}
        )

    def scope_key(self) -> str:
        encoded = json.dumps(
            self.scope_data(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


class QualifiedLogRecord(ControlModel):
    format: Literal["v2-log-capture-v1"] = "v2-log-capture-v1"
    provenance: LogProvenance
    capture_epoch: str = Field(min_length=1, max_length=255)
    native: dict[str, Any]
