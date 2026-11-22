"""Private controller observations, never Native state or mutation authority."""

import hashlib
import json
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef

FORMAT: Literal["jt-oz-runtime-mode-snapshot-v1"] = "jt-oz-runtime-mode-snapshot-v1"
MAX_ROOTS = 1000

type RootMode = Literal[
    "unstarted",
    "strict",
    "readonly-owned-check",
    "readonly-awaiting-idle",
    "unavailable",
    "not-observed",
]
type ModeReason = Literal[
    "startup-incomplete",
    "strict-observation",
    "owned-check-recovery",
    "positive-idle-required",
    "feed-unavailable",
    "diagnostics-unavailable",
    "not-observed",
]
REASONS: dict[RootMode, frozenset[ModeReason]] = {
    "unstarted": frozenset({"startup-incomplete"}),
    "strict": frozenset({"strict-observation"}),
    "readonly-owned-check": frozenset({"owned-check-recovery"}),
    "readonly-awaiting-idle": frozenset({"positive-idle-required"}),
    "unavailable": frozenset({"feed-unavailable", "diagnostics-unavailable"}),
    "not-observed": frozenset({"not-observed"}),
}


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode()
    ).hexdigest()


def scope_key(reference: SessionRef) -> str:
    """Exact full reference correlation; hashing is not anonymization or authority."""
    checked = SessionRef.model_validate(reference.model_dump(mode="json"))
    return canonical_digest(
        {"format": "runtime-mode-scope-v1", "reference": checked.model_dump(mode="json")}
    )


def lease_fingerprint(holder: str, fencing: int) -> str:
    if (
        not isinstance(holder, str)
        or not 1 <= len(holder) <= 128
        or any(ord(c) < 32 or ord(c) == 127 for c in holder)
        or type(fencing) is not int
        or fencing < 1
    ):
        raise ValueError("runtime_mode_lease_identity_invalid")
    return canonical_digest(
        {"format": "runtime-mode-lease-v1", "holder": holder, "fencing": fencing}
    )


class RootModeFact(ControlModel):
    scope_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: RootMode
    reason: ModeReason
    transition_at: float = Field(ge=0, allow_inf_nan=False)
    authority: Literal["diagnostic_only"] = "diagnostic_only"

    @field_validator("transition_at", mode="before")
    @classmethod
    def real_timestamp(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("runtime_mode_timestamp_must_be_float")
        return value

    @model_validator(mode="after")
    def coherent_reason(self) -> Self:
        if self.reason not in REASONS[self.mode]:
            raise ValueError("runtime_mode_reason_mismatch")
        return self


class ConsumerLeaseObservation(ControlModel):
    """Caller-supplied current read-only lease metadata, not a consumer fence."""

    lease_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)

    @field_validator("observed_at", "expires_at", mode="before")
    @classmethod
    def real_timestamp(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("runtime_mode_timestamp_must_be_float")
        return value


class RuntimeModeSnapshot(ControlModel):
    format: Literal["jt-oz-runtime-mode-snapshot-v1"] = FORMAT
    generated_at: float = Field(ge=0, allow_inf_nan=False)
    lease_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    roots: tuple[RootModeFact, ...] = Field(max_length=MAX_ROOTS)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("generated_at", mode="before")
    @classmethod
    def real_timestamp(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("runtime_mode_timestamp_must_be_float")
        return value

    def content(self) -> dict[str, object]:
        return {
            "format": self.format,
            "generated_at": self.generated_at,
            "lease_fingerprint": self.lease_fingerprint,
            "roots": [root.model_dump(mode="json") for root in self.roots],
        }

    @model_validator(mode="after")
    def coherent_snapshot(self) -> Self:
        keys = [root.scope_key for root in self.roots]
        if keys != sorted(set(keys)):
            raise ValueError("runtime_mode_duplicate_or_unordered_roots")
        if any(root.transition_at > self.generated_at for root in self.roots):
            raise ValueError("runtime_mode_future_transition")
        if canonical_digest(self.content()) != self.content_sha256:
            raise ValueError("runtime_mode_content_hash_mismatch")
        return self

    @classmethod
    def create(
        cls, *, generated_at: float, lease_fingerprint: str, roots: tuple[RootModeFact, ...]
    ) -> Self:
        if type(roots) is not tuple or len(roots) > MAX_ROOTS:
            raise ValueError("runtime_mode_root_capacity")
        if any(type(root) is not RootModeFact for root in roots):
            raise ValueError("runtime_mode_root_invalid")
        content = {
            "format": FORMAT,
            "generated_at": generated_at,
            "lease_fingerprint": lease_fingerprint,
            "roots": [
                root.model_dump(mode="json") for root in sorted(roots, key=lambda r: r.scope_key)
            ],
        }
        return cls.model_validate(content | {"content_sha256": canonical_digest(content)})
