import json
from typing import Any, Literal, Protocol

from pydantic import Field, StrictBool, StrictInt, field_validator

from jt_oz_bridge.domain.control import ControlModel, SessionControl
from jt_oz_bridge.domain.models import Capability, SessionRef


class HumanMessage(ControlModel):
    realm_id: str
    channel_id: StrictInt = Field(gt=0)
    topic: str
    message_id: StrictInt = Field(gt=0)
    revision: StrictInt = Field(ge=0)
    author_id: StrictInt = Field(gt=0)
    text: str = Field(max_length=1000000)
    deleted: StrictBool = False
    is_bot: StrictBool = False


class SourceReader(Protocol):
    async def read(self, realm: str, message_id: int) -> HumanMessage: ...


class Admission(ControlModel):
    status: Literal["admitted", "completed"]
    owner: Literal["bridge", "opencode"] = "opencode"
    upstream_id: str | None = Field(default=None, max_length=255)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def bounded_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode()) > 32768:
                raise ValueError("oversized")
            copied = json.loads(encoded)  # Copy nested evidence before handing it to storage.
            assert isinstance(copied, dict)
            return copied
        except (ValueError, TypeError, RecursionError):
            raise ValueError("invalid_native_admission_details") from None


class MutationRejected(ValueError):
    """A verified upstream response proves the operation was not admitted."""


class MutationNotSent(MutationRejected):
    """The adapter proves no native mutation request was attempted."""


class SteerNotReady(MutationNotSent):
    """Nothing was sent: the session stopped running before a steer could join it.

    The prompt keeps its place in the queue and is sent again, after the full
    authorization, source and Native checks, as an ordinary next message.
    """


class AnswerRejected(MutationRejected):
    """The installed form contract rejected an answer without settling its form."""


class ExecutionClient(SessionControl, Protocol):
    def capabilities(self, reference: SessionRef) -> dict[str, Capability]: ...
    async def submit(
        self, reference: SessionRef, payload: dict[str, Any], action_id: str
    ) -> Admission: ...


# Plain prompts may join a running turn (`delivery: steer`) only from these states.
# RUNNING: an active execution reads the steer at its next step boundary.
# QUEUED: no execution, only pending steers parked by a stop; the post wakes them.
STEER_STATES = frozenset({"running", "queued"})
# A prompt carrying any of these never joins a running turn.
UNSTEERABLE_PAYLOAD = frozenset(
    {
        "attachments",
        "workspace_attachments",
        "_attachment_import",
        "_workspace_attachment_import",
        "schedule",
    }
)
# Proven unsent because the proof moved between the preflight and the wire: the
# send guard, the headers boundary or the body boundary refused it. A fresh
# preflight may hold, so a prompt refused this way is tried again shortly.
SEND_PROOF_MOVED = "v2_native_send_proof_moved"
