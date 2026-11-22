"""Explicit original-session lifecycle requests and non-execution outcomes."""

from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.commands import parse_input


class SessionRename(ControlModel):
    previous_title: str = Field(max_length=4096)
    target_title: str = Field(min_length=1, max_length=512)

    @field_validator("target_title")
    @classmethod
    def explicit_single_line_title(cls, value: str) -> str:
        if (
            value != value.strip()
            or value.splitlines() != [value]
            or any(
                ord(c) < 32
                or 127 <= ord(c) < 160
                or 0x202A <= ord(c) <= 0x202E
                or 0x2066 <= ord(c) <= 0x2069
                for c in value
            )
        ):
            raise ValueError("session_rename_requires_nonblank_single_line_title")
        return value


class SessionRenameOutcome(ControlModel):
    operation: Literal["session.rename"] = "session.rename"
    change: SessionRename
    observed_title: str = Field(min_length=1, max_length=512)
    owner_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    starts_execution: Literal[False] = False
    turn_completed: Literal[False] = False

    @model_validator(mode="after")
    def original_title_read_back(self) -> Self:
        if self.change.target_title != self.observed_title:
            raise ValueError("session_rename_readback_mismatch")
        return self


# Explicit controls that need a preview and !confirm. Native 2.0.32 has no route
# that sets `time.archived` on a session, so archive/unarchive are absent here.
LifecycleOperation = Literal[
    "session.fork",
    "session.compact",
    "session.revert.stage",
    "session.revert.clear",
    "session.revert.commit",
]
LIFECYCLE_COMMANDS: dict[str, str] = {
    "session.fork": "fork",
    "session.compact": "compact",
    "session.revert.stage": "revert",
    "session.revert.clear": "revert",
    "session.revert.commit": "revert",
}
LIFECYCLE_OPERATIONS = frozenset(LIFECYCLE_COMMANDS)
LIFECYCLE_MENU_TOKEN = "session-lifecycle-menu"
LIFECYCLE_CONFIRM_TOKEN = "session-lifecycle-confirm"
LIFECYCLE_TOKEN_KINDS = (LIFECYCLE_MENU_TOKEN, LIFECYCLE_CONFIRM_TOKEN)
MESSAGE_ID = r"^msg_[^\s]{1,250}$"


class SessionMessageChoice(ControlModel):
    message_id: str = Field(pattern=MESSAGE_ID)
    preview: str = Field(max_length=240)


class SessionLifecycleChange(ControlModel):
    """The one effect a person previewed; the wire body comes only from these fields."""

    operation: LifecycleOperation
    message_id: str | None = Field(default=None, pattern=MESSAGE_ID)
    message_preview: str = Field(default="", max_length=240)
    files: bool = False
    pending_revert_message_id: str | None = Field(default=None, pattern=MESSAGE_ID)

    @model_validator(mode="after")
    def exact_shape(self) -> Self:
        needs_message = {"session.revert.stage": True, "session.fork": None}.get(
            self.operation, False
        )
        if (
            (needs_message is True and self.message_id is None)
            or (needs_message is False and self.message_id is not None)
            or (self.files and self.operation != "session.revert.stage")
            or (
                self.operation in {"session.revert.clear", "session.revert.commit"}
                and self.pending_revert_message_id is None
            )
            or (self.operation == "session.compact" and self.pending_revert_message_id is not None)
        ):
            raise ValueError("session_lifecycle_change_shape_invalid")
        return self

    def wire_body(self) -> dict[str, Any] | None:
        if self.operation == "session.fork":
            return {"before": self.message_id} if self.message_id else {}
        if self.operation == "session.compact":
            # The Native default steers a running turn; a bridge request only runs idle.
            return {"delivery": "queue"}
        if self.operation == "session.revert.stage":
            return {"messageID": self.message_id, "files": self.files}
        return None


class SessionLifecycleRequest(ControlModel):
    """One durable confirmed Action; `source` is the !confirm, previews what it confirms."""

    operation: LifecycleOperation
    reference: SessionRef
    source: HumanMessage
    preview_sources: tuple[HumanMessage, ...] = Field(min_length=1, max_length=2)
    change: SessionLifecycleChange
    reply_locale: Literal["en", "zh-TW"]
    confirm_expires_at: float = Field(gt=0, allow_inf_nan=False)
    confirmation_token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def one_person_one_topic(self) -> Self:
        messages = (self.source, *self.preview_sources)
        first, *menu_choice = self.preview_sources
        opening = parse_input(first.text, bound=True)
        confirmed = parse_input(self.source.text, bound=True)
        if (
            self.change.operation != self.operation
            or (confirmed.kind, confirmed.command, confirmed.arguments.strip())
            != ("command", "confirm", "")
            or (opening.kind, opening.command) != ("command", LIFECYCLE_COMMANDS[self.operation])
            or any(parse_input(m.text, bound=True).command != "choose" for m in menu_choice)
            or len({m.message_id for m in messages}) != len(messages)
            or any(m.is_bot or m.deleted or m.revision != 0 for m in messages)
            or len({(m.realm_id, m.channel_id, m.topic, m.author_id) for m in messages}) != 1
        ):
            raise ValueError("session_lifecycle_original_human_sources_required")
        return self


class SessionLifecycleOutcome(ControlModel):
    """What Native acknowledged and the bridge read back. No claim about later work."""

    operation: LifecycleOperation
    change: SessionLifecycleChange
    session_id: str = Field(min_length=1, max_length=255)
    new_session_id: str | None = Field(default=None, min_length=1, max_length=255)
    native_request_id: str | None = Field(default=None, min_length=1, max_length=255)
    owner_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    turn_completed: Literal[False] = False

    @model_validator(mode="after")
    def effect_identity(self) -> Self:
        if (
            self.change.operation != self.operation
            or (self.operation == "session.fork") != (self.new_session_id is not None)
            or self.new_session_id == self.session_id
            or (self.operation == "session.compact") != (self.native_request_id is not None)
        ):
            raise ValueError("session_lifecycle_outcome_identity_invalid")
        return self
