"""A confirmed Native fork's own Root and topic; never the original session's identity.

The bridge never creates the fork: Native did, once, for one confirmed Action.
Registration only reads that Native session back and binds it to a new topic.
"""

from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import SessionCreationIntent
from jt_oz_bridge.domain.session_lifecycle import MESSAGE_ID

FORK_REGISTRATION = "session.fork.register"
# Native assigns the fork's ID; its installed contract pins the exact format.
NATIVE_SESSION_ID = r"^[^\s/]{1,255}$"


class ForkedRootIntent(SessionCreationIntent):
    """Registration of the one session a confirmed fork returned; never a create."""

    native_session_id: str = Field(pattern=NATIVE_SESSION_ID)
    fork_of: str = Field(pattern=NATIVE_SESSION_ID)
    fork_action_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    # The boundary the person chose, or None when the whole history was copied.
    before: str | None = Field(default=None, pattern=MESSAGE_ID)

    @model_validator(mode="after")
    def another_session(self) -> Self:
        if self.native_session_id == self.fork_of or self.title is not None:
            raise ValueError("fork_registration_requires_a_different_untitled_session")
        return self


class ForkedRootActivation(ControlModel):
    """Owned receipt for one fork topic; current Native and Zulip authority stay separate."""

    format: Literal["forked-root-activation-v1"] = "forked-root-activation-v1"
    reference: SessionRef
    fork_of: SessionRef
    action_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    fork_action_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    scope: BindingScope
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    notice_batch_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    first_prompt_queued: bool
    activated_at: float = Field(ge=0, allow_inf_nan=False)
    native_created_at: StrictInt = Field(ge=0)
    starts_execution: Literal[False] = False

    @model_validator(mode="after")
    def its_own_root(self) -> Self:
        if (
            self.reference == self.fork_of
            or self.scope.reference != self.reference
            or (
                self.reference.backend_id,
                self.reference.backend_identity,
                self.reference.project_id,
                self.reference.canonical_directory,
            )
            != (
                self.fork_of.backend_id,
                self.fork_of.backend_identity,
                self.fork_of.project_id,
                self.fork_of.canonical_directory,
            )
        ):
            raise ValueError("fork_activation_must_bind_a_separate_root_in_the_same_project")
        return self
