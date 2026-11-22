"""Agent-selection inputs, never authority inferred from the metadata catalog.

Full Native definitions remain in memory only while hashing. These DTOs retain
bounded, inert labels and fingerprints, not request/system/permission contents.
No DTO below authorizes a Native write or changes an enrolled policy.
"""

from typing import Literal, Self

from pydantic import Field, StrictBool, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest


class AgentDefinition(ControlModel):
    agent_id: str = Field(min_length=1, max_length=1024)
    label: str = Field(max_length=512)
    mode: Literal["primary", "subagent", "all"]
    hidden: StrictBool
    definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    permissions_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("agent_id")
    @classmethod
    def inert_identity(cls, value: str) -> str:
        if any(
            ord(c) < 32
            or 127 <= ord(c) < 160
            or 0x202A <= ord(c) <= 0x202E
            or 0x2066 <= ord(c) <= 0x2069
            for c in value
        ):
            raise ValueError("agent_identifier_contains_control_character")
        return value

    @property
    def root_selectable(self) -> bool:
        return not self.hidden and self.mode in {"primary", "all"}


class AgentCatalog(ControlModel):
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: tuple[AgentDefinition, ...] = Field(max_length=4096)

    @model_validator(mode="after")
    def unique_visible_agents(self) -> Self:
        if any(item.hidden for item in self.items) or len(
            {item.agent_id for item in self.items}
        ) != len(self.items):
            raise ValueError("agent_catalog_unique_visible_definitions_required")
        return self


class AgentPolicyEndpoint(ControlModel):
    """A complete observed policy plus a full Agent-definition fingerprint.

    Permission rules can differ between endpoints. Equality to one approved
    endpoint is an exact comparison, not a claim that policies are equivalent.
    """

    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    definition: AgentDefinition
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentTransitionEnrollment(ControlModel):
    """Root-managed input for one exact directed transition, inert by default."""

    format: Literal["native-agent-transition-v1"]
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    permission_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before: AgentPolicyEndpoint
    after: AgentPolicyEndpoint
    installed_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def one_original_root(self) -> Self:
        if (
            self.before.reference != self.after.reference
            or self.before.native_project_id != self.after.native_project_id
            or self.before.definition.agent_id == self.after.definition.agent_id
            or not self.after.definition.root_selectable
        ):
            raise ValueError("agent_transition_original_root_and_explicit_target_required")
        return self

    @property
    def enrollment_sha256(self) -> str:
        return digest(self.model_dump(mode="json"))

    def matches(self, before: AgentPolicyEndpoint, after: AgentPolicyEndpoint) -> bool:
        # There is no reverse, wildcard, default or same-permissions fallback.
        return self.before == before and self.after == after


class AgentTransitionPreview(ControlModel):
    """Safe candidate preview facts, not a token, action or mutation grant."""

    before_label: str = Field(max_length=512)
    after_label: str = Field(max_length=512)
    permissions_differ: bool
    may_change_tools_system_or_provider: Literal[True] = True
    requires_original_source_and_authority: Literal[True] = True
    requires_qualified_transition_and_fresh_readback: Literal[True] = True
    starts_execution: Literal[False] = False
    mutation_authorized: Literal[False] = False


class AgentCandidate(ControlModel):
    """A root-enrolled exact target observed now; never authority by itself."""

    endpoint: AgentPolicyEndpoint
    transition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentObservation(ControlModel):
    """One bounded GET-only observation of an original Root, retained safely.

    Equal Agent labels here prove neither who changed them nor when they apply.
    """

    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    native_created_at: float = Field(ge=0, allow_inf_nan=False)
    configured_model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint: AgentPolicyEndpoint
    catalog: AgentCatalog
    candidates: tuple[AgentCandidate, ...] = Field(max_length=4096)
    state: ExecutionState
    settings_tail_ready: StrictBool
    owner_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)

    @property
    def agent_id(self) -> str:
        return self.endpoint.definition.agent_id

    def candidate(self, agent_id: str) -> AgentCandidate | None:
        return next(
            (c for c in self.candidates if c.endpoint.definition.agent_id == agent_id), None
        )


class AgentSwitchAck(ControlModel):
    """A single Native setter acknowledgement; not proof that any step uses it."""

    action_id: str = Field(min_length=1, max_length=36)
    agent_id: str = Field(min_length=1, max_length=1024)
    ack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentReadback(ControlModel):
    """ACK plus exact definition/policy/tail reads; attribution still needs the ACK."""

    observation: AgentObservation
    readback_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentSettingNotice(ControlModel):
    """Details sealed in a setting receipt; it is not a completed provider turn."""

    operation: Literal["agent.switch"] = "agent.switch"
    before_agent_id: str = Field(min_length=1, max_length=1024)
    after_agent_id: str = Field(min_length=1, max_length=1024)
    starts_execution: Literal[False] = False
    turn_completed: Literal[False] = False
