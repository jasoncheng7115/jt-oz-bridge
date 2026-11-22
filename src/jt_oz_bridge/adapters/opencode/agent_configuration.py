"""One in-memory readiness pointer for durable Root configuration heads.

SQL holds the journal. This cell only says which already committed configuration
the running process has proven, and it can withhold mutations. It never sends a
Native request, and an unmanaged Root keeps its original enrolled policy behavior.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal
from weakref import WeakSet

from jt_oz_bridge.adapters.opencode.agent_settings import AgentSettingsAttestation
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import Conflict

type ReadinessMode = Literal["mutation_ready", "read_only"]
# Fixed labels only: readable by status text, never Native or Source content.
type ReadinessReason = Literal[
    "transition",
    "review_required",
    "external_change",
    "activation_unverified",
    "native_unverified",
]


@dataclass(frozen=True, eq=False)
class ConfigurationReadiness:
    reference: SessionRef
    root_key: str
    revision: int
    effective_sha256: str
    agent_id: str
    policy_sha256: str
    mode: ReadinessMode
    reason: ReadinessReason | None = None

    def __post_init__(self) -> None:
        if (self.mode == "mutation_ready") != (self.reason is None):
            raise ValueError("configuration_readiness_reason_required_when_read_only")


@dataclass(frozen=True, eq=False)
class PreparedReadiness:
    value: ConfigurationReadiness
    _base: Mapping[SessionRef, ConfigurationReadiness]


class AgentConfigurationCell:
    """Loop-owned pointer: publication is synchronous, with no await or I/O."""

    def __init__(self, attestations: Mapping[SessionRef, AgentSettingsAttestation]) -> None:
        if any(ref != item.reference for ref, item in attestations.items()):
            raise ValueError("agent_configuration_exact_root_attestation_required")
        self._attestations = MappingProxyType(dict(attestations))
        self._state: Mapping[SessionRef, ConfigurationReadiness] = MappingProxyType({})
        self._issued: WeakSet[PreparedReadiness] = WeakSet()

    def attestation(self, reference: SessionRef) -> AgentSettingsAttestation | None:
        return self._attestations.get(reference)

    def readiness(self, reference: SessionRef) -> ConfigurationReadiness | None:
        return self._state.get(reference)

    def prepare(self, value: ConfigurationReadiness) -> PreparedReadiness:
        if value.reference not in self._attestations:
            raise Conflict("agent_configuration_root_not_enrolled")
        previous = self._state.get(value.reference)
        if previous is not None and (
            previous.root_key != value.root_key or value.revision < previous.revision
        ):
            raise Conflict("agent_configuration_revision_regressed")
        candidate = PreparedReadiness(value, self._state)
        self._issued.add(candidate)
        return candidate

    def publish(self, candidate: PreparedReadiness) -> ConfigurationReadiness:
        if candidate not in self._issued:
            raise Conflict("agent_configuration_candidate_not_issued")
        self._issued.discard(candidate)
        if self._state is not candidate._base:
            raise Conflict("agent_configuration_predecessor_changed")
        value = candidate.value
        self._state = MappingProxyType(dict(self._state) | {value.reference: value})
        return value

    def set(self, value: ConfigurationReadiness) -> ConfigurationReadiness:
        return self.publish(self.prepare(value))

    def policy_sha256(self, reference: SessionRef, original: str, operation: str) -> str:
        """Current approved fingerprint; read-only Roots refuse all but the setter."""
        saved = self._state.get(reference)
        if saved is None:
            return original
        if saved.mode != "mutation_ready" and operation != "agent.switch":
            raise ContractError("native_agent_configuration_not_mutation_ready")
        return saved.policy_sha256

    def mutation_ready(self, reference: SessionRef) -> bool:
        saved = self._state.get(reference)
        return saved is None or saved.mode == "mutation_ready"

    def fence_value(self, reference: SessionRef) -> dict[str, object] | None:
        saved = self._state.get(reference)
        if saved is None:
            return None
        return {
            "root_key": saved.root_key,
            "revision": saved.revision,
            "effective_sha256": saved.effective_sha256,
            "mode": saved.mode,
        }
