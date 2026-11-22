"""Derive a new Root's expected policy from an explicit administrator template.

Fresh API facts must match an already approved source fingerprint. This neither
certifies a backend protocol, grants users, creates a session nor changes Native.
"""

import time
from collections import OrderedDict
from typing import Any, Literal, Self

from pydantic import Field, StrictBool, model_validator

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.project_policy import (
    PERMISSION_SOURCE,
    POLICY_READS,
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import RootCreationTemplate, SessionCreationIntent
from jt_oz_bridge.storage.durable import digest


class CreationPolicyTemplate(ControlModel):
    format: Literal["native-root-creation-policy-v1"]
    source: NativePolicyEnrollment
    creation: RootCreationTemplate
    operations: frozenset[str] = Field(min_length=1)

    @model_validator(mode="after")
    def approved_subset(self) -> Self:
        reference = self.source.reference
        scope = self.creation.scope
        if (
            (
                reference.backend_id,
                reference.backend_identity,
                reference.project_id,
                reference.canonical_directory,
            )
            != (
                scope.backend_id,
                scope.backend_identity,
                scope.project_id,
                scope.canonical_directory,
            )
            or self.source.native_project_id != self.creation.native_project_id
            or self.source.contract_sha256 != INSTALLED_SCHEMA
            or self.source.permission_source_sha256 != PERMISSION_SOURCE
            or not self.operations <= self.source.operations
        ):
            raise ValueError("creation_template_must_anchor_same_approved_project_and_operations")
        return self

    def checksum(self) -> str:
        # JSON preserves list order, while frozenset iteration changes across
        # processes. Only operation sets are unordered; permission-rule order
        # remains semantically significant and must never be normalized away.
        value = self.model_dump(mode="json")
        value["operations"] = sorted(self.operations)
        value["source"]["operations"] = sorted(self.source.operations)
        return digest(value)


def effective_rules(agent: list[Any], session: list[Any]) -> list[Any]:
    """The rules OpenCode evaluates, agent first, with earlier exact repeats dropped.

    The last matching rule decides, so an earlier copy of a rule that appears again
    later can never decide anything; dropping it keeps every decision unchanged.
    """
    rules = [*agent, *session]
    return [rule for index, rule in enumerate(rules) if rule not in rules[index + 1 :]]


def same_rules(facts: dict[str, Any], source_session: list[Any]) -> bool:
    """A derived Root's rules decide every request as its source session's would.

    Saved approvals could sit between the agent's and the session's rules, so a
    project with any is never treated as equal.
    """
    agent = facts["agent"]["permissions"]
    return not facts["saved_permissions"] and effective_rules(
        agent, source_session
    ) == effective_rules(agent, facts["session_permissions"])


class DerivedCreationPolicy(ControlModel):
    enrollment: NativePolicyEnrollment
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    # Every observed policy fact but the session id equals the enrolled source's,
    # so the source's file-read qualification describes this Root too.
    same_as_source: StrictBool = False


class V2CreationPolicy:
    def __init__(self, anchor: V2ProjectPolicyGuard, template: CreationPolicyTemplate) -> None:
        if anchor.enrollments.get(template.source.reference) != template.source:
            raise ValueError("creation_source_policy_must_already_be_operator_enrolled")
        self.anchor, self.template = anchor, template
        self._issued: OrderedDict[str, tuple[DerivedCreationPolicy, ContractAttestation]] = (
            OrderedDict()
        )

    def selected(self, intent: SessionCreationIntent) -> ContractAttestation:
        source = self.template.source
        transport = self.anchor.proofs.feed.transport
        attestation = transport.attestation
        if (
            intent.scope != self.template.creation.scope
            or self.anchor.enrollments.get(source.reference) != source
            or attestation is None
            or attestation.schema_sha256 != INSTALLED_SCHEMA
            or transport.profile.sha256 != INSTALLED_SCHEMA
            or attestation.backend_identity != intent.scope.backend_identity
            or attestation.upstream_version != "2.0.32"
            or not POLICY_READS <= attestation.verified_operations
        ):
            raise ContractError("creation_policy_anchor_or_installed_contract_changed")
        return attestation

    async def original_owner(self, intent: SessionCreationIntent, epoch: str | None = None) -> str:
        """One Native process per derivation; not the process that created the Root.

        A Native restart after creation must not make the created Root unrestorable.
        """
        self.selected(intent)
        observed = await self.anchor.proofs.feed.current_owner()
        if (
            observed.backend_id != intent.scope.backend_id
            or observed.backend_identity != intent.scope.backend_identity
            or epoch is not None
            and observed.owner_epoch != epoch
            or not 0 <= time.time() - observed.observed_at < 5
        ):
            raise ContractError("creation_policy_original_owner_changed")
        return observed.owner_epoch

    async def derive(self, intent: SessionCreationIntent) -> DerivedCreationPolicy:
        self._issued.pop(intent.intent_id, None)
        attestation = self.selected(intent)
        epoch = await self.original_owner(intent)
        source = self.template.source
        first, _ = await self.anchor._bundle_facts(source.reference)
        second, _ = await self.anchor._bundle_facts(source.reference)
        await self.original_owner(intent, epoch)
        if (
            first != second
            or digest(first) != source.fingerprint_sha256
            or first["agent"]["id"] != self.template.creation.agent_id
            or self.selected(intent) is not attestation
        ):
            raise ContractError("creation_policy_source_drifted_from_operator_approval")
        reference = SessionRef(
            **intent.scope.model_dump(), upstream_session_id=intent.native_session_id
        )
        # Only these two facts are authorized to differ by the administrator's
        # explicit template. Global agent/plugin/saved/MCP policy must stay exact.
        source_rules = first["session_permissions"]
        first["reference"] = reference.model_dump(mode="json")
        first["session_permissions"] = [
            r.model_dump(mode="json") for r in self.template.creation.permissions
        ]
        enrollment = source.model_copy(
            update={
                "reference": reference,
                "fingerprint_sha256": digest(first),
                "operations": self.template.operations,
            }
        )
        result = DerivedCreationPolicy(
            enrollment=enrollment,
            intent_sha256=digest(intent.model_dump(mode="json")),
            template_sha256=self.template.checksum(),
            owner_epoch=epoch,
            observed_at=time.time(),
            same_as_source=same_rules(first, source_rules),
        )
        self._issued[intent.intent_id] = (result, attestation)
        self._issued.move_to_end(intent.intent_id)
        while len(self._issued) > 128:
            self._issued.popitem(last=False)
        return result

    async def current(self, intent: SessionCreationIntent, evidence: DerivedCreationPolicy) -> bool:
        previous = self._issued.get(intent.intent_id)
        if (
            previous is None
            or previous[0] is not evidence
            or evidence.intent_sha256 != digest(intent.model_dump(mode="json"))
            or evidence.template_sha256 != self.template.checksum()
            or not 0 <= time.time() - evidence.observed_at < 5
        ):
            return False
        try:
            await self.original_owner(intent, evidence.owner_epoch)
            facts, _ = await self.anchor._bundle_facts(self.template.source.reference)
            await self.original_owner(intent, evidence.owner_epoch)
            return (
                self._issued.get(intent.intent_id) is previous
                and self.selected(intent) is previous[1]
                and digest(facts) == self.template.source.fingerprint_sha256
                and 0 <= time.time() - evidence.observed_at < 5
            )
        except ValueError:
            return False
