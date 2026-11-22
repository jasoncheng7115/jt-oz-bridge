"""GET-only readback of a Native fork and its source Root's own policy.

OpenCode 2.0.32 (`SessionProjector.projectFork`) stores a fork with
`parent_id: null`, `fork_session_id` = the source session and the boundary, and
copies the source's project, directory, agent, model, metadata and permissions.
So a fork carries `fork` and never `parentID`. Anything else is not a fork this
bridge recognises, and registration stops.

Neither class sends a request that changes Native. A fork is never created,
recreated or retried here, and its policy is never broader than its source's.
"""

import time
from collections.abc import Callable
from typing import Any

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.creation_policy import (
    CreationPolicyTemplate,
    DerivedCreationPolicy,
    V2CreationPolicy,
    same_rules,
)
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import (
    NewSessionCandidate,
    RootCreationTemplate,
    SessionCreationIntent,
)
from jt_oz_bridge.domain.session_fork import ForkedRootIntent
from jt_oz_bridge.storage.durable import digest

FORK_READS = frozenset({"session.get", "session.fork"})
BOUNDARY_TYPES = frozenset({"before", "through"})


def fork_intent(intent: SessionCreationIntent) -> ForkedRootIntent:
    if not isinstance(intent, ForkedRootIntent):
        raise ContractError("forked_root_intent_required")
    return intent


class V2ForkedRootObserver(V2SessionCreation):
    """The creation observer's GET-only recovery path, with a fork's identity."""

    def selected(self, intent: SessionCreationIntent) -> RootCreationTemplate:
        fork_intent(intent)
        template = super().selected(intent)
        attestation = self.transport.attestation
        if attestation is None or not FORK_READS <= attestation.verified_operations:
            raise ContractError("forked_root_installed_operation_unqualified")
        return template

    def body(self, intent: SessionCreationIntent) -> dict[str, Any]:
        raise ContractError("forked_root_is_never_created_by_the_bridge")

    def check_info(self, intent: SessionCreationIntent, raw: dict[str, Any]) -> None:
        # A fork already holds copied history: there is no pristine readback.
        raise ContractError("forked_root_has_no_pristine_readback")

    async def create(
        self, intent: SessionCreationIntent, *, before_send: Callable[[], None]
    ) -> NewSessionCandidate:
        raise MutationNotSent("forked_root_is_never_created_by_the_bridge")

    def origin(
        self, intent: SessionCreationIntent, receipt: NewSessionCandidate, raw: dict[str, Any]
    ) -> dict[str, Any]:
        """The fork's immutable identity; later turns, titles and usage are not drift."""
        NewSessionCandidate.model_validate(receipt.model_dump(mode="json"))
        forked = fork_intent(intent)
        template = self.selected(intent)
        ref = SessionRef(**intent.scope.model_dump(), upstream_session_id=intent.native_session_id)
        fork = raw.get("fork")
        boundary = fork.get("boundary") if isinstance(fork, dict) else None
        if (
            receipt.reference != ref
            or receipt.intent_id != intent.intent_id
            or receipt.intent_sha256 != digest(intent.model_dump(mode="json"))
            or receipt.owner_epoch != intent.owner_epoch
            or raw["id"] != intent.native_session_id
            or raw["projectID"] != template.native_project_id
            or raw["location"] != {"directory": intent.scope.canonical_directory}
            or raw["time"]["created"] != receipt.native_created_at
            or "parentID" in raw
            or "archived" in raw["time"]
            or not isinstance(fork, dict)
            or set(fork) != {"sessionID", "boundary"}
            or fork["sessionID"] != forked.fork_of
            or not isinstance(boundary, dict)
            or set(boundary) != {"type", "messageID"}
            or boundary["type"] not in BOUNDARY_TYPES
            or not isinstance(boundary["messageID"], str)
            or not boundary["messageID"].startswith("msg_")
            or forked.before is not None
            and boundary != {"type": "before", "messageID": forked.before}
        ):
            raise ContractError("forked_root_original_identity_changed")
        return {
            "reference": ref.model_dump(mode="json"),
            "native_project_id": raw["projectID"],
            "created_at": raw["time"]["created"],
            "fork": fork,
        }


class V2ForkPolicy(V2CreationPolicy):
    """A fork's expected policy is its source Root's current one, nothing broader.

    Native copies the source's agent and permissions into the fork. The source
    Root's own enrolled policy must still read back exactly, and the fork may
    only run what both the source Root and the project's creation template allow.
    """

    def __init__(
        self,
        anchor: V2ProjectPolicyGuard,
        template: CreationPolicyTemplate,
        sources: Callable[[SessionRef], object],
    ) -> None:
        super().__init__(anchor, template)
        self.sources = sources
        self._source_facts: dict[str, str] = {}

    def source(self, intent: SessionCreationIntent) -> tuple[SessionRef, V2ProjectPolicyGuard]:
        forked = fork_intent(intent)
        ref = SessionRef(**intent.scope.model_dump(), upstream_session_id=forked.fork_of)
        guard = self.sources(ref)
        if (
            not isinstance(guard, V2ProjectPolicyGuard)
            or ref not in guard.enrollments
            or guard.proofs.feed is not self.anchor.proofs.feed
        ):
            raise ContractError("fork_policy_source_root_not_registered")
        return ref, guard

    async def derive(self, intent: SessionCreationIntent) -> DerivedCreationPolicy:
        self._issued.pop(intent.intent_id, None)
        self._source_facts.pop(intent.intent_id, None)
        attestation = self.selected(intent)
        source_ref, guard = self.source(intent)
        source = guard.enrollments[source_ref]
        epoch = await self.original_owner(intent)
        first, _ = await guard._bundle_facts(source_ref)
        second, _ = await guard._bundle_facts(source_ref)
        anchor, _ = await self.anchor._bundle_facts(self.template.source.reference)
        await self.original_owner(intent, epoch)
        operations = source.operations & self.template.operations
        if (
            first != second
            or digest(first) != source.fingerprint_sha256
            or digest(anchor) != self.template.source.fingerprint_sha256
            or source.native_project_id != self.template.source.native_project_id
            or not operations
            or self.selected(intent) is not attestation
        ):
            raise ContractError("fork_policy_source_drifted_from_its_enrollment")
        reference = SessionRef(
            **intent.scope.model_dump(), upstream_session_id=intent.native_session_id
        )
        source_sha256 = digest(first)
        facts = {**first, "reference": reference.model_dump(mode="json")}
        enrollment = source.model_copy(
            update={
                "reference": reference,
                "fingerprint_sha256": digest(facts),
                "operations": operations,
            }
        )
        unchanged = ("reference", "session_permissions")
        result = DerivedCreationPolicy(
            enrollment=enrollment,
            intent_sha256=digest(intent.model_dump(mode="json")),
            template_sha256=self.template.checksum(),
            owner_epoch=epoch,
            observed_at=time.time(),
            # The source Root's file read describes this Root only when every
            # other policy fact matches the project's enrolled anchor exactly.
            same_as_source=(
                {k: v for k, v in first.items() if k not in unchanged}
                == {k: v for k, v in anchor.items() if k not in unchanged}
                and same_rules(first, anchor["session_permissions"])
            ),
        )
        self._issued[intent.intent_id] = (result, attestation)
        self._source_facts[intent.intent_id] = source_sha256
        self._issued.move_to_end(intent.intent_id)
        while len(self._issued) > 128:
            dropped, _ = self._issued.popitem(last=False)
            self._source_facts.pop(dropped, None)
        return result

    async def current(self, intent: SessionCreationIntent, evidence: DerivedCreationPolicy) -> bool:
        previous = self._issued.get(intent.intent_id)
        expected = self._source_facts.get(intent.intent_id)
        if (
            previous is None
            or expected is None
            or previous[0] is not evidence
            or evidence.intent_sha256 != digest(intent.model_dump(mode="json"))
            or evidence.template_sha256 != self.template.checksum()
            or not 0 <= time.time() - evidence.observed_at < 5
        ):
            return False
        try:
            source_ref, guard = self.source(intent)
            await self.original_owner(intent, evidence.owner_epoch)
            facts, _ = await guard._bundle_facts(source_ref)
            await self.original_owner(intent, evidence.owner_epoch)
            return (
                self._issued.get(intent.intent_id) is previous
                and self._source_facts.get(intent.intent_id) == expected
                and self.selected(intent) is previous[1]
                and digest(facts) == expected
                and 0 <= time.time() - evidence.observed_at < 5
            )
        except ValueError:
            return False
