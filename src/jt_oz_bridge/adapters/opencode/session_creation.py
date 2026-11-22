"""Fixed new-Root RPC and GET-only reconciliation, outside the bound dispatcher.

The workflow must persist intent/send state and fresh Human/project authority.
This adapter never retries POST, registers a Root, binds a topic or starts a turn.
"""

import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEvidence
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportNotSent,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import (
    CreatedRootObservation,
    NewSessionCandidate,
    RootCreationTemplate,
    SessionCreationIntent,
)
from jt_oz_bridge.storage.durable import digest


class CreationOwner(Protocol):
    async def read(self) -> HostOwnerEvidence: ...


class V2SessionCreation:
    def __init__(
        self,
        transport: V2HTTPTransport,
        owner: CreationOwner,
        templates: Mapping[str, RootCreationTemplate],
    ) -> None:
        if (
            not templates
            or len(templates) > 1000
            or any(key != item.scope.project_id for key, item in templates.items())
            or len({(p.scope.backend_id, p.scope.backend_identity) for p in templates.values()})
            != 1
        ):
            raise ValueError("explicit_single_backend_creation_templates_required")
        for template in templates.values():
            path = template.scope.canonical_directory
            if (
                not path.startswith("/")
                or "\x00" in path
                or ".." in PurePosixPath(path).parts
                or str(PurePosixPath(path)) != path
            ):
                raise ValueError("canonical_creation_directory_required")
        self.transport, self.owner = transport, owner
        self.templates = MappingProxyType(dict(templates))
        self._candidates: OrderedDict[str, tuple[NewSessionCandidate, ContractAttestation]] = (
            OrderedDict()
        )
        self._existing: OrderedDict[str, tuple[CreatedRootObservation, ContractAttestation]] = (
            OrderedDict()
        )
        self._existing_epochs: dict[str, str] = {}

    def selected(self, intent: SessionCreationIntent) -> RootCreationTemplate:
        template = self.templates.get(intent.scope.project_id)
        attestation = self.transport.attestation
        if (
            template is None
            or template.scope != intent.scope
            or attestation is None
            or attestation.backend_identity != intent.scope.backend_identity
            or attestation.schema_sha256 != self.transport.profile.sha256
            or attestation.schema_sha256 != INSTALLED_SCHEMA
            or attestation.upstream_version != "2.0.32"
            or not {"session.create", "session.get"} <= attestation.verified_operations
            or self.transport.verify_identity is None
        ):
            raise ContractError("new_root_project_or_installed_operation_unqualified")
        return template

    async def original_owner(
        self,
        intent: SessionCreationIntent,
        *,
        same_process: bool = True,
        epoch: str | None = None,
    ) -> HostOwnerEvidence:
        """Creation and its pristine readback need the reserving Native process.

        An already created Root only needs one Native process for the whole
        observation (`epoch`): a later Native restart must not strand it or the
        Bridge that restores it.
        """
        self.selected(intent)
        observed = await self.owner.read()
        expected = intent.owner_epoch if same_process else epoch
        if (
            observed.backend_id != intent.scope.backend_id
            or observed.backend_identity != intent.scope.backend_identity
            or expected is not None
            and observed.owner_epoch != expected
            or observed.version != "2.0.32"
            or not 0 <= time.time() - observed.observed_at < 5
        ):
            raise ContractError("new_root_original_owner_changed")
        return observed

    async def live_epoch(self, project_id: str) -> str:
        """The Native process a new reservation is bound to; never an older pin."""
        template = self.templates.get(project_id)
        if template is None:
            raise ContractError("new_root_project_unqualified")
        observed = await self.owner.read()
        if (
            observed.backend_id != template.scope.backend_id
            or observed.backend_identity != template.scope.backend_identity
            or observed.version != "2.0.32"
            or not 0 <= time.time() - observed.observed_at < 5
        ):
            raise ContractError("new_root_original_owner_changed")
        return observed.owner_epoch

    def body(self, intent: SessionCreationIntent) -> dict[str, Any]:
        template = self.selected(intent)
        body: dict[str, Any] = {
            "id": intent.native_session_id,
            "location": {"directory": intent.scope.canonical_directory},
            "agent": template.agent_id,
            "permissions": [rule.model_dump() for rule in template.permissions],
            "metadata": {
                "jt_oz_bridge": {
                    "creation_id": intent.intent_id,
                    "intent_sha256": digest(intent.model_dump(mode="json")),
                }
            },
        }
        if intent.title is not None:
            body["title"] = intent.title
        return body

    def check_info(self, intent: SessionCreationIntent, raw: dict[str, Any]) -> None:
        template = self.selected(intent)
        expected = self.body(intent)
        if (
            raw["id"] != intent.native_session_id
            or raw["projectID"] != template.native_project_id
            or raw["location"] != expected["location"]
            or "parentID" in raw
            or "fork" in raw
            or raw.get("agent") != template.agent_id
            or raw.get("permissions") != expected["permissions"]
            or raw.get("metadata") != expected["metadata"]
            or intent.title is not None
            and raw.get("title") != intent.title
            or "model" in raw
            or "outcome" in raw
            or any(key in raw["time"] for key in ("idle", "archived"))
            or raw["cost"] != 0
            or any(raw["tokens"][key] != 0 for key in ("input", "output", "reasoning"))
            or any(raw["tokens"]["cache"][key] != 0 for key in ("read", "write"))
        ):
            raise ContractError("new_root_creation_or_readback_scope_changed")

    async def observe(self, intent: SessionCreationIntent) -> NewSessionCandidate:
        """GET only; usable for an uncertain committed intent, never recreate it."""
        self._candidates.pop(intent.intent_id, None)
        await self.original_owner(intent)
        attestation = self.transport.attestation
        raw = (
            await self.transport.request(
                "session.get", path={"sessionID": intent.native_session_id}
            )
        )["data"]
        self.check_info(intent, raw)
        await self.original_owner(intent)
        if self.transport.attestation is not attestation or attestation is None:
            raise ContractError("new_root_attestation_changed")
        candidate = NewSessionCandidate(
            intent_id=intent.intent_id,
            reference=SessionRef(**intent.scope.model_dump(), upstream_session_id=raw["id"]),
            intent_sha256=digest(intent.model_dump(mode="json")),
            session_info_sha256=digest(raw),
            native_created_at=raw["time"]["created"],
            owner_epoch=intent.owner_epoch,
            observed_at=time.time(),
        )
        self._candidates[intent.intent_id] = (candidate, attestation)
        self._candidates.move_to_end(intent.intent_id)
        while len(self._candidates) > 128:
            self._candidates.popitem(last=False)
        return candidate

    async def current(self, intent: SessionCreationIntent, candidate: NewSessionCandidate) -> bool:
        value = self._candidates.get(intent.intent_id)
        if (
            value is None
            or value[0] is not candidate
            or value[1] is not self.transport.attestation
            or candidate.intent_sha256 != digest(intent.model_dump(mode="json"))
            or not 0 <= time.time() - candidate.observed_at < 5
        ):
            return False
        try:
            await self.original_owner(intent)
            raw = (
                await self.transport.request(
                    "session.get", path={"sessionID": intent.native_session_id}
                )
            )["data"]
            self.check_info(intent, raw)
            if (
                digest(raw) != candidate.session_info_sha256
                or raw["time"]["created"] != candidate.native_created_at
            ):
                return False
            await self.original_owner(intent)
        except ValueError:
            return False
        return (
            self._candidates.get(intent.intent_id) is value
            and value[1] is self.transport.attestation
            and 0 <= time.time() - candidate.observed_at < 5
        )

    def origin(
        self, intent: SessionCreationIntent, receipt: NewSessionCandidate, raw: dict[str, Any]
    ) -> dict[str, Any]:
        """Match owned creation identity while allowing subsequent Native work.

        Historical receipts are inert data. The caller separately proves their
        durable source/authority; this function cannot promote one into a grant.
        Never relax the pristine check_info used by initial create/readback.
        """
        NewSessionCandidate.model_validate(receipt.model_dump(mode="json"))
        template = self.selected(intent)
        expected = self.body(intent)
        ref = SessionRef(**intent.scope.model_dump(), upstream_session_id=intent.native_session_id)
        if (
            receipt.reference != ref
            or receipt.intent_id != intent.intent_id
            or receipt.intent_sha256 != digest(intent.model_dump(mode="json"))
            or receipt.owner_epoch != intent.owner_epoch
            or raw["id"] != intent.native_session_id
            or raw["projectID"] != template.native_project_id
            or raw["location"] != expected["location"]
            or raw.get("agent") != template.agent_id
            or raw.get("permissions") != expected["permissions"]
            or raw.get("metadata") != expected["metadata"]
            or raw["time"]["created"] != receipt.native_created_at
            or "parentID" in raw
            or "fork" in raw
            or "archived" in raw["time"]
        ):
            raise ContractError("created_root_original_identity_changed")
        return {
            "reference": ref.model_dump(mode="json"),
            "native_project_id": raw["projectID"],
            "created_at": raw["time"]["created"],
            "agent": raw["agent"],
            "permissions": raw["permissions"],
            "metadata": raw["metadata"],
        }

    async def observe_existing(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        *,
        epoch: str | None = None,
    ) -> CreatedRootObservation:
        """GET-only used-Root recovery, never POST/recreate or require pristine usage."""
        self._existing.pop(intent.intent_id, None)
        self._existing_epochs.pop(intent.intent_id, None)
        first = await self.original_owner(intent, same_process=False, epoch=epoch)
        attestation = self.transport.attestation
        values = []
        for _ in range(2):
            raw = (
                await self.transport.request(
                    "session.get", path={"sessionID": intent.native_session_id}
                )
            )["data"]
            values.append(self.origin(intent, receipt, raw))
        await self.original_owner(intent, same_process=False, epoch=first.owner_epoch)
        if (
            values[0] != values[1]
            or self.transport.attestation is not attestation
            or attestation is None
        ):
            raise ContractError("created_root_origin_or_attestation_changed")
        value = CreatedRootObservation(
            reference=receipt.reference,
            intent_sha256=digest(intent.model_dump(mode="json")),
            creation_receipt_sha256=digest(receipt.model_dump(mode="json")),
            origin_sha256=digest(values[1]),
            owner_epoch=intent.owner_epoch,
            native_created_at=receipt.native_created_at,
            observed_at=time.time(),
        )
        self._existing[intent.intent_id] = value, attestation
        self._existing_epochs[intent.intent_id] = first.owner_epoch
        while len(self._existing) > 128:
            dropped, _ = self._existing.popitem(last=False)
            self._existing_epochs.pop(dropped, None)
        return value

    async def recover(
        self, intent: SessionCreationIntent
    ) -> tuple[NewSessionCandidate, CreatedRootObservation]:
        """Read a fixed owned intent after its ACK/readback was lost.

        The journal must prove a committed one-attempt admission and fresh
        explicit recovery authority. This never populates the pristine cache
        or authorizes a create. Immutable origin is checked against repeated
        reads; subsequent title, model and usage changes are not creation drift.
        """
        self._existing.pop(intent.intent_id, None)
        owner = await self.original_owner(intent, same_process=False)
        captured = self.transport.attestation
        raw = (
            await self.transport.request(
                "session.get", path={"sessionID": intent.native_session_id}
            )
        )["data"]
        receipt = NewSessionCandidate(
            intent_id=intent.intent_id,
            reference=SessionRef(**intent.scope.model_dump(), upstream_session_id=raw["id"]),
            intent_sha256=digest(intent.model_dump(mode="json")),
            session_info_sha256=digest(raw),
            native_created_at=raw["time"]["created"],
            owner_epoch=intent.owner_epoch,
            observed_at=time.time(),
        )
        self.origin(intent, receipt, raw)
        observation = await self.observe_existing(intent, receipt, epoch=owner.owner_epoch)
        if (
            self.transport.attestation is not captured
            or not await self.existing_current(intent, receipt, observation)
            or not 0 <= time.time() - receipt.observed_at < 5
        ):
            self._existing.pop(intent.intent_id, None)
            raise ContractError("created_root_recovery_origin_no_longer_current")
        return receipt, observation

    async def existing_current(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        observation: CreatedRootObservation,
    ) -> bool:
        previous = self._existing.get(intent.intent_id)
        if (
            previous is None
            or previous[0] is not observation
            or previous[1] is not self.transport.attestation
            or observation.intent_sha256 != digest(intent.model_dump(mode="json"))
            or observation.creation_receipt_sha256 != digest(receipt.model_dump(mode="json"))
            or not 0 <= time.time() - observation.observed_at < 5
        ):
            return False
        epoch = self._existing_epochs.get(intent.intent_id)
        if epoch is None:
            return False
        try:
            await self.original_owner(intent, same_process=False, epoch=epoch)
            raw = (
                await self.transport.request(
                    "session.get", path={"sessionID": intent.native_session_id}
                )
            )["data"]
            origin = self.origin(intent, receipt, raw)
            await self.original_owner(intent, same_process=False, epoch=epoch)
            return (
                self._existing.get(intent.intent_id) is previous
                and previous[1] is self.transport.attestation
                and digest(origin) == observation.origin_sha256
                and 0 <= time.time() - observation.observed_at < 5
            )
        except ValueError:
            return False

    async def create(
        self, intent: SessionCreationIntent, *, before_send: Callable[[], None]
    ) -> NewSessionCandidate:
        """Caller owns durable exactly-once admission; post-send faults stay uncertain."""
        try:
            body = self.body(intent)
            owner = await self.original_owner(intent)
            captured = self.transport.attestation

            def ready() -> None:
                self.selected(intent)
                if self.transport.attestation is not captured:
                    raise ContractError("new_root_attestation_changed_before_send")
                if not 0 <= time.time() - owner.observed_at < 5:
                    raise ContractError("new_root_owner_check_expired_before_send")
                before_send()

            self.transport.profile.prepare("session.create", body=body)
        except Exception:
            raise MutationNotSent("new_root_preflight_rejected") from None
        try:
            value = await self.transport.request("session.create", body=body, before_send=ready)
        except TransportNotSent:
            raise MutationNotSent("new_root_transport_did_not_send") from None
        self.check_info(intent, value["data"])
        if self.transport.attestation is not captured:
            raise ContractError("new_root_attestation_changed_after_send")
        return await self.observe(intent)
