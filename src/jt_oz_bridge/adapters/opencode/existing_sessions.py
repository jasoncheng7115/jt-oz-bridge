"""GET-only observation of an original existing session and its current policy.

No create marker, pristine history or idle state is required. Target session and
agent permissions are observed as-is. This is not an execution qualification or
registration witness: the controller separately proves the original resource
graph and retains Human/project/source authority before adopting any session.
"""

import asyncio
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.info_projection import progress_info
from jt_oz_bridge.adapters.opencode.project_policy import (
    POLICY_READS,
    V2ProjectPolicyGuard,
    _policy_facts,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.existing_sessions import ExistingSessionObservation
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

Authority = Callable[[], Awaitable[bool]]


@dataclass(frozen=True)
class ExistingSessionProtocol:
    """Backend-scope GET evidence supplied by trusted runtime enrollment only."""

    backend_id: str
    backend_identity: str
    schema_sha256: str
    installed_evidence_sha256: str
    operations: frozenset[str]


@dataclass(frozen=True)
class _Observed:
    original: ReferenceType[ExistingSessionObservation]
    attestation: object
    index: object
    task: object
    generation: str


class V2ExistingSessionObserver:
    def __init__(
        self,
        anchor: V2ProjectPolicyGuard,
        protocol: ExistingSessionProtocol,
        reference: SessionRef,
    ) -> None:
        self.anchor, self.protocol, self.reference = anchor, protocol, reference
        self.scope = ProjectScope(**reference.model_dump(exclude={"upstream_session_id"}))
        self._anchor, self._protocol, self._reference = anchor, protocol, reference
        self._proofs, self._feed = anchor.proofs, anchor.proofs.feed
        self._transport, self._owner = self._feed.transport, self._feed.owner
        self._client, self._profile = self._transport.client, self._transport.profile
        self._enrollment = anchor.enrollments.get(reference)
        self._observed: OrderedDict[int, _Observed] = OrderedDict()
        self.require(reference)

    def require(self, target: SessionRef) -> None:
        p, feed = self.protocol, self.anchor.proofs.feed
        enrolled = self.anchor.enrollments.get(self.reference)
        a = feed.transport.attestation
        if (
            self.anchor is not self._anchor
            or self.protocol is not self._protocol
            or self.reference is not self._reference
            or self.anchor.proofs is not self._proofs
            or feed is not self._feed
            or feed.transport is not self._transport
            or feed.owner is not self._owner
            or feed.transport.client is not self._client
            or feed.transport.profile is not self._profile
            or enrolled is not self._enrollment
            or enrolled is None
            or not self.scope.contains(target)
            or not target.upstream_session_id
            or (p.backend_id, p.backend_identity) != (target.backend_id, target.backend_identity)
            or p.schema_sha256 != INSTALLED_SCHEMA
            or enrolled.contract_sha256 != INSTALLED_SCHEMA
            or re.fullmatch(r"[0-9a-f]{64}", p.installed_evidence_sha256) is None
            or type(p.operations) is not frozenset
            or not POLICY_READS <= p.operations
            or a is None
            or a.backend_identity != p.backend_identity
            or a.schema_sha256 != INSTALLED_SCHEMA
            or a.upstream_version != "2.0.32"
            or not p.operations <= a.verified_operations
            or feed.transport.profile.sha256 != INSTALLED_SCHEMA
        ):
            raise ContractError("existing_session_original_backend_read_contract_required")
        self.anchor.proofs.select(self.reference)
        feed.transport.profile.prepare(
            "session.get", path={"sessionID": target.upstream_session_id}
        )

    async def owner(self) -> tuple[str, object, object, str]:
        feed = self._feed
        value = await feed.current_owner()
        self.require(self.reference)
        if (
            (value.backend_id, value.backend_identity)
            != (self.protocol.backend_id, self.protocol.backend_identity)
            or value.version != "2.0.32"
            or not 0 <= time.time() - value.observed_at < 5
            or feed.index is None
            or feed.task is None
        ):
            raise ContractError("existing_session_original_owner_changed")
        return value.owner_epoch, feed.index, feed.task, feed.index.require_live()

    async def peer(self) -> None:
        self.require(self.reference)
        verify = self._transport.verify_identity
        if verify is None or await verify() is not True:
            raise ContractError("existing_session_backend_identity_unverified")
        self.require(self.reference)

    def origin(
        self, target: SessionRef, info: dict[str, Any], parent: SessionRef | None
    ) -> dict[str, Any]:
        enrolled = self.anchor.enrollments[self.reference]
        created = info.get("time", {}).get("created")
        if (
            info.get("id") != target.upstream_session_id
            or info.get("projectID") != enrolled.native_project_id
            or info.get("location") != {"directory": target.canonical_directory}
            or type(created) is not int
            or created < 0
            or info.get("time", {}).get("archived") is not None
            or (
                "parentID" in info
                if parent is None
                else info.get("parentID") != parent.upstream_session_id
            )
        ):
            raise ContractError("existing_session_original_origin_or_parent_changed")
        return {
            "reference": target.model_dump(mode="json"),
            "native_project_id": enrolled.native_project_id,
            "created_at": created,
            "parent_id": parent.upstream_session_id if parent else None,
        }

    async def bundle(
        self, target: SessionRef, parent: SessionRef | None
    ) -> tuple[dict[str, Any], dict[str, Any], str, str]:
        self.require(target)
        t = self._feed.transport
        info = (await t.request("session.get", path={"sessionID": target.upstream_session_id}))[
            "data"
        ]
        origin = self.origin(target, info, parent)
        aid = info.get("agent")
        if not isinstance(aid, str) or not aid:
            raise ContractError("existing_session_explicit_native_agent_required")
        query = {"location": {"directory": target.canonical_directory}}
        agent, plugins, saved, mcp = await asyncio.gather(
            t.request("agent.get", path={"agentID": aid}, query=query),
            t.request("plugin.list", query=query),
            t.request("permission.saved.list", query={"projectID": origin["native_project_id"]}),
            t.request("mcp.list", query=query),
        )
        facts = _policy_facts(
            target,
            origin["native_project_id"],
            info,
            agent,
            plugins,
            saved,
            mcp,
            expected_parent_id=parent.upstream_session_id if parent else None,
        )
        if parent is not None:
            self.require(parent)
            raw_parent = (
                await t.request("session.get", path={"sessionID": parent.upstream_session_id})
            )["data"]
            ancestor = raw_parent.get("parentID")
            # This checks the immediate edge; the graph controller must prove the
            # complete lineage, bounded closure and absence of longer cycles.
            if ancestor == target.upstream_session_id:
                raise ContractError("existing_session_parent_cycle")
            parent_origin = self.origin(
                parent,
                raw_parent,
                None
                if ancestor is None
                else parent.model_copy(update={"upstream_session_id": ancestor}),
            )
            origin["parent_origin_sha256"] = digest(parent_origin)
            origin["parent_created_at"] = parent_origin["created_at"]
        return origin, facts, digest(info), digest(progress_info(info))

    async def observe(
        self,
        target: SessionRef,
        *,
        authorize: Authority,
        parent: SessionRef | None = None,
    ) -> ExistingSessionObservation:
        try:
            async with asyncio.timeout(5):
                return await self._observe(target, authorize=authorize, parent=parent)
        except TimeoutError:
            raise ContractError("existing_session_observation_expired") from None

    async def _observe(
        self, target: SessionRef, *, authorize: Authority, parent: SessionRef | None
    ) -> ExistingSessionObservation:
        self.require(target)
        if parent is not None:
            self.require(parent)
            if parent == target:
                raise ContractError("existing_session_parent_cycle")
        if await authorize() is not True:
            raise ContractError("existing_session_current_authority_required")
        started = time.time()
        context = await self.owner()
        await self.peer()
        transport = self._feed.transport
        attestation = transport.attestation
        anchor_first, _ = await self.anchor._bundle_facts(self.reference)
        first, facts, _, _ = await self.bundle(target, parent)
        second, repeated, info_sha, progress_sha = await self.bundle(target, parent)
        anchor_last, _ = await self.anchor._bundle_facts(self.reference)
        await self.peer()
        after = await self.owner()
        # Keep the original short-circuit order: diagnostics must not add reads
        # or call the final authorizer after an earlier boundary already failed.
        reason = None
        if context != after:
            reason = "owner_context"
        elif transport.attestation is not attestation:
            reason = "attestation_identity"
        elif first != second:
            reason = "target_origin"
        elif facts != repeated:
            reason = "target_policy"
        elif digest(anchor_first) != self.anchor.expected_fingerprint(
            self.reference, "session.adopt"
        ):
            reason = "anchor_fingerprint"
        elif anchor_last != anchor_first:
            reason = "anchor_repeat"
        elif any(facts[k] != anchor_first[k] for k in ("plugins", "saved_permissions", "mcp")):
            reason = "shared_inventory"
        elif not started <= time.time() < started + 5:
            reason = "observation_window"
        elif await authorize() is not True:
            reason = "authority"
        if reason is not None:
            error = ContractError("existing_session_original_observation_changed")
            error.add_note("existing_session_observation_guard=" + reason)
            raise error
        # Authorizer may yield. Keep the original owner/connection and deadline.
        if await self.owner() != context or not started <= time.time() < started + 5:
            raise ContractError("existing_session_observation_expired")
        value = ExistingSessionObservation(
            reference=target,
            native_project_id=first["native_project_id"],
            native_created_at=first["created_at"],
            parent_reference=parent,
            parent_created_at=first.get("parent_created_at"),
            origin_sha256=digest(first),
            policy_sha256=digest(facts),
            session_info_sha256=info_sha,
            progress_info_sha256=progress_sha,
            owner_epoch=context[0],
            observed_at=started,
            expires_at=started + 5,
        )
        now = time.time()
        retained: OrderedDict[int, _Observed] = OrderedDict()
        for key, saved in self._observed.items():
            original = saved.original()
            if original is not None and original.expires_at > now:
                retained[key] = saved
        self._observed = retained
        while len(self._observed) >= 1000:
            self._observed.popitem(last=False)
        self._observed[id(value)] = _Observed(
            weakref(value), attestation, context[1], context[2], context[3]
        )
        if not self.current(value):
            raise ContractError("existing_session_final_observation_expired")
        return value

    def current(self, value: ExistingSessionObservation) -> bool:
        saved, feed = self._observed.get(id(value)), self._feed
        try:
            self.require(value.reference)
            return bool(
                saved
                and saved.original() is value
                and feed.index is saved.index
                and feed.task is saved.task
                and feed.task is not None
                and not feed.task.done()
                and not feed.task.cancelling()
                and feed.index is not None
                and feed.index.require_live() == saved.generation
                and feed.index.owner_epoch == value.owner_epoch
                and feed.transport.attestation is saved.attestation
                and value.observed_at <= time.time() < value.expires_at
            )
        except ValueError:
            return False
