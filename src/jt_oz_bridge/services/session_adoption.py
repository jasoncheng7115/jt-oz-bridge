"""Current Human adoption and explicit startup restoration of original sessions.

This controller registers original readers and durable identities only. Catalog
and binding composition must call it before offering an unregistered session;
this module cannot issue a prompt, create a session or manufacture a Source.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
from jt_oz_bridge.domain.control import AudienceSnapshot, ExecutionState, SessionSnapshot
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.backend_registry import BackendRegistry
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.existing_session_factory import (
    PreparedExistingGraph,
    V2ExistingSessionFactory,
)
from jt_oz_bridge.services.existing_session_updates import (
    OriginalSessionGraphUpdates,
    PreparedSessionGraphUpdate,
)
from jt_oz_bridge.services.session_graph_generations import (
    PreparedGraphGeneration,
    SessionGraphGeneration,
)
from jt_oz_bridge.services.session_registration_journal import (
    LockedAuthority,
    RegistrationReceipt,
    SavedSessionRegistration,
    SessionRegistrationJournal,
    registration_identity,
)
from jt_oz_bridge.services.session_registry import RegisteredSession
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant


class ObservedOriginalSelection:
    """Issuer-owned Native witness, not Source or write authority.

    Only commit_observed accepts the separately closed Source permit. Merely
    holding this handle or its snapshot cannot authorize a registration.
    """

    __slots__ = ("_owner", "__weakref__")

    def __init__(self, owner: "SessionAdoptionService") -> None:
        self._owner = owner

    @property
    def snapshot(self) -> SessionSnapshot:
        return self._owner._observed(self).snapshot

    @property
    def selection(self) -> ExistingSessionSelection:
        return self._owner._observed(self).selection

    def require_current(self) -> None:
        self._owner._observed(self)


@dataclass
class _ObservedSelection:
    task: object
    message: HumanMessage
    audience: AudienceSnapshot
    reader: ZulipSourceReader
    permit: ZulipLocalWritePermit
    selection: ExistingSessionSelection
    snapshot: SessionSnapshot
    factory: V2ExistingSessionFactory
    check: Callable[[], None]
    expires_at: float
    candidate: PreparedExistingGraph | None = None
    publication: PreparedGraphGeneration | None = None
    update: PreparedSessionGraphUpdate | None = None
    previous: SavedSessionRegistration | None = None
    write_started: bool = False
    used: bool = False
    committed: bool = False
    published: object | None = None


class SessionAdoptionService:
    def __init__(
        self,
        bindings: BindingService,
        reader: SourceReader,
        fence: ConsumerFence,
        factories: Mapping[str, V2ExistingSessionFactory],
    ) -> None:
        if (
            not factories
            or len(factories) > 1000
            or any(
                key != factory.policy.anchor.project_id or not self.routed(bindings, factory)
                for key, factory in factories.items()
            )
        ):
            raise ValueError("original_session_adoption_registry_composition_required")
        self.bindings, self.reader = bindings, reader
        self.factories = MappingProxyType(dict(factories))
        self.journal = SessionRegistrationJournal(bindings.db, fence)
        self.updates = MappingProxyType(
            {
                project: OriginalSessionGraphUpdates(factory)
                for project, factory in factories.items()
                if factory.lineage is not None and factory.lineage.qualification_scope == "tree"
            }
        )
        self._gate = asyncio.Lock()
        self._observations: WeakKeyDictionary[ObservedOriginalSelection, _ObservedSelection] = (
            WeakKeyDictionary()
        )

    @staticmethod
    def routed(bindings: BindingService, factory: V2ExistingSessionFactory) -> bool:
        control = bindings.control
        if control is factory.registry:
            return True
        if not isinstance(control, BackendRegistry):
            return False
        anchor = factory.policy.anchor
        backend = control.backends.get(anchor.backend_id)
        return (
            backend is not None
            and backend.client is factory.registry
            and backend.identity == anchor.backend_identity
            and backend.contract_sha256 == factory.policy.contract_sha256
            and backend.projects.get(anchor.project_id) == anchor.canonical_directory
        )

    def factory(self, target: SessionRef) -> V2ExistingSessionFactory:
        factory = self.factories.get(target.project_id)
        if (
            factory is None
            or target.model_dump(exclude={"upstream_session_id"})
            != factory.policy.anchor.model_dump(exclude={"upstream_session_id"})
            or not self.routed(self.bindings, factory)
        ):
            raise AccessDenied("original_session_adoption_project_unavailable")
        factory.selected(target)
        return factory

    async def authority(
        self,
        message: HumanMessage,
        target: SessionRef,
        expected: AudienceSnapshot | None = None,
        *,
        operate: bool = True,
    ) -> AudienceSnapshot:
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise AccessDenied("original_session_adoption_source_changed")
        factory = self.factory(target)
        audience = await self.bindings.audience.inspect(
            message.realm_id, message.channel_id, message.topic
        )
        if (
            (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != (message.realm_id, message.channel_id, message.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
            or expected is not None
            and audience != expected
        ):
            raise AccessDenied("original_session_adoption_private_audience_changed")
        async with self.bindings.db.sessions() as session:
            await self.journal.enrollment_scope(
                session, message.realm_id, target, factory.policy.contract_sha256
            )
        await self.bindings.policy.require(
            message.realm_id,
            message.author_id,
            target.project_id,
            Permission.OPERATE if operate else Permission.VIEW,
        )
        await self.bindings.require_audience(audience, target.project_id)
        if await self.reader.read(message.realm_id, message.message_id) != message:
            raise AccessDenied("original_session_adoption_source_changed")
        return audience

    async def lock_grants(
        self,
        session: AsyncSession,
        message: HumanMessage,
        audience: AudienceSnapshot,
        target: SessionRef,
    ) -> None:
        grants = list(
            (
                await session.scalars(
                    select(Grant)
                    .where(
                        Grant.realm_id == message.realm_id,
                        Grant.project_id == target.project_id,
                        Grant.user_id.in_(audience.user_ids),
                        Grant.active.is_(True),
                    )
                    .order_by(Grant.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).all()
        )
        if {g.user_id for g in grants if Permission.VIEW in ROLES.get(g.role, set())} != set(
            audience.user_ids
        ) or not any(
            g.user_id == message.author_id and Permission.OPERATE in ROLES.get(g.role, set())
            for g in grants
        ):
            raise AccessDenied("original_session_adoption_current_grants_changed")

    def current(self, factory: V2ExistingSessionFactory, candidate: PreparedExistingGraph) -> bool:
        if self.factory(candidate.record.root) is not factory:
            raise Conflict("original_session_adoption_factory_changed")
        factory.require(candidate)
        return all(candidate.proofs.current_proof(ref) is not None for ref in candidate.entries)

    async def commit(
        self,
        factory: V2ExistingSessionFactory,
        candidate: PreparedExistingGraph,
        realm_id: str,
        *,
        authorize: Callable[[], Awaitable[bool]],
        lock_authority: LockedAuthority,
        previous: SavedSessionRegistration | None = None,
    ) -> Mapping[SessionRef, RegisteredSession]:
        receipt: RegistrationReceipt | None = None

        async def journal(record: object) -> None:
            nonlocal receipt
            if record is not candidate.record:
                raise Conflict("original_session_adoption_journal_record_changed")
            if await authorize() is not True:
                raise AccessDenied("original_session_adoption_current_authority_required")
            if previous is not None and previous.record.root != candidate.record.root:
                raise Conflict("original_session_recovery_root_changed")
            if (
                previous is not None
                and previous.record.qualification_sha256 != candidate.record.qualification_sha256
            ):
                # prepare_record admitted a legacy head and found the same graph.
                receipt = await self.journal.requalify(
                    previous,
                    candidate.record,
                    lock_authority=lock_authority,
                    current=lambda: self.current(factory, candidate),
                )
            elif (
                previous is not None
                and previous.record.graph_sha256 != candidate.record.graph_sha256
            ):
                receipt = await self.journal.extend(
                    previous,
                    candidate.record,
                    lock_authority=lock_authority,
                    current=lambda: self.current(factory, candidate),
                )
            else:
                receipt = await self.journal.prepare(
                    realm_id,
                    candidate.record,
                    lock_authority=lock_authority,
                    current=lambda: self.current(factory, candidate),
                )

        entries = await factory.commit(candidate, authorize=authorize, before_commit=journal)
        if receipt is None:
            raise Conflict("original_session_adoption_prepared_record_required")
        if await authorize() is not True:
            raise AccessDenied("original_session_adoption_current_authority_required")
        await self.journal.activate(
            receipt,
            lock_authority=lock_authority,
            current=lambda: self.current(factory, candidate),
        )
        if await authorize() is not True:
            raise AccessDenied("original_session_adoption_current_authority_required")
        self.current(factory, candidate)
        return entries

    async def adopt(
        self,
        message: HumanMessage,
        target: SessionRef,
        *,
        expected: ExistingSessionSelection | None = None,
    ) -> Mapping[SessionRef, RegisteredSession]:
        async with self._gate:
            factory = self.factory(target)
            audience = await self.authority(message, target)

            async def authorize() -> bool:
                await self.authority(message, target, audience)
                return True

            async def locked(session: AsyncSession) -> None:
                await self.lock_grants(session, message, audience, target)

            candidate = await factory.prepare(target, authorize=authorize)
            if expected is not None and not expected.matches(candidate.record):
                raise Conflict("original_session_menu_identity_changed")
            return await self.commit(
                factory, candidate, message.realm_id, authorize=authorize, lock_authority=locked
            )

    async def selection(
        self, message: HumanMessage, target: SessionRef
    ) -> ExistingSessionSelection:
        """VIEW-authorized metadata only; no reader enrollment or Native input."""
        factory = self.factory(target)
        audience = await self.authority(message, target, operate=False)

        async def authorize() -> bool:
            await self.authority(message, target, audience, operate=False)
            return True

        observed = await factory.observer.observer.observe(target, authorize=authorize)
        return ExistingSessionSelection.from_observation(
            observed,
            contract_sha256=factory.policy.contract_sha256,
            qualification_sha256=factory.qualification_sha256(),
        )

    def selected_identity(self, selection: ExistingSessionSelection) -> V2ExistingSessionFactory:
        selection = ExistingSessionSelection.model_validate(selection.model_dump(mode="python"))
        factory = self.factory(selection.reference)
        if (
            selection.contract_sha256 != factory.policy.contract_sha256
            or selection.qualification_sha256 != factory.qualification_sha256()
        ):
            raise Conflict("original_session_menu_qualification_changed")
        return factory

    async def prepare_selection(
        self, message: HumanMessage, selection: ExistingSessionSelection
    ) -> Callable[[], bool]:
        factory = self.selected_identity(selection)
        target = selection.reference
        if target not in factory.registry.sessions or factory.owns(target):
            await self.adopt(message, target, expected=selection)
        # Already qualified anchors retain their exact original readers/policies.
        return await self.guard_selection(message, selection)

    async def guard_selection(
        self, message: HumanMessage, selection: ExistingSessionSelection
    ) -> Callable[[], bool]:
        """Fresh identity/resources and a synchronous final fence for local commit."""
        factory = self.selected_identity(selection)
        target = selection.reference
        entry = factory.registry.selected(target)
        if not isinstance(entry.execution, V2ExecutionClient):
            raise Conflict("original_session_selection_native_reader_required")
        execution = entry.execution
        observer = factory.observer.observer
        feed = execution.proofs.feed if isinstance(execution.proofs, V2LeafResourceProofs) else None
        if feed is None or feed is not observer.anchor.proofs.feed:
            raise Conflict("original_session_selection_original_feed_required")
        audience = await self.authority(message, target)

        async def authorize() -> bool:
            await self.authority(message, target, audience)
            return True

        index = feed.index
        if index is None:
            raise Conflict("original_session_selection_original_feed_required")
        fence = index.stream_fence(state_only=True)
        before = await observer.observe(target, authorize=authorize)
        _snapshot, proof = await execution.qualified_snapshot(target)
        after = await observer.observe(target, authorize=authorize)
        for observed in (before, after):
            if (
                ExistingSessionSelection.from_observation(
                    observed,
                    contract_sha256=factory.policy.contract_sha256,
                    qualification_sha256=factory.qualification_sha256(),
                )
                != selection
            ):
                raise Conflict("original_session_menu_identity_changed")
        observed_info = (
            after.progress_info_sha256
            if isinstance(execution.proofs, V2LineageResourceProofs)
            else after.session_info_sha256
        )
        if observed_info is None or proof.session_info_sha256 != observed_info:
            raise Conflict("original_session_selection_resource_identity_changed")

        def current() -> bool:
            self.selected_identity(selection)
            if (
                factory.registry.sessions.get(target) is not entry
                or entry.execution is not execution
                or not observer.current(before)
                or not observer.current(after)
                or feed.index is not index
                or index.stream_fence(state_only=True) != fence
            ):
                raise Conflict("original_session_selection_proof_changed")
            execution.current(target, proof)
            return True

        current()
        return current

    def _observed(self, handle: ObservedOriginalSelection) -> _ObservedSelection:
        value = (
            self._observations.get(handle) if type(handle) is ObservedOriginalSelection else None
        )
        if (
            value is None
            or handle._owner is not self
            or value.task is not asyncio.current_task()
            or self.reader is not value.reader
            or time.monotonic() >= value.expires_at
            or self.selected_identity(value.selection) is not value.factory
        ):
            raise Conflict("original_session_observed_selection_expired_or_replaced")
        value.check()
        return value

    def _phase_permit(
        self, message: HumanMessage, audience: AudienceSnapshot
    ) -> tuple[ZulipSourceReader, ZulipLocalWritePermit]:
        reader = self.reader
        if not isinstance(reader, ZulipSourceReader):
            raise AccessDenied("original_session_actual_source_observation_required")
        permit = reader.scope.local_write_permit(reader, message, audience)
        return reader, permit

    async def _observed_authority(
        self,
        reader: ZulipSourceReader,
        permit: ZulipLocalWritePermit,
        message: HumanMessage,
        audience: AudienceSnapshot,
        target: SessionRef,
        *,
        write: bool = False,
        operate: bool = True,
    ) -> bool:
        def phase() -> None:
            if self.reader is not reader:
                raise AccessDenied("original_session_source_reader_replaced")
            require = (
                reader.scope.require_write_permit if write else reader.scope.require_read_permit
            )
            require(permit, reader, message, audience)
            if (
                message.is_bot
                or message.deleted
                or message.revision != 0
                or not audience.private
                or audience.untrusted_bot_ids
                or message.author_id not in audience.user_ids
                or (audience.realm_id, audience.channel_id, audience.canonical_topic)
                != (message.realm_id, message.channel_id, message.topic)
            ):
                raise AccessDenied("original_session_observed_audience_changed")

        phase()
        factory = self.factory(target)
        async with self.bindings.db.sessions() as session:
            await self.journal.fence.lock(session)
            phase()
            await self.journal.enrollment_scope(
                session, message.realm_id, target, factory.policy.contract_sha256
            )
            phase()
            if operate:
                await self.lock_grants(session, message, audience, target)
            else:
                grants = list(
                    (
                        await session.scalars(
                            select(Grant)
                            .where(
                                Grant.realm_id == message.realm_id,
                                Grant.project_id == target.project_id,
                                Grant.user_id.in_(audience.user_ids),
                                Grant.active.is_(True),
                            )
                            .execution_options(populate_existing=True)
                        )
                    ).all()
                )
                if {
                    g.user_id for g in grants if Permission.VIEW in ROLES.get(g.role, set())
                } != set(audience.user_ids):
                    raise AccessDenied("original_session_adoption_current_grants_changed")
            phase()
        phase()
        if self.factory(target) is not factory:
            raise Conflict("original_session_observed_factory_replaced")
        return True

    async def selection_observed(
        self, message: HumanMessage, target: SessionRef, expected_audience: AudienceSnapshot
    ) -> ExistingSessionSelection:
        """VIEW-only metadata inside the issuer's still-open Source observation."""
        reader, permit = self._phase_permit(message, expected_audience)
        factory = self.factory(target)

        async def authorize() -> bool:
            return await self._observed_authority(
                reader, permit, message, expected_audience, target, operate=False
            )

        await authorize()
        observed = await factory.observer.observer.observe(target, authorize=authorize)
        await authorize()
        if not factory.observer.observer.current(observed):
            raise Conflict("original_session_menu_observation_changed")
        return ExistingSessionSelection.from_observation(
            observed,
            contract_sha256=factory.policy.contract_sha256,
            qualification_sha256=factory.qualification_sha256(),
        )

    async def observe_selection(
        self,
        message: HumanMessage,
        selection: ExistingSessionSelection,
        expected_audience: AudienceSnapshot,
    ) -> ObservedOriginalSelection:
        """Stage GET-only original readers before the final Source half closes."""
        started = time.monotonic()
        reader, permit = self._phase_permit(message, expected_audience)
        factory = self.selected_identity(selection)
        target = selection.reference
        if len(self._observations) >= 1000:
            raise Conflict("original_session_observation_capacity_exceeded")

        # Trusted one-time facade composition precedes every Native/SQL await
        # and the exact assembly pins. It publishes no graph or new reference.
        prior_generation = factory.registry.publication.generation(target)
        updates_owner = self.updates.get(target.project_id)
        if prior_generation is not None and updates_owner is not None:
            if (
                updates_owner.factory is not factory
                or updates_owner.registry is not factory.registry
            ):
                raise Conflict("original_session_observed_updates_composition_changed")
            factory.registry.selected(target)
            updates_owner.attach_registered(only=target)
        control = self.bindings.control
        backend = (
            control.backends.get(target.backend_id)
            if isinstance(control, BackendRegistry)
            else None
        )
        anchor_assembly = self._native_assembly(factory.anchor)
        prior_entries: dict[SessionRef, RegisteredSession] = (
            dict(prior_generation.entries) if prior_generation is not None else {}
        )
        prior_assemblies = {
            ref: self._native_assembly(entry) for ref, entry in prior_entries.items()
        }
        policy_entries = dict(prior_entries)
        policy_entries[factory.anchor.reference] = factory.anchor
        policy_pins = {ref: self._native_policy_pin(entry) for ref, entry in policy_entries.items()}
        own_publication: list[object | None] = [None]
        update: PreparedSessionGraphUpdate | None = None

        def composition() -> None:
            if (
                self.bindings.control is not control
                or backend is not None
                and (
                    not isinstance(control, BackendRegistry)
                    or control.backends.get(target.backend_id) is not backend
                )
            ):
                raise Conflict("original_session_observed_backend_replaced")
            if any(
                a is not b
                for a, b in zip(self._native_assembly(factory.anchor), anchor_assembly, strict=True)
            ):
                raise Conflict("original_session_observed_anchor_assembly_changed")
            for ref, entry in prior_entries.items():
                if factory.registry.sessions.get(ref) is not entry or any(
                    a is not b
                    for a, b in zip(
                        self._native_assembly(entry), prior_assemblies[ref], strict=True
                    )
                ):
                    raise Conflict("original_session_observed_original_assembly_changed")
            published = own_publication[0]
            if published is not None:
                if update is not None:
                    expected_generation = update.prepared.generation
                    if (
                        not isinstance(published, SessionGraphGeneration)
                        or factory.registry.publication.generation(target) is not published
                        or any(
                            getattr(published, name) is not getattr(expected_generation, name)
                            for name in (
                                "record",
                                "entries",
                                "parents",
                                "descendants",
                                "enrollments",
                                "context",
                            )
                        )
                    ):
                        raise Conflict("original_session_observed_proposed_generation_changed")
                    update.context.require()
            for ref, entry in policy_entries.items():
                policy_map, items = policy_pins[ref]
                actual_map, _ = self._native_policy_pin(entry)
                if actual_map is not policy_map:
                    raise Conflict("original_session_observed_policy_view_replaced")
                expected_map = (
                    published.enrollments
                    if update is not None
                    and isinstance(published, SessionGraphGeneration)
                    and ref in published.entries
                    else dict((node, policy) for node, policy, _ in items)
                )
                if set(actual_map) != set(expected_map) or any(
                    actual_map.get(node) is not policy for node, policy in expected_map.items()
                ):
                    raise Conflict("original_session_observed_policy_membership_changed")
                if any(
                    actual_map.get(node) is not policy
                    or getattr(policy, "fingerprint_sha256", None) != fingerprint
                    for node, policy, fingerprint in items
                ):
                    raise Conflict("original_session_observed_original_policy_changed")

        async def authorize() -> bool:
            composition()
            result = await self._observed_authority(
                reader, permit, message, expected_audience, target
            )
            composition()
            return result

        await authorize()
        candidate = None
        publication = None
        previous = None
        if target not in factory.registry.sessions:
            candidate = await factory.prepare(target, authorize=authorize)
            if not selection.matches(candidate.record):
                raise Conflict("original_session_menu_identity_changed")
            publication = await factory.prepare_publication(candidate, authorize=authorize)
            snapshot = factory.registry.staged_snapshot(publication, target)
            original_candidate, original_publication = candidate, publication

            def check() -> None:
                self.current(factory, original_candidate)
                if own_publication[0] is None:
                    factory.registry.require_staged_graph(original_publication)
                elif factory.registry.publication.generation(target) is not own_publication[
                    0
                ] or any(
                    factory.registry.sessions.get(ref) is not entry
                    for ref, entry in original_candidate.entries.items()
                ):
                    raise Conflict("original_session_observed_publication_changed")

        else:
            generation = factory.registry.publication.generation(target)
            if generation is None or generation.root != target:
                raise Conflict("original_session_original_root_required")
            observed = await factory.observer.observe(target, authorize=authorize)
            observed_record = OriginalSessionGraphUpdates._record(factory, observed)
            if not selection.matches(observed_record):
                raise Conflict("original_session_menu_identity_changed")
            refs = {node.reference for node in observed.nodes}
            parents = {node.reference: node.parent_reference for node in observed.nodes}
            same = refs == set(generation.entries) and parents == dict(generation.parents)
            if same:
                historical = generation.record
                original_execution = generation.entries[target].execution
                original_provider = (
                    original_execution.proofs
                    if isinstance(original_execution, V2ExecutionClient)
                    else None
                )
                if historical is None and isinstance(original_provider, V2LineageResourceProofs):
                    historical = OriginalSessionGraphUpdates._record(
                        factory, original_provider.observation
                    )
                if historical is not None and registration_identity(
                    historical
                ) != registration_identity(observed_record):
                    raise Conflict("original_session_registered_identity_changed")
            if not same:
                updates = self.updates.get(target.project_id)
                if updates is None:
                    raise Conflict("original_session_graph_tree_qualification_required")

                async def locked(session: AsyncSession) -> None:
                    reader.scope.require_read_permit(permit, reader, message, expected_audience)
                    await self.lock_grants(session, message, expected_audience, target)
                    reader.scope.require_read_permit(permit, reader, message, expected_audience)

                saved = await self.journal.recovery_records(
                    message.realm_id,
                    target.project_id,
                    lock_authority=locked,
                    current=lambda: self.factory(target) is factory,
                )
                previous = next((item for item in saved if item.record.root == target), None)
                update = (
                    await updates.prepare_initial(target, authorize=authorize)
                    if previous is None
                    else await updates.prepare(target, previous, authorize=authorize)
                )
                if update is None or not selection.matches(update.record):
                    raise Conflict("original_session_graph_update_required")
                snapshot = await updates.qualify_publication(update, authorize=authorize)
                original_update = update

                def check() -> None:
                    updates.require(original_update)
            else:
                entries = dict(generation.entries)
                assemblies = {ref: self._native_assembly(entry) for ref, entry in entries.items()}
                witnesses = {}
                snapshots = {}
                watched: set[int] = set()
                for ref, entry in entries.items():
                    provider = getattr(entry.execution, "proofs", None)
                    if not isinstance(provider, V2LeafResourceProofs):
                        raise Conflict("original_session_original_resource_provider_required")
                    # Attaching the stable facade changes its generation-bound
                    # watch context. Re-prove the complete original provider;
                    # an old certificate or metadata observation is insufficient.
                    if isinstance(provider, V2LineageResourceProofs):
                        if id(provider) not in watched:
                            await provider.watch_graph(authorize=authorize)
                            watched.add(id(provider))
                    else:
                        await authorize()
                        await provider.watch(ref)
                        await authorize()
                for ref, entry in entries.items():
                    await authorize()
                    execution = entry.execution
                    if not isinstance(execution, V2ExecutionClient) or not isinstance(
                        execution.scope_guard, V2ProjectPolicyGuard
                    ):
                        raise Conflict("original_session_selection_native_reader_required")
                    snapshots[ref], witnesses[ref] = await execution.qualified_snapshot(ref)
                    if not snapshots[ref].reconciled or snapshots[ref].state in {
                        ExecutionState.UNKNOWN,
                        ExecutionState.DISCONNECTED,
                    }:
                        raise Conflict("original_session_observed_snapshot_unverified")
                    first = await execution.scope_guard.bundle(ref)
                    second = await execution.scope_guard.bundle(ref)
                    proof = witnesses[ref]
                    if first != second or first[1] != proof.session_info_sha256:
                        raise Conflict("original_session_selection_resource_identity_changed")
                    if set(snapshots[ref].descendants) != set(generation.descendants[ref]):
                        raise Conflict("original_session_selection_lineage_changed")
                after = await factory.observer.observe(target, authorize=authorize)
                if (
                    not selection.matches(OriginalSessionGraphUpdates._record(factory, after))
                    or after.graph_sha256 != observed.graph_sha256
                ):
                    raise Conflict("original_session_menu_identity_changed")
                snapshot = snapshots[target]

                def check() -> None:
                    factory.registry.publication.require_current(target, generation)
                    if not factory.observer.current(observed) or not factory.observer.current(
                        after
                    ):
                        raise Conflict("original_session_selection_observation_changed")
                    for ref, entry in entries.items():
                        if factory.registry.sessions.get(ref) is not entry or any(
                            a is not b
                            for a, b in zip(
                                self._native_assembly(entry), assemblies[ref], strict=True
                            )
                        ):
                            raise Conflict("original_session_selection_original_reader_changed")
                        assert isinstance(entry.execution, V2ExecutionClient)
                        entry.execution.current(ref, witnesses[ref])

        if snapshot.reference != target or not snapshot.reconciled:
            raise Conflict("original_session_observed_snapshot_unverified")
        check()
        await authorize()
        handle = ObservedOriginalSelection(self)
        value = _ObservedSelection(
            asyncio.current_task(),
            message,
            expected_audience,
            reader,
            permit,
            selection,
            snapshot,
            factory,
            check,
            started + 5,
            candidate,
            publication,
            update,
            previous,
        )
        # Publication is recorded synchronously by commit_observed before a
        # subsequent SQL await can inspect this same witness.
        value_published = own_publication
        original_check = value.check

        def final_check() -> None:
            value_published[0] = value.published
            composition()
            original_check()

        value.check = final_check
        self._observations[handle] = value
        handle.require_current()
        return handle

    @staticmethod
    def _native_assembly(entry: RegisteredSession) -> tuple[object, ...]:
        base = OriginalSessionGraphUpdates._assembly(entry)
        execution = entry.execution
        assert isinstance(execution, V2ExecutionClient)
        transport, proofs, guard = execution.transport, execution.proofs, execution.scope_guard
        return base + (
            transport.client,
            transport.profile,
            transport.attestation,
            transport.verify_identity,
            execution.projects,
            execution.selected(entry.reference),
            getattr(getattr(proofs, "feed", None), "owner", None),
            getattr(guard, "proofs", None),
        )

    @staticmethod
    def _native_policy_pin(
        entry: RegisteredSession,
    ) -> tuple[Mapping[SessionRef, object], tuple[tuple[SessionRef, object, object], ...]]:
        execution = entry.execution
        if not isinstance(execution, V2ExecutionClient):
            raise Conflict("original_session_observed_policy_guard_required")
        enrollments = getattr(execution.scope_guard, "enrollments", None)
        if not isinstance(enrollments, Mapping):
            raise Conflict("original_session_observed_policy_view_required")
        return enrollments, tuple(
            (ref, policy, getattr(policy, "fingerprint_sha256", None))
            for ref, policy in enrollments.items()
        )

    async def commit_observed(
        self, handle: ObservedOriginalSelection, *, mark_write_started: Callable[[], None]
    ) -> None:
        """Only local SQL/CAS publication; never remote reads after Source close.

        Registration and activation are separate durable transactions from the
        later Binding/TokenPlan transaction. Uncertain failures cannot replay.
        """
        value = self._observed(handle)
        if value.used:
            raise Conflict("original_session_observed_selection_already_consumed")
        value.reader.scope.require_write_permit(
            value.permit, value.reader, value.message, value.audience
        )
        value.used = True
        factory, target = value.factory, value.selection.reference

        def current() -> bool:
            self._observed(handle)
            value.reader.scope.require_write_permit(
                value.permit, value.reader, value.message, value.audience
            )
            return True

        async def authorize() -> bool:
            current()
            await self._observed_authority(
                value.reader, value.permit, value.message, value.audience, target, write=True
            )
            current()
            return True

        async def locked(session: AsyncSession) -> None:
            current()
            await self.journal.enrollment_scope(
                session, value.message.realm_id, target, factory.policy.contract_sha256
            )
            current()
            await self.lock_grants(session, value.message, value.audience, target)
            current()

        receipt: RegistrationReceipt | None = None

        async def journal(record: object) -> RegistrationReceipt:
            nonlocal receipt
            current()
            expected_record = (
                value.candidate.record
                if value.candidate is not None
                else value.update.record
                if value.update is not None
                else None
            )
            if record is not expected_record:
                raise Conflict("original_session_observed_journal_record_changed")
            await authorize()
            if not value.write_started:
                mark_write_started()
                value.write_started = True
            assert expected_record is not None
            if (
                value.previous is not None
                and value.previous.record.graph_sha256 != expected_record.graph_sha256
            ):
                receipt = await self.journal.extend(
                    value.previous, expected_record, lock_authority=locked, current=current
                )
            else:
                receipt = await self.journal.prepare(
                    value.message.realm_id, expected_record, lock_authority=locked, current=current
                )
            current()
            return receipt

        async with self._gate:
            await authorize()
            if value.candidate is not None:
                assert value.publication is not None

                async def prepare_record(record: object) -> None:
                    await journal(record)

                await factory.commit_publication(
                    value.candidate,
                    value.publication,
                    authorize=authorize,
                    before_commit=prepare_record,
                )
                value.published = factory.registry.publication.generation(target)
            elif value.update is not None:
                updates = self.updates[target.project_id]
                await updates.commit_publication(
                    value.update, authorize=authorize, before_commit=journal
                )
                value.published = factory.registry.publication.generation(target)
            current()
            await authorize()
            if value.candidate is not None or value.update is not None:
                if receipt is None:
                    raise Conflict("original_session_observed_registration_receipt_required")
                await self.journal.activate(receipt, lock_authority=locked, current=current)
                current()
                await authorize()
            value.committed = True

    async def recover_project(
        self,
        realm_id: str,
        project_id: str,
        *,
        authorize: Callable[[], Awaitable[bool]],
        lock_authority: LockedAuthority,
        deferred: frozenset[SessionRef] = frozenset(),
    ) -> tuple[SessionRef, ...]:
        """Startup-only trusted composition; never replay a historical Human source.

        Runtime must supply its current enrollment/policy checks and consumer
        fence. Recovery failure must prevent consumer/catalog activation; a
        prefix registered in memory is not a partially successful startup.
        ``deferred`` names unregistered chat-created Roots whose own creation
        restore failed: their heads stay unregistered here, never adopted
        under this project's policy instead of their creation provenance.
        """
        async with self._gate:
            factory = self.factories.get(project_id)
            if factory is None or await authorize() is not True:
                raise AccessDenied("original_session_recovery_current_authority_required")
            self.factory(factory.policy.anchor)

            def current() -> bool:
                self.factory(factory.policy.anchor)
                return True

            saved = await self.journal.recovery_records(
                realm_id,
                project_id,
                lock_authority=lock_authority,
                current=current,
            )
            result = []
            for entry in saved:
                if await authorize() is not True:
                    raise AccessDenied("original_session_recovery_current_authority_required")
                if entry.record.root in deferred:
                    if entry.record.root in factory.registry.sessions:
                        raise Conflict("original_session_recovery_deferred_root_registered")
                    continue
                if entry.record.root in factory.registry.sessions and project_id in self.updates:
                    await self._maintain_root(
                        realm_id,
                        project_id,
                        entry.record.root,
                        authorize=authorize,
                        lock_authority=lock_authority,
                    )
                    result.append(entry.record.root)
                    continue
                candidate = await factory.prepare_record(entry.record, authorize=authorize)
                await self.commit(
                    factory,
                    candidate,
                    realm_id,
                    authorize=authorize,
                    lock_authority=lock_authority,
                    previous=entry,
                )
                result.append(entry.record.root)
            if await authorize() is not True:
                raise AccessDenied("original_session_recovery_current_authority_required")
            return tuple(result)

    async def maintain_root(
        self,
        realm_id: str,
        project_id: str,
        root: SessionRef,
        *,
        authorize: Callable[[], Awaitable[bool]],
        lock_authority: LockedAuthority,
    ) -> bool:
        """Trusted GET-only maintenance, never a reconstructed Human command.

        Runtime supplies fresh project/operator/enrollment/fence checks. The
        existing authenticated journal supplies identity, not live authority.
        The final journal update and activation recheck current SQL authority.
        """
        async with self._gate:
            return await self._maintain_root(
                realm_id,
                project_id,
                root,
                authorize=authorize,
                lock_authority=lock_authority,
            )

    async def _maintain_root(
        self,
        realm_id: str,
        project_id: str,
        root: SessionRef,
        *,
        authorize: Callable[[], Awaitable[bool]],
        lock_authority: LockedAuthority,
    ) -> bool:
        # The public maintenance/recovery owner already holds _gate.
        updates = self.updates.get(project_id)
        if updates is None:
            raise AccessDenied("original_session_graph_tree_qualification_required")
        factory = self.factory(root)
        generation = factory.registry.publication.generation(root)
        if (
            root.project_id != project_id
            or generation is None
            or generation.root != root
            or updates.factory is not factory
            or await authorize() is not True
        ):
            raise AccessDenied("original_session_graph_maintenance_scope_changed")

        def enrolled() -> bool:
            return self.factory(root) is factory

        saved = await self.journal.recovery_records(
            realm_id, project_id, lock_authority=lock_authority, current=enrolled
        )
        previous = next((entry for entry in saved if entry.record.root == root), None)
        # The first head must come from the actual original reader's
        # complete baseline proof. This path never fabricates a historical
        # SavedSessionRegistration from current metadata.
        candidate = (
            await updates.prepare_initial(root, authorize=authorize)
            if previous is None
            else await updates.prepare(root, previous, authorize=authorize)
        )
        if candidate is None:
            return False

        async def journal(record: object) -> RegistrationReceipt:
            if record is not candidate.record or await authorize() is not True:
                raise AccessDenied("original_session_graph_maintenance_authority_changed")
            if (
                previous is not None
                and previous.record.qualification_sha256 != candidate.record.qualification_sha256
            ):
                # updates.prepare admitted a legacy head and found the same graph.
                return await self.journal.requalify(
                    previous,
                    candidate.record,
                    lock_authority=lock_authority,
                    current=lambda: updates.current(candidate),
                )
            if previous is None or previous.record.graph_sha256 == candidate.record.graph_sha256:
                return await self.journal.prepare(
                    realm_id,
                    candidate.record,
                    lock_authority=lock_authority,
                    current=lambda: updates.current(candidate),
                )
            return await self.journal.extend(
                previous,
                candidate.record,
                lock_authority=lock_authority,
                current=lambda: updates.current(candidate),
            )

        await updates.commit(candidate, authorize=authorize, before_commit=journal)
        published = factory.registry.publication.generation(root)
        if published is None or not isinstance(published.receipt, RegistrationReceipt):
            raise Conflict("original_session_graph_maintenance_receipt_missing")
        if await authorize() is not True:
            raise AccessDenied("original_session_graph_maintenance_authority_changed")
        await self.journal.activate(
            published.receipt,
            lock_authority=lock_authority,
            current=lambda: updates.current(candidate),
        )
        if await authorize() is not True or not updates.current(candidate):
            raise AccessDenied("original_session_graph_maintenance_authority_changed")
        return True
