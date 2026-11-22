"""Owned creation readback -> original registration -> atomic binding and notice.

Trusted composition calls this coordinator; it is not a chat endpoint. It never
creates Native sessions, starts turns, copies file privileges or retries POST.
"""

import asyncio
import logging
import re
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.graph_generation import GraphResourceContext
from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import AudienceSnapshot, ExecutionState
from jt_oz_bridge.domain.delivery import DeliveryRateLimited, without_marker
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import CreatedRootActivation
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.backend_registry import BackendRegistry
from jt_oz_bridge.services.created_root_factory import Authority, V2CreatedRootFactory
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.outbox import OutboundPayload, batch_digest
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.services.session_creation_journal import SessionCreationJournal, first_prompt
from jt_oz_bridge.services.session_registration_journal import (
    LockedAuthority,
    registration_identity,
    registration_key,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch
from jt_oz_bridge.storage.publication_models import BatchDependency
from jt_oz_bridge.storage.retained_payloads import retained_scope
from jt_oz_bridge.storage.session_registration_models import SessionRegistration

RENDERER_VERSION = "session-created-notice-v1"
# The message that opened the menu goes first only while it is still fresh. A creation
# finished much later (say, resumed with `!go` days after) never sends old text by itself.
FIRST_PROMPT_SECONDS = 600
# A chat-created Root whose startup restore fails stays unregistered alone and
# is read again (GET only) after this many seconds.
GRAPH_RESTORE_RETRY_SECONDS = 30
LOG = logging.getLogger(__name__)
CODE = re.compile(r"[a-z][a-z0-9_]{0,99}")


class SessionCreationActivation:
    def __init__(
        self,
        journal: SessionCreationJournal,
        factories: Mapping[str, V2CreatedRootFactory],
        replies: RoutedOutbox,
    ) -> None:
        if (
            not factories
            or len(factories) > 1000
            or set(factories) != set(journal.projects)
            or replies.outbox.bindings is not journal.bindings
            or replies.outbox.fence != journal.fence
        ):
            raise ValueError("creation_activation_original_composition_required")
        self.journal, self.db, self.replies = journal, journal.db, replies
        self.factories = MappingProxyType(dict(factories))
        self._control = journal.bindings.control
        self._lock = asyncio.Lock()
        # Completed creations in tree projects whose startup restore failed.
        self._unrestored: dict[str, SessionRef] = {}
        self._retry_at: dict[str, float] = {}
        self._graph_recovery: (
            tuple[SessionAdoptionService, Callable[[str], tuple[Authority, LockedAuthority]]] | None
        ) = None
        for project_id, factory in self.factories.items():
            project = journal.projects[project_id]
            anchor = factory.policies.template.source.reference
            control = self._control
            registry = (
                control.selected(anchor).client if isinstance(control, BackendRegistry) else control
            )
            if (
                registry is not factory.registry
                or factory.creator.templates.get(project_id) != project.template
                or factory.creator.transport.profile.sha256 != project.contract_sha256
                or factory.policies.template.checksum() != project.policy_template_sha256
            ):
                raise ValueError("creation_activation_project_factory_mismatch")

    def configure_graph_recovery(
        self,
        adoption: SessionAdoptionService,
        authority_for: Callable[[str], tuple[Authority, LockedAuthority]],
    ) -> None:
        """Once-only trusted composition; neither saved heads nor pointers grant authority."""
        if (
            self._graph_recovery is not None
            or adoption.bindings is not self.journal.bindings
            or adoption.reader is not self.journal.reader
            or adoption.journal.db is not self.db
            or adoption.journal.fence != self.journal.fence
            or not callable(authority_for)
        ):
            raise ValueError("created_graph_original_recovery_composition_required")
        for project_id in self.factories.keys() & adoption.factories.keys():
            created, existing = self.factories[project_id], adoption.factories[project_id]
            if (
                created.registry is not existing.registry
                or created.anchor is not existing.anchor
                or created.feed is not existing._feed
                or created.creator.transport is not existing._transport
            ):
                raise ValueError("created_graph_original_recovery_backend_required")
        self._graph_recovery = adoption, authority_for

    async def _restore_completed_graph(
        self, action: Action, binding: Binding, factory: V2CreatedRootFactory, authorized: Authority
    ) -> Binding:
        """Real creation ledger + authenticated graph head, never a synthetic baseline Root."""
        configured = self._graph_recovery
        assert configured is not None
        adoption, authority_for = configured
        project, intent, source = self.journal.payload(action, binding)
        receipt = self.journal.candidate(action, binding)
        existing = adoption.factory(receipt.reference)
        updates = adoption.updates.get(project.template.scope.project_id)
        if (
            updates is None
            or updates.factory is not existing
            or existing.registry is not factory.registry
            or existing._feed is not factory.feed
            or existing._transport is not factory.creator.transport
            or existing.anchor is not factory.anchor
            or adoption.bindings is not self.journal.bindings
            or adoption.journal.fence != self.journal.fence
        ):
            raise Conflict("created_graph_recovery_original_assembly_changed")
        runtime_authorized, runtime_locked = authority_for(intent.scope.project_id)
        expected = self.stamp(action, binding)
        activation = CreatedRootActivation.model_validate(action.native_result["activation"])
        await self.validate_notice(action, binding, activation)

        async def authorize() -> bool:
            if (
                self._graph_recovery is not configured
                or adoption.factory(receipt.reference) is not existing
            ):
                raise Conflict("created_graph_recovery_composition_changed")
            if await runtime_authorized() is not True or await authorized() is not True:
                raise Conflict("created_graph_recovery_current_authority_required")
            return True

        audience = await self.authority(action.id, expected)

        async def locked(session: AsyncSession) -> None:
            await runtime_locked(session)
            await self.journal.fence.lock(session)
            saved = await session.get(
                Action, action.id, with_for_update=True, populate_existing=True
            )
            current_binding = await session.get(
                Binding, binding.id, with_for_update=True, populate_existing=True
            )
            if (
                self._graph_recovery is not configured
                or saved is None
                or current_binding is None
                or self.stamp(saved, current_binding) != expected
                or saved.state != "completed"
                or current_binding.state != "active"
                or adoption.factory(receipt.reference) is not existing
            ):
                raise Conflict("created_graph_recovery_ledger_changed")
            current_project, current_intent, current_source = self.journal.payload(
                saved, current_binding
            )
            if (
                current_project != project
                or current_intent != intent
                or self.journal.candidate(saved, current_binding) != receipt
            ):
                raise Conflict("created_graph_recovery_creation_identity_changed")
            await self.journal.lock_authority(
                session, current_source, current_project, audience, require_operator=False
            )
            await self.journal.validate_scope(session, saved, current_binding, lock=True)

        # This is the actual authenticated journal, including prepared crash heads.
        heads = await adoption.journal.recovery_records(
            self.replies.realm_id,
            intent.scope.project_id,
            lock_authority=locked,
            current=lambda: self._graph_recovery is configured,
        )
        previous = next((saved for saved in heads if saved.record.root == receipt.reference), None)
        stage = await factory.prepare_restore(
            intent, receipt, authorize=authorize, lineage=existing.lineage
        )
        if activation.policy_fingerprint_sha256 != stage.policy.fingerprint_sha256:
            raise Conflict("created_graph_recovery_registered_policy_changed")
        qualified = (
            await existing.prepare_record(previous.record, authorize=authorize)
            if previous is not None
            else await existing.prepare(receipt.reference, authorize=authorize)
        )
        factory.require_restore(stage)
        policies = dict(qualified.guard.enrollments)
        policies[receipt.reference] = stage.policy
        guard = V2LineagePolicyGuard(qualified.proofs, policies)
        context = GraphResourceContext(qualified.proofs, guard, qualified.record)
        settings = {
            ref: getattr(getattr(entry.execution, "proofs", None), "model_settings", None)
            for ref, entry in qualified.entries.items()
        }
        root_execution = stage.entry.execution
        if not isinstance(root_execution, V2ExecutionClient) or not isinstance(
            root_execution.proofs, V2LeafResourceProofs
        ):
            raise Conflict("created_graph_recovery_original_execution_required")
        settings[receipt.reference] = root_execution.proofs.model_settings
        entries = {receipt.reference: stage.entry}
        # Stable facades attach once before publication; the sealed created Root
        # is never replaced, rebound to another feed, or arbitrarily rebaselined.
        updates._facades(receipt.reference, entries, policies, settings)
        prepared = factory.registry.prepare_generation(
            qualified.record, entries, expected=None, enrollments=policies, context=context
        )
        published = None

        def current() -> bool:
            existing.require(qualified)
            context.require()
            if published is None:
                factory.require_restore(stage)
            else:
                factory.registered(intent, receipt, stage.entry)
                factory.registry.publication.require_current(receipt.reference, published)
            return all(qualified.proofs.current_proof(ref) is not None for ref in entries)

        for ref in entries:
            first, second = await guard.bundle(ref), await guard.bundle(ref)
            proof = qualified.proofs.current_proof(ref)
            if (
                proof is None
                or first != second
                or first != (policies[ref].fingerprint_sha256, proof.session_info_sha256)
            ):
                raise Conflict("created_graph_recovery_current_node_policy_changed")
        if not await factory.creator.existing_current(intent, receipt, stage.origin):
            raise Conflict("created_graph_recovery_current_origin_changed")
        await authorize()
        # Refresh only audience authorization, never Native observation timestamps.
        audience = await self.authority(action.id, expected)
        if not current():
            raise Conflict("created_graph_recovery_original_proof_changed")
        same = previous is not None and registration_identity(
            previous.record
        ) == registration_identity(qualified.record)
        if (
            previous is not None
            and previous.record.qualification_sha256 != qualified.record.qualification_sha256
        ):
            # prepare_record admitted a legacy head and found the same graph.
            durable = await adoption.journal.requalify(
                previous, qualified.record, lock_authority=locked, current=current
            )
        elif previous is not None and not same:
            durable = await adoption.journal.extend(
                previous, qualified.record, lock_authority=locked, current=current
            )
        else:
            checked_expected = False

            async def expected_head_locked(session: AsyncSession) -> None:
                nonlocal checked_expected
                await locked(session)  # Every callback retains all fresh SQL guards.
                if not checked_expected:
                    if previous is not None:
                        await adoption.journal._fresh_head(session, previous)
                    elif (
                        await session.get(
                            SessionRegistration,
                            registration_key(self.replies.realm_id, receipt.reference),
                            with_for_update=True,
                        )
                        is not None
                    ):
                        raise Conflict("created_graph_recovery_expected_absent_head_changed")
                    checked_expected = True

            # Initial absence or exact same-head comparison occurs under this
            # very prepare transaction's consumer fence, not an external TOCTOU read.
            durable = await adoption.journal.prepare(
                self.replies.realm_id,
                qualified.record,
                lock_authority=expected_head_locked,
                current=current,
            )
        # SQL commit is a yield point: recheck current runtime and original
        # completed creation authority before making any Root visible.
        await authorize()
        bound = factory.registry.bind_receipt(prepared, durable)
        if not current():
            raise Conflict("created_graph_recovery_proof_changed_after_sql")
        factory.publish_restore(stage, bound)
        published = factory.registry.publication.generation(receipt.reference)
        await adoption.journal.activate(durable, lock_authority=locked, current=current)
        await authorize()
        if not current():
            raise Conflict("created_graph_recovery_published_graph_changed")
        return binding

    @staticmethod
    def stamp(action: Action, binding: Binding) -> str:
        return digest(
            {
                "action": action.id,
                "version": action.version,
                "state": action.state,
                "operation_digest": action.operation_digest,
                "admission": action.admission,
                "native_result": action.native_result,
                "binding": binding.id,
                "revision": binding.revision,
                "binding_state": binding.state,
                "paused": binding.dispatch_paused,
            }
        )

    async def authority(
        self, identity: str, expected: str, audience: AudienceSnapshot | None = None
    ) -> AudienceSnapshot:
        """Zulip and owned SQL authority; a given audience skips only the Zulip reads."""
        action, binding = await self.journal.load(identity)
        if (
            self.stamp(action, binding) != expected
            or binding.realm_id != self.replies.realm_id
            or self.journal.bindings.control is not self._control
        ):
            raise Conflict("creation_activation_owned_state_changed")
        project, _, source = self.journal.payload(action, binding)
        if audience is None:
            audience = await self.journal.authorized(action, binding)
        async with self.db.sessions.begin() as session:
            await self.journal.fence.lock(session)
            await self.journal.lock_authority(
                session, source, project, audience, require_operator=action.state != "completed"
            )
            saved = await session.get(Action, identity, with_for_update=True)
            reserved = await session.get(Binding, binding.id, with_for_update=True)
            if saved is None or reserved is None or self.stamp(saved, reserved) != expected:
                raise Conflict("creation_activation_claim_changed")
            self.journal.candidate(saved, reserved)
            await self.journal.validate_scope(session, saved, reserved, lock=True)
        return audience

    async def validate_notice(
        self,
        action: Action,
        binding: Binding,
        activation: CreatedRootActivation,
    ) -> None:
        """Read the immutable original notice without creating a live output scope.

        A moved Binding cannot authorize its old revision for delivery. This
        dedicated post-only verifier reads owned historical receipt data and
        never calls target(), queues output, creates a Binding or returns text.
        """
        original = self.journal.origin_scope(action, binding)
        async with self.db.sessions() as session:
            notice = await session.get(DeliveryBatch, activation.notice_batch_id)
            deliveries = list(
                (
                    await session.scalars(
                        select(Delivery)
                        .where(
                            Delivery.batch_id == activation.notice_batch_id,
                        )
                        .order_by(Delivery.batch_index)
                        .limit(101)
                    )
                ).all()
            )
            dependency = await session.get(BatchDependency, activation.notice_batch_id)
        expected_key = "reply-batch:" + digest(
            {
                "key": "session-created:" + action.id,
                "binding": original.binding_id,
                "revision": original.revision,
            }
        )
        if (
            notice is None
            or notice.destination_id is not None
            or dependency is not None
            or (notice.binding_id, notice.binding_revision)
            != (original.binding_id, original.revision)
            or notice.dedupe_key != expected_key
            or notice.renderer_version != RENDERER_VERSION
            or notice.plan_hash != activation.notice_plan_sha256
            or not 1 <= notice.page_count <= 100
            or len(deliveries) != notice.page_count
            or notice.message_limit < 173
            or notice.topic_limit < 1
            or notice.priority != 10
        ):
            raise Conflict("creation_activation_original_notice_changed")
        pages = []
        compacted = False
        for index, saved in enumerate(deliveries):
            if saved.destination_id is not None or (
                saved.binding_id,
                saved.binding_revision,
                saved.batch_index,
                saved.priority,
            ) != (original.binding_id, original.revision, index, 10):
                raise Conflict("creation_activation_original_notice_content_changed")
            if saved.payload_compacted_at is not None:
                # A week after delivery, retention keeps only an identity
                # tombstone of each posted page, bound to its original hash.
                # The batch row above still pins the activation's page plan.
                if (
                    saved.state != "delivered"
                    or type(saved.posted_message_id) is not int
                    or saved.posted_message_id < 1
                    or retained_scope(
                        saved.payload,
                        kind="delivery:payload",
                        identity=saved.id,
                        when=saved.payload_compacted_at,
                        checksum=saved.payload_hash,
                    )
                    != {}
                ):
                    raise Conflict("creation_activation_original_notice_content_changed")
                compacted = True
                continue
            payload = OutboundPayload.model_validate(saved.payload)
            if (
                saved.payload_hash != digest(saved.payload)
                or (
                    payload.operation,
                    payload.realm_id,
                    payload.channel_id,
                    payload.topic,
                    payload.bot_user_id,
                    payload.marker,
                )
                != (
                    "post",
                    original.realm_id,
                    original.channel_id,
                    original.topic,
                    self.replies.outbox.bot_user_id,
                    "jtoz:" + saved.id,
                )
                or len(payload.content) > notice.message_limit
                or len(payload.topic) > notice.topic_limit
            ):
                raise Conflict("creation_activation_original_notice_content_changed")
            page = without_marker(payload.content, "jtoz:" + saved.id)
            if page is None:
                raise Conflict("creation_activation_original_notice_content_changed")
            pages.append(page)
        if sum(len(page) for page in pages) > 1000000 or (
            not compacted
            and batch_digest(
                tuple(pages),
                notice.renderer_version,
                notice.message_limit,
                notice.topic_limit,
            )
            != activation.notice_plan_sha256
        ):
            # Only the complete original text can be re-planned; a compacted
            # page leaves the batch's own plan hash checked above.
            raise Conflict("creation_activation_original_notice_plan_changed")

    def pages(self, binding: Binding, action: Action) -> tuple[str, ...]:
        if binding.locale not in {"en", "zh-TW"}:
            raise Conflict("creation_activation_locale_unavailable")
        locale = cast(Locale, binding.locale)
        tr = self.replies.tr
        # The title OpenCode gave the conversation and its project; never the raw session ID.
        text = tr.render(
            "lifecycle.created",
            locale,
            title=visible(binding.title)
            if binding.title
            else tr.render("lifecycle.untitled", locale),
            project=visible(binding.project_id),
        )
        header = tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("creation_activation_notice_unavailable")
        return tuple(
            tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )

    async def reconcile(
        self,
        identity: str,
        *,
        restore: bool = False,
        recovery_authority: Authority | None = None,
    ) -> Binding:
        """Activate an admitted intent, or GET-only restore a completed one.

        Pending crash recovery may explicitly select restore=True to preserve
        work already started through Native. The owned durable creation receipt
        and current Human/project authority are still mandatory.
        """
        async with self._lock:
            action, binding = await self.journal.load(identity)
            project, intent, _ = self.journal.payload(action, binding)
            receipt = self.journal.candidate(action, binding)
            if action.state == "admitted" and binding.dispatch_paused:
                raise Conflict("creation_activation_reservation_paused")
            expected = self.stamp(action, binding)
            factory = self.factories.get(intent.scope.project_id)
            if (
                factory is None
                or project.policy_template_sha256 != factory.policies.template.checksum()
                or factory.creator.templates.get(intent.scope.project_id) != project.template
                or factory.creator.transport.profile.sha256 != project.contract_sha256
            ):
                raise Conflict("creation_activation_project_template_changed")

            checked: AudienceSnapshot | None = None

            async def authorized() -> bool:
                nonlocal checked
                if recovery_authority is not None and await recovery_authority() is not True:
                    raise Conflict("creation_recovery_command_no_longer_authorized")
                checked = await self.authority(identity, expected)
                return True

            async def still_authorized() -> bool:
                # Registration re-checks authority around every Native read, and
                # its creation readback expires 5 s after it is taken. One Zulip
                # check costs about 0.5 s, so ten of them outlast the readback.
                # Here only the owned grants, enrollment and reservation are
                # re-read; Zulip is read in full before and after registration.
                assert checked is not None
                await self.authority(identity, expected, checked)
                return True

            await authorized()
            recovery = restore or action.state == "completed"
            if (
                action.state == "completed"
                and receipt.reference not in factory.registry.sessions
                and self._graph_recovery is not None
                and intent.scope.project_id in self._graph_recovery[0].updates
            ):
                # The tree restore re-checks authority around every Native read
                # inside 5 s windows, like registration below. Zulip is read in
                # full here, and twice more inside the restore before SQL.
                return await self._restore_completed_graph(
                    action, binding, factory, still_authorized
                )
            registration_receipt = receipt if recovery else await factory.creator.observe(intent)
            if registration_receipt.native_created_at != receipt.native_created_at:
                raise Conflict("creation_activation_original_creation_time_changed")
            entry = await factory.register(
                intent, registration_receipt, authorize=still_authorized, restore=recovery
            )
            execution = entry.execution
            if not isinstance(execution, V2ExecutionClient):
                raise Conflict("creation_activation_original_execution_required")
            if not isinstance(execution.scope_guard, V2ProjectPolicyGuard):
                raise Conflict("creation_activation_original_policy_required")
            guard = execution.scope_guard
            enrollment = guard.enrollments[entry.reference]
            if action.state == "completed":
                activation = CreatedRootActivation.model_validate(
                    action.native_result["activation"]
                )
                if activation.policy_fingerprint_sha256 != enrollment.fingerprint_sha256:
                    raise Conflict("creation_activation_registered_policy_changed")
                await self.validate_notice(action, binding, activation)
                _, proof = await execution.qualified_snapshot(entry.reference)
                witness = await factory.observe_policy(intent, receipt, entry, proof)
                await authorized()
                factory.registered(intent, receipt, entry)
                execution.current(entry.reference, proof)
                factory.policy_current(intent, receipt, entry, proof, witness)
                return binding
            snapshot, proof = await execution.qualified_snapshot(entry.reference)
            if not snapshot.reconciled or not recovery and snapshot.state != ExecutionState.IDLE:
                raise Conflict("creation_activation_pristine_idle_required")
            witness = await factory.observe_policy(intent, receipt, entry, proof)
            audience = await self.authority(identity, expected)
            if recovery_authority is not None and await recovery_authority() is not True:
                raise Conflict("creation_recovery_command_changed_before_commit")
            prompt = None
            if (
                action.payload.get("prompt") is not None
                and time.time() - action.created_at <= FIRST_PROMPT_SECONDS
            ):
                prompt = first_prompt(
                    HumanMessage.model_validate(action.payload["source"]), action.payload["prompt"]
                )
                try:
                    await self.journal.source(prompt)
                except (ZulipReadUnavailable, DeliveryRateLimited):
                    raise  # Transient: activation retries with the prompt intact.
                except (Conflict, ValueError):
                    # Edited, deleted or moved since: never send a stale text, and
                    # never strand the Root that Native already created.
                    prompt = None
            async with self.db.sessions.begin() as session:
                await self.journal.fence.lock(session)
                saved = await session.get(Action, identity, with_for_update=True)
                reserved = await session.get(Binding, binding.id, with_for_update=True)
                if saved is None or reserved is None or self.stamp(saved, reserved) != expected:
                    raise Conflict("creation_activation_reservation_changed_before_commit")
                current_project, _, source = self.journal.payload(saved, reserved)
                self.journal.candidate(saved, reserved)
                await self.journal.lock_authority(session, source, current_project, audience)
                if current_project != project or reserved.dispatch_paused:
                    raise Conflict("creation_activation_project_or_queue_changed")
                reserved.state, reserved.title, reserved.observed_cursor = (
                    "active",
                    snapshot.title,
                    snapshot.cursor,
                )
                await session.flush()
                if prompt is not None:
                    # Same commit as the binding: the first message is queued exactly once.
                    await QueueService(self.journal.bindings)._receive_in_session(
                        session, reserved, prompt
                    )
                pages = self.pages(reserved, saved)
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    "session-created:" + identity,
                    reserved,
                    pages,
                    renderer_version=RENDERER_VERSION,
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=10,
                )
                activation = CreatedRootActivation(
                    reference=entry.reference,
                    action_id=saved.id,
                    binding_id=reserved.id,
                    binding_revision=reserved.revision,
                    intent_sha256=digest(intent.model_dump(mode="json")),
                    creation_receipt_sha256=digest(receipt.model_dump(mode="json")),
                    project_sha256=project.checksum(),
                    contract_sha256=project.contract_sha256,
                    policy_fingerprint_sha256=enrollment.fingerprint_sha256,
                    notice_batch_id=batch.id,
                    notice_plan_sha256=batch_digest(
                        pages,
                        RENDERER_VERSION,
                        self.replies.message_limit,
                        self.replies.topic_limit,
                    ),
                    activated_at=time.time(),
                )
                saved.native_result = {
                    **saved.native_result,
                    "activation": activation.model_dump(mode="json"),
                }
                saved.state, saved.status_reason, saved.version = (
                    "completed",
                    "creation_registered_bound",
                    saved.version + 1,
                )
                session.add(
                    AuditEvent(
                        actor=f"{source.realm_id}:{source.author_id}",
                        event="session_create_activated",
                        object_id=saved.id,
                    )
                )
                # SQL awaits may receive new Native events. Roll back the whole
                # activation and notice unless the original final fence survives.
                factory.registered(intent, receipt, entry)
                execution.current(entry.reference, proof)
                factory.policy_current(intent, receipt, entry, proof, witness)
            return reserved

    async def restore_active(self) -> tuple[str, ...]:
        """Explicit startup hook; no scans of Native's DB or advertised sessions."""
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Action.operation == "session.create",
                            Action.state == "completed",
                            Binding.state == "active",
                            Binding.realm_id == self.replies.realm_id,
                            Binding.project_id.in_(self.factories),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(1001)
                    )
                ).all()
            )
        if len(ids) > 1000:
            raise Conflict("creation_activation_restore_capacity_exceeded")
        restored = []
        for identity in ids:
            if await self._restore(identity):
                restored.append(identity)
        return tuple(restored)

    def unrestored_roots(self) -> frozenset[SessionRef]:
        """Created Roots left unregistered; graph recovery must not adopt them."""
        return frozenset(self._unrestored.values())

    async def retry_restores(self) -> None:
        """GET-only retry of deferred created Roots; each still fails closed alone."""
        now = time.monotonic()
        for identity in sorted(self._unrestored):
            if self._retry_at.get(identity, 0) <= now:
                await self._restore(identity, retry=True)

    async def _restore(self, identity: str, *, retry: bool = False) -> bool:
        # Bounded by its own steps: Native reads inside 5 s windows, each GET's
        # HTTP timeout and SQLite's busy timeout. No outer cancellation: cutting
        # a restore inside its SQL writes is not something to add here.
        try:
            await self.reconcile(identity, restore=True)
        except (ZulipReadUnavailable, DeliveryRateLimited):
            raise
        except (AccessDenied, Conflict, ValueError, TimeoutError) as error:
            try:
                reference = await self._restore_reference(identity)
            except (AccessDenied, Conflict, ValueError):
                reference = None  # The owned creation ledger itself no longer reads back.
            if reference is None:
                if retry:
                    # No longer an active creation to restore (say, unbound).
                    self._unrestored.pop(identity, None)
                    self._retry_at.pop(identity, None)
                    return False
                # A creation ledger that no longer reads back still stops startup.
                raise
            if reference in self.factories[reference.project_id].registry.sessions:
                # Registered before the failure: only stopping startup keeps it unused.
                raise
            self._unrestored[identity] = reference
            self._retry_at[identity] = time.monotonic() + GRAPH_RESTORE_RETRY_SECONDS
            # Only a fixed code: other ValueErrors may quote saved content.
            code = str(error) if CODE.fullmatch(str(error)) else "-"
            LOG.warning(
                "creation_restore_deferred action=%s session=%s kind=%s code=%s",
                identity,
                reference.upstream_session_id,
                type(error).__name__,
                code,
            )
            return False
        if self._unrestored.pop(identity, None) is not None:
            LOG.warning("creation_restore_recovered action=%s", identity)
        self._retry_at.pop(identity, None)
        return True

    async def _restore_reference(self, identity: str) -> SessionRef | None:
        """The Root of a still active completed creation in a configured project, else None.

        Leaf and tree projects alike: one Root that cannot be restored, say after
        OpenCode's policy changed, stays unregistered alone instead of stopping
        every other topic. Nothing is sent to it until a later restore succeeds.
        """
        action, binding = await self.journal.load(identity)
        _, intent, _ = self.journal.payload(action, binding)
        if (
            action.state != "completed"
            or binding.state != "active"
            or intent.scope.project_id not in self.factories
        ):
            return None
        return self.journal.candidate(action, binding).reference
