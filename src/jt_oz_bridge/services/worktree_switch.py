"""Explicit trusted-existing-Root switch, with one atomic Binding/output commit."""

import asyncio
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Literal
from uuid import uuid4
from weakref import ReferenceType
from weakref import ref as weakref

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.output_target import WorktreeSwitchPreviewTarget
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.domain.worktree_switch import ObservedWorktreeSwitch, WorktreeSwitchObserver
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import move_event, scope
from jt_oz_bridge.services.bindings import reference, topic_key
from jt_oz_bridge.services.command_receipts import CommandClaim, CommandInbox
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox
from jt_oz_bridge.services.outbox import Outbox, QueuedBatch, batch_digest
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.worktree_switch_output import WorktreeSwitchPreviews
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import AuditEvent, DeliveryBatch, Grant

CHOICE = "worktree-switch-choice"
CONFIRM = "worktree-switch-confirm"
PAGE = "worktree-switch-page"
PREFIX = "worktree-command:"


class SavedWorktreeReply(ControlModel):
    format: Literal["worktree-switch-reply-v1"] = "worktree-switch-reply-v1"
    source: HumanMessage
    old_binding_id: str
    old_binding_revision: int
    text: str
    locale: Locale
    target: WorktreeSwitchPreviewTarget | None = None
    binding_id: str | None = None
    binding_revision: int | None = None
    queued_batch_id: str
    confirmed_scope: BindingScope | None = None


class WorktreeSwitchCommands:
    def __init__(
        self,
        inbox: CommandInbox,
        tokens: TokenService,
        discovery_outbox: DiscoveryOutbox,
        bound_outbox: Outbox,
        observers: Mapping[tuple[SessionRef, SessionRef], WorktreeSwitchObserver],
        *,
        message_limit: int,
        topic_limit: int,
    ) -> None:
        d = discovery_outbox.destinations
        if (
            type(d.reader) is not ZulipSourceReader
            or inbox.db is not d.db
            or tokens.db is not d.db
            or bound_outbox.db is not d.db
            or tokens.fence != inbox.fence
            or bound_outbox.fence != inbox.fence
            or d.fence != inbox.fence
            or not observers
            or len(observers) > 128
            or any(k != (v.original, v.target) for k, v in observers.items())
            or message_limit < 173
            or topic_limit < 1
        ):
            raise ValueError("worktree_switch_original_pipeline_required")
        self.inbox, self.tokens, self.scoped, self.bound = (
            inbox,
            tokens,
            discovery_outbox,
            bound_outbox,
        )
        self.db, self.fence = inbox.db, inbox.fence
        self.reader, self.bindings, self.discovery = d.reader, d.discovery.bindings, d.discovery
        self.observers = MappingProxyType(dict(observers))
        self._native_stages: dict[
            int,
            tuple[
                ReferenceType[ObservedWorktreeSwitch], object, HumanMessage, WorktreeSwitchObserver
            ],
        ] = {}
        self.previews = WorktreeSwitchPreviews(d, self)
        self.message_limit, self.topic_limit = message_limit, topic_limit
        self.tr = Translator()

    def require_native(
        self, native: ObservedWorktreeSwitch, message: HumanMessage, target: SessionRef
    ) -> None:
        saved = self._native_stages.get(id(native))
        if (
            saved is None
            or saved[0]() is not native
            or saved[1] is not asyncio.current_task()
            or saved[2] is not message
            or native.selection.target != target
            or self.observers.get((native.selection.original, target)) is not saved[3]
        ):
            raise Conflict("worktree_switch_issuer_native_stage_required")
        native.require_current()

    @staticmethod
    def eligible(message: HumanMessage) -> bool:
        p = parse_input(message.text, bound=True)
        return p.kind == "command" and (
            p.command == "worktree" and p.arguments.split()[:1] == ["switch"]
        )

    def _pages(self, text: str, locale: Locale) -> tuple[str, ...]:
        header = self.tr.page_prefix(locale, 100, 100)
        result = MobileMarkdown(locale=locale).render(
            text,
            self.message_limit,
            reserved_characters=len(header) + MARKER_FOOTER_SIZE,
        )
        return tuple(
            self.tr.page_prefix(locale, i, len(result.pages)) + page
            for i, page in enumerate(result.pages, 1)
        )

    async def _authority(
        self,
        binding: Binding,
        message: HumanMessage,
        audience: AudienceSnapshot,
        target: SessionRef,
    ) -> None:
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
            or (audience.revision, sorted(audience.user_ids))
            != (binding.audience_revision, binding.audience_user_ids)
        ):
            raise AccessDenied("worktree_switch_original_human_audience_required")
        async with self.db.sessions() as session:
            current = await session.get(Binding, binding.id)
        if current is None or current.state != "active" or scope(current) != scope(binding):
            raise Conflict("worktree_switch_original_binding_changed")
        for ref, permission in (
            (reference(binding), Permission.MANAGE),
            (target, Permission.OPERATE),
        ):
            await self.discovery._project_in_audience(message, ref.project_id, audience)
            await self.bindings.enrolled(ref, message.realm_id)
            await self.bindings.policy.require(
                message.realm_id, message.author_id, ref.project_id, permission
            )

    async def _lock(
        self,
        session: AsyncSession,
        binding: Binding,
        message: HumanMessage,
        audience: AudienceSnapshot,
        target: SessionRef,
        current: Callable[[], None],
        *,
        switched: bool = False,
    ) -> None:
        current()
        await self.fence.lock(session)
        current()
        if switched:
            old = await session.get(Binding, binding.id, populate_existing=True)
            if (
                old is None
                or old.state != "unbound"
                or scope(old)
                != scope(binding).model_copy(update={"revision": binding.revision + 1})
            ):
                raise Conflict("worktree_switch_original_deactivation_changed")
        else:
            await lock_output_scope(self.bindings, session, binding)
        current()
        for ref, permission in (
            (reference(binding), Permission.MANAGE),
            (target, Permission.OPERATE),
        ):
            backend = await session.scalar(
                select(EnrolledBackend)
                .where(EnrolledBackend.id == ref.backend_id)
                .with_for_update()
            )
            current()
            project = await session.scalar(
                select(EnrolledProject)
                .where(EnrolledProject.id == ref.project_id)
                .with_for_update()
            )
            current()
            if (
                backend is None
                or project is None
                or not backend.enabled
                or not backend.verified
                or not project.enabled
                or backend.identity != ref.backend_identity
                or backend.contract_hash != self.bindings.control.contract_for(ref)
                or project.backend_id != backend.id
                or project.realm_id != message.realm_id
                or project.canonical_directory != ref.canonical_directory
            ):
                raise AccessDenied("worktree_switch_enrollment_changed")
            grants = list(
                (
                    await session.scalars(
                        select(Grant)
                        .where(
                            Grant.realm_id == message.realm_id,
                            Grant.project_id == ref.project_id,
                            Grant.user_id.in_(audience.user_ids),
                            Grant.active.is_(True),
                        )
                        .order_by(Grant.id)
                        .with_for_update()
                    )
                ).all()
            )
            current()
            if {g.user_id for g in grants if Permission.VIEW in ROLES.get(g.role, set())} != set(
                audience.user_ids
            ) or not any(
                g.user_id == message.author_id and permission in ROLES.get(g.role, set())
                for g in grants
            ):
                raise AccessDenied("worktree_switch_grants_changed")

    @staticmethod
    def _routed(saved: SavedWorktreeReply, identity: str) -> RoutedInput:
        return RoutedInput(
            "reply",
            saved.binding_id,
            saved.binding_revision,
            saved.text,
            PREFIX + identity,
            locale=saved.locale,
            discovery_target=saved.target,
            queued_batch_id=saved.queued_batch_id,
        )

    async def route(self, binding: Binding, message: HumanMessage, locale: Locale) -> RoutedInput:
        if not self.eligible(message) or self.tokens.active_plan is not None:
            raise Conflict("worktree_switch_explicit_command_required")
        previous = await self.inbox.find(message.realm_id, message.message_id)
        if previous is not None and previous.state == "completed":
            saved = SavedWorktreeReply.model_validate(previous.response)
            if saved.source != message:
                raise Conflict("worktree_switch_replay_source_changed")

            async def replay_read(audience: AudienceSnapshot) -> None:
                if saved.target is not None:
                    await self.previews.authorize_observed(saved.target, audience)
                else:
                    if saved.confirmed_scope is None or scope(binding) != saved.confirmed_scope:
                        raise Conflict("worktree_switch_replay_target_binding_changed")
                    await self.discovery._project_in_audience(message, binding.project_id, audience)
                    await self.bindings.policy.require(
                        message.realm_id, message.author_id, binding.project_id, Permission.OPERATE
                    )
                    if (audience.revision, audience.user_ids) != (
                        binding.audience_revision,
                        frozenset(binding.audience_user_ids),
                    ):
                        raise AccessDenied("worktree_switch_replay_audience_changed")

            sources = (message,)
            observation = await self.reader.scope.observe_sources(
                self.reader, sources, read_only=replay_read
            )
            self.reader.scope.consume_observation(observation, self.reader, sources)
            routed = self._routed(saved, previous.id)
            await self.committed(routed)
            return routed
        claim = await self.inbox.claim(
            message,
            parse_input(message.text, bound=True).command,
            binding_id=binding.id,
            binding_revision=binding.revision,
            recovered=message.revision != 0,
        )
        if claim.status != "claimed":
            return RoutedInput("held")
        try:
            return await self._produce(binding, message, locale, claim)
        except BaseException:
            try:
                await asyncio.shield(self.inbox.abandon(claim))
            except (Conflict, asyncio.CancelledError):
                pass
            raise

    async def _produce(
        self, binding: Binding, message: HumanMessage, locale: Locale, claim: CommandClaim
    ) -> RoutedInput:
        parsed = parse_input(message.text, bound=True)
        choices = tuple(
            sorted(
                (target for old, target in self.observers if old == reference(binding)),
                key=lambda v: (v.project_id, v.upstream_session_id),
            )
        )
        if not choices:
            raise AccessDenied("worktree_switch_no_qualified_target")
        saved_token = None
        target = choices[0]
        if parsed.arguments.strip() != "switch":
            words = parsed.arguments.split()
            if parsed.command == "worktree" and len(words) == 2 and words[0] == "switch":
                kinds, value = frozenset({CHOICE, CONFIRM, PAGE}), words[1]
            else:
                raise ValueError("worktree_switch_explicit_token_required")
            saved_token = await self.tokens.inspect_allowed(
                value, kinds, message.realm_id, message.author_id
            )
            if (
                saved_token.binding_id != binding.id
                or saved_token.binding_revision != binding.revision
                or saved_token.context.get("original_scope")
                != scope(binding).model_dump(mode="json")
            ):
                raise Conflict("worktree_switch_selection_scope_changed")
            target = SessionRef.model_validate(saved_token.context["target"])
        observer = self.observers.get((reference(binding), target))
        if observer is None:
            raise Conflict("worktree_switch_target_not_explicitly_configured")
        confirming = saved_token is not None and saved_token.kind == CONFIRM
        preview_source = (
            HumanMessage.model_validate(saved_token.context["preview_source"])
            if saved_token is not None and saved_token.kind == CONFIRM
            else None
        )
        if preview_source is not None and (
            preview_source.author_id != message.author_id
            or (preview_source.realm_id, preview_source.channel_id, preview_source.topic)
            != (message.realm_id, message.channel_id, message.topic)
        ):
            raise Conflict("worktree_switch_preview_source_changed")
        sources = (message,) if preview_source is None else (message, preview_source)
        final = None
        with self.tokens.planning() as plan:

            async def read_only(
                audience: AudienceSnapshot,
            ) -> tuple[
                AudienceSnapshot,
                ZulipLocalWritePermit,
                ObservedWorktreeSwitch,
                WorktreeSwitchPreviewTarget | None,
                str,
            ]:
                permit = self.reader.scope.local_write_permit(self.reader, message, audience)

                async def authorize() -> None:
                    self.reader.scope.require_read_permit(permit, self.reader, message, audience)
                    await self._authority(binding, message, audience, target)
                    self.reader.scope.require_read_permit(permit, self.reader, message, audience)

                await authorize()
                native = await observer.observe(authorize=authorize)
                await authorize()
                if (
                    native.selection.original != reference(binding)
                    or native.selection.target != target
                ):
                    raise Conflict("worktree_switch_observer_reference_changed")
                native.require_current()
                native_key = id(native)
                self._native_stages[native_key] = (
                    weakref(native, lambda _: self._native_stages.pop(native_key, None)),
                    asyncio.current_task(),
                    message,
                    observer,
                )
                self.require_native(native, message, target)
                selection = native.selection.model_dump(mode="json")
                if confirming and (
                    saved_token is None or selection != saved_token.context.get("selection")
                ):
                    raise Conflict("worktree_switch_preview_comparison_changed")
                context = {
                    "original_scope": scope(binding).model_dump(mode="json"),
                    "target": target.model_dump(mode="json"),
                    "selection": selection,
                    "channel_id": message.channel_id,
                    "topic": message.topic,
                    "audience_hash": digest(audience.model_dump(mode="json")),
                }
                if saved_token is not None:
                    async with self.db.sessions() as staged_session:
                        await self.tokens.consume_in_session(
                            staged_session, saved_token, database_deadline=True
                        )
                preview_target = None
                if not confirming:
                    kind = (
                        CONFIRM
                        if saved_token is not None and saved_token.kind == CHOICE
                        else CHOICE
                    )
                    if kind == CONFIRM:
                        context["preview_source"] = message.model_dump(mode="json")
                    token = await self.tokens.issue(
                        kind,
                        message.realm_id,
                        message.author_id,
                        context,
                        ttl=60,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                    )
                    key = "worktree.switch.preview" if kind == CONFIRM else "worktree.switch.choice"
                    text = self.tr.render(
                        key,
                        locale,
                        directory=literal(target.canonical_directory),
                        session=literal(target.upstream_session_id),
                        token=token,
                        dirty=str(native.selection.dirty_workspace).lower(),
                    )
                    if kind == CHOICE and choices.index(target) + 1 < len(choices):
                        next_context = {
                            **context,
                            "target": choices[choices.index(target) + 1].model_dump(mode="json"),
                        }
                        token_page = await self.tokens.issue(
                            PAGE,
                            message.realm_id,
                            message.author_id,
                            next_context,
                            ttl=60,
                            binding_id=binding.id,
                            binding_revision=binding.revision,
                        )
                        text += "\n\n!oz worktree switch " + token_page
                    preview_target = await self.previews.issue(
                        message, audience, binding, target, digest(selection), native
                    )
                else:
                    text = self.tr.render(
                        "worktree.switch.done",
                        locale,
                        session=literal(target.upstream_session_id),
                        directory=literal(target.canonical_directory),
                    )
                return audience, permit, native, preview_target, text

            observation = await self.reader.scope.observe_sources(
                self.reader, sources, read_only=read_only
            )
            completed = self.reader.scope.consume_observation(observation, self.reader, sources)
            audience, permit, native, preview_target, text = completed.value

            def current() -> None:
                if self.observers.get((reference(binding), target)) is not observer:
                    raise Conflict("worktree_switch_original_observer_changed")
                self.require_native(native, message, target)
                self.reader.scope.require_write_permit(permit, self.reader, message, audience)

            current()
            pages = self._pages(text, locale)

            async def commit(session: AsyncSession) -> None:
                nonlocal final
                await self._lock(session, binding, message, audience, target, current)
                current()
                selected: Binding | None
                if confirming:
                    await plan.commit(session)
                    current()
                    selected = await self._switch(
                        session, binding, message, audience, native, current
                    )
                    current()
                    queued = await self.bound.queue_batch_in_session(
                        session,
                        PREFIX + claim.id,
                        selected,
                        pages,
                        renderer_version="router-mobile-markdown-v2",
                        message_limit=self.message_limit,
                        topic_limit=self.topic_limit,
                    )
                    current()
                    await lock_output_scope(self.bindings, session, selected)
                    current()
                else:
                    selected = None
                    assert preview_target is not None
                    await plan.commit(session, target=preview_target)
                    current()
                    queued = await self.scoped.queue_scope_batch_in_session(
                        session,
                        PREFIX + claim.id,
                        preview_target,
                        pages,
                        renderer_version="discovery-mobile-markdown-v2",
                        message_limit=self.message_limit,
                        topic_limit=self.topic_limit,
                    )
                    current()
                    await self._lock(session, binding, message, audience, target, current)
                await self._lock(
                    session, binding, message, audience, target, current, switched=confirming
                )
                response = SavedWorktreeReply(
                    source=message,
                    old_binding_id=binding.id,
                    old_binding_revision=binding.revision,
                    text=text,
                    locale=locale,
                    target=preview_target,
                    binding_id=selected.id if selected else None,
                    binding_revision=selected.revision if selected else None,
                    queued_batch_id=queued.id,
                    confirmed_scope=scope(selected) if selected else None,
                )
                result = await session.execute(
                    update(CommandReceipt)
                    .where(
                        CommandReceipt.id == claim.id,
                        CommandReceipt.state == "completed",
                        CommandReceipt.version == claim.version + 1,
                        CommandReceipt.holder == self.fence.holder,
                        CommandReceipt.fencing == self.fence.fencing,
                    )
                    .values(response=response.model_dump(mode="json"))
                )
                current()
                if result.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("worktree_switch_receipt_changed")
                await self.fence.lock(session)
                current()
                final = self._routed(response, claim.id)

            await self.inbox.finish(claim, {}, commit=commit)
        if final is None:
            raise Conflict("worktree_switch_commit_unknown")
        return final

    async def _switch(
        self,
        session: AsyncSession,
        binding: Binding,
        message: HumanMessage,
        audience: AudienceSnapshot,
        native: ObservedWorktreeSwitch,
        current: Callable[[], None],
    ) -> Binding:
        target = native.selection.target
        key = digest(
            {
                "realm": message.realm_id,
                "backend": target.backend_id,
                "identity": target.backend_identity,
                "session": target.upstream_session_id,
            }
        )
        if await session.scalar(
            select(Binding.id).where(Binding.state == "active", Binding.session_key == key)
        ):
            raise Conflict("worktree_switch_target_already_bound")
        current()
        old = await lock_output_scope(self.bindings, session, binding)
        current()
        before = scope(old)
        old.state, old.dispatch_paused = "unbound", True
        old.session_key, old.topic_key, old.revision = None, None, old.revision + 1
        session.add(move_event(before, scope(old), message.author_id))
        await session.flush()
        current()
        selected = Binding(
            id=str(uuid4()),
            realm_id=message.realm_id,
            channel_id=message.channel_id,
            topic=message.topic,
            anchor_message_id=message.message_id,
            backend_id=target.backend_id,
            backend_identity=target.backend_identity,
            session_id=target.upstream_session_id,
            project_id=target.project_id,
            canonical_directory=target.canonical_directory,
            title=native.snapshot.title,
            owner_id=message.author_id,
            locale=binding.locale,
            revision=1,
            state="active",
            audience_revision=audience.revision,
            audience_user_ids=sorted(audience.user_ids),
            observed_cursor=native.snapshot.cursor,
            session_key=key,
            topic_key=topic_key(message.realm_id, message.channel_id, message.topic),
        )
        session.add(selected)
        session.add(
            AuditEvent(
                actor=f"{message.realm_id}:{message.author_id}",
                event="worktree_binding_switched_v1",
                object_id=f"{old.id}:{selected.id}",
            )
        )
        await session.flush()
        current()
        return selected

    async def committed(self, routed: RoutedInput) -> QueuedBatch:
        """Local receipt verifier, never a writer; delivery reauthorizes independently."""
        identity = (routed.delivery_key or "").removeprefix(PREFIX)
        async with self.db.sessions() as session:
            row = await session.get(CommandReceipt, identity)
        if row is None or row.state != "completed":
            raise Conflict("worktree_switch_completed_receipt_missing")
        saved = SavedWorktreeReply.model_validate(row.response)
        if (
            saved.format != "worktree-switch-reply-v1"
            or self._routed(saved, identity) != routed
            or row.source_hash != digest(saved.source.model_dump(mode="json"))
            or (
                row.realm_id,
                row.actor_id,
                row.message_id,
                row.channel_id,
                row.topic,
                row.source_revision,
                row.binding_id,
                row.binding_revision,
            )
            != (
                saved.source.realm_id,
                saved.source.author_id,
                saved.source.message_id,
                saved.source.channel_id,
                saved.source.topic,
                saved.source.revision,
                saved.old_binding_id,
                saved.old_binding_revision,
            )
        ):
            raise Conflict("worktree_switch_completed_receipt_changed")
        pages = self._pages(saved.text, saved.locale)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            batch = await session.get(DeliveryBatch, saved.queued_batch_id)
            if batch is None:
                raise Conflict("worktree_switch_committed_batch_missing")
            if saved.target is not None:
                if not await session.scalar(
                    select(and_(*self.scoped.destinations.guards(saved.target)))
                ):
                    raise AccessDenied("worktree_switch_preview_permission_revoked")
                expected = self.scoped.checksum(
                    saved.target,
                    pages,
                    "discovery-mobile-markdown-v2",
                    self.message_limit,
                    self.topic_limit,
                )
                result = await self.scoped.validated_scope_batch_in_session(
                    session, saved.target, batch
                )
            else:
                binding = await session.get(Binding, saved.binding_id)
                if (
                    binding is None
                    or binding.revision != saved.binding_revision
                    or scope(binding) != saved.confirmed_scope
                ):
                    raise Conflict("worktree_switch_new_binding_changed")
                await lock_output_scope(self.bindings, session, binding)
                expected = batch_digest(
                    pages, "router-mobile-markdown-v2", self.message_limit, self.topic_limit
                )
                result = await self.bound._validated_batch(binding, batch)
                await lock_output_scope(self.bindings, session, binding)
            if batch.plan_hash != expected:
                raise Conflict("worktree_switch_committed_pages_changed")
            await self.fence.lock(session)
            return result
