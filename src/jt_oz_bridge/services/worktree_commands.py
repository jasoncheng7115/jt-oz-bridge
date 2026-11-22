"""Fenced, actor-confirmed one-attempt worktree creation; no implicit move."""

import asyncio
import time
from collections.abc import Mapping
from types import MappingProxyType
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.execution import HumanMessage, MutationNotSent, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.worktrees import (
    WorktreeIntent,
    WorktreeObservation,
    WorktreeProducer,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import literal
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant

CHOICE = "worktree-create-choice"
CONFIRM = "worktree-create-confirm"


class WorktreeCommands:
    def __init__(
        self,
        bindings: BindingService,
        source: SourceReader,
        tokens: TokenService,
        producers: Mapping[SessionRef, WorktreeProducer],
    ) -> None:
        if (
            tokens.db is not bindings.db
            or tokens.fence is None
            or not producers
            or len(producers) > 1000
            or any(ref != producer.template.reference for ref, producer in producers.items())
        ):
            raise ValueError("worktree_same_pipeline_explicit_producers_required")
        self.bindings, self.source, self.tokens = bindings, source, tokens
        self.db, self.fence = bindings.db, tokens.fence
        self.producers = MappingProxyType(dict(producers))
        self.tr = Translator()

    async def _current(self, binding: Binding, message: HumanMessage) -> None:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in {"worktree", "worktrees"}
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("worktree_original_human_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or (current.audience_revision, current.audience_user_ids)
            != (binding.audience_revision, binding.audience_user_ids)
            or current.dispatch_paused
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("worktree_original_scope_changed")

    async def _lock(self, session: AsyncSession, binding: Binding, actor: int) -> None:
        await self.fence.lock(session)
        current = await lock_output_scope(self.bindings, session, binding)
        role = await session.scalar(
            select(Grant.id)
            .where(
                Grant.realm_id == binding.realm_id,
                Grant.user_id == actor,
                Grant.project_id == binding.project_id,
                Grant.active.is_(True),
                Grant.role.in_([r for r, ps in ROLES.items() if Permission.OPERATE in ps]),
            )
            .with_for_update()
        )
        if role is None or current.dispatch_paused:
            raise AccessDenied("worktree_current_operate_required")
        await self.fence.lock(session)

    def _producer(self, binding: Binding) -> WorktreeProducer:
        producer = self.producers.get(reference(binding))
        if producer is None or (
            producer.template.contract_sha256
            != self.bindings.control.contract_for(reference(binding))
        ):
            raise AccessDenied("worktree_original_producer_unavailable")
        return producer

    @staticmethod
    def _context(binding: Binding, message: HumanMessage) -> dict[str, object]:
        return {
            "reference": reference(binding).model_dump(mode="json"),
            "channel_id": message.channel_id,
            "topic": message.topic,
            "audience_revision": binding.audience_revision,
            "audience_user_ids": binding.audience_user_ids,
        }

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        if self.tokens.active_plan is not None:
            raise Conflict("worktree_mutation_cannot_borrow_catalog_token_plan")
        parsed = parse_input(message.text, bound=True)
        if parsed.command != command or parsed.arguments != arguments:
            raise Conflict("worktree_route_source_changed")
        await self._current(binding, message)
        producer = self._producer(binding)
        if command == "worktrees" and not arguments:
            async with self.db.sessions.begin() as session:
                await self._lock(session, binding, message.author_id)
            token = await self.tokens.issue(
                CHOICE,
                message.realm_id,
                message.author_id,
                {
                    **self._context(binding, message),
                    "template_sha256": digest(producer.template.model_dump(mode="json")),
                },
                ttl=300,
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            return self.tr.render("worktree.offer", locale, token=token)
        parts = arguments.split()
        if command != "worktree" or len(parts) != 2:
            raise ValueError("worktree_fixed_control_required")
        operation, value = parts
        if operation == "cancel":
            return await self._cancel(binding, message, locale, value)
        if operation == "status":
            return await self._status(binding, message, locale, value, producer)
        if operation not in {"create", "confirm"}:
            raise ValueError("worktree_fixed_control_required")
        saved = await self.tokens.inspect(
            value, CHOICE if operation == "create" else CONFIRM, message.realm_id, message.author_id
        )
        context = self._context(binding, message)
        if (
            saved.binding_id != binding.id
            or saved.binding_revision != binding.revision
            or any(saved.context.get(key) != item for key, item in context.items())
            or saved.context.get("template_sha256")
            != digest(producer.template.model_dump(mode="json"))
        ):
            raise Conflict("worktree_control_scope_changed")
        if operation == "create":
            intent = WorktreeIntent(
                intent_id=uuid4().hex,
                template=producer.template,
                source_sha256=digest(message.model_dump(mode="json")),
            )
            proof = await producer.prepare(intent)
            await self._current(binding, message)
            async with self.db.sessions.begin() as session:
                await self._lock(session, binding, message.author_id)
                if not producer.current(intent, proof):
                    raise Conflict("worktree_preview_native_changed")
                await self.tokens.consume_in_session(session, saved, database_deadline=True)
            token = await self.tokens.issue(
                CONFIRM,
                message.realm_id,
                message.author_id,
                {
                    **saved.context,
                    "intent": intent.model_dump(mode="json"),
                    "preview_source": message.model_dump(mode="json"),
                    "comparison_sha256": proof.comparison_sha256,
                },
                ttl=60,
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            return self.tr.render(
                "worktree.preview",
                locale,
                directory=literal(intent.directory),
                branch=literal(intent.branch),
                dirty=str(proof.dirty_workspace).lower(),
                setup=literal(intent.template.setup_command or "(none)"),
                receipt=intent.receipt_id,
                token=token,
            )
        intent = WorktreeIntent.model_validate(saved.context.get("intent"))
        preview = HumanMessage.model_validate(saved.context.get("preview_source"))
        if (
            intent.template != producer.template
            or digest(preview.model_dump(mode="json")) != intent.source_sha256
            or (preview.realm_id, preview.channel_id, preview.topic, preview.author_id)
            != (message.realm_id, message.channel_id, message.topic, message.author_id)
            or await self.source.read(preview.realm_id, preview.message_id) != preview
        ):
            raise Conflict("worktree_preview_source_changed")
        proof = await producer.prepare(intent)
        if proof.comparison_sha256 != saved.context.get("comparison_sha256"):
            raise Conflict("worktree_preview_native_digest_changed")
        await self._current(binding, message)
        payload = {
            "operation": "worktree.create",
            "consumer": {"holder": self.fence.holder, "fencing": self.fence.fencing},
            "intent": intent.model_dump(mode="json"),
            "source": message.model_dump(mode="json"),
            "preview_source": preview.model_dump(mode="json"),
            "comparison_sha256": proof.comparison_sha256,
        }
        identity = intent.receipt_id
        async with self.db.sessions.begin() as session:
            await self._lock(session, binding, message.author_id)
            if not producer.current(intent, proof):
                raise Conflict("worktree_confirm_native_changed")
            await self.tokens.consume_in_session(session, saved, database_deadline=True)
            session.add(
                Action(
                    id=identity,
                    dedupe_key="worktree:" + digest(message.model_dump(mode="json")),
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=message.author_id,
                    operation="worktree.create",
                    operation_digest=digest(payload),
                    payload=payload,
                    state="worktree_prepared",
                    owner="opencode",
                    admission={"attempt_reserved": True, "intent_id": intent.intent_id},
                )
            )

        async def authorize() -> None:
            await self._current(binding, message)
            if await self.source.read(preview.realm_id, preview.message_id) != preview:
                raise Conflict("worktree_preview_source_changed_before_send")
            async with self.db.sessions.begin() as session:
                await self._lock(session, binding, message.author_id)
                row = await session.get(Action, identity, with_for_update=True)
                if (
                    row is None
                    or row.state not in {"worktree_prepared", "worktree_sending"}
                    or row.operation_digest != digest(payload)
                    or row.payload.get("consumer")
                    != {"holder": self.fence.holder, "fencing": self.fence.fencing}
                ):
                    raise Conflict("worktree_durable_intent_changed_before_send")
                if time.time() >= saved.expires_at or not producer.current(intent, proof):
                    raise Conflict("worktree_confirm_proof_expired_before_send")
                row.state = "worktree_sending"

        try:
            observed = await producer.create(intent, proof, authorize=authorize)
            await self._current(binding, message)
            await self._save(binding, message, identity, observed, producer)
        except MutationNotSent:
            await self._outcome(identity, "failed", "worktree_not_sent")
            return self.tr.render("worktree.not_sent", locale, receipt=identity)
        except BaseException as error:
            task = asyncio.create_task(
                self._outcome(identity, "ambiguous", "worktree_outcome_unknown")
            )
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                await task
                raise
            if not isinstance(error, Exception):
                raise
            return self.tr.render("worktree.unknown", locale, receipt=identity)
        return self.tr.render(
            "worktree.completed", locale, receipt=identity, directory=literal(observed.directory)
        )

    async def _outcome(self, identity: str, state: str, reason: str) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            row = await session.get(Action, identity, with_for_update=True)
            if row is not None and row.state == "cancelled" and reason == "worktree_not_sent":
                return
            if row is None or row.state not in {"worktree_prepared", "worktree_sending"}:
                raise Conflict("worktree_outcome_action_changed")
            row.state, row.status_reason, row.version = state, reason, row.version + 1

    async def _save(
        self,
        binding: Binding,
        message: HumanMessage,
        identity: str,
        observed: WorktreeObservation,
        producer: WorktreeProducer,
    ) -> None:
        async with self.db.sessions.begin() as session:
            await self._lock(session, binding, message.author_id)
            row = await session.get(Action, identity, with_for_update=True)
            if row is None or row.state not in {"worktree_sending", "ambiguous"}:
                raise Conflict("worktree_result_action_changed")
            intent = WorktreeIntent.model_validate(row.payload.get("intent"))
            if (
                observed.intent_sha256 != digest(intent.model_dump(mode="json"))
                or observed.directory != intent.directory
                or observed.native_project_id != intent.template.native_project_id
                or row.operation_digest != digest(row.payload)
            ):
                raise Conflict("worktree_result_intent_changed")
            if not producer.observation_current(intent, observed):
                raise Conflict("worktree_readback_expired_before_result_commit")
            row.native_result = observed.model_dump(mode="json")
            # A lost response cannot establish that the setup script succeeded.
            row.state = "completed" if observed.status == "completed" else "ambiguous"
            row.status_reason = "worktree_" + observed.status
            row.version += 1
            await session.flush()
            await self.fence.lock(session)
            if not producer.observation_current(intent, observed):
                raise Conflict("worktree_readback_expired_after_result_flush")
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event=row.status_reason,
                    object_id=row.id,
                )
            )

    async def _status(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        identity: str,
        producer: WorktreeProducer,
    ) -> str:
        async with self.db.sessions() as session:
            row = await session.get(Action, identity)
        if (
            row is None
            or row.operation != "worktree.create"
            or row.binding_id != binding.id
            or row.binding_revision != binding.revision
            or row.actor_id != message.author_id
            or row.operation_digest != digest(row.payload)
        ):
            raise Conflict("worktree_status_owned_action_required")
        intent = WorktreeIntent.model_validate(row.payload.get("intent"))
        if intent.template != producer.template:
            raise Conflict("worktree_status_template_changed")
        if row.state == "failed":
            return self.tr.render("worktree.not_sent", locale, receipt=identity)
        observed = await producer.reconcile(intent)
        await self._current(binding, message)
        if row.state != "completed":
            await self._save(binding, message, identity, observed, producer)
        else:
            async with self.db.sessions.begin() as session:
                await self._lock(session, binding, message.author_id)
                original = WorktreeObservation.model_validate(row.native_result)
                if observed.directory_identity_sha256 != original.directory_identity_sha256:
                    raise Conflict("worktree_completed_directory_identity_changed")
                if not producer.observation_current(intent, observed):
                    raise Conflict("worktree_status_readback_expired")
        return self.tr.render(
            "worktree.status",
            locale,
            receipt=identity,
            directory=literal(observed.directory),
            status="completed" if row.state == "completed" else "registered_setup_unknown",
        )

    async def _cancel(
        self, binding: Binding, message: HumanMessage, locale: Locale, identity: str
    ) -> str:
        if len(identity) == 32:
            saved = await self.tokens.inspect(
                identity, CONFIRM, message.realm_id, message.author_id
            )
            if (
                saved.binding_id != binding.id
                or saved.binding_revision != binding.revision
                or any(
                    saved.context.get(k) != v for k, v in self._context(binding, message).items()
                )
            ):
                raise Conflict("worktree_cancel_preview_scope_changed")
            intent = WorktreeIntent.model_validate(saved.context.get("intent"))
            async with self.db.sessions.begin() as session:
                await self._lock(session, binding, message.author_id)
                await self.tokens.consume_in_session(session, saved, database_deadline=True)
            return self.tr.render("worktree.cancelled", locale, receipt=intent.receipt_id)
        async with self.db.sessions.begin() as session:
            await self._lock(session, binding, message.author_id)
            row = await session.get(Action, identity, with_for_update=True)
            if (
                row is None
                or row.operation != "worktree.create"
                or row.binding_id != binding.id
                or row.binding_revision != binding.revision
                or row.actor_id != message.author_id
                or row.operation_digest != digest(row.payload)
            ):
                raise Conflict("worktree_cancel_owned_action_required")
            if row.state != "worktree_prepared":
                raise Conflict("worktree_cancel_after_send_reservation_unknown")
            row.state, row.status_reason, row.version = (
                "cancelled",
                "worktree_cancelled_before_send",
                row.version + 1,
            )
        return self.tr.render("worktree.cancelled", locale, receipt=identity)

    async def recover(self) -> int:
        """Deny-only restart repair. Never obtains a fresh POST reservation."""
        changed = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            rows = list(
                (
                    await session.scalars(
                        select(Action)
                        .where(
                            Action.operation == "worktree.create",
                            Action.state.in_(["worktree_prepared", "worktree_sending"]),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(32)
                        .with_for_update()
                    )
                ).all()
            )
            for row in rows:
                if row.payload.get("consumer") == {
                    "holder": self.fence.holder,
                    "fencing": self.fence.fencing,
                }:
                    continue
                row.state = "held" if row.state == "worktree_prepared" else "ambiguous"
                row.status_reason = "worktree_prior_fence_no_post_authority"
                row.version += 1
                changed += 1
            await self.fence.lock(session)
        return changed
