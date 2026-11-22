"""Editable durable human inputs and explicit stop/resume queue policy."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.operations import current_operation
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.check_stop import (
    BACKGROUND_STOP_UNQUALIFIED,
    StopReceipt,
    UnqualifiedBackgroundStop,
    has_in_flight_check,
    prior_stop_receipt,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant
from jt_oz_bridge.storage.retained_payloads import retained_scope
from jt_oz_bridge.storage.statements import insert


@dataclass(frozen=True)
class QueueReceipt:
    action_id: str
    state: str
    already_dispatched: bool
    paused_at_admission: bool = False


class QueueService:
    def __init__(self, bindings: BindingService, *, fence: ConsumerFence | None = None) -> None:
        self.bindings, self.db = bindings, bindings.db
        self.fence = fence

    async def receive(
        self,
        binding_id: str,
        message: HumanMessage,
        *,
        recovered: bool = False,
        reply_locale: Locale | None = None,
        recovery_item_id: str | None = None,
        admitted: Callable[[AsyncSession, Binding, QueueReceipt], Awaitable[QueueReceipt]]
        | None = None,
    ) -> QueueReceipt:
        """``admitted`` runs inside the admission transaction, as on the closed path."""
        if reply_locale is not None and reply_locale not in {"en", "zh-TW"}:
            raise ValueError("invalid_prompt_reply_locale")
        if message.is_bot:
            raise AccessDenied("bot input cannot execute development operations")
        binding = await self.bindings.get(
            binding_id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if binding.channel_id != message.channel_id or binding.topic != message.topic:
            raise AccessDenied("message does not belong to the current binding")
        async with self.db.sessions.begin() as session:
            receipt = await self._receive_in_session(
                session,
                binding,
                message,
                recovered=recovered,
                reply_locale=reply_locale,
                recovery_item_id=recovery_item_id,
            )
            return receipt if admitted is None else await admitted(session, binding, receipt)

    async def _receive_in_session(
        self,
        session: AsyncSession,
        binding: Binding,
        message: HumanMessage,
        *,
        recovered: bool = False,
        reply_locale: Locale | None = None,
        recovery_item_id: str | None = None,
    ) -> QueueReceipt:
        """Original schema32 SQL core; caller owns current Source and actor guards."""
        if message.is_bot or (binding.realm_id, binding.channel_id, binding.topic) != (
            message.realm_id,
            message.channel_id,
            message.topic,
        ):
            raise AccessDenied("message does not belong to the current binding")
        if reply_locale is not None and reply_locale not in {"en", "zh-TW"}:
            raise ValueError("invalid_prompt_reply_locale")
        key = f"human:{message.realm_id}:{message.message_id}"
        parsed = parse_input(message.text, bound=True)
        forwardable = parsed.kind == "prompt"
        payload = {
            "operation": "prompt",
            "reference": reference(binding).model_dump(),
            "text": parsed.arguments if forwardable else "",
            "source": message.model_dump(mode="json"),
            "reply_locale": reply_locale
            or (binding.locale if binding.locale in {"en", "zh-TW"} else "en"),
        }
        if self.fence is not None:
            await self.fence.lock(session)
        from jt_oz_bridge.services.binding_scope_history import scope

        current = await session.scalar(
            select(Binding).where(Binding.id == binding.id).with_for_update()
        )
        if current is None or current.state != "active" or scope(current) != scope(binding):
            raise Conflict("binding_changed_before_queue_admission")
        recovery_item = None
        if recovery_item_id is not None:
            from jt_oz_bridge.domain.binding_scope import BindingScope
            from jt_oz_bridge.services.zulip_gap_recovery import run_payload
            from jt_oz_bridge.storage.models import InputEvent
            from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

            recovery_item = await session.get(ZulipRecoveryItem, recovery_item_id)
            if (
                recovery_item is None
                or not recovered
                or not forwardable
                or recovery_item.state not in {"captured", "held"}
                or (
                    recovery_item.binding_id,
                    recovery_item.binding_revision,
                    recovery_item.actor_id,
                    recovery_item.message_id,
                    recovery_item.source_revision,
                )
                != (
                    binding.id,
                    binding.revision,
                    message.author_id,
                    message.message_id,
                    message.revision,
                )
            ):
                raise Conflict("recovery_original_prompt_link_required")
            run = await session.get(InputEvent, recovery_item.run_id)
            facts = run_payload(run, recovery_item.source)
            if BindingScope.model_validate(facts["scopes"][binding.id]["scope"]) != scope(current):
                raise Conflict("recovery_original_binding_scope_changed")
        state = (
            "cancelled"
            if message.deleted or not forwardable
            else "held"
            if recovered or current.dispatch_paused
            else "queued"
        )
        action_id = (
            await session.execute(
                insert(self.db, Action)
                .values(
                    dedupe_key=key,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=message.author_id,
                    payload=payload,
                    operation=current_operation(payload),
                    operation_digest=digest(payload),
                    state=state,
                )
                .on_conflict_do_nothing(index_elements=["dedupe_key"])
                .returning(Action.id)
            )
        ).scalar_one_or_none()
        if action_id:
            if recovery_item is not None:
                if state != "held":
                    raise Conflict("recovery_prompt_must_start_held")
                recovery_item.action_id, recovery_item.state = str(action_id), "held"
                recovery_item.version += 1
            elif state == "held" and forwardable and not recovered:
                from jt_oz_bridge.services.zulip_gap_recovery import link_paused_prompt

                await link_paused_prompt(session, current, message, str(action_id))
            return QueueReceipt(
                str(action_id), state, False, paused_at_admission=bool(current.dispatch_paused)
            )
        existing = (await session.scalars(select(Action).where(Action.dedupe_key == key))).one()
        if (
            existing.binding_id != binding.id
            or existing.binding_revision != binding.revision
            or existing.actor_id != message.author_id
        ):
            raise Conflict("message binding or actor changed")
        if existing.payload_compacted_at is not None:
            if existing.state not in {"completed", "cancelled", "rejected", "failed"}:
                raise Conflict("retired_action_must_remain_terminal")
            retired_source_scope = retained_scope(
                existing.payload,
                kind="action:payload",
                identity=existing.id,
                when=existing.payload_compacted_at,
            )
            revision, checksum = (
                retired_source_scope.get("source_revision"),
                retired_source_scope.get("source_sha256"),
            )
            if type(revision) is not int or revision < 0 or not isinstance(checksum, str):
                raise Conflict("retired_prompt_source_identity_missing")
            if message.revision == revision and digest(message.model_dump(mode="json")) != checksum:
                raise Conflict("message revision reused with different content")
            return QueueReceipt(
                existing.id,
                existing.state,
                True,
                paused_at_admission=bool(current.dispatch_paused),
            )
        old = HumanMessage.model_validate(existing.payload["source"])
        from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

        linked = await session.scalar(
            select(ZulipRecoveryItem).where(ZulipRecoveryItem.action_id == existing.id)
        )
        if recovery_item is not None and recovery_item.action_id != existing.id:
            raise Conflict("recovery_cannot_adopt_existing_action")
        if linked is not None and message != old:
            if existing.state in {"queued", "held"}:
                existing.state, existing.version = "held", existing.version + 1
                existing.status_reason = "recovery_original_source_changed"
                linked.state, linked.version = "rejected", linked.version + 1
            return QueueReceipt(
                existing.id,
                existing.state,
                existing.state not in {"queued", "held"},
                paused_at_admission=bool(current.dispatch_paused),
            )
        if message.revision < old.revision:
            return QueueReceipt(
                existing.id,
                existing.state,
                existing.state not in {"queued", "held"},
                paused_at_admission=bool(current.dispatch_paused),
            )
        if message.revision == old.revision:
            if message != old:
                raise Conflict("message revision reused with different content")
            return QueueReceipt(
                existing.id,
                existing.state,
                existing.state not in {"queued", "held"},
                paused_at_admission=bool(current.dispatch_paused),
            )
        if existing.state not in {"queued", "held"}:
            return QueueReceipt(
                existing.id,
                existing.state,
                True,
                paused_at_admission=bool(current.dispatch_paused),
            )
        if reply_locale is None:
            # A dispatch-time source refresh has no new user-language decision.
            payload["reply_locale"] = existing.payload.get("reply_locale", payload["reply_locale"])
        target = "cancelled" if message.deleted or not forwardable else existing.state
        result = await session.execute(
            update(Action)
            .where(
                Action.id == existing.id,
                Action.version == existing.version,
                Action.state.in_(["queued", "held"]),
            )
            .values(
                payload=payload,
                operation=current_operation(payload),
                operation_digest=digest(payload),
                state=target,
                version=existing.version + 1,
            )
        )
        if result.rowcount != 1:  # type: ignore[attr-defined]
            raise Conflict("message was dispatched while editing")
        return QueueReceipt(
            existing.id, target, False, paused_at_admission=bool(current.dispatch_paused)
        )

    async def pause(self, binding_id: str, realm: str, user_id: int, revision: int) -> int:
        binding = await self.bindings.get(binding_id, realm, user_id, Permission.OPERATE)
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            result = (
                await session.execute(
                    update(Binding)
                    .where(
                        Binding.id == binding.id,
                        Binding.revision == revision,
                        Binding.state == "active",
                    )
                    .values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
                    .returning(Binding.queue_revision)
                )
            ).scalar_one_or_none()
            if result is None:
                raise Conflict("binding changed")
            await session.execute(
                update(Action)
                .where(Action.binding_id == binding.id, Action.state == "queued")
                .values(state="held", version=Action.version + 1)
            )
            session.add(
                AuditEvent(actor=f"{realm}:{user_id}", event="queue_paused", object_id=binding.id)
            )
            return result

    async def resume(
        self, binding_id: str, realm: str, user_id: int, revision: int, queue_revision: int
    ) -> int:
        binding = await self.bindings.get(binding_id, realm, user_id, Permission.OPERATE)
        async with self.db.sessions.begin() as session:
            return await self._resume_in_session(
                session, binding, realm, user_id, revision, queue_revision
            )

    async def _resume_in_session(
        self,
        session: AsyncSession,
        binding: Binding,
        realm: str,
        user_id: int,
        revision: int,
        queue_revision: int,
    ) -> int:
        """Original schema32 SQL core; caller owns current Source and actor guards."""
        if self.fence is not None:
            await self.fence.lock(session)
        from jt_oz_bridge.services.zulip_gap_recovery import run_payload
        from jt_oz_bridge.storage.models import InputEvent
        from jt_oz_bridge.storage.zulip_recovery_models import (
            ZulipRecoveryCheckpoint,
            ZulipRecoveryItem,
        )

        checkpoints = (
            await session.scalars(
                select(ZulipRecoveryCheckpoint).where(
                    ZulipRecoveryCheckpoint.realm_id == binding.realm_id,
                    ZulipRecoveryCheckpoint.channel_id == binding.channel_id,
                )
            )
        ).all()
        for checkpoint in checkpoints:
            if checkpoint.run_id:
                run = await session.get(InputEvent, checkpoint.run_id)
                value = run_payload(run, checkpoint.source)
                assert run is not None  # run_payload already rejects a missing authenticated row.
                target = value["scopes"].get(binding.id)
                if (
                    run.state == "zulip_recovery_capacity" or value.get("capacity_blocked")
                ) and target:
                    raise Conflict("recovery_capacity_requires_operator_review")
                if target and target["queue_revision"] == binding.queue_revision:
                    raise Conflict("recovery_owned_pause_requires_selected_review")
        blocked = await session.scalar(
            select(ZulipRecoveryItem.id)
            .join(Action, Action.id == ZulipRecoveryItem.action_id)
            .where(ZulipRecoveryItem.binding_id == binding.id, Action.state == "held")
            .limit(1)
        )
        if blocked is not None:
            raise Conflict("recovered_prompts_require_current_selected_review")
        result = (
            await session.execute(
                update(Binding)
                .where(
                    Binding.id == binding.id,
                    Binding.revision == revision,
                    Binding.state == "active",
                    Binding.queue_revision == queue_revision,
                )
                .values(dispatch_paused=False, queue_revision=Binding.queue_revision + 1)
                .returning(Binding.queue_revision)
            )
        ).scalar_one_or_none()
        if result is None:
            raise Conflict("stale queue resume")
        # Ambiguous/admitted actions never become queued here. Every dispatch reauthorizes.
        await session.execute(
            update(Action)
            .where(
                Action.binding_id == binding.id,
                Action.binding_revision == revision,
                Action.state == "held",
                Action.operation != "worktree.create",
            )
            .values(state="queued", version=Action.version + 1)
        )
        session.add(
            AuditEvent(actor=f"{realm}:{user_id}", event="queue_resumed", object_id=binding.id)
        )
        return result

    async def list(self, binding_id: str, realm: str, user_id: int) -> list[Action]:
        binding = await self.bindings.get(binding_id, realm, user_id)
        async with self.db.sessions() as session:
            return list(
                (
                    await session.scalars(
                        select(Action)
                        .where(
                            Action.binding_id == binding.id,
                            Action.state.in_(
                                [
                                    "queued",
                                    "held",
                                    "dispatching",
                                    "ambiguous",
                                    "admitted",
                                    "running",
                                ]
                            ),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(100)
                    )
                ).all()
            )

    async def stop(
        self,
        binding_id: str,
        realm: str,
        user_id: int,
        client_action_id: str,
        *,
        source: HumanMessage | None = None,
    ) -> str:
        receipt = await self.request_stop(
            binding_id, realm, user_id, client_action_id, source=source
        )
        if receipt.interrupt_action_id is None:
            # Compatibility API cannot return a dispatchable ID when nothing was sent.
            # Replays preserve the original refusal without re-pausing a resumed queue.
            raise UnqualifiedBackgroundStop("background_check_stop_not_qualified")
        return receipt.interrupt_action_id

    async def request_stop(
        self,
        binding_id: str,
        realm: str,
        user_id: int,
        client_action_id: str,
        *,
        source: HumanMessage | None = None,
    ) -> StopReceipt:
        binding = await self.bindings.get(binding_id, realm, user_id, Permission.OPERATE)
        payload = {"operation": "interrupt", "reference": reference(binding).model_dump()}
        if source is not None:
            if (
                source.is_bot
                or source.deleted
                or (source.realm_id, source.author_id, source.channel_id, source.topic)
                != (realm, user_id, binding.channel_id, binding.topic)
            ):
                raise AccessDenied("interrupt_source_outside_binding")
            payload["source"] = source.model_dump(mode="json")
        key = f"stop:{realm}:{client_action_id}"
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            from jt_oz_bridge.services.binding_scope_history import scope

            current = await session.scalar(
                select(Binding).where(Binding.id == binding.id).with_for_update()
            )
            if current is None or current.state != "active" or scope(current) != scope(binding):
                raise Conflict("binding_changed_before_stop")
            existing = await session.scalar(select(Action).where(Action.dedupe_key == key))
            if existing is not None:
                # A replay must not pause a subsequently resumed queue or turn a
                # formerly unsupported request into a new Native interrupt.
                return prior_stop_receipt(existing, binding, user_id, payload)
            if await has_in_flight_check(session, current):
                if self.fence is None:
                    raise Conflict("background_stop_requires_consumer_fence")
                await self.fence.lock(session)
                grant = (
                    select(Grant.id)
                    .where(
                        Grant.realm_id == realm,
                        Grant.user_id == user_id,
                        Grant.project_id == current.project_id,
                        Grant.active.is_(True),
                        Grant.role.in_(
                            [
                                role
                                for role, permissions in ROLES.items()
                                if Permission.OPERATE in permissions
                            ]
                        ),
                    )
                    .exists()
                )
                paused = await session.execute(
                    update(Binding)
                    .where(
                        Binding.id == current.id,
                        Binding.revision == current.revision,
                        Binding.state == "active",
                        grant,
                    )
                    .values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
                )
                if paused.rowcount != 1:  # type: ignore[attr-defined]
                    raise AccessDenied("background_stop_authority_changed_before_pause")
                await session.execute(
                    update(Action)
                    .where(Action.binding_id == current.id, Action.state == "queued")
                    .values(state="held", version=Action.version + 1)
                )
                # This is a terminal request receipt, not an attempted Native
                # interrupt. Durable Action dedupe prevents a replay from becoming
                # dispatchable after the original check ends or the queue resumes.
                session.add(
                    Action(
                        dedupe_key=key,
                        binding_id=current.id,
                        binding_revision=current.revision,
                        actor_id=user_id,
                        operation_digest=digest(payload),
                        payload=payload,
                        operation="interrupt",
                        state="rejected",
                        status_reason=BACKGROUND_STOP_UNQUALIFIED,
                        admission={},
                        native_result={},
                    )
                )
                session.add(
                    AuditEvent(
                        actor=f"{realm}:{user_id}",
                        event="queue_paused_background_stop_unqualified",
                        object_id=current.id,
                    )
                )
                return StopReceipt(None, True)
            action_id = (
                await session.execute(
                    insert(self.db, Action)
                    .values(
                        dedupe_key=key,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                        actor_id=user_id,
                        operation_digest=digest(payload),
                        payload=payload,
                        operation=current_operation(payload),
                        state="queued",
                    )
                    .on_conflict_do_nothing(index_elements=["dedupe_key"])
                    .returning(Action.id)
                )
            ).scalar_one_or_none()
            if not action_id:
                existing = (
                    await session.scalars(select(Action).where(Action.dedupe_key == key))
                ).one()
                return prior_stop_receipt(existing, binding, user_id, payload)
            updated = await session.execute(
                update(Binding)
                .where(
                    Binding.id == binding.id,
                    Binding.revision == binding.revision,
                    Binding.state == "active",
                )
                .values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
            )
            if updated.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("binding changed while stopping")
            await session.execute(
                update(Action)
                .where(
                    Action.binding_id == binding.id,
                    Action.state == "queued",
                    Action.id != action_id,
                )
                .values(state="held", version=Action.version + 1)
            )
            session.add(
                AuditEvent(
                    actor=f"{realm}:{user_id}", event="interrupt_queued", object_id=binding.id
                )
            )
            return StopReceipt(str(action_id), False)

    async def cancel(self, action_id: str, realm: str, user_id: int) -> bool:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if not action:
            raise Conflict("action unavailable")
        needed = Permission.OPERATE if action.actor_id == user_id else Permission.MANAGE
        await self.bindings.get(action.binding_id, realm, user_id, needed)
        async with self.db.sessions.begin() as session:
            return await self._cancel_in_session(session, action)

    async def _cancel_in_session(self, session: AsyncSession, action: Action) -> bool:
        """Original queued/held-only CAS; caller owns Source and actor guards."""
        if self.fence is not None:
            await self.fence.lock(session)
        result = await session.execute(
            update(Action)
            .where(
                Action.id == action.id,
                Action.version == action.version,
                Action.state.in_(["queued", "held"]),
            )
            .values(state="cancelled", version=Action.version + 1)
        )
        return result.rowcount == 1  # type: ignore[attr-defined,no-any-return]
