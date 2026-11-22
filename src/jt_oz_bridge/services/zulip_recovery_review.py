"""Same-topic progress and one current Human's exact recovered-prompt selection."""

from __future__ import annotations

import asyncio
from typing import Any, cast

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.routing import RoutedInput, SavedReply
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import checksum, scope
from jt_oz_bridge.services.command_receipts import CommandClaim
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.zulip_gap_recovery import ZulipGapRecovery, run_payload
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, InputEvent, uid
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem

KIND = "zulip-recovery-review"


class ZulipRecoveryReview:
    def __init__(self, recovery: ZulipGapRecovery) -> None:
        self.recovery, self.router = recovery, recovery.router
        self.bindings, self.db = self.router.bindings, self.router.db
        self.reader, self.fence, self.tokens = (
            self.router.reader,
            recovery.fence,
            self.router.tokens,
        )
        self.tr = self.router.tr

    async def current(self, binding: Binding, message: HumanMessage) -> Binding:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "recovery"
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("recovery_review_current_human_source_required")
        actual = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if scope(actual) != scope(binding):
            raise Conflict("recovery_review_binding_scope_changed")
        return actual

    async def original_items(
        self, binding: Binding, message: HumanMessage, ids: set[int] | None = None
    ) -> list[tuple[ZulipRecoveryItem, Action]]:
        async with self.db.sessions() as session:
            rows = list(
                (
                    await session.scalars(
                        select(ZulipRecoveryItem)
                        .where(
                            ZulipRecoveryItem.source == self.recovery.journal.source,
                            ZulipRecoveryItem.binding_id == binding.id,
                            ZulipRecoveryItem.binding_revision == binding.revision,
                            ZulipRecoveryItem.actor_id == message.author_id,
                            ZulipRecoveryItem.state.in_(["held", "reviewed"]),
                            ZulipRecoveryItem.action_id == Action.id,
                            Action.state == "held",
                            *([ZulipRecoveryItem.message_id.in_(ids)] if ids is not None else []),
                        )
                        .order_by(ZulipRecoveryItem.message_id)
                        .limit(101)
                    )
                ).all()
            )
            result = []
            for item in rows:
                if ids is not None and item.message_id not in ids:
                    continue
                action = await session.get(Action, item.action_id) if item.action_id else None
                if action is None or action.state != "held" or action.operation != "prompt":
                    continue
                result.append((item, action))
        if len(result) > 100 or ids is not None and {item.message_id for item, _ in result} != ids:
            raise Conflict("recovery_exact_owned_prompt_selection_required")
        return result

    async def source_items(
        self, binding: Binding, message: HumanMessage, pairs: list[tuple[ZulipRecoveryItem, Action]]
    ) -> dict[str, Any]:
        result = {}
        for item, action in pairs:
            original = HumanMessage.model_validate(action.payload["source"])
            if (
                original.author_id != message.author_id
                or original.is_bot
                or original.deleted
                or original.revision != 0
                or original.message_id != item.message_id
                or parse_input(original.text, bound=True).kind != "prompt"
                or await self.reader.read(original.realm_id, original.message_id) != original
                or digest(action.payload) != action.operation_digest
                or action.payload["reference"] != scope(binding).reference.model_dump(mode="json")
            ):
                raise Conflict("recovery_original_prompt_bytes_or_scope_changed")
            result[action.id] = {
                "item": item.id,
                "version": item.version,
                "action_version": action.version,
                "action_digest": action.operation_digest,
                "source_hash": digest(original.model_dump(mode="json")),
            }
        return result

    async def epoch(
        self, binding: Binding
    ) -> tuple[ZulipRecoveryCheckpoint, InputEvent, dict[str, Any], dict[str, Any]]:
        async with self.db.sessions() as session:
            cp = await session.get(
                ZulipRecoveryCheckpoint, (self.recovery.journal.source, binding.channel_id)
            )
            if cp is None or cp.run_id is None:
                raise Conflict("recovery_checkpoint_missing")
            row = await session.get(InputEvent, cp.run_id)
            if row is None:
                raise Conflict("recovery_run_missing")
            value = run_payload(row, self.recovery.journal.source)
            target = value["scopes"].get(binding.id)
            if (
                target is None
                or value["fencing"] != self.fence.fencing
                or value["holder"] != self.fence.holder
                or BindingScope.model_validate(target["scope"]) != scope(binding)
                or row.state != "zulip_recovery_captured"
                or not all(p["captured"] for p in value["channels"].values())
            ):
                raise Conflict("recovery_capture_not_complete_or_epoch_changed")
            return cp, row, value, target

    async def route(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        arguments: str,
        claim: CommandClaim,
    ) -> RoutedInput:
        try:
            return await self._route(binding, message, locale, arguments, claim)
        except BaseException:
            # Same one-attempt command semantics: unknown local effects do not
            # become a reusable confirmation merely because publication failed.
            cleanup = asyncio.create_task(self.router.inbox.abandon(claim))
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    if cleanup.done():
                        break
            try:
                cleanup.result()
            except Conflict:
                pass  # A different owner must not be written through the old fence.
            raise

    async def _route(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        arguments: str,
        claim: CommandClaim,
    ) -> RoutedInput:
        binding = await self.current(binding, message)
        parts = arguments.split()
        commit = None
        if not parts:
            pairs = await self.original_items(binding, message)
            async with self.db.sessions() as session:
                cp = await session.get(
                    ZulipRecoveryCheckpoint, (self.recovery.journal.source, binding.channel_id)
                )
                run = await session.get(InputEvent, cp.run_id) if cp and cp.run_id else None
                status = "none" if run is None else run.state
                coverage = "unknown_before_anchor" if cp is None else cp.coverage
            rows = "\n".join(f"- `{item.message_id}`" for item, _ in pairs)
            text = self.tr.render(
                "recovery.progress", locale, status=status, coverage=coverage, count=len(pairs)
            )
            text += "\n\n" + (rows or self.tr.render("router.empty", locale))
            text += "\n\n`!oz recovery preview <message-ids|none>`"
        elif parts[0] == "preview":
            if parts == ["preview", "none"]:
                ids = set()
            else:
                if not 2 <= len(parts) <= 21 or any(
                    not v.isascii() or not v.isdecimal() for v in parts[1:]
                ):
                    raise Conflict("recovery_preview_requires_explicit_message_ids")
                ids = {int(v) for v in parts[1:]}
                if len(ids) != len(parts) - 1 or min(ids) <= 0:
                    raise Conflict("recovery_duplicate_or_invalid_selection")
            cp, run, value, target = await self.epoch(binding)
            pairs = await self.original_items(binding, message, ids)
            selected = await self.source_items(binding, message, pairs)
            binding = await self.current(binding, message)
            context = {
                "scope_sha256": checksum(scope(binding)),
                "queue_revision": binding.queue_revision,
                "run_id": run.id,
                "run_sha256": run.payload_hash,
                "holder": self.fence.holder,
                "fencing": self.fence.fencing,
                "items": selected,
                "message_ids": sorted(ids),
                "previous_paused": target["previous_paused"],
            }
            if not binding.dispatch_paused or binding.queue_revision != target["queue_revision"]:
                raise Conflict("recovery_owned_pause_changed")
            token = await self.tokens.issue(
                KIND,
                message.realm_id,
                message.author_id,
                context,
                binding_id=binding.id,
                binding_revision=binding.revision,
                ttl=300,
            )
            text = self.tr.render(
                "recovery.preview", locale, ids=", ".join(map(str, sorted(ids))) or "0"
            )
            text += "\n\n" + self.tr.render(
                "recovery.keep_paused"
                if target["previous_paused"]
                else "recovery.release_selected",
                locale,
            )
            text += f"\n\n`!oz recovery confirm {token}`"
        elif parts[0] == "confirm" and len(parts) == 2:
            saved = await self.tokens.inspect(parts[1], KIND, message.realm_id, message.author_id)
            cp, run, value, target = await self.epoch(binding)
            context = saved.context
            if (
                (saved.binding_id, saved.binding_revision) != (binding.id, binding.revision)
                or context.get("scope_sha256") != checksum(scope(binding))
                or context.get("queue_revision") != binding.queue_revision
                or (context.get("run_id"), context.get("run_sha256")) != (run.id, run.payload_hash)
                or (context.get("holder"), context.get("fencing"))
                != (self.fence.holder, self.fence.fencing)
                or not binding.dispatch_paused
                or binding.queue_revision != target["queue_revision"]
            ):
                raise Conflict("recovery_confirmation_scope_or_pause_changed")
            pairs = await self.original_items(binding, message, set(context["message_ids"]))
            selected = await self.source_items(binding, message, pairs)
            if selected != context["items"]:
                raise Conflict("recovery_selection_changed_after_preview")
            binding = await self.current(binding, message)
            review_id = uid()
            released = not target["previous_paused"]

            async def commit(session: AsyncSession) -> None:
                with self.recovery.limits.watch(session, self.recovery.journal.source):
                    await self.fence.lock(session)
                    current = await lock_output_scope(self.bindings, session, binding)
                    operator = await session.scalar(
                        select(Grant.id)
                        .where(
                            Grant.realm_id == message.realm_id,
                            Grant.user_id == message.author_id,
                            Grant.project_id == binding.project_id,
                            Grant.active.is_(True),
                            Grant.role.in_(
                                [r for r, p in ROLES.items() if Permission.OPERATE in p]
                            ),
                        )
                        .with_for_update()
                    )
                    if operator is None:
                        raise AccessDenied("recovery_confirm_operate_revoked")
                    if (
                        not current.dispatch_paused
                        or current.queue_revision != context["queue_revision"]
                        or context["holder"] != self.fence.holder
                        or context["fencing"] != self.fence.fencing
                    ):
                        raise Conflict("recovery_final_owned_pause_changed")
                    live_cp = await session.get(
                        ZulipRecoveryCheckpoint, (self.recovery.journal.source, binding.channel_id)
                    )
                    live_run = await session.get(InputEvent, run.id)
                    if (
                        live_cp is None
                        or live_run is None
                        or live_cp.run_id != run.id
                        or live_run.payload_hash != context["run_sha256"]
                        or digest(live_run.payload) != live_run.payload_hash
                        or live_run.state != "zulip_recovery_captured"
                    ):
                        raise Conflict("recovery_final_epoch_changed")
                    unexpected = await session.scalar(
                        select(Action.id)
                        .where(Action.binding_id == binding.id, Action.state == "queued")
                        .limit(1)
                    )
                    if unexpected is not None:
                        raise Conflict("recovery_unselected_queued_work_exists")
                    await self.tokens.consume_in_session(session, saved, database_deadline=True)
                    clock = (
                        (func.julianday("now") - 2440587.5) * 86400.0
                        if self.db.engine.dialect.name == "sqlite"
                        else func.extract("epoch", func.clock_timestamp())
                    )
                    confirmed_at = float(cast(float, await session.scalar(select(clock))))
                    if confirmed_at >= saved.expires_at:
                        raise Conflict("recovery_confirmation_expired_during_commit")
                    reviewed = {
                        action.id: {
                            "item": item.id,
                            "version": item.version + 1,
                            "action_digest": context["items"][action.id]["action_digest"],
                            "source_hash": context["items"][action.id]["source_hash"],
                        }
                        for item, action in pairs
                    }
                    proof = {
                        "format": "zulip-recovery-review-v1",
                        "scope_sha256": checksum(scope(current)),
                        "run_id": run.id,
                        "items": reviewed,
                        "source": message.model_dump(mode="json"),
                        "actor_id": message.author_id,
                        "holder": self.fence.holder,
                        "fencing": self.fence.fencing,
                        "token_sha256": saved.token_hash,
                        "token_context_sha256": saved.context_hash,
                        "token_expires_at": saved.expires_at,
                        "confirmed_at": confirmed_at,
                        "released": released,
                    }
                    session.add(
                        InputEvent(
                            id=review_id,
                            source="zulip-recovery-review:" + self.recovery.journal.source,
                            source_id=review_id,
                            revision=0,
                            payload=proof,
                            payload_hash=digest(proof),
                            state="zulip_recovery_reviewed",
                        )
                    )
                    await session.flush()
                    for item, action in pairs:
                        live_item = await session.get(ZulipRecoveryItem, item.id)
                        live_action = await session.get(Action, action.id)
                        original = context["items"][action.id]
                        if (
                            live_item is None
                            or live_action is None
                            or live_item.version != original["version"]
                            or live_item.actor_id != message.author_id
                            or live_item.action_id != action.id
                            or live_item.state not in {"held", "reviewed"}
                            or live_action.state != "held"
                            or live_action.version != original["action_version"]
                            or live_action.operation_digest != original["action_digest"]
                            or digest(live_action.payload) != original["action_digest"]
                            or digest(live_action.payload["source"]) != original["source_hash"]
                        ):
                            raise Conflict("recovery_final_selection_changed")
                        live_item.state, live_item.version = "reviewed", live_item.version + 1
                        live_item.review_receipt_id = review_id
                        reviewed[action.id] = {
                            "item": item.id,
                            "version": live_item.version,
                            "action_digest": original["action_digest"],
                            "source_hash": original["source_hash"],
                        }
                        if released:
                            live_action.state, live_action.version = (
                                "queued",
                                live_action.version + 1,
                            )
                    await session.flush()
                    if released:
                        current.dispatch_paused, current.queue_revision = (
                            False,
                            current.queue_revision + 1,
                        )
                    session.add(
                        AuditEvent(
                            actor=f"{message.realm_id}:{message.author_id}",
                            event="zulip_recovered_prompts_reviewed",
                            object_id=review_id,
                        )
                    )
                    await session.flush()
                    await self.fence.lock(session)
                    await lock_output_scope(self.bindings, session, binding)
                    role = await session.scalar(
                        select(Grant.id).where(
                            Grant.realm_id == message.realm_id,
                            Grant.user_id == message.author_id,
                            Grant.project_id == binding.project_id,
                            Grant.active.is_(True),
                            Grant.role.in_(
                                [r for r, p in ROLES.items() if Permission.OPERATE in p]
                            ),
                        )
                    )
                    if role is None:
                        raise AccessDenied("recovery_final_operate_revoked")

            text = self.tr.render(
                "recovery.confirmed" if released else "recovery.keep_paused", locale
            )
        else:
            raise Conflict("invalid_recovery_operation")
        await self.current(binding, message)
        await self.router.inbox.finish(
            claim, SavedReply(text=text, locale=locale).model_dump(mode="json"), commit=commit
        )
        return RoutedInput(
            "reply", binding.id, binding.revision, text, "command:" + claim.id, locale=locale
        )
