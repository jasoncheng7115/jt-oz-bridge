"""Live explicit creation controls and a fenced one-attempt background worker.

Reservation replies are inert receipts, not unbound output permissions. Only
activation publishes the canonical success notice; status is a fresh command.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pydantic import Field
from sqlalchemy import select

from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import literal
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import topic_key
from jt_oz_bridge.services.command_receipts import CommandClaim, CommandInbox
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.session_creation_activation import SessionCreationActivation
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent

if TYPE_CHECKING:
    from jt_oz_bridge.services.session_fork_registration import SessionForkRegistration

LOG = logging.getLogger(__name__)
CODE = re.compile(r"[a-z][a-z0-9_]{0,99}")


class SavedCreationReply(ControlModel):
    origin: Literal["creation"] = "creation"
    kind: Literal["reserve", "resume"]
    action_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    locale: Locale


@dataclass(frozen=True)
class CreationResult:
    text: str = ""
    projects: tuple[str, ...] = ()
    receipt: SavedCreationReply | None = None


class CreationCommands:
    def __init__(
        self,
        activation: SessionCreationActivation,
        inbox: CommandInbox,
        discovery: DiscoveryService,
    ) -> None:
        journal = activation.journal
        if (
            inbox.db is not journal.db
            or inbox.fence != journal.fence
            or discovery.bindings is not journal.bindings
        ):
            raise ValueError("creation_commands_require_original_pipeline")
        self.activation, self.journal = activation, journal
        self.inbox, self.discovery = inbox, discovery
        self.db, self.fence, self.reader = journal.db, journal.fence, journal.reader
        self.tr, self._worker = Translator(), asyncio.Lock()
        # Trusted composition only: topics reserved for a confirmed fork.
        self.forks: SessionForkRegistration | None = None

    async def selected(
        self, message: HumanMessage, *, exact_audience: bool = True
    ) -> tuple[Action, Binding] | None:
        await self.journal.source(message)
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.realm_id == message.realm_id,
                            Binding.topic_key
                            == topic_key(message.realm_id, message.channel_id, message.topic),
                            Binding.state == "creating",
                            Action.operation == "session.create",
                        )
                        .limit(2)
                    )
                ).all()
            )
        if len(ids) > 1:
            raise Conflict("creation_topic_has_multiple_owned_actions")
        if not ids:
            return None
        action, binding = await self.journal.load(ids[0])
        project, _, _ = self.journal.payload(action, binding)
        audience = await self.journal.authority(message, project)
        if exact_audience and (audience.revision, sorted(audience.user_ids)) != (
            binding.audience_revision,
            binding.audience_user_ids,
        ):
            raise AccessDenied("creation_control_current_audience_changed")
        return action, binding

    async def menu(self, message: HumanMessage, locale: Locale, page: str = "") -> CreationResult:
        choices, audience = [], None
        allowed = self.discovery.channel_projects.get(message.channel_id)
        for key, project in sorted(self.journal.projects.items()):
            if allowed is not None and key not in allowed:
                continue  # A project channel only offers its own projects.
            try:
                seen = await self.journal.authority(message, project)
            except AccessDenied:
                continue
            if audience is not None and seen != audience:
                raise Conflict("creation_menu_audience_changed")
            audience = seen
            choices.append((key, project.checksum()))
        if not choices or audience is None:
            raise AccessDenied("no_authorized_creation_project")
        context = {
            "channel_id": message.channel_id,
            "topic": message.topic,
            "audience_sha256": digest(audience.model_dump(mode="json")),
            "projects": [list(p) for p in choices],
        }
        offset = 0
        if page:
            page_control = await self.journal.tokens.inspect(
                page, "creation-page", message.realm_id, message.author_id
            )
            offset = page_control.context.get("offset", -1)
            if (
                type(offset) is not int
                or not 0 < offset < len(choices)
                or page_control.context != {**context, "offset": offset}
            ):
                raise Conflict("creation_menu_page_changed")
            await self.journal.tokens.consume(
                page, "creation-page", message.realm_id, message.author_id
            )
        lines, projects = [self.tr.render("creation.menu", locale)], []
        for key, _ in choices[offset : offset + 10]:
            token = await self.journal.offer(key, message)
            lines.append(
                self.tr.render("creation.choice", locale, project=literal(key[:180]), token=token)
            )
            projects.append(key)
        if offset + 10 < len(choices):
            token = await self.journal.tokens.issue(
                "creation-page",
                message.realm_id,
                message.author_id,
                {**context, "offset": offset + 10},
            )
            lines.append("!oz new page " + token)
        return CreationResult("\n\n".join(lines), tuple(projects))

    async def processing(
        self, message: HumanMessage, claim: CommandClaim, command: str = "new"
    ) -> CommandReceipt:
        current = await self.inbox.find(message.realm_id, message.message_id)
        if current is None or (
            current.id,
            current.version,
            current.state,
            current.command,
            current.source_hash,
            current.binding_id,
            current.holder,
            current.fencing,
        ) != (
            claim.id,
            claim.version,
            "processing",
            command,
            digest(message.model_dump(mode="json")),
            None,
            self.fence.holder,
            self.fence.fencing,
        ):
            raise Conflict("creation_requires_current_command_claim")
        return current

    async def command(
        self, message: HumanMessage, arguments: str, locale: Locale, claim: CommandClaim
    ) -> CreationResult:
        await self.processing(message, claim)
        if not arguments:
            return await self.menu(message, locale)
        parts = arguments.split()
        if parts[0] == "page":
            if len(parts) != 2:
                raise ValueError("invalid_creation_page")
            return await self.menu(message, locale, parts[1])
        controls = {"status", "pause", "resume", "cancel"}
        if parts[0] in controls:
            if len(parts) != 1:
                raise ValueError("invalid_creation_control_arguments")
            selected = await self.selected(message, exact_audience=parts[0] == "resume")
            if selected is None:
                return CreationResult(self.tr.render("creation.none", locale))
            action, binding = selected
            if parts[0] == "status":
                return CreationResult(self.status(action, binding, locale), (binding.project_id,))
            return await self.control(message, locale, claim, action, binding, parts[0])
        if await self.selected(message) is not None:
            raise Conflict("creation_topic_already_reserved")
        identity = await self.journal.reserve(message, locale)
        return CreationResult(
            receipt=SavedCreationReply(
                kind="reserve",
                action_id=identity,
                source_sha256=digest(message.model_dump(mode="json")),
                locale=locale,
            )
        )

    async def choose(
        self,
        message: HumanMessage,
        locale: Locale,
        claim: CommandClaim,
        offer: str,
        choice: int,
        prompt: HumanMessage | None,
    ) -> CreationResult:
        """`!N` on a new-topic menu row: reserve exactly as `!oz new <token>` would."""
        await self.processing(message, claim, "choose")
        if await self.selected(message) is not None:
            raise Conflict("creation_topic_already_reserved")
        identity = await self.journal.reserve(
            message, locale, offer=offer, choice=choice, prompt=prompt
        )
        return CreationResult(
            receipt=SavedCreationReply(
                kind="reserve",
                action_id=identity,
                source_sha256=digest(message.model_dump(mode="json")),
                locale=locale,
            )
        )

    def status(self, action: Action, binding: Binding, locale: Locale) -> str:
        state = (
            action.state
            if action.state
            in {"queued", "held", "dispatching", "ambiguous", "admitted", "rejected"}
            else "held"
        )
        text = self.tr.render(
            "creation.status",
            locale,
            state=self.tr.render("creation.state." + state, locale),
            paused=self.tr.render(
                "creation.paused" if binding.dispatch_paused else "creation.ready", locale
            ),
        )
        if action.state in {"queued", "held"} and not action.admission:
            # Nothing reached OpenCode yet, so `!no` can still drop it.
            text += " " + self.tr.render("creation.cancel_hint", locale)
        return text

    async def word(
        self,
        message: HumanMessage,
        locale: Locale,
        claim: CommandClaim,
        command: str,
        operation: Literal["pause", "resume", "cancel"],
    ) -> CreationResult | None:
        """`!stop`, `!go` or `!no` in a topic still creating its conversation; else None."""
        await self.processing(message, claim, command)
        selected = await self.selected(message, exact_audience=operation == "resume")
        if selected is None:
            return None
        action, binding = selected
        return await self.control(message, locale, claim, action, binding, operation)

    async def reserved_here(self, message: HumanMessage, locale: Locale) -> CreationResult | None:
        """Plain text in a topic still creating its conversation gets that status, not a menu."""
        if self.forks is not None:
            opened = await self.forks.opened(message, locale)
            if opened is not None:
                return CreationResult(opened[0], (opened[1],))
        selected = await self.selected(message, exact_audience=False)
        if selected is None:
            return None
        action, binding = selected
        return CreationResult(
            self.tr.render("creation.reserved_here", locale)
            + "\n\n"
            + self.status(action, binding, locale),
            (binding.project_id,),
        )

    async def control(
        self,
        message: HumanMessage,
        locale: Locale,
        claim: CommandClaim,
        action: Action,
        binding: Binding,
        operation: str,
    ) -> CreationResult:
        project, _, _ = self.journal.payload(action, binding)
        audience = await self.journal.authority(message, project)
        if operation == "resume":
            if action.state not in {"queued", "held", "dispatching", "ambiguous", "admitted"}:
                raise Conflict("creation_rejected_attempt_requires_cancel_and_new_intent")
            await self.journal.authorized(action, binding)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.journal.lock_authority(session, message, project, audience)
            current = await session.get(Action, action.id, with_for_update=True)
            reserved = await session.get(Binding, binding.id, with_for_update=True)
            receipt = await session.get(CommandReceipt, claim.id, with_for_update=True)
            if (
                current is None
                or reserved is None
                or receipt is None
                or (
                    current.version,
                    current.state,
                    reserved.state,
                    reserved.dispatch_paused,
                    receipt.state,
                    receipt.holder,
                    receipt.fencing,
                )
                != (
                    action.version,
                    action.state,
                    "creating",
                    binding.dispatch_paused,
                    "processing",
                    self.fence.holder,
                    self.fence.fencing,
                )
            ):
                raise Conflict("creation_control_state_changed")
            self.journal.payload(current, reserved)
            if operation == "cancel":
                safe = (current.state in {"queued", "held"} and not current.admission) or (
                    current.state == "rejected"
                    and current.status_reason == "creation_proven_not_sent"
                )
                if not safe:
                    return CreationResult(
                        self.tr.render("creation.cancel_uncertain", locale),
                        (binding.project_id,),
                    )
                current.state, current.status_reason = "cancelled", "creation_cancelled_before_send"
                reserved.state, reserved.topic_key, reserved.session_key = "unbound", None, None
                reserved.revision += 1
                reserved.dispatch_paused = True
            elif operation == "pause":
                reserved.dispatch_paused = True
                current.status_reason = "creation_paused_by_operator"
            elif operation == "resume":
                reserved.dispatch_paused = False
                if current.state == "queued" and current.admission:
                    raise Conflict("creation_queue_already_has_a_send_attempt")
                if current.state == "held":
                    if current.admission:
                        raise Conflict("creation_held_with_possible_attempt")
                    current.state = "queued"
                elif current.state == "dispatching":
                    current.state = "ambiguous"
                current.status_reason = "creation_explicit_resume"
                if current.state == "queued":
                    current.native_result = {
                        "queue_resume": {
                            "receipt_id": claim.id,
                            "source": message.model_dump(mode="json"),
                        }
                    }
                else:
                    current.native_result = {
                        **current.native_result,
                        "recovery_resume": {
                            "receipt_id": claim.id,
                            "source": message.model_dump(mode="json"),
                        },
                    }
            else:
                raise ValueError("invalid_creation_control")
            current.version += 1
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="session_create_" + operation,
                    object_id=current.id,
                )
            )
        if operation == "resume":
            return CreationResult(
                receipt=SavedCreationReply(
                    kind="resume",
                    action_id=action.id,
                    source_sha256=digest(message.model_dump(mode="json")),
                    locale=locale,
                )
            )
        return CreationResult(
            self.tr.render("creation." + operation, locale), (binding.project_id,)
        )

    async def replay(self, saved: SavedCreationReply, message: HumanMessage) -> None:
        if saved.source_sha256 != digest(message.model_dump(mode="json")):
            raise Conflict("creation_receipt_source_changed")
        await self.journal.source(message)
        async with self.db.sessions() as session:
            action = await session.get(Action, saved.action_id)
            binding = await session.get(Binding, action.binding_id) if action else None
        if action is None or binding is None:
            raise Conflict("creation_replay_action_removed")
        if action.state == "cancelled":
            original = HumanMessage.model_validate(action.payload.get("source"))
            if (
                saved.kind != "reserve"
                or original != message
                or action.operation_digest != digest(action.payload)
                or action.status_reason != "creation_cancelled_before_send"
                or binding.state != "unbound"
                or binding.topic_key is not None
                or binding.session_key is not None
            ):
                raise Conflict("creation_cancelled_receipt_changed")
            project = self.journal.projects[binding.project_id]
            await self.journal.authority(message, project)
            return
        action, binding = await self.journal.load(saved.action_id)
        _, _, original = self.journal.payload(action, binding)
        if saved.kind == "reserve" and original != message:
            raise Conflict("creation_receipt_is_not_original_reservation")
        if (binding.realm_id, binding.channel_id, binding.topic) != (
            message.realm_id,
            message.channel_id,
            message.topic,
        ):
            raise Conflict("creation_receipt_current_topic_changed")
        await self.journal.authorized(action, binding)

    async def hold(self, action: Action, reason: str) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            saved = await session.get(Action, action.id, with_for_update=True)
            binding = await session.get(Binding, action.binding_id, with_for_update=True)
            if saved is None or binding is None or saved.version != action.version:
                return
            self.journal.payload(saved, binding)
            binding.dispatch_paused = True
            if saved.state == "queued" and not saved.admission:
                saved.state = "held"
            if not (
                saved.state == "rejected" and saved.status_reason == "creation_proven_not_sent"
            ):
                saved.status_reason = reason
            saved.version += 1

    async def live_queue(self, action: Action, binding: Binding) -> bool | None:
        if action.admission:
            raise Conflict("creation_queue_already_has_a_send_attempt")
        _, _, source = self.journal.payload(action, binding)
        resume = action.native_result.get("queue_resume")
        if resume is not None:
            return await self.live_resume(action, binding, resume)
        receipt = await self.inbox.find(source.realm_id, source.message_id)
        return await self.live_receipt(action, binding, source, receipt, "reserve")

    async def live_resume(self, action: Action, binding: Binding, resume: object) -> bool | None:
        if not isinstance(resume, dict) or set(resume) != {"receipt_id", "source"}:
            raise Conflict("creation_resume_receipt_invalid")
        source = HumanMessage.model_validate(resume["source"])
        async with self.db.sessions() as session:
            receipt = await session.get(CommandReceipt, resume["receipt_id"])
        return await self.live_receipt(action, binding, source, receipt, "resume")

    async def live_receipt(
        self,
        action: Action,
        binding: Binding,
        source: HumanMessage,
        receipt: CommandReceipt | None,
        kind: Literal["reserve", "resume"],
    ) -> bool | None:
        project, _, _ = self.journal.payload(action, binding)
        if receipt is None:
            return False  # The command claim must precede reservation.
        if (receipt.holder, receipt.fencing) != (self.fence.holder, self.fence.fencing):
            return False
        if receipt.state == "processing":
            return None
        if receipt.state != "completed" or receipt.binding_id is not None:
            return False
        saved = SavedCreationReply.model_validate(receipt.response)
        # A resume is `!oz new resume` or `!go` typed in the creating topic.
        resumed_by_go = kind == "resume" and receipt.command == "go"
        if (
            saved.kind,
            saved.action_id,
            saved.source_sha256,
            receipt.source_hash,
            "new" if resumed_by_go else receipt.command,
            receipt.actor_id,
            receipt.channel_id,
            receipt.topic,
            receipt.realm_id,
            receipt.message_id,
            receipt.source_revision,
        ) != (
            kind,
            action.id,
            digest(source.model_dump(mode="json")),
            digest(source.model_dump(mode="json")),
            "choose"
            if kind == "reserve" and action.payload.get("menu_choice") is not None
            else "new",
            source.author_id,
            source.channel_id,
            source.topic,
            source.realm_id,
            source.message_id,
            0,
        ) or (source.realm_id, source.channel_id, source.topic) != (
            binding.realm_id,
            binding.channel_id,
            binding.topic,
        ):
            raise Conflict("creation_queue_command_receipt_changed")
        await self.journal.authority(source, project)
        return True

    async def recover(self) -> None:
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Action.operation == "session.create",
                            Binding.state == "creating",
                            Binding.realm_id == self.activation.replies.realm_id,
                            Binding.project_id.in_(self.journal.projects),
                            Action.state.in_(["queued", "dispatching"]),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(1001)
                    )
                ).all()
            )
        if len(ids) > 1000:
            raise Conflict("creation_pending_recovery_capacity_exceeded")
        for identity in ids:
            action, binding = await self.journal.load(identity)
            if action.state == "dispatching":
                await self.journal.settle(
                    action, "ambiguous", "creation_recovered_fixed_id_readback"
                )
            else:
                # A runtime never treats an old queued command as live input.
                await self.hold(action, "creation_recovered_queue_requires_resume")

    async def once(self) -> None:
        async with self._worker:
            async with self.db.sessions() as session:
                ids = tuple(
                    (
                        await session.scalars(
                            select(Action.id)
                            .join(Binding, Binding.id == Action.binding_id)
                            .where(
                                Action.operation == "session.create",
                                Binding.state == "creating",
                                Binding.realm_id == self.activation.replies.realm_id,
                                Binding.project_id.in_(self.journal.projects),
                                Binding.dispatch_paused.is_(False),
                                Action.state.in_(
                                    ["queued", "dispatching", "ambiguous", "admitted"]
                                ),
                            )
                            .order_by(Action.created_at, Action.id)
                            .limit(10)
                        )
                    ).all()
                )
            for identity in ids:
                action = None
                try:
                    action, binding = await self.journal.load(identity)
                    factory = self.activation.factories[binding.project_id]
                    resume = action.native_result.get("recovery_resume")
                    if resume is not None:
                        eligible = await self.live_resume(action, binding, resume)
                        if eligible is None:
                            continue
                        if not eligible:
                            await self.hold(action, "creation_recovery_requires_live_resume")
                            continue
                    if action.state == "queued":
                        eligible = await self.live_queue(action, binding)
                        if eligible is None:
                            continue
                        if not eligible:
                            await self.hold(action, "creation_queue_requires_live_resume")
                            continue
                    if action.state == "dispatching":
                        await self.journal.settle(action, "ambiguous", "creation_fixed_id_readback")
                    state = await self.journal.advance(
                        identity, factory.creator, recover_existing=resume is not None
                    )
                    if state == "admitted":

                        async def recovery_authority(
                            identity: str = identity, resume: object = resume
                        ) -> bool:
                            current, reserved = await self.journal.load(identity)
                            return (
                                current.native_result.get("recovery_resume") == resume
                                and await self.live_resume(current, reserved, resume) is True
                            )

                        await self.activation.reconcile(
                            identity,
                            restore=resume is not None,
                            recovery_authority=recovery_authority if resume is not None else None,
                        )
                    elif state in {"ambiguous", "rejected"}:
                        latest, _ = await self.journal.load(identity)
                        await self.hold(latest, "creation_explicit_reconciliation_required")
                except (ZulipReadUnavailable, DeliveryRateLimited):
                    raise
                except (AccessDenied, Conflict, ValueError) as error:
                    if await self.cancelled(identity):
                        continue
                    # Only a fixed code: other ValueErrors may quote saved content.
                    code = str(error) if CODE.fullmatch(str(error)) else "-"
                    LOG.warning(
                        "creation_held action=%s kind=%s code=%s",
                        identity,
                        type(error).__name__,
                        code,
                    )
                    latest, _ = await self.journal.load(identity)
                    await self.hold(latest, "creation_authority_or_readback_changed")

    async def cancelled(self, identity: str) -> bool:
        """A concurrent proven-unsent cancellation may release a selected row."""
        async with self.db.sessions() as session:
            action = await session.get(Action, identity)
            binding = await session.get(Binding, action.binding_id) if action else None
        return bool(
            action is not None
            and binding is not None
            and action.operation == "session.create"
            and action.state == "cancelled"
            and action.status_reason == "creation_cancelled_before_send"
            and action.operation_digest == digest(action.payload)
            and binding.state == "unbound"
            and binding.realm_id == self.activation.replies.realm_id
            and binding.project_id in self.journal.projects
            and binding.revision == action.binding_revision + 1
            and binding.session_key is None
            and binding.topic_key is None
        )
