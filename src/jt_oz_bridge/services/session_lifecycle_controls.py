"""Fork, compact and revert on a bound original session: preview, then one !confirm.

Every step rereads the original Human messages, grant, audience and Native state.
A confirmation records one durable Action; only the dispatcher may reach Native,
once. Nothing here creates, rebinds or replaces a session. A fork's own topic is
registered afterwards, from the completed Action, by `SessionForkRegistration`.
"""

import time
from typing import Literal, Protocol, cast

from pydantic import Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_publish import CONFIRM_TOKEN as PUBLISH_CONFIRM
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.domain.session_lifecycle import (
    LIFECYCLE_COMMANDS,
    LIFECYCLE_CONFIRM_TOKEN,
    LIFECYCLE_MENU_TOKEN,
    LifecycleOperation,
    SessionLifecycleChange,
    SessionLifecycleRequest,
    SessionMessageChoice,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant

MENU_TTL = 300
CONFIRM_TTL = 120
QUEUED_TTL = 120
COMMANDS = frozenset({"fork", "compact", "revert", "choose", "confirm"})
# Starting a lifecycle control replaces any Agent or Git confirmation still open here.
AGENT_TOKENS = ("native-agent-menu", "native-agent-confirm", PUBLISH_CONFIRM)


class LifecycleReader(Protocol):
    async def pending_revert(self, reference: SessionRef) -> str | None: ...

    async def recent_user_messages(
        self, reference: SessionRef
    ) -> tuple[SessionMessageChoice, ...]: ...


class LifecycleMenu(ControlModel):
    operation: Literal["session.fork", "session.revert.stage"]
    reference: SessionRef
    source: HumanMessage
    files: bool = False
    pending_revert_message_id: str | None = None
    items: tuple[SessionMessageChoice, ...] = Field(min_length=1, max_length=10)


class LifecycleConfirmation(ControlModel):
    reference: SessionRef
    change: SessionLifecycleChange
    preview_sources: tuple[HumanMessage, ...] = Field(min_length=1, max_length=2)


class SessionLifecycleControls:
    def __init__(
        self,
        bindings: BindingService,
        tokens: TokenService,
        reader: SourceReader,
        capabilities: CapabilityLookup,
        *,
        fork_topics: frozenset[str] = frozenset(),
    ) -> None:
        if tokens.db is not bindings.db or tokens.fence is None:
            raise ValueError("session_lifecycle_requires_shared_database_and_consumer_fence")
        self.bindings, self.db, self.tokens = bindings, bindings.db, tokens
        self.reader, self.fence = reader, tokens.fence
        self.capabilities, self.tr = capabilities, Translator()
        # Projects whose confirmed forks get their own topic; the preview says which.
        self.fork_topics = fork_topics

    def supported(self, binding: Binding, operation: str) -> bool:
        try:
            capability = self.capabilities(reference(binding)).get(operation)
        except (ValueError, TypeError):
            return False
        return capability is not None and capability.supported

    def available(self, binding: Binding, command: str) -> bool:
        return any(
            self.supported(binding, operation)
            for operation, name in LIFECYCLE_COMMANDS.items()
            if name == command
        )

    async def current(self, binding: Binding, message: HumanMessage) -> Binding:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in COMMANDS
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("session_lifecycle_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("session_lifecycle_binding_changed")
        return current

    async def _latest(
        self, kind: str, binding: Binding, message: HumanMessage
    ) -> ControlToken | None:
        async with self.db.sessions() as session:
            saved: ControlToken | None = await session.scalar(
                select(ControlToken)
                .where(
                    ControlToken.kind == kind,
                    ControlToken.realm_id == message.realm_id,
                    ControlToken.user_id == message.author_id,
                    ControlToken.binding_id == binding.id,
                    ControlToken.binding_revision == binding.revision,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                )
                .order_by(ControlToken.expires_at.desc())
                .limit(1)
            )
        if saved is not None and saved.context_hash != digest(saved.context):
            raise Conflict("session_lifecycle_token_context_changed")
        return saved

    async def owns_choice(self, binding: Binding, message: HumanMessage) -> bool:
        return await self._latest(LIFECYCLE_MENU_TOKEN, binding, message) is not None

    async def owns_confirm(self, binding: Binding, message: HumanMessage) -> bool:
        return await self._latest(LIFECYCLE_CONFIRM_TOKEN, binding, message) is not None

    async def _retire(self, session: AsyncSession, binding: Binding, message: HumanMessage) -> None:
        await session.execute(
            update(ControlToken)
            .where(
                ControlToken.kind.in_(
                    [LIFECYCLE_MENU_TOKEN, LIFECYCLE_CONFIRM_TOKEN, *AGENT_TOKENS]
                ),
                ControlToken.realm_id == message.realm_id,
                ControlToken.user_id == message.author_id,
                ControlToken.binding_id == binding.id,
                ControlToken.used.is_(False),
            )
            .values(used=True)
        )

    async def _lock_operator(
        self, session: AsyncSession, binding: Binding, message: HumanMessage
    ) -> Binding:
        await self.fence.lock(session)
        current = await lock_output_scope(self.bindings, session, binding)
        grant = await session.scalar(
            select(Grant.id)
            .where(
                Grant.realm_id == message.realm_id,
                Grant.user_id == message.author_id,
                Grant.project_id == binding.project_id,
                Grant.active.is_(True),
                Grant.role.in_([r for r, p in ROLES.items() if Permission.OPERATE in p]),
            )
            .with_for_update()
        )
        if grant is None:
            raise AccessDenied("session_lifecycle_operate_grant_changed")
        return current

    def _view(self) -> LifecycleReader:
        return cast(LifecycleReader, self.bindings.control)

    async def _blocked(self, binding: Binding, locale: Locale) -> str | None:
        if binding.dispatch_paused:
            return self.tr.render("lifecycle.paused", locale)
        snapshot = await self.bindings.control.snapshot(reference(binding))
        if snapshot.reference != reference(binding) or not snapshot.reconciled:
            raise Conflict("session_lifecycle_original_snapshot_unavailable")
        if snapshot.state != ExecutionState.IDLE:
            return self.tr.render("lifecycle.busy", locale)
        return None

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        parsed = parse_input(message.text, bound=True)
        if parsed.command != command or parsed.arguments != arguments:
            raise Conflict("session_lifecycle_route_source_mismatch")
        words = arguments.split()
        operation: LifecycleOperation
        menu = False
        files = False
        if command == "fork" and words in ([], ["pick"]):
            operation, menu = "session.fork", bool(words)
        elif command == "compact" and not words:
            operation = "session.compact"
        elif command == "revert" and words in ([], ["files"]):
            operation, menu, files = "session.revert.stage", True, bool(words)
        elif command == "revert" and words == ["clear"]:
            operation = "session.revert.clear"
        elif command == "revert" and words == ["commit"]:
            operation = "session.revert.commit"
        else:
            raise ValueError("session_lifecycle_arguments_invalid")
        binding = await self.current(binding, message)
        if not self.supported(binding, operation):
            return self.tr.render("lifecycle.unavailable", locale)
        blocked = await self._blocked(binding, locale)
        if blocked is not None:
            return blocked
        pending = await self._view().pending_revert(reference(binding))
        if operation == "session.compact" and pending is not None:
            return self.tr.render("lifecycle.revert_pending", locale)
        if operation in {"session.revert.clear", "session.revert.commit"} and pending is None:
            return self.tr.render("lifecycle.no_pending_revert", locale)
        if menu:
            assert operation in {"session.fork", "session.revert.stage"}
            return await self._menu(
                binding,
                message,
                locale,
                cast(Literal["session.fork", "session.revert.stage"], operation),
                files,
                pending,
            )
        change = SessionLifecycleChange(operation=operation, pending_revert_message_id=pending)
        return await self._preview(binding, message, locale, change, (message,))

    async def _menu(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        operation: Literal["session.fork", "session.revert.stage"],
        files: bool,
        pending: str | None,
    ) -> str:
        items = await self._view().recent_user_messages(reference(binding))
        if not items:
            return self.tr.render("lifecycle.no_messages", locale)
        binding = await self.current(binding, message)
        async with self.db.sessions.begin() as session:
            await self._lock_operator(session, binding, message)
            await self._retire(session, binding, message)
        await self.tokens.issue(
            LIFECYCLE_MENU_TOKEN,
            message.realm_id,
            message.author_id,
            LifecycleMenu(
                operation=operation,
                reference=reference(binding),
                source=message,
                files=files,
                pending_revert_message_id=pending,
                items=items[:10],
            ).model_dump(mode="json"),
            ttl=MENU_TTL,
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        title = "lifecycle.fork_menu" if operation == "session.fork" else "lifecycle.revert_menu"
        lines = [self.tr.render(title, locale)]
        lines += [f"{i}. {visible(item.preview)}" for i, item in enumerate(items[:10], 1)]
        last = min(len(items), 10)
        choices = "`!1`" if last == 1 else f"`!1`–`!{last}`"
        lines.append(self.tr.render("lifecycle.menu_choose", locale, choices=choices))
        return "\n\n".join((lines[0], "\n".join(lines[1:-1]), lines[-1]))

    async def choose(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        binding = await self.current(binding, message)
        saved = await self._latest(LIFECYCLE_MENU_TOKEN, binding, message)
        if saved is None:
            raise Conflict("session_lifecycle_menu_unavailable")
        menu = LifecycleMenu.model_validate(saved.context)
        word = arguments.strip()
        if not word.isascii() or not word.isdecimal() or not 1 <= int(word) <= len(menu.items):
            raise Conflict("session_lifecycle_menu_item_unavailable")
        selected = menu.items[int(word) - 1]
        await self._require_source(menu.source, message)
        if menu.reference != reference(binding):
            raise Conflict("session_lifecycle_menu_changed")
        if not self.supported(binding, menu.operation):
            return self.tr.render("lifecycle.unavailable", locale)
        blocked = await self._blocked(binding, locale)
        if blocked is not None:
            return blocked
        pending = await self._view().pending_revert(reference(binding))
        offered = await self._view().recent_user_messages(reference(binding))
        if pending != menu.pending_revert_message_id or selected not in offered:
            raise Conflict("session_lifecycle_menu_native_state_changed")
        change = SessionLifecycleChange(
            operation=menu.operation,
            message_id=selected.message_id,
            message_preview=selected.preview,
            files=menu.files,
            pending_revert_message_id=pending,
        )
        return await self._preview(binding, message, locale, change, (menu.source, message))

    async def _require_source(self, source: HumanMessage, message: HumanMessage) -> None:
        if (
            source.message_id == message.message_id
            or source.author_id != message.author_id
            or (source.realm_id, source.channel_id, source.topic)
            != (message.realm_id, message.channel_id, message.topic)
            or source.revision != 0
            or source.deleted
            or source.is_bot
            or await self.reader.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("session_lifecycle_preview_source_changed")

    def _preview_text(
        self, change: SessionLifecycleChange, locale: Locale, binding: Binding
    ) -> str:
        boundary = visible(change.message_preview)
        if change.operation == "session.fork":
            lines = [
                self.tr.render("lifecycle.fork_preview_before", locale, message=boundary)
                if change.message_id
                else self.tr.render("lifecycle.fork_preview", locale),
                self.tr.render(
                    "lifecycle.fork_new_topic"
                    if binding.project_id in self.fork_topics
                    else "lifecycle.fork_stays",
                    locale,
                ),
            ]
        elif change.operation == "session.compact":
            lines = [self.tr.render("lifecycle.compact_preview", locale)]
        elif change.operation == "session.revert.stage":
            lines = [
                self.tr.render("lifecycle.revert_preview", locale, message=boundary),
                self.tr.render(
                    "lifecycle.revert_files" if change.files else "lifecycle.revert_no_files",
                    locale,
                ),
                self.tr.render("lifecycle.revert_outside", locale),
            ]
        elif change.operation == "session.revert.clear":
            lines = [self.tr.render("lifecycle.clear_preview", locale)]
        else:
            lines = [
                self.tr.render("lifecycle.commit_preview", locale),
                self.tr.render("lifecycle.revert_outside", locale),
            ]
        lines.append(self.tr.render("lifecycle.confirm", locale))
        return "\n\n".join(lines)

    async def _preview(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        change: SessionLifecycleChange,
        sources: tuple[HumanMessage, ...],
    ) -> str:
        text = self._preview_text(change, locale, binding)
        binding = await self.current(binding, message)
        async with self.db.sessions.begin() as session:
            await self._lock_operator(session, binding, message)
            await self._retire(session, binding, message)
        await self.tokens.issue(
            LIFECYCLE_CONFIRM_TOKEN,
            message.realm_id,
            message.author_id,
            LifecycleConfirmation(
                reference=reference(binding), change=change, preview_sources=sources
            ).model_dump(mode="json"),
            ttl=CONFIRM_TTL,
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return text

    async def confirm(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        binding = await self.current(binding, message)
        saved = await self._latest(LIFECYCLE_CONFIRM_TOKEN, binding, message)
        if saved is None:
            raise Conflict("session_lifecycle_confirmation_unavailable")
        confirmation = LifecycleConfirmation.model_validate(saved.context)
        change = confirmation.change
        if confirmation.reference != reference(binding):
            raise Conflict("session_lifecycle_confirmation_changed")
        for source in confirmation.preview_sources:
            await self._require_source(source, message)
        if not self.supported(binding, change.operation):
            return self.tr.render("lifecycle.unavailable", locale)
        blocked = await self._blocked(binding, locale)
        if blocked is not None:
            return blocked
        if (
            await self._view().pending_revert(reference(binding))
            != change.pending_revert_message_id
        ):
            raise Conflict("session_lifecycle_confirmation_native_state_changed")
        binding = await self.current(binding, message)
        payload = SessionLifecycleRequest(
            operation=change.operation,
            reference=reference(binding),
            source=message,
            preview_sources=confirmation.preview_sources,
            change=change,
            reply_locale=locale,
            confirm_expires_at=time.time() + QUEUED_TTL,
            confirmation_token_sha256=saved.token_hash,
        ).model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(session, binding, message)
            if current.dispatch_paused:
                return self.tr.render("lifecycle.paused", locale)
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, binding, message)
            action = Action(
                dedupe_key="session-lifecycle:" + saved.token_hash,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=message.author_id,
                operation=change.operation,
                payload=payload,
                operation_digest=digest(payload),
                state="queued",
            )
            session.add(action)
            await session.flush()
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="session_lifecycle_queued",
                    object_id=action.id,
                )
            )
        return self.tr.render("lifecycle.sending", locale)
