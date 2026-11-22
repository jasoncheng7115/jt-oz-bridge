"""Authorized bound-topic command routing; no network consumer or reply writer.

Unknown/control input never falls through to an agent prompt. Discovery and
additional operation handlers are added separately without widening this scope.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from typing import TYPE_CHECKING, Literal, cast

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_publish import CONFIRM_TOKEN as GIT_PUBLISH_TOKEN
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.domain.routing import RoutedInput as RoutedInput
from jt_oz_bridge.domain.routing import RoutingRateDeferred
from jt_oz_bridge.domain.routing import SavedReply as SavedReply
from jt_oz_bridge.domain.schedules import SCHEDULE_TOKEN
from jt_oz_bridge.domain.session_lifecycle import LIFECYCLE_TOKEN_KINDS
from jt_oz_bridge.i18n import Translator, clear_locale, message_locale, save_locale
from jt_oz_bridge.presentation.commands import (
    BARE_TRAILING,
    KNOWN,
    ParsedInput,
    bare_answer,
    canonical,
    parse_input,
    unmentioned,
)
from jt_oz_bridge.presentation.help import USAGE
from jt_oz_bridge.presentation.markdown import literal, sanitize_controls
from jt_oz_bridge.presentation.menu_buttons import (
    buttons_widget,
    menu_widget,
    notice_widget,
    numbered_menu,
)
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.services import menu_shortcuts
from jt_oz_bridge.services.bindings import BindingService, reference, topic_key
from jt_oz_bridge.services.check_commands import CheckCommands
from jt_oz_bridge.services.check_stop import has_in_flight_check
from jt_oz_bridge.services.command_receipts import CommandClaim, CommandInbox
from jt_oz_bridge.services.creation_commands import CreationCommands
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.file_menus import FileMenus
from jt_oz_bridge.services.generated_capture_commands import GeneratedCaptureCommands
from jt_oz_bridge.services.git_evidence_commands import GitEvidenceCommands
from jt_oz_bridge.services.git_publish_commands import GitPublishCommands
from jt_oz_bridge.services.git_review_commands import VERBS as GIT_REVIEW_VERBS
from jt_oz_bridge.services.git_review_commands import NativeGitReviewCommands
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.services.interactions import short_code
from jt_oz_bridge.services.menu_shortcuts import MENU_COMMANDS
from jt_oz_bridge.services.model_commands import ModelCommands
from jt_oz_bridge.services.native_metadata_commands import COMMANDS as METADATA_COMMANDS
from jt_oz_bridge.services.native_metadata_commands import NativeMetadataCommands
from jt_oz_bridge.services.permission_commands import QUICK_ANSWER, PermissionCommands
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.session_exports import SessionExportCommands
from jt_oz_bridge.services.session_lifecycle_commands import SessionLifecycleCommands
from jt_oz_bridge.services.session_lifecycle_controls import SessionLifecycleControls
from jt_oz_bridge.services.still_working import tool_names, waits_on
from jt_oz_bridge.services.tokens import MINTED, TokenService
from jt_oz_bridge.services.transcript_reconnect import KIND as RECONNECT_TOKEN
from jt_oz_bridge.services.transcript_reconnect import ReconnectUnavailable
from jt_oz_bridge.services.unbound_router import STATUS_TOPIC, UnboundRouter
from jt_oz_bridge.services.worktree_commands import WorktreeCommands
from jt_oz_bridge.services.zulip_events import OLD_HELD_SECONDS
from jt_oz_bridge.storage.control_models import Binding, ControlToken, PendingInteraction
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, AuditEvent

NAVIGATION = ("info", "status", "queue", "pending", "help", "settings")
# Refusals that have a next step to tell the person instead of "expired".
GUIDED_CONFLICTS = {
    "transcript_gap_requires_review_and_rebind": "router.gap_go",
    "nothing_waiting_for_confirmation": "router.nothing_to_confirm",
}
# Questions Bridge asks one person in a topic, which `!no` closes without sending anything.
DECLINABLE = (
    SCHEDULE_TOKEN,
    *LIFECYCLE_TOKEN_KINDS,
    GIT_PUBLISH_TOKEN,
    RECONNECT_TOKEN,
    "native-agent-menu",
    "native-agent-confirm",
)
# The receipt kind of a bare "ok" Bridge asked about instead of sending.
BARE_ANSWER = "bare-answer"
# How much of a waiting message `!status` shows, enough to tell two apart on a phone.
PREVIEW_CHARS = 30
# A waiting message at least this old shows when it was sent.
OLD_WAITING_SECONDS = OLD_HELD_SECONDS
if TYPE_CHECKING:
    from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue
    from jt_oz_bridge.services.prompt_schedules import PromptSchedules
    from jt_oz_bridge.services.transcript_reconnect import TranscriptReconnectService
    from jt_oz_bridge.services.typing_status import TypingStatus
    from jt_oz_bridge.services.zulip_recovery_review import ZulipRecoveryReview

LOCAL = frozenset(
    {
        "help",
        "pending",
        "approve",
        "answer",
        "skip",
        "confirm",
        "deny",
        "send",
        "menu",
        "choose",
        "info",
        "status",
        "queue",
        "cancel",
        "stop",
        "decline",
        "lang",
        "topic-lang",
        "settings",
    }
)


def safe(value: object) -> str:
    return literal(sanitize_controls(str(value))[0])


def _preview(item: Action) -> str:
    """The start of a waiting message on one line, inert; empty when it has no text."""
    text = item.payload.get("text") if item.operation == "prompt" else None
    if not isinstance(text, str):
        return ""
    words = " ".join(sanitize_controls(text)[0].split())
    if len(words) > PREVIEW_CHARS:
        words = words[: PREVIEW_CHARS - 1] + "…"
    return literal(words)


if TYPE_CHECKING:
    from jt_oz_bridge.services.agent_commands import AgentCommands
    from jt_oz_bridge.services.worktree_switch import WorktreeSwitchCommands


class CommandRouter:
    def __init__(
        self,
        bindings: BindingService,
        reader: SourceReader,
        inbox: CommandInbox,
        *,
        capabilities: CapabilityLookup | None = None,
        discovery: DiscoveryService | None = None,
        history: HistoryCommands | None = None,
        models: ModelCommands | None = None,
        metadata: NativeMetadataCommands | None = None,
        git_review: NativeGitReviewCommands | None = None,
        git_evidence: GitEvidenceCommands | None = None,
        lifecycle: SessionLifecycleCommands | None = None,
        lifecycle_controls: SessionLifecycleControls | None = None,
        files: FileCommands | None = None,
        exports: SessionExportCommands | None = None,
        file_menus: FileMenus | None = None,
        resume_guard: Callable[[Binding], Awaitable[None]] | None = None,
        creation: CreationCommands | None = None,
        generated: GeneratedCaptureCommands | None = None,
        checks: CheckCommands | None = None,
        worktrees: WorktreeCommands | None = None,
        git_publish: GitPublishCommands | None = None,
    ) -> None:
        self._typing: TypingStatus | None = None
        self.recovery: ZulipRecoveryReview | None = None
        self.reconnect: TranscriptReconnectService | None = None
        if worktrees is not None and (
            worktrees.bindings is not bindings
            or worktrees.source is not reader
            or worktrees.fence != inbox.fence
        ):
            raise ValueError("router_worktree_original_pipeline_required")
        self.worktrees = worktrees
        self.worktree_switch: WorktreeSwitchCommands | None = None
        self.closed_bound: ClosedBoundQueue | None = None
        # Trusted composition only; None keeps `!oz agent` as an unintegrated command.
        self.agents: AgentCommands | None = None
        # Trusted composition only; None sends a repeat-sounding message as written.
        self.schedules: PromptSchedules | None = None
        if inbox.db is not bindings.db:
            raise ValueError("router_database_mismatch")
        self.bindings, self.reader, self.inbox = bindings, reader, inbox
        self.resume_guard = resume_guard
        self.db, self.queue, self.tokens = (
            bindings.db,
            QueueService(bindings, fence=inbox.fence),
            TokenService(bindings.db, fence=inbox.fence),
        )
        if history is not None and (
            history.history.bindings is not bindings
            or history.reader is not reader
            or history.tokens.db is not self.db
            or history.tokens.fence != inbox.fence
        ):
            raise ValueError("router_history_scope_mismatch")
        self.history = history
        if models is not None and (
            models.bindings is not bindings
            or models.reader is not reader
            or models.tokens.db is not self.db
            or models.tokens.fence != inbox.fence
        ):
            raise ValueError("router_model_commands_scope_mismatch")
        self.models = models
        if metadata is not None and (
            metadata.bindings is not bindings
            or metadata.reader is not reader
            or metadata.tokens.db is not self.db
            or metadata.tokens.fence != inbox.fence
        ):
            raise ValueError("router_native_metadata_scope_mismatch")
        self.metadata = metadata
        if git_review is not None and (
            git_review.bindings is not bindings
            or git_review.db is not self.db
            or git_review.source is not reader
            or git_review.fence != inbox.fence
            or git_review.tokens.db is not self.db
            or git_review.tokens.fence != inbox.fence
        ):
            raise ValueError("router_git_review_scope_mismatch")
        self.git_review = git_review
        if git_evidence is not None and (
            git_evidence.bindings is not bindings
            or git_evidence.db is not self.db
            or git_evidence.source is not reader
            or git_evidence.fence != inbox.fence
            or git_evidence.tokens.db is not self.db
            or git_evidence.tokens.fence != inbox.fence
        ):
            raise ValueError("router_git_evidence_scope_mismatch")
        self.git_evidence = git_evidence
        if git_publish is not None and (
            git_publish.bindings is not bindings
            or git_publish.reader is not reader
            or git_publish.tokens.db is not self.db
            or git_publish.fence != inbox.fence
        ):
            raise ValueError("router_git_publish_scope_mismatch")
        self.git_publish = git_publish
        if lifecycle is not None and (
            lifecycle.bindings is not bindings
            or lifecycle.reader is not reader
            or lifecycle.fence != inbox.fence
        ):
            raise ValueError("router_session_lifecycle_scope_mismatch")
        self.lifecycle = lifecycle
        if lifecycle_controls is not None and (
            lifecycle_controls.bindings is not bindings
            or lifecycle_controls.reader is not reader
            or lifecycle_controls.fence != inbox.fence
        ):
            raise ValueError("router_session_lifecycle_scope_mismatch")
        self.lifecycle_controls = lifecycle_controls
        if checks is not None and (
            checks.bindings is not bindings
            or checks.reader is not reader
            or checks.tokens.db is not self.db
            or checks.tokens.fence != inbox.fence
        ):
            raise ValueError("router_check_commands_scope_mismatch")
        self.checks = checks
        if files is not None and (
            files.bindings is not bindings
            or files.reader is not reader
            or files.fence != inbox.fence
        ):
            raise ValueError("router_file_commands_scope_mismatch")
        if file_menus is not None and (
            files is None
            or file_menus.bindings is not bindings
            or file_menus.source is not reader
            or file_menus.fence != inbox.fence
            or files.choices is not file_menus.choices
        ):
            raise ValueError("router_file_menus_require_original_file_scope")
        self.file_menus = file_menus
        if exports is not None and (
            exports.bindings is not bindings
            or exports.reader is not reader
            or exports.fence != inbox.fence
            or exports.journal is not (files.journal if files else None)
        ):
            raise ValueError("router_export_original_file_scope_required")
        self.exports = exports
        self.files = files
        if generated is not None and (
            generated.bindings is not bindings
            or generated.source is not reader
            or generated.fence != inbox.fence
        ):
            raise ValueError("router_generated_capture_scope_mismatch")
        self.generated = generated
        self.tr = Translator()
        self.permissions = PermissionCommands(bindings, self.tokens, capabilities=capabilities)
        if discovery is not None and discovery.bindings is not bindings:
            raise ValueError("router_discovery_binding_service_mismatch")
        if creation is not None and discovery is None:
            raise ValueError("creation_requires_original_discovery")
        self.unbound = (
            UnboundRouter(discovery, reader, inbox, creation) if discovery is not None else None
        )

    def configure_typing(self, status: TypingStatus) -> None:
        if (
            self._typing is not None
            or status.bindings is not self.bindings
            or status.fence != self.inbox.fence
        ):
            raise ValueError("router_typing_original_scope_required")
        status.configure_routing(self.reader, self.unbound.discovery if self.unbound else None)
        self._typing = status

    async def _gap_note(self, binding: Binding, locale: Locale) -> str:
        """`!status` says when only a reconnect (`!ok`) can lift the pause."""
        if self.resume_guard is None:
            return ""
        try:
            await self.resume_guard(binding)
        except Conflict as error:
            if str(error) == "transcript_gap_requires_review_and_rebind":
                return "\n\n" + self.tr.render("router.gap_go", locale)
        return ""

    async def _doing_note(self, binding: Binding, locale: Locale) -> str:
        """`!status` of a running turn says whether it waits on a tool or the model."""
        async with self.db.sessions() as session:
            names = await waits_on(session, binding)
        if names is None:
            return ""
        if names:
            text = self.tr.render(
                "router.status_doing_tool", locale, tools=tool_names(self.tr, locale, names)
            )
        else:
            text = self.tr.render("router.status_doing_model", locale)
        return "\n\n" + text

    async def _background_stop_note(self, binding: Binding, locale: Locale) -> str:
        async with self.db.sessions() as session:
            pending = await has_in_flight_check(session, binding)
        return (
            "\n\n" + self.tr.render("router.background_stop_unqualified", locale) if pending else ""
        )

    async def binding_for(self, message: HumanMessage) -> Binding | None:
        audience = await self.bindings.audience.inspect(
            message.realm_id, message.channel_id, message.topic
        )
        if (audience.realm_id, audience.channel_id, audience.canonical_topic) != (
            message.realm_id,
            message.channel_id,
            message.topic,
        ):
            raise Conflict("source_topic_not_canonical")
        async with self.db.sessions() as session:
            identity = await session.scalar(
                select(Binding.id).where(
                    Binding.topic_key
                    == topic_key(message.realm_id, message.channel_id, audience.canonical_topic),
                    Binding.state == "active",
                )
            )
        if identity is None:
            return None
        return await self.bindings.get(str(identity), message.realm_id, message.author_id)

    async def current(self, binding: Binding, message: HumanMessage) -> Binding:
        latest = await self.bindings.get(binding.id, message.realm_id, message.author_id)
        if (latest.revision, latest.channel_id, latest.topic) != (
            binding.revision,
            message.channel_id,
            message.topic,
        ):
            raise Conflict("routing_binding_changed")
        return latest

    async def route_closed_menu_event(
        self, proposal: HumanMessage, *, recovered: bool = False
    ) -> RoutedInput | None:
        async with self._typing.routing(proposal) if self._typing is not None else nullcontext():
            return await self._route_closed_menu_event(proposal, recovered=recovered)

    async def _route_closed_menu_event(
        self, proposal: HumanMessage, *, recovered: bool = False
    ) -> RoutedInput | None:
        """Offer untrusted fresh wire data to the complete closed observer.

        SQL absence and command shape only select a reader. They authorize no
        source, grant, Native call or write. A declined candidate is effect-free;
        once selected, an error must propagate rather than invoke another route.
        Public route() retains all of its original standalone Source checks.
        """
        # Recovery owns paused-input linking and selected review. Its original
        # route must retain those messages and guards rather than use the
        # schema32 conversation shortcut.
        if not recovered and self.recovery is None and self.closed_bound is not None:
            selected = await self.closed_bound.candidate(proposal)
            if selected is not None:
                return await self.closed_bound.route(selected, proposal)
        owner = self.unbound
        if (
            recovered
            or owner is None
            or proposal.is_bot
            or proposal.deleted
            or proposal.revision != 0
            # The status topic is answered on the original route, never offered a menu.
            or proposal.topic == STATUS_TOPIC
        ):
            return None
        parsed = parse_input(proposal.text)
        if owner.closed_operation(proposal, parsed) is None:
            return None
        async with self.db.sessions() as session:
            existing = await session.scalar(
                select(Binding.id).where(
                    Binding.realm_id == proposal.realm_id,
                    Binding.topic_key
                    == topic_key(proposal.realm_id, proposal.channel_id, proposal.topic),
                    Binding.state == "active",
                )
            )
        if existing is not None:
            return None
        return await owner.try_closed_route(proposal, recovered=False)

    async def route(
        self, event: HumanMessage, *, recovered: bool = False, recovery_item_id: str | None = None
    ) -> RoutedInput:
        async with self._typing.routing(event) if self._typing is not None else nullcontext():
            return await self._route(event, recovered=recovered, recovery_item_id=recovery_item_id)

    async def _route(
        self, event: HumanMessage, *, recovered: bool = False, recovery_item_id: str | None = None
    ) -> RoutedInput:
        if event.is_bot:
            return RoutedInput("ignore")
        try:
            message = await self.reader.read(event.realm_id, event.message_id)
            if message != event or message.is_bot:
                # Never execute a newer edited control on the strength of an old event.
                return RoutedInput("ignore")
            # SQL absence is only a routing candidate, never authorization. The
            # unbound router independently verifies current Source/private
            # audience before claim/catalog access, and rejects a newly bound
            # topic again before output/token commit. Bound candidates retain
            # the public binding_for fresh canonical audience checks.
            async with self.db.sessions() as session:
                candidate = await session.scalar(
                    select(Binding.id).where(
                        Binding.topic_key
                        == topic_key(message.realm_id, message.channel_id, message.topic),
                        Binding.state == "active",
                    )
                )
            binding = (
                None
                if self.unbound is not None and candidate is None
                else await self.binding_for(message)
            )
        except DeliveryRateLimited as error:
            raise RoutingRateDeferred(error.retry_after) from None
        if self.unbound is not None:
            previous_unbound = await self.inbox.find(message.realm_id, message.message_id)
            if (
                binding is None
                or previous_unbound is not None
                and previous_unbound.binding_id is None
            ):
                return await self.unbound.route(
                    message, recovered=recovered, current_binding=binding
                )
        if binding is None:
            return RoutedInput("ignore")
        topic_locale: Locale = (
            cast(Locale, binding.locale) if binding.locale in {"en", "zh-TW"} else "en"
        )
        locale = await message_locale(self.db, self.reader, message, topic_locale)
        parsed = parse_input(message.text, bound=True)
        if self.worktree_switch is not None and self.worktree_switch.eligible(message):
            if recovered or recovery_item_id is not None:
                return RoutedInput("held")
            return await self.worktree_switch.route(binding, message, locale)
        previous = await self.inbox.find(message.realm_id, message.message_id)
        if message.deleted or parsed.kind == "ignore":
            if previous is None:
                await self.queue.receive(binding.id, message, recovered=recovered)
            return RoutedInput("ignore")
        if (
            parsed.kind == "prompt"
            and previous is not None
            and previous.command == BARE_ANSWER
            and previous.state == "completed"
            and previous.source_revision == message.revision
        ):
            # The same "ok" again (a redelivered event): the saved reply, nothing new.
            saved = SavedReply.model_validate(previous.response)
            await self.current(binding, message)
            return RoutedInput(
                "reply",
                binding.id,
                binding.revision,
                saved.text,
                f"bare-answer:{message.realm_id}:{message.message_id}:{message.revision}",
                locale=saved.locale,
                widget=saved.widget,
            )
        if (
            parsed.kind == "prompt"
            and parsed.command != "steer"
            and not recovered
            and recovery_item_id is None
            and previous is None
            and (word := bare_answer(message.text)) is not None
            and (asked := await self._asked(binding, message)) is not None
        ):
            # "ok" with a question open most likely answers it; ask instead of
            # handing the word to the AI or holding it behind the pause.
            kind, code = asked
            return await self._bare_answer(
                binding, message, locale, word if kind == "confirm" else kind, code
            )
        if (
            parsed.kind == "prompt"
            and self.schedules is not None
            and not recovered
            and recovery_item_id is None
            and parsed.command != "steer"
            and (
                previous is None
                and self.schedules.candidate(message)
                or await self.schedules.owns_source(message)
            )
        ):
            # "every 30 minutes … until 18:00" is shown back for `!confirm`, never sent as is.
            return await self.schedules.propose(binding, message, locale)
        if parsed.kind == "prompt":
            if previous is not None:
                return await self.reply(
                    binding,
                    message,
                    locale,
                    "router.changed",
                    f"changed:{previous.id}:{message.revision}",
                )
            closed = self.closed_bound
            receipt = await self.queue.receive(
                binding.id,
                message,
                recovered=recovered,
                reply_locale=locale,
                recovery_item_id=recovery_item_id,
                # A fresh prompt continues a pause no person chose, as on the closed
                # path; recovery keeps its own paused-input review.
                admitted=(
                    None
                    if closed is None or recovered or recovery_item_id or self.recovery
                    else lambda session, current, receipt: closed.continued(
                        session, current, message, receipt
                    )
                ),
            )
            paused = "router.paused_input"
            if receipt.state == "held" and receipt.paused_at_admission and self.resume_guard:
                try:
                    await self.resume_guard(binding)
                except Conflict as error:
                    if str(error) == "transcript_gap_requires_review_and_rebind":
                        # `!go` alone cannot lift it; the closed path words it the same.
                        paused = (
                            "router.paused_gap"
                            if closed is None
                            else await closed.paused_key(binding)
                        )
                if paused == "router.paused_input" and closed is not None:
                    # An old held message changes the choices; the closed path says the same.
                    paused = await closed.paused_key(binding)
            key = (
                "recovery.held"
                if recovery_item_id is not None and receipt.state == "held"
                else "recovery.paused_input"
                if self.recovery is not None
                and receipt.state == "held"
                and receipt.paused_at_admission
                else paused
                if receipt.state == "held" and receipt.paused_at_admission
                else "action.held"
                if receipt.state == "held"
                else "action.received"
            )
            text = (
                self.tr.render(
                    "router.not_editable",
                    locale,
                    state=self.tr.render("queue.state." + receipt.state, locale),
                )
                if receipt.already_dispatched
                else self.tr.render(key, locale)
            )
            await self.current(binding, message)
            # Typing and the reply already show an accepted message is moving.
            silent = not receipt.already_dispatched and receipt.state != "held"
            note = (
                await self.agents.barrier_note(binding, locale)
                if self.agents is not None and silent
                else None
            )
            if note is not None:
                # This input cannot start now. Say why instead of staying quiet.
                silent, text = False, note
            if parsed.command == "steer" and not receipt.already_dispatched:
                # Say plainly where the text goes: into the running turn, or next.
                steer = self.tr.render("steer.queued", locale)
                silent, text = False, steer if silent else text + "\n\n" + steer
            return RoutedInput(
                "ignore" if silent else "reply",
                binding.id,
                binding.revision,
                text,
                f"prompt:{message.realm_id}:{message.message_id}:{message.revision}",
                receipt.action_id,
                locale=locale,
                widget=self._notice_widget(key, text, locale),
            )
        async with self.db.sessions() as session:
            old_prompt = await session.scalar(
                select(Action.id).where(
                    Action.dedupe_key == f"human:{message.realm_id}:{message.message_id}"
                )
            )
        if old_prompt is not None:
            await self.queue.receive(binding.id, message, recovered=True)
            return await self.reply(
                binding,
                message,
                locale,
                "router.changed",
                f"changed-prompt:{old_prompt}:{message.revision}",
            )
        command = "unknown" if parsed.kind == "unknown" else parsed.command
        claim = await self.inbox.claim(
            message,
            command,
            binding_id=binding.id,
            binding_revision=binding.revision,
            recovered=recovered or message.revision > 0,
        )
        if claim.status == "replay":
            if (
                self.reconnect is not None
                and claim.response.get("format") == "transcript-reconnect-reply-v1"
            ):
                return await self.reconnect.route(binding, message, locale, claim)
            saved = SavedReply.model_validate(claim.response)
            if parsed.command == "git" and parsed.arguments.split()[:1] == ["evidence"]:
                if self.git_evidence is None:
                    raise Conflict("git_evidence_replay_handler_unavailable")
                replayed = await self.git_evidence.route(
                    binding, message, saved.locale, parsed.arguments, replay_text=saved.text
                )
                if replayed != saved.text:
                    raise Conflict("git_evidence_replay_qualification_changed")
            await self.current(binding, message)
            return RoutedInput(
                "reply",
                binding.id,
                binding.revision,
                saved.text,
                "command:" + claim.id,
                locale=saved.locale,
                widget=saved.widget,
            )
        if claim.status != "claimed":
            key = {
                "changed": "router.changed",
                "held": "router.held",
                "busy": "router.busy",
                "ambiguous": "router.ambiguous",
            }[claim.status]
            return await self.reply(
                binding,
                message,
                locale,
                key,
                "command-state:" + claim.id + ":" + claim.status,
                state=cast(
                    Literal["reply", "busy", "held", "ambiguous"],
                    claim.status if claim.status in {"busy", "held", "ambiguous"} else "reply",
                ),
            )
        if parsed.command == "recovery" and self.recovery is not None:
            return await self.recovery.route(binding, message, locale, parsed.arguments, claim)
        try:
            minted: list[str] = []
            guided: str | None = None
            typo: list[tuple[str, str]] | None = None
            try:
                if self.reconnect is not None and await self.reconnect.owns(
                    parsed, claim, binding, message
                ):
                    return await self.reconnect.route(binding, message, locale, claim)
                if parsed.command == "unbind" and self.unbound is not None:
                    routed = await self._unbind(binding, message, locale, claim)
                    if routed is not None:
                        return routed
                    text = self.tr.render("router.unbind_busy", locale)
                elif parsed.kind == "unknown" and parsed.arguments:
                    # A typo of an everyday word: offer it, or the text as written.
                    meant = parsed.arguments.split()[0]
                    text = self.tr.render(
                        "router.typo", locale, typed="!" + parsed.command, meant=meant
                    )
                    typo = [
                        (
                            self.tr.render("router.typo_button", locale, meant=meant),
                            parsed.arguments,
                        ),
                        (
                            self.tr.render("router.bare_answer_button_send", locale),
                            "!send " + unmentioned(message.text).strip(),
                        ),
                    ]
                elif parsed.kind in {"unknown", "invalid"}:
                    text = self.tr.render("router.invalid", locale)
                else:
                    minting = MINTED.set(minted)
                    try:
                        text = await self.execute(binding, message, parsed, locale, claim)
                    finally:
                        MINTED.reset(minting)
            except AccessDenied:
                text = self.tr.render("permission.denied", locale)
            except DeliveryRateLimited:
                raise  # Do not disguise throttled, possibly partial local effects as a stale reply.
            except (Conflict, ValueError) as error:
                # A plain ValueError is a malformed command; anything typed names its own cause.
                if type(error) is Conflict and str(error) in GUIDED_CONFLICTS:
                    guided = GUIDED_CONFLICTS[str(error)]
                text = self.tr.render(
                    error.code
                    if isinstance(error, ReconnectUnavailable)
                    else GUIDED_CONFLICTS[str(error)]
                    if type(error) is Conflict and str(error) in GUIDED_CONFLICTS
                    else "router.usage"
                    if type(error) is ValueError
                    else "router.stale",
                    locale,
                )
            await self.current(binding, message)
            reply_locale: Locale = (
                cast(Locale, parsed.arguments.strip())
                if parsed.command in {"lang", "topic-lang"}
                and parsed.arguments.strip() in {"en", "zh-TW"}
                else locale
            )
            if parsed.command == "lang" and parsed.arguments.strip() == "auto":
                reply_locale = await message_locale(self.db, self.reader, message, topic_locale)
            controls = (
                await self.menu_controls(binding, message, text, frozenset(minted))
                if parsed.command in MENU_COMMANDS
                else None
            )
            widget, rows = controls if controls is not None else (None, None)
            if widget is None and guided is not None:
                widget = self._notice_widget(guided, text, reply_locale)
            elif widget is None and typo is not None:
                widget = buttons_widget(text, typo)
            elif (
                widget is None
                and parsed.command == "status"
                and self.tr.render("router.held_hint_old", reply_locale) in text
            ):
                widget = notice_widget(
                    "router.paused_old", text, lambda name: self.tr.render(name, reply_locale)
                )
            elif (
                widget is None
                and parsed.command == "status"
                and self.tr.render("router.held_hint", reply_locale) in text
            ):
                widget = buttons_widget(
                    text,
                    [
                        (self.tr.render("button.go", reply_locale), "!go"),
                        (self.tr.render("button.drop", reply_locale), "!no"),
                    ],
                )
            elif widget is None and parsed.command == "stop":
                paused = self.tr.render("action.stop_paused", reply_locale)
                if text.startswith(
                    self.tr.render("action.received", reply_locale) + "\n\n" + paused
                ):
                    widget = notice_widget(
                        "action.stop_paused", text, lambda name: self.tr.render(name, reply_locale)
                    )
            if rows:
                # Phones show no buttons; desktop shows the widget instead of this text.
                text += "\n\n" + (
                    self.tr.render("menu.reply_one", reply_locale)
                    if len(rows) == 1
                    else self.tr.render("menu.reply_number", reply_locale, last=len(rows))
                )
            await self.inbox.finish(
                claim,
                SavedReply(
                    text=text, locale=reply_locale, widget=widget, shortcuts=rows
                ).model_dump(mode="json", exclude_none=True),
            )
            return RoutedInput(
                "reply",
                binding.id,
                binding.revision,
                text,
                "command:" + claim.id,
                locale=reply_locale,
                widget=widget,
            )
        except BaseException:
            # A lost fenced lease leaves recovery to the next owner. Cancellation
            # does not make the command reusable or claim that no local effect ran.
            try:
                await asyncio.shield(self.inbox.abandon(claim))
            except (Conflict, asyncio.CancelledError):
                pass
            raise

    async def _unbind(
        self, binding: Binding, message: HumanMessage, locale: Locale, claim: CommandClaim
    ) -> RoutedInput | None:
        """Free the conversation for another topic; OpenCode itself is not touched."""
        assert self.unbound is not None
        await self.bindings.get(binding.id, message.realm_id, message.author_id, Permission.MANAGE)
        async with self.db.sessions() as session:
            active = await session.scalar(
                select(Action.id)
                .where(
                    Action.binding_id == binding.id,
                    Action.state.in_(
                        ["queued", "held", "dispatching", "admitted", "running", "ambiguous"]
                    ),
                )
                .limit(1)
            )
        if active is not None:
            return None
        text = self.tr.render("router.unbound", locale)

        async def commit(session: AsyncSession) -> None:
            await self.bindings.unbind_in_session(
                session, binding.id, message.realm_id, message.author_id, binding.revision
            )

        await self.inbox.finish(
            claim, SavedReply(text=text, locale=locale).model_dump(mode="json"), commit=commit
        )
        # The topic is unbound now, so only the unbound path may carry the reply.
        try:
            target = await self.unbound.destinations.prepare(message, ())
        except (AccessDenied, ValueError):
            return RoutedInput("ignore")
        return RoutedInput(
            "reply",
            text=text,
            delivery_key="command:" + claim.id,
            locale=locale,
            discovery_target=target,
        )

    def _notice_widget(self, key: str, text: str, locale: Locale) -> str | None:
        """Desktop buttons when the reply is exactly that fixed notice, else none."""
        if text != self.tr.render(key, locale):
            return None
        return notice_widget(key, text, lambda name: self.tr.render(name, locale))

    async def _asked(
        self, binding: Binding, message: HumanMessage
    ) -> tuple[Literal["confirm", "permission", "several", "question"], str | None] | None:
        """What here waits on this person, with the code when one permission alone waits.

        A plain `!ok` answers a Bridge question or a reconnect, but a permission only
        with its code, so a button that left the code out would do nothing.
        """
        now = time.time()
        async with self.db.sessions() as session:
            question = await session.scalar(
                select(ControlToken.token_hash)
                .where(
                    ControlToken.kind.in_(DECLINABLE),
                    ControlToken.realm_id == message.realm_id,
                    ControlToken.user_id == message.author_id,
                    ControlToken.binding_id == binding.id,
                    ControlToken.binding_revision == binding.revision,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > now,
                )
                .limit(1)
            )
            waiting = list(
                await session.scalars(
                    select(PendingInteraction)
                    .where(
                        PendingInteraction.binding_id == binding.id,
                        PendingInteraction.binding_revision == binding.revision,
                        PendingInteraction.state == "pending",
                        PendingInteraction.expires_at > now,
                    )
                    .limit(10)
                )
            )
        kinds = {row.snapshot.get("kind") for row in waiting}
        if question is not None or await self._gap_note(binding, "en"):
            return "confirm", None
        if "permission" in kinds:
            if len(waiting) == 1:
                return "permission", short_code(waiting[0].id)
            return "several", None  # `!pending` lists each code.
        # An AI question is answered with `!a`, which `!pending` shows; not `!ok`.
        return ("question", None) if kinds else None

    async def _waiting_note(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        """In `!status`, how to answer what the AI waits on; a reconnect has its own note."""
        asked = await self._asked(binding, message)
        if asked is None or asked[0] == "confirm":
            return ""
        kind, code = asked
        if kind == "permission":
            return "\n\n" + self.tr.render("router.status_permission", locale, code=code)
        return "\n\n" + self.tr.render("router.status_pending", locale)

    async def _bare_answer(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        word: str,
        code: str | None = None,
    ) -> RoutedInput:
        """Name the commands for "ok"/"no" typed without `!`; nothing is queued or sent."""
        await self.current(binding, message)
        # Only a fixed word reaches here, so it is shown and sent back as typed.
        typed = message.text.strip().rstrip(BARE_TRAILING)
        coded = {} if code is None else {"code": code}
        text = self.tr.render("router.bare_answer_" + word, locale, word=typed, **coded)
        send = (self.tr.render("router.bare_answer_button_send", locale), "!send " + typed)
        suffix = "" if code is None else f" {code}"
        buttons = (
            [(self.tr.render("router.bare_answer_button_pending", locale), "!pending"), send]
            if word in {"question", "several"}
            else [
                (self.tr.render("router.bare_answer_button_ok", locale), "!ok" + suffix),
                (self.tr.render("router.bare_answer_button_no", locale), "!no" + suffix),
                send,
            ]
        )
        widget = buttons_widget(text, buttons)
        # Kept like a command receipt: an edit of this word then gets "changed",
        # never the AI, and a retry gets this same reply.
        await self.inbox.record_reply(
            message,
            BARE_ANSWER,
            SavedReply(text=text, locale=locale, widget=widget).model_dump(
                mode="json", exclude_none=True
            ),
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return RoutedInput(
            "reply",
            binding.id,
            binding.revision,
            text,
            f"bare-answer:{message.realm_id}:{message.message_id}:{message.revision}",
            locale=locale,
            widget=widget,
        )

    async def _queued(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        """`!status` also shows the waiting messages, so one word answers "what's going on".

        Numbered in order, without IDs; `!oz queue` still lists IDs for `!oz cancel`.
        """
        actions = await self.queue.list(binding.id, message.realm_id, message.author_id)
        if not actions:
            return ""
        lines = []
        for index, item in enumerate(actions, 1):
            kind = self.tr.render(
                "router.queue_kind." + ("prompt" if item.operation == "prompt" else "other"),
                locale,
            )
            state = self.tr.render("queue.state." + item.state, locale)
            if time.time() - item.created_at >= OLD_WAITING_SECONDS:
                # An old message can hold the topic; say when it was sent.
                state += self.tr.render(
                    "router.queue_row_sent",
                    locale,
                    when=time.strftime("%m/%d %H:%M", time.localtime(item.created_at)),
                )
            preview = _preview(item)
            lines.append(
                self.tr.render(
                    "router.queue_row_text",
                    locale,
                    number=str(index),
                    kind=kind,
                    state=state,
                    text=preview,
                )
                if preview
                else self.tr.render(
                    "router.queue_row", locale, number=str(index), kind=kind, state=state
                )
            )
        text = "\n\n" + self.tr.render("router.queue_waiting", locale) + "\n\n" + "\n".join(lines)
        held = [item for item in actions if item.state == "held"]
        old = [item for item in held if time.time() - item.created_at >= OLD_WAITING_SECONDS]
        if held:
            # With old and new both waiting, `!go new` sends just the new ones.
            hint = "router.held_hint_old" if old and len(old) < len(held) else "router.held_hint"
            text += "\n\n" + self.tr.render(hint, locale)
        return text

    async def _drop_old_held(self, binding: Binding, message: HumanMessage) -> int:
        """`!go new`: drop this person's held messages from an hour or more ago, unsent."""
        dropped = 0
        for item in await self.queue.list(binding.id, message.realm_id, message.author_id):
            if (
                item.state == "held"
                and item.actor_id == message.author_id
                and time.time() - item.created_at >= OLD_HELD_SECONDS
            ):
                dropped += await self.queue.cancel(item.id, message.realm_id, message.author_id)
        return dropped

    async def _decline(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        """`!no`: close every question Bridge asked this person here. Nothing is sent."""
        await self.bindings.get(binding.id, message.realm_id, message.author_id)
        async with self.db.sessions.begin() as session:
            await self.inbox.fence.lock(session)
            closed = await session.execute(
                update(ControlToken)
                .where(
                    ControlToken.kind.in_(DECLINABLE),
                    ControlToken.realm_id == message.realm_id,
                    ControlToken.user_id == message.author_id,
                    ControlToken.binding_id == binding.id,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                )
                .values(used=True)
            )
        count = getattr(closed, "rowcount", 0) or 0
        # A held message is also waiting on this person: `!no` drops theirs, unsent.
        dropped = 0
        for item in await self.queue.list(binding.id, message.realm_id, message.author_id):
            if item.state == "held" and item.actor_id == message.author_id:
                dropped += await self.queue.cancel(item.id, message.realm_id, message.author_id)
        if dropped:
            return self.tr.render("router.dropped_held", locale, count=str(dropped))
        return self.tr.render("router.declined" if count else "router.nothing_to_decline", locale)

    async def menu_widget(
        self, binding: Binding, message: HumanMessage, text: str, minted: frozenset[str]
    ) -> str | None:
        controls = await self.menu_controls(binding, message, text, minted)
        return controls[0] if controls is not None else None

    async def menu_controls(
        self, binding: Binding, message: HumanMessage, text: str, minted: frozenset[str]
    ) -> tuple[str, list[str]] | None:
        """Buttons, and the rows a phone's `!N` names, for tokens this command issued.

        Stored Native text (a saved reply page, say) can show any older token in a
        numbered line; it can never contain a token minted while this reply was built.
        """
        found = numbered_menu(text)
        if found is None:
            return None
        heading, choices, numbered = found
        if not {token for _label, _reply, token in choices} <= minted:
            return None
        hashes = {token_hash(token) for _label, _reply, token in choices}
        async with self.db.sessions() as session:
            issued = await session.scalar(
                select(func.count())
                .select_from(ControlToken)
                .where(
                    ControlToken.token_hash.in_(hashes),
                    ControlToken.realm_id == message.realm_id,
                    ControlToken.user_id == message.author_id,
                    ControlToken.binding_id == binding.id,
                    ControlToken.binding_revision == binding.revision,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                )
            )
        if issued != len(hashes):
            return None
        return menu_widget(heading, choices), [
            reply for _label, reply, _token in choices[:numbered]
        ]

    async def reply(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        key: str,
        delivery_key: str,
        *,
        state: Literal["reply", "busy", "held", "ambiguous"] = "reply",
    ) -> RoutedInput:
        await self.current(binding, message)
        return RoutedInput(
            state,
            binding.id,
            binding.revision,
            self.tr.render(key, locale),
            delivery_key,
            locale=locale,
        )

    async def execute(
        self,
        binding: Binding,
        message: HumanMessage,
        parsed: ParsedInput,
        locale: Locale,
        claim: CommandClaim,
    ) -> str:
        command, arguments = parsed.command, parsed.arguments
        if command == "help":
            if arguments.strip() == "all":
                return (
                    self.tr.render("router.help_all", locale)
                    + "\n\n"
                    + ", ".join(f"`{name}`" for name in sorted(KNOWN))
                )
            if arguments.strip():
                requested = canonical(arguments.strip().removeprefix("!"))
                if requested not in KNOWN:
                    return self.tr.render("router.invalid", locale)
                if requested == "git" and self.git_evidence is not None:
                    return self.tr.render("git_evidence.help", locale)
                if (
                    requested in {"backends", "projects", "sessions", "bind"}
                    and self.unbound is not None
                ):
                    return self.tr.render("discovery.new_topic", locale)
                key = (
                    "router.available"
                    if requested in LOCAL
                    or requested == "reconnect"
                    and self.reconnect is not None
                    or requested == "recovery"
                    and self.recovery is not None
                    or requested == "history"
                    and self.history is not None
                    or requested in {"models", "model", "variants", "variant"}
                    and self.models is not None
                    or requested == "agent"
                    and self.agents is not None
                    and self.agents.available(binding)
                    or self.metadata is not None
                    and self.metadata.available(binding, requested)
                    or requested == "git"
                    and self.git_review is not None
                    and self.git_review.available(binding)
                    or requested == "git"
                    and self.git_publish is not None
                    and self.git_publish.available(binding)
                    or self.lifecycle is not None
                    and self.lifecycle.available(binding, requested)
                    or self.lifecycle_controls is not None
                    and self.lifecycle_controls.available(binding, requested)
                    or requested in {"checks", "check"}
                    and self.checks is not None
                    and self.checks.available(binding)
                    or requested in {"files", "diff"}
                    and self.file_menus is not None
                    and self.file_menus.available(binding, requested)
                    or requested == "export"
                    and self.exports is not None
                    and self.exports.available(binding)
                    or requested == "file"
                    and self.files is not None
                    and self.files.available(binding)
                    or requested == "outputs"
                    and self.generated is not None
                    or requested == "output"
                    and self.history is not None
                    or requested in {"schedule", "once"}
                    and self.schedules is not None
                    else "router.not_integrated"
                )
                if requested in {"archive", "unarchive"} and self.lifecycle_controls is not None:
                    key = "lifecycle.archive_unavailable"
                if requested in {"steer", "run"}:
                    key = "steer.help" if requested == "steer" else "run.unavailable"
                if requested == "delete":
                    key = "lifecycle.delete_unavailable"
                if requested in {"schedule", "once"} and self.schedules is not None:
                    key = "schedule.help"
                usage = (
                    "file <file-token-or-relative-path>"
                    if requested == "file" and self.files is not None
                    else USAGE[requested]
                )
                if requested == "export" and self.exports is not None:
                    usage = "export [json|markdown|confirm <token>]"
                return f"`!oz {usage}`\n\n" + self.tr.render(key, locale)
            return self.tr.render("router.help", locale)
        if (
            command in {"go", "backends", "projects", "sessions", "bind"}
            and self.unbound is not None
        ):
            return self.tr.render("discovery.new_topic", locale)
        if command == "menu":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            token = await self.tokens.issue(
                "navigation",
                message.realm_id,
                message.author_id,
                {"commands": list(NAVIGATION)},
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            return (
                self.tr.render("menu.title", locale)
                + "\n\n"
                + "\n".join(f"{index}. `!oz {name}`" for index, name in enumerate(NAVIGATION, 1))
                + "\n\n"
                + self.tr.render("menu.choose", locale, menu_id=literal(token), item_number=1)
            )
        if command == "agent" and self.agents is not None:
            return await self.agents.route(binding, message, locale, command, arguments)
        if (
            command == "choose"
            and len(arguments.split()) == 1
            and self.agents is not None
            and await self.agents.owns_choice(binding, message)
            and not await menu_shortcuts.latest_is_menu(self.db, binding, message)
        ):
            return await self.agents.route(binding, message, locale, command, arguments)
        if (
            command == "confirm"
            and not arguments.strip()
            and self.agents is not None
            and await self.agents.owns_confirm(binding, message)
        ):
            return await self.agents.route(binding, message, locale, command, arguments)
        if (
            command == "choose"
            and len(arguments.split()) == 1
            and self.lifecycle_controls is not None
            and await self.lifecycle_controls.owns_choice(binding, message)
            and not await menu_shortcuts.latest_is_menu(self.db, binding, message)
        ):
            return await self.lifecycle_controls.choose(binding, message, locale, arguments)
        if (
            command == "confirm"
            and not arguments.strip()
            and self.lifecycle_controls is not None
            and await self.lifecycle_controls.owns_confirm(binding, message)
        ):
            return await self.lifecycle_controls.confirm(binding, message, locale)
        if (
            command == "confirm"
            and self.git_publish is not None
            and await self.git_publish.owns_confirm(binding, message, arguments)
        ):
            return await self.git_publish.confirm(binding, message, locale, arguments)
        if (
            command == "confirm"
            and not arguments.strip()
            and self.schedules is not None
            and await self.schedules.owns_confirm(binding, message)
        ):
            return await self.schedules.confirm(binding, message, locale)
        if command == "decline":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            return await self._decline(binding, message, locale)
        if command in {"schedule", "once"} and self.schedules is not None:
            if command == "schedule":
                return await self.schedules.route(binding, message, locale, arguments)
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            return await self.schedules.once(binding, message, locale)
        if command == "choose":
            parts = arguments.split()
            if len(parts) == 1 and parts[0].isdecimal():
                try:
                    row = await menu_shortcuts.resolve(self.db, binding, message)
                except menu_shortcuts.NoOpenMenu:
                    return self.tr.render("menu.no_open", locale)
                # Run exactly what that row's button would have sent, with all its checks.
                expanding = menu_shortcuts.EXPANDED.set(row)
                try:
                    return await self.execute(
                        binding, message, menu_shortcuts.expand(message.text, row), locale, claim
                    )
                finally:
                    menu_shortcuts.EXPANDED.reset(expanding)
            if (
                len(parts) != 2
                or not parts[1].isascii()
                or not parts[1].isdigit()
                or len(parts[1]) > 2
            ):
                raise ValueError("invalid_navigation_choice")
            saved = await self.tokens.inspect_allowed(
                parts[0],
                frozenset({"navigation", "interaction-page"}),
                message.realm_id,
                message.author_id,
            )
            if saved.kind == "interaction-page":
                return await self.permissions.choose(
                    binding, message, locale, parts[0], int(parts[1])
                )
            if saved.binding_id != binding.id or saved.binding_revision != binding.revision:
                raise Conflict("navigation_binding_changed")
            commands = saved.context.get("commands")
            if commands != list(NAVIGATION) or not 1 <= int(parts[1]) <= len(NAVIGATION):
                raise Conflict("navigation_menu_changed")
            await self.tokens.consume(parts[0], "navigation", message.realm_id, message.author_id)
            return await self.execute(
                binding,
                message,
                ParsedInput("command", NAVIGATION[int(parts[1]) - 1], ""),
                locale,
                claim,
            )
        if command == "outputs" and self.generated is not None:
            return await self.generated.execute(binding, message, locale, arguments)
        if command == "output":
            if self.history is None:
                return self.tr.render("output.unavailable", locale)
            return await self.history.output(binding, message, locale, arguments)
        if command == "run":
            # OpenCode 2.0.32 gives no command preview or receipt; see docs/STEER_RUN_OUTPUT.md.
            return self.tr.render("run.unavailable", locale)
        if command == "pending":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            return await self.permissions.pending(binding, message, locale)
        if command == "skip":
            return await self.permissions.forms.prepare_cancel(binding, message, locale, arguments)
        if command == "confirm":
            if not arguments.strip():
                # A bare `!ok` with no question open: show a waiting permission request,
                # whose own `!ok 1234` the list names; otherwise the question expired.
                waiting = await self.permissions.pending(binding, message, locale)
                if waiting == self.tr.render("pending.empty", locale):
                    raise Conflict("nothing_waiting_for_confirmation")
                return waiting
            return await self.permissions.forms.confirm_cancel(binding, message, locale, arguments)
        if command == "answer":
            if not arguments.strip():
                return await self.permissions.pending(binding, message, locale)
            if QUICK_ANSWER.fullmatch(arguments):
                return await self.permissions.answer_by_code(binding, message, locale, arguments)
            return await self.permissions.forms.answer(binding, message, locale, arguments)
        if command in {"approve", "deny"}:
            return await self.permissions.decide(binding, message, locale, command, arguments)
        if command == "history" and self.history is not None:
            return await self.history.route(binding, message, locale, arguments)
        if command in {"models", "model", "variants", "variant"} and self.models is not None:
            return await self.models.route(binding, message, locale, command, arguments)
        if command in {"worktrees", "worktree"} and self.worktrees is not None:
            return await self.worktrees.route(binding, message, locale, command, arguments)
        if command in {"checks", "check"} and self.checks is not None:
            return await self.checks.route(binding, message, locale, command, arguments)
        if (
            command == "git"
            and self.git_publish is not None
            and arguments.split(maxsplit=1)[0:1] in (["commit"], ["push"])
        ):
            return await self.git_publish.route(binding, message, locale, arguments)
        if command == "git" and arguments.split(maxsplit=1)[0:1] == ["evidence"]:
            if self.git_evidence is None:
                return self.tr.render("git_evidence.unavailable", locale)
            return await self.git_evidence.route(binding, message, locale, arguments)
        if (
            command == "git"
            and (git_parts := arguments.split(maxsplit=1))
            and git_parts[0] in GIT_REVIEW_VERBS
        ):
            # Recognize these fixed surfaces even without an enrolled reader.
            # They must never become a legacy metadata pagination token.
            if self.git_review is None:
                return self.tr.render("git_review.unavailable", locale)
            return await self.git_review.route(binding, message, locale, arguments)
        if command in METADATA_COMMANDS and self.metadata is not None:
            return await self.metadata.route(binding, message, locale, command, arguments)
        if command == "rename" and self.lifecycle is not None:
            return await self.lifecycle.rename(binding, message, locale, arguments)
        if command in {"fork", "compact", "revert"} and self.lifecycle_controls is not None:
            return await self.lifecycle_controls.route(binding, message, locale, command, arguments)
        if command in {"archive", "unarchive"} and self.lifecycle_controls is not None:
            return self.tr.render("lifecycle.archive_unavailable", locale)
        if command == "delete":
            # Native's DELETE also removes child sessions and cannot be undone or
            # read back. Chat never offers it; unbind keeps the session in OpenCode.
            return self.tr.render("lifecycle.delete_unavailable", locale)
        if command in {"files", "diff"} and self.file_menus is not None:
            return await self.file_menus.route(binding, message, locale, command, arguments)
        if command == "export" and self.exports is not None:
            return await self.exports.route(binding, message, locale, arguments, claim)
        if command == "file" and self.files is not None:
            return await self.files.route(binding, message, locale, claim)
        if command == "info":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            return self.tr.render(
                "router.info",
                locale,
                backend=safe(binding.backend_id),
                project=safe(binding.project_id),
                directory=safe(binding.canonical_directory),
                session=safe(binding.session_id),
                title=safe(binding.title),
            )
        if command == "status":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            try:
                snapshot = await self.bindings.control.snapshot(reference(binding))
                if snapshot.reference != reference(binding) or not snapshot.reconciled:
                    raise Conflict("session_not_reconciled")
            except (ValueError, TimeoutError, ConnectionError):
                if self.history is None:
                    raise
                text = await self.history.status(binding, message, locale)
                return (
                    text
                    + await self._queued(binding, message, locale)
                    + await self._waiting_note(binding, message, locale)
                    + await self._background_stop_note(binding, locale)
                    + await self._gap_note(binding, locale)
                )
            return (
                self.tr.render(
                    "router.status",
                    locale,
                    state=self.tr.render("status." + snapshot.state.value, locale),
                    paused=self.tr.render(
                        "router.yes" if binding.dispatch_paused else "router.no", locale
                    ),
                )
                + (
                    await self._doing_note(binding, locale)
                    if snapshot.state == ExecutionState.RUNNING
                    else ""
                )
                + await self._queued(binding, message, locale)
                + await self._waiting_note(binding, message, locale)
                + await self._background_stop_note(binding, locale)
                + await self._gap_note(binding, locale)
            )
        if command == "queue":
            if arguments.strip() in {"resume", "resume new"}:
                if self.resume_guard is not None:
                    await self.resume_guard(binding)
                dropped = (
                    await self._drop_old_held(binding, message)
                    if arguments.strip() == "resume new"
                    else None
                )
                await self.queue.resume(
                    binding.id,
                    message.realm_id,
                    message.author_id,
                    binding.revision,
                    binding.queue_revision,
                )
                if dropped is not None:
                    return self.tr.render("router.resumed_new", locale, count=str(dropped))
                return self.tr.render("router.resumed", locale)
            if arguments.strip():
                raise ValueError("invalid_queue_arguments")
            actions = await self.queue.list(binding.id, message.realm_id, message.author_id)
            return (
                self.tr.render("router.queue", locale)
                + "\n\n"
                + (
                    "\n".join(
                        f"- `{item.id}`: {self.tr.render('queue.state.' + item.state, locale)}"
                        for item in actions
                    )
                    if actions
                    else self.tr.render("router.empty", locale)
                )
            ) + await self._background_stop_note(binding, locale)
        if command == "stop":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            receipt = await self.queue.request_stop(
                binding.id, message.realm_id, message.author_id, claim.id, source=message
            )
            if receipt.background_stop_unqualified:
                return (
                    self.tr.render("action.queue_paused", locale)
                    + "\n\n"
                    + self.tr.render("router.background_stop_unqualified", locale)
                    + "\n\n"
                    + self.tr.render("router.background_stop_not_queued", locale)
                )
            if receipt.interrupt_action_id is None:
                raise Conflict("stop_receipt_missing_interrupt_identity")
            text = (
                self.tr.render("action.received", locale)
                + "\n\n"
                + self.tr.render("action.stop_paused", locale)
            )
            if self.schedules is not None:
                # `!stop` stops everything here, your repeats included.
                stopped = await self.schedules.halt(binding, message)
                if stopped:
                    text += "\n\n" + self.tr.render("schedule.stopped", locale, count=str(stopped))
            return text
        if command == "cancel":
            identity = arguments.strip()
            if not identity or len(identity) > 36 or any(char.isspace() for char in identity):
                raise ValueError("invalid_action_identity")
            async with self.db.sessions() as session:
                action = await session.get(Action, identity)
            if (
                action is None
                or action.binding_id != binding.id
                or action.binding_revision != binding.revision
            ):
                raise AccessDenied("action_outside_current_topic")
            result = await self.queue.cancel(identity, message.realm_id, message.author_id)
            return self.tr.render("router.cancelled" if result else "router.not_cancelled", locale)
        if command in {"lang", "topic-lang"}:
            selected = arguments.strip()
            if command == "lang" and selected == "auto":
                await clear_locale(
                    self.db,
                    f"user:{message.realm_id}:{message.author_id}",
                    fence=self.inbox.fence,
                )
                automatic = await message_locale(
                    self.db, self.reader, message, cast(Locale, binding.locale)
                )
                return (
                    self.tr.render("settings.personal_automatic", automatic, locale=automatic)
                    + "\n\n"
                    + self.tr.render("settings.agent_language_unchanged", automatic)
                )
            if selected not in {"en", "zh-TW"}:
                raise ValueError("unsupported_locale")
            chosen: Locale = selected  # type: ignore[assignment]
            if command == "lang":
                await save_locale(
                    self.db,
                    f"user:{message.realm_id}:{message.author_id}",
                    chosen,
                    fence=self.inbox.fence,
                )
            else:
                await self.bindings.get(
                    binding.id, message.realm_id, message.author_id, Permission.MANAGE
                )
                async with self.db.sessions.begin() as session:
                    await self.inbox.fence.lock(session)
                    changed = await session.execute(
                        update(Binding)
                        .where(
                            Binding.id == binding.id,
                            Binding.revision == binding.revision,
                            Binding.state == "active",
                        )
                        .values(locale=chosen)
                    )
                    if changed.rowcount != 1:  # type: ignore[attr-defined]
                        raise Conflict("binding_changed")
                    session.add(
                        AuditEvent(
                            actor=f"{message.realm_id}:{message.author_id}",
                            event="topic_locale_changed",
                            object_id=binding.id,
                        )
                    )
            return (
                self.tr.render(
                    "settings.personal_saved" if command == "lang" else "settings.topic_saved",
                    chosen,
                    locale=chosen,
                )
                + "\n\n"
                + self.tr.render("settings.agent_language_unchanged", chosen)
            )
        if command == "settings":
            if arguments.strip():
                raise ValueError("unexpected_arguments")
            return self.tr.render("router.settings", locale, personal=locale, topic=binding.locale)
        return self.tr.render(
            "capability.unsupported",
            locale,
            capability=safe(command),
            reason=self.tr.render("router.not_integrated", locale),
        )
