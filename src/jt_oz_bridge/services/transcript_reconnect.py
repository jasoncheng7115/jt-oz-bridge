"""Fenced recovery of one original transcript after a Native restart.

Bridge reconnects by itself when it can prove the same session, directory,
contract, semantics and installed evidence under a new Native owner. When that
automatic proof is refused, the person answers `!ok`: the same fresh proof and
checks, minus the preview round-trip. `!reconnect` still shows the details first.
Only qualified transcript GETs are used. The bounded payload-v2 lineage retains
old sealed observations; it never repairs a Native session or resends work.
"""

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.transcript import (
    NativeTranscriptPage,
    TranscriptEntry,
    same_message,
)
from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel, ExecutionState
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import ParsedInput, parse_input
from jt_oz_bridge.presentation.markdown import code_span
from jt_oz_bridge.presentation.menu_buttons import button_widget, buttons_widget
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import checksum, scope
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.closed_bound_queue import UNSETTLED, ClosedBoundQueue, person_paused
from jt_oz_bridge.services.command_receipts import CommandClaim, CommandInbox
from jt_oz_bridge.services.outbox import OutboundPayload, Outbox
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_records import (
    MAX_OWNER_TRANSITIONS,
    TranscriptObservation,
    TranscriptOwnerTransition,
    TranscriptScan,
    TranscriptState,
    incomplete,
    read_snapshot,
    read_stream,
    scope_key,
    write_stream,
)
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch, Grant
from jt_oz_bridge.storage.transcript_models import (
    TranscriptCandidate,
    TranscriptMessage,
    TranscriptStream,
    TranscriptVersion,
)
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

KIND = "transcript-reconnect-confirm"
TTL = 120
NOTICE_RENDERER = "transcript-reconnect-notice-v1"
OWNER_GAP = "original_owner_or_semantics_changed"
# Work the gap pause alone held back; anything else keeps the pause for a person.
PAUSE_HELD = ("prompt", "model.switch", "check.run")


class ReconnectUnavailable(Conflict):
    code = "reconnect.capacity"


def immutable_core(entry: TranscriptEntry) -> str:
    value = entry.projection()
    return digest(
        {
            "id": entry.native_id,
            "kind": entry.kind,
            "created": value["time"]["created"],
            "agent": value.get("agent"),
            "model": value.get("model"),
            "command": value.get("command"),
        }
    )


@dataclass(frozen=True)
class ReconnectCapture:
    state: TranscriptState
    stream_hash: str
    head: NativeTranscriptPage
    entries: tuple[TranscriptObservation, ...]
    total_bytes: int
    proof_hash: str
    require_current: Callable[[], None]
    # Installed evidence of the retained anchor/open observations.
    previous_installed: frozenset[str] = frozenset()


class ReconnectReply(ControlModel):
    format: Literal["transcript-reconnect-reply-v1"] = "transcript-reconnect-reply-v1"
    text: str
    locale: Locale
    source: HumanMessage
    binding_scope_hash: str
    token: str | None = None
    transition_id: str | None = None
    # Desktop button for the reply; phones use the typed command it repeats.
    widget: str | None = None


class TranscriptReconnectService:
    def __init__(
        self,
        collector: TranscriptCollector,
        source: SourceReader,
        inbox: CommandInbox,
        tokens: TokenService,
        *,
        source_guard: ClosedBoundQueue | None = None,
        queue: QueueService | None = None,
    ) -> None:
        if (
            collector.db is not inbox.db
            or tokens.db is not collector.db
            or tokens.fence != collector.fence
            or inbox.fence != collector.fence
            or source_guard is not None
            and (
                source_guard.reader is not source
                or source_guard.bindings is not collector.bindings
                or source_guard.inbox is not inbox
                or source_guard.continuity is not collector
            )
            or isinstance(source, ZulipSourceReader)
            and source_guard is None
        ):
            raise ValueError("reconnect_original_pipeline_required")
        self.collector, self.bindings, self.db = collector, collector.bindings, collector.db
        self.source, self.inbox, self.tokens = source, inbox, tokens
        self.fence, self.source_guard, self.tr = collector.fence, source_guard, Translator()
        if queue is not None and queue.bindings is not self.bindings:
            raise ValueError("reconnect_original_pipeline_required")
        self.queue = queue

    async def owns(
        self, parsed: ParsedInput, claim: CommandClaim, binding: Binding, message: HumanMessage
    ) -> bool:
        if (
            parsed.command == "reconnect"
            or claim.response.get("format") == ReconnectReply.model_fields["format"].default
        ):
            return True
        if parsed.command != "confirm":
            return False
        async with self.db.sessions() as session:
            if not parsed.arguments:
                # A bare `!ok` is ours while OpenCode's restart waits for a person here,
                # or while this person still has a reconnect preview open. Otherwise it
                # answers whatever else Bridge asked (a schedule, an Agent switch, ...).
                try:
                    if await self._owner_gap(session, binding):
                        return True
                except (Conflict, ValueError):
                    return True
                return await self._unused_preview(session, binding, message)
            saved = await session.get(ControlToken, token_hash(parsed.arguments))
            return saved is not None and saved.kind == KIND

    async def _sql(
        self,
        session: AsyncSession,
        binding: Binding,
        message: HumanMessage,
        audience: AudienceSnapshot,
        current: Callable[[], None],
        *,
        write: bool = True,
        fresh: bool = True,
    ) -> Binding:
        current()
        if self.source_guard is not None:
            found, _ = await self.source_guard._sql(
                session, binding, message, audience, current, write=write, fresh=fresh
            )
            if fresh and (
                found.queue_revision != binding.queue_revision or not found.dispatch_paused
            ):
                raise Conflict("reconnect_paused_queue_changed")
            return found
        # Custom test/provider composition retains the ordinary two-sided
        # Source checks. Real Zulip must use the original issuer and journal.
        if write:
            await self.fence.lock(session)
        found = await lock_output_scope(self.bindings, session, binding)
        if fresh and (found.queue_revision != binding.queue_revision or not found.dispatch_paused):
            raise Conflict("reconnect_paused_queue_changed")
        grants = list(
            await session.scalars(
                select(Grant)
                .where(
                    Grant.realm_id == binding.realm_id,
                    Grant.project_id == binding.project_id,
                    Grant.user_id == message.author_id,
                    Grant.active.is_(True),
                )
                .with_for_update()
            )
        )
        if (
            not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
            or audience.revision != found.audience_revision
            or set(audience.user_ids) != set(found.audience_user_ids)
            or not any(Permission.OPERATE in ROLES.get(grant.role, set()) for grant in grants)
        ):
            raise AccessDenied("reconnect_current_actor_or_audience_required")
        current()
        return found

    async def _observe[T](
        self,
        binding: Binding,
        sources: tuple[HumanMessage, ...],
        read: Callable[[], Awaitable[T]],
        *,
        fresh: bool = True,
    ) -> tuple[T, AudienceSnapshot, Callable[[], None]]:
        message = sources[0]
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or any(s.deleted or s.revision != 0 for s in sources)
        ):
            raise AccessDenied("reconnect_current_original_control_required")
        if isinstance(self.source, ZulipSourceReader):
            reader = self.source

            async def observed(
                audience: AudienceSnapshot,
            ) -> tuple[T, AudienceSnapshot, ZulipLocalWritePermit]:
                permit = reader.scope.local_write_permit(reader, message, audience)

                def current() -> None:
                    reader.scope.require_read_permit(permit, reader, message, audience)

                async with self.db.sessions() as session:
                    await self._sql(
                        session, binding, message, audience, current, write=False, fresh=fresh
                    )
                return await read(), audience, permit

            observation = await reader.scope.observe_sources(reader, sources, read_only=observed)
            closed = reader.scope.consume_observation(observation, reader, sources)
            value, original_audience, permit = closed.value

            def current() -> None:
                # The final side is equal data, not the issuer's original
                # capability object. Preserve its identity across consumption.
                reader.scope.require_write_permit(permit, reader, message, original_audience)

            current()
            return value, original_audience, current
        before = await self.bindings.audience_for_output(binding)
        for original in sources:
            if await self.source.read(original.realm_id, original.message_id) != original:
                raise AccessDenied("reconnect_original_source_changed")
        await self.bindings.get(binding.id, message.realm_id, message.author_id, Permission.OPERATE)
        value = await read()
        after = await self.bindings.audience_for_output(binding)
        for original in sources:
            if await self.source.read(original.realm_id, original.message_id) != original:
                raise AccessDenied("reconnect_original_source_changed")
        if after != before:
            raise AccessDenied("reconnect_audience_changed")
        return value, after, lambda: None

    async def capture(self, binding: Binding) -> ReconnectCapture:
        state, expected = await self.collector.load(binding)
        if state is not None and len(state.owner_transitions) >= MAX_OWNER_TRANSITIONS:
            raise ReconnectUnavailable("reconnect_owner_transition_capacity")
        if (
            state is None
            or expected is None
            or state.status != "gap"
            or state.gap_reason != "original_owner_or_semantics_changed"
            or state.scan is not None
        ):
            raise Conflict("reconnect_owner_gap_or_capacity_required")
        ref = reference(binding)
        await self.bindings.enrolled(ref, binding.realm_id)
        reader = self.collector.readers.get(ref)
        if reader is None:
            raise Conflict("reconnect_original_reader_required")
        wanted = set(state.open_ids)
        if state.anchor is not None:
            wanted.add(state.anchor)
        original_entries = {}
        installed = set()
        async with self.db.sessions() as session:
            for identity in wanted:
                record = await session.scalar(
                    select(TranscriptMessage).where(
                        TranscriptMessage.scope_key == state.key,
                        TranscriptMessage.native_id == identity,
                    )
                )
                version = (
                    await session.scalar(
                        select(TranscriptVersion).where(
                            TranscriptVersion.record_id == record.id,
                            TranscriptVersion.version == record.current_version,
                        )
                    )
                    if record
                    else None
                )
                if record is None or version is None:
                    raise Conflict("reconnect_original_anchor_record_missing")
                retained = read_snapshot(version, record, state).observation
                original_entries[identity] = retained.entry
                installed.add(retained.installed_evidence_sha256)
        cursor = None
        cursors: set[str] = set()
        identities: set[str] = set()
        observations = []
        first = None
        total = 0
        found = set()
        while True:
            page = await reader.capture(ref, cursor=cursor, limit=20)
            if (
                page.reference != ref
                or page.contract_sha256 != state.contract_sha256
                or page.semantics_sha256 != state.semantics_sha256
                or page.contract_sha256 != self.bindings.control.contract_for(ref)
                or page.cursor != cursor
                or page.limit != 20
                or not reader.current(page)
                or page.owner_epoch == state.owner_epoch
                or page.owner_epoch
                in {transition.old_owner for transition in state.owner_transitions}
                or page.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED}
            ):
                raise Conflict("reconnect_original_native_scope_changed")
            if first is None:
                first = page
            elif self._frontier(page) != self._frontier(first):
                raise Conflict("reconnect_native_changed_during_history")
            for index, entry in enumerate(page.entries):
                if entry.native_id in identities:
                    raise Conflict("reconnect_history_identity_repeated")
                identities.add(entry.native_id)
                observation = TranscriptObservation.capture(page, index)
                total += len(checked_json(observation.model_dump(mode="json")))
                if len(identities) > 10000 or total > 16 * 1024 * 1024:
                    raise Conflict("reconnect_history_capacity")
                if entry.native_id in original_entries:
                    old = original_entries[entry.native_id]
                    if (
                        old.kind != entry.kind
                        or immutable_core(old) != immutable_core(entry)
                        or not incomplete(old)
                        and not same_message(old, entry)
                    ):
                        raise Conflict("reconnect_original_history_anchor_changed")
                    found.add(entry.native_id)
                observations.append(observation)
            if wanted and found == wanted:
                break
            if page.next_cursor is None:
                if found != wanted:
                    raise Conflict("reconnect_original_history_anchor_missing")
                break
            if not page.entries or page.next_cursor in cursors:
                raise Conflict("reconnect_history_cursor_repeated")
            cursor = page.next_cursor
            cursors.add(cursor)
        assert first is not None
        # A closing qualified GET supplies the current five-second witness.
        # Saved earlier pages are observations, never a TTL extension.
        head = await reader.capture(ref, limit=20)
        if (
            self._frontier(head) != self._frontier(first)
            or head.cursor is not None
            or head.limit != 20
            or head.entries != first.entries
            or head.next_cursor != first.next_cursor
            or not reader.current(head)
        ):
            raise Conflict("reconnect_native_frontier_changed")
        assembly = (self.collector.readers, self.bindings.control)

        def current() -> None:
            if (
                self.collector.readers is not assembly[0]
                or self.bindings.control is not assembly[1]
                or self.collector.readers.get(ref) is not reader
                or not reader.current(head)
            ):
                raise Conflict("reconnect_native_witness_expired")

        proof = digest(
            {
                "scope": state.key,
                "old_stream": expected,
                "old_owner": state.owner_epoch,
                "new_owner": head.owner_epoch,
                "frontier": self._frontier(head),
                "anchor": state.anchor,
                "open": state.open_ids,
                "entries": [value.entry.model_dump(mode="json") for value in observations],
            }
        )
        current()
        return ReconnectCapture(
            state,
            expected,
            head,
            tuple(observations),
            total,
            proof,
            current,
            frozenset(installed),
        )

    @staticmethod
    def _frontier(page: NativeTranscriptPage) -> tuple[Any, ...]:
        return (
            page.reference.model_dump(mode="json"),
            page.contract_sha256,
            page.semantics_sha256,
            page.installed_evidence_sha256,
            page.owner_epoch,
            page.connection_epoch,
            page.resource_fence,
            page.session_info_sha256,
            page.state,
        )

    async def _preview_token(
        self, binding: Binding, message: HumanMessage
    ) -> tuple[str, HumanMessage, tuple[HumanMessage, ...]]:
        async with self.db.sessions() as session:
            return await self._preview_in_session(session, binding, message)

    async def _preview_in_session(
        self, session: AsyncSession, binding: Binding, message: HumanMessage
    ) -> tuple[str, HumanMessage, tuple[HumanMessage, ...]]:
        """Network-free latest-visible selection, rechecked at confirmation commit."""
        receipts = list(
            await session.scalars(
                select(CommandReceipt)
                .where(
                    CommandReceipt.realm_id == message.realm_id,
                    CommandReceipt.actor_id == message.author_id,
                    CommandReceipt.channel_id == message.channel_id,
                    CommandReceipt.topic == message.topic,
                    CommandReceipt.binding_id == binding.id,
                    CommandReceipt.binding_revision == binding.revision,
                    CommandReceipt.message_id < message.message_id,
                    CommandReceipt.command == "reconnect",
                    CommandReceipt.state == "completed",
                )
                .order_by(CommandReceipt.message_id.desc())
                .limit(100)
                .with_for_update()
            )
        )
        candidate = None
        for receipt in receipts:
            if receipt.response.get("format") != "transcript-reconnect-reply-v1":
                continue
            saved = ReconnectReply.model_validate(receipt.response)
            if saved.token is None:
                continue
            batch = await session.scalar(
                select(DeliveryBatch).where(
                    DeliveryBatch.dedupe_key
                    == "reply-batch:"
                    + digest(
                        {
                            "key": "command:" + receipt.id,
                            "binding": binding.id,
                            "revision": binding.revision,
                        }
                    )
                )
            )
            if batch is None:
                raise Conflict("reconnect_preview_not_delivered")
            rows = list(
                await session.scalars(
                    select(Delivery)
                    .where(Delivery.batch_id == batch.id)
                    .order_by(Delivery.batch_index)
                    .with_for_update()
                )
            )
            if (
                not rows
                or len(rows) != batch.page_count
                or [r.batch_index for r in rows] != list(range(batch.page_count))
            ):
                raise Conflict("reconnect_preview_pages_changed")
            if all(
                row.state == "delivered"
                and row.posted_message_id is not None
                and row.posted_message_id > message.message_id
                or row.state == "pending"
                and row.attempts == 0
                and row.posted_message_id is None
                for row in rows
            ):
                continue
            if any(
                row.state != "delivered"
                or row.posted_message_id is None
                or row.posted_message_id >= message.message_id
                for row in rows
            ):
                raise Conflict("reconnect_preview_delivery_uncertain")
            posted = max(row.posted_message_id or 0 for row in rows)
            if candidate is None or posted > candidate[0]:
                candidate = (posted, receipt, saved, rows)
            elif posted == candidate[0]:
                raise Conflict("reconnect_preview_delivery_order_ambiguous")
        if candidate is None:
            raise Conflict("reconnect_no_visible_preview")
        _, receipt, saved, rows = candidate
        if (
            saved.source.author_id != message.author_id
            or receipt.actor_id != message.author_id
            or saved.source.message_id != receipt.message_id
            or saved.binding_scope_hash != checksum(scope(binding))
            or receipt.source_hash != digest(saved.source.model_dump(mode="json"))
        ):
            raise Conflict("reconnect_preview_actor_or_scope_changed")
        bot_sources = []
        for row in rows:
            assert row.posted_message_id is not None
            if digest(row.payload) != row.payload_hash:
                raise Conflict("reconnect_preview_delivery_seal_changed")
            payload = OutboundPayload.model_validate(row.payload)
            if (payload.realm_id, payload.channel_id, payload.topic) != (
                message.realm_id,
                message.channel_id,
                message.topic,
            ):
                raise Conflict("reconnect_preview_delivery_scope_changed")
            bot_sources.append(
                HumanMessage(
                    realm_id=message.realm_id,
                    channel_id=message.channel_id,
                    topic=message.topic,
                    message_id=row.posted_message_id,
                    revision=0,
                    author_id=payload.bot_user_id,
                    text=payload.content,
                    is_bot=True,
                )
            )
        if len(bot_sources) > 6:
            raise Conflict("reconnect_preview_source_capacity")
        assert saved.token is not None
        return saved.token, saved.source, tuple(bot_sources)

    async def _owner_gap(self, session: AsyncSession, binding: Binding) -> bool:
        """Network-free: the stream waits in the gap `!reconnect` can preview."""
        row = await session.get(TranscriptStream, scope_key(binding))
        if row is None:
            return False
        state = read_stream(row, binding)
        return state.status == "gap" and state.gap_reason == OWNER_GAP and state.scan is None

    @staticmethod
    async def _unused_preview(
        session: AsyncSession, binding: Binding, message: HumanMessage, *, live: bool = False
    ) -> bool:
        """This person has a reconnect preview token here not used up (and, if live, unexpired)."""
        found = await session.scalar(
            select(ControlToken.token_hash)
            .where(
                ControlToken.kind == KIND,
                ControlToken.realm_id == message.realm_id,
                ControlToken.user_id == message.author_id,
                ControlToken.binding_id == binding.id,
                ControlToken.binding_revision == binding.revision,
                ControlToken.used.is_(False),
                *((ControlToken.expires_at > time.time(),) if live else ()),
            )
            .limit(1)
        )
        return found is not None

    async def _preview_open(
        self, session: AsyncSession, binding: Binding, message: HumanMessage
    ) -> bool:
        """True while a bare `!ok` from this person answers a reconnect preview.

        Any live preview token counts, shown yet or not, and so does an unclear
        latest preview. Then the answer is the preview's, with its token and
        delivery checks. A preview used up or past its two minutes is not open:
        its token can never confirm, so `!ok` reconnects from a fresh proof instead.
        """
        if await self._unused_preview(session, binding, message, live=True):
            return True
        try:
            opaque, _, _ = await self._preview_in_session(session, binding, message)
        except Conflict as error:
            return str(error) != "reconnect_no_visible_preview"
        saved = await session.get(ControlToken, token_hash(opaque))
        return (
            saved is None
            or saved.kind != KIND
            or (saved.realm_id, saved.user_id, saved.binding_id, saved.binding_revision)
            != (message.realm_id, message.author_id, binding.id, binding.revision)
            or not saved.used
            and saved.expires_at > time.time()
        )

    async def _one_step(self, binding: Binding, message: HumanMessage) -> bool:
        """A bare `!ok` reconnects at once: the restart waits and no preview is open."""
        async with self.db.sessions() as session:
            try:
                return await self._owner_gap(session, binding) and not await self._preview_open(
                    session, binding, message
                )
            except (Conflict, ValueError):
                return False

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, claim: CommandClaim
    ) -> RoutedInput:
        parsed = parse_input(message.text, bound=True)
        if claim.status == "replay":
            saved = ReconnectReply.model_validate(claim.response)
            if saved.source != message or saved.binding_scope_hash != checksum(scope(binding)):
                raise Conflict("reconnect_replay_scope_changed")

            async def read_saved() -> ReconnectReply:
                return saved

            await self._observe(binding, (message,), read_saved, fresh=False)
            return self._routed(binding, saved, claim.id)
        if claim.status != "claimed" or message.revision != 0 or parsed.kind != "command":
            raise Conflict("reconnect_fresh_command_required")
        if parsed.command == "reconnect":
            if parsed.arguments:
                raise ValueError("reconnect_takes_no_arguments")
            captured, audience, source_current = await self._observe(
                binding, (message,), lambda: self.capture(binding)
            )
            context = self._context(binding, message, audience, captured)
            with self.tokens.planning() as plan:
                opaque = await self.tokens.issue(
                    KIND,
                    message.realm_id,
                    message.author_id,
                    context,
                    ttl=TTL,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                )
                text = self.tr.render(
                    "reconnect.preview",
                    locale,
                    session=code_span(reference(binding).upstream_session_id),
                    directory=code_span(reference(binding).canonical_directory),
                    state=code_span(captured.head.state.value),
                    token=opaque,
                )
                saved = ReconnectReply(
                    text=text,
                    locale=locale,
                    source=message,
                    binding_scope_hash=checksum(scope(binding)),
                    token=opaque,
                    widget=button_widget(
                        text, self.tr.render("reconnect.button_confirm", locale), f"!ok {opaque}"
                    ),
                )

                async def commit_preview(session: AsyncSession) -> None:
                    await self._sql(session, binding, message, audience, source_current)
                    await self._stream(session, binding, captured.stream_hash)
                    captured.require_current()
                    await plan.commit(session)
                    source_current()
                    captured.require_current()

                await self.inbox.finish(claim, saved.model_dump(mode="json"), commit=commit_preview)
            return self._routed(binding, saved, claim.id)
        if parsed.command != "confirm":
            raise ValueError("reconnect_confirmation_required")
        if not parsed.arguments and await self._one_step(binding, message):
            return await self._reconnect_now(binding, message, locale, claim)
        opaque, preview_source, bot_sources = await self._preview_token(binding, message)
        if parsed.arguments and parsed.arguments != opaque:
            raise Conflict("reconnect_latest_preview_token_required")
        token = await self.tokens.inspect(opaque, KIND, message.realm_id, message.author_id)
        captured, audience, source_current = await self._observe(
            binding, (message, preview_source, *bot_sources), lambda: self.capture(binding)
        )
        expected_context = self._context(binding, preview_source, audience, captured)
        # Final output may legitimately evolve between preview and confirm.
        # All authority and original identity facts remain exact; history is
        # freshly proven, then its new proof is committed with the transition.
        if token.context != expected_context:
            raise Conflict("reconnect_preview_original_scope_changed")
        transition_id = str(uuid4())
        # The person asked to reconnect: lift the pause the gap set, like the
        # automatic path, so no extra `!go` is needed. Decided before the reply
        # text is fixed, and rechecked unchanged inside the commit.
        lift = await self._liftable(binding)
        text = self.tr.render("reconnect.resumed" if lift else "reconnect.completed", locale)
        saved = ReconnectReply(
            text=text,
            locale=locale,
            source=message,
            binding_scope_hash=checksum(scope(binding)),
            transition_id=transition_id,
            widget=None if lift else self._still_paused_widget(text, locale),
        )

        async def commit_confirmation(session: AsyncSession) -> None:
            current = await self._sql(session, binding, message, audience, source_current)
            if await self._preview_in_session(session, binding, message) != (
                opaque,
                preview_source,
                bot_sources,
            ):
                raise Conflict("reconnect_latest_preview_changed_before_commit")
            source_current()
            captured.require_current()
            row, old = await self._stream(session, binding, captured.stream_hash)
            captured.require_current()
            await self.tokens.consume_in_session(session, token, database_deadline=True)
            await self._confirmed(
                session, binding, message, current, row, old, captured, transition_id, lift
            )
            source_current()
            captured.require_current()

        await self.inbox.finish(claim, saved.model_dump(mode="json"), commit=commit_confirmation)
        return self._routed(binding, saved, claim.id)

    async def _reconnect_now(
        self, binding: Binding, message: HumanMessage, locale: Locale, claim: CommandClaim
    ) -> RoutedInput:
        """A bare `!ok` after the restart notice: `!reconnect` and its `!ok` in one step.

        Only the preview round-trip is skipped. The proof is captured fresh under the
        same Source, actor, grant, audience, queue and five-second Native witness checks
        `!reconnect` uses, all rechecked inside the commit with the transition `!ok`
        applies; a preview opened meanwhile makes this refuse instead.
        """
        captured, audience, source_current = await self._observe(
            binding, (message,), lambda: self.capture(binding)
        )
        transition_id = str(uuid4())
        lift = await self._liftable(binding)
        text = self.tr.render("reconnect.resumed" if lift else "reconnect.completed", locale)
        saved = ReconnectReply(
            text=text,
            locale=locale,
            source=message,
            binding_scope_hash=checksum(scope(binding)),
            transition_id=transition_id,
            widget=None if lift else self._still_paused_widget(text, locale),
        )

        async def commit_reconnect(session: AsyncSession) -> None:
            current = await self._sql(session, binding, message, audience, source_current)
            if await self._preview_open(session, binding, message):
                raise Conflict("reconnect_preview_opened_before_commit")
            source_current()
            captured.require_current()
            row, old = await self._stream(session, binding, captured.stream_hash)
            captured.require_current()
            await self._confirmed(
                session, binding, message, current, row, old, captured, transition_id, lift
            )
            source_current()
            captured.require_current()

        await self.inbox.finish(claim, saved.model_dump(mode="json"), commit=commit_reconnect)
        return self._routed(binding, saved, claim.id)

    async def _confirmed(
        self,
        session: AsyncSession,
        binding: Binding,
        message: HumanMessage,
        current: Binding,
        row: TranscriptStream,
        old: TranscriptState,
        captured: ReconnectCapture,
        transition_id: str,
        lift: bool,
    ) -> None:
        """The person's reconnect: transition, the gap's own pause, and one audit row."""
        await self._apply_transition(
            session,
            binding,
            row,
            old,
            captured,
            transition_id,
            kind="confirmed",
            actor_id=message.author_id,
            source_message_id=message.message_id,
            source_hash=digest(message.model_dump(mode="json")),
        )
        if lift != await self._gap_pause_only(session, current, old):
            raise Conflict("reconnect_paused_queue_changed")
        if lift:
            assert self.queue is not None
            # Same SQL as `!go`; its recovery-review refusals roll this back.
            await self.queue._resume_in_session(
                session,
                current,
                message.realm_id,
                message.author_id,
                binding.revision,
                current.queue_revision,
            )
            await session.refresh(current)
        else:
            # Only the gap's own pause is lifted; anything else still needs `!go`.
            current.dispatch_paused = True
            current.queue_revision += 1
        session.add(
            AuditEvent(
                actor=f"{message.realm_id}:{message.author_id}",
                event="transcript.owner_reconnected",
                object_id=transition_id,
            )
        )
        await session.flush()

    async def _apply_transition(
        self,
        session: AsyncSession,
        binding: Binding,
        row: TranscriptStream,
        old: TranscriptState,
        captured: ReconnectCapture,
        transition_id: str,
        *,
        kind: Literal["confirmed", "automatic"],
        actor_id: int,
        source_message_id: int,
        source_hash: str,
    ) -> None:
        """Seal one owner transition and bring the proven history live.

        Shared by `!ok` and the automatic reconnect. The caller owns the fence,
        the locked binding row and its queue pause; this never dispatches.
        """
        facts: dict[str, Any] = {
            "id": transition_id,
            "scope_key": old.key,
            "generation": len(old.owner_transitions) + 1,
            "old_owner": old.owner_epoch,
            "new_owner": captured.head.owner_epoch,
            "previous_hash": old.owner_transitions[-1].checksum
            if old.owner_transitions
            else "0" * 64,
            "previous_stream_hash": row.payload_hash,
            "actor_id": actor_id,
            "source_message_id": source_message_id,
            "source_hash": source_hash,
            "proof_hash": captured.proof_hash,
            "previous_gap_plan": old.gap_plan,
        }
        if kind != "confirmed":
            facts["kind"] = kind
        transition = TranscriptOwnerTransition.model_validate({**facts, "checksum": digest(facts)})
        scan = TranscriptScan(
            id=transition_id,
            anchor=old.anchor,
            head_id=captured.head.entries[0].native_id if captured.head.entries else old.anchor,
            remaining_open=(),
            found_anchor=True,
            offset=len(captured.entries),
            total_bytes=captured.total_bytes,
            recovering=True,
        )
        value = old.model_dump(mode="json")
        value.update(
            format="native-transcript-stream-v2",
            owner_epoch=captured.head.owner_epoch,
            owner_transitions=[
                *(v.model_dump(mode="json") for v in old.owner_transitions),
                transition.model_dump(mode="json"),
            ],
            status="scanning",
            scan=scan.model_dump(mode="json"),
            gap_reason=None,
            gap_plan=None,
            gap_resume_revision=None,
        )
        state = TranscriptState.model_validate(value)
        found_anchor = False
        for offset, observation in enumerate(captured.entries):
            if observation.entry.native_id == old.anchor:
                found_anchor = True
            payload = {
                "scope_key": old.key,
                "scan_id": scan.id,
                "offset": offset,
                "observation": observation.model_dump(mode="json"),
                "new": not found_anchor,
            }
            session.add(
                TranscriptCandidate(
                    scan_id=scan.id,
                    native_id=observation.entry.native_id,
                    scope_key=old.key,
                    offset=offset,
                    payload=payload,
                    payload_hash=digest(payload),
                )
            )
        await session.flush()
        captured.require_current()
        state = await self.collector.finalize(session, binding, state, scan, captured.head)
        write_stream(row, state)
        # A pre-restart form/permission/other Native control cannot survive
        # the owner boundary, even if its request ID happens to be reused.
        await session.execute(
            update(ControlToken)
            .where(
                ControlToken.binding_id == binding.id,
                ControlToken.binding_revision == binding.revision,
                ControlToken.used.is_(False),
            )
            .values(used=True)
        )

    async def automatic(
        self,
        binding: Binding,
        *,
        queue: QueueService,
        outbox: Outbox,
        message_limit: int,
        topic_limit: int,
    ) -> str:
        """Reconnect after a Native restart without asking anyone, or raise.

        The proof is the one `!reconnect` shows a person, plus unchanged
        installed evidence: same session, directory, backend, contract and
        semantics, a new owner that validates, and unchanged history anchors.
        On success one short line is queued in the topic. A pause the gap set
        is lifted when nothing touched the queue since; a person's pause, and
        any unclear or specially held work, keep it.
        """
        if queue.bindings is not self.bindings or outbox.fence != self.fence:
            raise ValueError("reconnect_original_pipeline_required")
        async with self.db.sessions() as session:
            fresh = await session.get(Binding, binding.id)
        if fresh is None or fresh.revision != binding.revision or fresh.state != "active":
            raise Conflict("reconnect_automatic_binding_changed")
        binding = fresh
        if self.bindings.supports_read_capture():
            captured = await self.bindings.capture_output(binding, lambda: self.capture(binding))
        else:
            await self.collector.preflight(binding)
            captured = await self.capture(binding)
            await self.collector.preflight(binding)
        head = captured.head
        if captured.previous_installed != {head.installed_evidence_sha256}:
            await self._ask_person(binding, captured, outbox, message_limit, topic_limit)
            raise Conflict("reconnect_automatic_installed_evidence_changed")
        locale: Locale = "zh-TW" if binding.locale == "zh-TW" else "en"
        transition_id = str(uuid4())
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            current = await lock_output_scope(self.bindings, session, binding)
            if current.queue_revision != binding.queue_revision or not current.dispatch_paused:
                raise Conflict("reconnect_paused_queue_changed")
            captured.require_current()
            row, old = await self._stream(session, binding, captured.stream_hash)
            captured.require_current()
            lift = (
                old.gap_resume_revision is not None
                and old.gap_resume_revision == current.queue_revision
                and await self._only_paused_work_waits(session, current)
            )
            await self._apply_transition(
                session,
                binding,
                row,
                old,
                captured,
                transition_id,
                kind="automatic",
                actor_id=0,
                source_message_id=0,
                source_hash=digest(
                    {
                        "automatic": captured.proof_hash,
                        "scope": old.key,
                        "old_stream": captured.stream_hash,
                        "new_owner": head.owner_epoch,
                        "installed_evidence": head.installed_evidence_sha256,
                    }
                ),
            )
            resumed = False
            if lift:
                try:
                    # Same SQL as `!go`, including its recovery-review refusals,
                    # which are raised before any write. It bumps the revision.
                    await queue._resume_in_session(
                        session,
                        current,
                        binding.realm_id,
                        0,
                        binding.revision,
                        current.queue_revision,
                    )
                    resumed = True
                except Conflict:
                    resumed = False
                await session.refresh(current)
            if not resumed:
                current.dispatch_paused = True
                current.queue_revision += 1
            notice = self.tr.render(
                "reconnect.automatic" if resumed else "reconnect.automatic_paused", locale
            )
            await outbox.queue_batch_in_session(
                session,
                "transcript-reconnected:" + transition_id,
                current,
                (notice,),
                renderer_version=NOTICE_RENDERER,
                message_limit=message_limit,
                topic_limit=topic_limit,
                widget=None if resumed else self._still_paused_widget(notice, locale),
            )
            session.add(
                AuditEvent(
                    actor="system",
                    event="transcript.owner_reconnected_automatically",
                    object_id=transition_id,
                )
            )
            await session.flush()
            captured.require_current()
        return transition_id

    def _still_paused_widget(self, text: str, locale: Locale) -> str | None:
        """Desktop buttons for the two commands a reconnected but paused notice names."""
        return buttons_widget(
            text,
            [
                (self.tr.render("button.status", locale), "!status"),
                (self.tr.render("button.go", locale), "!go"),
            ],
        )

    async def _ask_person(
        self,
        binding: Binding,
        captured: ReconnectCapture,
        outbox: Outbox,
        message_limit: int,
        topic_limit: int,
    ) -> None:
        """Say once per restart that a person's `!ok` reconnects; the gap notice only says maybe.

        Keyed by the old and new OpenCode owner, so retries and Bridge restarts
        never repeat it. Nothing else changes: the gap and its pause stay.
        """
        locale: Locale = "zh-TW" if binding.locale == "zh-TW" else "en"
        text = self.tr.render("reconnect.automatic_refused", locale)
        try:
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                current = await lock_output_scope(self.bindings, session, binding)
                if current.revision != binding.revision or current.state != "active":
                    return
                await self._stream(session, binding, captured.stream_hash)
                captured.require_current()
                await outbox.queue_batch_in_session(
                    session,
                    "transcript-reconnect-needed:"
                    + digest(
                        {
                            "scope": scope_key(binding),
                            "old_owner": captured.state.owner_epoch,
                            "new_owner": captured.head.owner_epoch,
                        }
                    ),
                    current,
                    (text,),
                    renderer_version=NOTICE_RENDERER,
                    message_limit=message_limit,
                    topic_limit=topic_limit,
                    widget=button_widget(text, self.tr.render("reconnect.button", locale), "!ok"),
                )
        except Conflict as error:
            # Already said for this restart in an earlier Bridge's words: once is enough.
            if str(error) != "reply_plan_changed":
                raise

    async def _liftable(self, binding: Binding) -> bool:
        async with self.db.sessions() as session:
            current = await session.get(Binding, binding.id)
            row = await session.get(TranscriptStream, scope_key(binding))
            if current is None or row is None:
                return False
            return await self._gap_pause_only(session, current, read_stream(row, binding))

    async def _gap_pause_only(
        self, session: AsyncSession, current: Binding, old: TranscriptState
    ) -> bool:
        """True when `!ok` may lift the pause: the gap set it and no person chose one since.

        Messages a person sent or dropped during the gap change the queue, but
        the preview they confirmed says waiting messages then go in order, as
        a fresh message does after a pause no person chose. A topic already
        paused before the gap, and a Zulip recovery hold, keep their own review.
        """
        if (
            self.queue is None
            or old.gap_resume_revision is None
            or old.gap_resume_revision > current.queue_revision
            or await person_paused(session, current.id)
        ):
            return False
        recovering = await session.scalar(
            select(ZulipRecoveryItem.id)
            .join(Action, Action.id == ZulipRecoveryItem.action_id)
            .where(ZulipRecoveryItem.binding_id == current.id, Action.state == "held")
            .limit(1)
        )
        return recovering is None and await self._only_paused_work_waits(session, current)

    @staticmethod
    async def _only_paused_work_waits(session: AsyncSession, binding: Binding) -> bool:
        """True when everything unsettled is queued/held only because of the pause."""
        other = await session.scalar(
            select(Action.id)
            .where(
                Action.binding_id == binding.id,
                Action.state.in_(UNSETTLED),
                ~and_(
                    Action.operation.in_(PAUSE_HELD),
                    Action.state.in_(("queued", "held")),
                    or_(Action.status_reason.is_(None), Action.status_reason == "queue_paused"),
                ),
            )
            .limit(1)
        )
        return other is None

    async def _stream(
        self, session: AsyncSession, binding: Binding, expected: str
    ) -> tuple[TranscriptStream, TranscriptState]:
        row = await session.get(TranscriptStream, scope_key(binding), with_for_update=True)
        if row is None or row.payload_hash != expected:
            raise Conflict("reconnect_stream_changed_before_commit")
        state = read_stream(row, binding)
        if state.status != "gap" or state.gap_reason != "original_owner_or_semantics_changed":
            raise Conflict("reconnect_gap_changed_before_commit")
        return row, state

    @staticmethod
    def _context(
        binding: Binding,
        source: HumanMessage,
        audience: AudienceSnapshot,
        captured: ReconnectCapture,
    ) -> dict[str, Any]:
        return {
            "reference": reference(binding).model_dump(mode="json"),
            "binding_scope_hash": checksum(scope(binding)),
            "queue_revision": binding.queue_revision,
            "stream_hash": captured.stream_hash,
            "old_owner": captured.state.owner_epoch,
            "new_owner": captured.head.owner_epoch,
            "contract": captured.head.contract_sha256,
            "semantics": captured.head.semantics_sha256,
            "installed_evidence": captured.head.installed_evidence_sha256,
            "audience_hash": digest(audience.model_dump(mode="json")),
            "source_hash": digest(source.model_dump(mode="json")),
        }

    @staticmethod
    def _routed(binding: Binding, saved: ReconnectReply, claim_id: str) -> RoutedInput:
        return RoutedInput(
            "reply",
            binding.id,
            binding.revision,
            saved.text,
            "reconnect:" + saved.transition_id if saved.transition_id else "command:" + claim_id,
            locale=saved.locale,
            widget=saved.widget,
        )
