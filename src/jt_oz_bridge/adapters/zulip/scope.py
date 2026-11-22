"""Qualified private-channel membership and original-message source reads.

No directory-wide user search, client-side topic case folding or automatic grants.
A trusted event/receipt index must supply each message's expected channel first.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any
from weakref import WeakKeyDictionary

from jt_oz_bridge.adapters.zulip.bulk_scope import BulkScopeReads
from jt_oz_bridge.adapters.zulip.client import ZulipClient, ZulipError, ZulipReadUnavailable
from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.i18n import platform_locale
from jt_oz_bridge.storage.durable import digest

SCOPE_OPERATIONS = frozenset({"channel.info", "channel.members", "user.info", "topic.list"})


class ZulipOperationObservation[T]:
    """Opaque issuer-owned admission handle, never a reusable authority DTO."""

    __slots__ = ("__weakref__",)


class ZulipLocalWritePermit:
    """Opaque permission for local writes after one real two-sided observation."""

    __slots__ = ("__weakref__",)


@dataclass
class _LocalWritePhase:
    task: object
    reader: "ZulipSourceReader"
    actor: HumanMessage
    audience: AudienceSnapshot
    current: Callable[[], None]
    consumed: bool = False
    failed: bool = False
    closed_at: float | None = None


@dataclass(frozen=True)
class ObservedSources[T]:
    """Observed data only; the SQL writer and delivery retain their own guards."""

    sources: tuple[HumanMessage, ...]
    audience: AudienceSnapshot
    value: T


@dataclass(frozen=True)
class _OperationObservation[T]:
    task: object
    reader: "ZulipSourceReader"
    source_hash: str
    guard: object
    attestation: object
    qualification: object
    channels: frozenset[int]
    expected_channel: object
    observed: ObservedSources[T]
    local_write_phase: _LocalWritePhase


async def _operation_read[T](current: Callable[[], None], read: Callable[[], Awaitable[T]]) -> T:
    current()
    value = await read()
    current()
    return value


def positive(value: Any) -> int:
    if type(value) is not int or not 0 < value < 10**18:
        raise ZulipError("scope_numeric_identity_required")
    return value


class ZulipScopeReader:
    def __init__(
        self, client: ZulipClient, *, channel_ids: frozenset[int], bulk_metadata: bool = False
    ) -> None:
        if type(bulk_metadata) is not bool:
            raise ZulipError("explicit_bulk_metadata_policy_required")
        enrolled = client.attestation
        if (
            enrolled is None
            or not SCOPE_OPERATIONS <= enrolled.verified_scope_operations
            or client.verify_identity is None
            or type(channel_ids) is not frozenset
            or not channel_ids
            or any(type(x) is not int or not 0 < x < 10**18 for x in channel_ids)
        ):
            raise ZulipError("qualified_explicit_channel_scope_required")
        self.client, self.enrolled, self.channel_ids = client, enrolled, channel_ids
        self.gateway = ZulipGateway(client)
        self._bulk = BulkScopeReads(self, enabled=bulk_metadata)
        self._observations: WeakKeyDictionary[
            ZulipOperationObservation[Any], _OperationObservation[Any]
        ] = WeakKeyDictionary()
        self._observing: set[object] = set()
        self._local_write_phases: dict[object, _LocalWritePhase] = {}
        self._local_write_permits: WeakKeyDictionary[ZulipLocalWritePermit, _LocalWritePhase] = (
            WeakKeyDictionary()
        )

    def local_write_permit(
        self, reader: "ZulipSourceReader", actor: HumanMessage, audience: AudienceSnapshot
    ) -> ZulipLocalWritePermit:
        """Issue only inside this exact callback, before its final Source reads.

        The handle remains unusable for writes until the original observation
        is synchronously consumed. It grants no Native mutation authority.
        """
        phase = self._local_write_phases.get(asyncio.current_task())
        if (
            phase is None
            or phase.reader is not reader
            or phase.actor is not actor
            or phase.audience is not audience
            or phase.consumed
            or phase.failed
            or len(self._local_write_permits) >= 1000
        ):
            raise ZulipError("local_write_permit_requires_original_read_phase")
        phase.current()
        permit = ZulipLocalWritePermit()
        self._local_write_permits[permit] = phase
        return permit

    def require_write_permit(
        self,
        permit: ZulipLocalWritePermit,
        reader: "ZulipSourceReader",
        actor: HumanMessage,
        audience: AudienceSnapshot,
    ) -> None:
        """Recheck the issuer, consumed Source phase and current pins after awaits.

        The adopting controller separately enforces its one-use Native proof,
        five-second deadline and fresh SQL authority on every write boundary.
        """
        phase = (
            self._local_write_permits.get(permit) if type(permit) is ZulipLocalWritePermit else None
        )
        if (
            phase is None
            or phase.task is not asyncio.current_task()
            or phase.reader is not reader
            or phase.actor is not actor
            or phase.audience is not audience
            or not phase.consumed
            or phase.failed
            or phase.closed_at is None
            or not phase.closed_at <= time.monotonic() < phase.closed_at + 5
        ):
            raise ZulipError("local_write_permit_not_current_and_consumed")
        phase.current()

    def require_read_permit(
        self,
        permit: ZulipLocalWritePermit,
        reader: "ZulipSourceReader",
        actor: HumanMessage,
        audience: AudienceSnapshot,
    ) -> None:
        """Recheck only the in-flight read phase; this cannot admit any write.

        Native observers retain their own fresh SQL authority checks. The
        original Source, all Human members and Bot are still read again by
        the enclosing operation before a write permit can become usable.
        """
        phase = (
            self._local_write_permits.get(permit) if type(permit) is ZulipLocalWritePermit else None
        )
        if (
            phase is None
            or phase.task is not asyncio.current_task()
            or self._local_write_phases.get(phase.task) is not phase
            or phase.reader is not reader
            or phase.actor is not actor
            or phase.audience is not audience
            or phase.consumed
            or phase.failed
        ):
            raise ZulipError("local_read_permit_not_current_callback")
        phase.current()

    async def observe_sources[T](
        self,
        reader: "ZulipSourceReader",
        sources: tuple[HumanMessage, ...],
        *,
        read_only: Callable[[AudienceSnapshot], Awaitable[T]],
    ) -> ZulipOperationObservation[T]:
        """Bracket explicitly read-only work with one complete two-sided observation.

        The callback owns its fresh local grants and original Native read proof;
        this method does not authorize Native writes or replace its five-second
        current-authority checks. No partial callback result is published here.
        """
        task, guard = asyncio.current_task(), self.client.verify_identity
        client, http, transport = self.client, self.client.client, self.client.client._transport
        qualification = getattr(guard, "qualification", None)
        if (
            task is None
            or task in self._observing
            or not isinstance(reader, ZulipSourceReader)
            or reader.scope is not self
            or type(sources) is not tuple
            or not 1 <= len(sources) <= 8
            or any(type(source) is not HumanMessage for source in sources)
            or sources[0].is_bot
            or any(source.deleted for source in sources)
            or len({source.message_id for source in sources}) != len(sources)
            or any(
                (source.realm_id, source.channel_id, source.topic)
                != (sources[0].realm_id, sources[0].channel_id, sources[0].topic)
                or source.author_id not in {sources[0].author_id, self.enrolled.bot_user_id}
                or source.is_bot != (source.author_id == self.enrolled.bot_user_id)
                for source in sources
            )
            or not callable(getattr(type(guard), "scope_reads", None))
            or not callable(getattr(type(guard), "scope_read", None))
            or not callable(read_only)
        ):
            raise ZulipError("closed_operation_source_or_guard_not_qualified")
        actor = sources[0]
        self.scope(actor.realm_id, actor.channel_id)
        source_hash = digest({"sources": [source.model_dump(mode="json") for source in sources]})
        enrolled, channels, expected_channel = (
            self.enrolled,
            self.channel_ids,
            reader.expected_channel,
        )

        def current() -> None:
            if (
                asyncio.current_task() is not task
                or self.client is not client
                or client.client is not http
                or http._transport is not transport
                or self.client.verify_identity is not guard
                or self.client.attestation is not enrolled
                or self.enrolled is not enrolled
                or self.channel_ids is not channels
                or reader.scope is not self
                or reader.expected_channel is not expected_channel
                or getattr(guard, "qualification", None) is not qualification
                or source_hash
                != digest({"sources": [source.model_dump(mode="json") for source in sources]})
            ):
                raise ZulipError("closed_operation_identity_or_source_pins_changed")
            self.scope(actor.realm_id, actor.channel_id)

        self._observing.add(task)
        phase: _LocalWritePhase | None = None
        issued = False
        try:
            async with self.identity_reads():
                current()
                first = await self._operation_side(reader, sources, current)
                phase = _LocalWritePhase(task, reader, actor, first, current)
                self._local_write_phases[task] = phase
                value = await _operation_read(current, lambda: read_only(first))
                self._local_write_phases.pop(task, None)
                final = await self._operation_side(reader, sources, current)
                if first != final:
                    raise ZulipError("closed_operation_audience_changed")
                for source in sources:
                    if (
                        await _operation_read(
                            current,
                            partial(expected_channel, source.realm_id, source.message_id),
                        )
                        != source.channel_id
                    ):
                        raise ZulipError("closed_operation_expected_channel_changed")
            # The real final Bot/server check above must finish before issuing.
            current()
            observation = ZulipOperationObservation[T]()
            self._observations[observation] = _OperationObservation(
                task,
                reader,
                source_hash,
                guard,
                self.enrolled,
                qualification,
                channels,
                expected_channel,
                ObservedSources(sources, final, value),
                phase,
            )
            # Immediate synchronous consumption only. A later event-loop turn
            # cannot turn these facts into a time-based Human ACL cache.
            asyncio.get_running_loop().call_soon(self._observations.pop, observation, None)
            issued = True
            return observation
        finally:
            self._local_write_phases.pop(task, None)
            if phase is not None and not issued:
                phase.failed = True
            self._observing.discard(task)

    async def _operation_side(
        self,
        reader: "ZulipSourceReader",
        sources: tuple[HumanMessage, ...],
        current: Callable[[], None],
    ) -> AudienceSnapshot:
        actor = sources[0]
        messages = []
        for source in sources:
            if (
                await _operation_read(
                    current, partial(reader.expected_channel, source.realm_id, source.message_id)
                )
                != source.channel_id
            ):
                raise ZulipError("closed_operation_expected_channel_changed")
            await _operation_read(current, lambda: self.identity(scope_read=True))
            raw = await _operation_read(
                current,
                partial(
                    self.client.request,
                    "GET",
                    f"messages/{source.message_id}",
                    params={"apply_markdown": "false", "allow_empty_topic_name": "true"},
                ),
            )
            messages.append(
                reader.message(
                    raw.get("message"), source.realm_id, source.channel_id, source.message_id
                )
            )
        channel = await _operation_read(current, lambda: self.channel(actor.channel_id))
        if channel["invite_only"] is not True or channel["is_web_public"] is not False:
            raise ZulipError("private_channel_required")
        ids = await _operation_read(current, lambda: self.members(actor.channel_id))
        users = [await _operation_read(current, partial(self.user, identity)) for identity in ids]
        by_id = {user["user_id"]: user for user in users}
        if (
            actor.author_id not in by_id
            or by_id[actor.author_id]["is_bot"]
            or not by_id[self.enrolled.bot_user_id]["is_bot"]
            or any(
                user["is_bot"] and user["user_id"] != self.enrolled.bot_user_id for user in users
            )
        ):
            raise ZulipError("closed_operation_human_or_bot_audience_changed")
        for source, message in zip(sources, messages, strict=True):
            user = by_id.get(source.author_id)
            if (
                user is None
                or HumanMessage(**message, is_bot=user["is_bot"], deleted=False) != source
            ):
                raise ZulipError("closed_operation_original_source_changed")
        canonical = await _operation_read(
            current,
            lambda: self._operation_canonical_topic(actor.channel_id, actor.topic, tuple(messages)),
        )
        if canonical != actor.topic:
            raise ZulipError("closed_operation_canonical_topic_changed")
        return AudienceSnapshot(
            realm_id=actor.realm_id,
            channel_id=actor.channel_id,
            canonical_topic=canonical,
            user_ids=frozenset(user["user_id"] for user in users if not user["is_bot"]),
            untrusted_bot_ids=frozenset(),
            private=True,
            revision=digest({"channel": channel, "users": users, "topic": canonical}),
        )

    async def _operation_canonical_topic(
        self, channel: int, topic: str, messages: tuple[dict[str, Any], ...]
    ) -> str:
        """Reuse a positive current-side GET ID, never an event or saved proposal.

        The fresh catalog must name an actual just-read message as its exact
        maximum for this literal topic. Otherwise the original server narrow
        remains necessary; no case folding or presumed newest message is used.
        """
        self.scope(self.enrolled.realm_id, channel)
        await self.identity(scope_read=True)
        if not isinstance(topic, str) or not 1 <= len(topic) <= self.enrolled.max_topic_length:
            raise ZulipError("existing_nonempty_topic_required")
        topics = (await self.client.request("GET", f"users/me/{channel}/topics")).get("topics")
        if not isinstance(topics, list) or not 1 <= len(topics) <= 10000:
            raise ZulipError("bounded_server_topic_catalog_required")
        by_id: dict[int, str] = {}
        names: set[str] = set()
        for row in topics:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                raise ZulipError("topic_catalog_contract_mismatch")
            identity, name = positive(row.get("max_id")), row["name"]
            if len(name) > self.enrolled.max_topic_length or identity in by_id or name in names:
                raise ZulipError("ambiguous_server_topic_catalog")
            by_id[identity], names = name, names | {name}
        positive_anchor = False
        for message in messages:
            canonical = by_id.get(message["message_id"])
            if canonical is None:
                continue
            if canonical != message["topic"] or canonical != topic:
                raise ZulipError("closed_operation_canonical_topic_changed")
            positive_anchor = True
        if positive_anchor:
            return topic
        # A concurrent newer message may be absent from this side's GET set.
        # This extra catalog read never replaces the unchanged narrow fallback.
        return await self.canonical_topic(channel, topic)

    def consume_observation[T](
        self,
        observation: ZulipOperationObservation[T],
        reader: "ZulipSourceReader",
        sources: tuple[HumanMessage, ...],
    ) -> ObservedSources[T]:
        """Consume in the issuing task before yielding into guarded local SQL."""
        if type(observation) is not ZulipOperationObservation:
            raise ZulipError("closed_operation_observation_not_issued")
        saved = self._observations.pop(observation, None)
        if (
            saved is None
            or saved.task is not asyncio.current_task()
            or saved.reader is not reader
            or reader.scope is not self
            or saved.guard is not self.client.verify_identity
            or saved.attestation is not self.client.attestation
            or saved.attestation is not self.enrolled
            or saved.channels is not self.channel_ids
            or saved.expected_channel is not reader.expected_channel
            or saved.qualification is not getattr(saved.guard, "qualification", None)
            or type(sources) is not tuple
            or any(type(source) is not HumanMessage for source in sources)
            or saved.source_hash
            != digest({"sources": [source.model_dump(mode="json") for source in sources]})
        ):
            raise ZulipError("closed_operation_observation_not_current")
        actor = sources[0]
        self.scope(actor.realm_id, actor.channel_id)
        phase = saved.local_write_phase
        if (
            phase.failed
            or phase.consumed
            or phase.actor != actor
            or phase.reader is not reader
            or phase.audience != saved.observed.audience
        ):
            raise ZulipError("local_write_phase_not_original_observation")
        phase.current()
        phase.closed_at = time.monotonic()
        phase.consumed = True
        return saved.observed

    @asynccontextmanager
    async def identity_reads(self) -> AsyncIterator[None]:
        guard = self.client.verify_identity
        factory = getattr(type(guard), "scope_reads", None)
        if not callable(factory):
            yield  # Original custom guards retain their existing call behavior.
            return
        async with factory(guard):
            if (
                self.client.attestation is not self.enrolled
                or self.client.verify_identity is not guard
            ):
                raise ZulipError("scope_identity_not_current")
            async with self._bulk.operation():
                yield
            if (
                self.client.attestation is not self.enrolled
                or self.client.verify_identity is not guard
            ):
                raise ZulipError("scope_identity_not_current")

    async def identity(self, *, scope_read: bool = False) -> None:
        guard = self.client.verify_identity
        scoped = getattr(type(guard), "scope_read", None) if scope_read else None
        if (
            self.client.attestation != self.enrolled
            or guard is None
            or not await (scoped(guard) if callable(scoped) else guard())
            or self.client.attestation != self.enrolled
            or self.client.verify_identity is not guard
        ):
            raise ZulipError("scope_identity_not_current")

    def scope(self, realm: str, channel: int) -> None:
        if (
            self.client.attestation != self.enrolled
            or self.client.verify_identity is None
            or realm != self.enrolled.realm_id
            or positive(channel) not in self.channel_ids
        ):
            raise ZulipError("channel_not_enrolled_for_scope_reads")

    async def channel(self, channel: int) -> dict[str, Any]:
        self.scope(self.enrolled.realm_id, channel)
        bundled = await self._bulk.channel(channel)
        if bundled is not None:
            return bundled
        raw = (await self.client.request("GET", f"streams/{channel}")).get("stream")
        if (
            not isinstance(raw, dict)
            or positive(raw.get("stream_id")) != channel
            or type(raw.get("invite_only")) is not bool
            or type(raw.get("is_web_public")) is not bool
            or type(raw.get("history_public_to_subscribers")) is not bool
            or raw.get("is_archived", False) is not False
        ):
            raise ZulipError("channel_metadata_contract_mismatch")
        return {
            k: raw[k]
            for k in (
                "stream_id",
                "invite_only",
                "is_web_public",
                "history_public_to_subscribers",
            )
        }

    async def members(self, channel: int) -> tuple[int, ...]:
        self.scope(self.enrolled.realm_id, channel)
        bundled = await self._bulk.members(channel)
        if bundled is not None:
            return bundled
        raw = (await self.client.request("GET", f"streams/{channel}/members")).get("subscribers")
        if not isinstance(raw, list) or not 1 <= len(raw) <= 10000:
            raise ZulipError("complete_channel_membership_required")
        ids = tuple(sorted(positive(x) for x in raw))
        if len(set(ids)) != len(ids) or self.enrolled.bot_user_id not in ids:
            raise ZulipError("unique_membership_including_dedicated_bot_required")
        return ids

    async def user(self, user_id: int) -> dict[str, Any]:
        if self.client.attestation != self.enrolled or self.client.verify_identity is None:
            raise ZulipError("scope_enrollment_changed")
        user_id = positive(user_id)
        bundled = await self._bulk.user(user_id)
        if bundled is not None:
            return bundled
        guard = self.client.verify_identity
        own_bot = getattr(type(guard), "scope_bot_user", None)
        raw = own_bot(guard) if user_id == self.enrolled.bot_user_id and callable(own_bot) else None
        if raw is None:
            raw = (await self.client.request("GET", f"users/{user_id}")).get("user")
        if (
            not isinstance(raw, dict)
            or positive(raw.get("user_id")) != user_id
            or type(raw.get("is_bot")) is not bool
            or type(raw.get("is_active")) is not bool
            or raw["is_active"] is not True
        ):
            raise ZulipError("active_numeric_user_identity_required")
        return {k: raw[k] for k in ("user_id", "is_bot", "is_active")}

    async def canonical_topic(self, channel: int, topic: str) -> str:
        # The narrow and catalog are independent GETs. A concurrent append can
        # advance the catalog head between them. Re-read the complete proof;
        # never authorize from the stale narrow or infer a normalized alias.
        for _ in range(2):
            canonical = await self._canonical_topic_once(channel, topic)
            if canonical is not None:
                return canonical
        raise ZulipReadUnavailable("topic_head_changed_during_resolution")

    async def _canonical_topic_once(self, channel: int, topic: str) -> str | None:
        self.scope(self.enrolled.realm_id, channel)
        await self.identity(scope_read=True)
        if not isinstance(topic, str) or not 1 <= len(topic) <= self.enrolled.max_topic_length:
            raise ZulipError("existing_nonempty_topic_required")
        data = await self.client.request(
            "GET",
            "messages",
            params={
                "narrow": json.dumps(
                    [
                        {"operator": "channel", "operand": channel},
                        {"operator": "topic", "operand": topic},
                    ]
                ),
                "anchor": "newest",
                "num_before": 1,
                "num_after": 0,
                "apply_markdown": "false",
                "allow_empty_topic_name": "true",
            },
        )
        rows = data.get("messages")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 2:
            raise ZulipError("topic_server_resolution_unavailable")
        messages = [self.gateway.message(row) for row in rows]
        if any(m.channel_id != channel for m in messages) or len({m.id for m in messages}) != len(
            messages
        ):
            raise ZulipError("topic_resolution_channel_mismatch")
        latest = max(messages, key=lambda m: m.id)
        topics = (await self.client.request("GET", f"users/me/{channel}/topics")).get("topics")
        if not isinstance(topics, list) or len(topics) > 10000:
            raise ZulipError("bounded_server_topic_catalog_required")
        by_id: dict[int, str] = {}
        names: set[str] = set()
        for row in topics:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                raise ZulipError("topic_catalog_contract_mismatch")
            identity, name = positive(row.get("max_id")), row["name"]
            if identity in by_id or name in names or len(name) > self.enrolled.max_topic_length:
                raise ZulipError("ambiguous_server_topic_catalog")
            by_id[identity], names = name, names | {name}
        canonical = by_id.get(latest.id)
        # A server-side narrow and the catalog's positive latest-message ID resolve
        # aliases. No local Unicode/case normalization substitutes for that proof.
        if canonical is None and any(
            name == latest.topic and identity > latest.id for identity, name in by_id.items()
        ):
            return None
        if canonical != latest.topic or not canonical:
            raise ZulipError("topic_changed_or_not_canonically_resolved")
        return canonical

    async def inspect(self, realm_id: str, channel_id: int, topic: str) -> AudienceSnapshot:
        self.scope(realm_id, channel_id)
        async with self.identity_reads():
            return await self._inspect(realm_id, channel_id, topic)

    def supports_read_capture(self) -> bool:
        guard = self.client.verify_identity
        return (
            guard is not None
            and getattr(guard, "qualification", None) is not None
            and callable(getattr(type(guard), "scope_reads", None))
            and callable(getattr(type(guard), "scope_read", None))
        )

    async def capture_readonly[T](
        self,
        realm_id: str,
        channel_id: int,
        topic: str,
        read: Callable[[AudienceSnapshot], Awaitable[T]],
    ) -> tuple[AudienceSnapshot, T]:
        """Bracket one original GET capture with complete independent ACL sides.

        No Source, Native mutation permit, SQL-write permit or authorization
        cache is issued. Callers still validate their original local binding,
        grants, consumer fence and live Native witness before committing.
        """
        if not self.supports_read_capture() or not callable(read):
            raise ZulipError("qualified_read_capture_required")
        task = asyncio.current_task()
        if task is None or task in self._observing:
            raise ZulipError("read_capture_original_task_required")
        client, http, guard, enrolled, channels = (
            self.client,
            self.client.client,
            self.client.verify_identity,
            self.enrolled,
            self.channel_ids,
        )
        transport, qualification = http._transport, getattr(guard, "qualification", None)

        def current() -> None:
            if (
                asyncio.current_task() is not task
                or self.client is not client
                or client.client is not http
                or http._transport is not transport
                or client.verify_identity is not guard
                or client.attestation is not enrolled
                or self.enrolled is not enrolled
                or self.channel_ids is not channels
                or getattr(guard, "qualification", None) is not qualification
            ):
                raise ZulipError("read_capture_identity_or_transport_changed")
            self.scope(realm_id, channel_id)

        async def side() -> AudienceSnapshot:
            channel = await _operation_read(current, lambda: self.channel(channel_id))
            if channel["invite_only"] is not True or channel["is_web_public"] is not False:
                raise ZulipError("private_channel_required")
            members = await _operation_read(current, lambda: self.members(channel_id))
            users = [await _operation_read(current, partial(self.user, uid)) for uid in members]
            if not next(u for u in users if u["user_id"] == enrolled.bot_user_id)["is_bot"]:
                raise ZulipError("dedicated_bot_identity_changed")
            canonical = await _operation_read(
                current, lambda: self.canonical_topic(channel_id, topic)
            )
            return AudienceSnapshot(
                realm_id=realm_id,
                channel_id=channel_id,
                canonical_topic=canonical,
                user_ids=frozenset(u["user_id"] for u in users if not u["is_bot"]),
                untrusted_bot_ids=frozenset(
                    u["user_id"]
                    for u in users
                    if u["is_bot"] and u["user_id"] != enrolled.bot_user_id
                ),
                private=True,
                revision=digest({"channel": channel, "users": users, "topic": canonical}),
            )

        self._observing.add(task)
        try:
            current()
            async with self.identity_reads():
                first = await side()
                value = await _operation_read(current, lambda: read(first))
                final = await side()
                if first != final:
                    raise ZulipError("read_capture_audience_changed")
            current()  # Includes the final independent Bot identity refresh.
            return final, value
        finally:
            self._observing.discard(task)

    async def _inspect(self, realm_id: str, channel_id: int, topic: str) -> AudienceSnapshot:
        self.scope(realm_id, channel_id)
        before = await self.channel(channel_id)
        if before["invite_only"] is not True or before["is_web_public"] is not False:
            raise ZulipError("private_channel_required")
        ids = await self.members(channel_id)
        users = [await self.user(identity) for identity in ids]
        if not next(u for u in users if u["user_id"] == self.enrolled.bot_user_id)["is_bot"]:
            raise ZulipError("dedicated_bot_identity_changed")
        canonical = await self.canonical_topic(channel_id, topic)
        if await self.members(channel_id) != ids or await self.channel(channel_id) != before:
            raise ZulipError("channel_membership_changed_during_inspection")
        current = [await self.user(identity) for identity in ids]
        if current != users or await self.canonical_topic(channel_id, canonical) != canonical:
            raise ZulipError("user_or_topic_changed_during_inspection")
        return AudienceSnapshot(
            realm_id=realm_id,
            channel_id=channel_id,
            canonical_topic=canonical,
            user_ids=frozenset(u["user_id"] for u in users if not u["is_bot"]),
            untrusted_bot_ids=frozenset(
                u["user_id"]
                for u in users
                if u["is_bot"] and u["user_id"] != self.enrolled.bot_user_id
            ),
            private=True,
            revision=digest({"channel": before, "users": users, "topic": canonical}),
        )


class ZulipSourceReader:
    def __init__(
        self,
        scope: ZulipScopeReader,
        expected_channel: Callable[[str, int], Awaitable[int | None]],
        *,
        language_file: Path | None = None,
        default_locale: Locale = "en",
    ) -> None:
        self.scope, self.expected_channel = scope, expected_channel
        self.language_file, self.default_locale = language_file, default_locale

    async def preferred_locale(self, realm: str, user_id: int) -> Locale | None:
        if realm != self.scope.enrolled.realm_id or type(user_id) is not int or user_id <= 0:
            raise ZulipError("platform_locale_identity_mismatch")
        return (
            platform_locale(self.language_file, realm, user_id)
            if self.language_file is not None
            else None
        )

    def message(self, raw: Any, realm: str, channel: int, message_id: int) -> dict[str, Any]:
        posted = self.scope.gateway.message(raw)
        if posted.realm_id != realm or posted.channel_id != channel or posted.id != message_id:
            raise ZulipError("original_message_scope_mismatch")
        history = raw.get("edit_history", [])
        if (
            not isinstance(history, list)
            or len(history) > 10000
            or any(not isinstance(row, dict) for row in history)
            or (raw.get("last_edit_timestamp") is not None and not history)
        ):
            raise ZulipError("original_message_revision_history_required")
        return {
            "realm_id": realm,
            "channel_id": channel,
            "topic": posted.topic,
            "message_id": message_id,
            "revision": len(history),
            "author_id": positive(posted.sender_id),
            "text": posted.content,
        }

    async def read(self, realm: str, message_id: int) -> HumanMessage:
        message_id = positive(message_id)
        channel = await self.expected_channel(realm, message_id)
        if channel is None:
            raise ZulipError("trusted_event_or_receipt_message_scope_required")
        self.scope.scope(realm, channel)
        await self.scope.identity()
        params = {"apply_markdown": "false", "allow_empty_topic_name": "true"}
        raw = await self.scope.client.request("GET", f"messages/{message_id}", params=params)
        message = self.message(raw.get("message"), realm, channel, message_id)
        user = await self.scope.user(message["author_id"])
        again = await self.scope.client.request("GET", f"messages/{message_id}", params=params)
        if (
            self.message(again.get("message"), realm, channel, message_id) != message
            or await self.expected_channel(realm, message_id) != channel
            or await self.scope.user(message["author_id"]) != user
        ):
            raise ZulipError("original_source_changed_during_read")
        return HumanMessage(**message, is_bot=user["is_bot"], deleted=False)
