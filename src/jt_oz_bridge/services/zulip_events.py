"""Fenced Zulip queue receipts and numeric source index; no native execution."""

import logging
import math
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.scope import positive
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.services.bindings import topic_key
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, InputEvent, uid
from jt_oz_bridge.storage.retained_payloads import retained_scope
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex, ZulipQueue, ZulipReceiptRetry

LOG = logging.getLogger(__name__)
# Realm-wide changes are seen for every channel and every person in the realm.
ACCOUNT_EVENTS = frozenset({"stream", "subscription", "realm_user", "realm"})
EVENT_OPS = frozenset(
    {
        "add",
        "create",
        "deactivated",
        "delete",
        "peer_add",
        "peer_remove",
        "remove",
        "update",
        "update_dict",
    }
)
# How a person looks; who they are and what they may do is everything else.
DISPLAY_PERSON_FIELDS = frozenset(
    {
        "user_id",
        "full_name",
        "avatar_url",
        "avatar_url_medium",
        "avatar_source",
        "avatar_version",
        "timezone",
        "custom_profile_field",
    }
)
DISPLAY_REALM_PROPERTIES = frozenset({"name", "description", "icon", "logo", "night_logo"})


def event_number(value: Any, *, watermark: bool = False) -> int:
    if type(value) is not int or not (-1 if watermark else 0) <= value < 2**63:
        raise ValueError("invalid_zulip_event_number")
    return value


def queue_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ValueError("invalid_zulip_queue_identity")
    return value


def event_channels(event: dict[str, Any]) -> set[int] | None:
    """Every channel a stream or subscription event names; None when one is unreadable."""
    found: list[Any] = []
    if "stream_id" in event:
        found.append(event["stream_id"])
    if "stream_ids" in event:
        if not isinstance(event["stream_ids"], list):
            return None
        found.extend(event["stream_ids"])
    for key in ("streams", "subscriptions"):
        if key in event:
            if not isinstance(event[key], list):
                return None
            found.extend(
                item.get("stream_id") if isinstance(item, dict) else None for item in event[key]
            )
    if not found or any(type(c) is not int or c <= 0 for c in found):
        return None
    return set(found)


def display_only(kind: str, op: str | None, event: dict[str, Any]) -> bool:
    """A change that cannot alter who is in our channels or what anyone may do there."""
    if kind == "subscription":
        # Bot-only settings such as colour, mute or notifications.
        return op == "update"
    if kind == "realm_user":
        if op == "add":
            # A new account is in no private channel until someone adds it.
            return True
        person = event.get("person")
        return (
            op == "update" and isinstance(person, dict) and person.keys() <= DISPLAY_PERSON_FIELDS
        )
    if kind == "realm":
        prop = event.get("property")
        return (
            op in {"update", "update_dict"}
            and isinstance(prop, str)
            and prop in DISPLAY_REALM_PROPERTIES
        )
    return False


@dataclass(frozen=True)
class ZulipEventClaim:
    receipt_id: str
    wire: dict[str, Any]
    recovered: bool
    routed: RoutedInput | None = None
    recovery_run_id: str | None = None


ROUTED = TypeAdapter(RoutedInput)
# Messages sent at most this long before Bridge came back are sent by themselves.
RESTART_RESEND_SECONDS = 600
# A message held this long is old: a new message no longer carries it along, so a
# days-old "ok" never reaches the AI as if just typed.
OLD_HELD_SECONDS = 3600
# Holds no person chose besides the restart's own (no reason): the dispatcher's.
UNCHOSEN_HOLDS = frozenset({"queue_paused"})
# Receipts for messages sent while Bridge was down use event ids no queue reaches.
MISSED_EVENT_BASE = 2**62
MISSED_FIELDS = (
    "id",
    "type",
    "stream_id",
    "sender_id",
    "subject",
    "content",
    "content_type",
    "timestamp",
)


def saved_route(payload: dict[str, Any]) -> RoutedInput | None:
    value = payload.get("routed_reply")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise Conflict("zulip_saved_route_changed")
    # Schema30 stored every original dataclass field before this optional
    # receipt link existed. Normalize exactly that one absent default in the
    # read view; do not rewrite encrypted payloads or accept other omissions.
    normalized = value if "queued_batch_id" in value else {**value, "queued_batch_id": None}
    queued = normalized["queued_batch_id"]
    if queued is not None:
        try:
            if type(queued) is not str or str(UUID(queued)) != queued:
                raise ValueError("invalid queued batch identity")
        except (ValueError, TypeError, AttributeError):
            raise Conflict("zulip_saved_route_batch_identity_changed") from None
    routed = ROUTED.validate_json(checked_json(value), strict=True)
    if ROUTED.dump_python(routed, mode="json") != normalized:
        raise Conflict("zulip_saved_route_changed")
    return routed


class ZulipEventJournal:
    def __init__(
        self,
        db: Database,
        fence: ConsumerFence,
        *,
        realm_id: str,
        bot_user_id: int,
        url: str,
        channel_ids: frozenset[int],
    ) -> None:
        if (
            not isinstance(realm_id, str)
            or not realm_id
            or len(realm_id) > 255
            or type(channel_ids) is not frozenset
            or not channel_ids
            or len(channel_ids) > 1000
        ):
            raise ValueError("explicit_zulip_event_scope_required")
        positive(bot_user_id)
        for c in channel_ids:
            positive(c)
        self.db, self.fence, self.realm_id, self.bot_user_id = db, fence, realm_id, bot_user_id
        self.restart_paused: dict[str, int] = {}
        self.channel_ids = channel_ids
        self.url = url.rstrip("/")
        self.source = digest(
            {
                "format": "zulip-event-source-v1",
                "realm_id": realm_id,
                "bot_user_id": bot_user_id,
                "url": self.url,
            }
        )

    def carried_over(self, payload: dict[str, Any], now: float | None = None) -> bool:
        """A plain new message the previous Bridge process captured but never began.

        Sent within ``RESTART_RESEND_SECONDS`` and unedited, so it goes through the
        normal path like a message that arrived now. Routing re-reads it anyway.
        """
        wire = payload.get("wire")
        row = wire.get("message") if isinstance(wire, dict) else None
        sent = row.get("timestamp") if isinstance(row, dict) else None
        current = time.time() if now is None else now
        return (
            isinstance(wire, dict)
            and wire.get("type") == "message"
            and wire.get("historical", False) is False
            and isinstance(row, dict)
            and row.get("last_edit_timestamp") is None
            and payload.get("recovery_run_id") is None
            and payload.get("defer_recovered", False) is False
            and type(sent) is int
            and current - RESTART_RESEND_SECONDS <= sent <= current + 60
        )

    def validate_receipt(self, row: InputEvent) -> None:
        p = row.payload
        compacted = row.payload_compacted_at is not None
        if compacted:
            if row.state not in {"zulip_done", "zulip_ignored"}:
                raise Conflict("retired_receipt_must_remain_terminal")
            p = retained_scope(
                p,
                kind="input:payload",
                identity=row.id,
                when=row.payload_compacted_at,
                checksum=row.payload_hash,
            )
        if (
            row.source != "zulip:" + self.source
            or row.revision != 0
            or not compacted
            and digest(p) != row.payload_hash
            or not compacted
            and p.get("format") != "zulip-event-capture-v1"
            or p.get("source") != self.source
            or p.get("realm_id") != self.realm_id
            or p.get("bot_user_id") != self.bot_user_id
            or type(p.get("capture_fencing")) is not int
            or p["capture_fencing"] < 1
            or not compacted
            and not isinstance(p.get("wire"), dict)
            or not compacted
            and p["wire"].get("id") != event_number(p.get("event_id"))
            or row.source_id
            != digest({"queue": queue_name(p.get("queue_id")), "native_event_id": p["event_id"]})
        ):
            raise Conflict("zulip_receipt_scope_changed")

    async def pause(
        self,
        session: AsyncSession,
        *,
        bindings: set[str] | None = None,
        channels: set[int] | None = None,
        reason: str,
    ) -> None:
        query = update(Binding).where(Binding.realm_id == self.realm_id, Binding.state == "active")
        if bindings is None and channels is None:
            # Only a pause this restart caused may later be lifted without a person.
            newly = await session.execute(
                select(Binding.id, Binding.queue_revision).where(
                    Binding.realm_id == self.realm_id,
                    Binding.state == "active",
                    Binding.dispatch_paused.is_(False),
                )
            )
            self.restart_paused.update({row[0]: row[1] + 1 for row in newly})
        if bindings is not None:
            if not bindings:
                return
            query = query.where(Binding.id.in_(bindings))
        if channels is not None:
            if not channels:
                return
            query = query.where(Binding.channel_id.in_(channels))
        result = await session.execute(
            query.values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
        )
        paused: int = result.rowcount  # type: ignore[attr-defined]
        if paused:
            LOG.warning(
                "zulip_change_paused reason=%s scope=%s bindings=%d",
                reason,
                "bindings" if bindings is not None else "channels" if channels else "all",
                paused,
            )

    async def release_restart_pause(
        self, binding_id: str, queue_revision: int, *, now: float | None = None
    ) -> str:
        """Lift the unchanged restart pause and send on what only the restart held.

        ``released``: every waiting action was held by the restart (or by the
        dispatcher's pause hold) within the last ``RESTART_RESEND_SECONDS``; they
        are queued again in their original order, exactly as `!go` would.
        ``kept_old``: older or otherwise held work waits, so nothing moves and the
        person decides with `!go` / `!no`. ``kept_unclear``: unclear work
        (dispatching, ambiguous, recovery review); nothing moves yet, and the
        caller asks again once it settles. ``kept``: a changed topic; nothing
        moves. A pause a person chose never reaches here: only bindings this
        restart paused do.
        """
        from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

        cutoff = (time.time() if now is None else now) - RESTART_RESEND_SECONDS
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            binding = await session.scalar(
                select(Binding).where(Binding.id == binding_id).with_for_update()
            )
            if (
                binding is None
                or binding.state != "active"
                or not binding.dispatch_paused
                or binding.queue_revision != queue_revision
            ):
                return "kept"
            rows = (
                await session.execute(
                    select(
                        Action.id,
                        Action.state,
                        Action.status_reason,
                        Action.created_at,
                        Action.binding_revision,
                        Action.operation,
                    ).where(
                        Action.binding_id == binding_id,
                        Action.state.in_(["queued", "held", "dispatching", "ambiguous"]),
                    )
                )
            ).all()
            linked = set(
                await session.scalars(
                    select(ZulipRecoveryItem.action_id).where(
                        ZulipRecoveryItem.binding_id == binding_id,
                        ZulipRecoveryItem.action_id.is_not(None),
                    )
                )
            )
            resend, old = [], False
            for identity, state, reason, created, revision, operation in rows:
                if state in {"dispatching", "ambiguous"} or identity in linked:
                    return "kept_unclear"
                if revision != binding.revision or state == "queued":
                    continue  # An older topic revision blocks nothing; queued already moves.
                if operation in {"worktree.create", "agent.switch"}:
                    continue  # Their own coordinators own them; `!go` never queues them.
                if (reason is None or reason in UNCHOSEN_HOLDS) and created >= cutoff:
                    resend.append(identity)
                else:
                    old = True
            if old:
                return "kept_old"
            changed = await session.execute(
                update(Binding)
                .where(
                    Binding.id == binding_id,
                    Binding.state == "active",
                    Binding.dispatch_paused.is_(True),
                    Binding.queue_revision == queue_revision,
                )
                .values(dispatch_paused=False, queue_revision=queue_revision + 1)
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                return "kept"
            if resend:
                await session.execute(
                    update(Action)
                    .where(Action.id.in_(resend), Action.state == "held")
                    .values(state="queued", version=Action.version + 1)
                )
                session.add(
                    AuditEvent(
                        actor="worker", event="queue_resumed_after_restart", object_id=binding_id
                    )
                )
            return "released"

    async def unseen_human_messages(
        self, binding_id: str, messages: list[dict[str, Any]], *, now: float | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        """Messages this consumer never captured, sent here while it was down.

        Returns the recent unedited ones (a proposal only: routing reads each one
        again) and how many others there are. Nothing here grants authority.
        """
        cutoff = (time.time() if now is None else now) - RESTART_RESEND_SECONDS
        candidates = [
            item
            for item in messages
            if isinstance(item, dict)
            and item.get("sender_id") != self.bot_user_id
            and type(item.get("id")) is int
            and item["id"] > 0
        ]
        if not candidates:
            return [], 0
        async with self.db.sessions() as session:
            seen = set(
                await session.scalars(
                    select(ZulipMessageIndex.message_id).where(
                        ZulipMessageIndex.realm_id == self.realm_id,
                        ZulipMessageIndex.message_id.in_([item["id"] for item in candidates]),
                    )
                )
            )
            binding = await session.get(Binding, binding_id)
        anchor = binding.anchor_message_id if binding is not None else None
        recent, older = [], 0
        for item in sorted(candidates, key=lambda m: m["id"]):
            if item["id"] in seen or anchor is not None and item["id"] <= anchor:
                continue
            stamp = item.get("timestamp")
            if (
                binding is not None
                and item.get("type") == "stream"
                and item.get("stream_id") == binding.channel_id
                and item.get("last_edit_timestamp") is None
                and isinstance(stamp, int | float)
                and not isinstance(stamp, bool)
                and math.isfinite(stamp)
                and stamp >= cutoff
            ):
                recent.append(item)
            else:
                older += 1
        return recent, older

    async def capture_missed(
        self, queue_id: str, messages: list[dict[str, Any]]
    ) -> tuple[str, ...]:
        """Record messages sent while Bridge was down as ordinary new receipts.

        Like a queue event, each is only a proposal: the normal routing reads the
        message again and checks it is the same unedited human message in a
        private channel, from someone allowed to operate the topic.
        """
        queue_id = queue_name(queue_id)
        frozen = strict_loads(checked_json({"messages": messages}))["messages"]
        saved = []
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            q = await session.get(ZulipQueue, self.source)
            if (
                q is None
                or q.queue_id != queue_id
                or q.state != "active"
                or q.enrolled_fencing != self.fence.fencing
            ):
                raise Conflict("zulip_queue_changed_before_capture")
            for item in frozen:
                mid = positive(item.get("id"))
                if await session.get(ZulipMessageIndex, (self.realm_id, mid)) is not None:
                    continue  # Already captured, maybe by the new queue itself.
                event = {
                    "id": event_number(MISSED_EVENT_BASE + mid),
                    "type": "message",
                    "message": {k: item[k] for k in MISSED_FIELDS if k in item},
                }
                source_id = digest({"queue": queue_id, "native_event_id": event["id"]})
                if await session.scalar(
                    select(InputEvent.id).where(
                        InputEvent.source == "zulip:" + self.source,
                        InputEvent.source_id == source_id,
                        InputEvent.revision == 0,
                    )
                ):
                    continue
                wire = await self.sanitize(session, event)
                if wire["type"] != "message":
                    continue
                payload = {
                    "format": "zulip-event-capture-v1",
                    "realm_id": self.realm_id,
                    "bot_user_id": self.bot_user_id,
                    "source": self.source,
                    "queue_id": queue_id,
                    "event_id": event["id"],
                    "capture_fencing": self.fence.fencing,
                    "raw_sha256": digest(event),
                    "wire": wire,
                    "missed_while_offline": True,
                }
                row = InputEvent(
                    id=uid(),
                    source="zulip:" + self.source,
                    source_id=source_id,
                    revision=0,
                    payload=payload,
                    payload_hash=digest(payload),
                    state="zulip_received",
                )
                session.add(row)
                await session.flush()
                await self.apply_index(session, wire, row.id)
                saved.append(row.id)
        return tuple(saved)

    async def enroll(
        self, queue_id: str, last_event_id: int, *, recovery_run_id: str | None = None
    ) -> int:
        queue_id = queue_name(queue_id)
        last_event_id = event_number(last_event_id, watermark=True)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            if recovery_run_id is not None:
                from jt_oz_bridge.services.zulip_gap_recovery import require_epoch

                await require_epoch(session, self, recovery_run_id)
            current = await session.get(ZulipQueue, self.source)
            if current:
                if current.queue_id == queue_id:
                    if current.enrolled_fencing != self.fence.fencing or current.state != "active":
                        raise Conflict("zulip_queue_requires_fresh_registration")
                    return current.generation  # Never rewind a committed cursor.
                if recovery_run_id is None:
                    await self.pause(session, reason="queue_registered")
                current.queue_id = queue_id
                current.event_id = last_event_id
                current.enrolled_fencing = self.fence.fencing
                current.generation += 1
                current.state = "active"
                current.updated_at = time.time()
                return current.generation
            session.add(
                ZulipQueue(
                    source=self.source,
                    realm_id=self.realm_id,
                    bot_user_id=self.bot_user_id,
                    queue_id=queue_id,
                    event_id=last_event_id,
                    enrolled_fencing=self.fence.fencing,
                    generation=1,
                    state="active",
                )
            )
            return 1

    async def expire(self, queue_id: str, *, recovery_run_id: str | None = None) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            q = await session.get(ZulipQueue, self.source)
            if q is None or q.queue_id != queue_id:
                raise Conflict("zulip_queue_changed")
            if recovery_run_id is None:
                await self.pause(session, reason="queue_expired")
            else:
                from jt_oz_bridge.services.zulip_gap_recovery import require_epoch

                await require_epoch(session, self, recovery_run_id)
            q.state = "expired"
            q.updated_at = time.time()

    async def cursor(self, queue_id: str) -> int:
        async with self.db.sessions() as session:
            q = await session.get(ZulipQueue, self.source)
        if (
            q is None
            or q.queue_id != queue_id
            or q.state != "active"
            or q.enrolled_fencing != self.fence.fencing
        ):
            raise Conflict("zulip_queue_not_current")
        return q.event_id

    async def expected_channel(self, realm: str, message_id: int) -> int | None:
        if realm != self.realm_id:
            return None
        message_id = positive(message_id)
        async with self.db.sessions() as session:
            r = await session.get(ZulipMessageIndex, (realm, message_id))
        if (
            r is None
            or r.source != self.source
            or r.state != "live"
            or r.channel_id not in self.channel_ids
        ):
            return None
        return r.channel_id

    async def sanitize(self, session: AsyncSession, event: dict[str, Any]) -> dict[str, Any]:
        kind = event.get("type")
        eid = event_number(event.get("id"))
        if not isinstance(kind, str) or not 1 <= len(kind) <= 128:
            raise ValueError("invalid_zulip_event_kind")
        if kind == "message":
            m = event.get("message")
            if not isinstance(m, dict):
                raise ValueError("invalid_zulip_message_event")
            if m.get("type") not in {"stream", "private"}:
                raise ValueError("invalid_zulip_message_type")
            if m["type"] == "stream":
                positive(m.get("stream_id"))
            if (
                m.get("type") != "stream"
                or m.get("stream_id") not in self.channel_ids
                or type(m.get("stream_id")) is not int
            ):
                return {"id": eid, "type": "ignored", "reason": "outside_enrolled_channel"}
            positive(m.get("id"))
            positive(m.get("sender_id"))
            if not isinstance(m.get("subject"), str) or not isinstance(m.get("content"), str):
                raise ValueError("invalid_zulip_message_source")
            if m.get("content_type") != "text/x-markdown":
                raise ValueError("zulip_raw_markdown_event_required")
            return event
        if kind in {"delete_message", "update_message"}:
            ids = event.get("message_ids")
            if ids is None:
                ids = [event.get("message_id")]
            if not isinstance(ids, list) or not 1 <= len(ids) <= 1000:
                raise ValueError("invalid_zulip_changed_message_ids")
            ids = [positive(x) for x in ids]
            if len(set(ids)) != len(ids):
                raise ValueError("duplicate_zulip_changed_message_id")
            rows = list(
                (
                    await session.scalars(
                        select(ZulipMessageIndex).where(
                            ZulipMessageIndex.realm_id == self.realm_id,
                            ZulipMessageIndex.source == self.source,
                            ZulipMessageIndex.message_id.in_(ids),
                        )
                    )
                ).all()
            )
            known = sorted(r.message_id for r in rows if r.channel_id in self.channel_ids)
            if not known:
                return {"id": eid, "type": "ignored", "reason": "unknown_changed_source"}
            # Retain only lifecycle metadata; edits never supply a new prompt.
            safe = {
                k: event[k]
                for k in [
                    "new_stream_id",
                    "stream_id",
                    "orig_subject",
                    "subject",
                    "orig_topic",
                    "topic",
                    "propagate_mode",
                    "edit_timestamp",
                ]
                if k in event
            }
            return {"id": eid, "type": kind, "message_ids": known, **safe}
        if kind in ACCOUNT_EVENTS:
            op = event.get("op") if isinstance(event.get("op"), str) else None
            if display_only(kind, op, event):
                return {"id": eid, "type": "ignored", "reason": "display_only_change"}
            ours = None
            if kind in {"stream", "subscription"}:
                named = event_channels(event)
                if named is not None:
                    ours = sorted(named & self.channel_ids)
                    if not ours:
                        return {"id": eid, "type": "ignored", "reason": "outside_enrolled_channel"}
            # No realm directory/person/email payload is retained. Without the
            # channels a change names, every topic pauses, as for people and the realm.
            return {
                "id": eid,
                "type": kind,
                "op": op if op in EVENT_OPS else "other",
                "channel_id": ours[0] if ours is not None and len(ours) == 1 else None,
                "channel_ids": ours,
            }
        return {"id": eid, "type": "ignored", "reason": "non_command_event"}

    async def apply_index(
        self, session: AsyncSession, wire: dict[str, Any], receipt_id: str
    ) -> None:
        kind = wire["type"]
        if kind == "message":
            m = wire["message"]
            key = (self.realm_id, m["id"])
            current = await session.get(ZulipMessageIndex, key)
            if current is not None:
                if current.source != self.source:
                    raise Conflict("zulip_source_index_changed")
                # A late create cannot resurrect a tombstone or moved source.
                if current.channel_id != m["stream_id"]:
                    current.state = "unresolved"
                    current.version += 1
                return
            binding = await session.scalar(
                select(Binding.id).where(
                    Binding.realm_id == self.realm_id,
                    Binding.state == "active",
                    Binding.topic_key == topic_key(self.realm_id, m["stream_id"], m["subject"]),
                )
            )
            session.add(
                ZulipMessageIndex(
                    realm_id=self.realm_id,
                    message_id=m["id"],
                    source=self.source,
                    channel_id=m["stream_id"],
                    binding_id=binding,
                    state="live",
                    input_event_id=receipt_id,
                    version=1,
                )
            )
        elif kind in {"delete_message", "update_message"}:
            affected = set()
            for mid in wire["message_ids"]:
                row = await session.get(ZulipMessageIndex, (self.realm_id, mid))
                if row is None or row.source != self.source:
                    raise Conflict("zulip_source_index_changed")
                moved = kind == "update_message" and (
                    "new_stream_id" in wire and wire["new_stream_id"] != row.channel_id
                )
                topic_changed = kind == "update_message" and any(
                    k in wire for k in ["orig_subject", "orig_topic"]
                )
                if kind == "delete_message":
                    row.state = "deleted"
                elif moved:
                    row.state = "unresolved"
                row.version += 1
                row.input_event_id = receipt_id
                if (kind == "delete_message" or moved or topic_changed) and row.binding_id:
                    affected.add(row.binding_id)
            await self.pause(session, bindings=affected, reason=kind)
        elif kind in ACCOUNT_EVENTS:
            # Receipts captured before channel_ids existed name at most one channel.
            ours = wire.get("channel_ids")
            channel = wire.get("channel_id")
            if ours is None and channel is not None:
                ours = [channel]
            await self.pause(
                session,
                channels=set(ours) if ours is not None else None,
                reason=f"{kind}:{wire.get('op', 'other')}",
            )

    async def capture(
        self, queue_id: str, events: list[dict[str, Any]], *, recovery_run_id: str | None = None
    ) -> tuple[str, ...]:
        queue_id = queue_name(queue_id)
        if not isinstance(events, list) or len(events) > 1000:
            raise ValueError("zulip_event_batch_capacity")
        frozen = strict_loads(checked_json({"events": events}))["events"]
        if len(checked_json({"events": frozen})) > 8 * 1024 * 1024:
            raise ValueError("zulip_event_batch_too_large")
        numbers = [event_number(e.get("id")) for e in frozen if isinstance(e, dict)]
        if len(numbers) != len(frozen) or any(
            b <= a for a, b in zip(numbers, numbers[1:], strict=False)
        ):
            raise ValueError("zulip_event_batch_order_invalid")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            q = await session.get(ZulipQueue, self.source)
            if (
                q is None
                or q.queue_id != queue_id
                or q.state != "active"
                or q.enrolled_fencing != self.fence.fencing
            ):
                raise Conflict("zulip_queue_changed_before_capture")
            if recovery_run_id is not None:
                from jt_oz_bridge.services.zulip_gap_recovery import require_epoch

                await require_epoch(session, self, recovery_run_id)
            saved = []
            for event in frozen:
                eid = event["id"]
                source_id = digest({"queue": queue_id, "native_event_id": eid})
                row = await session.scalar(
                    select(InputEvent).where(
                        InputEvent.source == "zulip:" + self.source,
                        InputEvent.source_id == source_id,
                        InputEvent.revision == 0,
                    )
                )
                if eid <= q.event_id:
                    if row is None:
                        raise Conflict("zulip_unseen_event_before_checkpoint")
                    # Apply no lifecycle update on a replay. The immutable raw
                    # receipt is checked without reinterpreting a newer index.
                    if row.payload_compacted_at is not None:
                        self.validate_receipt(row)
                        original = row.payload["scope"]
                    else:
                        if digest(row.payload) != row.payload_hash:
                            raise Conflict("zulip_event_receipt_changed")
                        original = row.payload
                    if original.get("raw_sha256") is not None and original.get(
                        "raw_sha256"
                    ) != digest(event):
                        raise Conflict("zulip_event_identity_reused")
                    saved.append(row.id)
                    continue
                wire = await self.sanitize(session, event)
                if len(checked_json(wire)) > 2 * 1024 * 1024:
                    raise ValueError("zulip_scoped_event_too_large")
                payload = {
                    "format": "zulip-event-capture-v1",
                    "realm_id": self.realm_id,
                    "bot_user_id": self.bot_user_id,
                    "source": self.source,
                    "queue_id": queue_id,
                    "event_id": eid,
                    "capture_fencing": self.fence.fencing,
                    "raw_sha256": None if wire["type"] == "ignored" else digest(event),
                    "wire": wire,
                }
                if recovery_run_id is not None:
                    payload["recovery_run_id"] = recovery_run_id
                row = InputEvent(
                    id=uid(),
                    source="zulip:" + self.source,
                    source_id=source_id,
                    revision=0,
                    payload=payload,
                    payload_hash=digest(payload),
                    state="zulip_received",
                )
                session.add(row)
                await session.flush()
                await self.apply_index(session, wire, row.id)
                saved.append(row.id)
                q.event_id = eid
                q.updated_at = time.time()
            return tuple(saved)

    async def claim(self, receipt_id: str) -> ZulipEventClaim | None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            r = await session.get(InputEvent, receipt_id)
            if r is None or r.source != "zulip:" + self.source:
                raise Conflict("zulip_receipt_scope_missing")
            self.validate_receipt(r)
            if r.state not in {"zulip_received", "zulip_processing", "zulip_deferred"}:
                return None
            retry = await session.get(ZulipReceiptRetry, r.id)
            if r.state == "zulip_deferred":
                if retry is None or type(r.payload.get("defer_recovered")) is not bool:
                    raise Conflict("zulip_retry_schedule_changed")
                if retry.retry_at > time.time():
                    return None
            queue = await session.get(ZulipQueue, self.source)
            moved = (
                r.payload["capture_fencing"] != self.fence.fencing
                or queue is None
                or queue.state != "active"
                or queue.queue_id != r.payload["queue_id"]
            )
            recovered = (
                r.payload.get("recovery_run_id") is not None
                or r.state == "zulip_processing"
                or r.state == "zulip_deferred"
                and r.payload["defer_recovered"]
                # A recent message the previous process never began is not
                # recovered intent; one it had started stays recovered.
                or moved
                and not (
                    r.state == "zulip_received"
                    and queue is not None
                    and queue.state == "active"
                    and self.carried_over(r.payload)
                )
            )
            if (
                r.state == "zulip_processing"
                and r.payload.get("processing_fencing") == self.fence.fencing
            ):
                return None
            payload = {**r.payload, "processing_fencing": self.fence.fencing}
            r.payload, r.payload_hash = payload, digest(payload)
            r.state = "zulip_processing"
            if retry is not None:
                await session.delete(retry)
            return ZulipEventClaim(
                r.id,
                strict_loads(checked_json(r.payload["wire"])),
                recovered,
                saved_route(r.payload),
                r.payload.get("recovery_run_id"),
            )

    async def waiting(self, receipt_id: str) -> bool:
        async with self.db.sessions() as session:
            row = await session.get(ZulipReceiptRetry, receipt_id)
            if row is None:
                return False
            event = await session.get(InputEvent, receipt_id)
            if event is None or event.state != "zulip_deferred" or not math.isfinite(row.retry_at):
                raise Conflict("zulip_retry_schedule_changed")
            self.validate_receipt(event)
            return row.retry_at > time.time()

    async def record_route(self, receipt_id: str, routed: RoutedInput) -> None:
        value = ROUTED.dump_python(routed, mode="json")
        saved_route({"routed_reply": value})
        if len(checked_json(value)) > 2 * 1024 * 1024:
            raise Conflict("zulip_saved_route_capacity")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            r = await session.get(InputEvent, receipt_id)
            if (
                r is None
                or r.source != "zulip:" + self.source
                or r.state != "zulip_processing"
                or r.payload.get("processing_fencing") != self.fence.fencing
            ):
                raise Conflict("zulip_processing_receipt_changed")
            self.validate_receipt(r)
            previous = saved_route(r.payload)
            if previous is not None:
                if previous != routed:
                    raise Conflict("zulip_saved_route_changed")
                return  # Keep the exact existing legacy representation immutable.
            r.payload = {**r.payload, "routed_reply": value}
            r.payload_hash = digest(r.payload)

    async def defer(self, receipt_id: str, retry_after: float, *, recovered: bool) -> None:
        if type(recovered) is not bool:
            raise ValueError("zulip_retry_recovery_flag_required")
        delay = max(1, min(3600, retry_after)) if math.isfinite(retry_after) else 60
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            r = await session.get(InputEvent, receipt_id)
            if (
                r is None
                or r.source != "zulip:" + self.source
                or r.state != "zulip_processing"
                or r.payload.get("processing_fencing") != self.fence.fencing
            ):
                raise Conflict("zulip_processing_receipt_changed")
            self.validate_receipt(r)
            r.payload = {**r.payload, "defer_recovered": recovered}
            r.payload_hash = digest(r.payload)
            r.state = "zulip_deferred"
            session.add(ZulipReceiptRetry(input_event_id=r.id, retry_at=time.time() + delay))

    async def finish(
        self, receipt_id: str, *, state: str = "done", routed: RoutedInput | None = None
    ) -> None:
        if state not in {"done", "ignored", "held"}:
            raise ValueError("invalid_zulip_receipt_result")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            r = await session.get(InputEvent, receipt_id)
            if (
                r is None
                or r.source != "zulip:" + self.source
                or r.state != "zulip_processing"
                or r.payload.get("processing_fencing") != self.fence.fencing
            ):
                raise Conflict("zulip_processing_receipt_changed")
            self.validate_receipt(r)
            r.state = "zulip_" + state
            if routed is not None:
                saved_route({"routed_reply": ROUTED.dump_python(routed, mode="json")})
                previous = saved_route(r.payload)
                if previous is not None and previous != routed:
                    raise Conflict("zulip_saved_route_changed")
            if routed and routed.binding_id and r.payload["wire"]["type"] == "message":
                mid = r.payload["wire"]["message"]["id"]
                index = await session.get(ZulipMessageIndex, (self.realm_id, mid))
                binding = await session.get(Binding, routed.binding_id)
                if (
                    index is not None
                    and index.state == "live"
                    and binding is not None
                    and binding.realm_id == self.realm_id
                    and binding.channel_id == index.channel_id
                    and binding.revision == routed.binding_revision
                ):
                    index.binding_id = binding.id
