"""Resolve short controls only from this actor's already delivered discovery reply."""

from dataclasses import dataclass
from typing import Literal, Self

from pydantic import Field, StrictBool, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox, DiscoveryPayload
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch


class DiscoveryShortcuts(ControlModel):
    inactive: StrictBool = False
    choose: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{32}$")
    confirm: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{32}$")
    next_token: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{32}$")
    next_command: Literal["backends", "projects", "sessions"] | None = None

    @model_validator(mode="after")
    def valid_links(self) -> Self:
        if (self.next_token is None) != (self.next_command is None):
            raise ValueError("shortcut_page_pair_required")
        active = any((self.choose, self.confirm, self.next_token))
        if active == self.inactive or (
            self.confirm is not None and (self.choose is not None or self.next_token is not None)
        ):
            raise ValueError("shortcut_reply_kind_invalid")
        return self


@dataclass(frozen=True)
class ShortcutObservation:
    links: DiscoveryShortcuts
    sources: tuple[HumanMessage, ...]
    fingerprint: str


class DiscoveryShortcutService:
    def __init__(self, db: Database, reader: SourceReader) -> None:
        self.db, self.reader = db, reader

    async def _menu_candidate(
        self, session: AsyncSession, message: HumanMessage
    ) -> tuple[DiscoveryShortcuts, DiscoveryTarget, list[Delivery]]:
        # Resolve by posted Bot message order, never creation/completion timing.
        # A Bot post made after the human shortcut cannot become its new target
        # during retry or restart. Bounded local reads do not spend API requests.
        candidate = None
        identities = list(
            await session.scalars(
                select(CommandReceipt.id)
                .where(
                    CommandReceipt.realm_id == message.realm_id,
                    CommandReceipt.channel_id == message.channel_id,
                    CommandReceipt.topic == message.topic,
                    CommandReceipt.binding_id.is_(None),
                    CommandReceipt.message_id < message.message_id,
                    CommandReceipt.state == "completed",
                )
                .order_by(CommandReceipt.message_id.desc())
                .limit(100)
            )
        )
        for identity in identities:
            receipt = await session.get(CommandReceipt, identity)
            if receipt is None:
                raise Conflict("shortcut_receipt_changed")
            raw = receipt.response
            if raw.get("origin") != "discovery" or raw.get("shortcuts") is None:
                continue
            links = DiscoveryShortcuts.model_validate(raw["shortcuts"])
            target = DiscoveryTarget.model_validate(raw["target"])
            source = target.source
            if (
                source.realm_id,
                source.author_id,
                source.channel_id,
                source.topic,
                source.message_id,
                digest(source.model_dump(mode="json")),
            ) != (
                message.realm_id,
                receipt.actor_id,
                message.channel_id,
                message.topic,
                receipt.message_id,
                receipt.source_hash,
            ):
                raise Conflict("shortcut_saved_source_changed")
            batch = await session.scalar(
                select(DeliveryBatch).where(
                    DeliveryBatch.dedupe_key
                    == DiscoveryOutbox.dedupe("command:" + receipt.id, target)
                )
            )

            if batch is None:
                raise Conflict("shortcut_menu_delivery_not_yet_certain")
            rows = list(
                await session.scalars(
                    select(Delivery)
                    .where(Delivery.batch_id == batch.id)
                    .order_by(Delivery.batch_index)
                    .limit(100)
                )
            )
            if (
                not 1 <= batch.page_count <= 100
                or len(rows) != batch.page_count
                or batch.destination_id != str(target.id)
            ):
                raise Conflict("shortcut_delivery_batch_changed")
            if [row.batch_index for row in rows] != list(range(batch.page_count)):
                raise Conflict("shortcut_delivery_page_order_changed")
            # A later response must never capture an instruction already
            # present on the server. Prove that *every* page was invisible
            # before this Human: authenticated posted IDs are strictly
            # later, or the durable worker has never claimed a POST. Claim
            # increments attempts and marks sending before transport I/O.
            # Mixing a previously visible page with later/unattempted pages
            # is ambiguous and must not silently choose an older menu.
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
                # Token expiry/use is not evidence of when an uncertain
                # reply became visible; never use it to select an older
                # menu after sending/ambiguous/partial delivery.
                raise Conflict("shortcut_menu_delivery_not_yet_certain")
            posted = max(row.posted_message_id or 0 for row in rows)
            if candidate is not None and posted == candidate[0]:
                raise Conflict("shortcut_delivery_order_ambiguous")
            if candidate is None or posted > candidate[0]:
                candidate = (posted, links, target, rows)
        if candidate is None:
            raise Conflict("shortcut_no_delivered_menu")
        _, links, target, rows = candidate
        if target.source.author_id != message.author_id:
            raise Conflict("shortcut_latest_visible_menu_belongs_to_other_actor")
        return links, target, rows

    async def latest(self, message: HumanMessage) -> DiscoveryShortcuts:
        async with self.db.sessions() as session:
            links, target, rows = await self._menu_candidate(session, message)
        if await self.reader.read(message.realm_id, target.source.message_id) != target.source:
            raise Conflict("shortcut_original_human_source_changed")
        for row in rows:
            payload = DiscoveryPayload.model_validate(row.payload)
            if (
                digest(row.payload) != row.payload_hash
                or row.destination_id != str(target.id)
                or str(payload.authorization_id) != str(target.id)
                or payload.authorization_hash != digest(target.model_dump(mode="json"))
                or payload.marker != "jtoz:" + row.id
            ):
                raise Conflict("shortcut_delivery_payload_changed")
            shown = await self.reader.read(message.realm_id, row.posted_message_id or 0)
            if (
                shown.realm_id,
                shown.channel_id,
                shown.topic,
                shown.author_id,
                shown.text,
                shown.is_bot,
                shown.deleted,
            ) != (
                message.realm_id,
                message.channel_id,
                message.topic,
                payload.bot_user_id,
                payload.content,
                True,
                False,
            ):
                raise Conflict("shortcut_visible_bot_reply_changed")
        return links

    async def observation_sources(self, message: HumanMessage) -> ShortcutObservation:
        """SQL-only expected data; only a later closed observer authenticates it."""
        async with self.db.sessions() as session:
            return await self._observation_in_session(session, message)

    async def _observation_in_session(
        self, session: AsyncSession, message: HumanMessage
    ) -> ShortcutObservation:
        links, target, rows = await self._menu_candidate(session, message)
        sources = [target.source]
        facts = []
        for row in rows:
            payload = DiscoveryPayload.model_validate(row.payload)
            if (
                digest(row.payload) != row.payload_hash
                or row.destination_id != str(target.id)
                or str(payload.authorization_id) != str(target.id)
                or payload.authorization_hash != digest(target.model_dump(mode="json"))
                or payload.marker != "jtoz:" + row.id
                or payload.realm_id != message.realm_id
                or payload.channel_id != message.channel_id
                or payload.topic != message.topic
            ):
                raise Conflict("shortcut_delivery_payload_changed")
            sources.append(
                HumanMessage(
                    realm_id=message.realm_id,
                    channel_id=message.channel_id,
                    topic=message.topic,
                    message_id=row.posted_message_id or 0,
                    revision=0,
                    author_id=payload.bot_user_id,
                    text=payload.content,
                    is_bot=True,
                    deleted=False,
                )
            )
            facts.append(
                {
                    "id": row.id,
                    "version": row.version,
                    "state": row.state,
                    "posted": row.posted_message_id,
                    "hash": row.payload_hash,
                    "batch": row.batch_id,
                    "index": row.batch_index,
                }
            )
        return ShortcutObservation(
            links,
            tuple(sources),
            digest(
                {
                    "links": links.model_dump(mode="json"),
                    "target": target.model_dump(mode="json"),
                    "pages": facts,
                }
            ),
        )

    async def validate_observation_in_session(
        self, session: AsyncSession, message: HumanMessage, expected: ShortcutObservation
    ) -> None:
        if await self._observation_in_session(session, message) != expected:
            raise Conflict("shortcut_selection_changed_before_commit")

    async def token(self, message: HumanMessage, kind: Literal["choose", "confirm"]) -> str:
        value = getattr(await self.latest(message), kind)
        if value is None:
            raise Conflict("shortcut_current_reply_has_no_" + kind)
        return str(value)
