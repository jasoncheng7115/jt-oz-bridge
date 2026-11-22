"""One-attempt discovery posts sharing global page eligibility and realm pacing."""

import time

from sqlalchemy import and_, select, update

from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway
from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader, ZulipSourceReader
from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.delivery import ChatGateway
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox, DiscoveryPayload
from jt_oz_bridge.services.outbox import OutboundPayload, QueuedBatch
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AuditEvent, Delivery, DeliveryBatch, DeliveryLane
from jt_oz_bridge.storage.output_models import OutputDestination
from jt_oz_bridge.storage.statements import insert


class DiscoveryDeliveryWorker(DeliveryWorker):
    def __init__(
        self,
        outbox: DiscoveryOutbox,
        gateway: ChatGateway,
        holder: str,
        fencing: int,
        *,
        minimum_interval: float = 1,
    ) -> None:
        if outbox.fence != ConsumerFence(holder, fencing):
            raise ValueError("discovery_delivery_consumer_mismatch")
        super().__init__(outbox, gateway, holder, fencing, minimum_interval=minimum_interval)
        self.scoped = outbox

    async def payload(self, saved: Delivery) -> DiscoveryPayload:
        if (
            saved.destination_id is None
            or saved.binding_id is not None
            or saved.binding_revision is not None
            or saved.batch_id is None
        ):
            raise Conflict("discovery_delivery_authorization_missing")
        payload = DiscoveryPayload.model_validate(saved.payload)
        if (
            saved.payload_hash != digest(saved.payload)
            or payload.marker != "jtoz:" + saved.id
            or payload.realm_id != self.gateway.realm_id
            or payload.bot_user_id != self.gateway.bot_user_id
            or str(payload.authorization_id) != saved.destination_id
        ):
            raise Conflict("discovery_delivery_identity_changed")
        target = await self.scoped.destinations.snapshot(saved.destination_id)
        if (
            payload.realm_id,
            payload.channel_id,
            payload.topic,
            payload.authorization_id,
            payload.authorization_hash,
        ) != (
            target.source.realm_id,
            target.source.channel_id,
            target.source.topic,
            target.id,
            digest(target.model_dump(mode="json")),
        ):
            raise Conflict("discovery_delivery_target_changed")
        reader = self._closed_reader()
        if reader is None:
            # Original custom readers/guards keep the public fresh authorization.
            batch = await self.scoped.scope_batch_by_id(saved.batch_id, target)
        else:
            batch = await self._observed_batch(saved, target, reader)
        if (
            saved.batch_index is None
            or not 0 <= saved.batch_index < len(batch.deliveries)
            or batch.deliveries[saved.batch_index] != saved.id
        ):
            raise Conflict("discovery_delivery_batch_changed")
        return payload

    def _closed_reader(self) -> ZulipSourceReader | None:
        reader = self.scoped.destinations.reader
        if (
            type(reader) is not ZulipSourceReader
            or type(reader.scope) is not ZulipScopeReader
            or self.scoped.destinations.discovery.bindings.audience is not reader.scope
            or type(self.gateway) is not ZulipGateway
        ):
            return None
        guard = reader.scope.client.verify_identity
        if not all(
            callable(getattr(type(guard), method, None)) for method in ("scope_reads", "scope_read")
        ):
            return None
        return reader

    async def _observed_batch(
        self, saved: Delivery, target: DiscoveryTarget, reader: ZulipSourceReader
    ) -> QueuedBatch:
        scope, gateway = reader.scope, self.gateway
        assert isinstance(gateway, ZulipGateway)
        client, guard, attestation = scope.client, scope.client.verify_identity, scope.enrolled
        qualification = getattr(guard, "qualification", None)

        def current() -> None:
            if (
                self.scoped.destinations.reader is not reader
                or reader.scope is not scope
                or self.scoped.destinations.discovery.bindings.audience is not scope
                or self.gateway is not gateway
                or gateway.client is not client
                or client.verify_identity is not guard
                or client.attestation is not attestation
                or scope.enrolled is not attestation
                or getattr(guard, "qualification", None) is not qualification
                or (gateway.realm_id, gateway.bot_user_id)
                != (attestation.realm_id, attestation.bot_user_id)
            ):
                raise Conflict("discovery_delivery_observer_identity_changed")

        async def read_only(audience: AudienceSnapshot) -> QueuedBatch:
            current()
            await self.scoped.destinations._authorize_observed(target, audience)
            async with self.db.sessions() as session:
                if not await session.scalar(select(and_(*self.scoped.destinations.guards(target)))):
                    raise AccessDenied("discovery_delivery_local_authorization_changed")
                parent = await session.get(DeliveryBatch, saved.batch_id)
                if parent is None:
                    raise Conflict("discovery_delivery_batch_missing")
                batch = await self.scoped.validated_scope_batch_in_session(session, target, parent)
            await self.scoped.destinations._authorize_observed(target, audience)
            current()
            return batch

        current()
        sources = (target.source,)
        observation = await scope.observe_sources(reader, sources, read_only=read_only)
        completed = scope.consume_observation(observation, reader, sources)
        current()
        if completed.sources != sources or completed.audience != target.audience:
            raise Conflict("discovery_delivery_observation_changed")
        return completed.value

    async def claim(self, saved: Delivery, payload: OutboundPayload) -> bool:
        if saved.destination_id is None or not isinstance(payload, DiscoveryPayload):
            return False
        # This is a local immutable snapshot read; no network call is awaited in
        # the write transaction below. All current local predicates are repeated.
        try:
            target = await self.scoped.destinations.snapshot(saved.destination_id)
        except (Conflict, ValueError):
            return False
        expected_hash = digest(target.model_dump(mode="json"))
        if (
            str(payload.authorization_id) != saved.destination_id
            or payload.authorization_hash != expected_hash
        ):
            return False
        now = time.time()
        async with self.db.sessions.begin() as session:
            try:
                await self.scoped.destinations.fence.lock(session)
            except Conflict:
                return False
            parent = await session.get(DeliveryBatch, saved.batch_id)
            if parent is None:
                return False
            batch = await self.scoped.validated_scope_batch_in_session(session, target, parent)
            if (
                saved.batch_index is None
                or not 0 <= saved.batch_index < len(batch.deliveries)
                or batch.deliveries[saved.batch_index] != saved.id
            ):
                return False
            now = time.time()
            await session.execute(
                insert(self.db, DeliveryLane)
                .values(realm_id=payload.realm_id)
                .on_conflict_do_nothing(index_elements=["realm_id"])
            )
            lane = await session.get(DeliveryLane, payload.realm_id)
            if (
                lane is None
                or lane.not_before > now
                or saved.retry_at > now
                or await session.scalar(self.next_pending(payload.realm_id, now)) != saved.id
            ):
                return False
            scope = (
                select(OutputDestination.id)
                .where(
                    OutputDestination.id == saved.destination_id,
                    OutputDestination.realm_id == payload.realm_id,
                    OutputDestination.state == "active",
                    OutputDestination.authorization_hash == expected_hash,
                    OutputDestination.expires_at == target.expires_at,
                    OutputDestination.expires_at > now,
                )
                .exists()
            )
            changed = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.destination_id == saved.destination_id,
                    Delivery.binding_id.is_(None),
                    Delivery.binding_revision.is_(None),
                    Delivery.state == "pending",
                    Delivery.version == saved.version,
                    Delivery.payload_hash == digest(saved.payload),
                    scope,
                    self.page_ready(),
                    self.lease(),
                    *self.scoped.destinations.guards(target),
                )
                .values(
                    state="sending",
                    version=Delivery.version + 1,
                    attempts=Delivery.attempts + 1,
                    status_reason=None,
                    updated_at=now,
                )
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                return False
            lane.not_before = now + max(self.interval, lane.backoff)
            session.add(
                AuditEvent(
                    actor="worker", event="discovery_delivery_dispatching", object_id=saved.id
                )
            )
            return True
