"""Complete Zulip audience reads per decision: bounded, never carried between decisions.

Real ownDB, synthetic Zulip and Native only. No Human, mobile or Native approval is produced.
"""

from sqlalchemy import update

from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.models import Delivery, Grant
from tests.integration.test_consumer_runtime import rows
from tests.integration.test_descendant_pending_notices import deliver_all, tree_pipeline
from tests.integration.test_permission_quick_replies import permission
from tests.integration.test_transcript_publisher import entry, setup, versions
from tests.support import REF


def count_reads(monkeypatch, audience):
    """Each call is one complete two-sided audience read of Zulip."""
    calls = []
    original = audience.inspect

    async def inspect(*args, **kwargs):
        calls.append(args)
        return await original(*args, **kwargs)

    monkeypatch.setattr(audience, "inspect", inspect)
    return calls


async def test_one_permission_notice_reads_zulip_in_full_twice_then_delivery_once(db, monkeypatch):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        reads = count_reads(monkeypatch, pipeline.bindings.audience)
        nodes[REF].add_request(permission())
        await pipeline.pending_notices_once()
        # One before the Native read, one before the outbox commit. It was four.
        assert len(reads) == 2
        assert len(await rows(db, PendingInteraction)) == 1
        await pipeline.pending_notices_once()
        assert len(reads) == 2  # Announced already: no new decision, no reads.
        deliveries = await deliver_all(pipeline, db)
        assert len(deliveries) == len(server.posts) == 1
        assert len(reads) == 3  # Delivery's own complete read before the POST.


async def test_a_grant_revoked_after_the_first_read_stops_the_notice_record(db, monkeypatch):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        nodes[REF].add_request(permission())
        original = nodes[REF].interaction

        async def revoke_then_read(*args):
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
            return await original(*args)

        monkeypatch.setattr(nodes[REF], "interaction", revoke_then_read)
        await pipeline.pending_notices_once()
        # The owned SQL re-check against the just-read audience refuses the record.
        assert await rows(db, PendingInteraction) == []
        assert await rows(db, Delivery) == []
        assert pipeline.deferred.get("pending_not_current_or_authorized") == 1
        assert server.posts == []


async def test_a_zulip_change_before_the_outbox_commit_is_seen_by_the_final_read(db, monkeypatch):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        nodes[REF].add_request(permission())
        original = pipeline.interactions.observe

        async def observe_then_open_channel(*args, **kwargs):
            identity = await original(*args, **kwargs)
            server.private = False  # The channel turns public after the first read.
            return identity

        monkeypatch.setattr(pipeline.interactions, "observe", observe_then_open_channel)
        await pipeline.pending_notices_once()
        assert len(await rows(db, PendingInteraction)) == 1
        assert await rows(db, Delivery) == []  # Nothing queued for the changed audience.
        assert pipeline.deferred.get("pending_not_current_or_authorized") == 1
        assert server.posts == []


async def test_a_new_scope_notice_reads_zulip_once_and_a_stored_one_still_twice(db, monkeypatch):
    publisher, collector, binding, reader, audience = await setup(db)
    state = await collector.collect(binding)
    reads = count_reads(monkeypatch, audience)
    batch = await publisher.scope_notice(state.key, "bootstrap")
    assert batch is not None and len(reads) == 1  # Was two: the plan it just wrote.
    assert len(await rows(db, Delivery)) == 1
    reads.clear()
    assert await publisher.scope_notice(state.key, "bootstrap") == batch
    assert len(reads) == 2  # A stored plan keeps its source and cached reads.
    reader.messages.insert(0, entry("new"))
    await collector.collect(binding)
    assert (await versions(db))[-1].id
