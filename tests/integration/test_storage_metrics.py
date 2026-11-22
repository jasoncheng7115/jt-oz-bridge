"""OwnDB/storage/process gauges on /metrics; synthetic rows, not live or Human evidence."""

import asyncio
import re
import time
from unittest.mock import AsyncMock

from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from jt_oz_bridge.security.redaction import redact_text, redactions_total
from jt_oz_bridge.services import runtime_enrollment as module
from jt_oz_bridge.services.live_capture import LiveEventJournal
from jt_oz_bridge.services.live_retention import FeedGenerations
from jt_oz_bridge.services.runtime import RuntimeResource, RuntimeWorker, SupervisedRuntime
from jt_oz_bridge.storage.artifact_models import ArtifactBudget
from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.durable import DurableStore, digest
from jt_oz_bridge.storage.live_models import NativeFeedReceipt
from jt_oz_bridge.storage.models import Delivery, InputEvent
from jt_oz_bridge.storage.workspace_models import WorkspaceBudget
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem
from tests.integration.test_runtime_enrollment import enrolled as enrolled
from tests.integration.test_web import _metrics_client, _metrics_values
from tests.support import bound

PRIVATE = "PRIVATE-TOPIC-person@example.invalid"
LINE = re.compile(r'^(jt_oz_bridge_[a-z0-9_]+)(\{(state|table)="[a-z_]+"\})? [0-9.]+$')


async def populate(db):
    _, binding, _, _ = await bound(db)
    now = time.time()
    body = {"text": PRIVATE}
    async with db.sessions.begin() as session:
        for index, (state, age, source) in enumerate(
            (
                ("zulip_received", 30, "zulip:" + PRIVATE),
                ("zulip_deferred", 10, "zulip:" + PRIVATE),
                ("zulip_done", 900, "zulip:" + PRIVATE),
                ("zulip_recovery_partial", 5, "zulip-recovery:" + PRIVATE),
            )
        ):
            session.add(
                InputEvent(
                    id=f"input-{index}",
                    source=source,
                    source_id=PRIVATE + str(index),
                    revision=1,
                    payload=body,
                    payload_hash=digest(body),
                    state=state,
                    created_at=now - age,
                )
            )
        await session.flush()
        session.add(
            ZulipRecoveryItem(
                source=PRIVATE,
                message_id=1,
                source_revision=1,
                input_event_id="input-0",
                run_id="input-3",
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=7,
                state="held",
            )
        )
        for index, (state, age, attempts) in enumerate(
            (("pending", 60, 2), ("held", 20, 0), ("delivered", 999, 3))
        ):
            session.add(
                Delivery(
                    dedupe_key=PRIVATE + str(index),
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    payload=body,
                    payload_hash=digest(body),
                    state=state,
                    attempts=attempts,
                    created_at=now - age,
                )
            )
        session.add(
            PendingInteraction(
                identity_key="a" * 64,
                binding_id=binding.id,
                binding_revision=binding.revision,
                snapshot=body,
                snapshot_hash=digest(body),
                expires_at=now + 600,
                created_at=now - 90,
            )
        )
        session.add(
            NativeFeedReceipt(
                key="b" * 64, connection_epoch="c" * 64, payload=body, payload_hash=digest(body)
            )
        )
        session.add(ArtifactBudget(id="artifact", reserved_bytes=4096, object_count=1))
        session.add(WorkspaceBudget(id="workspace", reserved_bytes=512, object_count=1))


def assert_fixed_shape(result):
    for line in result.text.splitlines():
        assert line.startswith("# TYPE jt_oz_bridge_") or LINE.match(line), line
    assert PRIVATE not in result.text and "example" not in result.text


async def test_storage_gauges_report_ages_backlog_quotas_and_files_without_labels(db):
    async with _metrics_client(db) as client:
        await populate(db)  # After startup recovery, which owns its own transitions.
        statements = []

        def observe(_conn, _cursor, statement, _params, _context, _many):
            statements.append(statement)

        event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
        try:
            result = await client.get("/metrics")
        finally:
            event.remove(db.engine.sync_engine, "before_cursor_execute", observe)
    assert result.status_code == 200
    assert_fixed_shape(result)
    values = _metrics_values(result)
    assert values["jt_oz_bridge_storage_sample_available"] == 1
    assert values["jt_oz_bridge_input_events_pending"] == 2
    assert 29 <= values["jt_oz_bridge_input_event_lag_seconds"] < 60
    assert values['jt_oz_bridge_outbox_deliveries{state="pending"}'] == 1
    assert values['jt_oz_bridge_outbox_deliveries{state="held"}'] == 1
    assert 59 <= values["jt_oz_bridge_outbox_oldest_age_seconds"] < 120
    assert values["jt_oz_bridge_outbox_retrying_deliveries"] == 1
    assert values["jt_oz_bridge_pending_interactions"] == 1
    assert 89 <= values["jt_oz_bridge_pending_interaction_oldest_age_seconds"] < 150
    assert values['jt_oz_bridge_recovery_runs{state="partial"}'] == 1
    assert values['jt_oz_bridge_recovery_items{state="held"}'] == 1
    assert values['jt_oz_bridge_live_source_rows{table="native_feed_receipts"}'] == 1
    assert values["jt_oz_bridge_artifact_reserved_bytes"] == 4096
    assert values["jt_oz_bridge_workspace_reserved_bytes"] == 512
    assert values["jt_oz_bridge_database_file_bytes"] > 0
    assert values["jt_oz_bridge_database_free_bytes"] >= 0
    assert "jt_oz_bridge_redactions_total" in values
    # Aggregates over plain columns only; no encrypted cell is selected.
    assert all(s.lstrip().upper().startswith(("SELECT", "PRAGMA", "BEGIN")) for s in statements)
    assert not any(
        column in s
        for s in statements
        for column in ("payload,", ".payload ", "snapshot", "binding_scopes", "source_id")
    )


async def test_failed_storage_sample_is_omitted_not_reported_as_zero(db):
    async with _metrics_client(db) as client:
        await populate(db)

        def fail(_conn, _cursor, sql, _params, _context, _many):
            if "zulip_receipt_retries" in sql:
                raise OperationalError("PRIVATE-SQL", {}, RuntimeError(PRIVATE))

        event.listen(db.engine.sync_engine, "before_cursor_execute", fail)
        try:
            result = await client.get("/metrics")
        finally:
            event.remove(db.engine.sync_engine, "before_cursor_execute", fail)
    # Core lease/backlog observations stay available and keep their status.
    assert result.status_code == 200
    values = _metrics_values(result)
    assert values["jt_oz_bridge_storage_sample_available"] == 0
    assert values["jt_oz_bridge_database_sample_available"] == 1
    assert not any("outbox" in key or "lag" in key for key in values)
    assert "PRIVATE" not in result.text


async def test_process_counters_are_allowlisted_and_redactions_count(db):
    before = redactions_total()
    assert redact_text("token sk-" + "a" * 40)[1] >= 1
    assert redactions_total() > before
    reported = {
        "zulip_rate_limited_total": 3,
        "zulip_requests_deferred_total": 4,
        "native_feeds_connected": 1,
        "live_receipts_deleted_total": 250,
        "live_captures_deleted_total": 2,
        'zulip_rate_limited_total{topic="' + PRIVATE + '"}': 9,
        PRIVATE: 1,
    }

    async def worker():
        await asyncio.Event().wait()

    def factory(database, fence):
        return SupervisedRuntime(
            database,
            fence,
            (RuntimeResource("synthetic-test-resource", AsyncMock(), AsyncMock()),),
            (RuntimeWorker("native-dispatch", worker),),
            metrics=lambda: reported,
        )

    async with _metrics_client(db, runtime_factory=factory) as client:
        values = _metrics_values(await client.get("/metrics"))
        assert values["jt_oz_bridge_zulip_rate_limited_total"] == 3
        assert values["jt_oz_bridge_zulip_requests_deferred_total"] == 4
        assert values["jt_oz_bridge_native_feeds_connected"] == 1
        assert values["jt_oz_bridge_live_receipts_deleted_total"] == 250
        assert values["jt_oz_bridge_live_captures_deleted_total"] == 2
        assert values["jt_oz_bridge_redactions_total"] >= before + 1
        reported["zulip_rate_limited_total"] = -1  # Never a negative or invented count.
        reported["native_feeds_connected"] = True
        result = await client.get("/metrics")
        assert_fixed_shape(result)
        values = _metrics_values(result)
        assert "jt_oz_bridge_zulip_rate_limited_total" not in values
        assert "jt_oz_bridge_native_feeds_connected" not in values


async def test_real_pipeline_exposes_its_feed_generations_and_budget_counters(enrolled, db):
    value, sha = module.read_enrollment(enrolled.settings)
    store = DurableStore(db)
    epoch = await store.acquire_lease("metrics-compose", ttl=120)
    fence = module.ConsumerFence("metrics-compose", epoch)
    pipeline = module.build_pipeline(enrolled.settings, value, sha, db, fence)
    try:
        generations = pipeline.retention.live.generations
        assert isinstance(generations, FeedGenerations) and generations.feeds
        for feed in generations.feeds:
            assert isinstance(feed.receipts, LiveEventJournal) and feed.receipts.fence == fence
            assert feed.index is None  # Not started: no epoch exists to protect or delete.
        assert generations.epochs() == frozenset() and generations.connected() == 0
        budget = pipeline.scope.client.budget
        budget.rate_limited(30)
        assert pipeline.runtime().process_metrics() == {
            "zulip_rate_limited_total": 1,
            "zulip_requests_deferred_total": budget.deferred,
            "native_feeds_connected": 0,
            "live_receipts_deleted_total": 0,
            "live_captures_deleted_total": 0,
        }
    finally:
        await pipeline.scope.client.close()
        for backend in pipeline.backends.values():
            for resource in reversed(backend.resources):
                await resource.close()
        await store.release_lease("metrics-compose", epoch)
