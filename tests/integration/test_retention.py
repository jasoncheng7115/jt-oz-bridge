"""Fenced local retention with synthetic rows/HTTP; no upstream cleanup or live certificate."""

import asyncio
import copy
import time

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.config import Retention
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import CURRENT_REVISION
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import (
    Action,
    AuditEvent,
    Checkpoint,
    Delivery,
    InputEvent,
    WorkerLease,
)
from tests.integration.test_consumer_runtime import setup as runtime_setup
from tests.integration.test_consumer_runtime import until
from tests.support import bound

DAY = 86400
MARKER = "PRIVATE_RETIRED_BODY_195"


async def executor(db, *, clock=None, batch_size=100):
    from jt_oz_bridge.services.retention import RetentionExecutor

    fencing = await DurableStore(db).acquire_lease("retention-test", ttl=120)
    assert fencing
    return RetentionExecutor(
        db,
        ConsumerFence("retention-test", fencing),
        Retention(),
        clock=clock or time.time,
        batch_size=batch_size,
    )


async def sweep_twice(retention):
    # A bounded scan wraps its ephemeral cursor, never holds a DB cursor/lock
    # between sweeps. No test changes SQL lease timers to make a proof pass.
    first = await retention.sweep()
    second = await retention.sweep()
    return first, second


async def delivered(db, binding, *, age=8, updated_age=None, key="standalone"):
    payload = {"body": MARKER, "binding": binding.id}
    row = Delivery(
        dedupe_key=key,
        binding_id=binding.id,
        binding_revision=binding.revision,
        payload=payload,
        payload_hash=digest(payload),
        state="delivered",
        posted_message_id=1001,
        created_at=time.time() - age * DAY,
        updated_at=time.time() - (age if updated_age is None else updated_age) * DAY,
    )
    async with db.sessions.begin() as session:
        session.add(row)
        await session.flush()
        identity = row.id
    return identity


@pytest.mark.parametrize("kind", ["payload", "audit"])
async def test_runtime_executes_configured_retention_without_upstream_work(db, kind):
    # Synthetic Human event through the real service pipeline, not a live Human.
    pipeline, server, native, _, binding, _ = await runtime_setup(db)
    identity = await delivered(db, binding)
    async with db.sessions.begin() as session:
        event = AuditEvent(
            actor="synthetic",
            event="ordinary_finalized",
            object_id="old",
            created_at=time.time() - 91 * DAY,
        )
        session.add(event)
        await session.flush()
        audit_id = event.id
    runtime = pipeline.runtime()
    await runtime.start()
    try:

        async def retired():
            assert runtime.healthy
            async with db.sessions() as session:
                if kind == "payload":
                    return MARKER not in str((await session.get(Delivery, identity)).payload)
                return await session.get(AuditEvent, audit_id) is None

        await until(retired)
        async with db.sessions() as session:
            if kind == "payload":
                row = await session.get(Delivery, identity)
                assert MARKER not in str(row.payload)
                assert row.payload["format"] == "bridge-retired-payload-v1"
            else:
                assert await session.get(AuditEvent, audit_id) is None
        assert not native.submitted and not server.posts and not server.edits
    finally:
        await runtime.close()


async def test_active_binding_terminal_payload_compacts_but_identity_and_hash_survive(db):
    _, binding, _, _ = await bound(db)
    identity = await delivered(db, binding)
    async with db.sessions() as session:
        before = await session.get(Delivery, identity)
        checksum, key = before.payload_hash, before.dedupe_key
        binding_fields = dict((await session.get(Binding, binding.id)).__dict__)
        binding_fields.pop("_sa_instance_state")
    retention = await executor(db)
    result = await retention.sweep()
    assert result.compacted == 1
    async with db.sessions() as session:
        row = await session.get(Delivery, identity)
        assert row.state == "delivered" and row.posted_message_id == 1001
        assert row.payload_hash == checksum and row.dedupe_key == key
        assert row.payload_compacted_at > 0 and MARKER not in str(row.payload)
        after = dict((await session.get(Binding, binding.id)).__dict__)
        after.pop("_sa_instance_state")
        assert after == binding_fields and after["state"] == "active"


@pytest.mark.parametrize("updated_age", [0, None])
async def test_old_created_delivery_needs_trustworthy_final_updated_time(db, updated_age):
    _, binding, _, _ = await bound(db)
    identity = await delivered(db, binding, age=100, updated_age=0)
    if updated_age is None:
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery).where(Delivery.id == identity).values(updated_at=0)
            )
    retention = await executor(db)
    await retention.sweep()
    async with db.sessions() as session:
        assert (await session.get(Delivery, identity)).payload["body"] == MARKER


@pytest.mark.parametrize("state", ["queued", "held", "ambiguous", "dispatching", "running"])
async def test_pending_and_ambiguous_actions_and_dependent_delivery_never_retire(db, state):
    _, binding, _, _ = await bound(db)
    identity = await delivered(db, binding)
    store = DurableStore(db)
    action_id = await store.enqueue(
        "pending", binding.id, binding.revision, 7, {"operation": "prompt", "text": MARKER}
    )
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action_id)
            .values(state=state, created_at=time.time() - 200 * DAY)
        )
    retention = await executor(db)
    await retention.sweep()
    async with db.sessions() as session:
        action, delivery = (
            await session.get(Action, action_id),
            await session.get(Delivery, identity),
        )
        assert action.payload["text"] == delivery.payload["body"] == MARKER
        assert action.retention_observed_at is None and action.state == state


async def test_terminal_action_age_is_observed_not_created_and_resets_on_change(db):
    _, binding, _, _ = await bound(db)
    store = DurableStore(db)
    payload = {"operation": "prompt", "text": MARKER}
    action_id = await store.enqueue("terminal", binding.id, binding.revision, 7, payload)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action_id)
            .values(state="completed", created_at=time.time() - 200 * DAY)
        )
    clock = [time.time()]
    retention = await executor(db, clock=lambda: clock[0])
    assert (await retention.sweep()).observed == 1
    clock[0] += 6 * DAY
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action_id)
            .values(version=2, status_reason="late_local_finalization")
        )
    await sweep_twice(retention)
    clock[0] += 6 * DAY
    await sweep_twice(retention)
    async with db.sessions() as session:
        assert (await session.get(Action, action_id)).payload["text"] == MARKER
    clock[0] += 2 * DAY
    await sweep_twice(retention)
    async with db.sessions() as session:
        row = await session.get(Action, action_id)
        assert row.payload["format"] == "bridge-retired-payload-v1"
        assert row.state == "completed" and row.upstream_id is None
    # Keeping the original operation digest prevents old dedupe keys from
    # recreating a prompt after its body was retired.
    assert await store.enqueue("terminal", binding.id, binding.revision, 7, payload) == action_id
    async with db.sessions() as session:
        assert (await session.get(Action, action_id)).state == "completed"


async def test_explicit_resource_reference_preserves_terminal_action(db):
    from jt_oz_bridge.storage.resource_models import ResourceResultRecord

    _, binding, _, _ = await bound(db)
    action_id = await DurableStore(db).enqueue(
        "proof", binding.id, binding.revision, 7, {"operation": "prompt", "text": MARKER}
    )
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == action_id).values(state="completed")
        )
        session.add(
            ResourceResultRecord(
                action_id=action_id,
                ordinal=1,
                binding_id=binding.id,
                binding_revision=1,
                source_hash="a" * 64,
            )
        )
    clock = [time.time()]
    retention = await executor(db, clock=lambda: clock[0])
    await retention.sweep()
    clock[0] += 100 * DAY
    await sweep_twice(retention)
    async with db.sessions() as session:
        row = await session.get(Action, action_id)
        assert row.payload["text"] == MARKER and row.retention_observed_at is None
        assert await session.get(ResourceResultRecord, action_id)


async def test_scope_chain_and_pending_audit_survive_ordinary_metadata_retirement(db):
    from jt_oz_bridge.services.binding_scope_history import EVENT

    _, binding, _, _ = await bound(db)
    pending_id = await DurableStore(db).enqueue(
        "audit-pending", binding.id, 1, 7, {"operation": "prompt", "text": MARKER}
    )
    async with db.sessions.begin() as session:
        events = [
            AuditEvent(
                actor="synthetic",
                event=event,
                object_id=identity,
                created_at=time.time() - 100 * DAY,
            )
            for event, identity in [
                (EVENT, binding.id),
                ("pending", pending_id),
                ("completed", binding.id),
                ("database_restored_held", "restore"),
                ("database_restore_review_completed", "restore"),
            ]
        ]
        session.add_all(events)
        await session.flush()
        ids = [row.id for row in events]
    retention = await executor(db)
    result = await retention.sweep()
    assert result.audit_deleted == 1
    async with db.sessions() as session:
        assert await session.get(AuditEvent, ids[0])
        assert await session.get(AuditEvent, ids[1])
        assert await session.get(AuditEvent, ids[2]) is None
        assert await session.get(AuditEvent, ids[3]) and await session.get(AuditEvent, ids[4])


@pytest.mark.parametrize("failure", ["expiry", "cancel"])
async def test_final_fence_failure_rolls_back_payload_audit_and_scan_cursor(db, failure):
    _, binding, _, _ = await bound(db)
    identity = await delivered(db, binding)
    retention = await executor(db)
    original = retention.fence
    async with db.sessions.begin() as session:
        event = AuditEvent(
            actor="s", event="old", object_id="orphan", created_at=time.time() - 100 * DAY
        )
        session.add(event)
        await session.flush()
        audit_id = event.id

    class LateFailure:
        calls = 0

        async def lock(self, session):
            self.calls += 1
            if self.calls == 2:
                if failure == "cancel":
                    raise asyncio.CancelledError()
                await session.execute(
                    update(WorkerLease).where(WorkerLease.role == "consumer").values(expires_at=0)
                )
            await original.lock(session)

    retention.fence = LateFailure()
    with pytest.raises(asyncio.CancelledError if failure == "cancel" else Conflict):
        await retention.sweep()
    assert retention._cursors == {} and retention._start == 0
    async with db.sessions() as session:
        assert (await session.get(Delivery, identity)).payload["body"] == MARKER
        assert await session.get(AuditEvent, audit_id)


async def test_batch_bound_and_cursor_do_not_starve_later_eligible_payloads(db):
    _, binding, _, _ = await bound(db)
    ids = [await delivered(db, binding, key="row" + str(i)) for i in range(7)]
    retention = await executor(db, batch_size=2)
    totals = []
    for _ in range(5):
        result = await retention.sweep()
        totals.append(result.compacted)
        assert result.scanned <= 2  # One total budget, including audit.
    assert sum(totals) == 7 and max(totals) <= 2
    async with db.sessions() as session:
        assert all(
            [(await session.get(Delivery, identity)).payload_compacted_at for identity in ids]
        )


async def test_zulip_terminal_tombstone_keeps_checkpoint_exact_replay_and_raw_mismatch_rejection(
    db,
):
    from tests.integration.test_zulip_consumer import setup

    consumer, server, _, _ = await setup(db)
    try:
        event = server.event("!oz help")
        assert await consumer.poll() == ("reply",)
        async with db.sessions() as session:
            row = (await session.scalars(select(InputEvent))).one()
            identity, checksum = row.id, row.payload_hash
            checkpoints = [
                (c.source, c.queue_id, c.event_id)
                for c in (await session.scalars(select(Checkpoint))).all()
            ]
        from jt_oz_bridge.services.retention import RetentionExecutor

        clock = [time.time()]
        retention = RetentionExecutor(
            db, consumer.journal.fence, Retention(), clock=lambda: clock[0]
        )
        await retention.sweep()
        clock[0] += 8 * DAY
        await sweep_twice(retention)
        async with db.sessions() as session:
            row = await session.get(InputEvent, identity)
            assert row.payload_hash == checksum and MARKER not in str(row.payload)
            assert row.payload_compacted_at and "wire" not in row.payload
            consumer.journal.validate_receipt(row)
        assert await consumer.journal.capture("native-queue", [event]) == (identity,)
        assert await consumer.journal.claim(identity) is None
        changed = copy.deepcopy(event)
        changed["message"]["content"] = "CHANGED"
        with pytest.raises(Conflict):
            await consumer.journal.capture("native-queue", [changed])
        async with db.sessions() as session:
            assert checkpoints == [
                (c.source, c.queue_id, c.event_id)
                for c in (await session.scalars(select(Checkpoint))).all()
            ]
            assert len((await session.scalars(select(InputEvent))).all()) == 1
    finally:
        await consumer.close()


async def test_retired_command_dedupes_without_reissuing_response_or_action(db):
    from jt_oz_bridge.services.command_receipts import CommandInbox
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from tests.integration.test_router import message

    retention = await executor(db)
    inbox = CommandInbox(db, retention.fence.holder, retention.fence.fencing)
    source = message("!oz help", 203)
    claim = await inbox.claim(source, "help")
    await inbox.finish(claim, {"text": MARKER})
    async with db.sessions.begin() as session:
        await session.execute(
            update(CommandReceipt)
            .where(CommandReceipt.id == claim.id)
            .values(updated_at=time.time() - 8 * DAY)
        )
    assert (await retention.sweep()).compacted == 1
    replay = await inbox.claim(source, "help")
    assert replay.id == claim.id and replay.status == "held" and replay.response == {}
    async with db.sessions() as session:
        row = await session.get(CommandReceipt, claim.id)
        assert row.state == "completed" and row.payload_compacted_at
        assert not list(await session.scalars(select(Action)))


async def test_expired_tokens_compact_context_without_becoming_reusable(db):
    from jt_oz_bridge.services.tokens import TokenService, token_hash
    from jt_oz_bridge.storage.control_models import ControlToken

    _, binding, _, _ = await bound(db)
    retention = await executor(db)
    tokens = TokenService(db, fence=retention.fence)
    token = await tokens.issue(
        "choose", "realm", 7, {"private": MARKER}, binding_id=binding.id, binding_revision=1
    )
    live = await tokens.issue("choose", "realm", 7, {"private": "LIVE"})
    async with db.sessions.begin() as session:
        await session.execute(
            update(ControlToken)
            .where(ControlToken.token_hash == token_hash(token))
            .values(expires_at=time.time() - 8 * DAY, used=True)
        )
    assert (await retention.sweep()).compacted == 1
    with pytest.raises(Conflict):
        await tokens.inspect(token, "choose", "realm", 7)
    assert (await tokens.inspect(live, "choose", "realm", 7)).context == {"private": "LIVE"}
    async with db.sessions() as session:
        row = await session.get(ControlToken, token_hash(token))
        assert row.used and row.context_hash == digest({"private": MARKER})
        assert MARKER not in str(row.context) and row.payload_compacted_at


async def test_expired_destination_copies_retire_and_fail_closed_on_load(db):
    from jt_oz_bridge.services.retention import RetentionExecutor
    from jt_oz_bridge.storage.output_models import OutputDestination
    from tests.integration.test_output_destinations import prepared

    destinations, _, target = await prepared(db)
    identity = await destinations.save("retention-expired", target)
    # Use the same real fence and an advanced retention clock. Production time
    # is not changed and the load must fail because its authorization is retired.
    retention = RetentionExecutor(
        db, destinations.fence, Retention(), clock=lambda: time.time() + 9 * DAY
    )
    assert (await retention.sweep()).compacted == 1
    with pytest.raises(Conflict, match="retired"):
        await destinations.load(identity)
    async with db.sessions() as session:
        row = await session.get(OutputDestination, str(identity))
        assert row.authorization_hash == digest(target.model_dump(mode="json"))
        assert "PRIVATE_DESTINATION_MARKER" not in str(row.authorization)


async def test_migration_32_to_33_adds_only_nullable_columns_and_keeps_ciphertext(tmp_path):
    import os
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect, text

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.storage import database as database_module
    from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
    from jt_oz_bridge.storage.database import Database, migrate
    from jt_oz_bridge.storage.payload_keys import verify_keys

    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    database = Database("sqlite+aiosqlite:///" + str(tmp_path / "legacy32.db"), cipher=cipher)

    def legacy(connection):
        verify_keys(connection, initialize=True)
        cfg = Config()
        cfg.set_main_option(
            "script_location", str(Path(database_module.__file__).parent / "migrations")
        )
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "0032_registration_extensions")
        verify_keys(connection, initialize=True)
        return set(inspect(connection).get_table_names())

    try:
        async with database.engine.begin() as connection:
            tables = await connection.run_sync(legacy)
            ciphertext = cipher.seal(
                checked_json({"text": MARKER}), payload_scope("input_events", "payload")
            )
            await connection.execute(
                text(
                    "INSERT INTO input_events(id,source,source_id,revision,payload_hash,payload,state,created_at) VALUES('old','synthetic','id',0,:hash,:payload,'held',1)"
                ),
                {"hash": digest({"text": MARKER}), "payload": ciphertext},
            )
            await connection.execute(
                text(
                    "INSERT INTO checkpoints(source,queue_id,event_id,updated_at) VALUES('synthetic','old-queue',123,1)"
                )
            )
            # Real predecessor DDL with populated synthetic unresolved rows;
            # no head stamping/create_all and no assumption of an empty service.
            for index, state in enumerate(("held", "held", "held", "ambiguous", "ambiguous")):
                await connection.execute(
                    Action.__table__.insert().values(
                        id="legacy-action-" + str(index),
                        dedupe_key="legacy-" + str(index),
                        binding_id="legacy-binding",
                        binding_revision=1,
                        actor_id=7,
                        operation_digest=digest({"text": MARKER}),
                        payload={"text": MARKER},
                        admission={},
                        native_result={},
                        state=state,
                        created_at=1,
                    )
                )
            await connection.execute(
                WorkerLease.__table__.insert(),
                [
                    {"role": "consumer", "holder": "old-stopped", "expires_at": 0, "fencing": 12},
                    {"role": "helper", "holder": "old-helper", "expires_at": 0, "fencing": 4},
                ],
            )
            previous = {}
            for table in sorted(tables - {"alembic_version"}):
                columns = [
                    row[1]
                    for row in (
                        await connection.execute(text('PRAGMA table_info("' + table + '")'))
                    ).all()
                ]
                rows = (
                    await connection.execute(
                        text(
                            "SELECT "
                            + ",".join('"' + name + '"' for name in columns)
                            + ' FROM "'
                            + table
                            + '"'
                        )
                    )
                ).all()
                previous[table] = (columns, sorted([tuple(row) for row in rows], key=repr))
        assert not await database.ready()
        await migrate(database.engine)
        assert await database.ready()
        async with database.engine.connect() as connection:
            added = {
                "zulip_recovery_checkpoints",
                "zulip_recovery_items",
                "session_configuration_heads",
                "prompt_schedules",
            }
            assert (
                await connection.run_sync(lambda c: set(inspect(c).get_table_names()))
                == tables | added
            )
            for name in added:
                assert await connection.scalar(text('SELECT count(*) FROM "' + name + '"')) == 0
            for table, (columns, before) in previous.items():
                after = sorted(
                    [
                        tuple(row)
                        for row in (
                            await connection.execute(
                                text(
                                    "SELECT "
                                    + ",".join('"' + name + '"' for name in columns)
                                    + ' FROM "'
                                    + table
                                    + '"'
                                )
                            )
                        ).all()
                    ],
                    key=repr,
                )
                if table == "worker_leases":
                    # Normal public migrate takes/releases just the consumer
                    # lease once; all other roles and every business cell stay.
                    actual = {row[0]: row for row in after}
                    assert actual["helper"] == ("helper", "old-helper", 0.0, 4)
                    consumer = actual["consumer"]
                    assert consumer[1] != "old-stopped" and consumer[2:] == (0.0, 13)
                    assert set(actual) == {"helper", "consumer"}
                else:
                    assert after == before, table
            assert (
                await connection.scalar(text("SELECT payload FROM input_events WHERE id='old'"))
                == ciphertext
            )
            assert tuple(
                (
                    await connection.execute(
                        text(
                            "SELECT state,payload_compacted_at,retention_observed_at,retention_fingerprint FROM input_events WHERE id='old'"
                        )
                    )
                ).one()
            ) == ("held", None, None, None)
            assert (
                await connection.execute(text("SELECT queue_id,event_id FROM checkpoints"))
            ).one() == ("old-queue", 123)
            assert (
                await connection.scalar(text("SELECT version_num FROM alembic_version"))
                == CURRENT_REVISION
            )
        # No implicit rollback/downgrade or retention occurs during migration.
        async with database.sessions() as session:
            assert (await session.get(InputEvent, "old")).payload == {"text": MARKER}
    finally:
        await database.close()


async def test_compacted_payload_backup_restore_preserves_tombstone_and_held_work(tmp_path):
    # Reuse the existing real backup/restore fixture construction, not a second
    # archive format. All bytes are isolated ownDB/artifacts only.
    import os

    from jt_oz_bridge.config import Settings
    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.services.backups import BackupService, restore_sqlite_backup
    from jt_oz_bridge.storage.database import Database, migrate

    live = tmp_path / "source"
    live.mkdir(mode=0o700)
    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    database = Database("sqlite+aiosqlite:///" + str(live / "bridge.db"), cipher=cipher)
    try:
        await migrate(database.engine)
        (live / "bridge.db").chmod(0o600)
        _, binding, _, _ = await bound(database)
        identity = await delivered(database, binding)
        retention = await executor(database)
        await retention.sweep()
        held_id = await DurableStore(database).enqueue(
            "still-held", binding.id, 1, 7, {"operation": "prompt", "text": MARKER}, recovered=True
        )
        settings = Settings.model_validate(
            {
                "app": {"state_dir": str(live), "environment": "test"},
                "retention": {"reserve_free_disk_bytes": 1},
                "admin": {"enabled": False},
                "security": {"secret_key_ref": "env:JTOZ_SYNTHETIC_RETENTION_KEY"},
            }
        )
        archive = tmp_path / "archive"
        await DurableStore(database).release_lease(retention.fence.holder, retention.fence.fencing)
        snapshot = await BackupService(database).create(archive, settings)
        restored_path = tmp_path / "restored"
        await restore_sqlite_backup(
            archive, restored_path, cipher, key_ref="env:JTOZ_SYNTHETIC_RETENTION_KEY"
        )
        restored = Database(
            "sqlite+aiosqlite:///" + str(restored_path / "bridge.db"), cipher=cipher
        )
        try:
            assert not await restored.ready()
            from jt_oz_bridge.config import load_settings

            safe = load_settings(restored_path / "restored-config.toml")
            await BackupService(restored).complete_review(snapshot["backup_id"], safe)
            assert await restored.ready()
            async with restored.sessions() as session:
                row = await session.get(Delivery, identity)
                assert (
                    row.payload_compacted_at
                    and row.payload["format"] == "bridge-retired-payload-v1"
                )
                held = await session.get(Action, held_id)
                assert held.state == "held" and held.payload["text"] == MARKER
                assert held.payload_compacted_at is None
        finally:
            await restored.close()
    finally:
        await database.close()


async def test_published_batch_dependency_retains_both_original_and_edit_payload(db):
    from jt_oz_bridge.services.retention import RetentionExecutor
    from tests.integration.test_batch_edits import batch
    from tests.integration.test_routed_output import setup

    outbox, binding, worker, _, chat = await setup(db)
    original = await batch(outbox, binding, "retention-original", MARKER)
    await worker.advance(original.deliveries[0])
    edited = await batch(
        outbox,
        binding,
        "retention-edit",
        "Updated " + MARKER,
        edit_of=original.deliveries[0],
        after_batch_id=original.id,
    )
    await worker.advance(edited.deliveries[0])
    async with db.sessions.begin() as session:
        await session.execute(update(Delivery).values(updated_at=time.time() - 8 * DAY))
    retention = RetentionExecutor(db, outbox.fence, Retention())
    assert (await retention.sweep()).compacted == 0
    async with db.sessions() as session:
        assert all(
            [
                not (await session.get(Delivery, identity)).payload_compacted_at
                for identity in original.deliveries + edited.deliveries
            ]
        )
    assert len(chat.messages) == 1 and len(chat.calls) == 2


@pytest.mark.parametrize(
    "state", ["zulip_received", "zulip_processing", "zulip_deferred", "zulip_held"]
)
async def test_pending_input_evidence_is_not_ttl_compacted(db, state):
    from jt_oz_bridge.services.retention import RetentionExecutor
    from tests.integration.test_zulip_consumer import setup

    consumer, server, _, _ = await setup(db)
    try:
        event = server.event("!oz help")
        identities = await consumer.journal.capture("native-queue", [event])
        async with db.sessions.begin() as session:
            row = await session.get(InputEvent, identities[0])
            row.state, row.created_at = state, time.time() - 100 * DAY
            original = copy.deepcopy(row.payload)
        retention = RetentionExecutor(
            db, consumer.journal.fence, Retention(), clock=lambda: time.time() + 200 * DAY
        )
        await retention.sweep()
        async with db.sessions() as session:
            row = await session.get(InputEvent, identities[0])
            assert (
                row.payload == original and row.state == state and row.payload_compacted_at is None
            )
    finally:
        await consumer.close()


async def test_real_queue_terminal_tombstone_dedupes_original_and_later_edit(db):
    from jt_oz_bridge.services.queue import QueueService
    from tests.integration.test_router import message

    bindings, binding, _, _ = await bound(db)
    clock = [time.time()]
    retention = await executor(db, clock=lambda: clock[0])
    queue = QueueService(bindings, fence=retention.fence)
    source = message(MARKER, 205)
    receipt = await queue.receive(binding.id, source)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == receipt.action_id).values(state="cancelled")
        )
    await retention.sweep()
    clock[0] += 8 * DAY
    await sweep_twice(retention)
    repeated = await queue.receive(binding.id, source)
    assert (
        repeated.action_id == receipt.action_id
        and repeated.state == "cancelled"
        and repeated.already_dispatched
    )
    with pytest.raises(Conflict, match="revision reused"):
        await queue.receive(binding.id, source.model_copy(update={"text": "substituted"}))
    edited = await queue.receive(
        binding.id, source.model_copy(update={"text": "later edit", "revision": 1})
    )
    assert edited == repeated
    async with db.sessions() as session:
        actions = list(await session.scalars(select(Action)))
        assert (
            len(actions) == 1
            and actions[0].state == "cancelled"
            and MARKER not in str(actions[0].payload)
        )


async def test_original_native_admission_is_not_retired_without_transcript_fk(db):
    # transcript.origin resolves original Native-owned user messages before it
    # has necessarily published a transcript FK; its admission is a live proof.
    _, binding, _, _ = await bound(db)
    action_id = await DurableStore(db).enqueue(
        "native-proof", binding.id, 1, 7, {"operation": "prompt", "text": MARKER}
    )
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action_id)
            .values(state="completed", owner="opencode", upstream_id="original-user-message")
        )
    retention = await executor(db, clock=lambda: time.time() + 365 * DAY)
    await retention.sweep()
    async with db.sessions() as session:
        row = await session.get(Action, action_id)
        assert row.payload["text"] == MARKER and row.retention_observed_at is None
        assert row.upstream_id == "original-user-message" and row.owner == "opencode"


async def test_scan_decrypts_one_candidate_at_a_time_not_a_payload_batch(db):
    _, binding, _, _ = await bound(db)
    for index in range(7):
        await delivered(db, binding, key="bounded-body-" + str(index))
    retention = await executor(db)
    original = retention._safe
    checked = []

    async def safe(session, kind, row, now, cutoff):
        if kind == "delivery":
            live = [value for value in session.identity_map.values() if isinstance(value, Delivery)]
            checked.append(len(live))
            assert len(live) == 1
        return await original(session, kind, row, now, cutoff)

    retention._safe = safe
    assert (await retention.sweep()).compacted == 7
    assert checked == [1] * 7


async def test_total_scan_budget_includes_audit_with_round_robin_progress(db):
    _, binding, _, _ = await bound(db)
    for index in range(9):
        await delivered(db, binding, key="budget" + str(index))
    async with db.sessions.begin() as session:
        session.add_all(
            [
                AuditEvent(
                    actor="synthetic",
                    event="ordinary",
                    object_id="old" + str(i),
                    created_at=time.time() - 100 * DAY,
                )
                for i in range(9)
            ]
        )
    retention = await executor(db, batch_size=2)
    total_payload = total_audit = 0
    for _ in range(20):
        result = await retention.sweep()
        assert result.scanned <= 2
        total_payload += result.compacted
        total_audit += result.audit_deleted
    assert total_payload == total_audit == 9


async def test_expiry_metadata_cannot_retire_still_current_output_authorization(db):
    from jt_oz_bridge.services.retention import RetentionExecutor
    from jt_oz_bridge.storage.output_models import OutputDestination
    from tests.integration.test_output_destinations import prepared

    destinations, _, target = await prepared(db)
    identity = await destinations.save("tampered-expiry", target)
    async with db.sessions.begin() as session:
        await session.execute(
            update(OutputDestination)
            .where(OutputDestination.id == identity)
            .values(expires_at=time.time() - 8 * DAY)
        )
    retention = RetentionExecutor(db, destinations.fence, Retention())
    with pytest.raises(Conflict, match="metadata_changed"):
        await retention.sweep()
    async with db.sessions() as session:
        row = await session.get(OutputDestination, str(identity))
        assert (
            row.authorization == target.model_dump(mode="json") and row.payload_compacted_at is None
        )


@pytest.mark.parametrize("evidence", ["admission", "native_result", "upstream_id"])
async def test_unknown_legacy_execution_evidence_survives_even_bridge_owner_metadata(db, evidence):
    _, binding, _, _ = await bound(db)
    identity = await DurableStore(db).enqueue(
        "legacy-evidence", binding.id, 1, 7, {"operation": "prompt", "text": MARKER}
    )
    value = (
        "original-native-correlation"
        if evidence == "upstream_id"
        else {"unknown_original_proof": MARKER}
    )
    async with db.sessions.begin() as session:
        row = await session.get(Action, identity)
        row.state = "completed"
        setattr(row, evidence, value)
    retention = await executor(db, clock=lambda: time.time() + 365 * DAY)
    await retention.sweep()
    async with db.sessions() as session:
        row = await session.get(Action, identity)
        assert row.owner == "bridge" and row.payload["text"] == MARKER
        assert getattr(row, evidence) == value and row.retention_observed_at is None
        assert row.payload_compacted_at is None
