"""Synthetic durable Source/SQL quota and TTL evidence; no live Human or Native."""

import asyncio
import copy
import time

import pytest
from sqlalchemy import func, select, update

from jt_oz_bridge.config import Retention, Runtime
from jt_oz_bridge.services.recovery_quota import RecoveryCapacityExceeded, RecoveryLimits
from jt_oz_bridge.services.retention import RetentionExecutor
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, InputEvent, MaintenanceFlag
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem
from tests.integration.test_zulip_gap_recovery import (
    close,
    command,
    outage,
    preview,
    rows,
    setup_recovery,
)

DAY = 86400
MARKER = "PRIVATE_RECOVERY_PAYLOAD_ABC" * 80


async def drain(p):
    for _ in range(12):
        await p.deliver_once()
        await p.consumer.poll()


async def retire(p):
    clock = [time.time() + 8 * DAY]
    r = RetentionExecutor(p.db, p.fence, Retention(), batch_size=100, clock=lambda: clock[0])
    for _ in range(3):
        await r.sweep()
    # Source -> item -> review/run are dependency layers. Each newly safe
    # layer must independently retain the entire configured observation TTL.
    for _ in range(4):
        clock[0] += 8 * DAY
        for _ in range(5):
            await r.sweep()
    return r


@pytest.mark.asyncio
async def test_real_unqualified_history_compacts_but_highwater_and_duplicate_barrier_survive(db):
    p, s, n, b = await setup_recovery(db)
    try:
        # Synthetic rebind drift deliberately removes historic scope authority.
        async with db.sessions.begin() as session:
            current = await session.get(Binding, b.id)
            current.revision += 1
        s.message(MARKER, 101)
        s.expired_queues.add(p.consumer.queue_id)
        for _ in range(10):
            await p.consumer.poll()
        original = next(
            e
            for e in await rows(db, InputEvent)
            if e.source.startswith("zulip-history:") and e.payload["message"]["id"] == 101
        )
        cp = (await rows(db, ZulipRecoveryCheckpoint))[0]
        before = copy.deepcopy(cp.binding_scopes), cp.message_id, cp.run_id
        await retire(p)
        retired = next(e for e in await rows(db, InputEvent) if e.id == original.id)
        assert retired.payload_compacted_at and MARKER not in str(retired.payload)
        assert (
            retired.payload_hash == original.payload_hash
            and retired.source_id == original.source_id
        )
        current = (await rows(db, ZulipRecoveryCheckpoint))[0]
        assert (current.binding_scopes, current.message_id, current.run_id) == before
        run = next(e for e in await rows(db, InputEvent) if e.id == cp.run_id)
        async with db.sessions.begin() as session:
            await p.fence.lock(session)
            await p.consumer.recovery.capture_history(
                session, run.payload, s.messages[101], "a" * 64, 90, 101
            )
        assert not await rows(db, Action) and not n.submitted
        assert len([e for e in await rows(db, InputEvent) if e.id == original.id]) == 1
        async with db.sessions.begin() as session:
            changed = await session.get(InputEvent, original.id)
            body = copy.deepcopy(changed.payload)
            body["scope"]["message_id"] = 102
            changed.payload = body
        with pytest.raises(Conflict, match="retired_history_identity"):
            async with db.sessions.begin() as session:
                await p.fence.lock(session)
                await p.consumer.recovery.capture_history(
                    session, run.payload, s.messages[101], "a" * 64, 90, 101
                )
    finally:
        await close(p)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state", ["held", "queued", "admitted", "running", "dispatching", "ambiguous"]
)
async def test_pending_original_action_keeps_source_review_and_consumed_token(db, state):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s, MARKER)
        token = await preview(p, s)
        await command(p, s, "!oz recovery confirm " + token, 130)
        await drain(p)
        async with db.sessions.begin() as session:
            current = await session.get(Action, action.id)
            current.state = state
        sources = {
            e.id: (copy.deepcopy(e.payload), e.payload_hash)
            for e in await rows(db, InputEvent)
            if e.source.startswith(("zulip-history:", "zulip-recovery-review:"))
        }
        tokens = {
            t.token_hash: copy.deepcopy(t.context)
            for t in await rows(db, ControlToken)
            if t.kind == "zulip-recovery-review"
        }
        await retire(p)
        for e in await rows(db, InputEvent):
            if e.id in sources:
                assert (e.payload, e.payload_hash) == sources[
                    e.id
                ] and e.payload_compacted_at is None
        for t in await rows(db, ControlToken):
            if t.token_hash in tokens:
                assert t.context == tokens[t.token_hash] and t.payload_compacted_at is None
        assert not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_cancelled_unsent_item_retires_then_review_token_and_source_without_reauthorizing(db):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s, MARKER)
        token = await preview(p, s)
        await command(p, s, "!oz recovery confirm " + token, 130)
        assert await p.dispatcher.queue.cancel(action.id, "realm", 7)
        await drain(p)
        await retire(p)
        item = next(i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id)
        assert item.state == "retired" and item.action_id == action.id
        assert next(
            e for e in await rows(db, InputEvent) if e.id == item.input_event_id
        ).payload_compacted_at
        receipt = next(e for e in await rows(db, InputEvent) if e.id == item.review_receipt_id)
        assert (
            receipt.payload_compacted_at
            and next(
                t for t in await rows(db, ControlToken) if t.kind == "zulip-recovery-review"
            ).payload_compacted_at
        )
        assert await p.dispatcher.advance(action.id) == "cancelled" and not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
@pytest.mark.parametrize("evidence", ["admission", "native_result", "upstream_id", "restore"])
async def test_terminal_native_or_restore_evidence_is_not_retired(db, evidence):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s, MARKER)
        token = await preview(p, s)
        await command(p, s, "!oz recovery confirm " + token, 130)
        async with db.sessions.begin() as session:
            current = await session.get(Action, action.id)
            current.state = "completed"
            if evidence == "restore":
                session.add(MaintenanceFlag(name="restored_backup_review", pending=True))
            else:
                setattr(
                    current,
                    evidence,
                    "original" if evidence == "upstream_id" else {"original": True},
                )
        await drain(p)
        await retire(p)
        item = next(i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id)
        assert item.state != "retired"
        assert (
            next(
                e for e in await rows(db, InputEvent) if e.id == item.input_event_id
            ).payload_compacted_at
            is None
        )
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_epoch_limit_is_fatal_sticky_and_keeps_original_held_pause_and_receipts(db):
    p, s, n, b = await setup_recovery(db)
    try:
        p.consumer.recovery.limits = RecoveryLimits(epochs=2)
        action = await outage(p, s)
        original = copy.deepcopy(action.payload)
        epochs = [
            e.id for e in await rows(db, InputEvent) if e.source.startswith("zulip-recovery:")
        ]
        s.expired_queues.add(p.consumer.queue_id)
        with pytest.raises(RecoveryCapacityExceeded):
            await p.consumer.poll()
        assert [
            e.id for e in await rows(db, InputEvent) if e.source.startswith("zulip-recovery:")
        ] == epochs
        current = next(a for a in await rows(db, Action) if a.id == action.id)
        assert current.payload == original and current.state == "held"
        assert (await rows(db, Binding))[0].dispatch_paused and not n.submitted
        calls = list(s.calls)
        with pytest.raises(RecoveryCapacityExceeded):
            await p.consumer.poll()
        assert s.calls == calls
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_item_limit_keeps_captured_live_source_without_creating_untracked_action(db):
    p, s, n, b = await setup_recovery(db)
    try:
        p.consumer.recovery.limits = RecoveryLimits(items=1)
        action = await outage(p, s)
        mid = max(s.messages) + 1
        s.next_mid = mid + 1
        s.input("new paused prompt beyond capacity", mid)
        with pytest.raises(RecoveryCapacityExceeded):
            await p.consumer.poll()
        assert len(await rows(db, ZulipRecoveryItem)) == 1
        assert [a.id for a in await rows(db, Action)] == [action.id]
        captured = next(
            e
            for e in await rows(db, InputEvent)
            if e.source.startswith("zulip:")
            and e.payload.get("wire", {}).get("message", {}).get("id") == mid
        )
        assert (
            captured.state == "zulip_held"
            and captured.payload["wire"]["message"]["content"]
            == "new paused prompt beyond capacity"
        )
        current = (await rows(db, Binding))[0]
        with pytest.raises(Conflict, match="recovery_capacity"):
            await p.dispatcher.queue.resume(
                b.id, "realm", 7, current.revision, current.queue_revision
            )
        assert not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_ciphertext_capacity_counts_actual_blob_bytes_and_rolls_back_oversized_page(db):
    p, s, n, b = await setup_recovery(db)
    try:
        p.consumer.recovery.limits = RecoveryLimits(bytes=16384)
        s.message("民" * 5000, 101)
        s.expired_queues.add(p.consumer.queue_id)
        with pytest.raises(RecoveryCapacityExceeded):
            for _ in range(6):
                await p.consumer.poll()
        async with db.sessions() as session:
            actual = await session.scalar(
                select(func.sum(func.length(InputEvent.payload))).where(
                    InputEvent.source.in_(
                        [
                            prefix + p.consumer.journal.source
                            for prefix in (
                                "zulip-history:",
                                "zulip-recovery:",
                                "zulip-recovery-review:",
                            )
                        ]
                    )
                )
            )
        assert actual <= 16384 and not await rows(db, Action) and not n.submitted
        assert (await rows(db, ZulipRecoveryCheckpoint))[0].message_id == 90
    finally:
        await close(p)


@pytest.mark.parametrize(
    "value",
    [
        {"zulip_recovery_max_epochs": 129},
        {"zulip_recovery_max_items": 10001},
        {"zulip_recovery_max_bytes": 128 * 1024**2 + 1},
        {"zulip_recovery_max_epochs": True},
    ],
)
def test_capacity_config_cannot_raise_hard_bounds_or_use_bool(value):
    with pytest.raises(ValueError):
        Runtime.model_validate(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("correlation", ["artifact_source", "artifact_action", "file_transfer"])
async def test_file_correlations_without_foreign_keys_protect_cancelled_original_source(
    db, correlation
):
    from jt_oz_bridge.storage.artifact_models import Artifact
    from jt_oz_bridge.storage.file_transfer_models import FileTransfer

    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s, MARKER)
        assert await p.dispatcher.queue.cancel(action.id, "realm", 7)
        async with db.sessions.begin() as session:
            artifact = Artifact(
                binding_id=b.id,
                binding_revision=b.revision,
                realm_id="realm",
                project_id=b.project_id,
                actor_id=7,
                kind="generated",
                state="ready",
                reserved_bytes=1,
                key_id="test",
                expires_at=time.time() + 3600,
                source_message_id=101 if correlation == "artifact_source" else None,
                action_id=action.id if correlation == "artifact_action" else None,
            )
            session.add(artifact)
            await session.flush()
            if correlation == "file_transfer":
                payload = {"synthetic_provenance": True}
                session.add(
                    FileTransfer(
                        id="synthetic-file-provenance",
                        dedupe_key="d" * 64,
                        artifact_id=artifact.id,
                        binding_id=b.id,
                        binding_revision=b.revision,
                        realm_id="realm",
                        source_message_id=101,
                        actor_id=7,
                        state="delivered",
                        payload=payload,
                        payload_hash=digest(payload),
                    )
                )
        await drain(p)
        await retire(p)
        item = next(i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id)
        assert item.state != "retired"
        assert (
            next(
                e for e in await rows(db, InputEvent) if e.id == item.input_event_id
            ).payload_compacted_at
            is None
        )
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_quota_session_hooks_are_removed_and_original_insert_rolls_back_on_cancellation(db):
    import asyncio

    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence

    fencing = await DurableStore(db).acquire_lease("quota-cancel", ttl=120)
    fence = ConsumerFence("quota-cancel", fencing)
    entered = asyncio.Event()
    listeners = []

    async def writer():
        async with db.sessions.begin() as session:
            await fence.lock(session)
            before = len(list(session.sync_session.dispatch.before_flush))
            try:
                with RecoveryLimits().watch(session, "synthetic"):
                    value = {"test": "real encrypted storage, no Source authority"}
                    session.add(
                        InputEvent(
                            id="quota-cancelled",
                            source="zulip-history:synthetic",
                            source_id="original",
                            revision=0,
                            payload=value,
                            payload_hash=digest(value),
                            state="zulip_history_unqualified",
                        )
                    )
                    await session.flush()
                    entered.set()
                    await asyncio.Event().wait()
            finally:
                listeners.append((before, len(list(session.sync_session.dispatch.before_flush))))

    task = asyncio.create_task(writer())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert listeners == [(0, 0)]
    assert not await rows(db, InputEvent)


@pytest.mark.asyncio
async def test_populated_recovery_backup_held_restore_preserves_ciphertexts_and_needs_new_human_review(
    db, tmp_path, tmp_path_factory
):
    import sqlite3
    import tomllib
    from contextlib import closing
    from types import SimpleNamespace

    import httpx

    from jt_oz_bridge.adapters.zulip.client import ZulipClient
    from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader
    from jt_oz_bridge.config import Settings
    from jt_oz_bridge.services.backups import BackupService, restore_sqlite_backup
    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
    from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
    from jt_oz_bridge.services.zulip_recovery_guards import verify_review
    from jt_oz_bridge.storage.database import Database
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence
    from tests.integration.test_zulip_gap_recovery import URL

    p, s, n, b = await setup_recovery(db)
    restored = q = None
    try:
        action = await outage(p, s, MARKER)
        token = await preview(p, s)
        await command(p, s, "!oz recovery confirm " + token, 130)
        await drain(p)
        await p.consumer.close()
        await DurableStore(db).release_lease(p.fence.holder, p.fence.fencing)
        live = tmp_path / "live-artifacts"
        live.mkdir(mode=0o700)
        settings = Settings.model_validate(
            {
                "app": {"state_dir": str(tmp_path), "environment": "test"},
                "runtime": {"zulip_recovery_enabled": True},
                "retention": {"reserve_free_disk_bytes": 1},
            }
        )
        # Only this owned fixture file; preserve the production private-file guard.
        from pathlib import Path

        await asyncio.to_thread(Path(db.engine.url.database).chmod, 0o600)
        # Archive/restore are outside the original live-state directory.
        outside = tmp_path_factory.mktemp("recovery-backup-outside")
        archive, target = outside / "backup", outside / "restored"
        manifest = await BackupService(db).create(archive, settings, artifacts=live)
        result = await restore_sqlite_backup(
            archive, target, db.cipher, key_ref="env:SYNTHETIC_RESTORE_KEY"
        )
        decoded = Settings.model_validate(
            tomllib.loads((target / "restored-config.toml").read_text())
        )
        assert not decoded.runtime.enabled and not decoded.runtime.zulip_recovery_enabled
        with (
            closing(sqlite3.connect(str(archive / "bridge.sqlite"))) as before,
            closing(sqlite3.connect(str(target / "bridge.db"))) as after,
        ):
            for table in (
                "zulip_recovery_items",
                "zulip_recovery_checkpoints",
                "input_events",
                "control_tokens",
            ):
                assert (
                    before.execute('SELECT * FROM "' + table + '" ORDER BY 1').fetchall()
                    == after.execute('SELECT * FROM "' + table + '" ORDER BY 1').fetchall()
                )
        restored = Database("sqlite+aiosqlite:///" + str(target / "bridge.db"), cipher=db.cipher)
        assert not await restored.ready()
        await BackupService(restored).complete_review(result["backup_id"], decoded)
        assert await restored.ready()
        holder = "new-owner-after-authenticated-restore"
        fencing = await DurableStore(restored).acquire_lease(holder, ttl=120)
        assert fencing > p.fence.fencing
        client = ZulipClient(
            URL,
            "bot@example.invalid",
            "synthetic",
            attestation=p.scope.client.attestation,
            transport=httpx.MockTransport(s.handle),
        )
        client.verify_identity = ZulipRuntimeIdentity(
            client,
            SimpleNamespace(
                bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
            ),
        )
        q = ConsumerPipeline(
            restored,
            ConsumerFence(holder, fencing),
            ZulipScopeReader(client, channel_ids=frozenset({10})),
            p.backends,
            zulip_recovery_enabled=True,
            delivery_interval=0,
        )
        original = next(a for a in await rows(restored, Action) if a.id == action.id)
        current = (await rows(restored, Binding))[0]
        with pytest.raises(Conflict, match="scope_or_original_action_changed"):
            await verify_review(q.bindings, q.source, original, current, holder, fencing)
        assert original.payload == action.payload and original.state == "held"
        await q.consumer.start()
        for _ in range(8):
            await q.consumer.poll()
        mid = max(s.messages) + 1
        s.next_mid = mid + 1
        fresh = await preview(q, s, mid=mid)
        assert fresh and fresh != token
        mid = max(s.messages) + 1
        s.next_mid = mid + 1
        await command(q, s, "!oz recovery confirm " + fresh, mid)
        selected = next(
            i for i in await rows(restored, ZulipRecoveryItem) if i.action_id == action.id
        )
        proof = next(
            e for e in await rows(restored, InputEvent) if e.id == selected.review_receipt_id
        )
        assert proof.payload["holder"] == holder and proof.payload["fencing"] == fencing
        # The restore's original pause is absolute: a new review records its
        # Source, but does not silently override the operator's held policy.
        assert (await rows(restored, Binding))[0].dispatch_paused
        assert await q.dispatcher.advance(action.id) == "held" and not n.submitted
        assert manifest["source_changed"] is False
    finally:
        if q is not None:
            await close(q)
        await p.scope.client.close()
        if restored is not None:
            await restored.close()


@pytest.mark.asyncio
async def test_late_fence_loss_rolls_back_source_tombstone_and_item_retirement_together(db):
    from types import SimpleNamespace

    from jt_oz_bridge.storage.models import WorkerLease

    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s, MARKER)
        assert await p.dispatcher.queue.cancel(action.id, "realm", 7)
        await drain(p)
        now = time.time() + 8 * DAY
        r = RetentionExecutor(db, p.fence, Retention(), batch_size=100, clock=lambda: now)
        for _ in range(3):
            await r.sweep()
        item = next(i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id)
        original = next(e for e in await rows(db, InputEvent) if e.id == item.input_event_id)
        r.clock = lambda: now + 8 * DAY
        count = 0

        async def late_loss(session):
            nonlocal count
            count += 1
            if count == 2:
                await session.execute(
                    update(WorkerLease).where(WorkerLease.role == "consumer").values(expires_at=0)
                )
            await p.fence.lock(session)

        r.fence = SimpleNamespace(lock=late_loss)
        with pytest.raises(Conflict, match="consumer_lease_unavailable"):
            await r.sweep()
        current = next(e for e in await rows(db, InputEvent) if e.id == original.id)
        assert current.payload == original.payload and current.payload_compacted_at is None
        assert (
            next(i for i in await rows(db, ZulipRecoveryItem) if i.id == item.id).state
            == item.state
        )
    finally:
        await close(p)


@pytest.mark.asyncio
@pytest.mark.parametrize("error", ["encoder", "sql_integrity"])
async def test_quota_hooks_remove_on_flush_errors_and_preserve_original_row(db, error):
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence

    fencing = await DurableStore(db).acquire_lease("quota-flush", ttl=120)
    fence = ConsumerFence("quota-flush", fencing)
    original = {"original": "ciphertext preserved"}
    async with db.sessions.begin() as session:
        session.add(
            InputEvent(
                id="quota-original",
                source="zulip-history:synthetic",
                source_id="same-id",
                revision=0,
                payload=original,
                payload_hash=digest(original),
                state="zulip_history_unqualified",
            )
        )
    listeners = []
    from sqlalchemy.exc import IntegrityError

    from jt_oz_bridge.storage.cipher_types import PayloadUnavailable

    with pytest.raises(PayloadUnavailable if error == "encoder" else IntegrityError):
        async with db.sessions.begin() as session:
            await fence.lock(session)
            before = len(list(session.sync_session.dispatch.before_flush))
            try:
                with RecoveryLimits().watch(session, "synthetic"):
                    value = (
                        {"invalid": float("nan")}
                        if error == "encoder"
                        else {"new": "must roll back"}
                    )
                    session.add(
                        InputEvent(
                            id="quota-new",
                            source="zulip-history:synthetic",
                            source_id="same-id",
                            revision=0,
                            payload=value,
                            payload_hash="f" * 64,
                            state="zulip_history_unqualified",
                        )
                    )
                    await session.flush()
            finally:
                listeners.append((before, len(list(session.sync_session.dispatch.before_flush))))
    assert listeners == [(0, 0)]
    actual = await rows(db, InputEvent)
    assert len(actual) == 1 and actual[0].id == "quota-original" and actual[0].payload == original


@pytest.mark.asyncio
async def test_lowered_full_byte_cap_still_commits_denial_without_reencrypting_original_evidence(
    db,
):
    from sqlalchemy import LargeBinary, cast

    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s, "民" * 5000)
        names = [
            prefix + p.consumer.journal.source
            for prefix in ("zulip-history:", "zulip-recovery:", "zulip-recovery-review:")
        ]
        async with db.sessions() as session:
            before = dict(
                (
                    await session.execute(
                        select(InputEvent.id, cast(InputEvent.payload, LargeBinary)).where(
                            InputEvent.source.in_(names)
                        )
                    )
                ).all()
            )
        assert sum(map(len, before.values())) > 8192
        p.consumer.recovery.limits = RecoveryLimits(bytes=8192)
        s.expired_queues.add(p.consumer.queue_id)
        with pytest.raises(RecoveryCapacityExceeded):
            await p.consumer.poll()
        async with db.sessions() as session:
            after = dict(
                (
                    await session.execute(
                        select(InputEvent.id, cast(InputEvent.payload, LargeBinary)).where(
                            InputEvent.source.in_(names)
                        )
                    )
                ).all()
            )
        assert after == before
        run = next(e for e in await rows(db, InputEvent) if e.id == p.consumer.recovery.run_id)
        assert run.state == "zulip_recovery_capacity"
        current = (await rows(db, Binding))[0]
        assert current.dispatch_paused
        with pytest.raises(Conflict, match="recovery_capacity"):
            await p.dispatcher.queue.resume(
                b.id, "realm", 7, current.revision, current.queue_revision
            )
        assert (
            next(a for a in await rows(db, Action) if a.id == action.id).state == "held"
            and not n.submitted
        )
    finally:
        await close(p)
