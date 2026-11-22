"""Own-data backup/held-restore tests; synthetic domain rows, no upstream clients."""

import asyncio
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import tomllib
from contextlib import closing
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import update

from jt_oz_bridge.config import Settings, load_settings
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.artifacts import ArtifactService, FileDescriptor
from jt_oz_bridge.services.backups import BackupError, BackupService, restore_sqlite_backup
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.artifact_models import Artifact, ArtifactBudget
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken, PendingInteraction
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import DurableStore, digest
from jt_oz_bridge.storage.models import (
    Action,
    AdminAccount,
    AdminSession,
    Checkpoint,
    Delivery,
    InputEvent,
    WorkerLease,
)
from jt_oz_bridge.storage.zulip_models import ZulipQueue
from tests.support import bound

MARKER = "PRIVATE_BACKUP_FIXTURE_8df13bcc"


async def chunks(value):
    yield value


@pytest_asyncio.fixture
async def source(tmp_path):
    live = tmp_path / "live"
    live.mkdir(mode=0o700)
    key = os.urandom(32)
    cipher = EnvelopeCipher({"v1": key}, "v1")
    db = Database("sqlite+aiosqlite:///" + str(live / "bridge.db"), cipher=cipher)
    await migrate(db.engine)
    (live / "bridge.db").chmod(0o600)
    bindings, binding, control, audience = await bound(db)
    files = LocalArtifactFiles(live / "artifacts")
    artifacts = ArtifactService(
        bindings, files, cipher, maximum_file_bytes=1024, reserve_free_bytes=0
    )
    artifact_id = await artifacts.create(
        binding.id,
        "realm",
        7,
        FileDescriptor(filename=MARKER + ".txt", mime_type="text/plain"),
        chunks(MARKER.encode()),
        expected_size=len(MARKER),
    )
    settings = Settings.model_validate(
        {
            "app": {"state_dir": str(live), "environment": "test"},
            "retention": {"reserve_free_disk_bytes": 1},
            "admin": {"enabled": False},
            "security": {"secret_key_ref": "env:JTOZ_BACKUP_FIXTURE_KEY"},
        }
    )
    try:
        yield {
            "db": db,
            "live": live,
            "key": key,
            "cipher": cipher,
            "settings": settings,
            "binding": binding,
            "bindings": bindings,
            "control": control,
            "audience": audience,
            "artifacts": artifacts,
            "artifact_id": artifact_id,
        }
    finally:
        files.close()
        await db.close()


async def backup(source, path, **kwargs):
    return await BackupService(source["db"]).create(
        path, source["settings"], artifacts=source["live"] / "artifacts", **kwargs
    )


async def restore(source, archive, destination, **kwargs):
    return await restore_sqlite_backup(
        archive,
        destination,
        source["cipher"],
        key_ref="env:JTOZ_BACKUP_FIXTURE_KEY",
        **kwargs,
    )


def rows(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection, connection:
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            name: sorted(connection.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr)
            for name in names
        }


async def test_consistent_wal_snapshot_restores_ids_dedupe_pending_decisions_and_held_work(
    source, tmp_path
):
    db, binding = source["db"], source["binding"]
    store = DurableStore(db)
    await store.enroll_queue("fixture-events", "old-queue", 0)
    event_id, inserted = await store.ingest(
        "fixture-events", "old-queue", 17, "original-event", 0, {"text": MARKER}
    )
    assert inserted
    action_ids, delivery_ids = {}, {}
    for state in ("queued", "dispatching", "ambiguous", "completed"):
        identity = await store.enqueue(
            "action-" + state,
            binding.id,
            binding.revision,
            7,
            {"operation": "prompt", "text": MARKER},
        )
        async with db.sessions.begin() as session:
            await session.execute(update(Action).where(Action.id == identity).values(state=state))
        action_ids[state] = identity
    for state in ("pending", "sending", "ambiguous", "delivered"):
        identity = await store.queue_delivery(
            "delivery-" + state, binding.id, binding.revision, {"fixture": MARKER}
        )
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery).where(Delivery.id == identity).values(state=state)
            )
        delivery_ids[state] = identity
    fencing = await store.acquire_lease("fixture-before-backup")
    message = HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic=binding.topic,
        message_id=99,
        revision=0,
        author_id=7,
        text="!oz status",
    )
    claim = await CommandInbox(db, "fixture-before-backup", fencing).claim(
        message, "status", binding_id=binding.id, binding_revision=binding.revision
    )
    await store.release_lease("fixture-before-backup", fencing)
    interaction_id = str(uuid4())
    context = {"request": "unresolved-fixture", "text": MARKER}
    async with db.sessions.begin() as session:
        session.add(
            PendingInteraction(
                id=interaction_id,
                identity_key="fixture-interaction",
                binding_id=binding.id,
                binding_revision=binding.revision,
                snapshot=context,
                snapshot_hash=digest(context),
                state="pending",
                expires_at=time.time() + 3600,
            )
        )
        session.add(
            ControlToken(
                token_hash="a" * 64,
                kind="permission",
                realm_id="realm",
                user_id=7,
                binding_id=binding.id,
                binding_revision=binding.revision,
                context=context,
                context_hash=digest(context),
                expires_at=time.time() + 3600,
                used=False,
            )
        )
        session.add(AdminAccount(id="fixture-admin", username="fixture", password_hash="hash-only"))
        session.add(
            AdminSession(
                token_hash="b" * 64,
                admin_id="fixture-admin",
                csrf_hash="c" * 64,
                expires_at=time.time() + 3600,
            )
        )
        session.add(
            ZulipQueue(
                source="d" * 64,
                realm_id="realm",
                bot_user_id=9,
                queue_id="old-queue",
                event_id=17,
                enrolled_fencing=fencing,
                generation=2,
                state="active",
            )
        )
    before = rows(source["live"] / "bridge.db")
    assert (source["live"] / "bridge.db-wal").stat().st_size > 0
    archive, destination = tmp_path / "backup", tmp_path / "restored"
    snapshot = await backup(source, archive)
    assert rows(source["live"] / "bridge.db") == before
    assert snapshot["source_changed"] is False and snapshot["keys_embedded"] is False
    with closing(sqlite3.connect(archive / "bridge.sqlite")) as copied, copied:
        assert copied.execute("SELECT event_id FROM checkpoints").fetchone()[0] == 17
    for path in archive.rglob("*"):
        assert not path.stat().st_mode & 0o077
        if path.is_file():
            assert (
                MARKER.encode() not in path.read_bytes() and source["key"] not in path.read_bytes()
            )
    result = await restore(source, archive, destination)
    assert result["operator_review_required"] and not result["runtime_enabled"]
    restored = Database(
        "sqlite+aiosqlite:///" + str(destination / "bridge.db"), cipher=source["cipher"]
    )
    try:
        assert not await restored.ready()
        config = load_settings(destination / "restored-config.toml")
        assert config.app.state_dir == destination and config.app.bind_host == "127.0.0.1"
        assert not config.runtime.enabled and not config.runtime.native_mirror_enabled
        assert not config.runtime.native_drafts_enabled and not config.admin.enabled
        assert config.security.secret_key_ref == "env:JTOZ_BACKUP_FIXTURE_KEY"
        await BackupService(restored).complete_review(snapshot["backup_id"], config)
        assert await restored.ready()
        async with restored.sessions() as session:
            assert (await session.get(Binding, binding.id)).dispatch_paused
            assert (await session.get(Checkpoint, "fixture-events")).event_id == 17
            assert (await session.get(InputEvent, event_id)).payload == {"text": MARKER}
            assert (await session.get(ControlToken, "a" * 64)).context == context
            assert (await session.get(PendingInteraction, interaction_id)).snapshot == context
            assert (await session.get(PendingInteraction, interaction_id)).state == "pending"
            assert (await session.get(CommandReceipt, claim.id)).state == "ambiguous"
            assert await session.get(AdminSession, "b" * 64) is None
            lease = await session.get(WorkerLease, "consumer")
            assert lease.fencing == fencing + 1 and lease.expires_at == 0
            assert (await session.get(ZulipQueue, "d" * 64)).state == "expired"
            for before_state, after_state in (
                ("queued", "held"),
                ("dispatching", "ambiguous"),
                ("ambiguous", "ambiguous"),
                ("completed", "completed"),
            ):
                action = await session.get(Action, action_ids[before_state])
                assert action.state == after_state and action.payload["text"] == MARKER
            for before_state, after_state in (
                ("pending", "held"),
                ("sending", "ambiguous"),
                ("ambiguous", "ambiguous"),
                ("delivered", "delivered"),
            ):
                assert (
                    await session.get(Delivery, delivery_ids[before_state])
                ).state == after_state
        replay_store = DurableStore(restored)
        assert (
            await replay_store.enqueue(
                "action-queued",
                binding.id,
                binding.revision,
                7,
                {"operation": "prompt", "text": MARKER},
            )
            == action_ids["queued"]
        )
        assert await replay_store.ingest(
            "fixture-events", "old-queue", 17, "original-event", 0, {"text": MARKER}
        ) == (event_id, False)
        current = await replay_store.acquire_lease("fixture-after-restore")
        assert current > fencing
        assert await replay_store.acquire_lease("second-consumer") is None
        assert not await replay_store.renew_lease("fixture-before-backup", fencing)
        repeated = await CommandInbox(restored, "fixture-after-restore", current).claim(
            message, "status", binding_id=binding.id, binding_revision=binding.revision
        )
        assert repeated.status == "ambiguous" and repeated.id == claim.id
        await replay_store.release_lease("fixture-after-restore", current)
        files = LocalArtifactFiles(destination / "artifacts")
        try:
            actual = await ArtifactService(
                source["bindings"].__class__(restored, source["control"], source["audience"]),
                files,
                source["cipher"],
                maximum_file_bytes=1024,
                reserve_free_bytes=0,
            ).read(source["artifact_id"], "realm", 8)
            assert actual.content == MARKER.encode()
        finally:
            files.close()
        assert rows(source["live"] / "bridge.db") == before
    finally:
        await restored.close()


@pytest.mark.parametrize("runtime_profile", ["deployed_file_features", "all_features"])
async def test_restore_disables_every_runtime_feature_and_retains_original_encrypted_settings(
    source, tmp_path, monkeypatch, runtime_profile
):
    # A genuine snapshot/restore must work with the enabled feature combination
    # used by production, and with every current runtime feature enabled.
    values = source["settings"].model_dump(mode="json")
    original_pin = tmp_path / "original-runtime-enrollment.json"
    feature_flags = {name for name, value in values["runtime"].items() if isinstance(value, bool)}
    values["runtime"].update({name: runtime_profile == "all_features" for name in feature_flags})
    values["runtime"].update(
        enabled=True,
        native_mirror_enabled=True,
        file_returns_enabled=True,
        workspace_menus_enabled=True,
        enrollment_file=str(original_pin),
    )
    values["admin"].update(enabled=True, public_url="https://bridge.example.invalid")
    values.update(
        zulip_realms=[
            {
                "id": "realm",
                "enabled": True,
                "url": "https://chat.example.invalid",
                "bot_email": "bot@example.invalid",
                "api_key_ref": "env:JTOZ_BACKUP_UNSET_BOT_KEY",
                "allowed_user_ids": [7, 8],
                "allowed_channel_ids": [10],
            }
        ],
        opencode_backends=[
            {
                "id": "backend",
                "enabled": True,
                "base_url": "http://127.0.0.1:4096",
                "credential_ref": "env:JTOZ_BACKUP_UNSET_NATIVE_KEY",
            }
        ],
        projects=[
            {
                "id": "project",
                "enabled": True,
                "backend_id": "backend",
                "realm_id": "realm",
                "workspace_root": "/workspace/project",
            }
        ],
    )
    for name in ("JTOZ_BACKUP_UNSET_BOT_KEY", "JTOZ_BACKUP_UNSET_NATIVE_KEY"):
        monkeypatch.delenv(name, raising=False)
    source["settings"] = Settings.model_validate(values)
    original = source["settings"].model_dump(mode="json")
    store = DurableStore(source["db"])
    queued = await store.enqueue(
        "restore-enabled-queued",
        source["binding"].id,
        1,
        7,
        {"operation": "prompt", "text": MARKER},
    )
    uncertain = await store.enqueue(
        "restore-enabled-uncertain",
        source["binding"].id,
        1,
        7,
        {"operation": "prompt", "text": MARKER + "-uncertain"},
    )
    async with source["db"].sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == uncertain).values(state="dispatching")
        )
    delivery = await store.queue_delivery(
        "restore-enabled-delivery", source["binding"].id, 1, {"content": MARKER}
    )
    before = rows(source["live"] / "bridge.db")
    archive, destination = tmp_path / "enabled-backup", tmp_path / "enabled-restored"
    snapshot = await backup(source, archive)
    original_configuration = source["cipher"].open(
        (archive / "configuration.enc").read_bytes(),
        {"purpose": "backup-configuration", "backup_id": snapshot["backup_id"]},
        max_plaintext_bytes=1024**2,
    )
    assert json.loads(original_configuration) == original
    assert not original_pin.exists()  # Offline snapshot never resolves enrollment.
    result = await restore_sqlite_backup(
        archive, destination, source["cipher"], key_ref="env:JTOZ_RESTORED_FIXTURE_KEY"
    )
    safe = load_settings(destination / "restored-config.toml")
    restored_runtime = safe.runtime.model_dump(mode="json")
    assert {
        name for name, value in restored_runtime.items() if isinstance(value, bool)
    } == feature_flags
    assert all(restored_runtime[name] is False for name in feature_flags)
    assert safe.runtime.enrollment_file == original_pin
    assert not safe.admin.enabled and not safe.admin.public_url
    assert safe.app.state_dir == destination and safe.app.bind_host == "127.0.0.1"
    assert safe.database.url == "sqlite+aiosqlite:///" + str(destination / "bridge.db")
    assert safe.database.url_ref is None
    assert safe.security.secret_key_ref == "env:JTOZ_RESTORED_FIXTURE_KEY"
    for key in ("zulip_realms", "opencode_backends", "projects"):
        assert safe.model_dump(mode="json")[key] == original[key]
    assert (destination / "configuration.snapshot.enc").read_bytes() == (
        archive / "configuration.enc"
    ).read_bytes()
    assert result["operator_review_required"] and result["upstream_mutations"] == 0
    assert not result["runtime_enabled"] and not result["admin_enabled"]
    restored = Database(
        "sqlite+aiosqlite:///" + str(destination / "bridge.db"), cipher=source["cipher"]
    )
    try:
        assert not await restored.ready()
        async with restored.sessions() as session:
            assert (await session.get(Binding, source["binding"].id)).dispatch_paused
            assert (await session.get(Action, queued)).state == "held"
            assert (await session.get(Action, queued)).payload["text"] == MARKER
            assert (await session.get(Action, uncertain)).state == "ambiguous"
            assert (await session.get(Delivery, delivery)).state == "held"
        restored_rows = rows(destination / "bridge.db")
        assert restored_rows["grants"] == before["grants"]
        assert restored_rows["backends"] == before["backends"]
        assert restored_rows["projects"] == before["projects"]
        assert restored_rows["artifacts"] == before["artifacts"]
        await BackupService(restored).complete_review(snapshot["backup_id"], safe)
        assert await restored.ready()
        async with restored.sessions() as session:
            assert (await session.get(Binding, source["binding"].id)).dispatch_paused
            assert (await session.get(Action, queued)).state == "held"
            assert (await session.get(Action, uncertain)).state == "ambiguous"
            assert (await session.get(Delivery, delivery)).state == "held"
        assert rows(source["live"] / "bridge.db") == before
        assert source["settings"].model_dump(mode="json") == original
        assert not original_pin.exists()
    finally:
        await restored.close()


async def test_active_consumer_backup_refusal_does_not_revoke_its_lease(source, tmp_path):
    store = DurableStore(source["db"])
    fencing = await store.acquire_lease("running-fixture")
    before = rows(source["live"] / "bridge.db")
    with pytest.raises(BackupError, match="stopped_bridge"):
        await backup(source, tmp_path / "refused")
    assert not (tmp_path / "refused").exists()
    assert rows(source["live"] / "bridge.db") == before
    assert await store.renew_lease("running-fixture", fencing)
    await store.release_lease("running-fixture", fencing)


@pytest.mark.parametrize(
    "name", ["manifest.json", "manifest.auth", "bridge.sqlite", "configuration.enc", "artifact"]
)
async def test_tampering_is_rejected_before_creating_restore_destination(source, tmp_path, name):
    archive = tmp_path / "backup"
    await backup(source, archive)
    path = (
        archive / name
        if name != "artifact"
        else archive / "artifacts" / (source["artifact_id"] + ".bin")
    )
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    destination = tmp_path / "must-not-exist"
    with pytest.raises(ValueError):
        await restore(source, archive, destination)
    assert not destination.exists()


async def test_wrong_key_restore_cannot_create_plaintext_or_a_destination(source, tmp_path):
    archive = tmp_path / "backup"
    await backup(source, archive)
    with pytest.raises(ValueError):
        await restore_sqlite_backup(
            archive,
            tmp_path / "wrong-key",
            EnvelopeCipher({"v1": os.urandom(32)}, "v1"),
            key_ref="env:JTOZ_BACKUP_FIXTURE_KEY",
        )
    assert not (tmp_path / "wrong-key").exists()


@pytest.mark.parametrize("operation", ["backup", "restore"])
async def test_existing_destination_is_never_overwritten(source, tmp_path, operation):
    existing = tmp_path / "existing"
    existing.mkdir(mode=0o700)
    sentinel = existing / "keep-me"
    sentinel.write_bytes(b"original")
    if operation == "backup":
        with pytest.raises(FileExistsError):
            await backup(source, existing)
    else:
        await backup(source, tmp_path / "backup")
        with pytest.raises(FileExistsError):
            await restore(source, tmp_path / "backup", existing)
    assert sentinel.read_bytes() == b"original" and set(existing.iterdir()) == {sentinel}


@pytest.mark.parametrize("state", ["staging", "deleting", "failed_cleanup"])
async def test_in_progress_artifact_io_blocks_snapshot_without_changing_evidence(
    source, tmp_path, state
):
    async with source["db"].sessions.begin() as session:
        await session.execute(update(Artifact).values(state=state))
    before = rows(source["live"] / "bridge.db")
    with pytest.raises(BackupError, match="settled_artifact_io"):
        await backup(source, tmp_path / "refused")
    assert not (tmp_path / "refused").exists()
    assert rows(source["live"] / "bridge.db") == before


@pytest.mark.parametrize("kind", ["missing", "symlink", "hardlink", "untracked", "quota"])
async def test_artifact_integrity_and_scope_fail_closed(source, tmp_path, kind):
    path = source["live"] / "artifacts" / (source["artifact_id"] + ".bin")
    original = path.read_bytes()
    outside = tmp_path / "outside"
    outside.write_bytes(original)
    outside.chmod(0o600)
    if kind in {"missing", "symlink", "hardlink"}:
        path.unlink()
        if kind == "symlink":
            path.symlink_to(outside)
        elif kind == "hardlink":
            os.link(outside, path)
    elif kind == "untracked":
        (path.parent / "not-a-registered-object").write_bytes(b"do not include")
    else:
        async with source["db"].sessions.begin() as session:
            await session.execute(update(ArtifactBudget).values(reserved_bytes=0))
    with pytest.raises((ValueError, OSError)):
        await backup(source, tmp_path / "invalid")
    assert not (tmp_path / "invalid" / "manifest.auth").exists()
    assert outside.read_bytes() == original


async def test_quarantined_partial_evidence_is_retained_without_becoming_ready(source, tmp_path):
    identity = str(uuid4())
    partial = b"JTOZ-partial-encrypted-crash-evidence"
    path = source["live"] / "artifacts" / (identity + ".part")
    path.write_bytes(partial)
    path.chmod(0o600)
    binding = source["binding"]
    async with source["db"].sessions.begin() as session:
        session.add(
            Artifact(
                id=identity,
                binding_id=binding.id,
                binding_revision=binding.revision,
                realm_id="realm",
                project_id="project",
                actor_id=7,
                kind="attachment",
                state="quarantined",
                reserved_bytes=500,
                key_id="v1",
                expires_at=time.time() - 1,
            )
        )
        await session.execute(
            update(ArtifactBudget).values(
                reserved_bytes=ArtifactBudget.reserved_bytes + 500,
                object_count=ArtifactBudget.object_count + 1,
            )
        )
    await backup(source, tmp_path / "backup")
    await restore(source, tmp_path / "backup", tmp_path / "restored")
    assert (tmp_path / "restored" / "artifacts" / path.name).read_bytes() == partial
    with closing(sqlite3.connect(tmp_path / "restored" / "bridge.db")) as connection, connection:
        assert connection.execute(
            "SELECT state,reserved_bytes FROM artifacts WHERE id=?", (identity,)
        ).fetchone() == ("quarantined", 500)


async def test_restore_review_identity_and_disabled_runtime_are_required(source, tmp_path):
    snapshot = await backup(source, tmp_path / "backup")
    await restore(source, tmp_path / "backup", tmp_path / "restored")
    config = load_settings(tmp_path / "restored" / "restored-config.toml")
    database = Database(config.database.url, cipher=source["cipher"])
    try:
        service = BackupService(database)
        with pytest.raises(BackupError, match="identity_mismatch"):
            await service.complete_review(str(uuid4()), config)
        assert not await database.ready()
        enabled = config.model_copy(
            update={"admin": config.admin.model_copy(update={"enabled": True})}
        )
        with pytest.raises(BackupError, match="disabled_runtime_and_admin"):
            await service.complete_review(snapshot["backup_id"], enabled)
        assert not await database.ready()
        await service.complete_review(snapshot["backup_id"], config)
        assert await database.ready()
        with pytest.raises(BackupError, match="maintenance_pending"):
            await service.complete_review(snapshot["backup_id"], config)
    finally:
        await database.close()


async def test_reviewed_restores_can_be_backed_up_and_restored_again_without_old_review_authority(
    source, tmp_path
):
    current, settings, state = source["db"], source["settings"], source["live"]
    previous_ids, preserved_audit_ids = [], set()
    opened = []
    try:
        for generation in range(3):
            archive, destination = (
                tmp_path / f"archive-{generation}",
                tmp_path / f"restore-{generation}",
            )
            snapshot = await BackupService(current).create(
                archive, settings, artifacts=state / "artifacts"
            )
            await restore_sqlite_backup(
                archive, destination, source["cipher"], key_ref="env:JTOZ_BACKUP_FIXTURE_KEY"
            )
            config = load_settings(destination / "restored-config.toml")
            restored = Database(config.database.url, cipher=source["cipher"])
            opened.append(restored)
            service = BackupService(restored)
            assert not await restored.ready()
            for previous in previous_ids:
                with pytest.raises(BackupError, match="identity_mismatch"):
                    await service.complete_review(previous, config)
                assert not await restored.ready()
            await service.complete_review(snapshot["backup_id"], config)
            assert await restored.ready() and not config.runtime.enabled
            with closing(sqlite3.connect(destination / "bridge.db")) as connection, connection:
                audits = {row[0] for row in connection.execute("SELECT id FROM audit_events")}
                assert preserved_audit_ids < audits
                preserved_audit_ids = audits
                assert connection.execute(
                    "SELECT pending FROM maintenance_flags WHERE name='restored_backup_review'"
                ).fetchall() == [(0,)]
                assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1
            assert sorted(p.read_bytes() for p in (destination / "artifacts").iterdir()) == sorted(
                p.read_bytes() for p in (source["live"] / "artifacts").iterdir()
            )
            previous_ids.append(snapshot["backup_id"])
            current, settings, state = restored, config, destination
    finally:
        for database in opened:
            await database.close()


async def test_size_limits_leave_no_complete_snapshot_and_restore_does_not_overrun(
    source, tmp_path
):
    with pytest.raises(BackupError):
        await backup(source, tmp_path / "too-small", max_bytes=1024)
    assert not (tmp_path / "too-small" / "manifest.auth").exists()
    await backup(source, tmp_path / "backup")
    with pytest.raises(BackupError, match="total_limit"):
        await restore(source, tmp_path / "backup", tmp_path / "restored", max_bytes=1024)
    assert not (tmp_path / "restored").exists()


async def test_cancelled_backup_is_joined_before_reporting_it_stopped(
    source, tmp_path, monkeypatch
):
    from jt_oz_bridge.services import backups

    entered, release = threading.Event(), threading.Event()

    def delayed(*args):
        entered.set()
        assert release.wait(3)
        return {"joined": True}

    monkeypatch.setattr(backups, "_snapshot", delayed)
    task = asyncio.create_task(backup(source, tmp_path / "unused"))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_cli_roundtrip_emits_metadata_only_and_generates_valid_disabled_toml(
    source, tmp_path
):
    config = tmp_path / "source.toml"
    config.write_text(
        "[app]\nstate_dir = "
        + json.dumps(str(source["live"]))
        + "\n[admin]\nenabled = false\n[retention]\nreserve_free_disk_bytes = 1\n"
        + '[security]\nsecret_key_ref = "env:JTOZ_BACKUP_FIXTURE_KEY"\n'
    )
    env = dict(os.environ, JTOZ_BACKUP_FIXTURE_KEY=base64.b64encode(source["key"]).decode())

    async def command(path, *arguments):
        result = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-m", "jt_oz_bridge.cli", "--config", str(path), *map(str, arguments)],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        assert MARKER not in result.stdout and env["JTOZ_BACKUP_FIXTURE_KEY"] not in result.stdout
        return result.stdout

    snapshot = json.loads(await command(config, "backup", "--output", tmp_path / "backup"))
    result = json.loads(
        await command(
            config,
            "restore",
            "--backup",
            tmp_path / "backup",
            "--destination",
            tmp_path / "restored",
        )
    )
    assert result["operator_review_required"]
    restored_config = tmp_path / "restored" / "restored-config.toml"
    assert not load_settings(restored_config).runtime.enabled
    assert (
        await command(restored_config, "validate")
        == "Configuration valid. No connections or credentials resolved.\n"
    )
    completed = json.loads(
        await command(restored_config, "complete-restore", "--backup-id", snapshot["backup_id"])
    )
    assert completed["review_completed"] and not completed["held_actions_resumed"]
    (tmp_path / "backup" / "manifest.json").write_text(
        '{"marker": "' + MARKER + '", "nested": ' + "[" * 10000 + "0" + "]" * 10000 + "}"
    )
    malformed = await asyncio.to_thread(
        subprocess.run,
        [
            sys.executable,
            "-m",
            "jt_oz_bridge.cli",
            "--config",
            str(config),
            "restore",
            "--backup",
            str(tmp_path / "backup"),
            "--destination",
            str(tmp_path / "rejected"),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert malformed.returncode == 2 and not (tmp_path / "rejected").exists()
    assert "Traceback" not in malformed.stderr and MARKER not in malformed.stderr
    assert env["JTOZ_BACKUP_FIXTURE_KEY"] not in malformed.stdout + malformed.stderr


async def test_running_consumer_is_rejected_before_any_expensive_snapshot_scan(
    source, tmp_path, monkeypatch
):
    from jt_oz_bridge.services import backups

    def must_not_scan(*args, **kwargs):
        raise AssertionError("active dataset must not be scanned while holding its write lock")

    store = DurableStore(source["db"])
    fence = await store.acquire_lease("running-fixture")
    monkeypatch.setattr(backups, "_verify_database", must_not_scan)
    try:
        with pytest.raises(BackupError, match="stopped_bridge"):
            await backup(source, tmp_path / "refused")
        assert await store.renew_lease("running-fixture", fence)
    finally:
        await store.release_lease("running-fixture", fence)


def resign(archive, cipher, mutate):
    path = archive / "manifest.json"
    manifest = json.loads(path.read_bytes())
    mutate(manifest)
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    (archive / "manifest.auth").write_bytes(
        cipher.seal(raw, {"purpose": "backup-manifest", "backup_id": manifest["backup_id"]})
    )


async def test_review_cannot_clear_the_gate_after_a_binding_was_resumed(source, tmp_path):
    snapshot = await backup(source, tmp_path / "backup")
    await restore(source, tmp_path / "backup", tmp_path / "restored")
    config = load_settings(tmp_path / "restored" / "restored-config.toml")
    database = Database(config.database.url, cipher=source["cipher"])
    try:
        with (
            closing(sqlite3.connect(tmp_path / "restored" / "bridge.db")) as connection,
            connection,
        ):
            connection.execute("UPDATE bindings SET dispatch_paused=false")
        with pytest.raises(BackupError, match="unheld_work"):
            await BackupService(database).complete_review(snapshot["backup_id"], config)
        assert not await database.ready()
    finally:
        await database.close()


@pytest.mark.parametrize(
    "case", ["path", "missing-config", "schema", "counts", "embedded-key", "trigger"]
)
async def test_authenticated_but_invalid_snapshot_still_fails_semantic_checks(
    source, tmp_path, case
):
    archive = tmp_path / "backup"
    await backup(source, archive)

    def mutate(manifest):
        if case == "path":
            manifest["files"]["artifacts/../../outside"] = manifest["files"]["configuration.enc"]
        elif case == "missing-config":
            del manifest["files"]["configuration.enc"]
        elif case == "schema":
            manifest["schema_revision"] = "0018_native_transcript"
        elif case == "counts":
            manifest["table_counts"]["actions"] += 1
        elif case == "embedded-key":
            manifest["encryption_keys_embedded"] = True
        else:
            with closing(sqlite3.connect(archive / "bridge.sqlite")) as connection, connection:
                connection.execute(
                    "CREATE TRIGGER unexpected AFTER UPDATE ON bindings BEGIN SELECT 1; END"
                )
            value = (archive / "bridge.sqlite").read_bytes()
            manifest["files"]["bridge.sqlite"] = {
                "size": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }

    resign(archive, source["cipher"], mutate)
    with pytest.raises(ValueError):
        await restore(source, archive, tmp_path / "refused")
    assert not (tmp_path / "refused").exists()


async def test_corrupt_old_encrypted_payload_is_detected_even_with_a_valid_key_canary(
    source, tmp_path
):
    from sqlalchemy import text

    identity = await DurableStore(source["db"]).enqueue(
        "corrupted-old-payload", source["binding"].id, 1, 7, {"text": MARKER}
    )
    async with source["db"].engine.begin() as connection:
        await connection.execute(
            text("UPDATE actions SET payload=:bad WHERE id=:id"),
            {"bad": b"JTOZ-invalid", "id": identity},
        )
    assert await source[
        "db"
    ].ready()  # Readiness checks the key; the offline scan checks all cells.
    with pytest.raises(ValueError):
        await backup(source, tmp_path / "refused")
    assert not (tmp_path / "refused" / "manifest.auth").exists()


async def test_encrypted_payload_corruption_in_authenticated_archive_is_not_restored(
    source, tmp_path
):
    identity = await DurableStore(source["db"]).enqueue(
        "corrupted-backup-payload", source["binding"].id, 1, 7, {"text": MARKER}
    )
    archive = tmp_path / "backup"
    await backup(source, archive)
    with closing(sqlite3.connect(archive / "bridge.sqlite")) as connection, connection:
        connection.execute("UPDATE actions SET payload=? WHERE id=?", (b"JTOZ-invalid", identity))

    def mutate(manifest):
        value = (archive / "bridge.sqlite").read_bytes()
        manifest["files"]["bridge.sqlite"] = {
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }

    resign(archive, source["cipher"], mutate)
    with pytest.raises(ValueError):
        await restore(source, archive, tmp_path / "refused")
    assert not (tmp_path / "refused").exists()


async def test_source_and_archive_directories_cannot_contain_their_own_output(source, tmp_path):
    with pytest.raises(BackupError, match="outside_live_state"):
        await backup(source, source["live"] / "self-backup")
    with pytest.raises(BackupError, match="outside_live_state"):
        await backup(source, source["live"] / "artifacts" / "self-backup")
    await backup(source, tmp_path / "backup")
    with pytest.raises(BackupError, match="outside_backup"):
        await restore(source, tmp_path / "backup", tmp_path / "backup" / "self-restore")
    with pytest.raises(BackupError, match="outside_original_state"):
        await restore(source, tmp_path / "backup", source["live"] / "self-restore")


async def test_nested_effective_settings_roundtrip_to_standard_toml_without_secret_values(
    source, tmp_path
):
    from jt_oz_bridge.services.backups import _settings_toml

    values = source["settings"].model_dump(mode="json")
    values.update(
        zulip_realms=[
            {
                "id": "本機",
                "enabled": True,
                "url": "https://chat.example.invalid",
                "bot_email": "fixture@example.invalid",
                "api_key_ref": "env:FIXTURE_BOT_KEY",
                "allowed_user_ids": [7, 8],
                "allowed_channel_ids": [10],
                "request_budget": {"requests": 180, "window_seconds": 60, "reserved_requests": 64},
            }
        ],
        opencode_backends=[
            {
                "id": "backend",
                "enabled": True,
                "base_url": "http://127.0.0.1:4096",
                "credential_ref": "env:FIXTURE_NATIVE_KEY",
            }
        ],
        projects=[
            {
                "id": "project",
                "enabled": True,
                "backend_id": "backend",
                "realm_id": "本機",
                "workspace_root": '/workspace/含空白 "原件"',
            }
        ],
    )
    model = Settings.model_validate(values)
    raw = _settings_toml(model)
    decoded = Settings.model_validate(tomllib.loads(raw.decode()))
    assert decoded == model
    assert decoded.zulip_realms[0].request_budget.reserved_requests == 64
    assert decoded.projects[0].workspace_root == '/workspace/含空白 "原件"'
    assert source["key"] not in raw and MARKER.encode() not in raw


@pytest.mark.parametrize(
    "limits",
    [
        {"max_bytes": True},
        {"max_bytes": -1},
        {"maximum_seconds": float("nan")},
        {"maximum_seconds": float("inf")},
    ],
)
async def test_invalid_limits_cannot_disable_offline_io_bounds(source, tmp_path, limits):
    with pytest.raises(BackupError, match="invalid_backup_limits"):
        await backup(source, tmp_path / "refused", **limits)
    assert not (tmp_path / "refused").exists()


async def _registration_backup_roundtrip(source, tmp_path, active, *, extended):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.services.session_registration_journal import SessionRegistrationJournal
    from jt_oz_bridge.storage.durable import Conflict
    from jt_oz_bridge.storage.fencing import ConsumerFence
    from tests.integration.test_session_registration_extension import grow
    from tests.integration.test_session_registration_journal import record

    db = source["db"]
    store = DurableStore(db)
    epoch = await store.acquire_lease("registration-backup-fixture", ttl=120)
    journal = SessionRegistrationJournal(db, ConsumerFence("registration-backup-fixture", epoch))
    value = record()
    receipt = await journal.prepare(
        "realm", value, lock_authority=AsyncMock(), current=lambda: True
    )
    lineage = [value]
    if extended:
        for name in ("first-child", "later-grandchild"):
            previous = (
                await journal.recovery_records(
                    "realm", value.root.project_id, lock_authority=AsyncMock(), current=lambda: True
                )
            )[0]
            value = grow(value, name, parent=value.nodes[-1].reference)
            receipt = await journal.extend(
                previous, value, lock_authority=AsyncMock(), current=lambda: True
            )
            lineage.append(value)
    if active:
        await journal.activate(receipt, lock_authority=AsyncMock(), current=lambda: True)
    await store.release_lease("registration-backup-fixture", epoch)
    original_tables = rows(source["live"] / "bridge.db")
    original = original_tables["session_registrations"]
    original_deltas = original_tables["session_registration_extensions"]
    archive, destination = tmp_path / "registration-backup", tmp_path / "registration-restore"
    snapshot = await backup(source, archive)
    assert rows(archive / "bridge.sqlite")["session_registrations"] == original
    assert rows(archive / "bridge.sqlite")["session_registration_extensions"] == original_deltas
    await restore(source, archive, destination)
    restored = Database(
        "sqlite+aiosqlite:///" + str(destination / "bridge.db"), cipher=source["cipher"]
    )
    try:
        assert not await restored.ready()
        blocked = SessionRegistrationJournal(restored, journal.fence)
        with pytest.raises(Conflict, match="database_not_ready"):
            await blocked.recovery_records(
                "realm", value.root.project_id, lock_authority=AsyncMock(), current=lambda: True
            )
        assert rows(destination / "bridge.db")["session_registrations"] == original
        assert rows(destination / "bridge.db")["session_registration_extensions"] == original_deltas
        settings = load_settings(destination / "restored-config.toml")
        assert not settings.runtime.enabled
        await BackupService(restored).complete_review(snapshot["backup_id"], settings)
        current = await DurableStore(restored).acquire_lease("after-registration-restore", ttl=120)
        assert current is not None
        recovered = SessionRegistrationJournal(
            restored, ConsumerFence("after-registration-restore", current)
        )
        records = await recovered.recovery_records(
            "realm", value.root.project_id, lock_authority=AsyncMock(), current=lambda: True
        )
        assert len(records) == 1 and records[0].record == value
        assert records[0].state == ("active" if active else "prepared")
        assert records[0].extension_count == (2 if extended else 0)
        history = await recovered.history(
            records[0], lock_authority=AsyncMock(), current=lambda: True
        )
        assert [entry.predecessor.record for entry in history] == lineage[:-1]
        assert [entry.successor.record for entry in history] == lineage[1:]
        # Historical active metadata has no fresh observation or current fencing.
        with pytest.raises(Conflict, match="superseded"):
            await recovered.activate(receipt, lock_authority=AsyncMock(), current=lambda: True)
    finally:
        await restored.close()


@pytest.mark.parametrize("active", [False, True])
async def test_original_session_identity_survives_backup_without_bypassing_held_restore(
    source, tmp_path, active
):
    await _registration_backup_roundtrip(source, tmp_path, active, extended=False)


@pytest.mark.parametrize("active", [False, True])
async def test_original_graph_extension_history_survives_held_backup_restore(
    source, tmp_path, active
):
    await _registration_backup_roundtrip(source, tmp_path, active, extended=True)
