"""Bounded raw archive/held-state component tests, without a PostgreSQL server.

SQLite synthetic fixtures exercise actual authentication/ciphertext/files. These
cases deliberately do not certify PostgreSQL SQL, transactions or archives.
"""

import hashlib
import os
import time
from uuid import uuid4

import pytest
import sqlalchemy as sa

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.backups import REVIEW_FLAG, BackupError, BackupService, _json
from jt_oz_bridge.services.postgres_backups import (
    FORMAT,
    AuthenticatedSource,
    LogicalManifest,
    bounded_rows,
    hold,
    restore_postgres_backup,
)
from jt_oz_bridge.storage.backup_files import PrivateDirectory
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.logical_archive import (
    LogicalArchiveError,
    TableWriter,
    authenticate_row,
    checksum,
    encode_row,
    read_rows,
    row_file,
    schema_spec,
)
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem
from tests.integration import test_backups as backup_fixtures

source = backup_fixtures.source
backup = backup_fixtures.backup


def row():
    return {"name": "fixture-flag", "pending": False}


def file_roundtrip(tmp_path, value):
    folder = PrivateDirectory(tmp_path / "rows", create=True)
    writer = TableWriter(folder, "maintenance_flags", 1024**2, time.monotonic() + 10)
    try:
        writer.row(value)
        record = writer.finish()
    finally:
        writer.close()
    return folder, record


def test_raw_record_roundtrip_is_exact_and_schema_bound(tmp_path):
    folder, record = file_roundtrip(tmp_path, row())
    try:
        assert list(read_rows(folder, "maintenance_flags", 1, record, time.monotonic() + 10)) == [
            row()
        ]
        with pytest.raises(LogicalArchiveError, match="table_or_schema"):
            list(read_rows(folder, "alembic_version", 1, record, time.monotonic() + 10))
    except FileNotFoundError:
        # No alternate filename is ever inferred from the caller's supplied file.
        assert row_file("maintenance_flags") != row_file("alembic_version")
    finally:
        folder.close()


@pytest.mark.parametrize("mutation", ["trailing", "truncated", "header", "digest", "count"])
def test_raw_record_rejects_tamper_and_false_counts(tmp_path, mutation):
    folder, record = file_roundtrip(tmp_path, row())
    try:
        target = tmp_path / "rows" / row_file("maintenance_flags")
        data = target.read_bytes()
        if mutation == "trailing":
            data += b"X"
        elif mutation == "truncated":
            data = data[:-1]
        elif mutation == "header":
            data = b"X" + data[1:]
        elif mutation == "digest":
            record["sha256"] = "0" * 64
        target.write_bytes(data)
        if mutation not in {"digest", "count"}:
            record = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        with pytest.raises(LogicalArchiveError):
            list(
                read_rows(
                    folder,
                    "maintenance_flags",
                    0 if mutation == "count" else 1,
                    record,
                    time.monotonic() + 10,
                )
            )
    finally:
        folder.close()


@pytest.mark.parametrize(
    "value",
    [
        {"name": "x", "pending": 1},
        {"name": "x", "pending": None},
        {"name": "x", "pending": False, "sql": "DROP TABLE actions"},
    ],
)
def test_record_types_and_exact_column_inventory_are_not_archive_instructions(value):
    with pytest.raises(LogicalArchiveError):
        list(encode_row("maintenance_flags", value))


def test_object_bound_checks_before_accumulating_unbounded_metadata():
    consumed = []

    def values():
        for i in range(100):
            consumed.append(i)
            yield {"id": i}

    with pytest.raises(BackupError, match="object_limit"):
        bounded_rows(values(), 2)
    assert consumed == [0, 1, 2]


async def test_authenticated_sqlite_source_keeps_every_id_and_original_ciphertext(source, tmp_path):
    identity = await DurableStore(source["db"]).enqueue(
        "archive-cipher-identity",
        source["binding"].id,
        source["binding"].revision,
        7,
        {"operation": "prompt", "text": "synthetic ciphertext preservation"},
    )
    store = DurableStore(source["db"])
    await store.enroll_queue("archive-recovery", "synthetic-queue", 0)
    event, inserted = await store.ingest(
        "archive-recovery", "synthetic-queue", 1, "synthetic-event", 0, {"synthetic": True}
    )
    assert inserted
    async with source["db"].sessions.begin() as session:
        session.add(
            ZulipRecoveryCheckpoint(
                source="archive-recovery",
                channel_id=10,
                realm_id="realm",
                bot_user_id=11,
                message_id=1,
                binding_scopes={"synthetic": True},
                run_id=event,
            )
        )
        session.add(
            ZulipRecoveryItem(
                source="archive-recovery",
                message_id=1,
                source_revision=0,
                input_event_id=event,
                run_id=event,
                binding_id=source["binding"].id,
                binding_revision=source["binding"].revision,
                actor_id=7,
                action_id=identity,
            )
        )
    path = tmp_path / "archive"
    await backup(source, path)
    opened = AuthenticatedSource(path, source["cipher"], 32 * 1024**2, time.monotonic() + 30)
    try:
        assert set(opened.manifest.table_counts) == set(schema_spec())
        checkpoint = next(opened.rows("zulip_recovery_checkpoints"))
        assert checkpoint["run_id"] == event and type(checkpoint["binding_scopes"]) is bytes
        assert authenticate_row("zulip_recovery_checkpoints", checkpoint, source["cipher"]) == set()
        item = next(opened.rows("zulip_recovery_items"))
        assert item["input_event_id"] == event and item["action_id"] == identity
        assert next(opened.rows("artifacts"))["id"] == source["artifact_id"]
        action = next(opened.rows("actions"))
        assert action["id"] == identity and type(action["payload"]) is bytes
        original = opened.sqlite.execute(
            "SELECT payload FROM actions WHERE id=?", (identity,)
        ).fetchone()[0]
        assert action["payload"] == original
        assert authenticate_row("actions", action, source["cipher"]) == set()
        with pytest.raises(ValueError):
            authenticate_row("actions", action, EnvelopeCipher({"v1": os.urandom(32)}, "v1"))
    finally:
        opened.close()


async def logical_from_sqlite(source, tmp_path):
    original = tmp_path / "sqlite-archive"
    await backup(source, original)
    opened = AuthenticatedSource(original, source["cipher"], 32 * 1024**2, time.monotonic() + 30)
    directory = PrivateDirectory(tmp_path / "logical-archive", create=True)
    artifacts = PrivateDirectory(directory.path / "artifacts", create=True)
    try:
        files = {}
        for name in schema_spec():
            writer = TableWriter(directory, name, 32 * 1024**2, time.monotonic() + 30)
            try:
                for value in opened.rows(name):
                    writer.row(value)
                files[row_file(name)] = writer.finish()
            finally:
                writer.close()
        identity = str(uuid4())
        files["configuration.enc"] = directory.write(
            "configuration.enc",
            source["cipher"].seal(
                source["settings"].model_dump_json().encode(),
                {"purpose": "backup-configuration", "backup_id": identity},
            ),
        )
        for name in opened.artifacts.names():
            files["artifacts/" + name] = artifacts.copy(
                name, opened.artifacts.chunks(name, 32 * 1024**2), 32 * 1024**2
            )
        manifest = LogicalManifest(
            format=FORMAT,
            backup_id=identity,
            created_at=time.time(),
            package_version="0.1.0.dev0",
            schema_revision=CURRENT_REVISION,
            schema_sha256=checksum(schema_spec()),
            key_id="v1",
            encryption_keys_embedded=False,
            files=files,
            table_counts=opened.manifest.table_counts,
            sequences=opened.sequence_values,
        )
        raw = _json(manifest.model_dump(mode="json"))
        directory.write("manifest.json", raw)
        directory.write(
            "manifest.auth",
            source["cipher"].seal(raw, {"purpose": "backup-manifest", "backup_id": identity}),
        )
        return directory.path
    finally:
        opened.close()
        artifacts.close()
        directory.close()


async def test_logical_archive_authentication_and_raw_codec_cover_all_current_tables(
    source, tmp_path
):
    path = await logical_from_sqlite(source, tmp_path)
    opened = AuthenticatedSource(path, source["cipher"], 32 * 1024**2, time.monotonic() + 30)
    try:
        assert opened.logical
        assert set(opened.manifest.table_counts) == set(schema_spec())
        assert next(opened.rows("artifacts"))["id"] == source["artifact_id"]
        assert sum(sum(1 for _ in opened.rows(name)) for name in schema_spec()) > 0
    finally:
        opened.close()


async def test_authenticated_manifest_cannot_add_executable_or_unknown_schema_data(
    source, tmp_path
):
    path = await logical_from_sqlite(source, tmp_path)
    with (path / "instructions.sql").open("xb") as stream:
        stream.write(b"DROP DATABASE ignored")
    (path / "instructions.sql").chmod(0o600)
    with pytest.raises(BackupError, match="untracked"):
        AuthenticatedSource(path, source["cipher"], 32 * 1024**2, time.monotonic() + 30)


async def test_non_pg_import_rejects_before_creating_destination_or_reading_bad_archive(
    source, tmp_path
):
    settings = source["settings"].model_copy(
        update={
            "database": source["settings"].database.model_copy(
                update={"url": None, "url_ref": "env:ISOLATED_PG_URL"}
            )
        }
    )
    destination = tmp_path / "must-not-exist"
    with pytest.raises(BackupError, match="postgresql_target"):
        await restore_postgres_backup(tmp_path / "missing", destination, source["db"], settings)
    assert not destination.exists()


async def test_held_transition_preserves_original_ambiguous_work_and_never_unpauses(source):
    # Same fixed SQL transitions run on a real isolated SQLite connection here;
    # real PostgreSQL SQL/rollback remains a separate required qualification.
    store = DurableStore(source["db"])
    ambiguous = await store.enqueue(
        "pg-ambiguous",
        source["binding"].id,
        source["binding"].revision,
        7,
        {"operation": "prompt", "text": "synthetic recovery"},
    )
    queued = await store.enqueue(
        "pg-queued",
        source["binding"].id,
        source["binding"].revision,
        7,
        {"operation": "prompt", "text": "synthetic queued"},
    )
    async with source["db"].engine.begin() as connection:
        await connection.execute(
            sa.text("UPDATE actions SET state='ambiguous' WHERE id=:id"), {"id": ambiguous}
        )
        original = (
            await connection.execute(
                sa.text("SELECT * FROM actions WHERE id=:id"), {"id": ambiguous}
            )
        ).one()
        original_queued = (
            await connection.execute(
                sa.text("SELECT payload FROM actions WHERE id=:id"), {"id": queued}
            )
        ).scalar_one()
        before = (
            await connection.execute(sa.text("SELECT id,revision,queue_revision FROM bindings"))
        ).one()
        result = await hold(connection, "fixture-held-identity")
        after = (
            await connection.execute(
                sa.text("SELECT id,revision,queue_revision,dispatch_paused FROM bindings")
            )
        ).one()
        assert tuple(after[:2]) == tuple(before[:2])
        assert after[2] == before[2] + 1 and after[3] == 1
        assert result["bindings_paused"] == 1
        assert (
            await connection.scalar(
                sa.text("SELECT pending FROM maintenance_flags WHERE name=:name"),
                {"name": REVIEW_FLAG},
            )
            == 1
        )
        assert (
            await connection.execute(
                sa.text("SELECT * FROM actions WHERE id=:id"), {"id": ambiguous}
            )
        ).one() == original
        recovered = (
            await connection.execute(
                sa.text("SELECT state,payload FROM actions WHERE id=:id"), {"id": queued}
            )
        ).one()
        assert recovered.state == "held" and recovered.payload == original_queued


async def test_postgres_backup_facade_accepts_encrypted_engine_without_connecting():
    # Constructor only: the network is never used, and this is not PG SQL proof.
    db = Database(
        "postgresql+asyncpg://unused@/isolated", cipher=EnvelopeCipher({"v1": os.urandom(32)}, "v1")
    )
    try:
        assert BackupService(db).db is db
    finally:
        await db.close()


@pytest.mark.parametrize("mutation", ["page_rewrite", "new_wal"])
async def test_authenticated_sqlite_source_rejects_change_after_validation(
    source, tmp_path, mutation
):
    path = tmp_path / "archive"
    await backup(source, path)
    opened = AuthenticatedSource(path, source["cipher"], 32 * 1024**2, time.monotonic() + 30)
    try:
        if mutation == "page_rewrite":
            # Even an equal-byte rewrite changes ctime: no post-auth page edit
            # can be admitted by relying on the earlier whole-file manifest.
            with (path / "bridge.sqlite").open("r+b") as stream:
                first = stream.read(1)
                stream.seek(0)
                stream.write(first)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            (path / "bridge.sqlite-wal").write_bytes(b"untrusted-extra")
            (path / "bridge.sqlite-wal").chmod(0o600)
        with pytest.raises(BackupError, match="source_(file|inventory)_changed"):
            opened.require_unchanged()
    finally:
        opened.close()


@pytest.mark.parametrize(
    "flag",
    [
        "enabled",
        "native_mirror_enabled",
        "native_drafts_enabled",
        "file_returns_enabled",
        "generated_returns_enabled",
        "workspace_inputs_enabled",
        "workspace_menus_enabled",
        "session_creation_enabled",
        "zulip_recovery_enabled",
    ],
)
async def test_pg_restore_rejects_each_active_runtime_before_archive_or_database(
    source, tmp_path, flag
):
    settings = source["settings"].model_copy(
        update={
            "database": source["settings"].database.model_copy(
                update={"url": None, "url_ref": "env:ISOLATED_PG_URL"}
            ),
            "runtime": source["settings"].runtime.model_copy(update={flag: True}),
        }
    )
    destination = tmp_path / "must-not-exist"
    with pytest.raises(BackupError, match="inert_loopback"):
        await restore_postgres_backup(tmp_path / "missing", destination, source["db"], settings)
    assert not destination.exists()


SCHEMA37_COLUMNS = {
    "native_feed_receipts": (", recorded_at FLOAT",),
    "native_live_captures": (
        ", connection_epoch VARCHAR(64)",
        ", receipt_key VARCHAR(64)",
        ", recorded_at FLOAT",
    ),
    "pending_interactions": (", created_at FLOAT",),
}
SCHEMA37_INDEXES = frozenset(
    {
        "ix_native_feed_receipts_recorded_at",
        "ix_native_live_captures_connection_epoch",
        "ix_native_live_captures_receipt_key",
        "ix_native_live_captures_recorded_at",
    }
)


def schema37_removed(rows):
    """Strip exactly schema37's nullable ADD COLUMN DDL and its new indexes."""
    result = []
    for kind, name, table, sql in rows:
        if kind == "index" and name in SCHEMA37_INDEXES:
            continue
        if kind == "table" and name in SCHEMA37_COLUMNS:
            for needle in SCHEMA37_COLUMNS[name]:
                assert sql.count(needle) == 1, (name, needle)
                sql = sql.replace(needle, "", 1)
        result.append((kind, name, table, sql))
    return result


async def test_schema35_sqlite_preserves_all_schema_ddl_and_original_encrypted_input(tmp_path):
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
    from jt_oz_bridge.storage.database import migrate

    cipher = EnvelopeCipher({"v1": os.urandom(32)}, "v1")
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'previous.db'}", cipher=cipher)
    sealed = cipher.seal(
        checked_json({"original": "preserved"}), payload_scope("input_events", "payload")
    )

    def previous(connection):
        cfg = Config()
        cfg.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "0034_zulip_gap_recovery")

    async def schema(connection):
        return (
            await connection.execute(
                sa.text("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
            )
        ).all()

    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(previous)
            await connection.execute(
                sa.text(
                    "INSERT INTO input_events (id,source,source_id,revision,payload_hash,payload,state,created_at) VALUES ('original','fixture','1',0,'hash',:payload,'held',123)"
                ),
                {"payload": sealed},
            )
            ddl = await schema(connection)
            original = (await connection.execute(sa.text("SELECT * FROM input_events"))).all()
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            current = await schema(connection)
            assert [
                row
                for row in schema37_removed(current)
                if row[2] not in {"session_configuration_heads", "prompt_schedules"}
            ] == ddl
            assert (
                await connection.execute(sa.text("SELECT * FROM input_events"))
            ).all() == original
            assert (
                await connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                == CURRENT_REVISION
            )
            assert await connection.scalar(sa.text("PRAGMA integrity_check")) == "ok"
            assert not (await connection.execute(sa.text("PRAGMA foreign_key_check"))).all()
    finally:
        await db.close()
