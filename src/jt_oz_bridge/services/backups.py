"""Offline, authenticated own-data snapshots and explicitly reviewed held restores.

Only the configured bridge dataset is opened (SQLite or PostgreSQL). There are no upstream
clients, subprocesses, automatic service stops, key exports or in-place restores.
"""

import asyncio
import hashlib
import json
import math
import os
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import Field

from jt_oz_bridge import __version__
from jt_oz_bridge.config import Settings
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.backup_files import FileRecord, PrivateDirectory, beneath
from jt_oz_bridge.storage.cipher_types import (
    KEY_CHECK,
    MAX_PAYLOAD,
    EncryptedJSON,
    checked_json,
    payload_scope,
)
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database
from jt_oz_bridge.storage.schema import Base

MAX_METADATA = 4 * 1024**2
MAX_CONFIG = 1024**2
MAX_ARTIFACT = 128 * 1024**2 + 8192
MAX_FILES = 20002
REVIEW_FLAG = "restored_backup_review"


class BackupError(ValueError):
    pass


class BackupFile(ControlModel):
    size: int = Field(strict=True, ge=0, le=2**50)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class BackupManifest(ControlModel):
    format: Literal["jt-oz-bridge-sqlite-backup-v1"]
    backup_id: str
    created_at: float = Field(gt=0, allow_inf_nan=False)
    package_version: str
    schema_revision: str
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,32}$")
    encryption_keys_embedded: Literal[False]
    configuration_format: Literal["effective-settings-json-v1"]
    files: dict[str, BackupFile] = Field(min_length=2, max_length=MAX_FILES)
    table_counts: dict[str, Annotated[int, Field(strict=True, ge=0)]] = Field(
        min_length=1, max_length=1000
    )
    required_key_ids: list[str] = Field(max_length=1000)


def _uuid(value: str) -> str:
    if str(UUID(value)) != value:
        raise BackupError("canonical_backup_identity_required")
    return value


def _json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _parse_json(value: bytes) -> Any:
    try:
        return strict_loads(value)
    except (RecursionError, UnicodeError):
        raise BackupError("backup_invalid_json") from None


async def _thread[T](function: Callable[[], T]) -> T:
    # A cancelled caller must not report completion while its snapshot still
    # owns the maintenance lock or is writing files in a background thread.
    task = asyncio.create_task(asyncio.to_thread(function))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.gather(task, return_exceptions=True)
        raise


def _connect(directory: PrivateDirectory, name: str, *, writable: bool) -> sqlite3.Connection:
    directory.verify()
    fd = directory.open_file(name)
    os.close(fd)
    path = directory.path / name
    mode = "rw" if writable else "ro"
    connection = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=1)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _verify_database(
    connection: sqlite3.Connection,
    cipher: EnvelopeCipher,
    *,
    review: bool = False,
    deadline: float | None = None,
) -> dict[str, int]:
    if deadline is not None:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise BackupError("backup_database_integrity_failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise BackupError("backup_database_foreign_keys_failed")
    names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if (
        names != set(Base.metadata.tables) | {"alembic_version"}
        or connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1"
        ).fetchone()
    ):
        raise BackupError("backup_requires_exact_owned_schema")
    revisions = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    if len(revisions) != 1 or revisions[0][0] != CURRENT_REVISION:
        raise BackupError("backup_schema_version_mismatch")
    pending = {
        row[0] for row in connection.execute("SELECT name FROM maintenance_flags WHERE pending")
    }
    if pending != ({REVIEW_FLAG} if review else set()):
        raise BackupError("backup_database_maintenance_pending")
    checks = connection.execute("SELECT key_id,challenge FROM payload_key_checks").fetchall()
    if not checks or cipher.active_key_id not in {row[0] for row in checks}:
        raise BackupError("backup_database_key_missing")
    for key, challenge in checks:
        if (
            cipher.open(
                challenge,
                {"purpose": "database-key-check", "key_id": key},
                max_plaintext_bytes=len(KEY_CHECK),
            )
            != KEY_CHECK
        ):
            raise BackupError("backup_database_key_mismatch")
    # A valid canary alone cannot detect a corrupted old encrypted event or
    # pending decision. Validate every encrypted cell without exporting plaintext.
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if not isinstance(column.type, EncryptedJSON):
                continue
            quoted_table = table.name.replace('"', '""')
            quoted_column = column.name.replace('"', '""')
            for (blob,) in connection.execute(
                f'SELECT "{quoted_column}" FROM "{quoted_table}" WHERE "{quoted_column}" IS NOT NULL'
            ):
                if deadline is not None and time.monotonic() >= deadline:
                    raise BackupError("backup_database_deadline_reached")
                if not isinstance(blob, bytes):
                    raise BackupError("backup_plaintext_payload_rejected")
                plaintext = cipher.open(
                    blob, payload_scope(table.name, column.name), max_plaintext_bytes=MAX_PAYLOAD
                )
                checked_json(_parse_json(plaintext))
    return {
        name: connection.execute(
            'SELECT count(*) FROM "' + name.replace('"', '""') + '"'
        ).fetchone()[0]
        for name in sorted(names)
    }


def _stopped(connection: sqlite3.Connection) -> None:
    if connection.execute(
        "SELECT 1 FROM worker_leases WHERE expires_at > ? LIMIT 1", (time.time(),)
    ).fetchone():
        raise BackupError("backup_requires_stopped_bridge")


def _artifacts(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [dict(row) for row in connection.execute("SELECT * FROM artifacts ORDER BY id")]
    if len(rows) > 10000:
        raise BackupError("backup_artifact_object_limit_reached")
    for row in rows:
        _uuid(row["id"])
        if row["state"] not in {"ready", "quarantined", "failed", "deleted"}:
            raise BackupError("backup_requires_settled_artifact_io")
        if type(row["reserved_bytes"]) is not int or row["reserved_bytes"] < 0:
            raise BackupError("backup_artifact_budget_invalid")
        if row["state"] in {"failed", "deleted"} and row["reserved_bytes"]:
            raise BackupError("backup_artifact_budget_invalid")
    budgets = connection.execute("SELECT * FROM artifact_budgets").fetchall()
    expected = sum(row["reserved_bytes"] for row in rows)
    objects = sum(row["reserved_bytes"] > 0 for row in rows)
    if budgets:
        if len(budgets) != 1 or tuple(budgets[0]) != ("global", expected, objects):
            raise BackupError("backup_artifact_budget_invalid")
    elif expected or objects:
        raise BackupError("backup_artifact_budget_missing")
    return rows


def _verify_artifact(row: dict[str, Any], value: bytes, cipher: EnvelopeCipher) -> None:
    if row["state"] != "ready":
        return  # Quarantined crash evidence is preserved byte-for-byte, never activated.
    scope = {"purpose": "artifact", "object_id": row["id"]}
    scope.update(
        {
            key: row[key]
            for key in (
                "realm_id",
                "project_id",
                "binding_id",
                "binding_revision",
                "kind",
                "key_id",
            )
        }
    )
    plaintext = cipher.open(value, scope, max_plaintext_bytes=MAX_ARTIFACT)
    size = int.from_bytes(plaintext[:4], "big")
    if not 1 <= size <= 4096 or len(plaintext) < 4 + size:
        raise BackupError("backup_artifact_metadata_invalid")
    from jt_oz_bridge.services.artifacts import FileDescriptor

    FileDescriptor.model_validate(_parse_json(plaintext[4 : 4 + size]))
    content = plaintext[4 + size :]
    if (
        len(value) != row["reserved_bytes"]
        or len(content) != row["size_bytes"]
        or hashlib.sha256(content).hexdigest() != row["checksum"]
    ):
        raise BackupError("backup_artifact_integrity_failed")


def _artifact_files(rows: list[dict[str, Any]], names: set[str]) -> dict[str, dict[str, Any]]:
    expected = {}
    for row in rows:
        possible = {row["id"] + ".bin", row["id"] + ".part"}
        found = names & possible
        if row["state"] == "ready" and found != {row["id"] + ".bin"}:
            raise BackupError("backup_ready_artifact_missing_or_partial")
        if row["state"] in {"failed", "deleted"} and found:
            raise BackupError("backup_unsettled_artifact_files")
        for name in found:
            expected[name] = row
    if names != set(expected):
        raise BackupError("backup_untracked_artifact_files")
    return expected


def _limits(max_bytes: int, timeout: float) -> None:
    if (
        type(max_bytes) is not int
        or not 1024 <= max_bytes <= 2**50
        or type(timeout) not in {int, float}
        or not math.isfinite(timeout)
        or not 1 <= timeout <= 3600
    ):
        raise BackupError("invalid_backup_limits")


def _snapshot(
    database: Path,
    artifacts: Path | None,
    output: Path,
    settings: Settings,
    cipher: EnvelopeCipher,
    max_bytes: int,
    timeout: float,
) -> dict[str, Any]:
    _limits(max_bytes, timeout)
    source = PrivateDirectory(database.parent)
    archive = artifact_source = artifact_target = None
    guard = reader = target = None
    deadline = time.monotonic() + timeout
    try:
        guard = _connect(source, database.name, writable=True)
        guard.execute("BEGIN IMMEDIATE")
        _stopped(guard)
        counts = _verify_database(guard, cipher, deadline=deadline)
        rows = _artifacts(guard)
        if artifacts is not None:
            artifact_source = PrivateDirectory(artifacts)
        expected = _artifact_files(rows, artifact_source.names() if artifact_source else set())
        if (
            database.parent == output
            or beneath(source, output.parent)
            or artifact_source is not None
            and beneath(artifact_source, output.parent)
        ):
            raise BackupError("backup_output_must_be_outside_live_state")
        archive = PrivateDirectory(output, create=True)
        artifact_target = PrivateDirectory(output / "artifacts", create=True)
        records: dict[str, FileRecord] = {}
        consumed = 0

        def progress(_status: int, _remaining: int, pages: int) -> None:
            if time.monotonic() >= deadline or pages * page_size > max_bytes:
                raise BackupError("backup_deadline_or_size_limit_reached")

        page_size = guard.execute("PRAGMA page_size").fetchone()[0]
        estimate = page_size * guard.execute("PRAGMA page_count").fetchone()[0]
        if artifact_source is not None:
            for name in expected:
                fd = artifact_source.open_file(name)
                try:
                    estimate += os.fstat(fd).st_size
                finally:
                    os.close(fd)
        # Reserve room for the bounded configuration and both manifest copies too.
        if (
            estimate > max_bytes
            or archive.free_bytes()
            < estimate + MAX_CONFIG + 2 * MAX_METADATA + settings.retention.reserve_free_disk_bytes
        ):
            raise BackupError("backup_space_reserve_reached")
        archive.write("bridge.sqlite", b"")
        reader = _connect(source, database.name, writable=False)
        target = _connect(archive, "bridge.sqlite", writable=True)
        reader.backup(target, pages=128, progress=progress, sleep=0.01)
        target.execute("PRAGMA journal_mode=DELETE")
        if _verify_database(target, cipher, deadline=deadline) != counts:
            raise BackupError("backup_snapshot_counts_changed")
        target.close()
        target = None
        records["bridge.sqlite"] = archive.record("bridge.sqlite", max_bytes, deadline=deadline)
        consumed += records["bridge.sqlite"]["size"]
        for name, row in sorted(expected.items()):
            assert artifact_source is not None
            if time.monotonic() >= deadline:
                raise BackupError("backup_deadline_or_size_limit_reached")
            if name.endswith(".bin") and row["state"] == "ready":
                _verify_artifact(
                    row, artifact_source.read(name, MAX_ARTIFACT, deadline=deadline), cipher
                )
            record = artifact_target.copy(
                name,
                artifact_source.chunks(name, max_bytes - consumed, deadline=deadline),
                max_bytes - consumed,
            )
            records["artifacts/" + name] = record
            consumed += record["size"]
        identity = str(uuid4())
        configuration = settings.model_dump_json().encode()
        if len(configuration) > MAX_CONFIG:
            raise BackupError("backup_configuration_limit_reached")
        encrypted = cipher.seal(
            configuration, {"purpose": "backup-configuration", "backup_id": identity}
        )
        records["configuration.enc"] = archive.write("configuration.enc", encrypted)
        consumed += len(encrypted)
        manifest = BackupManifest(
            format="jt-oz-bridge-sqlite-backup-v1",
            backup_id=identity,
            created_at=time.time(),
            package_version=__version__,
            schema_revision=CURRENT_REVISION,
            key_id=cipher.active_key_id,
            encryption_keys_embedded=False,
            configuration_format="effective-settings-json-v1",
            files={name: BackupFile(**record) for name, record in records.items()},
            table_counts=counts,
            required_key_ids=sorted(
                {row[0] for row in guard.execute("SELECT key_id FROM payload_key_checks")}
                | {row["key_id"] for row in rows if row["state"] in {"ready", "quarantined"}}
            ),
        )
        raw = _json(manifest.model_dump(mode="json"))
        authenticated = cipher.seal(raw, {"purpose": "backup-manifest", "backup_id": identity})
        if len(raw) > MAX_METADATA or consumed + len(raw) + len(authenticated) > max_bytes:
            raise BackupError("backup_metadata_or_total_limit_reached")
        archive.verify()
        source.verify()
        if artifact_source is not None:
            artifact_source.verify()
        archive.write("manifest.json", raw)
        archive.write(
            "manifest.auth", authenticated
        )  # Complete only after this authenticated commit.
        return {
            "backup_id": identity,
            "schema_revision": CURRENT_REVISION,
            "files": len(records),
            "bytes": consumed + len(raw) + len(authenticated),
            "keys_embedded": False,
            "source_changed": False,
        }
    finally:
        for connection in (target, reader, guard):
            if connection is not None:
                connection.close()
        for closing_directory in (artifact_target, artifact_source, archive, source):
            if closing_directory is not None:
                closing_directory.close()


def _manifest(archive: PrivateDirectory, cipher: EnvelopeCipher, max_bytes: int) -> BackupManifest:
    raw = archive.read("manifest.json", MAX_METADATA)
    manifest = BackupManifest.model_validate(_parse_json(raw))
    _uuid(manifest.backup_id)
    if manifest.schema_revision != CURRENT_REVISION or manifest.key_id != cipher.active_key_id:
        raise BackupError("backup_version_or_active_key_mismatch")
    actual = cipher.open(
        archive.read("manifest.auth", MAX_METADATA + 1024),
        {"purpose": "backup-manifest", "backup_id": manifest.backup_id},
        max_plaintext_bytes=MAX_METADATA,
    )
    if actual != raw:
        raise BackupError("backup_manifest_authentication_failed")
    if not {"bridge.sqlite", "configuration.enc"} <= set(manifest.files):
        raise BackupError("backup_required_files_missing")
    if sum(record.size for record in manifest.files.values()) > max_bytes:
        raise BackupError("backup_total_limit_reached")
    if any(type(count) is not int or count < 0 for count in manifest.table_counts.values()):
        raise BackupError("backup_table_counts_invalid")
    for name in manifest.files:
        if name in {"bridge.sqlite", "configuration.enc"}:
            continue
        if (
            not name.startswith("artifacts/")
            or name.count("/") != 1
            or not name.endswith((".bin", ".part"))
        ):
            raise BackupError("backup_manifest_path_rejected")
        _uuid(name.removeprefix("artifacts/").rsplit(".", 1)[0])
    if archive.names() != {
        "bridge.sqlite",
        "configuration.enc",
        "manifest.json",
        "manifest.auth",
        "artifacts",
    }:
        raise BackupError("backup_untracked_files")
    return manifest


def _settings_toml(settings: Settings) -> bytes:
    lines: list[str] = []

    def scalar(value: Any) -> str:
        if isinstance(value, (str, bool, int, float)):
            return json.dumps(value, ensure_ascii=False, allow_nan=False)
        if isinstance(value, list) and all(
            not isinstance(item, dict) and item is not None for item in value
        ):
            return "[" + ", ".join(scalar(item) for item in value) + "]"
        raise BackupError("restore_configuration_type_rejected")

    def emit(table: dict[str, Any], prefix: tuple[str, ...], array: bool = False) -> None:
        if prefix:
            name = ".".join(json.dumps(key) for key in prefix)
            lines.append(("[[" if array else "[") + name + ("]]" if array else "]"))
        for key, value in table.items():
            if (
                value is None
                or isinstance(value, dict)
                or isinstance(value, list)
                and value
                and isinstance(value[0], dict)
            ):
                continue
            lines.append(json.dumps(key) + " = " + scalar(value))
        lines.append("")
        for key, value in table.items():
            if isinstance(value, dict):
                emit(value, (*prefix, key))
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                for item in value:
                    emit(item, (*prefix, key), True)

    emit(settings.model_dump(mode="json"), ())
    return "\n".join(lines).encode()


def _recover_copy(connection: sqlite3.Connection, identity: str) -> dict[str, int]:
    now = time.time()
    result = {}
    connection.execute("BEGIN IMMEDIATE")
    for before, after in (("queued", "held"), ("dispatching", "ambiguous")):
        result["actions_" + after] = connection.execute(
            "UPDATE actions SET state=?, version=version+1, status_reason=? WHERE state=?",
            (after, "backup_restored_" + before, before),
        ).rowcount
    for before, after in (("pending", "held"), ("sending", "ambiguous")):
        result["deliveries_" + after] = connection.execute(
            "UPDATE deliveries SET state=?, version=version+1, updated_at=?, status_reason=? WHERE state=?",
            (after, now, "backup_restored_" + before, before),
        ).rowcount
    result["commands_ambiguous"] = connection.execute(
        "UPDATE command_receipts SET state='ambiguous',version=version+1,updated_at=? WHERE state='processing'",
        (now,),
    ).rowcount
    result["commands_held"] = connection.execute(
        "UPDATE command_receipts SET state='held',version=version+1,updated_at=? WHERE state='deferred'",
        (now,),
    ).rowcount
    result["bindings_paused"] = connection.execute(
        "UPDATE bindings SET dispatch_paused=true,queue_revision=queue_revision+1 WHERE state='active'"
    ).rowcount
    connection.execute("UPDATE worker_leases SET expires_at=0,fencing=fencing+1")
    connection.execute("UPDATE zulip_queues SET state='expired',updated_at=?", (now,))
    result["admin_sessions_invalidated"] = connection.execute("DELETE FROM admin_sessions").rowcount
    connection.execute(
        "INSERT INTO maintenance_flags (name,pending) VALUES (?,true) "
        "ON CONFLICT(name) DO UPDATE SET pending=true",
        (REVIEW_FLAG,),
    )
    connection.execute(
        "INSERT INTO audit_events (id,actor,event,object_id,created_at) VALUES (?,?,?,?,?)",
        (str(uuid4()), "operator", "database_restored_held", identity, now),
    )
    connection.commit()
    return result


def _restore(
    backup: Path,
    destination: Path,
    cipher: EnvelopeCipher,
    key_ref: str,
    max_bytes: int,
    maximum_seconds: float,
) -> dict[str, Any]:
    _limits(max_bytes, maximum_seconds)
    deadline = time.monotonic() + maximum_seconds
    archive = PrivateDirectory(backup)
    incoming = output = outgoing = None
    connection = None
    try:
        if destination == backup or beneath(archive, destination.parent):
            raise BackupError("restore_destination_must_be_outside_backup")
        manifest = _manifest(archive, cipher, max_bytes)
        incoming = PrivateDirectory(backup / "artifacts")
        expected_names = {
            name.removeprefix("artifacts/")
            for name in manifest.files
            if name.startswith("artifacts/")
        }
        if incoming.names() != expected_names:
            raise BackupError("backup_artifact_inventory_mismatch")
        # Authenticate and hash the entire snapshot before creating any destination.
        for name, record in manifest.files.items():
            directory, filename = (
                (incoming, name.removeprefix("artifacts/"))
                if name.startswith("artifacts/")
                else (archive, name)
            )
            if (
                directory.record(filename, min(record.size, max_bytes), deadline=deadline)
                != record.model_dump()
            ):
                raise BackupError("backup_file_integrity_failed")
        configuration = cipher.open(
            archive.read("configuration.enc", MAX_CONFIG + 1024),
            {"purpose": "backup-configuration", "backup_id": manifest.backup_id},
            max_plaintext_bytes=MAX_CONFIG,
        )
        settings = Settings.model_validate(_parse_json(configuration))
        if destination == settings.app.state_dir or destination.is_relative_to(
            settings.app.state_dir
        ):
            raise BackupError("restore_destination_must_be_outside_original_state")
        connection = _connect(archive, "bridge.sqlite", writable=False)
        if _verify_database(connection, cipher, deadline=deadline) != manifest.table_counts:
            raise BackupError("backup_snapshot_counts_changed")
        rows = _artifacts(connection)
        expected = _artifact_files(rows, incoming.names())
        for name, row in expected.items():
            if name.endswith(".bin") and row["state"] == "ready":
                _verify_artifact(row, incoming.read(name, MAX_ARTIFACT, deadline=deadline), cipher)
        connection.close()
        connection = None
        output = PrivateDirectory(destination, create=True)
        outgoing = PrivateDirectory(destination / "artifacts", create=True)
        if (
            output.free_bytes()
            < sum(record.size for record in manifest.files.values())
            + settings.retention.reserve_free_disk_bytes
        ):
            raise BackupError("restore_space_reserve_reached")
        for name, record in manifest.files.items():
            if name.startswith("artifacts/"):
                filename = name.removeprefix("artifacts/")
                copied = outgoing.copy(
                    filename, incoming.chunks(filename, record.size, deadline=deadline), record.size
                )
            elif name == "bridge.sqlite":
                copied = output.copy(
                    "restoring.sqlite",
                    archive.chunks(name, record.size, deadline=deadline),
                    record.size,
                )
            else:
                copied = output.copy(
                    "configuration.snapshot.enc",
                    archive.chunks(name, record.size, deadline=deadline),
                    record.size,
                )
            if copied != record.model_dump():
                raise BackupError("backup_changed_during_restore")
        connection = _connect(output, "restoring.sqlite", writable=True)
        held = _recover_copy(connection, manifest.backup_id)
        _verify_database(connection, cipher, review=True, deadline=deadline)
        connection.close()
        connection = None
        values = settings.model_dump(mode="json")
        values["app"].update(state_dir=str(destination), bind_host="127.0.0.1")
        values["database"].update(
            url="sqlite+aiosqlite:///" + str(destination / "bridge.db"), url_ref=None
        )
        # Keep the original configuration encrypted and intact, but make every
        # restored runtime feature inert until an operator reviews recovery.
        # Every switch, so a feature added later cannot stay on (or depend on
        # one that was turned off) after restore.
        values["runtime"].update(
            {
                key: False
                for key in values["runtime"]
                if key == "enabled" or key.endswith("_enabled")
            }
        )
        values["admin"].update(enabled=False, public_url="")
        values["security"]["secret_key_ref"] = key_ref
        safe_settings = Settings.model_validate(values)
        output.write("restored-config.toml", _settings_toml(safe_settings))
        result = {
            "backup_id": manifest.backup_id,
            "schema_revision": CURRENT_REVISION,
            "held_recovery": held,
            "operator_review_required": True,
            "runtime_enabled": False,
            "admin_enabled": False,
            "upstream_mutations": 0,
            "keys_embedded": False,
        }
        output.write("restore-report.json", _json(result))
        output.verify()
        archive.verify()
        # Publish a usable database only after artifacts, config and held state exist.
        os.link(
            "restoring.sqlite",
            "bridge.db",
            src_dir_fd=output.fd,
            dst_dir_fd=output.fd,
            follow_symlinks=False,
        )
        os.unlink("restoring.sqlite", dir_fd=output.fd)
        os.fsync(output.fd)
        return result
    finally:
        if connection is not None:
            connection.close()
        for closing_directory in (outgoing, output, incoming, archive):
            if closing_directory is not None:
                closing_directory.close()


class BackupService:
    def __init__(self, database: Database) -> None:
        if database.engine.dialect.name not in {"sqlite", "postgresql"} or database.cipher is None:
            raise BackupError("sqlite_backup_requires_own_encrypted_dataset")
        self.db, self.cipher = database, database.cipher
        self.path = Path(database.engine.url.database or "")

    async def create(
        self,
        output: Path,
        settings: Settings,
        *,
        artifacts: Path | None = None,
        max_bytes: int = 64 * 1024**3,
        maximum_seconds: float = 300,
    ) -> dict[str, Any]:
        if self.db.engine.dialect.name == "postgresql":
            from jt_oz_bridge.services.postgres_backups import PostgresBackupService

            return await PostgresBackupService(self.db).create(
                output,
                settings,
                artifacts=artifacts,
                max_bytes=max_bytes,
                maximum_seconds=maximum_seconds,
            )
        if not await self.db.ready():
            raise BackupError("backup_database_not_ready")
        return await _thread(
            lambda: _snapshot(
                self.path, artifacts, output, settings, self.cipher, max_bytes, maximum_seconds
            )
        )

    async def complete_review(self, backup_id: str, settings: Settings) -> dict[str, Any]:
        if self.db.engine.dialect.name == "postgresql":
            from jt_oz_bridge.services.postgres_backups import PostgresBackupService

            return await PostgresBackupService(self.db).complete_review(backup_id, settings)
        _uuid(backup_id)
        if (
            settings.runtime.enabled
            or settings.admin.enabled
            or settings.app.bind_host not in {"127.0.0.1", "::1", "localhost"}
        ):
            raise BackupError("restore_review_requires_disabled_runtime_and_admin")

        def complete() -> dict[str, Any]:
            directory = PrivateDirectory(self.path.parent)
            connection = None
            try:
                connection = _connect(directory, self.path.name, writable=True)
                connection.execute("BEGIN IMMEDIATE")
                _stopped(connection)
                _verify_database(
                    connection, self.cipher, review=True, deadline=time.monotonic() + 300
                )
                # Completed recovery history remains in subsequent backups.
                # Only the one outstanding restore can authorize this review;
                # a historically valid backup ID must not clear a newer gate.
                unreviewed = connection.execute(
                    "SELECT object_id FROM audit_events WHERE event='database_restored_held' "
                    "EXCEPT SELECT object_id FROM audit_events "
                    "WHERE event='database_restore_review_completed' LIMIT 2"
                ).fetchall()
                if [row[0] for row in unreviewed] != [backup_id]:
                    raise BackupError("restore_review_identity_mismatch")
                if (
                    connection.execute(
                        "SELECT 1 FROM actions WHERE state IN ('queued','dispatching') LIMIT 1"
                    ).fetchone()
                    or connection.execute(
                        "SELECT 1 FROM deliveries WHERE state IN ('pending','sending') LIMIT 1"
                    ).fetchone()
                ):
                    raise BackupError("restore_review_unheld_work")
                for query in (
                    "SELECT 1 FROM bindings WHERE state='active' AND dispatch_paused=false LIMIT 1",
                    "SELECT 1 FROM zulip_queues WHERE state='active' LIMIT 1",
                    "SELECT 1 FROM command_receipts WHERE state='processing' LIMIT 1",
                    "SELECT 1 FROM admin_sessions LIMIT 1",
                ):
                    if connection.execute(query).fetchone():
                        raise BackupError("restore_review_unheld_work")
                connection.execute(
                    "UPDATE maintenance_flags SET pending=false WHERE name=?", (REVIEW_FLAG,)
                )
                connection.execute(
                    "INSERT INTO audit_events (id,actor,event,object_id,created_at) VALUES (?,?,?,?,?)",
                    (
                        str(uuid4()),
                        "operator",
                        "database_restore_review_completed",
                        backup_id,
                        time.time(),
                    ),
                )
                connection.commit()
                return {
                    "backup_id": backup_id,
                    "review_completed": True,
                    "runtime_enabled": False,
                    "held_actions_resumed": False,
                    "upstream_mutations": 0,
                }
            finally:
                if connection is not None:
                    connection.close()
                directory.close()

        return await _thread(complete)


async def restore_sqlite_backup(
    backup: Path,
    destination: Path,
    cipher: EnvelopeCipher,
    *,
    key_ref: str,
    max_bytes: int = 64 * 1024**3,
    maximum_seconds: float = 300,
) -> dict[str, Any]:
    return await _thread(
        lambda: _restore(backup, destination, cipher, key_ref, max_bytes, maximum_seconds)
    )
