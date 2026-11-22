"""Offline PostgreSQL logical backup and authenticated empty-database import.

Only fixed current bridge metadata becomes SQL. The archive supplies typed data
and authenticated hashes, never executable DDL. No upstream client is created.
"""

import asyncio
import hashlib
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import uuid4

import sqlalchemy as sa
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncConnection

from jt_oz_bridge import __version__
from jt_oz_bridge.config import Settings
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.backups import (
    MAX_ARTIFACT,
    MAX_CONFIG,
    MAX_FILES,
    MAX_METADATA,
    REVIEW_FLAG,
    BackupError,
    BackupFile,
    _artifact_files,
    _connect,
    _json,
    _limits,
    _manifest,
    _parse_json,
    _settings_toml,
    _verify_artifact,
    _verify_database,
)
from jt_oz_bridge.storage.backup_files import PrivateDirectory, beneath
from jt_oz_bridge.storage.database import (
    CURRENT_REVISION,
    PG_MAINTENANCE_LOCK,
    Database,
    upgrade_in_transaction,
)
from jt_oz_bridge.storage.logical_archive import (
    MAX_ROWS,
    TableWriter,
    authenticate_row,
    checksum,
    encode_row,
    normalized,
    raw_metadata,
    read_rows,
    row_file,
    schema_spec,
)
from jt_oz_bridge.storage.payload_keys import verify_keys
from jt_oz_bridge.storage.schema import Base

FORMAT: Literal["jt-oz-bridge-postgresql-logical-backup-v1"] = (
    "jt-oz-bridge-postgresql-logical-backup-v1"
)
MAINTENANCE_LOCK = PG_MAINTENANCE_LOCK
RUNTIME_FLAGS = (
    "enabled",
    "native_mirror_enabled",
    "native_drafts_enabled",
    "file_returns_enabled",
    "generated_returns_enabled",
    "workspace_inputs_enabled",
    "workspace_menus_enabled",
    "session_creation_enabled",
    "zulip_recovery_enabled",
)


class SequenceState(ControlModel):
    value: int = Field(strict=True, ge=1, le=2**63 - 1)
    called: bool = Field(strict=True)


class LogicalManifest(ControlModel):
    format: Literal["jt-oz-bridge-postgresql-logical-backup-v1"]
    backup_id: str
    created_at: float = Field(gt=0, allow_inf_nan=False)
    package_version: str
    schema_revision: str
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    key_id: str
    encryption_keys_embedded: Literal[False]
    files: dict[str, BackupFile] = Field(min_length=2, max_length=MAX_FILES)
    table_counts: dict[str, Annotated[int, Field(strict=True, ge=0, le=MAX_ROWS)]]
    sequences: dict[str, SequenceState]


def tables() -> dict[str, sa.Table]:
    return dict(raw_metadata().tables)


def insertion_order() -> list[str]:
    return [table.name for table in Base.metadata.sorted_tables] + ["alembic_version"]


def ordered(table: sa.Table, dialect: str) -> sa.Select[Any]:
    keys = [
        column.collate("C" if dialect == "postgresql" else "BINARY")
        if isinstance(column.type, sa.String)
        else column
        for column in table.primary_key
    ]
    if not keys:
        raise BackupError("owned_table_primary_key_required")
    return sa.select(table).order_by(*keys)


async def transaction_settings(connection: AsyncConnection, deadline: float) -> None:
    remaining = max(1, int((deadline - time.monotonic()) * 1000))
    await connection.execute(
        sa.text("SELECT pg_catalog.set_config('lock_timeout', :timeout, true)"),
        {"timeout": str(min(5000, remaining)) + "ms"},
    )
    await connection.execute(
        sa.text("SELECT pg_catalog.set_config('statement_timeout', :timeout, true)"),
        {"timeout": str(remaining) + "ms"},
    )
    await connection.execute(
        sa.text("SELECT pg_catalog.pg_advisory_xact_lock(:identity)"),
        {"identity": MAINTENANCE_LOCK},
    )


async def exact_schema(connection: AsyncConnection, *, empty: bool = False) -> None:
    def inspect(sync: sa.Connection) -> None:
        inspector = sa.inspect(sync)
        namespaces = set(inspector.get_schema_names()) - {"information_schema", "pg_catalog"}
        namespaces = {name for name in namespaces if not name.startswith("pg_")}
        if namespaces != {"public"}:
            raise BackupError("postgres_requires_dedicated_public_database")
        names = set(inspector.get_table_names(schema="public"))
        expected = set(schema_spec())
        if names != (set() if empty else expected):
            raise BackupError(
                "postgres_target_not_empty" if empty else "postgres_owned_schema_mismatch"
            )
        if inspector.get_view_names(schema="public") or inspector.get_materialized_view_names(
            schema="public"
        ):
            raise BackupError("postgres_views_not_owned_backup_data")
        if empty:
            if inspector.get_sequence_names(schema="public"):
                raise BackupError("postgres_target_not_empty")
            objects = sync.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'"
                )
            )
            types = sync.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public'"
                )
            )
            if objects or types:
                raise BackupError("postgres_target_not_empty")
            return
        for name, descriptor in schema_spec().items():
            actual = {c["name"]: c for c in inspector.get_columns(name, schema="public")}
            if set(actual) != {c["name"] for c in descriptor["columns"]}:
                raise BackupError("postgres_column_inventory_mismatch")
            for column in descriptor["columns"]:
                found = actual[column["name"]]
                expected_type = column["kind"]
                types = {
                    "cipher": sa.LargeBinary,
                    "bytes": sa.LargeBinary,
                    "bool": sa.Boolean,
                    "int32": sa.Integer,
                    "int64": sa.BigInteger,
                    "float": sa.Float,
                    "str": sa.String,
                    "json": sa.JSON,
                }
                if (
                    not isinstance(found["type"], types[expected_type])
                    or found["nullable"] != column["nullable"]
                ):
                    raise BackupError("postgres_column_type_or_nullability_mismatch")
                if expected_type == "int32" and isinstance(found["type"], sa.BigInteger):
                    raise BackupError("postgres_integer_width_mismatch")
                if (
                    expected_type == "str"
                    and getattr(found["type"], "length", None) != column["length"]
                ):
                    raise BackupError("postgres_string_width_mismatch")
            primary = inspector.get_pk_constraint(name, schema="public")["constrained_columns"]
            if set(primary) != {c["name"] for c in descriptor["columns"] if c["primary"]}:
                raise BackupError("postgres_primary_key_mismatch")
            actual_fk = sorted(
                [
                    [
                        local,
                        fk["referred_table"] + "." + remote,
                        fk.get("options", {}).get("ondelete"),
                        fk.get("options", {}).get("onupdate"),
                    ]
                    for fk in inspector.get_foreign_keys(name, schema="public")
                    for local, remote in zip(
                        fk["constrained_columns"], fk["referred_columns"], strict=True
                    )
                ],
                key=repr,
            )
            if actual_fk != descriptor["foreign_keys"]:
                raise BackupError("postgres_foreign_key_inventory_mismatch")
            actual_unique = sorted(
                sorted(c["column_names"])
                for c in inspector.get_unique_constraints(name, schema="public")
            )
            if actual_unique != sorted(sorted(c) for c in descriptor["unique"]):
                raise BackupError("postgres_unique_constraint_inventory_mismatch")
            fixed = Base.metadata.tables.get(name)
            if fixed is not None:
                expected_indexes = sorted(
                    (i.name, bool(i.unique), tuple(c.name for c in i.columns))
                    for i in fixed.indexes
                )
                actual_indexes = sorted(
                    (i["name"], bool(i["unique"]), tuple(i["column_names"]))
                    for i in inspector.get_indexes(name, schema="public")
                    if not i.get("duplicates_constraint")
                )
                if actual_indexes != expected_indexes:
                    raise BackupError("postgres_index_inventory_mismatch")
                expected_checks = {
                    c.name for c in fixed.constraints if isinstance(c, sa.CheckConstraint)
                }
                if {
                    c["name"] for c in inspector.get_check_constraints(name, schema="public")
                } != expected_checks:
                    raise BackupError("postgres_check_constraint_inventory_mismatch")

    await connection.run_sync(inspect)
    unknown = await connection.scalar(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='public'"
        )
    )
    dangerous = await connection.scalar(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relrowsecurity"
        )
    )
    triggers = await connection.scalar(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal"
        )
    )
    if unknown or dangerous or triggers:
        raise BackupError("postgres_nonmetadata_execution_objects_forbidden")
    owned = await connection.scalar(
        sa.text(
            "SELECT pg_catalog.pg_get_userbyid(datdba)=current_user FROM pg_catalog.pg_database "
            "WHERE datname=current_database()"
        )
    )
    if owned is not True:
        raise BackupError("postgres_dedicated_database_owner_required")


async def stopped(connection: AsyncConnection, *, review: bool = False) -> None:
    if await connection.scalar(
        sa.text("SELECT count(*) FROM worker_leases WHERE expires_at>:now"), {"now": time.time()}
    ):
        raise BackupError("postgres_maintenance_requires_stopped_consumers")
    flags = set(
        (
            await connection.execute(sa.text("SELECT name FROM maintenance_flags WHERE pending"))
        ).scalars()
    )
    if flags != ({REVIEW_FLAG} if review else set()):
        raise BackupError("postgres_maintenance_pending")
    if (
        await connection.execute(sa.text("SELECT version_num FROM alembic_version"))
    ).scalars().all() != [CURRENT_REVISION]:
        raise BackupError("postgres_schema_revision_mismatch")


async def lock_tables(connection: AsyncConnection) -> None:
    # Identifiers come exclusively from current metadata, never an archive.
    quote = connection.dialect.identifier_preparer.quote
    names = ", ".join("public." + quote(name) for name in sorted(schema_spec()))
    await connection.execute(sa.text("LOCK TABLE " + names + " IN ACCESS EXCLUSIVE MODE"))


def serial_columns() -> dict[str, tuple[str, str]]:
    result = {}
    for table in Base.metadata.sorted_tables:
        column = table.autoincrement_column
        if column is not None:
            result[table.name + "." + column.name] = (table.name, column.name)
    return result


async def sequences(connection: AsyncConnection) -> dict[str, SequenceState]:
    result = {}
    for key, (table, column) in serial_columns().items():
        name = await connection.scalar(
            sa.text("SELECT pg_catalog.pg_get_serial_sequence(:table,:column)"),
            {"table": "public." + table, "column": column},
        )
        expected = "public." + table + "_" + column + "_seq"
        if name != expected:
            raise BackupError("postgres_sequence_identity_mismatch")
        quote = connection.dialect.identifier_preparer.quote
        row = (
            await connection.execute(
                sa.text(
                    "SELECT last_value,is_called FROM public." + quote(expected.split(".", 1)[1])
                )
            )
        ).one()
        result[key] = SequenceState(value=row[0], called=row[1])
    found = await connection.run_sync(
        lambda c: set(sa.inspect(c).get_sequence_names(schema="public"))
    )
    if found != {t + "_" + c + "_seq" for t, c in serial_columns().values()}:
        raise BackupError("postgres_sequence_inventory_mismatch")
    return result


async def hold(connection: AsyncConnection, identity: str) -> dict[str, int]:
    now = time.time()
    result = {}
    statements = [
        (
            "actions_held",
            "UPDATE actions SET state='held',version=version+1,status_reason='backup_restored_queued' WHERE state='queued'",
        ),
        (
            "actions_ambiguous",
            "UPDATE actions SET state='ambiguous',version=version+1,status_reason='backup_restored_dispatching' WHERE state='dispatching'",
        ),
        (
            "deliveries_held",
            "UPDATE deliveries SET state='held',version=version+1,updated_at=:now,status_reason='backup_restored_pending' WHERE state='pending'",
        ),
        (
            "deliveries_ambiguous",
            "UPDATE deliveries SET state='ambiguous',version=version+1,updated_at=:now,status_reason='backup_restored_sending' WHERE state='sending'",
        ),
        (
            "commands_ambiguous",
            "UPDATE command_receipts SET state='ambiguous',version=version+1,updated_at=:now WHERE state='processing'",
        ),
        (
            "commands_held",
            "UPDATE command_receipts SET state='held',version=version+1,updated_at=:now WHERE state='deferred'",
        ),
        (
            "bindings_paused",
            "UPDATE bindings SET dispatch_paused=true,queue_revision=queue_revision+1 WHERE state='active'",
        ),
        ("leases_revoked", "UPDATE worker_leases SET expires_at=0,fencing=fencing+1"),
        ("queues_expired", "UPDATE zulip_queues SET state='expired',updated_at=:now"),
        ("admin_sessions_invalidated", "DELETE FROM admin_sessions"),
    ]
    for key, statement in statements:
        value = await connection.execute(sa.text(statement), {"now": now})
        result[key] = value.rowcount
    updated = await connection.execute(
        sa.text("UPDATE maintenance_flags SET pending=true WHERE name=:name"), {"name": REVIEW_FLAG}
    )
    if not updated.rowcount:
        await connection.execute(
            sa.text("INSERT INTO maintenance_flags(name,pending) VALUES (:name,true)"),
            {"name": REVIEW_FLAG},
        )
    await connection.execute(
        sa.text(
            "INSERT INTO audit_events(id,actor,event,object_id,created_at) VALUES (:id,'operator','database_restored_held',:identity,:now)"
        ),
        {"id": str(uuid4()), "identity": identity, "now": now},
    )
    return result


class AuthenticatedSource:
    """One authenticated current-schema archive; all files remain descriptor-owned."""

    def __init__(self, path: Path, cipher: EnvelopeCipher, maximum: int, deadline: float):
        self.archive = PrivateDirectory(path)
        self.artifacts: PrivateDirectory | None = None
        self.sqlite: Any = None
        self.cipher, self.maximum, self.deadline = cipher, maximum, deadline
        self.logical = False
        self.file_pins: dict[tuple[str, str], tuple[int, ...]] = {}
        try:
            raw = self.archive.read("manifest.json", MAX_METADATA, deadline=deadline)
            header = _parse_json(raw)
            if header.get("format") == FORMAT:
                manifest = LogicalManifest.model_validate(header)
                from jt_oz_bridge.services.backups import _uuid

                _uuid(manifest.backup_id)
                opened = cipher.open(
                    self.archive.read("manifest.auth", MAX_METADATA + 1024, deadline=deadline),
                    {"purpose": "backup-manifest", "backup_id": manifest.backup_id},
                    max_plaintext_bytes=MAX_METADATA,
                )
                if opened != raw or raw != _json(manifest.model_dump(mode="json")):
                    raise BackupError("postgres_manifest_authentication_failed")
                if (
                    manifest.schema_revision != CURRENT_REVISION
                    or manifest.schema_sha256 != checksum(schema_spec())
                    or manifest.key_id != cipher.active_key_id
                    or set(manifest.table_counts) != set(schema_spec())
                    or set(manifest.sequences) != set(serial_columns())
                ):
                    raise BackupError("postgres_archive_current_schema_required")
                self.logical = True
                self.manifest: Any = manifest
            elif header.get("format") == "jt-oz-bridge-sqlite-backup-v1":
                self.manifest = _manifest(self.archive, cipher, maximum)
                self.pin_file("archive", "bridge.sqlite")
                self.sqlite = _connect(self.archive, "bridge.sqlite", writable=False)
                self.sqlite.execute("BEGIN")
                if (
                    _verify_database(self.sqlite, cipher, deadline=deadline)
                    != self.manifest.table_counts
                ):
                    raise BackupError("sqlite_archive_counts_changed")
                self._sqlite_schema()
            else:
                raise BackupError("unsupported_authenticated_backup_format")
            self.artifacts = PrivateDirectory(path / "artifacts")
            expected_rows = (
                {row_file(name) for name in schema_spec()} if self.logical else {"bridge.sqlite"}
            )
            ordinary = expected_rows | {"configuration.enc"}
            artifact_files = {
                name.removeprefix("artifacts/")
                for name in self.manifest.files
                if name.startswith("artifacts/")
            }
            if set(self.manifest.files) != ordinary | {"artifacts/" + n for n in artifact_files}:
                raise BackupError("exact_archive_file_inventory_required")
            if self.archive.names() != ordinary | {"manifest.json", "manifest.auth", "artifacts"}:
                raise BackupError("archive_untracked_files")
            if self.artifacts.names() != artifact_files:
                raise BackupError("archive_artifact_file_inventory")
            self.expected_names = self.archive.names()
            self.expected_artifacts = artifact_files
            consumed = len(raw) + len(self.archive.read("manifest.auth", MAX_METADATA + 1024))
            for name, record in self.manifest.files.items():
                folder, filename = (
                    (self.artifacts, name[10:])
                    if name.startswith("artifacts/")
                    else (self.archive, name)
                )
                self.pin_file("artifacts" if name.startswith("artifacts/") else "archive", filename)
                if (
                    folder.record(filename, min(record.size, maximum), deadline=deadline)
                    != record.model_dump()
                ):
                    raise BackupError("archive_file_integrity_failed")
                consumed += record.size
                if consumed > maximum:
                    raise BackupError("archive_total_size_limit")
            configuration = cipher.open(
                self.archive.read("configuration.enc", MAX_CONFIG + 1024, deadline=deadline),
                {"purpose": "backup-configuration", "backup_id": self.manifest.backup_id},
                max_plaintext_bytes=MAX_CONFIG,
            )
            self.settings = Settings.model_validate(_parse_json(configuration))
            keys: set[str] = set()
            for name in schema_spec():
                for row in self.rows(name):
                    keys.update(authenticate_row(name, dict(row), cipher))
                    if name == "alembic_version" and row["version_num"] != CURRENT_REVISION:
                        raise BackupError("archive_schema_row_mismatch")
                    if name == "worker_leases" and row["expires_at"] > self.manifest.created_at:
                        raise BackupError("archive_source_consumer_was_active")
                    if name == "maintenance_flags" and row["pending"]:
                        raise BackupError("archive_source_maintenance_pending")
            if (
                cipher.active_key_id not in keys
                or self.manifest.table_counts["alembic_version"] != 1
            ):
                raise BackupError("archive_active_key_or_revision_missing")
            self.artifact_rows = bounded_rows(self.rows("artifacts"), 10000)
            validate_artifact_rows(
                self.artifact_rows, bounded_rows(self.rows("artifact_budgets"), 1)
            )
            objects = _artifact_files(self.artifact_rows, self.artifacts.names())
            for name, artifact_row in objects.items():
                if name.endswith(".bin") and artifact_row["state"] == "ready":
                    _verify_artifact(
                        artifact_row,
                        self.artifacts.read(name, MAX_ARTIFACT, deadline=deadline),
                        cipher,
                    )
            self.sequence_values = self._sequences()
            self.require_unchanged()
        except BaseException:
            self.close()
            raise

    def file_identity(self, scope: str, name: str) -> tuple[int, ...]:
        directory = self.artifacts if scope == "artifacts" else self.archive
        assert directory is not None
        fd = directory.open_file(name)
        try:
            info = os.fstat(fd)
            return (
                info.st_dev,
                info.st_ino,
                info.st_uid,
                info.st_gid,
                info.st_mode,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        finally:
            os.close(fd)

    def pin_file(self, scope: str, name: str) -> None:
        key = (scope, name)
        actual = self.file_identity(scope, name)
        if key in self.file_pins and self.file_pins[key] != actual:
            raise BackupError("authenticated_source_file_changed")
        self.file_pins[key] = actual

    def require_unchanged(self) -> None:
        # In particular, bind SQLite's read transaction to the authenticated
        # original file: later page changes or a WAL/SHM sidecar are not accepted.
        assert self.artifacts is not None
        self.archive.verify()
        self.artifacts.verify()
        if (
            self.archive.names() != self.expected_names
            or self.artifacts.names() != self.expected_artifacts
        ):
            raise BackupError("authenticated_source_inventory_changed")
        for (scope, name), expected in self.file_pins.items():
            if self.file_identity(scope, name) != expected:
                raise BackupError("authenticated_source_file_changed")

    def _sqlite_schema(self) -> None:
        for name, descriptor in schema_spec().items():
            found = self.sqlite.execute('PRAGMA table_info("' + name + '")').fetchall()
            actual = {row[1]: row for row in found}
            if set(actual) != {c["name"] for c in descriptor["columns"]}:
                raise BackupError("sqlite_exact_column_inventory_required")
            for column in descriptor["columns"]:
                row = actual[column["name"]]
                declared = row[2].upper()
                allowed = {
                    "cipher": ("BLOB",),
                    "bytes": ("BLOB",),
                    "bool": ("BOOLEAN",),
                    "int32": ("INTEGER",),
                    "int64": ("BIGINT", "INTEGER"),
                    "float": ("FLOAT", "REAL"),
                    "str": ("VARCHAR", "TEXT"),
                    "json": ("JSON",),
                }[column["kind"]]
                if not any(declared == item or declared.startswith(item + "(") for item in allowed):
                    raise BackupError("sqlite_column_type_mismatch")
                if bool(row[3]) != (not column["nullable"]) or bool(row[5]) != column["primary"]:
                    raise BackupError("sqlite_nullability_or_key_mismatch")
            foreign = sorted(
                [
                    [
                        r[3],
                        r[2] + "." + r[4],
                        None if r[6] == "NO ACTION" else r[6],
                        None if r[5] == "NO ACTION" else r[5],
                    ]
                    for r in self.sqlite.execute('PRAGMA foreign_key_list("' + name + '")')
                ],
                key=repr,
            )
            if foreign != descriptor["foreign_keys"]:
                raise BackupError("sqlite_foreign_key_inventory_mismatch")

    def rows(self, name: str) -> Iterator[dict[str, Any]]:
        if name not in schema_spec():
            raise BackupError("unknown_archive_table")
        if self.logical:
            record = self.manifest.files[row_file(name)].model_dump()
            yield from read_rows(
                self.archive, name, self.manifest.table_counts[name], record, self.deadline
            )
            return
        descriptor = schema_spec()[name]["columns"]
        names = ",".join('"' + c["name"] + '"' for c in descriptor)
        keys = ",".join(
            '"' + c["name"] + '" COLLATE BINARY' if c["kind"] == "str" else '"' + c["name"] + '"'
            for c in descriptor
            if c["primary"]
        )
        cursor = self.sqlite.execute("SELECT " + names + ' FROM "' + name + '" ORDER BY ' + keys)
        seen = 0
        try:
            for raw in cursor:
                if time.monotonic() >= self.deadline or seen >= MAX_ROWS:
                    raise BackupError("archive_row_deadline_or_count")
                seen += 1
                yield {
                    c["name"]: normalized(value, c, sqlite=True)
                    for c, value in zip(descriptor, raw, strict=True)
                }
        finally:
            cursor.close()
        if seen != self.manifest.table_counts[name]:
            raise BackupError("archive_row_count_changed")

    def _sequences(self) -> dict[str, SequenceState]:
        if self.logical:
            return dict(self.manifest.sequences)
        result = {}
        has_sequence = self.sqlite.execute(
            "SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'"
        ).fetchone()
        for key, (table, column) in serial_columns().items():
            maximum = (
                self.sqlite.execute('SELECT MAX("' + column + '") FROM "' + table + '"').fetchone()[
                    0
                ]
                or 0
            )
            stored = (
                self.sqlite.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name=?", (table,)
                ).fetchone()
                if has_sequence
                else None
            )
            value = max(maximum, stored[0] if stored else 0)
            result[key] = SequenceState(value=max(1, value), called=value > 0)
        return result

    def close(self) -> None:
        if self.sqlite is not None:
            self.sqlite.close()
            self.sqlite = None
        if self.artifacts is not None:
            self.artifacts.close()
            self.artifacts = None
        self.archive.close()


def bounded_rows(rows: Iterator[dict[str, Any]], maximum: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        if len(result) >= maximum:
            raise BackupError("backup_metadata_object_limit")
        result.append(row)
    return result


def guarded_chunks(
    source: PrivateDirectory,
    name: str,
    maximum: int,
    target: PrivateDirectory,
    reserve: int,
    deadline: float,
) -> Iterator[bytes]:
    for block in source.chunks(name, maximum, deadline=deadline):
        if target.free_bytes() < reserve + len(block):
            raise BackupError("backup_space_reserve_reached")
        yield block


def validate_artifact_rows(rows: list[dict[str, Any]], budgets: list[dict[str, Any]]) -> None:
    from jt_oz_bridge.services.backups import _uuid

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
    expected = sum(row["reserved_bytes"] for row in rows)
    objects = sum(row["reserved_bytes"] > 0 for row in rows)
    if budgets:
        if budgets != [{"id": "global", "reserved_bytes": expected, "object_count": objects}]:
            raise BackupError("backup_artifact_budget_invalid")
    elif expected or objects:
        raise BackupError("backup_artifact_budget_missing")


class PostgresBackupService:
    def __init__(self, db: Database):
        if db.engine.dialect.name != "postgresql" or db.cipher is None:
            raise BackupError("encrypted_postgresql_dataset_required")
        self.db, self.cipher = db, db.cipher

    async def create(
        self,
        output: Path,
        settings: Settings,
        *,
        artifacts: Path | None = None,
        max_bytes: int = 64 * 1024**3,
        maximum_seconds: float = 300,
    ) -> dict[str, Any]:
        _limits(max_bytes, maximum_seconds)
        async with asyncio.timeout(maximum_seconds):
            return await self._create(
                output,
                settings,
                artifacts=artifacts,
                max_bytes=max_bytes,
                maximum_seconds=maximum_seconds,
            )

    async def _create(
        self,
        output: Path,
        settings: Settings,
        *,
        artifacts: Path | None = None,
        max_bytes: int = 64 * 1024**3,
        maximum_seconds: float = 300,
    ) -> dict[str, Any]:
        _limits(max_bytes, maximum_seconds)
        if settings.database.url is not None or not settings.database.url_ref:
            raise BackupError("postgres_configuration_requires_secret_reference")
        if output == settings.app.state_dir or output.is_relative_to(settings.app.state_dir):
            raise BackupError("backup_output_must_be_outside_live_state")
        deadline = time.monotonic() + maximum_seconds
        archive = PrivateDirectory(output, create=True)
        artifact_source = artifact_target = None
        files = {}
        counts = {}
        consumed = 0
        key_ids: set[str] = set()
        try:
            artifact_target = PrivateDirectory(output / "artifacts", create=True)
            if artifacts is not None:
                artifact_source = PrivateDirectory(artifacts)
                if beneath(artifact_source, output.parent):
                    raise BackupError("backup_output_must_be_outside_artifacts")
            async with self.db.engine.connect() as initial:
                connection = await initial.execution_options(isolation_level="SERIALIZABLE")
                async with connection.begin():
                    await transaction_settings(connection, deadline)
                    await exact_schema(connection)
                    await lock_tables(connection)
                    await exact_schema(connection)
                    await stopped(connection)
                    await connection.run_sync(verify_keys)
                    metadata = tables()
                    artifact_rows = (
                        (await connection.execute(sa.select(metadata["artifacts"]).limit(10001)))
                        .mappings()
                        .all()
                    )
                    budgets = (
                        (await connection.execute(sa.select(metadata["artifact_budgets"]).limit(2)))
                        .mappings()
                        .all()
                    )
                    rows = [dict(row) for row in artifact_rows]
                    validate_artifact_rows(rows, [dict(row) for row in budgets])
                    artifact_map = _artifact_files(
                        rows, artifact_source.names() if artifact_source else set()
                    )
                    for name in sorted(metadata):
                        writer = TableWriter(archive, name, max_bytes - consumed, deadline)
                        try:
                            async with connection.stream(
                                ordered(metadata[name], "postgresql"),
                                execution_options={"yield_per": 1},
                            ) as stream:
                                async for row in stream.mappings():
                                    key_ids.update(authenticate_row(name, dict(row), self.cipher))
                                    if (
                                        archive.free_bytes()
                                        < settings.retention.reserve_free_disk_bytes
                                        + MAX_METADATA * 2
                                        + 160 * 1024**2
                                    ):
                                        raise BackupError("backup_space_reserve_reached")
                                    writer.row(dict(row))
                            files[row_file(name)] = BackupFile(**writer.finish())
                            counts[name] = writer.count
                            consumed += files[row_file(name)].size
                        finally:
                            writer.close()
                    sequence_values = await sequences(connection)
                    if self.cipher.active_key_id not in key_ids:
                        raise BackupError("backup_active_database_key_missing")
                    for name, artifact_row in sorted(artifact_map.items()):
                        assert artifact_source is not None
                        if name.endswith(".bin") and artifact_row["state"] == "ready":
                            _verify_artifact(
                                artifact_row,
                                artifact_source.read(name, MAX_ARTIFACT, deadline=deadline),
                                self.cipher,
                            )
                        record = artifact_target.copy(
                            name,
                            guarded_chunks(
                                artifact_source,
                                name,
                                max_bytes - consumed,
                                archive,
                                settings.retention.reserve_free_disk_bytes,
                                deadline,
                            ),
                            max_bytes - consumed,
                        )
                        files["artifacts/" + name] = BackupFile(**record)
                        consumed += record["size"]
            identity = str(uuid4())
            configuration = settings.model_dump_json().encode()
            if len(configuration) > MAX_CONFIG:
                raise BackupError("backup_configuration_limit_reached")
            sealed = self.cipher.seal(
                configuration, {"purpose": "backup-configuration", "backup_id": identity}
            )
            if consumed + len(sealed) + MAX_METADATA * 2 > max_bytes:
                raise BackupError("backup_total_limit_reached")
            files["configuration.enc"] = BackupFile(**archive.write("configuration.enc", sealed))
            consumed += files["configuration.enc"].size
            manifest = LogicalManifest(
                format=FORMAT,
                backup_id=identity,
                created_at=time.time(),
                package_version=__version__,
                schema_revision=CURRENT_REVISION,
                schema_sha256=checksum(schema_spec()),
                key_id=self.cipher.active_key_id,
                encryption_keys_embedded=False,
                files=files,
                table_counts=counts,
                sequences=sequence_values,
            )
            raw = _json(manifest.model_dump(mode="json"))
            signature = self.cipher.seal(raw, {"purpose": "backup-manifest", "backup_id": identity})
            if len(raw) > MAX_METADATA or consumed + len(raw) + len(signature) > max_bytes:
                raise BackupError("backup_metadata_or_total_limit_reached")
            archive.write("manifest.json", raw)
            archive.write("manifest.auth", signature)
            return {
                "backup_id": identity,
                "schema_revision": CURRENT_REVISION,
                "backend": "postgresql",
                "table_counts": counts,
                "files": len(files),
                "bytes": consumed + len(raw) + len(signature),
                "keys_embedded": False,
                "source_changed": False,
            }
        finally:
            for directory in (artifact_source, artifact_target, archive):
                if directory is not None:
                    directory.close()

    async def complete_review(self, backup_id: str, settings: Settings) -> dict[str, Any]:
        async with asyncio.timeout(300):
            return await self._complete_review(backup_id, settings)

    async def _complete_review(self, backup_id: str, settings: Settings) -> dict[str, Any]:
        from jt_oz_bridge.services.backups import _uuid

        _uuid(backup_id)
        require_inert(settings)
        deadline = time.monotonic() + 300
        async with self.db.engine.begin() as connection:
            await transaction_settings(connection, deadline)
            await exact_schema(connection)
            await lock_tables(connection)
            await exact_schema(connection)
            await stopped(connection, review=True)
            await connection.run_sync(verify_keys)
            outstanding = (
                (
                    await connection.execute(
                        sa.text(
                            "SELECT object_id FROM audit_events WHERE event='database_restored_held' "
                            "EXCEPT SELECT object_id FROM audit_events "
                            "WHERE event='database_restore_review_completed' LIMIT 2"
                        )
                    )
                )
                .scalars()
                .all()
            )
            if outstanding != [backup_id]:
                raise BackupError("restore_review_identity_mismatch")
            for statement in (
                "SELECT 1 FROM actions WHERE state IN ('queued','dispatching') LIMIT 1",
                "SELECT 1 FROM deliveries WHERE state IN ('pending','sending') LIMIT 1",
                "SELECT 1 FROM command_receipts WHERE state IN ('processing','deferred') LIMIT 1",
                "SELECT 1 FROM bindings WHERE state='active' AND dispatch_paused=false LIMIT 1",
                "SELECT 1 FROM zulip_queues WHERE state='active' LIMIT 1",
                "SELECT 1 FROM admin_sessions LIMIT 1",
            ):
                if await connection.scalar(sa.text(statement)):
                    raise BackupError("restore_review_unheld_work")
            await authenticate_database(connection, self.cipher, deadline)
            await connection.execute(
                sa.text("UPDATE maintenance_flags SET pending=false WHERE name=:flag"),
                {"flag": REVIEW_FLAG},
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO audit_events(id,actor,event,object_id,created_at) "
                    "VALUES (:id,'operator','database_restore_review_completed',:backup,:now)"
                ),
                {"id": str(uuid4()), "backup": backup_id, "now": time.time()},
            )
        return {
            "backup_id": backup_id,
            "review_completed": True,
            "runtime_enabled": False,
            "held_actions_resumed": False,
            "upstream_mutations": 0,
        }


def require_inert(settings: Settings) -> None:
    if (
        any(getattr(settings.runtime, flag) for flag in RUNTIME_FLAGS)
        or settings.admin.enabled
        or settings.app.bind_host not in {"127.0.0.1", "::1", "localhost"}
    ):
        raise BackupError("postgres_restore_requires_inert_loopback_configuration")
    if settings.database.url is not None or not settings.database.url_ref:
        raise BackupError("postgres_configuration_requires_secret_reference")


def check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise BackupError("postgres_backup_deadline_reached")


async def authenticate_database(
    connection: AsyncConnection,
    cipher: EnvelopeCipher,
    deadline: float,
) -> None:
    keys: set[str] = set()
    for name, table in tables().items():
        async with connection.stream(
            ordered(table, "postgresql"), execution_options={"yield_per": 1}
        ) as stream:
            async for row in stream.mappings():
                check_deadline(deadline)
                keys.update(authenticate_row(name, dict(row), cipher))
    if cipher.active_key_id not in keys:
        raise BackupError("postgres_active_database_key_missing")


async def compare_import(
    connection: AsyncConnection,
    source: AuthenticatedSource,
    deadline: float,
) -> dict[str, int]:
    """Compare every original cell, including ciphertext, before held transitions."""
    counts = {}
    for name, table in tables().items():
        original = hashlib.sha256()
        count = 0
        for row in source.rows(name):
            check_deadline(deadline)
            for part in encode_row(name, row):
                original.update(part)
        actual = hashlib.sha256()
        async with connection.stream(
            ordered(table, "postgresql"), execution_options={"yield_per": 1}
        ) as stream:
            async for actual_row in stream.mappings():
                check_deadline(deadline)
                for part in encode_row(name, dict(actual_row)):
                    actual.update(part)
                authenticate_row(name, dict(actual_row), source.cipher)
                count += 1
        if count != source.manifest.table_counts[name] or actual.digest() != original.digest():
            raise BackupError("postgres_import_original_cell_mismatch")
        counts[name] = count
    return counts


async def _restore_postgres_backup(
    backup: Path,
    destination: Path,
    database: Database,
    settings: Settings,
    *,
    max_bytes: int = 64 * 1024**3,
    maximum_seconds: float = 300,
) -> dict[str, Any]:
    """Authenticate an archive, then build only an empty, dedicated PostgreSQL DB.

    DDL, data and held transitions share one PostgreSQL transaction. Files are
    staged before commit; an unknown commit outcome is never a retry permission.
    There is no operation against the source database or upstream service.
    """
    _limits(max_bytes, maximum_seconds)
    require_inert(settings)
    if database.engine.dialect.name != "postgresql" or database.cipher is None:
        raise BackupError("encrypted_postgresql_target_required")
    deadline = time.monotonic() + maximum_seconds
    source = AuthenticatedSource(backup, database.cipher, max_bytes, deadline)
    output = outgoing = None
    try:
        if (
            destination == backup
            or beneath(source.archive, destination.parent)
            or destination == source.settings.app.state_dir
            or destination.is_relative_to(source.settings.app.state_dir)
        ):
            raise BackupError("restore_destination_must_be_outside_backup_and_original_state")
        # Authentication has completed before opening the target connection or
        # creating the destination. Existing state is never an import target.
        output = PrivateDirectory(destination, create=True)
        outgoing = PrivateDirectory(destination / "artifacts", create=True)
        reserve = settings.retention.reserve_free_disk_bytes
        needed = sum(
            v.size
            for k, v in source.manifest.files.items()
            if k.startswith("artifacts/") or k == "configuration.enc"
        )
        if output.free_bytes() < reserve + needed + MAX_CONFIG:
            raise BackupError("restore_space_reserve_reached")
        assert source.artifacts is not None
        for name, record in source.manifest.files.items():
            if name.startswith("artifacts/"):
                filename = name.removeprefix("artifacts/")
                copied = outgoing.copy(
                    filename,
                    source.artifacts.chunks(filename, record.size, deadline=deadline),
                    record.size,
                )
            elif name == "configuration.enc":
                copied = output.copy(
                    "configuration.snapshot.enc",
                    source.archive.chunks(name, record.size, deadline=deadline),
                    record.size,
                )
            else:
                continue
            if copied != record.model_dump():
                raise BackupError("backup_changed_during_restore")
        values = source.settings.model_dump(mode="json")
        values["app"].update(state_dir=str(destination), bind_host="127.0.0.1")
        values["database"].update(url=None, url_ref=settings.database.url_ref)
        values["runtime"].update({flag: False for flag in RUNTIME_FLAGS})
        values["admin"].update(enabled=False, public_url="")
        values["security"]["secret_key_ref"] = settings.security.secret_key_ref
        safe = Settings.model_validate(values)
        output.write("restored-config.toml", _settings_toml(safe))
        source.require_unchanged()
        async with database.engine.connect() as initial:
            connection = await initial.execution_options(isolation_level="SERIALIZABLE")
            async with connection.begin():
                await transaction_settings(connection, deadline)
                await exact_schema(connection, empty=True)
                check_deadline(deadline)
                if await upgrade_in_transaction(connection, str(uuid4())):
                    raise BackupError("postgres_import_target_was_not_empty")
                await exact_schema(connection)
                metadata = tables()
                # Only fixed migrations' fresh canary/version rows may exist.
                for name, table in metadata.items():
                    count = await connection.scalar(sa.select(sa.func.count()).select_from(table))
                    if count and name not in {"payload_key_checks", "alembic_version"}:
                        raise BackupError("postgres_fresh_migration_created_unexpected_data")
                await connection.execute(metadata["payload_key_checks"].delete())
                await connection.execute(metadata["alembic_version"].delete())
                for name in insertion_order():
                    for row in source.rows(name):
                        check_deadline(deadline)
                        await connection.execute(metadata[name].insert().values(**row))
                await connection.run_sync(verify_keys)
                counts = await compare_import(connection, source, deadline)
                await exact_schema(connection)
                # Only sequences created in THIS transaction are touched. A
                # PostgreSQL setval on an existing sequence cannot be rolled back.
                for key, (table_name, column) in serial_columns().items():
                    actual = await connection.scalar(
                        sa.text("SELECT pg_catalog.pg_get_serial_sequence(:table,:column)"),
                        {"table": "public." + table_name, "column": column},
                    )
                    expected = "public." + table_name + "_" + column + "_seq"
                    if actual != expected:
                        raise BackupError("postgres_sequence_identity_mismatch")
                    state = source.sequence_values[key]
                    maximum = await connection.scalar(
                        sa.select(sa.func.max(metadata[table_name].c[column]))
                    )
                    if maximum is not None and (state.value < maximum or not state.called):
                        raise BackupError("postgres_sequence_before_original_ids")
                    await connection.execute(
                        sa.text(
                            "SELECT pg_catalog.setval(pg_catalog.to_regclass(:name),:value,:called)"
                        ),
                        {"name": actual, "value": state.value, "called": state.called},
                    )
                if await sequences(connection) != source.sequence_values:
                    raise BackupError("postgres_sequence_state_mismatch")
                held = await hold(connection, source.manifest.backup_id)
                await stopped(connection, review=True)
                await authenticate_database(connection, database.cipher, deadline)
                check_deadline(deadline)
                output.verify()
                outgoing.verify()
                source.archive.verify()
                source.artifacts.verify()
                source.require_unchanged()
        result = {
            "backup_id": source.manifest.backup_id,
            "schema_revision": CURRENT_REVISION,
            "source_backend": "postgresql" if source.logical else "sqlite",
            "target_backend": "postgresql",
            "original_table_counts": counts,
            "original_ciphertext_preserved": True,
            "held_recovery": held,
            "operator_review_required": True,
            "runtime_enabled": False,
            "admin_enabled": False,
            "upstream_mutations": 0,
            "keys_embedded": False,
        }
        # Published only after the server acknowledged commit. If this write or
        # commit acknowledgement fails, leave the destination inert for review;
        # never overwrite or retry against the now nonempty database.
        output.write("restore-report.json", _json(result))
        return result
    finally:
        if outgoing is not None:
            outgoing.close()
        if output is not None:
            output.close()
        source.close()


async def restore_postgres_backup(
    backup: Path,
    destination: Path,
    database: Database,
    settings: Settings,
    *,
    max_bytes: int = 64 * 1024**3,
    maximum_seconds: float = 300,
) -> dict[str, Any]:
    _limits(max_bytes, maximum_seconds)
    async with asyncio.timeout(maximum_seconds):
        return await _restore_postgres_backup(
            backup,
            destination,
            database,
            settings,
            max_bytes=max_bytes,
            maximum_seconds=maximum_seconds,
        )
