"""Isolation and real-migration equivalence of the synthetic empty DB fixture."""

import asyncio
import os
import re
import sqlite3
from contextlib import closing
from dataclasses import replace

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Grant

SCHEMA = "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"


def canonical_schema_row(row):
    """Keep DDL exact except independent plain single-line UNIQUE/FK ordering.

    Alembic batch reflection can emit those clauses in either order. Columns,
    names, clause contents, CHECK/PK/options, indices and triggers stay exact.
    Explicit conflict/action/deferral/collation clauses are never reordered.
    """
    kind, name, table, sql = row
    if kind != "table" or sql is None:
        return tuple(row)
    layout, independent = [], []
    pattern = r'^(?:CONSTRAINT\s+(?:"(?:[^"]|"")*"|[A-Za-z0-9_]+)\s+)?(?:UNIQUE|FOREIGN\s+KEY)\s*\('
    for line in sql.splitlines():
        clause = line.strip()
        if (
            re.match(pattern, clause)
            and clause.count("(") == clause.count(")")
            and not any(
                option in clause.upper()
                for option in ("ON CONFLICT", "ON DELETE", "ON UPDATE", "DEFERRABLE", "COLLATE")
            )
        ):
            independent.append(clause.removesuffix(","))
        else:
            layout.append(line)
    return kind, name, table, (tuple(layout), tuple(sorted(independent)))


async def schema(database):
    async with database.engine.connect() as connection:
        return [canonical_schema_row(row) for row in await connection.execute(text(SCHEMA))]


async def test_clone_has_current_schema_key_readiness_wal_and_foreign_keys(
    db, empty_database_template
):
    assert await db.ready()
    with closing(sqlite3.connect(empty_database_template.path)) as template:
        expected = [canonical_schema_row(row) for row in template.execute(SCHEMA)]
    assert await schema(db) == expected
    async with db.engine.connect() as connection:
        for pragma, expected_value in (
            ("journal_mode", "wal"),
            ("foreign_keys", 1),
            ("synchronous", 2),
        ):
            assert (
                await connection.execute(text("PRAGMA " + pragma))
            ).scalar_one() == expected_value
        for table in (
            "grants",
            "bindings",
            "actions",
            "deliveries",
            "admin_accounts",
            "admin_decisions",
            "audit_events",
            "worker_leases",
        ):
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM " + table))
            ).scalar_one() == 0


async def test_template_schema_matches_independent_real_fresh_migration(db, tmp_path):
    fresh = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "independent-fresh.db"),
        cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"),
    )
    try:
        await migrate(fresh.engine)
        assert await fresh.ready() and await schema(fresh) == await schema(db)
    finally:
        await fresh.close()


async def test_concurrent_clones_do_not_share_rows_leases_engines_or_cipher_instances(
    empty_database_template, tmp_path
):
    first, second = await asyncio.gather(
        empty_database_template.database(tmp_path / "first.db"),
        empty_database_template.database(tmp_path / "second.db"),
    )
    try:
        assert first.engine is not second.engine and first.cipher is not second.cipher
        assert first.cipher._keys is not second.cipher._keys
        async with first.sessions.begin() as session:
            session.add(
                Grant(
                    id="fixture-only",
                    realm_id="realm",
                    project_id="project",
                    user_id=7,
                    role="view",
                )
            )
        assert await DurableStore(first).acquire_lease("first") == 1
        assert await DurableStore(second).acquire_lease("second") == 1
        async with second.sessions() as session:
            assert not (await session.scalars(select(Grant))).all()
        async with first.sessions.begin() as session:
            session.add(
                Grant(
                    id="duplicate", realm_id="realm", project_id="project", user_id=7, role="view"
                )
            )
            with pytest.raises(IntegrityError):
                await session.flush()
    finally:
        await first.close()
        await second.close()


async def test_wrong_key_for_one_copy_does_not_validate_or_damage_other_copy(
    empty_database_template, tmp_path
):
    good = await empty_database_template.database(tmp_path / "good.db")
    bad = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "good.db"),
        cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"),
    )
    try:
        assert not await bad.ready() and await good.ready()
    finally:
        await bad.close()
        await good.close()


async def test_modified_template_is_rejected_before_creating_a_case_database(
    empty_database_template, tmp_path
):
    corrupted = tmp_path / "modified-template.db"
    corrupted.write_bytes(empty_database_template.path.read_bytes() + b"modified")
    snapshot = replace(empty_database_template, path=corrupted)
    destination = tmp_path / "must-not-exist.db"
    with pytest.raises(ValueError, match="template_changed"):
        await snapshot.database(destination)
    assert not destination.exists()


async def test_clone_never_overwrites_existing_file_or_reveals_template_key(
    empty_database_template, tmp_path
):
    destination = tmp_path / "existing.db"
    destination.write_bytes(b"existing-private-data")
    with pytest.raises(FileExistsError):
        await empty_database_template.database(destination)
    assert destination.read_bytes() == b"existing-private-data"
    assert repr(empty_database_template.key) not in repr(empty_database_template)


PLAIN_SCHEMA = """CREATE TABLE sample (
    id INTEGER PRIMARY KEY,
    actor INTEGER,
    value INTEGER NOT NULL,
    CHECK (value > 0),
    UNIQUE (actor),
    FOREIGN KEY(actor) REFERENCES parent (id)
)"""


def test_schema_signature_ignores_only_independent_plain_constraint_order_and_keeps_enforcement():
    reordered = PLAIN_SCHEMA.replace(
        "    UNIQUE (actor),\n    FOREIGN KEY(actor) REFERENCES parent (id)",
        "    FOREIGN KEY(actor) REFERENCES parent (id),\n    UNIQUE (actor)",
    )
    assert PLAIN_SCHEMA != reordered
    assert canonical_schema_row(
        ("table", "sample", "sample", PLAIN_SCHEMA)
    ) == canonical_schema_row(("table", "sample", "sample", reordered))
    for definition in (PLAIN_SCHEMA, reordered):
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            connection.execute(definition)
            connection.execute("INSERT INTO parent VALUES (1)")
            connection.execute("INSERT INTO sample VALUES (1,1,1)")
            for sql in [
                "INSERT INTO sample VALUES (2,1,1)",
                "INSERT INTO sample VALUES (3,99,1)",
                "INSERT INTO sample VALUES (4,NULL,0)",
                "INSERT INTO sample VALUES (5,NULL,NULL)",
                "INSERT INTO sample VALUES (1,NULL,1)",
            ]:
                with pytest.raises(sqlite3.IntegrityError):
                    connection.execute(sql)


@pytest.mark.parametrize(
    "changed",
    [
        PLAIN_SCHEMA.replace("UNIQUE (actor)", "UNIQUE (actor, value)"),
        PLAIN_SCHEMA.replace("REFERENCES parent", "REFERENCES other_parent"),
        PLAIN_SCHEMA.replace("value INTEGER NOT NULL", "value INTEGER"),
        PLAIN_SCHEMA.replace("CHECK (value > 0)", "CHECK (value >= 0)"),
        PLAIN_SCHEMA.replace(
            "actor INTEGER,\n    value INTEGER NOT NULL",
            "value INTEGER NOT NULL,\n    actor INTEGER",
        ),
        PLAIN_SCHEMA.replace("UNIQUE (actor)", "UNIQUE (actor) ON CONFLICT IGNORE"),
        PLAIN_SCHEMA.replace("REFERENCES parent (id)", "REFERENCES parent (id) ON DELETE CASCADE"),
    ],
    ids=[
        "unique-columns",
        "foreign-target",
        "nullable",
        "check",
        "column-order",
        "unique-conflict",
        "foreign-action",
    ],
)
def test_schema_signature_still_rejects_functional_constraint_column_or_option_changes(changed):
    assert canonical_schema_row(
        ("table", "sample", "sample", PLAIN_SCHEMA)
    ) != canonical_schema_row(("table", "sample", "sample", changed))


def test_schema_signature_keeps_non_table_objects_exact():
    first = ("index", "ix_sample", "sample", "CREATE INDEX ix_sample ON sample (actor)")
    second = ("index", "ix_sample", "sample", "CREATE UNIQUE INDEX ix_sample ON sample (value)")
    assert canonical_schema_row(first) == first and canonical_schema_row(
        first
    ) != canonical_schema_row(second)
