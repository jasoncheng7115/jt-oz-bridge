"""Stopped empty synthetic schema only; every case gets its own engine and file.

The ephemeral template key is held in process memory, never saved or used by a
service. Real migration tests continue to construct and migrate their own DBs.
"""

import asyncio
import hashlib
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.database import Database, migrate


@dataclass(frozen=True)
class EmptyDatabaseTemplate:
    path: Path
    sha256: str
    key: bytes = field(repr=False)

    def _copy(self, destination: Path) -> None:
        body = self.path.read_bytes()
        if hashlib.sha256(body).hexdigest() != self.sha256:
            raise ValueError("empty_test_database_template_changed")
        with destination.open("xb") as out:
            out.write(body)

    async def database(self, destination: Path) -> Database:
        await asyncio.to_thread(self._copy, destination)
        value = Database(
            "sqlite+aiosqlite:///" + str(destination),
            cipher=EnvelopeCipher({"test": self.key}, "test"),
        )
        try:
            if not await value.ready():
                raise ValueError("cloned_test_database_not_ready")
        except BaseException:
            await value.close()
            raise
        return value


def _freeze(source: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError("empty_test_database_template_already_exists")
    # sqlite3 context managers commit/rollback but do not close connections.
    # Explicit close completes the stopped snapshot before any case copies it.
    with (
        closing(sqlite3.connect("file:" + str(source) + "?mode=ro", uri=True)) as original,
        closing(sqlite3.connect(destination)) as snapshot,
    ):
        original.backup(snapshot)
        snapshot.execute("PRAGMA journal_mode=DELETE")
    destination.chmod(0o400)


async def build_empty_database_template(path: Path) -> EmptyDatabaseTemplate:
    key = os.urandom(32)
    bootstrap = path.with_suffix(".bootstrap.db")
    database = Database(
        "sqlite+aiosqlite:///" + str(bootstrap),
        cipher=EnvelopeCipher({"test": key}, "test"),
    )
    try:
        await migrate(database.engine)
        if not await database.ready():
            raise ValueError("fresh_test_database_migration_not_ready")
    finally:
        await database.close()
    await asyncio.to_thread(_freeze, bootstrap, path)
    body = await asyncio.to_thread(path.read_bytes)
    return EmptyDatabaseTemplate(path, hashlib.sha256(body).hexdigest(), key)
