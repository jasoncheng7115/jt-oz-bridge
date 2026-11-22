import asyncio
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import aiosqlite
from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.cipher_types import key_state, register, unregister
from jt_oz_bridge.storage.payload_keys import verify_keys
from jt_oz_bridge.storage.sessions import SessionFactory, WriteGate

CURRENT_REVISION = "0038_prompt_schedules"
# SQLite's busy timeout and this process's write-queue budget. A writer that
# still cannot start fails with ``database is locked``; nothing is retried
# silently beyond this. Thirty seconds rides out a busy burst of short writers.
DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 30000
_ALEMBIC_GATE = threading.Lock()
PG_MAINTENANCE_LOCK = 0x4A544F5A4241434B


async def _join_owned[T](task: asyncio.Task[T]) -> T:
    # The caller has already been cancelled. Join this exact owned operation;
    # further cancellation must not abandon its connection/close in flight.
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                break
    return task.result()


async def _sqlite_owned_connect(
    creator: Callable[..., Awaitable[aiosqlite.Connection]], *args: Any, **kwargs: Any
) -> aiosqlite.Connection:
    async def connect() -> aiosqlite.Connection:
        connection = creator(*args, **kwargs)
        # Match the installed SQLAlchemy aiosqlite adapter for this newly
        # constructed driver object only. Custom coroutine creators retain
        # their own thread policy. No global driver or pool is patched.
        if isinstance(connection, threading.Thread):
            connection.daemon = True
        elif isinstance(connection, aiosqlite.Connection):
            connection._thread.daemon = True
        return await connection

    pending = asyncio.create_task(connect())
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError as cancelled:
        try:
            connection = await _join_owned(pending)
        except (Exception, asyncio.CancelledError) as error:
            # No connection was returned. Preserve original cancellation and
            # expose any actual connector failure as its explicit cause.
            raise cancelled from error
        cleanup = asyncio.create_task(connection.close())
        try:
            await _join_owned(cleanup)
        except (Exception, asyncio.CancelledError) as error:
            # A failed close is not reported as completed cleanup. Its cause
            # remains visible to the lifecycle owner, and its task is joined.
            raise cancelled from error
        raise


class Database:
    def __init__(
        self,
        url: str,
        busy_timeout_ms: int = DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        *,
        cipher: EnvelopeCipher | None = None,
    ) -> None:
        parsed = make_url(url)
        if parsed.drivername not in {"sqlite+aiosqlite", "postgresql+asyncpg"}:
            raise ValueError("unsupported database driver")
        if parsed.drivername == "sqlite+aiosqlite":
            if not parsed.database or not Path(parsed.database).is_absolute():
                raise ValueError("SQLite requires an absolute local file path")
        self.engine = create_async_engine(
            url,
            echo=False,
            hide_parameters=True,
            connect_args={
                "server_settings": {"search_path": "public", "application_name": "jt-oz-bridge"}
            }
            if parsed.drivername == "postgresql+asyncpg"
            else {},
        )
        self.cipher = cipher
        if cipher is not None:
            register(self.engine.dialect, cipher)
        if parsed.drivername == "sqlite+aiosqlite":

            @event.listens_for(self.engine.sync_engine, "do_connect")
            def owned_connect(_dialect: Any, _record: Any, _args: Any, parameters: Any) -> None:
                # Retain SQLAlchemy's complete dialect-generated arguments and
                # preceding per-engine event changes. This is the same adapter
                # bridge used by its public async_creator API, without losing
                # URL/query options or recursively calling engine.connect().
                creator = parameters.get("async_creator_fn") or aiosqlite.connect

                async def owned(*args: Any, **kwargs: Any) -> aiosqlite.Connection:
                    return await _sqlite_owned_connect(creator, *args, **kwargs)

                parameters["async_creator_fn"] = owned

            @event.listens_for(self.engine.sync_engine, "connect")
            def pragmas(connection: Any, _: Any) -> None:
                connection.isolation_level = None
                cur = connection.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=FULL")
                cur.close()

            @event.listens_for(self.engine.sync_engine, "begin")
            def begin(connection: Connection) -> None:
                if connection.get_execution_options().get("jtoz_autocommit_maintenance"):
                    return
                command = (
                    "BEGIN IMMEDIATE"
                    if connection.get_execution_options().get("jtoz_begin_immediate")
                    else "BEGIN"
                )
                connection.exec_driver_sql(command)

        # One FIFO queue for this process's SQLite writers; PostgreSQL has row locks.
        self.sessions = (
            SessionFactory(self.engine, write_gate=WriteGate(int(busy_timeout_ms) / 1000))
            if parsed.drivername == "sqlite+aiosqlite"
            else SessionFactory(self.engine)
        )

    async def ready(self) -> bool:
        try:
            async with self.engine.connect() as conn:
                revision = await conn.execute(text("SELECT version_num FROM alembic_version"))
                if revision.scalar_one() != CURRENT_REVISION:
                    return False
                pending = await conn.scalar(
                    text("SELECT COUNT(*) FROM maintenance_flags WHERE pending=true")
                )
                if pending:
                    return False
                await conn.run_sync(verify_keys)
                return True
        except (SQLAlchemyError, ValueError):
            if self.cipher is not None:
                key_state(self.engine.dialect).verified = False
            return False

    async def close(self) -> None:
        await self.engine.dispose()
        unregister(self.engine.dialect)


def _upgrade(connection: Connection, holder: str) -> bool:
    from alembic import command
    from alembic.config import Config

    if connection.dialect.name == "postgresql":
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(
            text("SELECT pg_catalog.pg_advisory_xact_lock(:identity)"),
            {"identity": PG_MAINTENANCE_LOCK},
        )
    key_state(connection.dialect).verified = False
    verify_keys(connection, initialize=True)
    leased = inspect(connection).has_table("worker_leases")
    if leased:
        won = connection.execute(
            text("""INSERT INTO worker_leases (role, holder, expires_at, fencing)
            VALUES ('consumer', :holder, :expiry, 1)
            ON CONFLICT (role) DO UPDATE SET holder=:holder, expires_at=:expiry, fencing=worker_leases.fencing+1
            WHERE worker_leases.expires_at <= :now RETURNING fencing"""),
            {"holder": holder, "expiry": time.time() + 300, "now": time.time()},
        ).scalar_one_or_none()
        if won is None:
            raise ValueError("migration_requires_stopped_consumer")
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")
    verify_keys(connection, initialize=True)
    return leased


async def upgrade_in_transaction(connection: AsyncConnection, holder: str) -> bool:
    """Run fixed migrations in the caller's transaction; never commits it."""
    # Alembic proxies are global even for independent engines/keys.
    while not _ALEMBIC_GATE.acquire(blocking=False):  # noqa: ASYNC110
        await asyncio.sleep(0.01)
    try:
        return await connection.run_sync(_upgrade, holder)
    finally:
        _ALEMBIC_GATE.release()


async def migrate(engine: AsyncEngine) -> None:
    """Explicit migration, with a key check and stopped-consumer requirement."""
    holder = str(uuid.uuid4())
    # Check before any connection/DDL, so a missing key cannot mutate the database.
    state = key_state(engine.dialect)
    state.verified = False
    leased = False
    try:
        # Alembic's module proxies are process-global. Do not allow two greenlets
        # (even for different engines/keys) to replace each other's context.
        while not _ALEMBIC_GATE.acquire(blocking=False):  # noqa: ASYNC110 - process gate spans event loops
            await asyncio.sleep(0.01)
        try:
            async with engine.execution_options(jtoz_begin_immediate=True).begin() as connection:
                leased = await connection.run_sync(_upgrade, holder)
        finally:
            _ALEMBIC_GATE.release()
        async with engine.connect() as connection:
            pending = await connection.scalar(
                text(
                    "SELECT COUNT(*) FROM maintenance_flags WHERE name='payload_disk_cleanup' AND pending=true"
                )
            )
        if pending:
            if engine.dialect.name != "sqlite":
                raise ValueError("legacy_payload_cleanup_required")
            # isolation_level=None plus this private option deliberately avoids BEGIN.
            async with engine.execution_options(
                jtoz_autocommit_maintenance=True
            ).connect() as connection:
                await connection.exec_driver_sql("VACUUM")
                result = (await connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")).one()
                if result[0] != 0:
                    raise ValueError("payload_checkpoint_busy")
            async with engine.execution_options(jtoz_begin_immediate=True).begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE maintenance_flags SET pending=false WHERE name='payload_disk_cleanup'"
                    )
                )
        state.verified = True
    except BaseException:
        state.verified = False
        raise
    finally:
        if leased:
            async with engine.execution_options(jtoz_begin_immediate=True).begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE worker_leases SET expires_at=0 WHERE role='consumer' AND holder=:holder"
                    ),
                    {"holder": holder},
                )
