"""Own SQLite cancellation joins, no Native clients or production database."""

import asyncio

import pytest
from sqlalchemy import func, select, text

from jt_oz_bridge.storage.models import AuditEvent


@pytest.mark.parametrize("write", [False, True])
async def test_cancelling_exit_cannot_finish_before_own_database_cleanup(db, monkeypatch, write):
    entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def operation():
        context = db.sessions.begin() if write else db.sessions()
        async with context as session:
            close = session.close

            async def blocked_close():
                entered.set()
                await release.wait()
                try:
                    await close()
                finally:
                    finished.set()

            monkeypatch.setattr(session, "close", blocked_close)
            await session.execute(text("SELECT 1"))
            if write:
                session.add(
                    AuditEvent(actor="synthetic", event="cleanup_committed", object_id="own-db")
                )

    task = asyncio.create_task(operation())
    try:
        async with asyncio.timeout(3):
            await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not task.done(), "worker returned while its SQL close was still running"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set() and db.engine.pool.checkedout() == 0
        async with db.sessions() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.event == "cleanup_committed")
            )
            assert count == int(write)  # Cancellation after commit is not a fabricated rollback.
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        async with asyncio.timeout(3):
            await finished.wait()


async def test_repeated_cancellation_still_joins_rollback_before_releasing_session(db, monkeypatch):
    body, entered, release, finished = (asyncio.Event() for _ in range(4))

    async def operation():
        async with db.sessions.begin() as session:
            close = session.close

            async def blocked_close():
                entered.set()
                await release.wait()
                try:
                    await close()
                finally:
                    finished.set()

            monkeypatch.setattr(session, "close", blocked_close)
            session.add(AuditEvent(actor="synthetic", event="cleanup_rollback", object_id="own-db"))
            await session.flush()
            body.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(operation())
    try:
        async with asyncio.timeout(3):
            await body.wait()
            task.cancel()
            await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not task.done(), "second cancellation abandoned the rollback/close task"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set() and db.engine.pool.checkedout() == 0
        async with db.sessions() as session:
            assert (
                await session.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event == "cleanup_rollback")
                )
                == 0
            )
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        async with asyncio.timeout(3):
            await finished.wait()


@pytest.mark.parametrize("repeat_cancel", [False, True])
async def test_cancelled_pending_sqlite_connect_joins_and_closes_owned_raw_connection(
    tmp_path, repeat_cancel
):
    """Real connector barrier, independent of GC or when ResourceWarning happens."""
    import sqlite3
    import threading

    from sqlalchemy import event

    from jt_oz_bridge.storage.database import Database

    entered, release = threading.Event(), threading.Event()
    raw, workers, closes = [], [], []

    class TrackedConnection(sqlite3.Connection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            raw.append(self)
            workers.append(threading.current_thread())
            entered.set()
            if not release.wait(3):
                raise RuntimeError("synthetic_connector_barrier_not_released")

        def close(self):
            closes.append(self)
            return super().close()

    database = Database("sqlite+aiosqlite:///" + str(tmp_path / "cancelled-connect.db"))

    @event.listens_for(database.engine.sync_engine, "do_connect", insert=True)
    def synthetic_connector(_dialect, _record, _args, parameters):
        parameters["factory"] = TrackedConnection

    async def query():
        async with database.sessions() as session:
            await session.execute(text("SELECT 1"))

    task = asyncio.create_task(query())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel("original_connect_cancellation")
        await asyncio.sleep(0)
        if repeat_cancel:
            task.cancel("additional_connect_cancellation")
            await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError) as stopped:
            await task
        assert stopped.value.args == ("original_connect_cancellation",)
        for worker in workers:
            await asyncio.to_thread(worker.join, 3)
            assert not worker.is_alive()
        assert len(raw) == len(closes) == 1, "cancelled connect abandoned its raw SQLite handle"
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            raw[0].execute("SELECT 1")
        assert database.engine.pool.checkedout() == 0
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        # Only this test's exact constructed handles; assertions above are made
        # before cleanup. Never close another pool/driver/unknown connection.
        for value in raw:
            if value not in closes:
                value.close()
        for worker in workers:
            await asyncio.to_thread(worker.join, 3)
        await database.close()


@pytest.mark.parametrize("failure", ["connector", "close", "close_cancel", "none"])
async def test_cancelled_sqlite_creator_joins_errors_and_close_without_losing_original_cancel(
    failure,
):
    from jt_oz_bridge.storage.database import _sqlite_owned_connect

    entered, release, closing, finish = (asyncio.Event() for _ in range(4))
    connector_error = RuntimeError("synthetic_connector_failure")
    close_error = (
        asyncio.CancelledError("synthetic_owned_close_cancel")
        if failure == "close_cancel"
        else RuntimeError("synthetic_owned_close_failure")
    )
    completed, closed = [], []

    class OwnedConnection:
        async def close(self):
            closing.set()
            try:
                await finish.wait()
                if failure in {"close", "close_cancel"}:
                    raise close_error
                closed.append(True)
            finally:
                completed.append("close")

    connection = OwnedConnection()

    async def creator(*args, **kwargs):
        entered.set()
        try:
            await release.wait()
            if failure == "connector":
                raise connector_error
            return connection
        finally:
            completed.append("creator")

    task = asyncio.create_task(_sqlite_owned_connect(creator))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel("original_cancellation")
        await asyncio.sleep(0)
        assert not task.done(), "connect was abandoned instead of joined"
        release.set()
        if failure != "connector":
            await asyncio.wait_for(closing.wait(), 3)
            task.cancel("cancel_again_while_owned_close_is_pending")
            await asyncio.sleep(0)
            assert not task.done(), "owned close was abandoned on repeated cancellation"
        finish.set()
        with pytest.raises(asyncio.CancelledError) as stopped:
            await task
        assert stopped.value.args == ("original_cancellation",)
        expected = connector_error if failure == "connector" else close_error
        assert stopped.value.__cause__ is (None if failure == "none" else expected)
        assert completed == (["creator"] if failure == "connector" else ["creator", "close"])
        assert bool(closed) is (failure == "none")
    finally:
        release.set()
        finish.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_normal_sqlite_connect_failure_preserves_driver_error(tmp_path):
    import sqlite3

    from sqlalchemy import event
    from sqlalchemy.exc import OperationalError

    from jt_oz_bridge.storage.database import Database

    expected = sqlite3.OperationalError("synthetic_connect_denied")

    async def creator(*args, **kwargs):
        raise expected

    database = Database("sqlite+aiosqlite:///" + str(tmp_path / "failed-connect.db"))

    @event.listens_for(database.engine.sync_engine, "do_connect", insert=True)
    def custom_creator(_dialect, _record, _args, parameters):
        parameters["async_creator_fn"] = creator

    try:
        with pytest.raises(OperationalError) as failed:
            async with database.engine.connect():
                pytest.fail("failed connector returned an engine connection")
        assert failed.value.orig is expected
        assert database.engine.pool.checkedout() == 0
    finally:
        await database.close()


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?timeout=0.25&check_same_thread=false&cached_statements=17",
        "?timeout=0.5&check_same_thread=true",
        "?uri=true&mode=rwc&cache=shared&timeout=0.75&check_same_thread=false",
    ],
)
async def test_owned_sqlite_creator_preserves_dialect_url_options_and_normal_pool_lifecycle(
    tmp_path, query
):
    import sqlite3

    from sqlalchemy import event
    from sqlalchemy.engine import make_url

    from jt_oz_bridge.storage.database import Database

    # Database paths remain literal under SQLAlchemy's existing URL semantics;
    # do not silently unescape percent, space, Unicode or '#' in a file name.
    url = "sqlite+aiosqlite:///" + str(tmp_path / "空 白%2F#path.db") + query
    database = Database(url)
    args, parameters = database.engine.dialect.create_connect_args(make_url(url))
    observed, raw, closes = [], [], []

    class TrackedConnection(sqlite3.Connection):
        def __init__(self, *values, **options):
            observed.append((list(values), dict(options)))
            super().__init__(*values, **options)
            raw.append(self)

        def close(self):
            closes.append(self)
            return super().close()

    @event.listens_for(database.engine.sync_engine, "do_connect", insert=True)
    def test_factory(_dialect, _record, _args, options):
        options["factory"] = TrackedConnection

    try:
        async with database.sessions() as session:
            assert await session.scalar(text("SELECT 1")) == 1
        assert len(raw) == 1 and not closes  # Successful connection belongs to pool.
        assert observed == [(list(args), {**parameters, "factory": TrackedConnection})]
        async with database.sessions() as session:
            assert await session.scalar(text("PRAGMA foreign_keys")) == 1
            assert await session.scalar(text("PRAGMA busy_timeout")) == 30000
        assert len(raw) == 1 and not closes
    finally:
        await database.close()
    assert closes == raw


@pytest.mark.parametrize(
    "url",
    [
        "sqlite+aiosqlite:///:memory:",
        "sqlite+aiosqlite:///file:memory?mode=memory&cache=shared&uri=true",
        "sqlite+aiosqlite:///relative.db",
    ],
)
def test_owned_sqlite_creator_does_not_widen_existing_memory_uri_or_relative_path_policy(url):
    from jt_oz_bridge.storage.database import Database

    with pytest.raises(ValueError, match="absolute local file"):
        Database(url)


def test_owned_sqlite_hook_does_not_change_postgresql_engine_creation(monkeypatch):
    from types import SimpleNamespace

    from jt_oz_bridge.storage import database as module

    calls = []
    engine = SimpleNamespace(dialect=object())

    def create(url, **options):
        calls.append((url, options))
        return engine

    monkeypatch.setattr(module, "create_async_engine", create)
    monkeypatch.setattr(module, "SessionFactory", lambda value: ("sessions", value))
    value = module.Database("postgresql+asyncpg://local.invalid/synthetic")
    assert value.engine is engine and value.sessions == ("sessions", engine)
    assert calls == [
        (
            "postgresql+asyncpg://local.invalid/synthetic",
            {
                "echo": False,
                "hide_parameters": True,
                "connect_args": {
                    "server_settings": {
                        "search_path": "public",
                        "application_name": "jt-oz-bridge",
                    }
                },
            },
        )
    ]


async def test_repeated_pool_disposal_does_not_nest_owned_sqlite_creators(tmp_path, monkeypatch):
    import aiosqlite

    from jt_oz_bridge.storage import database as module

    original, creators = module._sqlite_owned_connect, []

    async def observe(creator, *args, **kwargs):
        creators.append(creator)
        return await original(creator, *args, **kwargs)

    monkeypatch.setattr(module, "_sqlite_owned_connect", observe)
    database = module.Database("sqlite+aiosqlite:///" + str(tmp_path / "reconnect.db"))
    try:
        for generation in range(8):
            async with database.sessions() as session:
                assert await session.scalar(text("SELECT 1")) == 1
            # A nested wrapper would re-enter observe during the owned task.
            assert creators == [aiosqlite.connect] * (generation + 1)
            assert database.engine.pool.checkedout() == 0
            await database.engine.dispose()
    finally:
        await database.close()


async def test_public_default_creator_hook_keeps_sqlalchemy_none_fallback(tmp_path):
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    from jt_oz_bridge.storage.database import Database

    # Public class events precede this Database's per-engine hook. This is a
    # scoped test fixture only; the product never installs a global driver hook.
    def explicit_default(dialect, _record, _args, parameters):
        if dialect.name == "sqlite":
            parameters["async_creator_fn"] = None

    event.listen(Engine, "do_connect", explicit_default)
    database = None
    try:
        database = Database("sqlite+aiosqlite:///" + str(tmp_path / "default-creator.db"))
        async with database.sessions() as session:
            assert await session.scalar(text("SELECT 1")) == 1
    finally:
        event.remove(Engine, "do_connect", explicit_default)
        if database is not None:
            await database.close()
