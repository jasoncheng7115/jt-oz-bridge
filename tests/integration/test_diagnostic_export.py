"""Synthetic admin downloads, never installed/mobile acceptance or Native access."""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import delete, event, update
from sqlalchemy.exc import OperationalError

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.admin import AdminAuth
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.diagnostics import (
    DiagnosticUnavailable,
    collect_diagnostics,
    sqlite_file_bytes,
)
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import Action, AdminAccount, AdminSession
from jt_oz_bridge.web.app import create_app
from tests.integration.test_admin_catalog import PRIVATE, configured, records

URL = "/api/v1/admin/diagnostics/export"


@asynccontextmanager
async def administrator(db, *, reset=True, settings=None):
    initial = await AdminAuth(db).create("diagnostic-admin")
    app = create_app(settings or configured(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            result = await client.post(
                "/api/v1/auth/login", json={"username": "diagnostic-admin", "password": initial}
            )
            csrf = result.json()["csrf_token"]
            if reset:
                password = "synthetic-diagnostics-only-password"
                assert (
                    await client.post(
                        "/api/v1/auth/password",
                        json={"password": password},
                        headers={"x-csrf-token": csrf},
                    )
                ).status_code == 200
                result = await client.post(
                    "/api/v1/auth/login",
                    json={"username": "diagnostic-admin", "password": password},
                )
                csrf = result.json()["csrf_token"]
            yield client, {"x-csrf-token": csrf}


async def test_download_contains_only_fixed_aggregates_without_payload_decryption(db, monkeypatch):
    await records(db)
    async with administrator(db) as (client, headers):
        async with db.engine.connect() as connection:
            before = (await connection.exec_driver_sql("SELECT payload FROM actions")).all()

        def no_decrypt(*_args, **_kwargs):
            raise AssertionError("diagnostic must not decrypt dialogue or tool bodies")

        monkeypatch.setattr(EnvelopeCipher, "open", no_decrypt)
        result = await client.post(URL, json={}, headers=headers)
        assert result.status_code == 200
        assert result.headers["content-disposition"] == (
            'attachment; filename="jt-oz-bridge-diagnostics.json"'
        )
        assert result.headers["cache-control"] == "no-store"
        assert result.headers["x-content-type-options"] == "nosniff"
        assert len(result.content) < 32768
        value = result.json()
        assert value["format"] == "jt-oz-bridge-diagnostics-v1"
        assert value["authority"] == "diagnostic_only" and value["schema_current"] is True
        assert value["counts"]["actions_held"] == 1
        assert value["counts"]["actions_total"] == 1
        assert value["counts"]["deliveries_total"] == 5
        assert value["oldest_queued_age_seconds"] is None
        assert value["runtime_healthy"] is None
        assert all(type(n) is int and n >= 0 for n in value["counts"].values())
        assert all(type(n) is bool for n in value["features"].values())
        for secret in (
            PRIVATE,
            "synthetic-bot@chat.invalid",
            "/workspace/project",
            "native.invalid",
        ):
            assert secret not in result.text
        async with db.engine.connect() as connection:
            assert (await connection.exec_driver_sql("SELECT payload FROM actions")).all() == before


@pytest.mark.parametrize("mode", ["missing_cookie", "missing_csrf", "wrong_origin", "must_reset"])
async def test_rejected_principal_never_collects_diagnostics(db, monkeypatch, mode):
    collect = AsyncMock(side_effect=AssertionError("unauthorized collection"))
    monkeypatch.setattr("jt_oz_bridge.web.app.collect_diagnostics", collect)
    async with administrator(db, reset=mode != "must_reset") as (client, headers):
        if mode == "missing_cookie":
            client.cookies.clear()
        if mode == "missing_csrf":
            headers = {}
        if mode == "wrong_origin":
            headers = {**headers, "origin": "https://other.invalid"}
        result = await client.post(URL, json={}, headers=headers)
        assert result.status_code == 403
        assert collect.await_count == 0


@pytest.mark.parametrize("key", ["path", "table", "session_id", "include_prompts"])
async def test_no_user_selected_scope_or_sensitive_export_options(db, key):
    async with administrator(db) as (client, headers):
        result = await client.post(URL, json={key: PRIVATE}, headers=headers)
        assert result.status_code == 422 and PRIVATE not in result.text


@pytest.mark.parametrize("mode", ["expire_session", "password_reset", "delete_account"])
async def test_authorization_is_rechecked_after_collection(db, monkeypatch, mode):
    async def changed(*_args, **_kwargs):
        async with db.sessions.begin() as session:
            if mode == "expire_session":
                await session.execute(update(AdminSession).values(expires_at=0))
            elif mode == "password_reset":
                await session.execute(update(AdminAccount).values(must_reset=True))
            else:
                await session.execute(delete(AdminAccount))
        return PRIVATE.encode()

    monkeypatch.setattr("jt_oz_bridge.web.app.collect_diagnostics", changed)
    async with administrator(db) as (client, headers):
        result = await client.post(URL, json={}, headers=headers)
        assert result.status_code == 403 and PRIVATE not in result.text


async def test_database_failure_never_becomes_zero_statistics_or_raw_exception(db):
    async with administrator(db) as (client, headers):

        def failure(_connection, _cursor, statement, _parameters, _context, _many):
            if "count(" in statement.lower():
                raise OperationalError(PRIVATE + " postgres://secret@host", {}, Exception(PRIVATE))

        event.listen(db.engine.sync_engine, "before_cursor_execute", failure)
        try:
            result = await client.post(URL, json={}, headers=headers)
        finally:
            event.remove(db.engine.sync_engine, "before_cursor_execute", failure)
        assert result.status_code == 503
        assert PRIVATE not in result.text and "counts" not in result.json()


async def test_queued_record_age_is_wall_clock_not_native_execution_time(db):
    await records(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Action).values(state="queued", created_at=time.time() - 60))
    result = json.loads(
        await collect_diagnostics(
            db, Settings(), process_lease_current=False, runtime_healthy=False
        )
    )
    assert 59 <= result["oldest_queued_age_seconds"] <= 62
    assert result["process_lease_current"] is False and result["runtime_healthy"] is False
    assert "Native" in " ".join(result["excluded"])


async def test_unknown_private_status_is_omitted_but_included_in_total_count(db):
    await records(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Action).values(state=PRIVATE))
    content = await collect_diagnostics(
        db, Settings(), process_lease_current=True, runtime_healthy=None
    )
    value = json.loads(content)
    assert PRIVATE.encode() not in content and value["counts"]["actions_total"] == 1
    assert value["counts"]["actions_held"] == 0


async def test_stale_schema_does_not_export_a_misleading_snapshot(db):
    async with db.engine.begin() as connection:
        await connection.exec_driver_sql("UPDATE alembic_version SET version_num='stale'")
    with pytest.raises(DiagnosticUnavailable, match="schema_not_current"):
        await collect_diagnostics(db, Settings(), process_lease_current=False, runtime_healthy=None)


async def test_own_database_file_size_does_not_follow_a_symlink(tmp_path):
    target = tmp_path / "private-original"
    target.write_bytes(PRIVATE.encode())
    link = tmp_path / "linked.db"
    link.symlink_to(target)
    db = Database("sqlite+aiosqlite:///" + str(link))
    try:
        assert sqlite_file_bytes(db) is None and target.read_bytes() == PRIVATE.encode()
    finally:
        await db.close()


async def test_admin_overview_has_localized_download_without_external_assets(db):
    async with administrator(db) as (client, headers):
        for locale, label in (("en", "Download safe diagnostics"), ("zh-TW", "下載安全診斷資料")):
            assert (
                await client.patch(
                    "/api/v1/preferences/me", json={"locale": locale}, headers=headers
                )
            ).status_code == 200
            page = await client.get("/")
            assert label in page.text and 'src="/static/diagnostics.js"' in page.text
            assert "http://" not in page.text and "https://" not in page.text
        script = await client.get("/static/diagnostics.js")
        assert script.status_code == 200


@pytest.mark.parametrize("cancelled", [True, False])
async def test_cancellation_or_query_timeout_joins_the_owned_database_context(cancelled):
    import jt_oz_bridge.services.diagnostics as module

    closed = asyncio.Event()
    blocked = asyncio.Event()

    class Session:
        async def scalar(self, _statement):
            return module.CURRENT_REVISION

        async def execute(self, _statement):
            blocked.set()
            await asyncio.Event().wait()

    @asynccontextmanager
    async def sessions():
        try:
            yield Session()
        finally:
            closed.set()

    class DB:
        engine = type("Engine", (), {"dialect": type("Dialect", (), {"name": "sqlite"})()})()

    db = DB()
    db.sessions = sessions
    task = asyncio.create_task(
        collect_diagnostics(db, Settings(), process_lease_current=False, runtime_healthy=None)
    )
    await blocked.wait()
    if cancelled:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(DiagnosticUnavailable, match="database_unavailable"):
            await asyncio.wait_for(task, timeout=10)
    assert closed.is_set()


async def test_disabled_admin_never_collects_even_with_a_saved_cookie(db, monkeypatch):
    settings = Settings()
    settings = settings.model_copy(
        update={"admin": settings.admin.model_copy(update={"enabled": False})}
    )
    auth = AdminAuth(db)
    password = await auth.create("synthetic-disabled-admin")
    token, csrf, _ = await auth.login("synthetic-disabled-admin", password, "127.0.0.1")
    collect = AsyncMock(side_effect=AssertionError("disabled diagnostic collection"))
    monkeypatch.setattr("jt_oz_bridge.web.app.collect_diagnostics", collect)
    app = create_app(settings, db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            client.cookies.set("jtoz_session", token)
            result = await client.post(URL, json={}, headers={"x-csrf-token": csrf})
            assert result.status_code == 403 and collect.await_count == 0
