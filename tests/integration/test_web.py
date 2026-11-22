import asyncio
import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import event, update
from sqlalchemy.exc import OperationalError

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.admin import AdminAuth, token_hash
from jt_oz_bridge.services.runtime import RuntimeResource, RuntimeWorker, SupervisedRuntime
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import Action, AdminAccount, AdminSession, WorkerLease
from jt_oz_bridge.web.app import create_app


async def test_auth_reset_csrf_locale_and_protected_diagnostics(db):
    initial = await AdminAuth(db).create("admin")
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            assert (await client.get("/healthz")).status_code == 200
            assert (await client.get("/readyz")).json()["agent_consumers"] is False
            assert (await client.get("/api/v1/capabilities")).status_code == 403
            assert (await client.get("/", headers={"accept-language": "zh-TW"})).text.find(
                'lang="en"'
            ) >= 0
            result = await client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": initial}
            )
            assert result.json()["password_reset_required"] is True
            assert (
                "Secure" in result.headers["set-cookie"]
                and "HttpOnly" in result.headers["set-cookie"]
            )
            csrf = result.json()["csrf_token"]
            assert (await client.get("/api/v1/capabilities")).status_code == 403
            new_password = "test-only-new-password-123"
            assert (
                await client.post("/api/v1/auth/password", json={"password": new_password})
            ).status_code == 403
            reset = await client.post(
                "/api/v1/auth/password",
                json={"password": new_password},
                headers={"x-csrf-token": csrf},
            )
            assert reset.status_code == 200
            assert (await client.get("/api/v1/capabilities")).status_code == 403
            result = await client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": new_password}
            )
            csrf = result.json()["csrf_token"]
            assert result.json()["password_reset_required"] is False
            assert (await client.get("/api/v1/capabilities")).json()[
                "live_operations_enabled"
            ] is False
            assert (
                await client.patch("/api/v1/preferences/me", json={"locale": "zh-TW"})
            ).status_code == 403
            headers = {"x-csrf-token": csrf}
            assert (
                await client.patch(
                    "/api/v1/preferences/me", json={"locale": "zh-TW"}, headers=headers
                )
            ).status_code == 200
            page = await client.get("/")
            assert 'lang="zh-TW"' in page.text and "橋接管理" in page.text
            assert "default-src 'none'" in page.headers["content-security-policy"]
            assert (
                await client.patch(
                    "/api/v1/preferences/me",
                    json={"locale": "en"},
                    headers={**headers, "origin": "https://evil.invalid"},
                )
            ).status_code == 403
            assert (await client.post("/api/v1/auth/logout", headers=headers)).status_code == 200
            assert (await client.get("/api/v1/capabilities")).status_code == 403


async def test_login_limits_persist_and_invalid_payload_never_echoes_password(db):
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            invalid = await client.post(
                "/api/v1/auth/login",
                json={"username": "a", "password": "LEAK-MARKER", "extra": "LEAK-MARKER"},
            )
            assert invalid.status_code == 422 and "LEAK-MARKER" not in invalid.text
            for _ in range(5):
                result = await client.post(
                    "/api/v1/auth/login", json={"username": "unknown", "password": "test"}
                )
                assert result.status_code == 403
            result = await client.post(
                "/api/v1/auth/login", json={"username": "another", "password": "test"}
            )
            assert result.status_code == 429
            assert result.json()["code"] == "login_throttled"


async def test_second_process_cannot_serve_with_same_lease(db):
    app = create_app(Settings(), db)
    second_db = Database(str(db.engine.url), cipher=db.cipher)
    second = create_app(Settings(), second_db)
    async with app.router.lifespan_context(app):
        with pytest.raises(RuntimeError, match="another active"):
            async with second.router.lifespan_context(second):
                pytest.fail("second process became active")


async def test_chunked_oversized_body_rejected(db):
    app = create_app(Settings(), db)

    async def chunks():
        for _ in range(8):
            yield b"x" * 10000

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            response = await client.post(
                "/api/v1/auth/login", content=chunks(), headers={"content-type": "application/json"}
            )
            assert response.status_code == 413


async def test_parallel_login_rate_limit_is_atomic(db):
    from jt_oz_bridge.security.admin import LoginRejected

    auth = AdminAuth(db)

    async def attempt():
        try:
            await auth.login("unknown", "test", "same-peer")
        except LoginRejected as error:
            return str(error)

    results = await asyncio.gather(*[attempt() for _ in range(12)])
    assert results.count("invalid_credentials") == 5
    assert results.count("login_throttled") == 7


async def test_explicit_migration_required_and_no_auto_schema_creation(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'unmigrated.db'}")
    app = create_app(Settings(), db)
    with pytest.raises(RuntimeError, match="database migration required"):
        async with app.router.lifespan_context(app):
            pytest.fail("missing migration must not start")


async def test_old_password_login_cannot_race_past_password_reset(db, monkeypatch):
    from sqlalchemy import select

    from jt_oz_bridge.security import admin
    from jt_oz_bridge.storage.models import AdminAccount

    auth = AdminAuth(db)
    initial = await auth.create("admin")
    verified, resume = asyncio.Event(), asyncio.Event()
    original_to_thread = asyncio.to_thread

    async def intercept(function, *args):
        result = await original_to_thread(function, *args)
        if function == admin.HASHER.verify:
            verified.set()
            await resume.wait()
        return result

    monkeypatch.setattr(asyncio, "to_thread", intercept)
    pending = asyncio.create_task(auth.login("admin", initial, "peer"))
    await asyncio.wait_for(verified.wait(), 5)
    async with db.sessions() as session:
        account = await session.scalar(select(AdminAccount))
    await auth.reset_password(account, "new-test-only-password-123")
    resume.set()
    with pytest.raises(admin.LoginRejected, match="invalid_credentials"):
        await pending


@asynccontextmanager
async def _metrics_client(
    db, *, settings=None, runtime_factory=None, reset=False, peer="127.0.0.1"
):
    # Synthetic administrator/session in an isolated ownDB, not Human/Native proof.
    token = "private-metrics-test-session"
    async with db.sessions.begin() as session:
        account = AdminAccount(
            username="metrics-test-admin", password_hash="unused-test-hash", must_reset=reset
        )
        session.add(account)
        await session.flush()
        session.add(
            AdminSession(
                token_hash=token_hash(token),
                admin_id=account.id,
                csrf_hash=token_hash("unused-test-csrf"),
                expires_at=time.time() + 3600,
            )
        )
    app = create_app(settings or Settings(), db, runtime_factory=runtime_factory)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(peer, 1234)),
            base_url="https://bridge.invalid",
            cookies={"jtoz_session": token},
        ) as client:
            yield client


def _metrics_values(response):
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    return {
        line.split()[0]: float(line.split()[1])
        for line in response.text.splitlines()
        if line and not line.startswith("#")
    }


@pytest.mark.parametrize(
    "enabled,peer,configured,status",
    [
        (False, "127.0.0.1", "127.0.0.1", 404),
        (False, "192.0.2.3", "127.0.0.1", 404),
        (True, "192.0.2.3", "127.0.0.1", 403),
        (True, "::ffff:127.0.0.1", "127.0.0.1", 403),
        (True, "127.0.0.1", "::1", 403),
        (True, None, "127.0.0.1", 403),
    ],
)
async def test_metrics_disabled_or_foreign_peer_never_reads_database(
    db, monkeypatch, enabled, peer, configured, status
):
    settings = Settings()
    settings.observability.metrics_enabled = enabled
    settings.observability.metrics_bind_host = configured
    app = create_app(settings, db)
    forbidden = AsyncMock(side_effect=AssertionError("unexpected ownDB access"))
    monkeypatch.setattr(AdminAuth, "authenticate", forbidden)
    monkeypatch.setattr(db, "ready", forbidden)
    monkeypatch.setattr(db, "sessions", forbidden)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(peer, 1234) if peer else None),
        base_url="https://bridge.invalid",
    ) as client:
        result = await client.get(
            "/metrics", headers={"x-forwarded-for": configured, "forwarded": f"for={configured}"}
        )
    assert result.status_code == status
    forbidden.assert_not_called()


@pytest.mark.parametrize("reset", [False, True])
async def test_metrics_requires_existing_active_administrator(db, reset):
    async with _metrics_client(db, reset=reset) as client:
        if not reset:
            client.cookies.clear()
        result = await client.get("/metrics")
        assert result.status_code == 403
        assert "jt_oz_bridge_" not in result.text


async def test_metrics_ipv6_peer_is_allowed_only_when_explicitly_configured(db):
    settings = Settings()
    settings.observability.metrics_bind_host = "::1"
    async with _metrics_client(db, settings=settings, peer="::1") as client:
        assert (await client.get("/metrics")).status_code == 200


async def test_metrics_foundation_counts_only_fixed_states_without_payload_or_network(
    db, monkeypatch
):
    remote = AsyncMock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", remote)
    async with _metrics_client(db) as client:
        async with db.sessions.begin() as session:
            for index, state in enumerate(("queued", "held", "held", "ambiguous", "completed")):
                session.add(
                    Action(
                        id=f"PRIVATE-ACTION-{index}",
                        dedupe_key=f"PRIVATE-DEDUPE-{index}",
                        binding_id="PRIVATE-ROOT-BINDING",
                        binding_revision=1,
                        actor_id=987,
                        operation="prompt",
                        operation_digest="a" * 64,
                        payload={"secret": "PRIVATE-SOURCE-CREDENTIAL"},
                        state=state,
                    )
                )
        statements = []

        def observe(_conn, _cursor, statement, _params, _context, _many):
            statements.append(statement)

        event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
        try:
            result = await client.get(
                "/metrics", headers={"x-forwarded-for": "192.0.2.4", "forwarded": "for=192.0.2.4"}
            )
        finally:
            event.remove(db.engine.sync_engine, "before_cursor_execute", observe)
        assert result.status_code == 200
        values = _metrics_values(result)
        # File and process observations vary by run; their names are still fixed.
        assert values.pop("jt_oz_bridge_database_file_bytes") > 0
        assert values.pop("jt_oz_bridge_database_free_bytes") >= 0
        assert values.pop("jt_oz_bridge_redactions_total") >= 0
        assert values == {
            "jt_oz_bridge_runtime_configured": 0,
            "jt_oz_bridge_database_ready": 1,
            "jt_oz_bridge_database_sample_available": 1,
            "jt_oz_bridge_consumer_lease_valid": 1,
            'jt_oz_bridge_actions{state="queued"}': 1,
            'jt_oz_bridge_actions{state="held"}': 2,
            'jt_oz_bridge_actions{state="ambiguous"}': 1,
            "jt_oz_bridge_storage_sample_available": 1,
            "jt_oz_bridge_input_events_pending": 0,
            "jt_oz_bridge_input_event_lag_seconds": 0,
            'jt_oz_bridge_outbox_deliveries{state="pending"}': 0,
            'jt_oz_bridge_outbox_deliveries{state="sending"}': 0,
            'jt_oz_bridge_outbox_deliveries{state="held"}': 0,
            'jt_oz_bridge_outbox_deliveries{state="ambiguous"}': 0,
            "jt_oz_bridge_outbox_oldest_age_seconds": 0,
            "jt_oz_bridge_outbox_retrying_deliveries": 0,
            "jt_oz_bridge_zulip_receipt_retries": 0,
            "jt_oz_bridge_pending_interactions": 0,
            "jt_oz_bridge_pending_interaction_oldest_age_seconds": 0,
            'jt_oz_bridge_recovery_runs{state="running"}': 0,
            'jt_oz_bridge_recovery_runs{state="partial"}': 0,
            'jt_oz_bridge_recovery_runs{state="capacity"}': 0,
            'jt_oz_bridge_recovery_items{state="captured"}': 0,
            'jt_oz_bridge_recovery_items{state="held"}': 0,
            'jt_oz_bridge_recovery_items{state="reviewed"}': 0,
            'jt_oz_bridge_live_source_rows{table="native_feed_receipts"}': 0,
            'jt_oz_bridge_live_source_rows{table="native_live_captures"}': 0,
            "jt_oz_bridge_artifact_reserved_bytes": 0,
            "jt_oz_bridge_artifact_quota_bytes": 2 * 1024**3,
            "jt_oz_bridge_workspace_reserved_bytes": 0,
            "jt_oz_bridge_workspace_quota_bytes": 2 * 1024**3,
        }
        assert "PRIVATE" not in result.text and "987" not in result.text
        assert result.headers["cache-control"] == "no-store"
        assert all(
            sql.lstrip().upper().startswith(("SELECT", "PRAGMA", "BEGIN")) for sql in statements
        )
        assert any("count(actions.id)" in sql for sql in statements)
        assert not any(
            name in sql
            for sql in statements
            for name in ("actions.payload", "actions.admission", "actions.native_result")
        )
        remote.assert_not_awaited()
        # Existing foundation readiness is not relabelled as managed Native health.
        assert (await client.get("/readyz")).json() == {
            "ready": True,
            "mode": "foundation",
            "agent_consumers": False,
        }


@pytest.mark.parametrize("failure", ["not_ready", "ready_error", "count_error"])
async def test_metrics_database_failure_omits_unknown_samples_and_secrets(db, monkeypatch, failure):
    async with _metrics_client(db) as client:
        listener = None
        if failure == "not_ready":
            monkeypatch.setattr(db, "ready", AsyncMock(return_value=False))
        elif failure == "ready_error":
            monkeypatch.setattr(
                db,
                "ready",
                AsyncMock(
                    side_effect=OperationalError(
                        "PRIVATE-SQL", {}, RuntimeError("PRIVATE-CREDENTIAL")
                    )
                ),
            )
        else:

            def listener(_conn, _cursor, sql, _params, _context, _many):
                if "FROM actions" in sql:
                    raise OperationalError("PRIVATE-SQL", {}, RuntimeError("PRIVATE-CREDENTIAL"))

            event.listen(db.engine.sync_engine, "before_cursor_execute", listener)
        try:
            result = await client.get("/metrics")
        finally:
            if listener:
                event.remove(db.engine.sync_engine, "before_cursor_execute", listener)
        assert result.status_code == 503
        values = _metrics_values(result)
        assert values["jt_oz_bridge_database_ready"] == int(failure == "count_error")
        assert values["jt_oz_bridge_database_sample_available"] == 0
        assert "jt_oz_bridge_consumer_lease_valid" not in values
        assert not any(key.startswith("jt_oz_bridge_actions") for key in values)
        assert "PRIVATE" not in result.text


@pytest.mark.parametrize("change", ["expired", "foreign_holder", "foreign_epoch"])
async def test_metrics_checks_fresh_owned_lease_without_waiting_for_heartbeat(db, change):
    async with _metrics_client(db) as client:
        assert (
            _metrics_values(await client.get("/metrics"))["jt_oz_bridge_consumer_lease_valid"] == 1
        )
        changed = {
            "expired": {"expires_at": 0},
            "foreign_holder": {"holder": "PRIVATE-FOREIGN-HOLDER"},
            "foreign_epoch": {"fencing": 999999},
        }[change]
        async with db.sessions.begin() as session:
            await session.execute(
                update(WorkerLease).where(WorkerLease.role == "consumer").values(**changed)
            )
        result = await client.get("/metrics")
        assert result.status_code == 200
        assert _metrics_values(result)["jt_oz_bridge_consumer_lease_valid"] == 0
        assert "PRIVATE" not in result.text


async def test_metrics_reports_real_supervisor_failure_without_native_health_inference(db):
    trigger, closed = asyncio.Event(), asyncio.Event()

    async def worker():
        await trigger.wait()
        raise ValueError("PRIVATE-UPSTREAM-BODY")

    async def cleanup():
        closed.set()

    def factory(database, fence):
        return SupervisedRuntime(
            database,
            fence,
            (RuntimeResource("synthetic-test-resource", AsyncMock(), cleanup),),
            (RuntimeWorker("native-dispatch", worker),),
        )

    async with _metrics_client(db, runtime_factory=factory) as client:
        first = _metrics_values(await client.get("/metrics"))
        assert (
            first["jt_oz_bridge_runtime_configured"] == first["jt_oz_bridge_runtime_healthy"] == 1
        )
        trigger.set()
        await asyncio.wait_for(closed.wait(), 3)
        result = await client.get("/metrics")
        assert _metrics_values(result)["jt_oz_bridge_runtime_healthy"] == 0
        assert "PRIVATE" not in result.text
        assert (await client.get("/readyz")).status_code == 503
