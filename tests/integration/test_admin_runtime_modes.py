"""Isolated authenticated diagnostics, not Native/Human/mobile qualification."""

import asyncio
import time
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import event, update

from jt_oz_bridge.domain.runtime_readiness import (
    RootModeFact,
    RuntimeModeSnapshot,
    lease_fingerprint,
    scope_key,
)
from jt_oz_bridge.security.admin import AdminAuth
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.models import AdminAccount, WorkerLease
from jt_oz_bridge.web import app as web
from tests.integration.test_admin_catalog import configured, sign_in
from tests.support import REF, bound

SECRET = "UNAUTHORIZED_ROOT_NEVER_RETURN"


async def test_explicit_root_workspace_allows_canonical_absolute_binding(db):
    await bound(db)
    original = settings()
    rooted = original.model_copy(
        update={"projects": [original.projects[0].model_copy(update={"workspace_root": "/"})]}
    )
    app = web.create_app(rooted, db, runtime_factory=ModeRuntime)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            row = (await client.get("/api/v1/admin/runtime-modes")).json()["items"][0]
            assert row["mode"] == "readonly-awaiting-idle"


def settings():
    original = configured()
    return original.model_copy(
        update={
            "opencode_backends": [
                b.model_copy(update={"enabled": True}) for b in original.opencode_backends
            ],
            "projects": [p.model_copy(update={"enabled": True}) for p in original.projects],
            "zulip_realms": [r.model_copy(update={"enabled": True}) for r in original.zulip_realms],
        }
    )


class LegacyRuntime:
    def __init__(self, db, fence):
        self.db, self.fence = db, fence
        self.healthy = False
        self.stopped = asyncio.Event()

    async def start(self):
        self.healthy = True

    async def close(self):
        self.healthy = False
        self.stopped.set()

    async def wait_stopped(self):
        await self.stopped.wait()


class ModeRuntime(LegacyRuntime):
    calls = 0
    variant = "valid"
    reference = REF

    def runtime_mode_snapshot(self):
        self.calls += 1
        now = time.time()
        if self.variant == "unhealthy":
            self.healthy = False
        if self.variant == "exception":
            raise ValueError(SECRET)
        if self.variant == "missing":
            return None
        reference = self.reference
        if self.variant == "wrong-fullref":
            reference = reference.model_copy(update={"canonical_directory": "/" + SECRET})
        fact = RootModeFact(
            scope_key=scope_key(reference),
            mode="readonly-awaiting-idle",
            reason="positive-idle-required",
            transition_at=now - 100,
        )
        hidden = RootModeFact(
            scope_key=scope_key(REF.model_copy(update={"upstream_session_id": SECRET})),
            mode="strict",
            reason="strict-observation",
            transition_at=now - 99,
        )
        generated = (
            now - 6 if self.variant == "stale" else now + 6 if self.variant == "future" else now
        )
        roots = [fact, hidden]
        second = getattr(self, "secondary_reference", None)
        if second is not None:
            roots.append(
                RootModeFact(
                    scope_key=scope_key(second),
                    mode="strict",
                    reason="strict-observation",
                    transition_at=now - 90,
                )
            )
        snapshot = RuntimeModeSnapshot.create(
            generated_at=generated,
            lease_fingerprint=lease_fingerprint(
                self.fence.holder, self.fence.fencing + (self.variant == "wrong-lease")
            ),
            roots=tuple(roots),
        )
        if self.variant == "forged":
            return snapshot.model_copy(update={"content_sha256": "0" * 64})
        return snapshot


def application(db, kind=ModeRuntime, variant="valid"):
    values = []

    def factory(database, fence):
        instance = kind(database, fence)
        instance.variant = variant
        values.append(instance)
        return instance

    return web.create_app(settings(), db, runtime_factory=factory), values


@pytest.mark.parametrize("locale", ("en", "zh-TW"))
async def test_active_admin_gets_only_current_binding_mode_and_clear_diagnostic_ui(
    db, monkeypatch, locale
):
    _, binding, _, _ = await bound(db)
    app, runtimes = application(db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            csrf = await sign_in(client, db)
            await client.patch(
                "/api/v1/preferences/me", json={"locale": locale}, headers={"x-csrf-token": csrf}
            )

            def forbidden(*args, **kwargs):
                raise AssertionError("diagnostics must not decrypt payloads")

            monkeypatch.setattr(db.cipher, "open", forbidden)
            api = await client.get("/api/v1/admin/runtime-modes")
            page = await client.get("/admin/runtime-modes")
            assert api.status_code == page.status_code == 200
            result = api.json()
            assert result["authority"] == "diagnostic_only" and result["read_only"] is True
            assert set(result) == {"authority", "read_only", "source", "items", "next_after"}
            assert len(result["items"]) == 1
            row = result["items"][0]
            assert row["binding_id"] == binding.id
            assert (
                row["mode"] == "readonly-awaiting-idle"
                and row["reason"] == "positive-idle-required"
            )
            assert row["transition_at"] < row["observed_at"]
            assert set(row) == {"binding_id", "mode", "reason", "transition_at", "observed_at"}
            for text in (api.text, page.text):
                for private in (
                    SECRET,
                    scope_key(REF),
                    REF.upstream_session_id,
                    REF.canonical_directory,
                    runtimes[0].fence.holder,
                    lease_fingerprint(runtimes[0].fence.holder, runtimes[0].fence.fencing),
                ):
                    assert private not in text
            assert "Idle" in page.text and "Strict" in page.text
            assert (
                "does not mean Idle, writable" in page.text
                if locale == "en"
                else "不表示 Idle、可寫入" in page.text
            )
            assert f'lang="{locale}"' in page.text
            assert api.headers["cache-control"] == page.headers["cache-control"] == "no-store"
            monkeypatch.undo()  # readyz legitimately verifies the database key separately.
            assert (await client.get("/readyz")).json()["ready"] is True
            capabilities = (await client.get("/api/v1/capabilities")).json()
            assert capabilities["live_operations_enabled"] is True
            assert capabilities["live_operations_scope"] == "consumer_health_only"
            assert capabilities["grants_operation_authority"] is False
            assert len((await client.get("/")).text.split("/admin/runtime-modes")) == 2


@pytest.mark.parametrize(
    "variant", ("stale", "future", "wrong-lease", "missing", "unhealthy", "exception", "forged")
)
async def test_missing_invalid_or_unhealthy_projection_is_unavailable_without_exception_leaks(
    db, variant
):
    await bound(db)
    app, _ = application(db, variant=variant)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            response = await client.get("/api/v1/admin/runtime-modes")
            assert response.status_code == 200 and SECRET not in response.text
            assert response.json()["items"][0] == {
                "binding_id": response.json()["items"][0]["binding_id"],
                "mode": "unavailable",
                "reason": "diagnostics-unavailable",
                "transition_at": None,
                "observed_at": None,
            }


@pytest.mark.parametrize("kind", (LegacyRuntime, ModeRuntime))
async def test_legacy_or_mismatched_full_reference_cannot_infer_strict_from_hash(db, kind):
    await bound(db)
    app, _ = application(db, kind, "wrong-fullref")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            row = (await client.get("/api/v1/admin/runtime-modes")).json()["items"][0]
            assert row["mode"] == row["reason"] == "not-observed"
            assert row["transition_at"] is row["observed_at"] is None


@pytest.mark.parametrize("prefix", ("/api/v1/admin/", "/admin/"))
async def test_projection_requires_login_and_password_reset_completion(db, prefix):
    app, runtimes = application(db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            assert (await client.get(prefix + "runtime-modes")).status_code == 403
            password = await AdminAuth(db).create("admin")
            await client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": password}
            )
            assert (await client.get(prefix + "runtime-modes")).status_code == 403
            assert runtimes[0].calls == 0


@pytest.mark.parametrize("drift", ("lease", "snapshot-deadline", "binding", "account-lock"))
async def test_last_await_revalidates_current_lease_binding_and_snapshot_deadline(
    db, monkeypatch, drift
):
    await bound(db)
    app, _ = application(db)
    clock = [time.time()]
    monkeypatch.setattr(web, "time", SimpleNamespace(time=lambda: clock[0]))
    counts = {"lease": 0, "bindings": 0}
    fired = False

    def change(conn, cursor, statement, params, context, many):
        nonlocal fired
        if not statement.lstrip().startswith("SELECT"):
            return
        lease_read = "SELECT worker_leases.expires_at" in statement
        binding_read = "FROM bindings JOIN" in statement
        counts["lease"] += lease_read
        counts["bindings"] += binding_read
        if (drift == "binding" and binding_read and counts["bindings"] == 2) or (
            drift != "binding" and lease_read and counts["lease"] == 2
        ):
            fired = True
            if drift == "lease":
                conn.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
            elif drift == "account-lock":
                conn.execute(update(AdminAccount).values(must_reset=True))
            elif drift == "binding":
                conn.execute(update(Binding).values(canonical_directory="/" + SECRET))
            else:
                clock[0] = time.time() + 6

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            event.listen(db.engine.sync_engine, "before_cursor_execute", change)
            try:
                response = await client.get("/api/v1/admin/runtime-modes")
            finally:
                event.remove(db.engine.sync_engine, "before_cursor_execute", change)
            assert fired and SECRET not in response.text
            if drift == "account-lock":
                assert response.status_code == 403
                return
            assert response.status_code == 200
            items = response.json()["items"]
            assert items == [] if drift == "binding" else items[0]["mode"] == "unavailable"


@pytest.mark.parametrize("revoked", ("binding", "backend", "project"))
async def test_disabled_or_noncurrent_binding_is_omitted_and_hidden_roots_not_counted(db, revoked):
    await bound(db)
    async with db.sessions.begin() as session:
        if revoked == "binding":
            await session.execute(update(Binding).values(state="unbound"))
        elif revoked == "backend":
            await session.execute(update(EnrolledBackend).values(identity=SECRET))
        else:
            await session.execute(update(EnrolledProject).values(enabled=False))
    app, _ = application(db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            response = await client.get("/api/v1/admin/runtime-modes")
            page = await client.get("/admin/runtime-modes")
            assert response.json()["items"] == [] and SECRET not in response.text + page.text
            assert "does not mean Native has no sessions" in page.text


async def test_account_locked_during_projection_cannot_return_root_metadata(db):
    await bound(db)
    app, _ = application(db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            async with db.sessions.begin() as session:
                await session.execute(update(AdminAccount).values(must_reset=True))
            assert (await client.get("/api/v1/admin/runtime-modes")).status_code == 403


@pytest.mark.parametrize(
    "directory",
    (
        "/workspace/project-elsewhere",
        "/workspace/project/../outside",
        "/workspace/project/..",
        "/workspace/project/./same",
    ),
)
async def test_old_enrollment_and_matching_snapshot_cannot_escape_loaded_workspace_scope(
    db, directory
):
    await bound(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(canonical_directory=directory))
        await session.execute(update(EnrolledProject).values(canonical_directory=directory))
    app, runtimes = application(db)
    async with app.router.lifespan_context(app):
        runtimes[0].reference = REF.model_copy(update={"canonical_directory": directory})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            result = (await client.get("/api/v1/admin/runtime-modes")).json()
            assert result["items"] == [] and result["next_after"] is None


async def test_relocated_loaded_workspace_does_not_reveal_old_binding_from_enrolled_rows(db):
    await bound(db)
    configured = settings()
    relocated = configured.model_copy(
        update={
            "projects": [
                configured.projects[0].model_copy(update={"workspace_root": "/workspace/new-root"})
            ]
        }
    )
    app = web.create_app(relocated, db, runtime_factory=ModeRuntime)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            assert (await client.get("/api/v1/admin/runtime-modes")).json()["items"] == []


async def test_child_directory_within_loaded_root_is_allowed_only_by_exact_fullref(db):
    await bound(db)
    child = REF.model_copy(update={"canonical_directory": REF.canonical_directory + "/child"})
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(canonical_directory=child.canonical_directory))
        await session.execute(
            update(EnrolledProject).values(canonical_directory=child.canonical_directory)
        )
    app, runtimes = application(db)
    async with app.router.lifespan_context(app):
        runtimes[0].reference = child
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            assert (await client.get("/api/v1/admin/runtime-modes")).json()["items"][0][
                "mode"
            ] == "readonly-awaiting-idle"


async def test_one_readonly_root_does_not_change_other_root_or_existing_operation_authority(db):
    bindings, first, control, _ = await bound(db)
    second_ref = REF.model_copy(update={"upstream_session_id": "second-original-session"})
    control.ref = second_ref
    second = await bindings.bind("realm", 7, 10, "Second original work", second_ref)
    app, runtimes = application(db)
    async with app.router.lifespan_context(app):
        runtimes[0].secondary_reference = second_ref
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            records = (await client.get("/api/v1/admin/runtime-modes")).json()["items"]
            assert {r["binding_id"]: r["mode"] for r in records} == {
                first.id: "readonly-awaiting-idle",
                second.id: "strict",
            }
            capabilities = (await client.get("/api/v1/capabilities")).json()
            assert (
                capabilities["live_operations_enabled"]
                and not capabilities["grants_operation_authority"]
            )
            first_page = (await client.get("/api/v1/admin/runtime-modes?limit=1")).json()
            assert len(first_page["items"]) == 1 and first_page["next_after"]
            last_page = (
                await client.get(
                    "/api/v1/admin/runtime-modes",
                    params={"limit": 1, "after": first_page["next_after"]},
                )
            ).json()
            assert len(last_page["items"]) == 1 and last_page["next_after"] is None
            assert first_page["items"][0]["binding_id"] != last_page["items"][0]["binding_id"]


@pytest.mark.parametrize("parameter", ({"limit": 101}, {"limit": 0}, {"after": "x" * 256}))
async def test_projection_has_bounded_queries_and_never_bypasses_disabled_admin(db, parameter):
    app, _ = application(db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            assert (
                await client.get("/api/v1/admin/runtime-modes", params=parameter)
            ).status_code == 422
            app_settings = settings().model_copy(
                update={"admin": settings().admin.model_copy(update={"enabled": False})}
            )
            other = web.create_app(app_settings, db)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=other),
                base_url="https://bridge.invalid",
                cookies=client.cookies,
            ) as disabled:
                assert (await disabled.get("/api/v1/admin/runtime-modes")).status_code == 403
                assert (await disabled.get("/admin/runtime-modes")).status_code == 403


@pytest.mark.parametrize("deadline", ("snapshot", "lease"))
async def test_final_clock_gate_is_after_fullref_hash_projection_not_only_last_await(
    db, monkeypatch, deadline
):
    await bound(db)
    app, _ = application(db)
    offset = [0.0]
    monkeypatch.setattr(web, "time", SimpleNamespace(time=lambda: time.time() + offset[0]))
    original = web.scope_key

    def delayed(reference):
        value = original(reference)
        offset[0] = 6.0 if deadline == "snapshot" else 2.0
        return value

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            if deadline == "lease":
                async with db.sessions.begin() as session:
                    await session.execute(update(WorkerLease).values(expires_at=time.time() + 1.0))
            monkeypatch.setattr(web, "scope_key", delayed)
            response = await client.get("/api/v1/admin/runtime-modes")
            assert response.status_code == 200
            row = response.json()["items"][0]
            assert row["mode"] == "unavailable" and row["reason"] == "diagnostics-unavailable"
            assert row["transition_at"] is row["observed_at"] is None
