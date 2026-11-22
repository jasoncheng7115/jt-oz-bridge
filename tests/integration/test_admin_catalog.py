"""Synthetic administrative read paths; not production UI or upstream certification."""

import time

import httpx
import pytest
from sqlalchemy import event, select

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.admin import AdminAuth
from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery
from jt_oz_bridge.web.app import create_app
from jt_oz_bridge.web.catalog import SECTIONS, AdminCatalog
from tests.support import bound

PRIVATE = "NEVER_RETURN_PRIVATE_PAYLOAD"


def configured():
    return Settings.model_validate(
        {
            "opencode_backends": [
                {
                    "id": "backend",
                    "base_url": "https://native.invalid",
                    "credential_ref": "env:" + PRIVATE,
                }
            ],
            "zulip_realms": [
                {
                    "id": "realm",
                    "url": "https://chat.invalid",
                    "bot_email": "synthetic-bot@chat.invalid",
                    "api_key_ref": "env:" + PRIVATE,
                    "allowed_user_ids": [7, 8],
                    "allowed_channel_ids": [10],
                }
            ],
            "projects": [
                {
                    "id": "project",
                    "backend_id": "backend",
                    "realm_id": "realm",
                    "workspace_root": "/workspace/project",
                }
            ],
        }
    )


async def records(db):
    _, binding, _, _ = await bound(db)
    async with db.sessions.begin() as session:
        session.add(
            Action(
                id="action",
                dedupe_key="catalog",
                binding_id=binding.id,
                binding_revision=1,
                actor_id=7,
                operation_digest="a" * 64,
                payload={"prompt": PRIVATE},
                admission={"original": PRIVATE},
                native_result={"output": PRIVATE},
                operation="task",
                state="held",
            )
        )
        for i, state in enumerate(("held", "ambiguous", "failed", "delivered", "pending")):
            session.add(
                Delivery(
                    id=f"delivery-{i}",
                    dedupe_key=f"catalog-{i}",
                    binding_id=binding.id,
                    binding_revision=1,
                    payload={"content": PRIVATE},
                    payload_hash="b" * 64,
                    state=state,
                )
            )
        for i, state in enumerate(("pending", "answered")):
            session.add(
                PendingInteraction(
                    id=f"interaction-{i}",
                    identity_key=str(i) * 64,
                    binding_id=binding.id,
                    binding_revision=1,
                    snapshot={"question": PRIVATE},
                    snapshot_hash="c" * 64,
                    state=state,
                    expires_at=time.time() + 60,
                )
            )
    return binding


async def sign_in(client, db):
    auth = AdminAuth(db)
    initial = await auth.create("admin")
    token, _, _ = await auth.login("admin", initial, "setup")
    await auth.reset_password(await auth.authenticate(token), "synthetic-admin-password-123")
    response = await client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "synthetic-admin-password-123"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("locale", ("en", "zh-TW"))
async def test_authenticated_pages_metadata_and_locale_never_decrypt_or_mutate(
    db, monkeypatch, section, locale
):
    binding = await records(db)
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            csrf = await sign_in(client, db)
            await client.patch(
                "/api/v1/preferences/me", json={"locale": locale}, headers={"x-csrf-token": csrf}
            )

            def forbidden(*args, **kwargs):
                raise AssertionError("administrative read decrypted a payload")

            monkeypatch.setattr(db.cipher, "open", forbidden)
            statements = []

            def observe(conn, cursor, statement, params, context, many):
                statements.append(statement)

            event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
            try:
                api = await client.get("/api/v1/admin/" + section)
                page = await client.get("/admin/" + section)
                assert api.status_code == page.status_code == 200
                assert api.json()["read_only"] is True and api.json()["snapshot_is_live"] is True
                assert PRIVATE not in api.text + page.text
                assert f'lang="{locale}"' in page.text
                assert 'aria-current="page"' in page.text and 'href="#content"' in page.text
                assert page.headers["cache-control"] == "no-store"
                assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
                assert all(
                    not q.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
                    for q in statements
                )
                if section == "bindings":
                    assert api.json()["items"][0]["session_id"] == binding.session_id
                if section == "deliveries":
                    assert {x["state"] for x in api.json()["items"]} == {
                        "held",
                        "ambiguous",
                        "failed",
                    }
                if section == "interactions":
                    assert [x["id"] for x in api.json()["items"]] == ["interaction-0"]
                if section in {"backends", "compatibility"}:
                    row = api.json()["items"][0]
                    assert (
                        row["enrolled_verified"]
                        and not row["certified"]
                        and not row["connection_checked"]
                    )
            finally:
                event.remove(db.engine.sync_engine, "before_cursor_execute", observe)


@pytest.mark.parametrize("section", SECTIONS)
async def test_no_section_bypasses_login_password_reset_or_disabled_admin(db, section):
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            for prefix in ("/admin/", "/api/v1/admin/"):
                assert (await client.get(prefix + section)).status_code == 403
            initial = await AdminAuth(db).create("admin")
            await client.post("/api/v1/auth/login", json={"username": "admin", "password": initial})
            for prefix in ("/admin/", "/api/v1/admin/"):
                assert (await client.get(prefix + section)).status_code == 403
            app_settings = Settings(admin={"enabled": False})
            other = create_app(app_settings, db)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=other),
                base_url="https://bridge.invalid",
                cookies=client.cookies,
            ) as denied:
                assert (await denied.get("/api/v1/admin/" + section)).status_code == 403


async def test_keyset_pagination_filters_and_html_escape_over_live_audit(db):
    async with db.sessions.begin() as session:
        for name in ("100", "200", "300"):
            session.add(
                AuditEvent(
                    id=name, actor="<script>alert(1)</script>", event="fixture", object_id=name
                )
            )
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            first = (
                await client.get("/api/v1/admin/audit", params={"event": "fixture", "limit": 2})
            ).json()
            assert [x["id"] for x in first["items"]] == ["100", "200"] and first[
                "next_after"
            ] == "200"
            page = await client.get("/admin/audit", params={"event": "fixture", "limit": 2})
            assert (
                "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
                and "<script>alert(1)</script>" not in page.text
            )
            assert "/admin/audit?limit=2&amp;after=200&amp;event=fixture" in page.text
            async with db.sessions.begin() as session:
                session.add(
                    AuditEvent(id="150", actor="synthetic", event="fixture", object_id="concurrent")
                )
            second = (
                await client.get(
                    "/api/v1/admin/audit",
                    params={"event": "fixture", "limit": 2, "after": first["next_after"]},
                )
            ).json()
            assert [x["id"] for x in second["items"]] == ["300"] and second["next_after"] is None
            refresh = (
                await client.get("/api/v1/admin/audit", params={"event": "fixture", "limit": 2})
            ).json()
            assert [x["id"] for x in refresh["items"]] == ["100", "150"]
            assert not (
                await client.get("/api/v1/admin/audit", params={"event": "fixture' OR 1=1 --"})
            ).json()["items"]


@pytest.mark.parametrize(
    "query", ("limit=0", "limit=101", "limit=bad", "after=" + "x" * 256, "event=" + "x" * 65)
)
async def test_invalid_page_inputs_are_bounded_and_not_echoed(db, query):
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            for prefix in ("/admin/", "/api/v1/admin/"):
                result = await client.get(prefix + "audit?" + query)
                assert result.status_code == 422 and "x" * 65 not in result.text


async def test_unknown_sections_invalid_filters_and_get_only_contract(db):
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            assert (await client.get("/api/v1/admin/password_hash")).status_code == 404
            assert (await client.get("/api/v1/admin/actions?event=fixture")).status_code == 422
            assert (
                await client.post("/api/v1/admin/grants", json={"role": "administrator"})
            ).status_code == 405
            assert (await client.get("/static/theme.js")).status_code == 200
    async with db.sessions() as session:
        assert await session.scalar(select(Action.id)) is None


async def test_loaded_configuration_cursor_and_no_secret_reference_readback(db):
    catalog = AdminCatalog(db, configured())
    assert not (await catalog.page("projects", after="project")).items
    assert PRIVATE not in str((await catalog.page("zulip")).response())
    with pytest.raises(ValueError, match="invalid_admin_page"):
        await catalog.page("actions", limit=101)
    with pytest.raises(ValueError, match="unknown_admin_section"):
        await catalog.page("upstream")
