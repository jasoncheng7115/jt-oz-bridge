"""Synthetic Bridge API v1 reads and reviewed binding writes; not Human/Native acceptance."""

import time

import httpx
import pytest
from sqlalchemy import event, func, select, update

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.admin import AdminAuth
from jt_oz_bridge.storage.admin_models import AdminDecision
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding, PendingInteraction
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, uid
from jt_oz_bridge.web.app import create_app
from tests.support import bound

PRIVATE = "NEVER_RETURN_PRIVATE_API_PAYLOAD"
HOSTILE = '"><script>alert(1)</script>'
LISTS = ("backends", "projects", "sessions", "bindings", "actions", "interactions", "audit")
ORIGIN = "https://bridge.invalid"


def configured(enabled=True):
    return Settings.model_validate(
        {
            "opencode_backends": [
                {
                    "id": "backend",
                    "enabled": enabled,
                    "base_url": "https://native.invalid",
                    "credential_ref": "env:" + PRIVATE,
                }
            ],
            "zulip_realms": [
                {
                    "id": "realm",
                    "enabled": enabled,
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
                    "enabled": enabled,
                    "backend_id": "backend",
                    "realm_id": "realm",
                    "workspace_root": "/workspace/project",
                }
            ],
        }
    )


def action(binding_id, state, index, operation="prompt"):
    return Action(
        id=f"action-{index}",
        dedupe_key=f"api-{index}",
        binding_id=binding_id,
        binding_revision=1,
        actor_id=7,
        operation_digest="a" * 64,
        payload={"prompt": PRIVATE},
        admission={"original": PRIVATE},
        native_result={"output": PRIVATE},
        operation=operation,
        state=state,
    )


async def records(db):
    _, binding, control, _ = await bound(db)
    async with db.sessions.begin() as session:
        # Topic/title are Human/Agent text and must never appear in API responses.
        await session.execute(
            update(Binding)
            .where(Binding.id == binding.id)
            .values(topic=PRIVATE + HOSTILE, title=PRIVATE + HOSTILE)
        )
        for i, state in enumerate(("queued", "queued", "running", "held")):
            session.add(action(binding.id, state, i))
        session.add(action(binding.id, "failed", 9, operation=HOSTILE))
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
                    expires_at=time.time() + 600,
                )
            )
        session.add(
            Binding(
                realm_id="realm",
                channel_id=10,
                topic=PRIVATE,
                backend_id="backend",
                backend_identity="enrolled-installation",
                session_id="second-session",
                project_id="project",
                canonical_directory="/workspace/project",
                title=PRIVATE,
                owner_id=8,
                state="unbound",
                audience_revision="audience:1",
                audience_user_ids=[7, 8],
                observed_cursor="cursor",
            )
        )
        session.add(
            Artifact(
                id="artifact-1",
                binding_id=binding.id,
                binding_revision=1,
                realm_id="realm",
                project_id="project",
                actor_id=7,
                source_message_id=42,
                kind="upload",
                state="ready",
                reserved_bytes=10,
                size_bytes=10,
                checksum="e" * 64,
                key_id="synthetic-key",
                expires_at=time.time() + 600,
            )
        )
        for name, actor, when in (
            ("a1", HOSTILE, 100.0),
            ("a2", "admin:synthetic", 200.0),
            ("a3", "admin:synthetic", 300.0),
        ):
            session.add(
                AuditEvent(
                    id=name, actor=actor, event="api_fixture", object_id=name, created_at=when
                )
            )
    return binding, control


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


def client_for(app, **kwargs):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN, **kwargs)


def writes(statements):
    return [q for q in statements if q.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))]


async def counts(db):
    async with db.sessions() as session:
        return {
            model.__tablename__: await session.scalar(select(func.count()).select_from(model))
            for model in (Action, AuditEvent, AdminDecision, Grant, Binding, PendingInteraction)
        }


MUTATIONS = (
    ("PATCH", "/api/v1/bindings/{binding}"),
    ("DELETE", "/api/v1/bindings/{binding}"),
    ("POST", "/api/v1/backends"),
    ("POST", "/api/v1/backends/backend/probe"),
    ("POST", "/api/v1/bindings"),
    ("POST", "/api/v1/actions"),
    ("POST", "/api/v1/interactions/interaction-0/reply"),
)
READS = (
    *("/api/v1/" + name for name in LISTS),
    "/api/v1/actions/action-0",
    "/api/v1/artifacts/artifact-1",
)


async def test_every_route_requires_an_active_web_administrator(db):
    binding, _ = await records(db)
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        async with client_for(app) as client:
            # Anonymous requests, and Zulip Human grants of any role, confer nothing.
            async with db.sessions() as session:
                roles = set(await session.scalars(select(Grant.role)))
            assert {"operator", "administrator"} <= roles
            for path in READS:
                assert (await client.get(path)).status_code == 403
            for method, path in MUTATIONS:
                result = await client.request(method, path.format(binding=binding.id), json={})
                assert result.status_code == 403
            async with client_for(app, cookies={"jtoz_session": "forged"}) as forged:
                for path in READS:
                    assert (await forged.get(path)).status_code == 403
            initial = await AdminAuth(db).create("admin")
            await client.post("/api/v1/auth/login", json={"username": "admin", "password": initial})
            for path in READS:  # A password reset is still required.
                assert (await client.get(path)).status_code == 403
            await AdminAuth(db).reset_password(
                await AdminAuth(db).authenticate(client.cookies["jtoz_session"]),
                "synthetic-admin-password-123",
            )
            login = await client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "synthetic-admin-password-123"},
            )
            csrf = login.json()["csrf_token"]
            for path in READS:
                assert (await client.get(path)).status_code == 200, path
            for method, path in MUTATIONS:  # No CSRF header: refused before any work.
                result = await client.request(method, path.format(binding=binding.id), json={})
                assert result.status_code == 403
                assert result.json()["code"] == "csrf_failed"
            disabled = create_app(Settings(admin={"enabled": False}), db)
            async with client_for(disabled, cookies=client.cookies) as denied:
                for path in READS:
                    assert (await denied.get(path)).status_code == 403
                result = await denied.post("/api/v1/actions", headers={"x-csrf-token": csrf})
                assert result.status_code == 403
                assert result.json()["code"] == "admin_disabled"


@pytest.mark.parametrize("resource", LISTS)
async def test_lists_never_decrypt_write_or_return_private_text(db, monkeypatch, resource):
    await records(db)
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        async with client_for(app) as client:
            await sign_in(client, db)

            def forbidden(*args, **kwargs):
                raise AssertionError("API read decrypted a payload")

            monkeypatch.setattr(db.cipher, "open", forbidden)
            statements = []

            def observe(conn, cursor, statement, params, context, many):
                statements.append(statement)

            event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
            try:
                result = await client.get("/api/v1/" + resource)
            finally:
                event.remove(db.engine.sync_engine, "before_cursor_execute", observe)
            assert result.status_code == 200
            data = result.json()
            assert data["read_only"] is True and data["resource"] == resource
            assert PRIVATE not in result.text and "synthetic-bot@" not in result.text
            assert not writes(statements)
            assert result.headers["cache-control"] == "no-store"
            for item in data["items"]:
                assert not {
                    "topic",
                    "title",
                    "payload",
                    "admission",
                    "native_result",
                    "snapshot",
                    "audience_user_ids",
                    "credential_ref",
                    "key_id",
                } & set(item)
            if resource == "backends":
                assert data["probe_available"] is False
                assert data["items"][0]["connection_checked"] is False
            if resource == "projects":
                row = data["items"][0]
                assert row["enrolled"] and row["enrolled_enabled"] and row["enrollment_matches"]
            if resource == "interactions":
                assert [x["id"] for x in data["items"]] == ["interaction-0"]
            if resource == "sessions":
                assert data["native_requests"] == 0
                assert [(x["session_id"], x["active_bindings"]) for x in data["items"]] == [
                    ("original-session", 1),
                    ("second-session", 0),
                ]
                assert data["items"][0]["enrolled_scope"] is True
                assert not any(x["native_observed"] for x in data["items"])


@pytest.mark.parametrize(
    "query",
    (
        "limit=0",
        "limit=101",
        "limit=bad",
        "after=" + "x" * 256,
        "state=" + "x" * 40,
        "state=Bad%20State",
        "actor_id=12x",
        "actor_id=99999999999999999999",
        "unknown=1",
        "state=queued&state=held",
        "event=x",
    ),
)
async def test_invalid_pages_and_filters_are_bounded_and_not_echoed(db, query):
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with client_for(app) as client:
            await sign_in(client, db)
            result = await client.get("/api/v1/actions?" + query)
            assert result.status_code == 422 and "x" * 40 not in result.text


@pytest.mark.parametrize(
    "path",
    (
        "/api/v1/sessions?after=" + "A" * 1025,
        "/api/v1/sessions?after=not-a-cursor",
        "/api/v1/sessions?active=maybe",
        "/api/v1/audit?since=nan",
        "/api/v1/audit?until=1e400",
        "/api/v1/audit?event=" + "e" * 65,
        "/api/v1/bindings?dispatch_paused=yes",
        "/api/v1/projects?realm_id=" + "r" * 256,
        "/api/v1/actions/" + "a" * 37,
        "/api/v1/artifacts/bad%20id",
    ),
)
async def test_other_bounds_reject_invalid_input(db, path):
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        async with client_for(app) as client:
            await sign_in(client, db)
            assert (await client.get(path)).status_code == 422


async def test_filters_keyset_pages_and_details(db):
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        # Startup recovery holds queued work, so queued fixtures are added afterwards.
        await records(db)
        async with client_for(app) as client:
            await sign_in(client, db)
            first = (await client.get("/api/v1/actions", params={"limit": 2})).json()
            assert [x["id"] for x in first["items"]] == ["action-0", "action-1"]
            second = (
                await client.get(
                    "/api/v1/actions", params={"limit": 2, "after": first["next_after"]}
                )
            ).json()
            assert [x["id"] for x in second["items"]] == ["action-2", "action-3"]
            queued = (await client.get("/api/v1/actions", params={"state": "queued"})).json()
            assert {x["id"] for x in queued["items"]} == {"action-0", "action-1"}
            assert queued["filters"] == {"state": "queued"}
            by_actor = (await client.get("/api/v1/actions", params={"actor_id": "8"})).json()
            assert by_actor["items"] == []
            answered = (
                await client.get("/api/v1/interactions", params={"state": "answered"})
            ).json()
            assert [x["id"] for x in answered["items"]] == ["interaction-1"]
            audit = (
                await client.get(
                    "/api/v1/audit",
                    params={"actor": "admin:synthetic", "since": "150", "until": "300"},
                )
            ).json()
            assert [x["id"] for x in audit["items"]] == ["a2"]
            injected = await client.get("/api/v1/audit", params={"actor": "x' OR 1=1 --"})
            assert injected.status_code == 200 and injected.json()["items"] == []
            paused = (await client.get("/api/v1/bindings", params={"state": "unbound"})).json()
            assert [x["session_id"] for x in paused["items"]] == ["second-session"]
            sessions = (await client.get("/api/v1/sessions", params={"limit": 1})).json()
            assert sessions["next_after"]
            rest = (
                await client.get(
                    "/api/v1/sessions", params={"limit": 1, "after": sessions["next_after"]}
                )
            ).json()
            assert [x["session_id"] for x in rest["items"]] == ["second-session"]
            assert rest["next_after"] is None
            active = (await client.get("/api/v1/sessions", params={"active": "false"})).json()
            assert [x["session_id"] for x in active["items"]] == ["second-session"]
            detail = (await client.get("/api/v1/actions/action-0")).json()
            assert detail["item"]["state"] == "queued" and PRIVATE not in str(detail)
            assert (await client.get("/api/v1/actions/missing")).status_code == 404
            artifact = await client.get("/api/v1/artifacts/artifact-1")
            data = artifact.json()
            assert data["download"] == {
                "available": False,
                "reason": "no_http_artifact_download_endpoint",
            }
            assert data["descriptor_encrypted"] is True
            assert "synthetic-key" not in artifact.text
            assert not {"filename", "mime_type", "key_id"} & set(data["item"])
            assert data["item"]["checksum"] == "e" * 64
            assert (await client.get("/api/v1/artifacts/missing")).status_code == 404


async def test_patch_and_delete_go_through_preview_and_confirmation(db):
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        binding, control = await records(db)
        async with client_for(app) as client:
            csrf = await sign_in(client, db)
            headers = {"x-csrf-token": csrf}
            path = f"/api/v1/bindings/{binding.id}"
            body = {
                "client_action_id": uid(),
                "dispatch_paused": True,
                "binding_revision": 1,
                "queue_revision": 0,
            }
            evil = await client.patch(
                path, json=body, headers={**headers, "origin": "https://evil.invalid"}
            )
            assert evil.status_code == 403
            extra = await client.patch(
                path, json={**body, "actor_id": 7, "note": "DO_NOT_ECHO"}, headers=headers
            )
            assert extra.status_code == 422 and "DO_NOT_ECHO" not in extra.text
            before = await counts(db)
            resume = await client.patch(
                path, json={**body, "dispatch_paused": False}, headers=headers
            )
            assert resume.status_code == 403
            assert resume.json()["reason"] == "queue_resume_requires_zulip_human"
            assert await counts(db) == before
            preview = await client.patch(path, json=body, headers=headers)
            assert preview.status_code == 200
            data = preview.json()
            assert data["state"] == "pending" and data["preview"]["operation"] == "pause"
            assert data["preview"]["affected"]["actions"]["queued"] == 2
            assert (await client.patch(path, json=body, headers=headers)).json() == data
            async with db.sessions() as session:  # Preview alone changes nothing.
                assert not (await session.get(Binding, binding.id)).dispatch_paused
            confirmed = await client.post(
                data["confirm_path"],
                json={"confirmation_token": data["confirmation_token"], "version": 1},
                headers=headers,
            )
            assert confirmed.status_code == 200 and confirmed.json()["state"] == "confirmed"
            async with db.sessions() as session:
                current = await session.get(Binding, binding.id)
                assert current.dispatch_paused and current.state == "active"
                states = set(await session.scalars(select(Action.state)))
                assert "queued" not in states and "held" in states
            unbind = {"client_action_id": uid(), "binding_revision": 1, "queue_revision": 1}
            stale = await client.request(
                "DELETE", path, json={**unbind, "queue_revision": 0}, headers=headers
            )
            assert stale.status_code == 409
            preview = await client.request("DELETE", path, json=unbind, headers=headers)
            assert preview.status_code == 200
            data = preview.json()
            assert data["preview"]["operation"] == "unbind"
            assert data["preview"]["native_session_deleted"] is False
            cancelled = await client.post(
                data["cancel_path"],
                json={"confirmation_token": data["confirmation_token"], "version": 1},
                headers=headers,
            )
            assert cancelled.json()["state"] == "cancelled"
            again = await client.request(
                "DELETE", path, json={**unbind, "client_action_id": uid()}, headers=headers
            )
            data = again.json()
            confirmed = await client.post(
                data["confirm_path"],
                json={"confirmation_token": data["confirmation_token"], "version": 1},
                headers=headers,
            )
            assert confirmed.json()["result"]["native_session_deleted"] is False
            async with db.sessions() as session:
                current = await session.get(Binding, binding.id)
                assert current.state == "unbound" and current.revision == 2
            assert all(call[0] == "snapshot" for call in control.calls)


@pytest.mark.parametrize("method,path", MUTATIONS[2:])
async def test_refused_writes_change_nothing(db, method, path):
    await records(db)
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        async with client_for(app) as client:
            csrf = await sign_in(client, db)
            before = await counts(db)
            result = await client.request(
                method,
                path,
                json={"answer": "allow", "role": "administrator", "token": "DO_NOT_ECHO"},
                headers={"x-csrf-token": csrf},
            )
            assert result.status_code == 403
            assert result.json()["code"] == "administrative_write_refused"
            assert result.json()["reason"].endswith(
                ("_manifest", "_human", "_qualification", "_confirmation")
            )
            assert "DO_NOT_ECHO" not in result.text
            assert await counts(db) == before


async def test_html_sections_show_filters_new_columns_and_escape_hostile_text(db):
    await records(db)
    app = create_app(configured(), db)
    async with app.router.lifespan_context(app):
        async with client_for(app) as client:
            await sign_in(client, db)
            page = await client.get(
                "/admin/actions", params={"state": "failed", "operation": HOSTILE}
            )
            assert page.status_code == 200
            assert HOSTILE not in page.text and "<script>alert(1)</script>" not in page.text
            assert "&lt;script&gt;" in page.text and PRIVATE not in page.text
            assert 'name="state"' in page.text and 'value="failed"' in page.text
            assert "/api/v1/actions" in page.text and "Status reason" in page.text
            audit = await client.get("/admin/audit", params={"limit": 1, "actor": HOSTILE})
            assert "<script>alert(1)</script>" not in audit.text
            listed = await client.get(
                "/admin/audit", params={"limit": 1, "event": "api_fixture", "since": "1"}
            )
            assert "/admin/audit?limit=1&amp;after=a1&amp;event=api_fixture&amp;since=1" in (
                listed.text
            )
            assert (await client.get("/admin/grants", params={"state": "x"})).status_code == 422
            grants = await client.get("/admin/grants", params={"role": "operator"})
            assert "operator-reviewed runtime manifest" in grants.text
            projects = await client.get("/admin/projects")
            assert "Enrollment matches allowlist" in projects.text
            bindings = await client.get("/admin/bindings", params={"dispatch_paused": "false"})
            assert bindings.status_code == 200 and PRIVATE not in bindings.text
            assert 'value="false" selected' in bindings.text
            await client.patch(
                "/api/v1/preferences/me",
                json={"locale": "zh-TW"},
                headers={"x-csrf-token": client.cookies["jtoz_csrf"]},
            )
            translated = await client.get("/admin/backends")
            assert "操作者審核過的執行期清單" in translated.text
