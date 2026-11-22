"""Real isolated SQL/runtime setting decisions; no Agent/Zulip writes."""

import asyncio
import json
import time
import uuid
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import event, func, select, text, update

from jt_oz_bridge.config import Settings, load_settings
from jt_oz_bridge.security.admin import AdminAuth, LoginRejected
from jt_oz_bridge.services.admin_decisions import AdminDecisions
from jt_oz_bridge.services.runtime_configuration import RuntimeConfiguration
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AdminAccount, AuditEvent, WorkerLease
from jt_oz_bridge.storage.runtime_config_models import (
    RuntimeConfigurationState,
    RuntimeSettingDecision,
)
from jt_oz_bridge.web.app import create_app

PASSWORD = "synthetic-runtime-setting-password"


async def setup(db, tmp_path, monkeypatch, *, toml=None, environment=None, fence=None):
    path = tmp_path / "runtime-config.toml"
    path.write_text("" if toml is None else '[i18n]\ndefault_locale="' + toml + '"\n')
    if environment is None:
        monkeypatch.delenv("JTOZ__I18N__DEFAULT_LOCALE", raising=False)
    else:
        monkeypatch.setenv("JTOZ__I18N__DEFAULT_LOCALE", environment)
    settings = load_settings(path)
    auth = AdminAuth(db)
    password = await auth.create("runtime-admin")
    token, _, _ = await auth.login("runtime-admin", password, "setup")
    account = await auth.authenticate(token)
    await auth.reset_password(account, PASSWORD)
    token, csrf, _ = await auth.login("runtime-admin", PASSWORD, "setup")
    account = await auth.authenticate(token)
    if fence is None:
        holder = str(uuid.uuid4())
        epoch = await DurableStore(db).acquire_lease(holder)
        assert epoch
        fence = ConsumerFence(holder, epoch)
    return SimpleNamespace(
        db=db,
        settings=settings,
        auth=auth,
        token=token,
        csrf=csrf,
        admin=account.id,
        fence=fence,
        service=RuntimeConfiguration(db, settings),
    )


async def preview(e, value="zh-TW", **changes):
    view = await e.service.read()
    data = dict(
        client_action_id=str(uuid.uuid4()),
        key="i18n.default_locale",
        value=value,
        configuration_revision=view.configuration_revision,
        baseline_hash=view.baseline_hash,
    )
    data.update(changes)
    return await e.service.preview(e.token, e.admin, e.fence, **data)


async def finish(e, item, **changes):
    data = dict(
        decision_id=item["decision_id"], confirmation_token=item["confirmation_token"], version=1
    )
    data.update(changes)
    return await e.service.finish(e.token, e.admin, e.fence, **data)


@pytest.mark.parametrize(
    "toml,environment", [(None, None), ("en", None), ("zh-TW", None), ("en", "en"), ("en", "zh-TW")]
)
async def test_set_clear_precedence_encryption_and_original_settings_unchanged(
    db, tmp_path, monkeypatch, toml, environment
):
    e = await setup(db, tmp_path, monkeypatch, toml=toml, environment=environment)
    original = e.settings.model_dump(mode="json")
    before = await e.service.read()
    item = await preview(e, "zh-TW")
    reply = await finish(e, item)
    view = await e.service.read()
    assert (
        reply["state"] == "confirmed"
        and view.configuration_revision == 1
        and view.stored_override == "zh-TW"
    )
    assert view.value == (environment or "zh-TW") and view.origin == (
        "environment" if environment else "administrator_runtime"
    )
    assert await finish(e, item) == reply and (await e.service.read()).configuration_revision == 1
    cleared = await preview(e, None)
    await finish(e, cleared)
    view = await e.service.read()
    assert (
        view.configuration_revision == 2
        and view.stored_override is None
        and view.value == before.value
        and view.origin == before.origin
    )
    assert e.settings.model_dump(mode="json") == original
    async with db.engine.connect() as c:
        payloads = (
            (await c.execute(text("SELECT payload FROM runtime_setting_decisions"))).scalars().all()
        )
        assert all(
            isinstance(x, bytes) and item["confirmation_token"].encode() not in x for x in payloads
        )
        assert (
            await c.execute(text("SELECT typeof(payload) FROM runtime_configuration"))
        ).scalar_one() == "blob"
        for table in ("actions", "bindings", "command_receipts", "control_tokens"):
            assert (await c.execute(text("SELECT COUNT(*) FROM " + table))).scalar_one() == 0
    async with db.sessions() as s:
        actors = (
            await s.scalars(
                select(AuditEvent.actor).where(AuditEvent.event.like("runtime_setting_%"))
            )
        ).all()
        assert actors and set(actors) == {"admin:" + e.admin}


async def test_replay_is_original_receipt_after_another_setting_change(db, tmp_path, monkeypatch):
    e = await setup(db, tmp_path, monkeypatch)
    a = await preview(e)
    old = await finish(e, a)
    b = await preview(e, "en")
    await finish(e, b)
    assert (
        await finish(e, a) == old
        and (await e.service.read()).configuration_revision == 2
        and (await e.service.read()).value == "en"
    )


async def test_same_client_id_retries_same_preview_but_cannot_change_intent(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    client = str(uuid.uuid4())
    a = await preview(e, client_action_id=client)
    assert await preview(e, client_action_id=client) == a
    with pytest.raises(Conflict):
        await preview(e, "en", client_action_id=client)
    replies = await asyncio.gather(finish(e, a), finish(e, a))
    assert replies[0] == replies[1] and (await e.service.read()).configuration_revision == 1


async def test_stale_preview_rejected_then_cancelled_without_overwriting_new_revision(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    first = await preview(e)
    stale = await preview(e, "en")
    await finish(e, first)
    with pytest.raises(Conflict):
        await finish(e, stale)
    assert (await finish(e, stale, cancel=True))["state"] == "cancelled"
    with pytest.raises(Conflict):
        await finish(e, stale)
    assert (await e.service.read()).configuration_revision == 1


@pytest.mark.parametrize("change", ["settings", "session", "fence", "expired", "reset", "disabled"])
async def test_changed_authority_or_scope_cannot_consume_pending_setting(
    db, tmp_path, monkeypatch, change
):
    e = await setup(db, tmp_path, monkeypatch)
    item = await preview(e)
    if change == "settings":
        e.settings.i18n.default_locale = "zh-TW"
    elif change == "session":
        await e.auth.logout(e.token)
    elif change == "disabled":
        e.settings.admin.enabled = False
    else:
        async with db.sessions.begin() as s:
            if change == "fence":
                await s.execute(update(WorkerLease).values(fencing=e.fence.fencing + 1))
            elif change == "expired":
                row = await s.get(RuntimeSettingDecision, item["decision_id"])
                payload = dict(row.payload)
                payload["expires_at"] = time.time() - 1
                from jt_oz_bridge.storage.durable import digest

                row.payload = payload
                row.payload_hash = digest(payload)
                row.expires_at = payload["expires_at"]
            else:
                await s.execute(update(AdminAccount).values(must_reset=True))
    with pytest.raises((Conflict, LoginRejected)):
        await finish(e, item)
    async with db.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(RuntimeConfigurationState)) == 0
        assert (await s.get(RuntimeSettingDecision, item["decision_id"])).state == "pending"


async def test_new_epoch_can_replay_completed_but_cannot_confirm_old_pending(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    a = await preview(e)
    result = await finish(e, a)
    pending = await preview(e, "en")
    await DurableStore(db).release_lease(e.fence.holder, e.fence.fencing)
    holder = str(uuid.uuid4())
    number = await DurableStore(db).acquire_lease(holder)
    e.fence = ConsumerFence(holder, number)
    assert await finish(e, a) == result
    with pytest.raises(Conflict):
        await finish(e, pending)
    assert (await finish(e, pending, cancel=True))["state"] == "cancelled"


@pytest.mark.parametrize("mode", ["insert", "update"])
async def test_real_sql_wait_rechecks_deadline_at_actual_configuration_write(
    db, tmp_path, monkeypatch, mode
):
    e = await setup(db, tmp_path, monkeypatch)
    if mode == "update":
        await finish(e, await preview(e))
    before = await e.service.read()
    monkeypatch.setattr("jt_oz_bridge.services.runtime_configuration.TTL", 1.0)
    item = await preview(e, "en")
    waited = []

    def wait(conn, cursor, statement, params, context, many):
        if statement.upper().startswith(
            ("INSERT INTO RUNTIME_CONFIGURATION ", "UPDATE RUNTIME_CONFIGURATION ")
        ):
            waited.append(True)
            time.sleep(1.2)

    event.listen(db.engine.sync_engine, "before_cursor_execute", wait)
    try:
        with pytest.raises(Conflict):
            await finish(e, item)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", wait)
    assert waited and await e.service.read() == before
    async with db.sessions() as s:
        assert (await s.get(RuntimeSettingDecision, item["decision_id"])).state == "pending"


async def test_audit_failure_rolls_back_state_and_nonce_together(db, tmp_path, monkeypatch):
    e = await setup(db, tmp_path, monkeypatch)
    item = await preview(e)

    def fail(conn, cursor, statement, params, context, many):
        if (
            statement.upper().startswith("INSERT INTO AUDIT_EVENTS")
            and "runtime_setting_changed" in params
        ):
            raise RuntimeError("synthetic audit unavailable")

    event.listen(db.engine.sync_engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError):
            await finish(e, item)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", fail)
    assert (await e.service.read()).configuration_revision == 0
    assert (await finish(e, item))["state"] == "confirmed"


@pytest.mark.parametrize("kind", ["token", "value", "key", "baseline", "revision"])
async def test_invalid_confirmation_and_scope_input_cannot_write(db, tmp_path, monkeypatch, kind):
    e = await setup(db, tmp_path, monkeypatch)
    with pytest.raises(Conflict):
        if kind == "token":
            await finish(e, await preview(e), confirmation_token="wrong")
        else:
            await preview(
                e,
                **{"value": "unsupported"}
                if kind == "value"
                else {"key": "security.secret_key_ref"}
                if kind == "key"
                else {"baseline_hash": "0" * 64}
                if kind == "baseline"
                else {"configuration_revision": True},
            )
    assert (await e.service.read()).configuration_revision == 0


async def test_programmatic_and_changed_base_do_not_invent_runtime_precedence(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    await finish(e, await preview(e))
    untracked = RuntimeConfiguration(db, Settings())
    view = await untracked.read()
    assert (
        not view.runtime_allowed
        and view.origin == "not_recorded"
        and view.stored_override == "zh-TW"
        and view.value == "en"
    )
    e.settings.app.log_level = "DEBUG"
    view = await e.service.read()
    assert not view.runtime_allowed and view.origin == "modified_after_load"


async def test_pending_limit_is_shared_with_binding_controls(db, tmp_path, monkeypatch):
    e = await setup(db, tmp_path, monkeypatch)
    for _ in range(50):
        await preview(e)
    with pytest.raises(Conflict, match="pending_preview_limit"):
        await AdminDecisions(db, e.settings).preview(
            e.token,
            e.admin,
            e.fence,
            client_action_id=str(uuid.uuid4()),
            operation="pause",
            binding_id=str(uuid.uuid4()),
            binding_revision=1,
            queue_revision=0,
        )
    with pytest.raises(Conflict, match="pending_preview_limit"):
        await preview(e)


async def test_web_site_default_hot_reload_saved_preference_and_post_security(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    await DurableStore(db).release_lease(e.fence.holder, e.fence.fencing)
    app = create_app(e.settings, db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as c:
            await c.post(
                "/api/v1/auth/login", json={"username": "runtime-admin", "password": PASSWORD}
            )
            csrf = c.cookies["jtoz_csrf"]
            body = {
                "client_action_id": str(uuid.uuid4()),
                "key": "i18n.default_locale",
                "value": "zh-TW",
                **{
                    k: v
                    for k, v in (await e.service.read()).model_dump().items()
                    if k in {"configuration_revision", "baseline_hash"}
                },
            }
            assert (await c.post("/api/v1/admin/settings/preview", json=body)).status_code == 403
            assert (
                await c.post(
                    "/api/v1/admin/settings/preview",
                    json=body,
                    headers={"x-csrf-token": csrf, "origin": "https://foreign.invalid"},
                )
            ).status_code == 403
            reply = await c.post(
                "/api/v1/admin/settings/preview", json=body, headers={"x-csrf-token": csrf}
            )
            assert reply.status_code == 200
            data = reply.json()
            url = "/api/v1/admin/settings/decisions/" + data["decision_id"] + "/confirm"
            assert (await c.get(url)).status_code == 405
            finished = await c.post(
                url,
                json={"confirmation_token": data["confirmation_token"], "version": 1},
                headers={"x-csrf-token": csrf},
            )
            assert finished.status_code == 200
            assert 'lang="zh-TW"' in (await c.get("/")).text
            saved = await c.patch(
                "/api/v1/preferences/me", json={"locale": "en"}, headers={"x-csrf-token": csrf}
            )
            assert saved.status_code == 200 and 'lang="en"' in (await c.get("/")).text
            page = (await c.get("/api/v1/admin/settings", params={"limit": 100})).json()
            row = next(x for x in page["items"] if x["id"] == "i18n.default_locale")
            assert row["value"] == "zh-TW" and row["origin"] == "administrator_runtime"
            assert "confirmation_token" not in json.dumps(
                page
            ) and "payload_hash" not in json.dumps(page)


@pytest.mark.parametrize("table", ["admin_sessions", "worker_leases", "admin_accounts"])
async def test_actual_configuration_sql_rechecks_authority_after_nonce_claim(
    db, tmp_path, monkeypatch, table
):
    e = await setup(db, tmp_path, monkeypatch)
    item = await preview(e)
    changed = []

    def revoke(conn, cursor, statement, params, context, many):
        if statement.upper().startswith("INSERT INTO RUNTIME_CONFIGURATION "):
            cursor.execute(
                "UPDATE "
                + table
                + " SET "
                + ("must_reset=1" if table == "admin_accounts" else "expires_at=0")
            )
            changed.append(True)

    event.listen(db.engine.sync_engine, "before_cursor_execute", revoke)
    try:
        with pytest.raises(Conflict):
            await finish(e, item)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", revoke)
    assert changed and (await e.service.read()).configuration_revision == 0
    assert (await finish(e, item))["state"] == "confirmed"


async def test_setting_and_receipt_survive_an_independent_engine_and_epoch(
    db, tmp_path, monkeypatch
):
    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.storage.database import Database

    e = await setup(db, tmp_path, monkeypatch)
    item = await preview(e)
    reply = await finish(e, item)
    await DurableStore(db).release_lease(e.fence.holder, e.fence.fencing)
    second = Database(str(db.engine.url), cipher=EnvelopeCipher(e.db.cipher._keys, "test"))
    try:
        assert await second.ready()
        service = RuntimeConfiguration(second, load_settings(tmp_path / "runtime-config.toml"))
        assert (await service.read()).value == "zh-TW"
        holder = str(uuid.uuid4())
        number = await DurableStore(second).acquire_lease(holder)
        fence = ConsumerFence(holder, number)
        assert (
            await service.finish(
                e.token,
                e.admin,
                fence,
                decision_id=item["decision_id"],
                confirmation_token=item["confirmation_token"],
                version=1,
            )
            == reply
        )
    finally:
        await second.close()


async def test_other_administrator_cannot_use_setting_nonce(db, tmp_path, monkeypatch):
    e = await setup(db, tmp_path, monkeypatch)
    item = await preview(e)
    # A second synthetic existing account; bootstrap itself remains one-use.
    async with db.sessions.begin() as session:
        original = await session.get(AdminAccount, e.admin)
        session.add(
            AdminAccount(
                username="other-runtime-admin",
                password_hash=original.password_hash,
                must_reset=False,
            )
        )
    token, _, _ = await e.auth.login("other-runtime-admin", PASSWORD, "other")
    user = await e.auth.authenticate(token)
    with pytest.raises(Conflict):
        await e.service.finish(
            token,
            user.id,
            e.fence,
            decision_id=item["decision_id"],
            confirmation_token=item["confirmation_token"],
            version=1,
        )
    assert (await e.service.read()).configuration_revision == 0


async def test_removing_environment_requires_new_startup_model_before_runtime_becomes_effective(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch, toml="en", environment="en")
    await finish(e, await preview(e))
    assert (await e.service.read()).environment_shadowed
    monkeypatch.delenv("JTOZ__I18N__DEFAULT_LOCALE")
    assert (await e.service.read()).origin == "environment"
    restarted = RuntimeConfiguration(db, load_settings(tmp_path / "runtime-config.toml"))
    view = await restarted.read()
    assert view.value == "zh-TW" and view.origin == "administrator_runtime"


async def test_slow_preview_flush_cannot_issue_already_expired_confirmation(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    monkeypatch.setattr("jt_oz_bridge.services.runtime_configuration.TTL", 0.1)

    def wait(conn, cursor, statement, params, context, many):
        if statement.upper().startswith("INSERT INTO RUNTIME_SETTING_DECISIONS "):
            time.sleep(0.2)

    event.listen(db.engine.sync_engine, "before_cursor_execute", wait)
    try:
        with pytest.raises(Conflict):
            await preview(e)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", wait)
    async with db.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(RuntimeSettingDecision)) == 0


async def test_web_invalid_setting_input_does_not_echo_private_body(db, tmp_path, monkeypatch):
    e = await setup(db, tmp_path, monkeypatch)
    await DurableStore(db).release_lease(e.fence.holder, e.fence.fencing)
    app = create_app(e.settings, db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as c:
            await c.post(
                "/api/v1/auth/login", json={"username": "runtime-admin", "password": PASSWORD}
            )
            response = await c.post(
                "/api/v1/admin/settings/preview",
                json={
                    "value": "PRIVATE_RUNTIME_BODY",
                    "key": "security.secret_key_ref",
                    "client_action_id": "bad",
                    "configuration_revision": True,
                    "baseline_hash": "PRIVATE_RUNTIME_BODY",
                },
                headers={"x-csrf-token": c.cookies["jtoz_csrf"]},
            )
            assert response.status_code == 422 and "PRIVATE_RUNTIME_BODY" not in response.text


@pytest.mark.parametrize("target", ["decision", "state"])
async def test_corrupted_encrypted_configuration_evidence_is_rejected(
    db, tmp_path, monkeypatch, target
):
    e = await setup(db, tmp_path, monkeypatch)
    item = await preview(e)
    if target == "decision":
        async with db.engine.begin() as c:
            await c.execute(
                text("UPDATE runtime_setting_decisions SET payload=:body"), {"body": b"corrupt"}
            )
        with pytest.raises(Conflict):
            await finish(e, item)
    else:
        await finish(e, item)
        async with db.engine.begin() as c:
            await c.execute(
                text("UPDATE runtime_configuration SET payload=:body"), {"body": b"corrupt"}
            )
        with pytest.raises(Conflict):
            await e.service.read()
