"""Typed runtime rendering controls and real fenced draft/outbox behavior, isolated DB only."""

import asyncio
import html
import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import text

from jt_oz_bridge.config import load_settings
from jt_oz_bridge.security.admin import AdminAuth
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.runtime_configuration import (
    INTERVAL_KEY,
    RuntimeConfiguration,
    RuntimeValues,
    SettingIntent,
)
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.transcript_models import TranscriptDraft
from jt_oz_bridge.web.app import create_app
from tests.integration.test_resource_publisher import rows
from tests.integration.test_runtime_configuration import finish, preview, setup
from tests.integration.test_transcript_drafts import (
    current_candidate,
    deliver,
    live,
    update_text,
)
from tests.integration.test_transcript_drafts import (
    setup as draft_setup,
)


async def setting(e, value, **changes):
    before = await e.service.read(INTERVAL_KEY)
    data = dict(
        client_action_id=str(uuid.uuid4()),
        key=INTERVAL_KEY,
        value=value,
        configuration_revision=before.configuration_revision,
        baseline_hash=before.baseline_hash,
    )
    data.update(changes)
    return await e.service.preview(e.token, e.admin, e.fence, **data)


@pytest.mark.parametrize("value", [0, -1, True, 1.2, "1000", "en", 60001])
async def test_interval_rejects_coercion_wrong_type_or_outside_bound(
    db, tmp_path, monkeypatch, value
):
    e = await setup(db, tmp_path, monkeypatch)
    with pytest.raises(Conflict):
        await setting(e, value)
    assert (await e.service.read(INTERVAL_KEY)).configuration_revision == 0


@pytest.mark.parametrize(
    "toml,environment", [(None, None), (1000, None), (2500, None), (1000, "1000"), (2500, "4000")]
)
async def test_interval_set_clear_and_origin_preserve_locale(
    db, tmp_path, monkeypatch, toml, environment
):
    e = await setup(db, tmp_path, monkeypatch)
    if environment is not None:
        monkeypatch.setenv("JTOZ__RENDERING__STREAM_UPDATE_MIN_INTERVAL_MS", environment)
    else:
        monkeypatch.delenv("JTOZ__RENDERING__STREAM_UPDATE_MIN_INTERVAL_MS", raising=False)
    file = tmp_path / "rendering.toml"
    file.write_text(
        "" if toml is None else "[rendering]\nstream_update_min_interval_ms=" + str(toml) + "\n"
    )
    e.settings = load_settings(file)
    e.service = RuntimeConfiguration(db, e.settings)
    language_plan = await preview(e, "zh-TW")
    language = await finish(e, language_plan)
    initial = await e.service.read(INTERVAL_KEY)
    planned = await setting(e, 1)
    result = await finish(e, planned)
    current = await e.service.read(INTERVAL_KEY)
    assert current.value == (int(environment) if environment else 1)
    assert current.origin == ("environment" if environment else "administrator_runtime")
    assert await e.service.locale() == "zh-TW" and await finish(e, planned) == result
    assert await finish(e, language_plan) == language
    cleared = await setting(e, None)
    await finish(e, cleared)
    current = await e.service.read(INTERVAL_KEY)
    assert (current.value, current.origin) == (initial.value, initial.origin)
    assert (
        await e.service.locale() == "zh-TW"
        and e.settings.rendering.stream_update_min_interval_ms == initial.value
    )
    async with db.sessions() as session:
        assert await e.service.draft_interval(session) == initial.value / 1000
    async with db.engine.connect() as connection:
        assert (
            await connection.execute(
                text("SELECT DISTINCT typeof(payload) FROM runtime_setting_decisions")
            )
        ).scalars().all() == ["blob"]


async def test_cross_key_stale_preview_and_replay_do_not_clobber_later_value(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    locale_plan = await preview(e)
    interval_plan = await setting(e, 60000)
    old = await finish(e, locale_plan)
    with pytest.raises(Conflict):
        await finish(e, interval_plan)
    assert (await finish(e, interval_plan, cancel=True))["state"] == "cancelled"
    await finish(e, await setting(e, 60000))
    assert await finish(e, locale_plan) == old
    assert (
        await e.service.locale() == "zh-TW" and (await e.service.read(INTERVAL_KEY)).value == 60000
    )


@pytest.mark.parametrize("value", ["en", True, 0, 60001])
async def test_corrupt_cross_key_state_is_not_silently_accepted(value):
    with pytest.raises(ValidationError):
        RuntimeValues(revision=1, overrides={INTERVAL_KEY: value})


async def test_interval_nonce_cannot_be_relabelled_as_locale(db, tmp_path, monkeypatch):
    e = await setup(db, tmp_path, monkeypatch)
    item = await setting(e, 2000)
    async with db.sessions() as session:
        from jt_oz_bridge.storage.runtime_config_models import RuntimeSettingDecision

        row = await session.get(RuntimeSettingDecision, item["decision_id"])
        data = dict(row.payload)
    data["key"] = "i18n.default_locale"
    with pytest.raises(ValidationError):
        SettingIntent.model_validate(data)


async def test_existing_live_draft_uses_confirmed_interval_without_restarting_or_new_message(
    db, tmp_path, monkeypatch
):
    c, b, r, p, d, w, chat, clock, _ = await draft_setup(db, holder=str(uuid.uuid4()))
    auth = AdminAuth(db)
    password = await auth.create("render-admin")
    token, _, _ = await auth.login("render-admin", password, "setup")
    admin = await auth.authenticate(token)
    await auth.reset_password(admin, "synthetic-rendering-password")
    token, _, _ = await auth.login("render-admin", "synthetic-rendering-password", "setup")
    admin = await auth.authenticate(token)
    path = tmp_path / "render.toml"
    path.write_text("")
    monkeypatch.delenv("JTOZ__RENDERING__STREAM_UPDATE_MIN_INTERVAL_MS", raising=False)
    service = RuntimeConfiguration(db, load_settings(path))
    e = SimpleNamespace(service=service, token=token, admin=admin.id, fence=c.fence)
    d.interval_resolver = service.draft_interval
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    original = (await rows(db, TranscriptDraft))[0]
    previous = await d.outbox.load(original.payload["last_delivery_id"])
    await finish(e, await setting(e, 10000))
    clock[0] = previous.updated_at + 2.1
    await update_text(c, b, r, p, "Second partial after confirmed ten-second interval")
    waiting = await current_candidate(d)
    assert await d.publish(waiting) is None
    assert not await d.next_pending()
    await finish(e, await setting(e, 2000))
    # A new source observation enters ordinary planning immediately; no replay of the old pending request.
    await update_text(c, b, r, p, "Latest partial under two-second interval")
    latest = await current_candidate(d)
    assert latest != waiting and await d.publish(latest)
    await deliver(w)
    frame = (await rows(db, TranscriptDraft))[0]
    assert frame.record_id == original.record_id and frame.payload["minimum_interval"] == 2
    assert [kind for kind, _ in chat.calls].count("edit") == 1
    assert any(
        "Latest partial under two-second interval" in html.unescape(message.content)
        for message in chat.messages.values()
    ), [message.content for message in chat.messages.values()]
    assert not await rows(db, Action)
    # Raising the interval affects that same sealed frame; no adapter or worker restart.
    await finish(e, await setting(e, 60000))
    await update_text(c, b, r, p, "Newer text must wait")
    assert await d.publish(await current_candidate(d)) is None
    assert [kind for kind, _ in chat.calls].count("edit") == 1


async def test_rendering_api_has_both_controls_and_strict_value_validation(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    app = create_app(e.settings, db)
    from jt_oz_bridge.storage.durable import DurableStore

    await DurableStore(db).release_lease(e.fence.holder, e.fence.fencing)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "username": "runtime-admin",
                    "password": "synthetic-runtime-setting-password",
                },
            )
            assert response.status_code == 200
            csrf = client.cookies.get("jtoz_csrf")
            headers = {"X-CSRF-Token": csrf, "Origin": "https://bridge.invalid"}
            page = (await client.get("/api/v1/admin/settings", params={"limit": 100})).json()
            assert page["controls"]["key"] == "i18n.default_locale"
            view = page["controls"]["rendering_interval"]
            assert view["key"] == INTERVAL_KEY
            html = await client.get("/admin/settings", params={"limit": 100})
            assert 'id="runtime-render-editor"' in html.text and 'id="runtime-editor"' in html.text
            data = dict(
                key=INTERVAL_KEY,
                value=2500,
                client_action_id=str(uuid.uuid4()),
                configuration_revision=view["configuration_revision"],
                baseline_hash=view["baseline_hash"],
            )
            for invalid in [True, "2000", "en", 60001, 0]:
                bad = await client.post(
                    "/api/v1/admin/settings/preview",
                    json={**data, "value": invalid},
                    headers=headers,
                )
                assert bad.status_code == 422
            item = (
                await client.post("/api/v1/admin/settings/preview", json=data, headers=headers)
            ).json()
            reply = await client.post(
                "/api/v1/admin/settings/decisions/" + item["decision_id"] + "/confirm",
                json={"confirmation_token": item["confirmation_token"], "version": 1},
                headers=headers,
            )
            assert reply.status_code == 200 and (await e.service.read(INTERVAL_KEY)).value == 2500


async def test_upgrade_from28_preserves_encrypted_decisions_and_accepts_new_key(tmp_path):
    db = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "old.db"),
        cipher=EnvelopeCipher({"fixture": os.urandom(32)}, "fixture"),
    )

    def install(connection):
        cfg = Config()
        cfg.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "0028_runtime_configuration")

    try:
        from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope

        captured = db.cipher.seal(
            checked_json({"existing": "private unchanged"}),
            payload_scope("runtime_setting_decisions", "payload"),
        )
        async with db.engine.begin() as connection:
            await connection.run_sync(install)
            await connection.execute(
                text("INSERT INTO admin_accounts VALUES ('admin','existing','hash',0,1)")
            )
            await connection.execute(
                text(
                    "INSERT INTO runtime_setting_decisions VALUES ('original','admin','session','client','i18n.default_locale',0,'holder',1,'token',:payload,'hash','pending',1,1000,1)"
                ),
                {"payload": captured},
            )
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.begin() as connection:
            assert (
                await connection.execute(
                    text("SELECT payload,setting_key FROM runtime_setting_decisions")
                )
            ).one() == (captured, "i18n.default_locale")
            await connection.execute(
                text("UPDATE runtime_setting_decisions SET setting_key=:key WHERE id='original'"),
                {"key": INTERVAL_KEY},
            )
            assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()
    finally:
        await db.close()


async def test_concurrent_different_keys_share_one_configuration_revision(
    db, tmp_path, monkeypatch
):
    e = await setup(db, tmp_path, monkeypatch)
    first = await setting(e, 2000)
    second = await preview(e)
    results = await asyncio.gather(finish(e, first), finish(e, second), return_exceptions=True)
    assert sum(isinstance(item, dict) for item in results) == 1
    assert sum(isinstance(item, Conflict) for item in results) == 1
    view = await e.service.read(INTERVAL_KEY)
    assert view.configuration_revision == 1
    locale = await e.service.read()
    assert sum(value is not None for value in (view.stored_override, locale.stored_override)) == 1


async def test_draft_policy_failure_rolls_back_publication_without_fallback_or_send(
    db, tmp_path, monkeypatch
):
    c, b, r, p, d, w, chat, clock, _ = await draft_setup(db)
    path = tmp_path / "draft-policy.toml"
    path.write_text("")
    resolver = RuntimeConfiguration(db, load_settings(path))
    d.interval_resolver = resolver.draft_interval
    await live(c, b, r, p)
    async with db.engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO runtime_configuration VALUES ('site',1,:payload,'hash')"),
            {"payload": b"corrupt-own-fixture"},
        )
    before = list(chat.calls)
    with pytest.raises(Conflict):
        await d.publish(await current_candidate(d))
    assert list(chat.calls) == before and not await rows(db, TranscriptDraft)
    assert not await rows(db, Action)


async def test_schema28_confirmed_locale_receipt_replays_after29_without_reencryption(
    tmp_path, monkeypatch
):
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence
    from jt_oz_bridge.storage.payload_keys import verify_keys

    db = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "valid-old.db"),
        cipher=EnvelopeCipher({"fixture": os.urandom(32)}, "fixture"),
    )

    def old(connection):
        cfg = Config()
        cfg.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "0028_runtime_configuration")
        verify_keys(connection, initialize=True)

    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(old)
        # Bare Alembic leaves the mandatory cleanup flag pending. Complete the
        # same offline SQLite maintenance before issuing any consumer lease.
        async with db.engine.execution_options(
            jtoz_autocommit_maintenance=True
        ).connect() as connection:
            await connection.exec_driver_sql("VACUUM")
            checkpoint = (await connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")).one()
            assert checkpoint[0] == 0
        async with db.engine.begin() as connection:
            await connection.execute(
                text("UPDATE maintenance_flags SET pending=false WHERE name='payload_disk_cleanup'")
            )
        # Reconstruct an existing schema28 consumer as fixture state. The
        # current application correctly refuses to start against an old schema;
        # this does not bypass production readiness or certify the old binary.
        import time

        holder = str(uuid.uuid4())
        async with db.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO worker_leases (role,holder,expires_at,fencing) VALUES ('consumer',:holder,:expiry,1)"
                ),
                {"holder": holder, "expiry": time.time() + 30},
            )
        e = await setup(db, tmp_path, monkeypatch, fence=ConsumerFence(holder, 1))
        item = await preview(e, "zh-TW")
        receipt = await finish(e, item)
        async with db.engine.connect() as connection:
            captured = {
                t: (await connection.execute(text("SELECT payload FROM " + t))).scalars().all()
                for t in ("runtime_configuration", "runtime_setting_decisions")
            }
        await DurableStore(db).release_lease(e.fence.holder, e.fence.fencing)
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            for table, values in captured.items():
                retained = (
                    (await connection.execute(text("SELECT payload FROM " + table))).scalars().all()
                )
                assert retained == values
        holder = str(uuid.uuid4())
        fencing = await DurableStore(db).acquire_lease(holder)
        assert fencing
        e.fence = ConsumerFence(holder, fencing)
        assert await finish(e, item) == receipt and await e.service.locale() == "zh-TW"
        await finish(e, await setting(e, 5000))
        assert (
            await e.service.read(INTERVAL_KEY)
        ).value == 5000 and await e.service.locale() == "zh-TW"
    finally:
        await db.close()
