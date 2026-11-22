"""Authenticated startup-setting projections; synthetic DB, no upstream."""

import json

import httpx
import pytest
from sqlalchemy import event

from jt_oz_bridge.config import load_settings
from jt_oz_bridge.web.app import create_app
from jt_oz_bridge.web.catalog import AdminCatalog
from tests.integration.test_admin_catalog import sign_in

PRIVATE = "NEVER_DISPLAY_CONFIGURATION_REFERENCE"


def configured(tmp_path, monkeypatch):
    file = tmp_path / "private-config.toml"
    file.write_text(
        '[app]\nlog_level="INFO"\n[security]\nsecret_key_ref="env:' + PRIVATE + '"\n'
        '[admin]\nbootstrap_token_ref="file:/private/' + PRIVATE + '"\n'
        'session_signing_key_ref="env:' + PRIVATE + '"\n'
        '[database]\nurl_ref="env:' + PRIVATE + '"\n'
        '[[opencode_backends]]\nid="backend"\nbase_url="https://native.invalid"\n'
        'credential_ref="env:' + PRIVATE + '"\n'
        '[[zulip_realms]]\nid="realm"\nurl="https://chat.invalid"\n'
        'bot_email="bot@chat.invalid"\napi_key_ref="env:' + PRIVATE + '"\n'
        '[[projects]]\nid="project"\nbackend_id="backend"\nrealm_id="realm"\n'
        'workspace_root="/workspace/project"\n'
    )
    monkeypatch.setenv("JTOZ__APP__LOG_LEVEL", "INFO")
    return load_settings(file)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_authenticated_configuration_values_sources_and_pagination_without_secrets_or_writes(
    db, tmp_path, monkeypatch, locale
):
    settings = configured(tmp_path, monkeypatch)
    app = create_app(settings, db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            csrf = await sign_in(client, db)
            await client.patch(
                "/api/v1/preferences/me", json={"locale": locale}, headers={"x-csrf-token": csrf}
            )
            statements = []

            def observe(conn, cursor, statement, params, context, many):
                statements.append(statement)

            def forbidden(*args, **kwargs):
                raise AssertionError("settings GET attempted secret/payload/network resolution")

            event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
            monkeypatch.setattr(db.cipher, "open", forbidden)
            monkeypatch.setattr("jt_oz_bridge.security.secrets.resolve_secret", forbidden)
            monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
            rows, after = [], ""
            try:
                for _ in range(20):
                    response = await client.get(
                        "/api/v1/admin/settings", params={"limit": 17, "after": after}
                    )
                    assert response.status_code == 200 and PRIVATE not in response.text
                    data = response.json()
                    assert data["read_only"] and data["source"] == "startup_configuration"
                    assert len(data["items"]) <= 17
                    rows.extend(data["items"])
                    after = data["next_after"]
                    if after is None:
                        break
                else:
                    pytest.fail("configuration pagination failed to terminate")
                assert len(rows) == len({row["id"] for row in rows}) > 70
                actual = {row["id"]: row for row in rows}
                assert actual["app.log_level"]["value"] == "INFO"
                assert actual["app.log_level"]["origin"] == "environment"
                assert actual["app.workers"]["origin"] == "default"
                assert actual["opencode_backends.0.base_url"]["origin"] == "toml"
                assert all(
                    row["application"]
                    == (
                        "runtime_allowed"
                        if row["id"]
                        in {"i18n.default_locale", "rendering.stream_update_min_interval_ms"}
                        else "restart_required"
                    )
                    for row in rows
                )
                assert not any("_ref" in row["id"] or row["id"] == "database.url" for row in rows)
                html = await client.get("/admin/settings", params={"limit": 100})
                assert html.status_code == 200 and PRIVATE not in html.text
                assert ("Environment override" if locale == "en" else "環境變數覆寫") in html.text
                assert ("Bridge restart" if locale == "en" else "重啟 Bridge 後") in html.text
                assert f'lang="{locale}"' in html.text
                assert all(
                    not sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
                    for sql in statements
                )
            finally:
                event.remove(db.engine.sync_engine, "before_cursor_execute", observe)


@pytest.mark.parametrize("changed", [False, True])
async def test_projection_reports_missing_or_stale_origin_honestly(
    db, tmp_path, monkeypatch, changed
):
    settings = configured(tmp_path, monkeypatch)
    if changed:
        settings.retention.audit_metadata_days = 91
        expected = "modified_after_load"
    else:
        settings = type(settings).model_validate(settings.model_dump())
        expected = "not_recorded"
    page = await AdminCatalog(db, settings).page("settings", limit=100)
    assert set(row["origin"] for row in page.items) == {expected}
    assert PRIVATE not in json.dumps(page.response(), default=str)


async def test_setting_values_are_html_escaped_without_creating_links(db, tmp_path, monkeypatch):
    settings = configured(tmp_path, monkeypatch)
    settings.projects[0].workspace_root = '/workspace/<img src=x onerror="alert(1)">'
    app = create_app(settings, db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            await sign_in(client, db)
            response = await client.get("/admin/settings", params={"limit": 100})
            assert response.status_code == 200
            assert (
                "&lt;img" in response.text and '<img src=x onerror="alert(1)">' not in response.text
            )
