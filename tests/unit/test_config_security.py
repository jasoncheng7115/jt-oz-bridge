import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from jt_oz_bridge.config import Settings, load_settings
from jt_oz_bridge.security.secrets import SecretUnavailable, resolve_secret


def test_supplied_example_loads_without_resolving_secrets():
    settings = load_settings(Path("config.example.toml"))
    assert settings.i18n.default_locale == "en"
    assert settings.app.workers == 1
    assert not any(x.enabled for x in settings.opencode_backends)
    assert settings.runtime.file_returns_enabled is False
    assert settings.runtime.generated_returns_enabled is False
    assert settings.runtime.workspace_menus_enabled is False


def test_file_runtime_requires_an_enabled_explicit_enrollment():
    with pytest.raises(ValidationError):
        Settings.model_validate({"runtime": {"file_returns_enabled": True}})


@pytest.mark.parametrize(
    "data",
    [
        {"unexpected": True},
        {"security": {"authorization_default": "allow"}},
        {"app": {"workers": 2}},
        {"security": {"allow_shell_on_bridge_host": True}},
        {"security": {"allow_other_bot_input": True}},
        {"security": {"allow_plain_http_non_loopback": True}},
        {"admin": {"csrf_protection": False}},
        {"i18n": {"default_locale": "zh-CN"}},
        {"app": {"bind_host": "0.0.0.0"}},
        {"recovery": {"reconnect_min_seconds": 90}},
        {"database": {"url": "sqlite+aiosqlite:////tmp/a", "url_ref": "env:DB"}},
        {"database": {"url": "postgresql+asyncpg://user:password@db/main"}},
        {"commands": {"menu_page_size": 11}},
    ],
)
def test_invalid_or_unsafe_configuration_rejected(data):
    with pytest.raises(ValidationError):
        Settings.model_validate(data)


@pytest.mark.parametrize(
    "url", ["http://10.0.0.17", "https://user:secret@host", "https://host/?token=x"]
)
def test_no_insecure_backend_or_embedded_secret(url):
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {"opencode_backends": [{"id": "b", "base_url": url, "credential_ref": "env:KEY"}]}
        )


def test_override_is_explicit_and_nested(monkeypatch):
    monkeypatch.setenv("JTOZ__I18N__DEFAULT_LOCALE", "zh-TW")
    monkeypatch.setenv("JTOZ_BOOTSTRAP_TOKEN", "not-a-setting")
    assert load_settings().i18n.default_locale == "zh-TW"
    monkeypatch.setenv("JTOZ__BAD__FIELD", "secret-value")
    with pytest.raises(ValidationError):
        load_settings()


def test_secret_reference_permissions_and_redacted_repr(tmp_path, monkeypatch):
    path = tmp_path / "secret"
    path.write_text("a-secret-value\n")
    path.chmod(0o600)
    resolved = resolve_secret("file:" + str(path))
    assert resolved.get_secret_value() == "a-secret-value"
    assert "a-secret-value" not in repr(resolved)
    path.chmod(0o644)
    with pytest.raises(SecretUnavailable):
        resolve_secret("file:" + str(path))
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(SecretUnavailable):
        resolve_secret("file:" + str(link))
    monkeypatch.setenv("EXAMPLE_KEY", "example-value")
    assert resolve_secret("env:EXAMPLE_KEY").get_secret_value() == "example-value"
    with pytest.raises(SecretUnavailable):
        resolve_secret("env:NOT_A_CONFIGURED_SECRET")


def test_dsn_not_exposed_by_validation_error():
    with pytest.raises(ValidationError) as error:
        Settings.model_validate({"database": {"url": "postgresql://user:PRIVATE@host/db"}})
    assert "PRIVATE" not in str(error.value)


def test_catalog_json_is_not_a_secret():
    assert (
        json.loads(Path("src/jt_oz_bridge/i18n/en.json").read_text())["app.name"] == "jt-oz-bridge"
    )


def test_runtime_requires_explicit_absolute_root_enrollment_but_validation_is_inert():
    assert Settings().runtime.enabled is False
    with pytest.raises(ValidationError):
        Settings.model_validate({"runtime": {"enabled": True}})
    with pytest.raises(ValidationError):
        Settings.model_validate({"runtime": {"enabled": True, "enrollment_file": "relative"}})
    settings = Settings.model_validate(
        {"runtime": {"enabled": True, "enrollment_file": "/etc/not-present/runtime.json"}}
    )
    assert settings.runtime.enabled  # No files, credentials or network resolved.


def test_native_mirror_is_opt_in_and_requires_managed_runtime():
    assert Settings().runtime.native_mirror_enabled is False
    with pytest.raises(ValidationError):
        Settings.model_validate({"runtime": {"native_mirror_enabled": True}})
    settings = Settings.model_validate(
        {
            "runtime": {
                "enabled": True,
                "native_mirror_enabled": True,
                "enrollment_file": "/etc/not-present/runtime.json",
            }
        }
    )
    assert settings.runtime.native_mirror_enabled


def test_live_drafts_require_the_explicit_native_mirror_runtime():
    assert Settings().runtime.native_drafts_enabled is False
    with pytest.raises(ValidationError):
        Settings.model_validate({"runtime": {"native_drafts_enabled": True}})
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "runtime": {
                    "enabled": True,
                    "enrollment_file": "/etc/runtime.json",
                    "native_drafts_enabled": True,
                }
            }
        )
    value = Settings.model_validate(
        {
            "runtime": {
                "enabled": True,
                "enrollment_file": "/etc/runtime.json",
                "native_mirror_enabled": True,
                "native_drafts_enabled": True,
            }
        }
    )
    assert value.runtime.native_drafts_enabled


@pytest.mark.parametrize(
    "data",
    [
        {"requests": True},
        {"requests": 3},
        {"reserved_requests": 180},
        {"window_seconds": True},
        {"window_seconds": float("inf")},
        {"window_seconds": 0},
        {"requests": 100001},
    ],
)
def test_invalid_zulip_request_budget_configuration_is_rejected(data):
    from jt_oz_bridge.config import ZulipBudget

    with pytest.raises(ValidationError):
        ZulipBudget.model_validate(data)


def test_workspace_menus_require_original_file_runtime():
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "runtime": {
                    "enabled": True,
                    "enrollment_file": "/etc/test-runtime.json",
                    "workspace_menus_enabled": True,
                }
            }
        )


def test_generated_capture_requires_original_file_runtime_and_stays_opt_in():
    assert not Settings().runtime.generated_returns_enabled
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "runtime": {
                    "enabled": True,
                    "enrollment_file": "/etc/runtime.json",
                    "generated_returns_enabled": True,
                }
            }
        )
    value = Settings.model_validate(
        {
            "runtime": {
                "enabled": True,
                "enrollment_file": "/etc/runtime.json",
                "file_returns_enabled": True,
                "generated_returns_enabled": True,
            }
        }
    )
    assert value.runtime.generated_returns_enabled and value.runtime.file_returns_enabled


@pytest.mark.parametrize(
    "plugins",
    [
        [{"id": "a", "path": "relative.js", "sha256": "0" * 64}],
        [{"id": "a", "path": "/etc/opencode/plugins/../a.js", "sha256": "0" * 64}],
        [{"id": "a", "path": "/etc/opencode/plugins/a.js", "sha256": "short"}],
        [{"id": "a", "path": "/etc/a.js", "sha256": "0" * 64}] * 2,
    ],
)
def test_observer_plugin_approvals_are_exact_absolute_and_distinct(plugins):
    backend = {"id": "b", "base_url": "http://127.0.0.1:4096", "credential_ref": "env:KEY"}
    Settings.model_validate({"opencode_backends": [backend]})
    with pytest.raises(ValidationError):
        Settings.model_validate({"opencode_backends": [{**backend, "observer_plugins": plugins}]})
