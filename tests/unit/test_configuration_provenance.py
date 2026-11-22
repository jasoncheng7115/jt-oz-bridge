"""Startup origin attribution, without secret or network resolution."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from jt_oz_bridge.config import Settings, load_settings


@pytest.fixture(autouse=True)
def clean_configuration_environment(monkeypatch):
    import os

    for key in os.environ:
        if key.startswith("JTOZ__"):
            monkeypatch.delenv(key)


@pytest.mark.parametrize("toml_value", [None, "INFO", "DEBUG"])
@pytest.mark.parametrize("environment_value", [None, "INFO", "WARNING"])
def test_explicit_origin_is_not_inferred_from_equality_to_default(
    tmp_path, monkeypatch, toml_value, environment_value
):
    file = tmp_path / "config.toml"
    file.write_text("" if toml_value is None else f'[app]\nlog_level="{toml_value}"\n')
    if environment_value is not None:
        monkeypatch.setenv("JTOZ__APP__LOG_LEVEL", environment_value)
    settings = load_settings(file)
    assert settings.app.log_level == (environment_value or toml_value or "INFO")
    assert settings.configuration_origins()["app.log_level"] == (
        "environment" if environment_value else "toml" if toml_value else "default"
    )
    assert settings.configuration_origins()["app.workers"] == "default"


@pytest.mark.parametrize("environment", [False, True])
def test_list_value_and_nested_table_defaults_have_exact_leaf_sources(
    tmp_path, monkeypatch, environment
):
    file = tmp_path / "config.toml"
    file.write_text('[i18n]\nsupported_locales=["en","zh-TW"]\n')
    if environment:
        monkeypatch.setenv("JTOZ__I18N__SUPPORTED_LOCALES", '["en","zh-TW"]')
    sources = load_settings(file).configuration_origins()
    assert sources["i18n.supported_locales"] == ("environment" if environment else "toml")
    assert sources["i18n.default_locale"] == "default"


def test_array_entries_and_request_budget_defaults_do_not_inherit_container_origin(tmp_path):
    file = tmp_path / "config.toml"
    file.write_text(
        '[[zulip_realms]]\nid="realm"\nurl="https://chat.invalid"\n'
        'bot_email="bot@chat.invalid"\napi_key_ref="env:PRIVATE_TEST_KEY"\n'
        "[zulip_realms.request_budget]\nrequests=180\n"
    )
    settings = load_settings(file)
    sources = settings.configuration_origins()
    assert sources["zulip_realms.0.url"] == "toml"
    assert sources["zulip_realms.0.request_budget.requests"] == "toml"
    assert sources["zulip_realms.0.request_budget.window_seconds"] == "default"
    assert sources["zulip_realms.0.enabled"] == "default"


@pytest.mark.parametrize("mode", ["nested_assignment", "copy", "reorder"])
def test_changed_model_cannot_reuse_loaded_source_claims(tmp_path, mode):
    file = tmp_path / "config.toml"
    file.write_text(
        '[app]\nlog_level="INFO"\n'
        '[[opencode_backends]]\nid="first"\nbase_url="https://one.invalid"\n'
        'credential_ref="env:ONE"\n'
        '[[opencode_backends]]\nid="second"\nbase_url="https://two.invalid"\n'
        'credential_ref="env:TWO"\n'
    )
    settings = load_settings(file)
    if mode == "nested_assignment":
        settings.app.log_level = "DEBUG"
    elif mode == "copy":
        settings = settings.model_copy(
            update={"app": settings.app.model_copy(update={"log_level": "DEBUG"})}
        )
    else:
        settings.opencode_backends.reverse()
    assert set(settings.configuration_origins().values()) == {"modified_after_load"}


def test_programmatic_or_revalidated_models_have_no_captured_startup_source():
    for settings in (Settings(), Settings.model_validate(Settings().model_dump())):
        assert set(settings.configuration_origins().values()) == {"not_recorded"}


def test_origins_are_private_not_serialized_and_returned_maps_cannot_change_them():
    settings = load_settings()
    sources = settings.configuration_origins()
    sources["app.name"] = "environment"
    assert settings.configuration_origins()["app.name"] == "default"
    assert "_loaded" not in settings.model_dump_json() + repr(settings)
    assert "_loaded_origins" not in Settings.model_json_schema()["properties"]


def test_readback_uses_captured_model_without_reloading_files_or_environment(tmp_path, monkeypatch):
    file = tmp_path / "config.toml"
    file.write_text('[app]\nlog_level="DEBUG"\n')
    settings = load_settings(file)

    def forbidden(*args, **kwargs):
        raise AssertionError("readback attempted external resolution")

    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr("jt_oz_bridge.security.secrets.resolve_secret", forbidden)
    monkeypatch.setenv("JTOZ__APP__LOG_LEVEL", "WARNING")
    assert settings.app.log_level == "DEBUG"
    assert settings.configuration_origins()["app.log_level"] == "toml"


@pytest.mark.parametrize("key", ["JTOZ__APP__UNKNOWN", "JTOZ__OPENCODE_BACKENDS__0", "JTOZ__X"])
def test_unknown_or_unsupported_overrides_still_fail_without_secret_input_echo(monkeypatch, key):
    monkeypatch.setenv(key, "PRIVATE_BAD_CONFIG_VALUE")
    with pytest.raises((ValidationError, ValueError)) as error:
        load_settings()
    assert "PRIVATE_BAD_CONFIG_VALUE" not in str(error.value)


def test_secret_environment_variables_remain_distinct_from_configuration(monkeypatch):
    monkeypatch.setenv("JTOZ_SECRET_KEY", "PRIVATE_VALUE_MUST_NOT_BE_READ")
    settings = load_settings()
    assert set(settings.configuration_origins().values()) == {"default"}
    assert "PRIVATE_VALUE_MUST_NOT_BE_READ" not in json.dumps(settings.model_dump(mode="json"))
