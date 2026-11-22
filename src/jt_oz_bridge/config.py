"""Strict configuration. Loading configuration never resolves credentials or makes network calls."""

import hashlib
import ipaddress
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

Locale = Literal["en", "zh-TW"]
Positive = Annotated[int, Field(strict=True, gt=0)]
SecretRef = Annotated[str, Field(pattern=r"^(env:[A-Z][A-Z0-9_]*|file:/[^\r\n]+)$")]
ConfigurationOrigin = Literal[
    "default", "toml", "environment", "not_recorded", "modified_after_load"
]


def _configuration_paths(value: Any, prefix: str = "") -> set[str]:
    if isinstance(value, dict) and value:
        return {
            path
            for key, child in value.items()
            for path in _configuration_paths(child, f"{prefix}.{key}" if prefix else key)
        }
    if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
        return {
            path
            for index, child in enumerate(value)
            for path in _configuration_paths(child, f"{prefix}.{index}")
        }
    return {prefix} if prefix else set()


def _configuration_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def default_locales() -> list[Locale]:
    return ["en", "zh-TW"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True, hide_input_in_errors=True)


class App(StrictModel):
    name: Literal["jt-oz-bridge"] = "jt-oz-bridge"
    environment: Literal["production", "development", "test"] = "production"
    bind_host: str = "127.0.0.1"
    bind_port: Annotated[int, Field(strict=True, gt=0, lt=65536)] = 8765
    workers: Literal[1] = 1
    state_dir: Path = Path("/var/lib/jt-oz-bridge")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("state_dir")
    @classmethod
    def absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("absolute state directory required")
        return value


class I18n(StrictModel):
    default_locale: Locale = "en"
    supported_locales: list[Locale] = Field(default_factory=default_locales)
    allow_user_switch: bool = True
    allow_topic_switch: bool = True
    agent_response_language: Literal["inherit"] = "inherit"
    default_timezone: str = "UTC"

    @field_validator("supported_locales")
    @classmethod
    def locales(cls, value: list[Locale]) -> list[Locale]:
        if value != ["en", "zh-TW"]:
            raise ValueError("both canonical locales are required")
        return value

    @field_validator("default_timezone")
    @classmethod
    def timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError:
            raise ValueError("unknown timezone") from None
        return value


class DatabaseConfig(StrictModel):
    url: str | None = None
    url_ref: SecretRef | None = None
    sqlite_journal_mode: Literal["WAL"] = "WAL"
    sqlite_busy_timeout_ms: Positive = 30000

    @model_validator(mode="after")
    def source(self) -> Self:
        if self.url and self.url_ref:
            raise ValueError("database url and url_ref are mutually exclusive")
        if self.url and not self.url.startswith("sqlite+aiosqlite:///"):
            raise ValueError("non-SQLite database credentials require url_ref")
        return self


class Admin(StrictModel):
    enabled: bool = True
    bootstrap_token_ref: SecretRef = "env:JTOZ_BOOTSTRAP_TOKEN"
    session_signing_key_ref: SecretRef = "env:JTOZ_SESSION_SIGNING_KEY"
    trusted_proxy_networks: list[str] = Field(default_factory=list)
    csrf_protection: Literal[True] = True
    public_url: str = ""

    @field_validator("trusted_proxy_networks")
    @classmethod
    def networks(cls, value: list[str]) -> list[str]:
        for item in value:
            ipaddress.ip_network(item, strict=True)
        return value


class Security(StrictModel):
    authorization_default: Literal["deny"] = "deny"
    require_private_channels: Literal[True] = True
    allow_other_bot_input: Literal[False] = False
    allow_shell_on_bridge_host: Literal[False] = False
    allow_plain_http_loopback: bool = True
    allow_plain_http_non_loopback: Literal[False] = False
    secret_key_ref: SecretRef = "env:JTOZ_SECRET_KEY"
    reveal_secrets_on_readback: Literal[False] = False


class Commands(StrictModel):
    prefix: Literal["!oz"] = "!oz"
    menu_page_size: Annotated[int, Field(strict=True, ge=1, le=10)] = 10
    menu_token_ttl_seconds: Positive = 900
    interaction_token_ttl_seconds: Positive = 900
    require_scoped_confirmation: Literal[True] = True


class Execution(StrictModel):
    max_active_sessions_global: Positive = 4
    max_active_sessions_per_backend: Positive = 2
    busy_input_policy: Literal["queue"] = "queue"
    resume_queue_after_stop: Literal["manual"] = "manual"
    ambiguous_mutation_policy: Literal["hold_and_reconcile"] = "hold_and_reconcile"
    recovered_unsent_input_policy: Literal["hold_for_review"] = "hold_for_review"


class Rendering(StrictModel):
    stream_update_min_interval_ms: Positive = 1000
    history_backfill_messages: Positive = 20
    include_raw_reasoning: Literal[False] = False
    long_output_mode: Literal["summary_with_authorized_full_output"] = (
        "summary_with_authorized_full_output"
    )
    lock_screen_notification_detail: Literal["minimal"] = "minimal"


class Attachments(StrictModel):
    max_file_bytes: Positive = 20 * 1024 * 1024
    allowed_download_origins: list[str] = Field(default_factory=list)
    allow_cross_origin_redirects: Literal[False] = False
    allow_private_url_fetch: Literal[False] = False
    allow_automatic_extraction: Literal[False] = False
    allow_automatic_execution: Literal[False] = False


class Recovery(StrictModel):
    reconnect_min_seconds: Positive = 1
    reconnect_max_seconds: Positive = 60
    reconcile_interval_seconds: Positive = 60
    unknown_outbound_delivery_policy: Literal["reconcile_then_hold"] = "reconcile_then_hold"

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.reconnect_max_seconds < self.reconnect_min_seconds:
            raise ValueError("invalid reconnect bounds")
        return self


class Retention(StrictModel):
    finalized_payload_days: Positive = 7
    temporary_artifact_days: Positive = 7
    audit_metadata_days: Positive = 90
    retain_pending_and_ambiguous: Literal[True] = True
    artifact_quota_bytes: Positive = 2 * 1024**3
    workspace_quota_bytes: Annotated[int, Field(strict=True, gt=0, lt=2**63)] = 2 * 1024**3
    workspace_maximum_objects: Annotated[int, Field(strict=True, gt=0, le=1000000)] = 10000
    reserve_free_disk_bytes: Positive = 1024**3


class Observability(StrictModel):
    metrics_enabled: bool = True
    metrics_bind_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    redact_content_by_default: Literal[True] = True


class ZulipBudget(StrictModel):
    requests: Annotated[int, Field(strict=True, ge=4, le=100000)] = 180
    window_seconds: Annotated[float, Field(strict=True, allow_inf_nan=False, ge=1, le=3600)] = 60
    reserved_requests: Annotated[int, Field(strict=True, ge=0, le=99999)] = 64

    @model_validator(mode="after")
    def reserve_fits(self) -> Self:
        if self.reserved_requests >= self.requests:
            raise ValueError("zulip_budget_reserve_must_fit")
        return self


class ChannelProjects(StrictModel):
    """One private channel per project: its new topics offer only these projects."""

    channel_id: Positive
    projects: list[Annotated[str, Field(min_length=1, max_length=255)]] = Field(
        min_length=1, max_length=100
    )


class Realm(StrictModel):
    id: str
    enabled: bool = False
    url: str
    bot_email: str
    request_budget: ZulipBudget = Field(default_factory=ZulipBudget)
    api_key_ref: SecretRef
    default_locale: Locale = "en"
    allowed_user_ids: list[Positive] = Field(default_factory=list)
    allowed_channel_ids: list[Positive] = Field(default_factory=list)
    # Optional. A listed channel only offers its own projects; others offer all.
    channel_projects: list[ChannelProjects] = Field(default_factory=list)
    platform_locale_file: Path | None = None

    @model_validator(mode="after")
    def channel_projects_in_allowed_channels(self) -> Self:
        channels = [item.channel_id for item in self.channel_projects]
        if len(set(channels)) != len(channels) or not set(channels) <= set(
            self.allowed_channel_ids
        ):
            raise ValueError("channel_projects_require_unique_allowed_channels")
        return self

    @field_validator("platform_locale_file")
    @classmethod
    def absolute_language_file(cls, value: Path | None) -> Path | None:
        if value is not None and (not value.is_absolute() or ".." in value.parts):
            raise ValueError("absolute_platform_locale_file_required")
        return value


class ObserverPlugin(StrictModel):
    """A local OpenCode plugin the operator read and approved as observe-only.

    It is pinned by its exact file bytes; any change makes it policy drift again.
    """

    id: str = Field(min_length=1, max_length=200)
    path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def absolute_plugin_file(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("absolute_observer_plugin_path_required")
        return value


class Backend(StrictModel):
    id: str
    enabled: bool = False
    base_url: str
    api_generation: Literal["auto", "v1", "v2"] = "auto"
    credential_ref: SecretRef
    require_identity_enrollment: Literal[True] = True
    observer_plugins: list[ObserverPlugin] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def distinct_observer_plugins(self) -> Self:
        if len({p.id for p in self.observer_plugins}) != len(self.observer_plugins):
            raise ValueError("duplicate_observer_plugin_id")
        return self


class Project(StrictModel):
    id: str
    enabled: bool = False
    backend_id: str
    workspace_root: str
    realm_id: str
    input_mode: Literal["authorized_humans_in_bound_topic", "explicit_command"] = (
        "authorized_humans_in_bound_topic"
    )
    default_topic_locale: Locale = "en"


def validate_endpoint(value: str, allow_loopback: bool = True) -> None:
    url = urlsplit(value)
    if url.username or url.password or url.query or url.fragment or not url.hostname:
        raise ValueError("endpoint must not contain credentials, query or fragment")
    loopback = url.hostname in {"127.0.0.1", "::1", "localhost"}
    if url.scheme != "https" and not (allow_loopback and loopback and url.scheme == "http"):
        raise ValueError("HTTPS required outside loopback")


class Runtime(StrictModel):
    enabled: bool = False
    native_mirror_enabled: bool = False
    native_drafts_enabled: bool = False
    file_returns_enabled: bool = False
    generated_returns_enabled: bool = False
    workspace_inputs_enabled: bool = False
    workspace_menus_enabled: bool = False
    session_creation_enabled: bool = False
    session_fork_topics_enabled: bool = False
    # `!oz git commit` / `push`: a previewed, confirmed prompt; see docs/GIT_PUBLISH.md.
    git_publish_enabled: bool = False
    # "every 30 minutes … until 18:00": confirmed timed prompts; see docs/SCHEDULES.md.
    prompt_schedules_enabled: bool = False
    # Before a session's first prompt, attach one instruction entry asking its AI to
    # write for Zulip; needs the put in verified operations. See docs/RUNTIME.md.
    zulip_format_instructions_enabled: bool = True
    zulip_recovery_enabled: bool = False
    zulip_recovery_max_epochs: Annotated[int, Field(strict=True, ge=1, le=128)] = 128
    zulip_recovery_max_items: Annotated[int, Field(strict=True, ge=1, le=10000)] = 10000
    zulip_recovery_max_bytes: Annotated[int, Field(strict=True, ge=8192, le=128 * 1024**2)] = (
        128 * 1024**2
    )
    enrollment_file: Path | None = None

    @model_validator(mode="after")
    def explicit_enrollment(self) -> Self:
        if self.generated_returns_enabled and not self.file_returns_enabled:
            raise ValueError("generated_returns_require_original_file_runtime")
        if self.session_creation_enabled and not self.enabled:
            raise ValueError("session_creation_requires_enabled_enrolled_runtime")
        if self.session_fork_topics_enabled and not self.session_creation_enabled:
            raise ValueError("session_fork_topics_require_session_creation")
        if self.git_publish_enabled and not self.enabled:
            raise ValueError("git_publish_requires_enabled_enrolled_runtime")
        if self.prompt_schedules_enabled and not self.enabled:
            raise ValueError("prompt_schedules_require_enabled_enrolled_runtime")
        if self.native_mirror_enabled and not self.enabled:
            raise ValueError("native_mirror_requires_enabled_enrolled_runtime")
        if self.native_drafts_enabled and not self.native_mirror_enabled:
            raise ValueError("native_drafts_require_native_mirror")
        if self.workspace_inputs_enabled and not self.file_returns_enabled:
            raise ValueError("workspace_inputs_require_enrolled_file_runtime")
        if self.workspace_menus_enabled and not self.file_returns_enabled:
            raise ValueError("workspace_menus_require_enrolled_file_runtime")
        if self.file_returns_enabled and not self.enabled:
            raise ValueError("file_returns_require_enabled_enrolled_runtime")
        if self.enabled and self.enrollment_file is None:
            raise ValueError("enabled_runtime_requires_explicit_enrollment_file")
        if self.enrollment_file is not None and (
            not self.enrollment_file.is_absolute() or ".." in self.enrollment_file.parts
        ):
            raise ValueError("absolute_runtime_enrollment_file_required")
        return self


class Settings(StrictModel):
    _loaded_origins: dict[str, ConfigurationOrigin] = PrivateAttr(default_factory=dict)
    _loaded_digest: str | None = PrivateAttr(default=None)
    app: App = Field(default_factory=App)
    runtime: Runtime = Field(default_factory=Runtime)
    i18n: I18n = Field(default_factory=I18n)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    admin: Admin = Field(default_factory=Admin)
    security: Security = Field(default_factory=Security)
    commands: Commands = Field(default_factory=Commands)
    execution: Execution = Field(default_factory=Execution)
    rendering: Rendering = Field(default_factory=Rendering)
    attachments: Attachments = Field(default_factory=Attachments)
    recovery: Recovery = Field(default_factory=Recovery)
    retention: Retention = Field(default_factory=Retention)
    observability: Observability = Field(default_factory=Observability)
    zulip_realms: list[Realm] = Field(default_factory=list)
    opencode_backends: list[Backend] = Field(default_factory=list)
    projects: list[Project] = Field(default_factory=list)

    def configuration_origins(self) -> dict[str, ConfigurationOrigin]:
        """Startup provenance only; never infer an origin by comparing defaults.

        Metadata is private and not serialized. An unrecorded/programmatic or
        subsequently changed model cannot borrow the loader's source claims.
        This does not resolve references or read TOML/environment again.
        """
        values = self.model_dump(mode="json")
        paths = _configuration_paths(values)
        if self._loaded_digest is None:
            return dict.fromkeys(paths, "not_recorded")
        if _configuration_digest(values) != self._loaded_digest:
            return dict.fromkeys(paths, "modified_after_load")
        return {path: self._loaded_origins.get(path, "default") for path in paths}

    @model_validator(mode="after")
    def cross_validate(self) -> Self:
        for ids in [
            [x.id for x in self.zulip_realms],
            [x.id for x in self.opencode_backends],
            [x.id for x in self.projects],
        ]:
            if len(set(ids)) != len(ids):
                raise ValueError("duplicate configured identity")
        realms = {x.id: x for x in self.zulip_realms}
        backends = {x.id: x for x in self.opencode_backends}
        for r in self.zulip_realms:
            validate_endpoint(r.url, False)
        for b in self.opencode_backends:
            validate_endpoint(b.base_url, self.security.allow_plain_http_loopback)
        for p in self.projects:
            if p.backend_id not in backends or p.realm_id not in realms:
                raise ValueError("project references unknown backend/realm")
            if not p.workspace_root.startswith("/"):
                raise ValueError("absolute project workspace required")
            if p.enabled and not (backends[p.backend_id].enabled and realms[p.realm_id].enabled):
                raise ValueError("enabled project requires enabled backend and realm")
        for origin in self.attachments.allowed_download_origins:
            validate_endpoint(origin, False)
            if urlsplit(origin).path not in {"", "/"}:
                raise ValueError("attachment origin must not contain path")
        if self.app.bind_host not in {"127.0.0.1", "::1", "localhost"}:
            if not self.admin.public_url:
                raise ValueError("remote bind requires public HTTPS URL")
        if self.admin.public_url:
            validate_endpoint(self.admin.public_url, False)
            if urlsplit(self.admin.public_url).path not in {"", "/"}:
                raise ValueError("admin public URL must be an origin")
        return self


def load_settings(path: Path | None = None) -> Settings:
    data: dict[str, Any] = tomllib.loads(path.read_text()) if path else {}
    origins: dict[str, ConfigurationOrigin] = dict.fromkeys(_configuration_paths(data), "toml")
    # Explicit nested overrides; secret reference variables are not parsed as settings.
    for key, value in os.environ.items():
        if not key.startswith("JTOZ__"):
            continue
        parts = key.removeprefix("JTOZ__").lower().split("__")
        if len(parts) != 2 or not all(re.fullmatch(r"[a-z][a-z0-9_]*", x) for x in parts):
            raise ValueError("invalid configuration override")
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = value
        section = data.setdefault(parts[0], {})
        if not isinstance(section, dict):
            raise ValueError("override section must be a table")
        section[parts[1]] = parsed
        prefix = ".".join(parts)
        origins = {
            path: source
            for path, source in origins.items()
            if path != prefix and not path.startswith(prefix + ".")
        }
        origins.update(dict.fromkeys(_configuration_paths(parsed, prefix), "environment"))
    settings = Settings.model_validate(data)
    settings._loaded_origins = origins
    settings._loaded_digest = _configuration_digest(settings.model_dump(mode="json"))
    return settings
