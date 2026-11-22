"""Reviewed non-secret startup settings; no reflective automatic field exposure."""

from typing import Any

from jt_oz_bridge.config import Settings

PUBLIC_FIELDS = {
    "app": ("name", "environment", "bind_host", "bind_port", "workers", "state_dir", "log_level"),
    "runtime": (
        "enabled",
        "native_mirror_enabled",
        "native_drafts_enabled",
        "file_returns_enabled",
        "generated_returns_enabled",
        "workspace_inputs_enabled",
        "workspace_menus_enabled",
        "session_creation_enabled",
    ),
    "i18n": (
        "default_locale",
        "supported_locales",
        "allow_user_switch",
        "allow_topic_switch",
        "agent_response_language",
        "default_timezone",
    ),
    "database": ("sqlite_journal_mode", "sqlite_busy_timeout_ms"),
    "admin": ("enabled", "trusted_proxy_networks", "csrf_protection", "public_url"),
    "security": (
        "authorization_default",
        "require_private_channels",
        "allow_other_bot_input",
        "allow_shell_on_bridge_host",
        "allow_plain_http_loopback",
        "allow_plain_http_non_loopback",
        "reveal_secrets_on_readback",
    ),
    "commands": (
        "prefix",
        "menu_page_size",
        "menu_token_ttl_seconds",
        "interaction_token_ttl_seconds",
        "require_scoped_confirmation",
    ),
    "execution": (
        "max_active_sessions_global",
        "max_active_sessions_per_backend",
        "busy_input_policy",
        "resume_queue_after_stop",
        "ambiguous_mutation_policy",
        "recovered_unsent_input_policy",
    ),
    "rendering": (
        "stream_update_min_interval_ms",
        "history_backfill_messages",
        "include_raw_reasoning",
        "long_output_mode",
        "lock_screen_notification_detail",
    ),
    "attachments": (
        "max_file_bytes",
        "allowed_download_origins",
        "allow_cross_origin_redirects",
        "allow_private_url_fetch",
        "allow_automatic_extraction",
        "allow_automatic_execution",
    ),
    "recovery": (
        "reconnect_min_seconds",
        "reconnect_max_seconds",
        "reconcile_interval_seconds",
        "unknown_outbound_delivery_policy",
    ),
    "retention": (
        "finalized_payload_days",
        "temporary_artifact_days",
        "audit_metadata_days",
        "retain_pending_and_ambiguous",
        "artifact_quota_bytes",
        "workspace_quota_bytes",
        "workspace_maximum_objects",
        "reserve_free_disk_bytes",
    ),
    "observability": ("metrics_enabled", "metrics_bind_host", "redact_content_by_default"),
}
PUBLIC_LIST_FIELDS = {
    "opencode_backends": (
        "id",
        "enabled",
        "base_url",
        "api_generation",
        "require_identity_enrollment",
    ),
    "zulip_realms": (
        "id",
        "enabled",
        "url",
        "bot_email",
        "default_locale",
        "allowed_user_ids",
        "allowed_channel_ids",
        "request_budget.requests",
        "request_budget.window_seconds",
        "request_budget.reserved_requests",
    ),
    "projects": (
        "id",
        "enabled",
        "backend_id",
        "workspace_root",
        "realm_id",
        "input_mode",
        "default_topic_locale",
    ),
}


def configuration_rows(settings: Settings) -> list[dict[str, Any]]:
    origins = settings.configuration_origins()
    rows: list[dict[str, Any]] = []

    def append(prefix: str, model: Any, fields: tuple[str, ...]) -> None:
        for field in fields:
            value = model
            for part in field.split("."):
                value = getattr(value, part)
            path = prefix + "." + field
            rows.append(
                dict(
                    id=path,
                    value=value,
                    origin=origins.get(path, "not_recorded"),
                    application="restart_required",
                )
            )

    for section, fields in PUBLIC_FIELDS.items():
        append(section, getattr(settings, section), fields)
    for section, fields in PUBLIC_LIST_FIELDS.items():
        for index, model in enumerate(getattr(settings, section)):
            append(f"{section}.{index}", model, fields)
    return rows
