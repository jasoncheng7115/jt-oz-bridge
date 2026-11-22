"""Bounded administrative metadata views; no upstream calls or payload decryption."""

import base64
import binascii
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from sqlalchemy import and_, case, func, or_, select

from jt_oz_bridge.config import Settings
from jt_oz_bridge.services.runtime_configuration import INTERVAL_KEY, RuntimeConfiguration
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import (
    Binding,
    EnrolledBackend,
    EnrolledProject,
    PendingInteraction,
)
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, Grant
from jt_oz_bridge.web.configuration import configuration_rows

SECTIONS = (
    "backends",
    "projects",
    "zulip",
    "bindings",
    "actions",
    "interactions",
    "grants",
    "deliveries",
    "retention",
    "audit",
    "backup",
    "compatibility",
    "settings",
)

# Exact-match filters accepted per section. Values are SQL parameters (or exact
# Python comparisons over loaded configuration), never expressions or patterns.
FILTERS: dict[str, dict[str, str]] = {
    "backends": {"enabled": "bool"},
    "compatibility": {"enabled": "bool"},
    "projects": {"enabled": "bool", "backend_id": "text", "realm_id": "text"},
    "bindings": {
        "state": "state",
        "realm_id": "text",
        "channel_id": "int",
        "project_id": "text",
        "backend_id": "text",
        "session_id": "text",
        "dispatch_paused": "bool",
    },
    "actions": {
        "state": "state",
        "binding_id": "text",
        "operation": "text",
        "actor_id": "int",
    },
    "interactions": {"state": "state", "binding_id": "text"},
    "grants": {
        "realm_id": "text",
        "project_id": "text",
        "user_id": "int",
        "role": "state",
        "active": "bool",
    },
    "deliveries": {"state": "state", "binding_id": "text"},
    "audit": {
        "event": "event",
        "actor": "text",
        "object_id": "text",
        "since": "time",
        "until": "time",
    },
}
SESSION_FILTERS = {
    "backend_id": "text",
    "project_id": "text",
    "session_id": "text",
    "active": "bool",
}
FILTER_NAMES = frozenset(name for spec in (*FILTERS.values(), SESSION_FILTERS) for name in spec)
STATE = re.compile(r"[a-z][a-z0-9_.-]{0,31}")
INTEGER = re.compile(r"-?[0-9]{1,19}")
MAX_CURSOR = 1024
ACTION_COLUMNS = (
    "id",
    "binding_id",
    "binding_revision",
    "actor_id",
    "operation",
    "state",
    "version",
    "owner",
    "status_reason",
    "created_at",
)
ARTIFACT_COLUMNS = (
    "id",
    "binding_id",
    "binding_revision",
    "realm_id",
    "project_id",
    "actor_id",
    "source_message_id",
    "kind",
    "state",
    "size_bytes",
    "checksum",
    "pinned",
    "version",
    "created_at",
    "expires_at",
)
SESSION_COLUMNS = (
    "backend_id",
    "session_id",
    "project_id",
    "bindings",
    "active_bindings",
    "last_bound_at",
    "enrolled_scope",
    "native_observed",
)


def parse_filters(spec: Mapping[str, str], values: Mapping[str, str]) -> dict[str, Any]:
    """Typed exact filters; empty form fields mean unset, anything else is bounded."""
    parsed: dict[str, Any] = {}
    for name, raw in values.items():
        kind = spec.get(name)
        if kind is None:
            raise ValueError("unsupported_admin_filter")
        if type(raw) is not str:
            raise ValueError("invalid_admin_filter")
        if raw == "":
            continue
        if kind == "bool":
            if raw not in {"true", "false"}:
                raise ValueError("invalid_admin_filter")
            parsed[name] = raw == "true"
        elif kind == "int":
            if not INTEGER.fullmatch(raw) or not -(2**63) <= int(raw) < 2**63:
                raise ValueError("invalid_admin_filter")
            parsed[name] = int(raw)
        elif kind == "time":
            if len(raw) > 32:
                raise ValueError("invalid_admin_filter")
            try:
                number = float(raw)
            except ValueError:
                raise ValueError("invalid_admin_filter") from None
            if not math.isfinite(number) or not 0 <= number <= 1e11:
                raise ValueError("invalid_admin_filter")
            parsed[name] = number
        elif kind == "state":
            if not STATE.fullmatch(raw):
                raise ValueError("invalid_admin_filter")
            parsed[name] = raw
        elif len(raw) > (64 if kind == "event" else 255):
            raise ValueError("invalid_admin_filter")
        else:
            parsed[name] = raw
    return parsed


def encode_cursor(values: tuple[str, ...]) -> str:
    return base64.urlsafe_b64encode(json.dumps(list(values)).encode()).decode().rstrip("=")


def decode_cursor(value: str, size: int) -> tuple[str, ...] | None:
    if not value:
        return None
    if len(value) > MAX_CURSOR or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid_admin_page")
    try:
        decoded = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise ValueError("invalid_admin_page") from None
    if (
        type(decoded) is not list
        or len(decoded) != size
        or any(type(x) is not str or len(x) > 255 for x in decoded)
    ):
        raise ValueError("invalid_admin_page")
    return tuple(decoded)


@dataclass(frozen=True)
class CatalogPage:
    section: str
    columns: tuple[str, ...]
    items: list[dict[str, Any]]
    next_after: str | None
    source: str
    controls: dict[str, Any] | None = None
    filters: dict[str, Any] = field(default_factory=dict)

    def response(self) -> dict[str, Any]:
        return {
            "section": self.section,
            "columns": self.columns,
            "items": self.items,
            "next_after": self.next_after,
            "source": self.source,
            "read_only": True,
            "snapshot_is_live": True,
            "filters": self.filters,
            **({"controls": self.controls} if self.controls is not None else {}),
        }


class AdminCatalog:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db, self.settings = db, settings

    async def page(
        self,
        section: str,
        *,
        limit: int = 25,
        after: str = "",
        event: str = "",
        filters: Mapping[str, str] | None = None,
    ) -> CatalogPage:
        if section not in SECTIONS:
            raise ValueError("unknown_admin_section")
        if not 1 <= limit <= 100 or len(after) > 255 or len(event) > 64:
            raise ValueError("invalid_admin_page")
        if event and section != "audit":
            raise ValueError("audit_filter_only")
        raw = dict(filters or {})
        if event:
            raw["event"] = event
        chosen = parse_filters(FILTERS.get(section, {}), raw)
        page = await self._section(section, limit, after, chosen)
        page.filters.update(chosen)
        return page

    async def _section(
        self, section: str, limit: int, after: str, chosen: dict[str, Any]
    ) -> CatalogPage:
        tables: dict[str, tuple[Any, tuple[str, ...]]] = {
            "bindings": (
                Binding,
                (
                    "id",
                    "realm_id",
                    "channel_id",
                    "project_id",
                    "backend_id",
                    "session_id",
                    "owner_id",
                    "revision",
                    "state",
                    "dispatch_paused",
                    "queue_revision",
                    "created_at",
                ),
            ),
            "actions": (Action, ACTION_COLUMNS),
            "interactions": (
                PendingInteraction,
                (
                    "id",
                    "binding_id",
                    "binding_revision",
                    "state",
                    "version",
                    "action_id",
                    "winner_user_id",
                    "created_at",
                    "expires_at",
                ),
            ),
            "grants": (
                Grant,
                ("id", "realm_id", "project_id", "user_id", "role", "active", "revision"),
            ),
            "deliveries": (
                Delivery,
                ("id", "binding_id", "state", "version", "attempts", "retry_at"),
            ),
            "audit": (AuditEvent, ("id", "actor", "event", "object_id", "created_at")),
        }
        if section in tables:
            model, columns = tables[section]
            # Selecting explicit columns avoids even loading encrypted prompt/output/token
            # fields. Administrative visibility is separate from a Zulip Human grant.
            statement = select(*(getattr(model, name) for name in columns)).where(model.id > after)
            if section == "interactions" and "state" not in chosen:
                statement = statement.where(PendingInteraction.state == "pending")
            if section == "deliveries":
                statement = statement.where(Delivery.state.in_(("held", "ambiguous", "failed")))
            for name, value in chosen.items():
                if name == "since":
                    statement = statement.where(AuditEvent.created_at >= value)
                elif name == "until":
                    statement = statement.where(AuditEvent.created_at < value)
                else:
                    statement = statement.where(getattr(model, name) == value)
            async with self.db.sessions() as session:
                rows = [
                    dict(row)
                    for row in (
                        await session.execute(statement.order_by(model.id).limit(limit + 1))
                    ).mappings()
                ]
            return self._page(section, columns, rows, limit, "bridge_database")
        return await self._configuration(section, limit, after, chosen)

    @staticmethod
    def _page(
        section: str,
        columns: tuple[str, ...],
        rows: list[dict[str, Any]],
        limit: int,
        source: str,
        controls: dict[str, Any] | None = None,
    ) -> CatalogPage:
        next_after = str(rows[limit - 1]["id"]) if len(rows) > limit else None
        return CatalogPage(section, columns, rows[:limit], next_after, source, controls)

    async def _configuration(
        self, section: str, limit: int, after: str, chosen: dict[str, Any]
    ) -> CatalogPage:
        settings = self.settings
        controls = None
        rows: list[dict[str, Any]]
        columns: tuple[str, ...]
        if section in {"backends", "compatibility"}:
            values = sorted(
                (
                    b
                    for b in settings.opencode_backends
                    if b.id > after and chosen.get("enabled", b.enabled) == b.enabled
                ),
                key=lambda b: b.id,
            )[: limit + 1]
            async with self.db.sessions() as session:
                enrolled = {
                    row.id: row
                    for row in (
                        await session.execute(
                            select(
                                EnrolledBackend.id,
                                EnrolledBackend.enabled,
                                EnrolledBackend.verified,
                                EnrolledBackend.version,
                            ).where(EnrolledBackend.id.in_([b.id for b in values]))
                        )
                    ).mappings()
                }
            rows = [
                dict(
                    id=b.id,
                    enabled=b.enabled,
                    base_url=b.base_url,
                    api_generation=b.api_generation,
                    enrolled=b.id in enrolled,
                    enrolled_verified=bool(enrolled[b.id]["verified"])
                    if b.id in enrolled
                    else False,
                    version=enrolled[b.id]["version"] if b.id in enrolled else None,
                    certified=False,
                    connection_checked=False,
                )
                for b in values
            ]
            columns = (
                "id",
                "enabled",
                "base_url",
                "api_generation",
                "enrolled",
                "enrolled_verified",
                "version",
                "certified",
                "connection_checked",
            )
        elif section == "projects":
            selected = sorted(
                (
                    p
                    for p in settings.projects
                    if p.id > after
                    and all(getattr(p, name) == value for name, value in chosen.items())
                ),
                key=lambda p: p.id,
            )[: limit + 1]
            async with self.db.sessions() as session:
                recorded = {
                    row.id: row
                    for row in (
                        await session.execute(
                            select(
                                EnrolledProject.id,
                                EnrolledProject.backend_id,
                                EnrolledProject.realm_id,
                                EnrolledProject.canonical_directory,
                                EnrolledProject.enabled,
                            ).where(EnrolledProject.id.in_([p.id for p in selected]))
                        )
                    ).mappings()
                }
            rows = []
            for p in selected:
                saved = recorded.get(p.id)
                rows.append(
                    dict(
                        id=p.id,
                        enabled=p.enabled,
                        backend_id=p.backend_id,
                        realm_id=p.realm_id,
                        workspace_root=p.workspace_root,
                        input_mode=p.input_mode,
                        enrolled=saved is not None,
                        enrolled_enabled=bool(saved["enabled"]) if saved is not None else False,
                        # Recorded enrollment equals the loaded allowlist. This is a lexical
                        # comparison, not filesystem proof or a Native project probe.
                        enrollment_matches=saved is not None
                        and (saved["backend_id"], saved["realm_id"], saved["canonical_directory"])
                        == (p.backend_id, p.realm_id, str(PurePosixPath(p.workspace_root))),
                    )
                )
            columns = (
                "id",
                "enabled",
                "backend_id",
                "realm_id",
                "workspace_root",
                "input_mode",
                "enrolled",
                "enrolled_enabled",
                "enrollment_matches",
            )
        elif section == "zulip":
            rows = [
                dict(
                    id=r.id,
                    enabled=r.enabled,
                    url=r.url,
                    bot_email=r.bot_email,
                    allowed_user_ids=r.allowed_user_ids,
                    allowed_channel_ids=r.allowed_channel_ids,
                    connection_checked=False,
                )
                for r in settings.zulip_realms
                if r.id > after
            ]
            columns = (
                "id",
                "enabled",
                "url",
                "bot_email",
                "allowed_user_ids",
                "allowed_channel_ids",
                "connection_checked",
            )
        elif section == "settings":
            resolver = RuntimeConfiguration(self.db, settings)
            effective_rows = await resolver.views()
            effective = effective_rows["i18n.default_locale"]
            interval = effective_rows[INTERVAL_KEY]
            controls = {
                **effective.model_dump(mode="json"),
                "rendering_interval": interval.model_dump(mode="json"),
            }
            rows = [row for row in configuration_rows(settings) if row["id"] > after]
            for row in rows:
                if row["id"] in effective_rows:
                    current = effective_rows[row["id"]]
                    row.update(
                        value=current.value,
                        origin=current.origin,
                        application="runtime_allowed"
                        if current.runtime_allowed
                        else "restart_required",
                    )
            columns = ("id", "value", "origin", "application")
        elif section == "retention":
            rows = [
                dict(id=k, value=v) for k, v in settings.retention.model_dump().items() if k > after
            ]
            columns = ("id", "value")
        else:
            # Guidance is translated at presentation time. No downloadable DB, secret,
            # host path or untrusted upstream response is exposed by a GET request.
            rows = [
                dict(id=k, guidance_key="console.backup_" + k)
                for k in ("consistent", "encrypted", "restore", "private")
                if k > after
            ]
            columns = ("id", "guidance_key")
        rows.sort(key=lambda row: str(row["id"]))
        return self._page(
            section,
            columns,
            rows[: limit + 1],
            limit,
            "startup_configuration"
            if section == "settings"
            else "loaded_configuration"
            if section != "backup"
            else "operator_guidance",
            controls,
        )

    async def sessions(
        self, *, limit: int = 25, after: str = "", filters: Mapping[str, str] | None = None
    ) -> CatalogPage:
        """Original sessions known through Bridge bindings; never the Native database.

        No Native request is made, so ``native_observed`` is always false here.
        """
        if not 1 <= limit <= 100:
            raise ValueError("invalid_admin_page")
        cursor = decode_cursor(after, 3)
        chosen = parse_filters(SESSION_FILTERS, dict(filters or {}))
        keys = (Binding.backend_id, Binding.session_id, Binding.project_id)
        active = func.sum(case((Binding.state == "active", 1), else_=0))
        statement = select(
            *keys,
            func.count(Binding.id).label("bindings"),
            active.label("active_bindings"),
            func.max(Binding.created_at).label("last_bound_at"),
        )
        if cursor is not None:
            backend, session_id, project = cursor
            statement = statement.where(
                or_(
                    Binding.backend_id > backend,
                    and_(Binding.backend_id == backend, Binding.session_id > session_id),
                    and_(
                        Binding.backend_id == backend,
                        Binding.session_id == session_id,
                        Binding.project_id > project,
                    ),
                )
            )
        for name in ("backend_id", "project_id", "session_id"):
            if name in chosen:
                statement = statement.where(getattr(Binding, name) == chosen[name])
        statement = statement.group_by(*keys)
        if "active" in chosen:
            statement = statement.having(active > 0 if chosen["active"] else active == 0)
        statement = statement.order_by(*keys).limit(limit + 1)
        async with self.db.sessions() as session:
            found = [dict(row) for row in (await session.execute(statement)).mappings()]
            projects = {
                row.id: row
                for row in (
                    await session.execute(
                        select(
                            EnrolledProject.id, EnrolledProject.backend_id, EnrolledProject.enabled
                        ).where(EnrolledProject.id.in_({r["project_id"] for r in found}))
                    )
                ).mappings()
            }
            backends = {
                row.id: row
                for row in (
                    await session.execute(
                        select(
                            EnrolledBackend.id, EnrolledBackend.enabled, EnrolledBackend.verified
                        ).where(EnrolledBackend.id.in_({r["backend_id"] for r in found}))
                    )
                ).mappings()
            }
        configured = {(p.id, p.backend_id) for p in self.settings.projects if p.enabled}
        items = []
        for row in found[:limit]:
            saved_project = projects.get(row["project_id"])
            saved_backend = backends.get(row["backend_id"])
            items.append(
                {
                    **row,
                    "bindings": int(row["bindings"]),
                    "active_bindings": int(row["active_bindings"] or 0),
                    "enrolled_scope": bool(
                        saved_project is not None
                        and saved_backend is not None
                        and saved_project["enabled"]
                        and saved_project["backend_id"] == row["backend_id"]
                        and saved_backend["enabled"]
                        and saved_backend["verified"]
                        and (row["project_id"], row["backend_id"]) in configured
                    ),
                    "native_observed": False,
                }
            )
        next_after = (
            encode_cursor(
                tuple(found[limit - 1][k] for k in ("backend_id", "session_id", "project_id"))
            )
            if len(found) > limit
            else None
        )
        return CatalogPage(
            "sessions", SESSION_COLUMNS, items, next_after, "bridge_database", None, chosen
        )

    async def action(self, identity: str) -> dict[str, Any] | None:
        async with self.db.sessions() as session:
            row = (
                (
                    await session.execute(
                        select(
                            *(getattr(Action, name) for name in ACTION_COLUMNS),
                            Action.payload_compacted_at,
                        ).where(Action.id == identity)
                    )
                )
                .mappings()
                .one_or_none()
            )
        return dict(row) if row is not None else None

    async def artifact(self, identity: str) -> dict[str, Any] | None:
        # Filename, MIME type and content are encrypted together and never opened here.
        async with self.db.sessions() as session:
            row = (
                (
                    await session.execute(
                        select(*(getattr(Artifact, name) for name in ARTIFACT_COLUMNS)).where(
                            Artifact.id == identity
                        )
                    )
                )
                .mappings()
                .one_or_none()
            )
        return dict(row) if row is not None else None
