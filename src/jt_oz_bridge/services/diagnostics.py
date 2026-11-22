"""Fixed numeric support export; never dialogue, credentials or Native inspection."""

import asyncio
import json
import math
import stat
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from jt_oz_bridge import __version__
from jt_oz_bridge.config import Settings
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, Delivery, InputEvent
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem

MAX_EXPORT_BYTES = 32768
TIMEOUT_SECONDS = 2.0
FEATURES = (
    "enabled",
    "native_mirror_enabled",
    "native_drafts_enabled",
    "file_returns_enabled",
    "generated_returns_enabled",
    "workspace_inputs_enabled",
    "workspace_menus_enabled",
    "session_creation_enabled",
    "zulip_recovery_enabled",
)


class DiagnosticUnavailable(Exception):
    """Fixed label only; callers must not return a database exception body."""


def sqlite_file_bytes(database: Database) -> int | None:
    """Apparent size of own SQLite files; no file bytes or symlinks are read."""
    if database.engine.dialect.name != "sqlite":
        return None
    name = database.engine.url.database
    if not name or not Path(name).is_absolute():
        return None
    total = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            info = Path(name + suffix).lstat()
        except FileNotFoundError:
            if not suffix:
                return None
            continue
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        total += info.st_size
    return total


async def collect_diagnostics(
    database: Database,
    settings: Settings,
    *,
    process_lease_current: bool,
    runtime_healthy: bool | None,
) -> bytes:
    if type(process_lease_current) is not bool or (
        runtime_healthy is not None and type(runtime_healthy) is not bool
    ):
        raise DiagnosticUnavailable("invalid_diagnostic_process_observation")
    driver = database.engine.dialect.name
    if driver not in {"sqlite", "postgresql"}:
        raise DiagnosticUnavailable("unsupported_diagnostic_database")
    observed = time.time()
    if not math.isfinite(observed) or observed <= 0:
        raise DiagnosticUnavailable("invalid_diagnostic_clock")
    columns: list[Any] = [
        select(func.count()).select_from(Binding).scalar_subquery().label("bindings_total"),
        select(func.count())
        .select_from(Binding)
        .where(Binding.state == "active", Binding.dispatch_paused.is_(True))
        .scalar_subquery()
        .label("bindings_active_paused"),
    ]
    for model, prefix, states in (
        (Action, "actions", ("queued", "admitted", "held", "ambiguous", "failed")),
        (Delivery, "deliveries", ("pending", "sending", "held", "ambiguous", "failed")),
        (FileTransfer, "file_transfers", ("prepared", "uploading", "queued", "ambiguous")),
    ):
        columns.append(
            select(func.count()).select_from(model).scalar_subquery().label(prefix + "_total")
        )
        columns.extend(
            select(func.count())
            .select_from(model)
            .where(model.state == state)
            .scalar_subquery()
            .label(prefix + "_" + state)
            for state in states
        )
    for counted_model, label in (
        (Artifact, "artifacts_total"),
        (ZulipRecoveryCheckpoint, "recovery_checkpoints_total"),
        (ZulipRecoveryItem, "recovery_items_total"),
    ):
        columns.append(
            select(func.count()).select_from(counted_model).scalar_subquery().label(label)
        )
    columns.extend(
        (
            select(func.coalesce(func.sum(Artifact.size_bytes), 0))
            .scalar_subquery()
            .label("artifact_recorded_bytes"),
            select(func.count())
            .select_from(InputEvent)
            .where(InputEvent.payload_compacted_at.is_not(None))
            .scalar_subquery()
            .label("compacted_input_records"),
            select(func.min(Action.created_at))
            .where(Action.state == "queued")
            .scalar_subquery()
            .label("oldest_queued_created_at"),
        )
    )
    try:
        async with asyncio.timeout(TIMEOUT_SECONDS):
            async with database.sessions() as session:
                revision = await session.scalar(text("SELECT version_num FROM alembic_version"))
                if revision != CURRENT_REVISION:
                    raise DiagnosticUnavailable("diagnostic_schema_not_current")
                row = (await session.execute(select(*columns))).one()._mapping
    except (SQLAlchemyError, TimeoutError):
        raise DiagnosticUnavailable("diagnostic_database_unavailable") from None
    values = dict(row)
    oldest = values.pop("oldest_queued_created_at")
    size = values["artifact_recorded_bytes"]
    if isinstance(size, Decimal) and size.is_finite() and size == size.to_integral_value():
        values["artifact_recorded_bytes"] = int(size)
    if any(type(v) is not int or not 0 <= v <= 2**63 - 1 for v in values.values()) or (
        oldest is not None
        and (type(oldest) not in {int, float} or not math.isfinite(oldest) or oldest < 0)
    ):
        raise DiagnosticUnavailable("invalid_diagnostic_numeric_observation")
    document = {
        "format": "jt-oz-bridge-diagnostics-v1",
        "version": __version__,
        "observed_at_unix": observed,
        "authority": "diagnostic_only",
        "schema_current": True,
        "database_driver": driver,
        "process_lease_current": process_lease_current,
        "runtime_healthy": runtime_healthy,
        "features": {key: getattr(settings.runtime, key) for key in FEATURES},
        "counts": values,
        "oldest_queued_age_seconds": None if oldest is None else max(0.0, observed - oldest),
        "sqlite_apparent_file_bytes": sqlite_file_bytes(database),
        "observation_scope": "One aggregate SQL query; process and file metadata observed separately.",
        "excluded": [
            "dialogue and tool output",
            "credentials and tokens",
            "account, project, session and message identities",
            "paths, addresses, configuration files and secret references",
            "Native inspection and execution authority",
        ],
    }
    result = (json.dumps(document, sort_keys=True, allow_nan=False) + "\n").encode()
    if len(result) > MAX_EXPORT_BYTES:
        raise DiagnosticUnavailable("diagnostic_export_capacity_exceeded")
    return result
