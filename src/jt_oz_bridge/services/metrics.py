"""Fixed-name ownDB and storage gauges for /metrics; never payloads or identities.

One aggregate SQL query over plain columns, no decryption and no Native or Zulip
request. Labels come only from the literal state/table sets below, so cardinality
is fixed and no topic, session, user, path or message text can become a label.
"""

import asyncio
import math
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select, text

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.redaction import redactions_total
from jt_oz_bridge.services.diagnostics import sqlite_file_bytes
from jt_oz_bridge.storage.artifact_models import ArtifactBudget
from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.live_models import NativeFeedReceipt, NativeLiveCapture
from jt_oz_bridge.storage.models import Delivery, InputEvent
from jt_oz_bridge.storage.workspace_models import WorkspaceBudget
from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

TIMEOUT_SECONDS = 2.0
INPUT_PENDING = ("zulip_received", "zulip_processing", "zulip_deferred")
OUTBOX_STATES = ("pending", "sending", "held", "ambiguous")
RECOVERY_RUNS = {
    "running": "zulip_recovery_running",
    "partial": "zulip_recovery_partial",
    "capacity": "zulip_recovery_capacity",
}
RECOVERY_ITEMS = ("captured", "held", "reviewed")
LIVE_TABLES = {"native_feed_receipts": NativeFeedReceipt, "native_live_captures": NativeLiveCapture}
OLDEST = frozenset({"input_oldest", "outbox_oldest", "interaction_oldest"})  # NULL when empty

PROCESS_METRICS = {
    "zulip_rate_limited_total": "counter",
    "zulip_requests_deferred_total": "counter",
    "native_feeds_connected": "gauge",
    "live_receipts_deleted_total": "counter",
    "live_captures_deleted_total": "counter",
}

Sample = tuple[str, str, dict[str, str], int | float]


def _count(model: Any, *conditions: Any) -> Any:
    return select(func.count()).select_from(model).where(*conditions).scalar_subquery()


def _number(value: Any) -> int | float | None:
    if isinstance(value, Decimal) and value.is_finite():
        value = int(value) if value == value.to_integral_value() else float(value)
    if type(value) is int and 0 <= value <= 2**63 - 1:
        return value
    if type(value) is float and math.isfinite(value) and value >= 0:
        return value
    return None


def _age(now: float, oldest: Any) -> float:
    value = _number(oldest)
    return 0.0 if value is None else round(max(0.0, now - value), 3)


async def collect_storage_metrics(
    database: Database, settings: Settings, now: float
) -> list[Sample]:
    """Return (name, type, labels, value); raise rather than report a guessed zero."""
    columns: dict[str, Any] = {
        "input_pending": _count(InputEvent, InputEvent.state.in_(INPUT_PENDING)),
        "input_oldest": select(func.min(InputEvent.created_at))
        .where(InputEvent.state.in_(INPUT_PENDING))
        .scalar_subquery(),
        "outbox_oldest": select(func.min(Delivery.created_at))
        .where(Delivery.state.in_(OUTBOX_STATES))
        .scalar_subquery(),
        "outbox_retrying": _count(
            Delivery, Delivery.state.in_(OUTBOX_STATES), Delivery.attempts > 0
        ),
        "receipt_retries": _count(ZulipReceiptRetry),
        "interactions": _count(PendingInteraction, PendingInteraction.state == "pending"),
        "interaction_oldest": select(func.min(PendingInteraction.created_at))
        .where(PendingInteraction.state == "pending")
        .scalar_subquery(),
        "artifact_bytes": select(
            func.coalesce(func.sum(ArtifactBudget.reserved_bytes), 0)
        ).scalar_subquery(),
        "workspace_bytes": select(
            func.coalesce(func.sum(WorkspaceBudget.reserved_bytes), 0)
        ).scalar_subquery(),
    }
    for state in OUTBOX_STATES:
        columns["outbox_" + state] = _count(Delivery, Delivery.state == state)
    for label, state in RECOVERY_RUNS.items():
        columns["run_" + label] = _count(InputEvent, InputEvent.state == state)
    for state in RECOVERY_ITEMS:
        columns["item_" + state] = _count(ZulipRecoveryItem, ZulipRecoveryItem.state == state)
    for table, model in LIVE_TABLES.items():
        columns["rows_" + table] = _count(model)
    free: int | None = None
    async with asyncio.timeout(TIMEOUT_SECONDS):
        async with database.sessions() as session:
            row = (
                (await session.execute(select(*(v.label(k) for k, v in columns.items()))))
                .one()
                ._mapping
            )
            if database.engine.dialect.name == "sqlite":
                pages = await session.scalar(text("PRAGMA freelist_count"))
                size = await session.scalar(text("PRAGMA page_size"))
                if type(pages) is int and type(size) is int:
                    free = pages * size
    values: dict[str, int | float] = {}
    for key, raw in row.items():
        number = _number(raw)
        if number is not None:
            values[key] = number
        elif key not in OLDEST:
            raise ValueError("invalid_metric_aggregate")
    gauge = "gauge"
    samples: list[Sample] = [
        ("input_events_pending", gauge, {}, values["input_pending"]),
        ("input_event_lag_seconds", gauge, {}, _age(now, row["input_oldest"])),
    ]
    samples.extend(
        ("outbox_deliveries", gauge, {"state": state}, values["outbox_" + state])
        for state in OUTBOX_STATES
    )
    samples.extend(
        (
            ("outbox_oldest_age_seconds", gauge, {}, _age(now, row["outbox_oldest"])),
            ("outbox_retrying_deliveries", gauge, {}, values["outbox_retrying"]),
            ("zulip_receipt_retries", gauge, {}, values["receipt_retries"]),
            ("pending_interactions", gauge, {}, values["interactions"]),
            (
                "pending_interaction_oldest_age_seconds",
                gauge,
                {},
                _age(now, row["interaction_oldest"]),
            ),
        )
    )
    samples.extend(
        ("recovery_runs", gauge, {"state": label}, values["run_" + label])
        for label in RECOVERY_RUNS
    )
    samples.extend(
        ("recovery_items", gauge, {"state": state}, values["item_" + state])
        for state in RECOVERY_ITEMS
    )
    samples.extend(
        ("live_source_rows", gauge, {"table": table}, values["rows_" + table])
        for table in LIVE_TABLES
    )
    samples.extend(
        (
            ("artifact_reserved_bytes", gauge, {}, values["artifact_bytes"]),
            ("artifact_quota_bytes", gauge, {}, settings.retention.artifact_quota_bytes),
            ("workspace_reserved_bytes", gauge, {}, values["workspace_bytes"]),
            ("workspace_quota_bytes", gauge, {}, settings.retention.workspace_quota_bytes),
        )
    )
    # Apparent own file sizes only. Deleted rows leave reusable SQLite pages;
    # no VACUUM runs, so file size alone does not show retention progress.
    on_disk = sqlite_file_bytes(database)
    if on_disk is not None:
        samples.append(("database_file_bytes", gauge, {}, on_disk))
    if free is not None and free >= 0:
        samples.append(("database_free_bytes", gauge, {}, free))
    return samples


def process_samples(runtime: object | None) -> list[Sample]:
    """In-process counters; an unknown name or non-count value is dropped."""
    samples: list[Sample] = [("redactions_total", "counter", {}, redactions_total())]
    callback = getattr(runtime, "process_metrics", None)
    if not callable(callback):
        return samples
    try:
        values = callback()
    except Exception:
        return samples  # Never expose a runtime exception or guess its counts.
    if isinstance(values, dict):
        samples.extend(
            (name, kind, {}, values[name])
            for name, kind in PROCESS_METRICS.items()
            if type(values.get(name)) is int and 0 <= values[name] <= 2**63 - 1
        )
    return samples


def render(samples: list[Sample]) -> list[str]:
    lines: list[str] = []
    typed: set[str] = set()
    for name, kind, labels, value in samples:
        metric = "jt_oz_bridge_" + name
        if metric not in typed:
            typed.add(metric)
            lines.append(f"# TYPE {metric} {kind}")
        label = ",".join(f'{key}="{labels[key]}"' for key in sorted(labels))
        lines.append(f"{metric}{{{label}}} {value}" if label else f"{metric} {value}")
    return lines
