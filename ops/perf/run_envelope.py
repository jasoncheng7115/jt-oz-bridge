#!/usr/bin/env python3
"""SYNTHETIC load harness for the target workload shape (docs/PERFORMANCE.md).

Drives the real ConsumerPipeline, supervised runtime, V2PublicFeed, encrypted
SQLite ownDB, outbox, request budget and delivery worker. Zulip and OpenCode
Native are in-process synthetic peers, so a result here is never a real-Zulip
or real-Native result, never Human or mobile evidence and never acceptance
evidence for performance or load. See docs/PERFORMANCE.md for how to read the output.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import platform
import re
import sys
import tempfile
import time
from array import array
from bisect import bisect_right
from collections import Counter, deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from html import unescape
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
from sqlalchemy import event, func, select

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.sse import iter_sse
from jt_oz_bridge.adapters.opencode.transcript import NativeTranscriptPage, project_message
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    NativeResourceTurn,
    ProjectedTurn,
    ResourceText,
)
from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.domain.catalog import CatalogPage, CatalogSession
from jt_oz_bridge.domain.control import ExecutionState, InteractionSnapshot, SessionSnapshot
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.model_catalog import NativeModelCatalog, NativeModelOption, NativeModelRef
from jt_oz_bridge.domain.models import Capability, SessionRef
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline, RuntimeBackend
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.live_capture import LiveEventJournal, LiveTextCollector
from jt_oz_bridge.services.runtime import RuntimeResource
from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.database import DEFAULT_SQLITE_BUSY_TIMEOUT_MS, Database, migrate
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.live_models import NativeFeedReceipt, NativeLiveCapture
from jt_oz_bridge.storage.models import Action, Delivery, Grant

try:  # The in-process write queue; absent from older trees compared with this one.
    from jt_oz_bridge.storage.sessions import WriteGateExpired as QUEUE_EXPIRED
except ImportError:  # pragma: no cover - comparison runs against an older tree only
    QUEUE_EXPIRED = None  # type: ignore[assignment,misc]

SYNTHETIC_LABEL = (
    "SYNTHETIC LOAD ONLY: in-process synthetic Zulip and Native peers; "
    "NOT a real-Zulip or real-Native result; NOT Human/mobile evidence; "
    "NOT acceptance evidence for performance or load."
)
URL = "https://zulip.invalid"
NATIVE_URL = "http://127.0.0.1:4096"
OWNER = "a" * 64
CHANNEL = 10
HUMAN = 7
BOT = 11
ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "tests/fixtures/contracts/opencode-v2.0.32-installed.json"
FINAL_MARKER = re.compile(r"PERF-FINAL:t(\d+):n(\d+)\b")
DELTA_MARKER = re.compile(r"S(\d+)\.")
HUMAN_MARKER = re.compile(r"PERF-H:t(\d+):h(\d+)\b")
COMPUTER_MARKER = re.compile(r"PERF-C:t(\d+):n(\d+)\b")
PERCENT_KEYS = (50, 90, 95, 99)
# The one-message permission notice repeats the request description; the
# generic "runtime.pending" text is only the unpreviewable fallback.
PERMISSION_DESCRIPTION = "Synthetic load permission request"
DatabaseFactory = Callable[[Path], Awaitable[Database]]


@dataclass
class Config:
    duration: float = 600.0
    topics: int = 20
    active: int = 5
    rate: float = 100.0
    events_per_turn: int = 300
    delta_bytes: int = 16
    budget_requests: int = 180
    budget_window: float = 60.0
    budget_reserved: int = 64
    human_per_minute: float = 6.0
    interactions_per_minute: float = 6.0
    inject_429_every: int = 0
    retry_after: float = 5.0
    busy_timeout_ms: int = DEFAULT_SQLITE_BUSY_TIMEOUT_MS
    zulip_latency_ms: float = 20.0
    native_latency_ms: float = 5.0
    drafts: bool = True
    interval: float = 1.0
    delivery_interval: float = 1.0
    draft_interval: float = 1.0
    drain_seconds: float = 300.0
    warmup_seconds: float = 180.0
    sample_seconds: float = 5.0
    max_rss_mib: float = 750.0
    max_rss_growth_mib_per_minute: float = 5.0
    interaction_p95_limit_seconds: float = 5.0
    load_tolerance: float = 0.95
    budget_tolerance: int = 2
    fault: str | None = None
    workdir: str | None = None


class Recorder:
    """Bounded numeric samples; never message bodies."""

    def __init__(self) -> None:
        self.series: dict[str, array[float]] = {}

    def add(self, name: str, value: float) -> None:
        self.series.setdefault(name, array("d")).append(max(0.0, value))

    def summary(self) -> dict[str, dict[str, float | int]]:
        return {name: percentiles(values) for name, values in sorted(self.series.items())}


def percentiles(values: Any) -> dict[str, float | int]:
    ordered = sorted(values)
    if not ordered:
        return {"count": 0}
    result: dict[str, float | int] = {"count": len(ordered)}
    for key in PERCENT_KEYS:
        position = min(len(ordered) - 1, max(0, int(len(ordered) * key / 100 + 0.5) - 1))
        result[f"p{key}"] = round(ordered[position], 4)
    result["max"] = round(ordered[-1], 4)
    return result


class SyntheticZulip:
    """Long-polling in-process peer that records what the bridge actually sent."""

    def __init__(self, config: Config, recorder: Recorder, pending_notice: str) -> None:
        self.config, self.recorder, self.pending_notice = config, recorder, pending_notice
        self.messages: dict[int, dict[str, Any]] = {}
        self.events: deque[dict[str, Any]] = deque()
        self.next_event = 0
        self.next_mid = 100000
        self.changed = asyncio.Event()
        self.topic_latest: dict[str, deque[dict[str, Any]]] = {}
        self.request_times: deque[float] = deque()
        self.peak_requests_in_window = 0
        self.routes: Counter[str] = Counter()
        self.writes = 0
        self.responses_429 = 0
        self.cooldown_from = 0.0
        self.cooldown_until = 0.0
        self.during_cooldown = 0
        self.finals: dict[tuple[int, int], list[tuple[float, int, str]]] = {}
        self.final_order: dict[int, list[int]] = {}
        self.computer_echo: Counter[tuple[int, int]] = Counter()
        self.received_at: dict[int, float] = {}
        self.draft_top: dict[int, int] = {}
        self.draft_regressions = 0
        self.notices: Counter[str] = Counter()
        self.notice_times: dict[str, list[float]] = {}
        self.dropped: set[tuple[int, int]] = set()
        self.emit_time: array[float] = array("d")
        self.wire_bytes = 0
        self.warm = False

    def message(self, text: str, mid: int, author: int, topic: str) -> dict[str, Any]:
        value = {
            "id": mid,
            "type": "stream",
            "stream_id": CHANNEL,
            "subject": topic,
            "sender_id": author,
            "content": text,
            "content_type": "text/x-markdown",
            "edit_history": [],
        }
        self.messages[mid] = value
        self.topic_latest.setdefault(topic, deque(maxlen=2)).append(value)
        return value

    def input(self, text: str, topic: str, author: int = HUMAN) -> int:
        mid = self.next_mid
        self.next_mid += 1
        value = self.message(text, mid, author, topic)
        self.events.append(
            {"id": self.next_event, "type": "message", "message": copy.deepcopy(value)}
        )
        self.next_event += 1
        self.changed.set()
        return mid

    def _account(self, now: float, request: httpx.Request) -> None:
        route = request.url.path.removeprefix("/api/v1/")
        self.routes[request.method + " " + re.sub(r"[0-9]+", "N", route)] += 1
        if not self.warm:
            return
        if self.cooldown_from <= now < self.cooldown_until:
            self.during_cooldown += 1
        window = self.config.budget_window
        self.request_times.append(now)
        while self.request_times and self.request_times[0] <= now - window:
            self.request_times.popleft()
        self.peak_requests_in_window = max(self.peak_requests_in_window, len(self.request_times))

    def _record_output(self, now: float, mid: int, text: str, kind: str, topic: str) -> None:
        body = unescape(text)
        self.wire_bytes += len(text.encode())
        final = FINAL_MARKER.search(body)
        if final is not None:
            key = (int(final.group(1)), int(final.group(2)))
            if self._should_drop(key):
                return
            self.finals.setdefault(key, []).append((now, mid, kind))
            self.final_order.setdefault(key[0], [])
            if kind == "post":
                self.final_order[key[0]].append(key[1])
        echoed = COMPUTER_MARKER.search(body)
        if echoed is not None and kind == "post":
            self.computer_echo[(int(echoed.group(1)), int(echoed.group(2)))] += 1
        found = DELTA_MARKER.findall(body)
        if found and final is None:
            top = max(map(int, found))
            previous = self.draft_top.get(mid)
            if previous is not None and top < previous:
                self.draft_regressions += 1
            self.draft_top[mid] = max(top, previous or 0)
            if top < len(self.emit_time):
                self.recorder.add("native_event_to_draft_display", now - self.emit_time[top])
        if self.pending_notice in body and kind == "post":
            self.notices[topic] += 1
            self.notice_times.setdefault(topic, []).append(now)

    def _should_drop(self, key: tuple[int, int]) -> bool:
        # The first final seen is lost for good: neither its post nor a later edit
        # (a closed draft repeating the final text) may count as delivered.
        if self.config.fault != "drop-final":
            return False
        if not self.dropped:
            self.dropped.add(key)
        return key in self.dropped

    async def handle(self, request: httpx.Request) -> httpx.Response:
        now = time.monotonic()
        self._account(now, request)
        route = request.url.path.removeprefix("/api/v1/")
        method = request.method
        if method == "GET" and route == "events":
            return await self._events(request)
        if self.config.zulip_latency_ms:
            await asyncio.sleep(self.config.zulip_latency_ms / 1000)
        if route == "users/me":
            return self._ok(
                {
                    "user_id": BOT,
                    "is_bot": True,
                    "is_active": True,
                    "bot_owner_id": HUMAN,
                    "role": 400,
                }
            )
        if route == "server_settings":
            return self._ok({"realm_url": URL, "zulip_version": "12.3", "zulip_feature_level": 500})
        if method == "POST" and route == "typing":
            return self._ok({})
        if method == "POST" and route == "register":
            return self._ok(
                {
                    "queue_id": "synthetic-queue",
                    "last_event_id": -1,
                    "server_typing_started_wait_period_milliseconds": 30000,
                    "server_typing_started_expiry_period_milliseconds": 45000,
                    "server_typing_stopped_wait_period_milliseconds": 12000,
                }
            )
        if method == "DELETE" and route == "events":
            return self._ok({})
        if route == "users/me/subscriptions":
            return self._ok(
                {
                    "subscriptions": [
                        {
                            "stream_id": CHANNEL,
                            "invite_only": True,
                            "is_web_public": False,
                            "history_public_to_subscribers": False,
                            "is_archived": False,
                            "subscribers": [HUMAN, 8, BOT],
                        }
                    ]
                }
            )
        if route == "users":
            ids = json.loads(request.url.params["user_ids"])
            return self._ok({"members": [self._user(uid) for uid in ids]})
        if route == f"streams/{CHANNEL}":
            return self._ok(
                {
                    "stream": {
                        "stream_id": CHANNEL,
                        "invite_only": True,
                        "is_web_public": False,
                        "history_public_to_subscribers": False,
                    }
                }
            )
        if route == f"streams/{CHANNEL}/members":
            return self._ok({"subscribers": [HUMAN, 8, BOT]})
        if route == f"users/me/{CHANNEL}/topics":
            return self._ok(
                {
                    "topics": [
                        {"name": name, "max_id": rows[-1]["id"]}
                        for name, rows in self.topic_latest.items()
                        if rows
                    ]
                }
            )
        if route.startswith("users/"):
            return self._ok({"user": self._user(int(route.split("/")[1]))})
        if route == "messages" and method == "POST":
            return self._post(now, request)
        if route == "messages":
            narrow = json.loads(request.url.params.get("narrow", "[]"))
            topic = next((x["operand"] for x in narrow if x["operator"] == "topic"), "")
            return self._ok({"messages": list(self.topic_latest.get(topic, ()))})
        if route.startswith("messages/") and method == "PATCH":
            return self._patch(now, request, int(route.split("/")[1]))
        if route.startswith("messages/") and method == "GET":
            return self._ok({"message": self.messages[int(route.split("/")[1])]})
        raise AssertionError("unexpected synthetic route " + method + " " + route)

    @staticmethod
    def _user(uid: int) -> dict[str, Any]:
        return {"user_id": uid, "is_active": True, "is_bot": uid == BOT}

    @staticmethod
    def _ok(data: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={"result": "success", **copy.deepcopy(data)})

    def _rate_limited(self, now: float) -> httpx.Response | None:
        every = self.config.inject_429_every
        self.writes += 1
        if not (self.warm and every and self.writes % every == 0):
            return None
        self.responses_429 += 1
        # Requests already started before the client could see this 429 are not violations.
        self.cooldown_from = now + 2 * self.config.zulip_latency_ms / 1000 + 0.1
        self.cooldown_until = now + self.config.retry_after - 0.1
        return httpx.Response(
            429,
            headers={"retry-after": str(self.config.retry_after)},
            json={"result": "error", "code": "RATE_LIMIT_HIT", "msg": "synthetic"},
        )

    def _post(self, now: float, request: httpx.Request) -> httpx.Response:
        limited = self._rate_limited(now)
        if limited is not None:
            return limited
        data = parse_qs(request.content.decode())
        text, topic = data["content"][0], data["topic"][0]
        mid = self.next_mid
        self.next_mid += 1
        self.received_at[mid] = now
        self._record_output(now, mid, text, "post", topic)
        value = self.message(text, mid, BOT, topic)
        # Real Zulip echoes the Bot's own message into its event queue.
        self.events.append(
            {"id": self.next_event, "type": "message", "message": copy.deepcopy(value)}
        )
        self.next_event += 1
        self.changed.set()
        return httpx.Response(200, json={"result": "success", "id": mid})

    def _patch(self, now: float, request: httpx.Request, mid: int) -> httpx.Response:
        limited = self._rate_limited(now)
        if limited is not None:
            return limited
        text = parse_qs(request.content.decode())["content"][0]
        saved = self.messages[mid]
        saved["content"] = text
        self._record_output(now, mid, text, "edit", saved["subject"])
        return httpx.Response(200, json={"result": "success"})

    async def _events(self, request: httpx.Request) -> httpx.Response:
        last = int(request.url.params["last_event_id"])
        while self.events and self.events[0]["id"] <= last:
            self.events.popleft()
        deadline = time.monotonic() + 25
        while not self.events:
            self.changed.clear()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(self.changed.wait(), remaining)
            except TimeoutError:
                break
        return httpx.Response(
            200, json={"result": "success", "events": copy.deepcopy(list(self.events))}
        )


class SyntheticNative:
    """One enrolled synthetic original session. No model, tool or real OpenCode."""

    contract_hash = INSTALLED_SCHEMA

    def __init__(self, index: int, ref: SessionRef, harness: Harness) -> None:
        self.index, self.ref, self.harness = index, ref, harness
        self.state = ExecutionState.IDLE
        self.messages: list[Any] = []
        self.pages: deque[NativeTranscriptPage] = deque(maxlen=64)
        self.clock = 1
        self.token = 0
        self.submitted: list[tuple[str, str]] = []
        self.requests: dict[str, InteractionSnapshot] = {}
        self.pending_human: deque[tuple[str, str]] = deque()
        self.turn_number = 0
        self.turn_final_text: dict[str, tuple[str, str, str]] = {}
        self.results_seen: dict[str, Any] = {}
        # A real original session already has history; its baseline is one notice.
        self.messages.append(
            project_message(
                {
                    "id": f"msg_t{index:03d}_history",
                    "type": "user",
                    "time": {"created": 1},
                    "text": "Existing computer input",
                }
            )
        )

    def contract_for(self, reference: SessionRef) -> str:
        return self.contract_hash

    def capabilities(self, reference: SessionRef) -> dict[str, Capability]:
        return {
            kind: Capability(
                supported=True,
                scope="session",
                reason="synthetic load peer only",
                verification="synthetic_test",
            )
            for kind in ("prompt", "permission.reply", "form.reply", "interrupt")
        }

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot:
        await self.harness.native_delay()
        return SessionSnapshot(
            reference=reference,
            title="Synthetic original session",
            state=self.state,
            cursor="synthetic-state",
            reconciled=True,
            descendants=(),
        )

    async def interaction(self, reference: SessionRef, request_id: str) -> InteractionSnapshot:
        await self.harness.native_delay()
        request = self.requests.get(request_id)
        if request is None:
            # The same typed outcome the real adapter gives a request answered elsewhere.
            raise ContractError("synthetic_request_already_resolved")
        return request

    async def submit(self, reference: SessionRef, payload: dict[str, Any], action_id: str) -> Any:
        await self.harness.native_delay()
        text = payload.get("text", "")
        upstream = "msg_user_" + hashlib.sha256(action_id.encode()).hexdigest()[:24]
        self.submitted.append((text, action_id))
        self.harness.note_submit(self, text)
        if payload["operation"] == "prompt":
            self.state = ExecutionState.RUNNING
            self.pending_human.append((upstream, text))
        return Admission(status="admitted", upstream_id=upstream)

    def bump(self) -> None:
        self.token += 1

    def change_token(self, reference: SessionRef) -> str:
        return str(self.token)

    def current(self, page: NativeTranscriptPage) -> bool:
        return any(saved is page for saved in self.pages)

    async def capture(
        self, reference: SessionRef, *, cursor: str | None = None, limit: int = 20
    ) -> NativeTranscriptPage:
        await self.harness.native_delay()
        start = 0
        if cursor:
            anchor = cursor.removeprefix("opaque:")
            start = next(
                (i + 1 for i, entry in enumerate(self.messages) if entry.native_id == anchor), 0
            )
        entries = tuple(self.messages[start : start + limit])
        following = (
            "opaque:" + entries[-1].native_id
            if entries and start + limit < len(self.messages)
            else None
        )
        now = time.time()
        page = NativeTranscriptPage(
            reference=reference,
            contract_sha256=self.contract_hash,
            semantics_sha256="b" * 64,
            installed_evidence_sha256="c" * 64,
            owner_epoch=OWNER,
            connection_epoch=self.harness.connection_epoch(),
            resource_fence="e" * 64,
            session_info_sha256="f" * 64,
            state=self.state,
            witness_id=str(uuid4()),
            observed_at=now,
            expires_at=now + 5,
            cursor=cursor,
            limit=limit,
            next_cursor=following,
            entries=entries,
        )
        self.pages.append(page)
        return page

    def begin_turn(self, user_id: str, text: str) -> tuple[str, str]:
        self.turn_number += 1
        self.state = ExecutionState.RUNNING
        identity = f"msg_t{self.index:03d}_n{self.turn_number:05d}"
        assistant = identity + "_a"
        self.clock += 1
        self.messages.insert(
            0, project_message(self._assistant(assistant, "", completed=False, created=self.clock))
        )
        self.messages.insert(
            1,
            project_message(
                {"id": user_id, "type": "user", "time": {"created": self.clock}, "text": text}
            ),
        )
        self.bump()
        return assistant, identity

    def finish_turn(self, assistant: str, identity: str, text: str, user_id: str) -> None:
        self.clock += 1
        terminal = identity + "_idle"
        self.messages[0] = project_message(
            self._assistant(assistant, text, completed=True, created=self.clock)
        )
        self.messages.insert(
            0,
            project_message(
                {
                    "id": terminal,
                    "type": "idle",
                    "time": {"created": self.clock + 1},
                    "outcome": "succeeded",
                }
            ),
        )
        self.turn_final_text[user_id] = (assistant, terminal, text)
        self.state = ExecutionState.IDLE if not self.pending_human else ExecutionState.RUNNING
        self.bump()

    def _assistant(self, identity: str, text: str, *, completed: bool, created: int) -> dict:
        return {
            "id": identity,
            "type": "assistant",
            "agent": "build",
            "model": {"providerID": "synthetic", "id": "model"},
            "time": {"created": created, **({"completed": created + 1} if completed else {})},
            "content": [{"type": "text", "text": text}],
        }


class SyntheticResults:
    """Correlated finished turn for one synthetic session; refuses unfinished turns."""

    def __init__(self, native: SyntheticNative) -> None:
        self.native = native
        self.evidence: NativeResourceTurn | None = None

    async def capture(self, correlation: Any) -> NativeResourceTurn:
        await self.native.harness.native_delay()
        saved = self.native.turn_final_text.get(correlation.upstream_id)
        if saved is None:
            raise ContractError("synthetic_turn_not_finished")
        assistant, terminal, text = saved
        now = time.time()
        self.evidence = NativeResourceTurn(
            correlation=correlation,
            contract_sha256=INSTALLED_SCHEMA,
            semantics_sha256=RESOURCE_SEMANTICS,
            installed_evidence_sha256="a" * 64,
            connection_epoch="synthetic-only-resource-epoch",
            owner_epoch="b" * 64,
            ownership_evidence_sha256="c" * 64,
            session_info_sha256="d" * 64,
            resource_fence="e" * 64,
            observed_at=now,
            expires_at=now + 5,
            turn=ProjectedTurn(
                user_id=correlation.upstream_id,
                user_projection_sha256="f" * 64,
                terminal_id=terminal,
                terminal_projection_sha256="a" * 64,
                terminal_created=1,
                outcome="succeeded",
                text=(ResourceText(assistant_id=assistant, content_index=0, text=text),),
                tools=(),
                ordered_message_ids=(correlation.upstream_id, assistant, terminal),
                selected_projection_sha256="b" * 64,
            ),
        )
        return self.evidence

    def current(self, value: Any) -> bool:
        return value is self.evidence and time.time() < value.expires_at


class SyntheticCatalog:
    """Installed-shape model catalog with one synthetic option."""

    def __init__(self, ref: SessionRef) -> None:
        selected = NativeModelRef(provider_id="synthetic", model_id="load")
        self.snapshot = NativeModelCatalog(
            reference=ref,
            contract_sha256=INSTALLED_SCHEMA,
            selected=selected,
            default=selected,
            items=(
                NativeModelOption(
                    reference=selected,
                    upstream_model_id="synthetic-load",
                    name="Synthetic load model",
                    status="active",
                    variant_ids=(),
                ),
            ),
        )

    def contract_for(self, ref: SessionRef) -> str:
        return INSTALLED_SCHEMA

    async def read(self, ref: SessionRef) -> NativeModelCatalog:
        return self.snapshot


class SyntheticSessions:
    def __init__(self, refs: tuple[SessionRef, ...]) -> None:
        self.refs = refs

    def contract_for_project(self, scope: Any) -> str:
        return INSTALLED_SCHEMA

    async def list_sessions(self, scope: Any, *, search: Any, cursor: Any, limit: Any) -> Any:
        return CatalogPage(
            scope=scope,
            contract_sha256=INSTALLED_SCHEMA,
            search=search,
            cursor=cursor,
            items=tuple(
                CatalogSession(reference=ref, title=ref.upstream_session_id) for ref in self.refs
            ),
        )


class TimedJournal(LiveEventJournal):
    """The real durable receipt journal, plus an emit-to-durable-receipt timing."""

    harness: Harness

    async def record_many(self, values: tuple[Any, ...]) -> tuple[bool, ...]:
        result = await super().record_many(values)
        now = time.monotonic()
        for value in values:
            match = re.fullmatch(r"evt_perf_(\d+)", value.native_id)
            if match:
                self.harness.recorder.add(
                    "native_event_to_durable_receipt",
                    now - self.harness.zulip.emit_time[int(match.group(1))],
                )
        return result


@dataclass
class Turn:
    native: SyntheticNative
    number: int
    assistant: str
    identity: str
    user_id: str
    remaining: int
    text: list[str] = field(default_factory=list)
    started: bool = False


class Harness:
    def __init__(self, config: Config, workdir: Path) -> None:
        self.config, self.workdir = config, workdir
        self.recorder = Recorder()
        self.zulip = SyntheticZulip(config, self.recorder, PERMISSION_DESCRIPTION)
        self.natives: list[SyntheticNative] = []
        self.sse: asyncio.Queue[bytes] = asyncio.Queue()
        self.sse_peak = 0
        self.feed: V2PublicFeed | None = None
        self.seq = 0
        self.samples: list[dict[str, Any]] = []
        self.finished_turns: dict[tuple[int, int], float] = {}
        self.human_sent: dict[str, float] = {}
        self.human_submitted: Counter[str] = Counter()
        self.human_submit_order: dict[int, list[int]] = {}
        self.interactions_sent: dict[str, list[float]] = {}
        self.interaction_count = 0
        self.open_requests: list[tuple[SyntheticNative, str, str, int]] = []
        self.emitted = 0
        self.emit_started = 0.0
        self.emit_ended = 0.0
        self.emitter_late_peak = 0.0
        self.db: Database | None = None
        self.pipeline: ConsumerPipeline | None = None
        self.runtime: Any = None
        self.budget: ZulipRequestBudget | None = None
        self.binding_topics: dict[int, str] = {}
        self.emitting = False
        self.store: DurableStore | None = None
        self.lease: int | None = None
        self.lease_renewals_refused = 0
        self.sample_started = time.monotonic()
        self.requests_by_worker: Counter[str] = Counter()
        self.database_errors: Counter[str] = Counter()
        self.cpu_mark = (time.monotonic(), time.process_time())

    @staticmethod
    def _worker_name() -> str:
        """The supervised worker's task name; unnamed tasks are the feed and its helpers."""
        task = asyncio.current_task()
        if task is None:
            return "no_task"
        label = task.get_name()
        return "unnamed_task" if label.startswith("Task-") else label

    def _attribute_requests(self, client: ZulipClient) -> None:
        """Tally each Zulip request by the supervised worker that issued it."""
        original = client.request
        tally = self.requests_by_worker

        async def request(*args: Any, **kwargs: Any) -> Any:
            tally[self._worker_name()] += 1
            return await original(*args, **kwargs)

        client.request = request  # type: ignore[method-assign]

    def _attribute_database(self) -> None:
        """Observe SQLite write-lock holds and errors; message text only, no statement."""
        assert self.db is not None
        engine = self.db.engine.sync_engine
        holds: dict[int, tuple[float, str]] = {}
        task_label = self._worker_name
        entered: dict[int, float] = {}
        factory = self.db.sessions
        original_begin = factory.begin
        recorder, errors = self.recorder, self.database_errors

        @asynccontextmanager
        async def timed_begin() -> AsyncIterator[Any]:
            # From asking for a write transaction to holding the lock: the in-process
            # queue (when present) plus SQLite's own busy wait.
            task = id(asyncio.current_task())
            entered[task] = time.monotonic()
            try:
                async with original_begin() as session:
                    yield session
            except Exception as error:
                if QUEUE_EXPIRED is not None and isinstance(error, QUEUE_EXPIRED):
                    errors[
                        f"{type(error).__name__}: database is locked @ {task_label()} "
                        f"statement=queued waited={error.waited:.2f}s"
                    ] += 1
                raise
            finally:
                entered.pop(task, None)

        factory.begin = timed_begin  # type: ignore[method-assign]

        @event.listens_for(engine, "begin")
        def begin(connection: Any) -> None:
            if connection.get_execution_options().get("jtoz_begin_immediate"):
                now = time.monotonic()
                asked = entered.pop(id(asyncio.current_task()), None)
                if asked is not None:
                    recorder.add("sqlite_write_wait:" + task_label(), now - asked)
                holds[id(connection)] = (now, task_label())

        def finish(connection: Any) -> None:
            held = holds.pop(id(connection), None)
            if held is not None:
                self.recorder.add("sqlite_write_hold:" + held[1], time.monotonic() - held[0])

        event.listen(engine, "commit", finish)
        event.listen(engine, "rollback", finish)

        @event.listens_for(engine, "before_cursor_execute")
        def statement_started(
            connection: Any,
            _cursor: Any,
            statement: str,
            _parameters: Any,
            _context: Any,
            _many: Any,
        ) -> None:
            connection.info["perf_statement"] = (time.monotonic(), statement.split(None, 2)[:2])

        @event.listens_for(engine, "handle_error")
        def failed(context: Any) -> None:
            error = context.original_exception
            if isinstance(error, asyncio.CancelledError):
                return  # Worker shutdown noise, not a database condition.
            # Keyword and table only: how long this statement waited tells a busy-timeout
            # expiry (about the timeout) from an immediate snapshot conflict (about zero).
            connection = context.connection
            started, words = (
                connection.info.get("perf_statement", (None, ["?"]))
                if connection is not None
                else (None, ["?"])
            )
            waited = "?" if started is None else f"{time.monotonic() - started:.2f}s"
            # Which writer, if any, still held the lock when this statement gave up.
            now = time.monotonic()
            holders = sorted(((now - at, worker) for at, worker in holds.values()), reverse=True)[
                :3
            ]
            label = (
                f"{type(error).__name__}: {str(error)[:80]} @ {task_label()} "
                f"statement={' '.join(words)} waited={waited} open_writers="
                + ",".join(f"{worker}:{age:.2f}s" for age, worker in holders)
            )
            self.database_errors[label] += 1

    async def heartbeat(self) -> None:
        """Same duty as the web application's consumer heartbeat, without its web app."""
        assert self.store is not None and self.lease is not None
        while True:
            await asyncio.sleep(10)
            if not await self.store.renew_lease("perf-envelope", self.lease, ttl=120):
                self.lease_renewals_refused += 1

    async def loop_probe(self) -> None:
        """How late the single event loop runs a 50 ms timer: a CPU saturation signal."""
        while True:
            started = time.monotonic()
            await asyncio.sleep(0.05)
            self.recorder.add("event_loop_lag", time.monotonic() - started - 0.05)

    async def native_delay(self) -> None:
        if self.config.native_latency_ms:
            await asyncio.sleep(self.config.native_latency_ms / 1000)

    def connection_epoch(self) -> str:
        assert self.feed is not None and self.feed.index is not None
        return self.feed.index.require_live()

    def note_submit(self, native: SyntheticNative, text: str) -> None:
        match = HUMAN_MARKER.search(text)
        if match is None:
            return
        self.human_submitted[match.group(0)] += 1
        self.human_submit_order.setdefault(native.index, []).append(int(match.group(2)))
        sent = self.human_sent.get(match.group(0))
        if sent is not None:
            self.recorder.add("human_ingest_to_native_submit", time.monotonic() - sent)

    async def _sse_chunks(self) -> AsyncIterator[bytes]:
        while True:
            yield await self.sse.get()

    async def _events(
        self, operation: str, *, oversized_event_bytes: int | None = None
    ) -> AsyncIterator[Any]:
        # Same parser options as the real transport for an oversized frame.
        frames = (
            iter_sse(self._sse_chunks())
            if oversized_event_bytes is None
            else iter_sse(
                self._sse_chunks(), max_event_bytes=oversized_event_bytes, discard_oversized=True
            )
        )
        async for frame in frames:
            yield frame

    def _frame(self, raw: dict[str, Any]) -> None:
        self.sse.put_nowait(b"data: " + json.dumps(raw).encode() + b"\n\n")
        if self.emitting:  # The end-of-load flush of unfinished turns is not ingest lag.
            self.sse_peak = max(self.sse_peak, self.sse.qsize())

    async def build(self, database: DatabaseFactory | None = None) -> None:
        config = self.config
        if database is not None:
            self.db = await database(self.workdir / "perf.db")
        else:
            key = os.urandom(32)
            self.db = Database(
                "sqlite+aiosqlite:///" + str(self.workdir / "perf.db"),
                busy_timeout_ms=config.busy_timeout_ms,
                cipher=EnvelopeCipher({"perf": key}, "perf"),
            )
            await migrate(self.db.engine)
        assert await self.db.ready()
        self._attribute_database()
        directory = "/workspace/perf"
        refs = tuple(
            SessionRef(
                backend_id="backend",
                backend_identity="synthetic-installation",
                upstream_session_id=f"ses_perf{i:03d}",
                project_id="project",
                canonical_directory=directory,
            )
            for i in range(config.topics)
        )
        async with self.db.sessions.begin() as session:
            session.add(
                EnrolledBackend(
                    id="backend",
                    identity=refs[0].backend_identity,
                    contract_hash=INSTALLED_SCHEMA,
                    enabled=True,
                    verified=True,
                    version="synthetic-load",
                )
            )
            session.add(
                EnrolledProject(
                    id="project",
                    backend_id="backend",
                    realm_id="realm",
                    canonical_directory=directory,
                    enabled=True,
                )
            )
            for user in (HUMAN, 8):
                for role in ("operator", "approver", "administrator"):
                    session.add(
                        Grant(realm_id="realm", user_id=user, project_id="project", role=role)
                    )

        async def identity() -> bool:
            return True

        client = ZulipClient(
            URL,
            "bot@example.invalid",
            "synthetic-only-key",
            attestation=ZulipAttestation(
                URL,
                "realm",
                BOT,
                500,
                10000,
                60,
                verified_scope_operations=SCOPE_OPERATIONS,
                verified_event_operations=EVENT_OPERATIONS | {"cleanup"},
            ),
            verify_identity=identity,
            transport=httpx.MockTransport(self.zulip.handle),
        )
        # The production guard and bulk metadata path, so request counts are realistic.
        client.verify_identity = ZulipRuntimeIdentity(
            client,
            SimpleNamespace(
                bot_user_id=BOT,
                bot_owner_id=HUMAN,
                url=client.url,
                zulip_version="12.3",
                feature_level=500,
            ),
        )
        scope = ZulipScopeReader(client, channel_ids=frozenset({CHANNEL}), bulk_metadata=True)
        self._attribute_requests(client)
        self.store = DurableStore(self.db)
        self.lease = await self.store.acquire_lease("perf-envelope", ttl=120)
        assert self.lease
        fence = ConsumerFence("perf-envelope", self.lease)
        profile = OpenAPIProfile.from_file(PROFILE_PATH)

        async def owner_read() -> Any:
            return SimpleNamespace(owner_epoch=OWNER)

        owner = SimpleNamespace(
            enrollment=SimpleNamespace(
                backend_id="backend",
                backend_identity=refs[0].backend_identity,
                version="2.0.32",
                url=NATIVE_URL,
            ),
            read=owner_read,
        )
        transport = SimpleNamespace(
            profile=profile,
            client=SimpleNamespace(base_url=NATIVE_URL + "/"),
            events=self._events,
            attestation=ContractAttestation(
                profile.sha256,
                refs[0].backend_identity,
                "2.0.32",
                frozenset({"event.subscribe"}),
            ),
        )
        journal = TimedJournal(self.db, fence)
        journal.harness = self
        self.feed = V2PublicFeed(
            transport, owner, refs, receipts=journal, capture_text=config.drafts
        )
        texts = LiveTextCollector(self.db, fence, self.feed) if config.drafts else None
        entries = {}
        for index, ref in enumerate(refs):
            native = SyntheticNative(index, ref, self)
            self.natives.append(native)

            async def pending(selected: SessionRef, client: SyntheticNative = native) -> tuple:
                return tuple(client.requests)

            entries[ref] = RegisteredSession(
                ref,
                INSTALLED_SCHEMA,
                native,
                SyntheticCatalog(ref),
                SyntheticResults(native),
                pending,
                transcript=native,
                live_text=texts,
            )
        registry = SessionRegistry(entries)
        feed = self.feed

        async def pulse() -> None:
            # Same order as the production backend pulse, without owner recovery.
            await feed.current_owner()
            if texts is not None:
                await texts.collect()
            assert feed.index is not None
            while feed.index.pop() is not None:
                pass

        backend = RuntimeBackend(
            RegisteredBackend(
                refs[0].backend_identity, INSTALLED_SCHEMA, registry.projects, registry
            ),
            RegisteredCatalog(
                refs[0].backend_identity,
                INSTALLED_SCHEMA,
                registry.projects,
                SyntheticSessions(refs),
            ),
            registry.models,
            registry.results,
            refs,
            registry.pending,
            pulse,
            (RuntimeResource("native-feed", feed.start, feed.close),),
            transcripts=registry.transcripts,
            live_text=registry.live_text,
        )
        self.pipeline = ConsumerPipeline(
            self.db,
            fence,
            scope,
            {"backend": backend},
            max_global=max(config.active, 5),
            max_backend=max(config.active, 5),
            interval=config.interval,
            delivery_interval=config.delivery_interval,
            mirror_enabled=True,
            drafts_enabled=config.drafts,
            draft_interval=config.draft_interval,
        )
        for index, ref in enumerate(refs):
            topic = f"perf topic {index:03d}"
            self.binding_topics[index] = topic
            # A topic only resolves once the server has a message in it.
            self.zulip.message("Existing original topic", 1000 + index, HUMAN, topic)
            await self.pipeline.bindings.bind("realm", HUMAN, CHANNEL, topic, ref)
        self._frame(
            {"id": "evt_connection", "type": "server.connected", "created": 1.0, "data": {}}
        )

    async def warmup(self) -> float:
        """Wait for every baseline, then attach the budget under measurement."""
        assert self.db is not None and self.pipeline is not None
        started = time.monotonic()
        deadline = started + self.config.warmup_seconds
        quiet = 0
        while time.monotonic() < deadline:
            self.require_healthy()
            async with self.db.sessions() as session:
                pending = await session.scalar(
                    select(func.count()).select_from(Delivery).where(Delivery.state == "pending")
                )
                total = await session.scalar(select(func.count()).select_from(Delivery))
            quiet = quiet + 1 if not pending and (total or 0) >= self.config.topics else 0
            if quiet >= 3:
                break
            await asyncio.sleep(0.25)
        else:
            raise RuntimeError("synthetic_warmup_did_not_settle")
        self.budget = ZulipRequestBudget(
            requests=self.config.budget_requests,
            window=self.config.budget_window,
            reserved=self.config.budget_reserved,
        )
        self.pipeline.scope.client.budget = self.budget
        self.zulip.warm = True
        return time.monotonic() - started

    def require_healthy(self) -> None:
        if self.runtime is not None and not self.runtime.healthy:
            raise RuntimeError(
                "synthetic_runtime_failed " + str(self.runtime.failure_detail or "unknown")
            )

    def _emit_text(self, turn: Turn, kind: str) -> None:
        seq = self.seq
        self.seq += 1
        self.zulip.emit_time.append(time.monotonic())
        ref = turn.native.ref
        data: dict[str, Any] = {
            "sessionID": ref.upstream_session_id,
            "assistantMessageID": turn.assistant,
            "ordinal": 0,
        }
        raw: dict[str, Any] = {
            "id": f"evt_perf_{seq}",
            "created": int(time.time() * 1000),
            "type": "session.text." + kind,
            "location": {"directory": ref.canonical_directory},
            "data": data,
        }
        if kind == "delta":
            prefix = f"S{seq}. "
            piece = prefix + "x" * max(0, self.config.delta_bytes - len(prefix) - 1) + " "
            data["delta"] = piece
            turn.text.append(piece)
        else:
            raw["durable"] = {"aggregateID": ref.upstream_session_id, "seq": seq + 1}
            if kind == "ended":
                data["text"] = "".join(turn.text)
        self._frame(raw)

    def _next_turn(self, cursor: list[int], busy: set[int]) -> Turn:
        for native in self.natives:
            if native.pending_human and native.index not in busy:
                user_id, text = native.pending_human.popleft()
                return self._start(native, user_id, text)
        count = len(self.natives)
        for _ in range(count):
            native = self.natives[cursor[0] % count]
            cursor[0] += 1
            if native.index not in busy:
                number = native.turn_number + 1
                text = f"Computer input PERF-C:t{native.index}:n{number}"
                user_id = f"msg_u{native.index:03d}_n{number:05d}"
                return self._start(native, user_id, text)
        raise RuntimeError("synthetic_active_exceeds_topics")

    def _start(self, native: SyntheticNative, user_id: str, text: str) -> Turn:
        assistant, identity = native.begin_turn(user_id, text)
        return Turn(
            native,
            native.turn_number,
            assistant,
            identity,
            user_id,
            self.config.events_per_turn,
        )

    async def emit(self) -> None:
        config = self.config
        cursor = [0]
        busy: set[int] = set()
        turns: list[Turn] = []
        for _ in range(config.active):
            turn = self._next_turn(cursor, busy)
            busy.add(turn.native.index)
            turns.append(turn)
        self.emit_started = time.monotonic()
        self.emitting = True
        end = self.emit_started + config.duration
        slot = 0
        loop_at = self.emit_started
        while (now := time.monotonic()) < end:
            self.emit_ended = now  # Stays accurate when a runtime failure ends the load early.
            self.require_healthy()
            self.emitter_late_peak = max(self.emitter_late_peak, now - loop_at)
            target = int((now - self.emit_started) * config.rate)
            while self.emitted < target:
                position = slot % len(turns)
                turn = turns[position]
                slot += 1
                self._step(turn)
                self.emitted += 1
                if turn.remaining <= 0:
                    self._finish(turn)
                    busy.discard(turn.native.index)
                    replacement = self._next_turn(cursor, busy)
                    busy.add(replacement.native.index)
                    turns[position] = replacement
            loop_at = time.monotonic() + 0.01
            await asyncio.sleep(0.01)
        self.emit_ended = time.monotonic()
        self.emitting = False
        for turn in turns:
            # Finish, never abandon, in-flight work so finals remain checkable.
            while turn.remaining > 0:
                self._step(turn)
                self.emitted += 1
            self._finish(turn)

    def _step(self, turn: Turn) -> None:
        if not turn.started:
            self._emit_text(turn, "started")
            turn.started = True
        elif turn.remaining == 1:
            self._emit_text(turn, "ended")
        else:
            self._emit_text(turn, "delta")
        turn.remaining -= 1

    def _finish(self, turn: Turn) -> None:
        native = turn.native
        marker = f"PERF-FINAL:t{native.index}:n{turn.number}"
        text = "".join(turn.text) + "\n\n" + marker
        native.finish_turn(turn.assistant, turn.identity, text, turn.user_id)
        self.finished_turns[(native.index, turn.number)] = time.monotonic()

    async def humans(self) -> None:
        rate = self.config.human_per_minute
        if rate <= 0:
            return
        number = 0
        delay = 60 / rate
        await asyncio.sleep(delay / 2)
        while self.emitting:
            native = self.natives[number % len(self.natives)]
            marker = f"PERF-H:t{native.index}:h{number}"
            self.human_sent[marker] = time.monotonic()
            self.zulip.input("Task " + marker, self.binding_topics[native.index])
            number += 1
            await asyncio.sleep(delay)

    async def interactions(self) -> None:
        rate = self.config.interactions_per_minute
        if rate <= 0:
            return
        delay = 60 / rate
        await asyncio.sleep(delay / 3)
        number = 0
        while self.emitting:
            running = [n for n in self.natives if n.state == ExecutionState.RUNNING]
            if running:
                native = running[number % len(running)]
                request = f"per_perf{number:06d}"
                native.requests[request] = InteractionSnapshot(
                    reference=native.ref,
                    upstream_request_id=request,
                    generation="synthetic-generation",
                    kind="permission",
                    pending=True,
                    description=PERMISSION_DESCRIPTION,
                    operation="bash",
                )
                self.interaction_count += 1
                topic = self.binding_topics[native.index]
                sent = self.interactions_sent.setdefault(topic, [])
                sent.append(time.monotonic())
                self.open_requests.append((native, request, topic, len(sent)))
            number += 1
            await asyncio.sleep(delay)

    def _resolve_announced_requests(self) -> None:
        """A synthetic actor answers a request only after its notice really arrived."""
        remaining = []
        for item in self.open_requests:
            native, request, topic, ordinal = item
            if len(self.zulip.notice_times.get(topic, ())) >= ordinal:
                native.requests.pop(request, None)
            else:
                remaining.append(item)
        self.open_requests = remaining

    async def sampler(self) -> None:
        self.sample_started = time.monotonic()
        while True:
            await self._sample()
            await asyncio.sleep(self.config.sample_seconds)

    async def _sample(self) -> None:
        assert self.db is not None and self.feed is not None
        self._resolve_announced_requests()
        async with self.db.sessions() as session:
            rows = await session.execute(
                select(Delivery.priority, func.count())
                .where(Delivery.state == "pending")
                .group_by(Delivery.priority)
            )
            pending = {int(priority): int(count) for priority, count in rows.all()}
            action_rows = await session.execute(
                select(Action.state, func.count()).group_by(Action.state)
            )
            actions = {str(state): int(count) for state, count in action_rows.all()}
            receipts = await session.scalar(select(func.count()).select_from(NativeFeedReceipt))
            captures = await session.scalar(select(func.count()).select_from(NativeLiveCapture))
        now = time.monotonic()
        cpu = time.process_time()
        elapsed = max(now - self.cpu_mark[0], 1e-9)
        cpu_percent = (cpu - self.cpu_mark[1]) / elapsed * 100
        self.cpu_mark = (now, cpu)
        self.samples.append(
            {
                "t": round(now - self.sample_started, 2),
                "rss_mib": round(current_rss_mib(), 2),
                "cpu_percent": round(cpu_percent, 1),
                "sse_backlog": self.sse.qsize(),
                "feed_buffer_peak_bytes": self.feed.buffer_peak_bytes,
                "deliveries_pending_by_priority": pending,
                "actions": actions,
                "feed_receipts": receipts,
                "live_captures": captures,
                "db_bytes": db_bytes(self.workdir),
                "finals_finished": len(self.finished_turns),
                "finals_delivered": sum(
                    1 for key in self.finished_turns if key in self.zulip.finals
                ),
                "budget_retained": self.budget.retained_requests if self.budget else None,
                "budget_deferred": self.budget.deferred if self.budget else None,
                "emitted": self.emitted,
            }
        )

    def _finish_late_human_turns(self) -> None:
        """A prompt admitted after emission ended still gets its one complete turn."""
        for native in self.natives:
            while native.pending_human and native.state != ExecutionState.IDLE:
                user_id, text = native.pending_human.popleft()
                turn = self._start(native, user_id, text)
                turn.remaining = min(turn.remaining, 8)
                while turn.remaining > 0:
                    self._step(turn)
                    self.emitted += 1
                self._finish(turn)

    async def drain(self) -> tuple[float, bool]:
        assert self.db is not None
        started = time.monotonic()
        deadline = started + self.config.drain_seconds
        quiet = 0
        while time.monotonic() < deadline:
            self.require_healthy()
            self._finish_late_human_turns()
            self._resolve_announced_requests()
            missing = [key for key in self.finished_turns if key not in self.zulip.finals]
            unsent = [m for m in self.human_sent if m not in self.human_submitted]
            async with self.db.sessions() as session:
                pending = await session.scalar(
                    select(func.count()).select_from(Delivery).where(Delivery.state == "pending")
                )
                queued = await session.scalar(
                    select(func.count())
                    .select_from(Action)
                    .where(Action.state.in_(["queued", "admitted", "running"]))
                )
            settled = not unsent and not pending and not queued
            # A fault-injected drop can never appear, so it must not hold the drain open.
            quiet = quiet + 1 if settled and len(missing) <= len(self.zulip.dropped) else 0
            if quiet >= 3:
                return time.monotonic() - started, True
            await asyncio.sleep(0.5)
        return time.monotonic() - started, False

    async def collect(self) -> dict[str, Any]:
        assert self.db is not None
        rec = self.recorder
        async with self.db.sessions() as session:
            actions = list(
                (await session.execute(select(Action.created_at, Action.payload, Action.state)))
                .tuples()
                .all()
            )
            deliveries = list(
                (
                    await session.execute(
                        select(
                            Delivery.priority,
                            Delivery.created_at,
                            Delivery.updated_at,
                            Delivery.state,
                            Delivery.posted_message_id,
                        )
                    )
                )
                .tuples()
                .all()
            )
        wall_minus_mono = time.time() - time.monotonic()
        for created, payload, _state in actions:
            match = HUMAN_MARKER.search((payload or {}).get("text", "") or "")
            if match and match.group(0) in self.human_sent:
                sent = self.human_sent[match.group(0)] + wall_minus_mono
                rec.add("human_ingest_to_queued", created - sent)
        delivered_rows = [row for row in deliveries if row[3] == "delivered"]
        created_by_mid = {}
        for priority, created, updated, _state, mid in delivered_rows:
            label = lane_label(priority)
            rec.add("published_to_delivered:" + label, updated - created)
            if mid is not None:
                created_by_mid.setdefault(mid, created - wall_minus_mono)
        for key, marks in self.zulip.finals.items():
            final_at = self.finished_turns.get(key)
            if final_at is None:
                continue
            first = marks[0]
            rec.add("native_final_to_delivered", first[0] - final_at)
            published = created_by_mid.get(first[1])
            if published is not None:
                rec.add("native_final_to_published", published - final_at)
        for topic, times in self.interactions_sent.items():
            seen = list(self.zulip.notice_times.get(topic, ()))
            for at in times:
                position = bisect_right(seen, at)
                if position < len(seen):
                    rec.add("interaction_to_notice_delivered", seen.pop(position) - at)
        return {
            "inversions": priority_inversions(delivered_rows),
            "delivery_states": dict(Counter(row[3] for row in deliveries)),
            "actions": dict(Counter(row[2] for row in actions)),
        }


def lane_label(priority: int) -> str:
    if priority <= 10:
        return "interaction"
    if priority >= 200:
        return "draft"
    if priority <= 100:
        return "final_or_normal"
    return "normal"


def priority_inversions(rows: list[Any]) -> dict[str, int]:
    """A lower-priority row both created after and delivered before an interaction."""
    interactions = [row for row in rows if row[0] <= 10]
    others = sorted((row for row in rows if row[0] > 10), key=lambda row: row[1])
    inversions = overtaken = 0
    for priority, created, updated, *_ in interactions:
        for other in others:
            if other[0] <= priority:
                continue
            if other[1] > created and other[2] < updated:
                inversions += 1
            if other[1] < created and other[2] > updated:
                overtaken += 1
    return {"interactions": len(interactions), "inversions": inversions, "overtaken": overtaken}


def current_rss_mib() -> float:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    return 0.0


def peak_rss_mib() -> float:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) / 1024
    return 0.0


def db_bytes(workdir: Path) -> int:
    return sum(path.stat().st_size for path in workdir.glob("perf.db*"))


def hardware() -> dict[str, Any]:
    model, flags = "unknown", ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name") and model == "unknown":
                model = line.split(":", 1)[1].strip()
            if line.startswith("flags") and not flags:
                flags = line
    except OSError:
        pass
    total = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            total = int(line.split()[1]) // 1024
    return {
        "cpu_model": model,
        "logical_cpus": os.cpu_count(),
        "avx": " avx " in flags + " ",
        "memory_mib": total,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "load_average_at_end": os.getloadavg(),
    }


def rss_slope(samples: list[dict[str, Any]]) -> float | None:
    """MiB per minute over the later half; None when too short to mean anything."""
    if len(samples) < 8 or samples[-1]["t"] - samples[0]["t"] < 120:
        return None
    later = samples[len(samples) // 2 :]
    xs = [row["t"] / 60 for row in later]
    ys = [row["rss_mib"] for row in later]
    mean_x, mean_y = sum(xs) / len(xs), sum(ys) / len(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if not denominator:
        return None
    return sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / denominator


def strictly_increasing(values: list[int]) -> bool:
    return all(a < b for a, b in zip(values, values[1:], strict=False))


def evaluate(report: dict[str, Any], config: Config) -> dict[str, dict[str, Any]]:
    """Pure PASS/FAIL over the measured report; each check can really fail."""
    observed = report["observed"]
    checks: dict[str, dict[str, Any]] = {}

    def check(name: str, passed: bool | None, **detail: Any) -> None:
        checks[name] = {"status": "NOT_EVALUATED" if passed is None else _word(passed), **detail}

    finals = observed["finals"]
    check(
        "no_message_lost",
        not finals["missing"] and not observed["human"]["never_submitted"],
        missing_finals=finals["missing"][:20],
        missing_final_count=len(finals["missing"]),
        drain_complete=observed["drain_complete"],
        note=None
        if observed["drain_complete"]
        else "Drain deadline passed: an entry may be late rather than permanently lost.",
        never_submitted=observed["human"]["never_submitted"][:20],
        finished_turns=finals["finished"],
    )
    check(
        "no_duplicates",
        not finals["duplicates"] and not observed["human"]["duplicate_submits"],
        duplicate_finals=finals["duplicates"][:20],
        duplicate_native_submits=observed["human"]["duplicate_submits"][:20],
    )
    check(
        "order_preserved_within_topic",
        not finals["out_of_order_topics"]
        and not observed["human"]["out_of_order_topics"]
        and observed["draft_regressions"] == 0,
        final_out_of_order_topics=finals["out_of_order_topics"],
        human_out_of_order_topics=observed["human"]["out_of_order_topics"],
        draft_regressions=observed["draft_regressions"],
    )
    memory = observed["memory"]
    slope = memory["slope_mib_per_minute_later_half"]
    check(
        "memory_bounded",
        memory["peak_rss_mib"] <= config.max_rss_mib
        and (slope is None or slope <= config.max_rss_growth_mib_per_minute),
        peak_rss_mib=memory["peak_rss_mib"],
        limit_mib=config.max_rss_mib,
        slope_mib_per_minute=slope,
        slope_limit=config.max_rss_growth_mib_per_minute,
        slope_evaluated=slope is not None,
    )
    budget = observed["budget"]
    check(
        "budget_honoured",
        budget["server_peak_requests_in_window"] <= config.budget_requests + config.budget_tolerance
        and budget["requests_during_429_cooldown"] == 0,
        peak_requests_in_window=budget["server_peak_requests_in_window"],
        limit=config.budget_requests,
        tolerance=config.budget_tolerance,
        requests_during_429_cooldown=budget["requests_during_429_cooldown"],
    )
    interactions = observed["interactions"]
    latency = interactions["latency"]
    p95 = latency.get("p95")
    inversions = interactions["priority"]["inversions"]
    check(
        "interactions_prioritised",
        interactions["undelivered"] == 0
        and inversions == 0
        and (p95 is None or p95 <= config.interaction_p95_limit_seconds),
        injected=interactions["injected"],
        undelivered=interactions["undelivered"],
        inversions=inversions,
        overtook_older_lower_priority=interactions["priority"]["overtaken"],
        p95_seconds=p95,
        p95_limit_seconds=config.interaction_p95_limit_seconds,
    )
    load = observed["load"]
    check(
        "load_offered",
        load["achieved_events_per_second"] >= config.rate * config.load_tolerance
        and load["sse_backlog_peak"] < config.rate * 30,
        achieved_events_per_second=load["achieved_events_per_second"],
        target=config.rate,
        sse_backlog_peak=load["sse_backlog_peak"],
    )
    check(
        "runtime_healthy",
        observed["runtime_healthy"],
        failure=observed["runtime_failure"],
    )
    return checks


def _word(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def targets(
    summary: dict[str, dict[str, Any]], peak_rss: float, idle_rss: float | None
) -> dict[str, Any]:
    """The project's targets (docs/PERFORMANCE.md) side by side. Synthetic peers only."""

    def p95(name: str) -> Any:
        return summary.get(name, {}).get("p95")

    def met(value: Any, limit: float) -> bool | None:
        return None if value is None else value < limit

    durable = p95("human_ingest_to_queued")
    draft = p95("native_event_to_draft_display")
    final = p95("native_final_to_delivered")
    return {
        "note": (
            "The targets exclude upstream throttling; these synthetic values include "
            "any local budget deferral. Not a verdict on the real system."
        ),
        "local_authorization_durable_ack_p95_below_1s": {
            "measured_p95": durable,
            "met": met(durable, 1),
        },
        "event_to_display_scheduling_p95_below_2s_drafts": {
            "measured_p95": draft,
            "met": met(draft, 2),
        },
        "event_to_display_scheduling_p95_below_2s_finals": {
            "measured_p95": final,
            "met": met(final, 2),
        },
        "idle_rss_below_300_mib": {
            "measured_first_sample_mib": idle_rss,
            "met": met(idle_rss, 300),
        },
        "steady_rss_below_750_mib": {"measured_peak_mib": peak_rss, "met": peak_rss < 750},
    }


def build_report(harness: Harness, config: Config, phases: dict[str, Any]) -> dict[str, Any]:
    zulip = harness.zulip
    missing = sorted(
        f"t{key[0]}:n{key[1]}" for key in harness.finished_turns if key not in zulip.finals
    )
    # A closed draft preview may legitimately repeat the final text as an edit, so
    # it is counted apart; a duplicate is more than one separately posted final.
    duplicates = sorted(
        f"t{key[0]}:n{key[1]}"
        for key, marks in zulip.finals.items()
        if len({mark[1] for mark in marks if mark[2] == "post"}) > 1
    )
    closed_drafts = sum(
        1 for marks in zulip.finals.values() if any(mark[2] == "edit" for mark in marks)
    )
    out_of_order = sorted(
        topic for topic, seen in zulip.final_order.items() if not strictly_increasing(seen)
    )
    human_out = sorted(
        topic for topic, seen in harness.human_submit_order.items() if not strictly_increasing(seen)
    )
    summary = harness.recorder.summary()
    interaction_latency = summary.get("interaction_to_notice_delivered", {"count": 0})
    delivered = interaction_latency.get("count", 0)
    # Only events inside the measured emission window define achieved load.
    seconds = max(harness.emit_ended - harness.emit_started, 1e-9)
    in_window = int(seconds * config.rate)
    peak = peak_rss_mib()
    samples = harness.samples
    largest_pending = max(
        (sum(row["deliveries_pending_by_priority"].values()) for row in samples), default=0
    )
    budget = harness.budget
    pipeline = harness.pipeline
    total_requests = sum(zulip.routes.values())
    messages_written = zulip.routes["POST messages"] + zulip.routes["PATCH messages/N"]
    observed = {
        "load": {
            "topics": config.topics,
            "active_sessions": config.active,
            "target_events_per_second": config.rate,
            "emission_seconds": round(seconds, 2),
            "events_emitted_total": harness.emitted,
            "achieved_events_per_second": round(min(harness.emitted, in_window) / seconds, 2),
            "emitter_late_peak_seconds": round(harness.emitter_late_peak, 3),
            "sse_backlog_peak": harness.sse_peak,
            "feed_buffer_peak_bytes": harness.feed.buffer_peak_bytes if harness.feed else 0,
            "payload": {
                "delta_bytes": config.delta_bytes,
                "events_per_turn": config.events_per_turn,
                "final_text_bytes_approx": config.delta_bytes * config.events_per_turn,
            },
        },
        "finals": {
            "finished": len(harness.finished_turns),
            "delivered": sum(1 for key in harness.finished_turns if key in zulip.finals),
            "missing": missing,
            "duplicates": duplicates,
            "out_of_order_topics": out_of_order,
            "closed_draft_edits_repeating_final_text": closed_drafts,
        },
        "human": {
            "sent": len(harness.human_sent),
            "submitted": sum(harness.human_submitted.values()),
            "never_submitted": sorted(
                m for m in harness.human_sent if m not in harness.human_submitted
            ),
            "duplicate_submits": sorted(m for m, n in harness.human_submitted.items() if n > 1),
            "out_of_order_topics": human_out,
        },
        "interactions": {
            "injected": harness.interaction_count,
            "undelivered": max(0, harness.interaction_count - delivered),
            "notices_posted": sum(zulip.notices.values()),
            "latency": interaction_latency,
            "priority": phases["collected"]["inversions"],
        },
        "draft_regressions": zulip.draft_regressions,
        "memory": {
            "peak_rss_mib": round(peak, 2),
            "first_sample_rss_mib": samples[0]["rss_mib"] if samples else None,
            "last_sample_rss_mib": samples[-1]["rss_mib"] if samples else None,
            "slope_mib_per_minute_later_half": _round(rss_slope(samples)),
            "includes_synthetic_peers_in_same_process": True,
        },
        "queues": {
            "largest_pending_deliveries": largest_pending,
            "largest_sse_backlog": harness.sse_peak,
            "final_delivery_states": phases["collected"]["delivery_states"],
            "final_action_states": phases["collected"]["actions"],
            "db_bytes_at_end": db_bytes(harness.workdir),
            "feed_receipts_at_end": samples[-1]["feed_receipts"] if samples else None,
            "live_captures_at_end": samples[-1]["live_captures"] if samples else None,
        },
        "budget": {
            "limit": config.budget_requests,
            "window_seconds": config.budget_window,
            "reserved": config.budget_reserved,
            "local_deferrals": budget.deferred if budget else None,
            "local_rate_limit_events": budget.rate_limits if budget else None,
            "server_peak_requests_in_window": zulip.peak_requests_in_window,
            "responses_429_injected": zulip.responses_429,
            "requests_during_429_cooldown": zulip.during_cooldown,
            "pipeline_deferred_by_category": dict(pipeline.deferred) if pipeline else {},
        },
        "wire": {
            "route_counts": dict(zulip.routes.most_common()),
            "bytes_sent_to_zulip": zulip.wire_bytes,
            "requests_total": total_requests,
            "requests_by_worker": dict(harness.requests_by_worker.most_common()),
            "messages_written": messages_written,
            "requests_per_written_message": round(total_requests / max(messages_written, 1), 1),
        },
        "cpu": {
            "percent_of_one_core_mean": round(
                sum(row["cpu_percent"] for row in samples) / max(len(samples), 1), 1
            ),
            "percent_of_one_core_peak": max((row["cpu_percent"] for row in samples), default=0),
            "lease_renewals_refused": harness.lease_renewals_refused,
        },
        "database_errors": dict(harness.database_errors.most_common()),
        "runtime_healthy": bool(harness.runtime and harness.runtime.healthy),
        "runtime_failure": str(harness.runtime.failure_detail)
        if harness.runtime and harness.runtime.failure_detail
        else None,
        "drain_seconds": round(phases["drain"], 2),
        "drain_complete": phases["drain_complete"],
        "warmup_seconds": round(phases["warmup"], 2),
    }
    report: dict[str, Any] = {
        "evidence_class": "synthetic",
        "label": SYNTHETIC_LABEL,
        "real_zulip": False,
        "real_native": False,
        "acceptance_status_changed": False,
        "load_acceptance": "not run",
        "database": "SQLite via aiosqlite, encrypted columns, local disk",
        "hardware": hardware(),
        "config": asdict(config),
        "latency_seconds": summary,
        "observed": observed,
        "samples": samples,
    }
    report["targets_side_by_side"] = targets(
        summary, round(peak, 2), samples[0]["rss_mib"] if samples else None
    )
    report["checks"] = evaluate(report, config)
    report["passed"] = all(row["status"] != "FAIL" for row in report["checks"].values())
    return report


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


async def run(config: Config, *, database: DatabaseFactory | None = None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="jt-oz-perf-", dir=config.workdir) as name:
        harness = Harness(config, Path(name))
        await harness.build(database)
        assert harness.pipeline is not None and harness.db is not None
        harness.runtime = harness.pipeline.runtime()
        await harness.runtime.start()
        sampler = None
        support: list[asyncio.Task[None]] = []
        failure = None
        phases: dict[str, Any] = {"warmup": 0.0, "drain": 0.0, "drain_complete": False}
        try:
            phases["warmup"] = await harness.warmup()
            harness.cpu_mark = (time.monotonic(), time.process_time())
            sampler = asyncio.create_task(harness.sampler())
            support = [
                asyncio.create_task(harness.loop_probe()),
                asyncio.create_task(harness.heartbeat()),
            ]
            harness.emitting = True
            workers = [
                asyncio.create_task(harness.humans()),
                asyncio.create_task(harness.interactions()),
            ]
            try:
                await harness.emit()
            finally:
                harness.emitting = False
                await asyncio.gather(*workers, return_exceptions=True)
            phases["drain"], phases["drain_complete"] = await harness.drain()
        except RuntimeError as error:
            failure = str(error)
        finally:
            if sampler is not None:
                support.append(sampler)
            for task in support:
                task.cancel()
            await asyncio.gather(*support, return_exceptions=True)
            await harness._sample()
            phases["collected"] = await harness.collect()
            report = build_report(harness, config, phases)
            report["harness_failure"] = failure
            if failure is not None:
                report["passed"] = False
            await harness.runtime.close()
            await harness.db.close()
        return report


def parse(argv: list[str] | None = None) -> tuple[Config, Path | None]:
    defaults = Config()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--no-drafts", action="store_true")
    for item in (
        "duration",
        "rate",
        "budget_window",
        "human_per_minute",
        "interactions_per_minute",
        "retry_after",
        "zulip_latency_ms",
        "native_latency_ms",
        "interval",
        "delivery_interval",
        "draft_interval",
        "drain_seconds",
        "warmup_seconds",
        "sample_seconds",
        "max_rss_mib",
        "max_rss_growth_mib_per_minute",
        "interaction_p95_limit_seconds",
    ):
        parser.add_argument(
            "--" + item.replace("_", "-"), type=float, default=getattr(defaults, item)
        )
    for item in (
        "topics",
        "active",
        "events_per_turn",
        "delta_bytes",
        "budget_requests",
        "budget_reserved",
        "busy_timeout_ms",
        "inject_429_every",
    ):
        parser.add_argument(
            "--" + item.replace("_", "-"), type=int, default=getattr(defaults, item)
        )
    parser.add_argument("--workdir", default=None)
    values = vars(parser.parse_args(argv))
    output = values.pop("output")
    values["drafts"] = not values.pop("no_drafts")
    return Config(**values), output


def main(argv: list[str] | None = None) -> int:
    config, output = parse(argv)
    print(SYNTHETIC_LABEL, file=sys.stderr, flush=True)
    report = asyncio.run(run(config))
    text = json.dumps(report, indent=2, sort_keys=True, default=str)
    if output is not None:
        output.write_text(text + "\n")
    else:
        print(text)
    brief = {
        "passed": report["passed"],
        "checks": {name: row["status"] for name, row in report["checks"].items()},
    }
    print(json.dumps(brief, sort_keys=True), file=sys.stderr, flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
