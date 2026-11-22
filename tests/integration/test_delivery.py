import asyncio
import time

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.delivery import (
    DeliveryRateLimited,
    DeliveryRejected,
    PostedMessage,
    with_marker,
    without_marker,
)
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Delivery, DeliveryLane, Grant, WorkerLease
from tests.support import bound


class SyntheticChat:
    """Isolated gateway double, not actual Zulip compatibility evidence."""

    realm_id, bot_user_id, writes_enabled = "realm", 77, True

    def __init__(self):
        self.messages, self.calls, self.mode = {}, [], "success"
        self.widgets = []
        self.entered = asyncio.Event()

    async def send(self, channel, topic, content, marker, *, widget=None):
        self.calls.append(("send", content))
        self.widgets.append(widget)
        self.entered.set()
        if self.mode == "rate":
            raise DeliveryRateLimited(30)
        if self.mode == "reject":
            raise DeliveryRejected("proven fixture rejection")
        message_id = len(self.messages) + 1000
        self.messages[message_id] = PostedMessage(
            realm_id=self.realm_id,
            id=message_id,
            channel_id=channel,
            topic=topic,
            sender_id=self.bot_user_id,
            content=content,
        )
        if self.mode == "timeout":
            raise TimeoutError("fixture accepted with lost response")
        if self.mode == "wait":
            await asyncio.Event().wait()
        return message_id

    async def edit(self, message_id, content):
        self.calls.append(("edit", content))
        self.messages[message_id] = self.messages[message_id].model_copy(
            update={"content": content}
        )
        if self.mode == "timeout":
            raise TimeoutError("fixture edited with lost response")

    async def get(self, message_id):
        return self.messages[message_id]

    async def find(self, channel, topic, marker):
        return tuple(item for item in self.messages.values() if marker in item.content)


async def worker(db):
    bindings, binding, _, _ = await bound(db)
    fence = await DurableStore(db).acquire_lease("delivery-test")
    chat = SyntheticChat()
    outbox = Outbox(bindings, chat.bot_user_id)
    return DeliveryWorker(outbox, chat, "delivery-test", fence, minimum_interval=0), binding, chat


async def test_one_post_for_concurrent_workers_and_same_source_content(db):
    sender, binding, chat = await worker(db)
    ids = await asyncio.gather(
        *[sender.outbox.queue("source-event", binding.id, 1, "Exact output") for _ in range(5)]
    )
    assert len(set(ids)) == 1
    await asyncio.gather(*[sender.advance(ids[0]) for _ in range(5)])
    assert len(chat.calls) == 1
    saved = await sender.outbox.load(ids[0])
    assert saved.state == "delivered" and saved.attempts == 1 and saved.posted_message_id == 1000
    assert chat.messages[1000].content == with_marker("Exact output", "jtoz:" + saved.id)
    with pytest.raises(Conflict):
        await sender.outbox.queue("source-event", binding.id, 1, "Different output")


async def test_lost_post_response_reconciles_exact_bot_target_content_without_resending(db):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("source", binding.id, 1, "Exact output")
    chat.mode = "timeout"
    assert await sender.advance(identity) == "ambiguous"
    assert await sender.advance(identity) == "ambiguous"
    assert await sender.reconcile(identity) == "delivered"
    assert len(chat.calls) == 1


@pytest.mark.parametrize(
    "change", ["sender", "topic", "realm", "channel", "content", "absent", "duplicate"]
)
async def test_marker_alone_or_history_absence_never_proves_delivery(db, change):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("source", binding.id, 1, "Exact output")
    chat.mode = "timeout"
    await sender.advance(identity)
    message = chat.messages[1000]
    if change == "absent":
        chat.messages.clear()
    elif change == "duplicate":
        chat.messages[1001] = message.model_copy(update={"id": 1001})
    else:
        fields = {
            "sender": {"sender_id": 88},
            "topic": {"topic": "other"},
            "realm": {"realm_id": "other"},
            "channel": {"channel_id": 99},
            "content": {"content": "Forged " + message.content},
        }
        chat.messages[1000] = message.model_copy(update=fields[change])
    assert await sender.reconcile(identity) == "ambiguous"
    assert len(chat.calls) == 1
    with pytest.raises(Conflict):
        await sender.outbox.resume(
            identity, "realm", 7, (await sender.outbox.load(identity)).version
        )


async def test_priority_reserves_next_slot_for_interactions_and_429_defers_the_realm(db):
    sender, binding, chat = await worker(db)
    draft = await sender.outbox.queue("draft", binding.id, 1, "Draft", priority=100)
    control = await sender.outbox.queue("permission", binding.id, 1, "Permission", priority=0)
    assert await sender.advance(draft) == "pending" and not chat.calls
    chat.mode = "rate"
    assert await sender.advance(control) == "pending"
    assert await sender.advance(draft) == "pending"
    assert len(chat.calls) == 1
    async with db.sessions() as session:
        assert (await session.get(DeliveryLane, "realm")).not_before > time.time()
        assert (await session.get(Delivery, control)).retry_at > time.time()
    async with db.sessions.begin() as session:
        await session.execute(update(DeliveryLane).values(not_before=0, backoff=0))
        await session.execute(update(Delivery).values(retry_at=0))
    chat.mode = "success"
    assert await sender.advance(control) == "delivered"
    assert await sender.advance(draft) == "delivered"


@pytest.mark.parametrize("revoked", [False, True])
async def test_scope_query_429_defers_before_any_send_and_rechecks_acl_after_cooldown(db, revoked):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("scope-rate", binding.id, 1, "Scoped output")
    other = await sender.outbox.queue("other", binding.id, 1, "Other output")
    audience = sender.outbox.bindings.audience
    inspect = audience.inspect
    calls = 0

    async def limited(*args):
        nonlocal calls
        calls += 1
        raise DeliveryRateLimited(30)

    audience.inspect = limited
    assert await sender.advance(identity) == "pending"
    saved = await sender.outbox.load(identity)
    assert saved.status_reason == "scope_rate_limited" and saved.attempts == 0
    assert saved.retry_at > time.time() and not chat.calls
    assert await sender.advance(identity) == await sender.advance(other) == "pending"
    assert calls == 1  # Cooldown schedules work; it is not a cached ACL witness.
    audience.inspect = inspect
    audience.private = not revoked
    async with db.sessions.begin() as session:
        await session.execute(update(DeliveryLane).values(not_before=0, backoff=0))
        await session.execute(update(Delivery).values(retry_at=0))
    assert await sender.advance(identity) == ("held" if revoked else "delivered")
    assert len(chat.calls) == (0 if revoked else 1)


async def test_edit_source_read_429_has_no_mutation_attempt_and_revalidates_original_content(db):
    sender, binding, chat = await worker(db)
    original = await sender.outbox.queue("initial", binding.id, 1, "Initial")
    assert await sender.advance(original) == "delivered"
    edit = await sender.outbox.queue("edit", binding.id, 1, "Updated", edit_of=original)
    get = chat.get

    async def limited(*args):
        raise DeliveryRateLimited(30)

    chat.get = limited
    assert await sender.advance(edit) == "pending"
    assert len(chat.calls) == 1 and (await sender.outbox.load(edit)).attempts == 0
    chat.get = get
    async with db.sessions.begin() as session:
        await session.execute(update(DeliveryLane).values(not_before=0, backoff=0))
        await session.execute(update(Delivery).values(retry_at=0))
    assert await sender.advance(edit) == "delivered"
    assert [kind for kind, _ in chat.calls] == ["send", "edit"]


async def test_cancellation_after_post_preserves_ambiguity_and_can_reconcile(db):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("source", binding.id, 1, "Output")
    chat.mode = "wait"
    task = asyncio.create_task(sender.advance(identity))
    await asyncio.wait_for(chat.entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await sender.outbox.load(identity)).state == "ambiguous"
    assert await sender.reconcile(identity) == "delivered"


async def test_stale_lease_move_or_changed_audience_cannot_send(db):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("source", binding.id, 1, "Output")
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
    assert await sender.advance(identity) == "pending" and not chat.calls
    fence = await DurableStore(db).acquire_lease(sender.holder)
    sender.fencing = fence
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(revision=2, topic="New audience"))
    assert await sender.advance(identity) == "held" and not chat.calls


async def test_edit_requires_original_bot_content_and_ambiguous_edit_is_read_only_reconciled(db):
    sender, binding, chat = await worker(db)
    original = await sender.outbox.queue("draft1", binding.id, 1, "Draft")
    await sender.advance(original)
    edit = await sender.outbox.queue("draft2", binding.id, 1, "Updated draft", edit_of=original)
    chat.mode = "timeout"
    assert await sender.advance(edit) == "ambiguous"
    assert await sender.reconcile(edit) == "delivered"
    stale = await sender.outbox.queue("stale", binding.id, 1, "Stale overwrite", edit_of=original)
    assert await sender.advance(stale) == "held"
    assert [item[0] for item in chat.calls] == ["send", "edit"]


async def test_restart_holds_unsent_output_and_manual_resume_requires_current_revision(db):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("source", binding.id, 1, "Output")
    await DurableStore(db).recover()
    saved = await sender.outbox.load(identity)
    assert saved.state == "held"
    with pytest.raises(Conflict):
        await sender.outbox.resume(identity, "realm", 7, saved.version - 1)
    await sender.outbox.resume(identity, "realm", 7, saved.version)
    assert await sender.advance(identity) == "delivered"
    async with db.sessions() as session:
        assert len((await session.scalars(select(Delivery))).all()) == 1


@pytest.mark.parametrize("revocation", ["viewer", "backend", "project"])
async def test_output_claim_rechecks_revocation_after_preflight(db, revocation):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("source", binding.id, 1, "Output")
    saved = await sender.outbox.load(identity)
    payload = await sender.payload(saved)
    async with db.sessions.begin() as session:
        if revocation == "viewer":
            await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        elif revocation == "backend":
            await session.execute(update(EnrolledBackend).values(verified=False))
        else:
            await session.execute(update(EnrolledProject).values(enabled=False))
    assert not await sender.claim(saved, payload)
    assert (await sender.outbox.load(identity)).state == "pending" and not chat.calls


async def test_local_http_budget_defers_unsent_draft_without_using_critical_lane_or_attempt(db):
    import httpx

    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
    from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway

    w, binding, _ = await worker(db)
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"result": "success", "id": 1234})

    async def identity():
        return True

    c = ZulipClient(
        "https://chat.example.invalid",
        "bot",
        "fixture",
        attestation=ZulipAttestation("https://chat.example.invalid", "realm", 77, 500, 10000, 100),
        verify_identity=identity,
        transport=httpx.MockTransport(handle),
        budget=ZulipRequestBudget(requests=4, reserved=1),
    )
    w.gateway = ZulipGateway(c)
    try:
        for _ in range(3):
            await c.server_settings()
        draft = await w.outbox.queue("deferred-preview", binding.id, 1, "Preview", priority=250)
        assert await w.advance(draft) == "pending"
        saved = await w.outbox.load(draft)
        assert saved.attempts == 0 and saved.status_reason == "request_budget_deferred"
        assert len(requests) == 3
        control = await w.outbox.queue("critical-control", binding.id, 1, "Control", priority=5)
        assert await w.advance(control) == "delivered"
        assert (await w.outbox.load(control)).attempts == 1
        assert len(requests) == 4 and requests[-1].method == "POST"
        assert (await w.outbox.load(draft)).state == "pending"
    finally:
        await c.close()


async def test_local_scope_budget_deferral_keeps_control_headroom_and_zero_attempts(db):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred

    w, binding, chat = await worker(db)
    identity = await w.outbox.queue("before-scope-budget", binding.id, 1, "Preview", priority=250)
    original = w.outbox.bindings.audience.inspect
    w.outbox.bindings.audience.inspect = AsyncMock(side_effect=RequestBudgetDeferred(10))
    assert await w.advance(identity) == "pending"
    saved = await w.outbox.load(identity)
    assert saved.attempts == 0 and saved.status_reason == "request_budget_deferred"
    assert not chat.calls
    w.outbox.bindings.audience.inspect = original
    control = await w.outbox.queue("control-after-budget", binding.id, 1, "Control", priority=5)
    assert await w.advance(control) == "delivered"


async def test_protected_http_usage_does_not_deduct_a_second_normal_lane_reservation(db):
    import httpx

    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget, request_lane
    from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
    from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway

    w, binding, _ = await worker(db)
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"result": "success", "id": 1234})

    async def identity():
        return True

    c = ZulipClient(
        "https://chat.example.invalid",
        "bot",
        "fixture",
        attestation=ZulipAttestation("https://chat.example.invalid", "realm", 77, 500, 10000, 100),
        verify_identity=identity,
        transport=httpx.MockTransport(handle),
        budget=ZulipRequestBudget(requests=4, reserved=1),
    )
    w.gateway = ZulipGateway(c)
    try:
        with request_lane("control"):
            await c.request("GET", "users/me")
        await c.server_settings()
        await c.server_settings()
        identity = await w.outbox.queue(
            "after-protected-usage", binding.id, 1, "Preview", priority=250
        )
        assert await w.advance(identity) == "delivered"
        saved = await w.outbox.load(identity)
        assert saved.attempts == 1 and saved.posted_message_id == 1234
        assert len(requests) == 4 and requests[-1].method == "POST"
    finally:
        await c.close()


@pytest.mark.parametrize("boundary", ["prepayload", "postclaim"])
async def test_distributed_local_budget_waits_whole_window_without_post_or_realm_backoff(
    db, boundary
):
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget, request_lane

    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("partial-rolling-budget", binding.id, 1, "Exact output")
    clock = [100.0]
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    with request_lane("control"):
        for _ in range(180):
            budget.acquire()
            clock[0] += 0.3
    assert 0 < budget._starts[0][0] + budget.window - clock[0] < 7
    assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
    if boundary == "prepayload":
        original = sender.outbox.bindings.audience.inspect

        async def inspect(*args):
            budget.acquire()  # Actual typed refusal before any transport call.
            return await original(*args)

        sender.outbox.bindings.audience.inspect = inspect
    else:
        original = chat.send

        async def send(*args):
            budget.acquire()  # Claim exists, but the HTTP mutation never starts.
            return await original(*args)

        chat.send = send
    before = time.time()
    assert await sender.advance(identity) == "pending"
    saved = await sender.outbox.load(identity)
    assert saved.retry_at >= before + budget.window - 0.1
    assert saved.attempts == 0 and saved.status_reason == "request_budget_deferred"
    assert saved.posted_message_id is None and not chat.calls and not chat.messages
    async with db.sessions() as session:
        lane = await session.get(DeliveryLane, "realm")
        assert lane is None or (lane.not_before <= time.time() and lane.backoff == 0)


@pytest.mark.parametrize(
    ("retry", "window", "expected"),
    [
        (6, None, 6),
        (6, 60, 60),
        (6, 90, 90),
        (120, 60, 120),
        (5000, 60, 3600),
        (float("nan"), 90, 90),
        (0.01, None, 1),
    ],
)
async def test_local_budget_scheduling_keeps_longer_cooldown_and_custom_legacy_policy(
    db, retry, window, expected
):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("refill-policy", binding.id, 1, "Exact output")
    saved = await sender.outbox.load(identity)
    before = time.time()
    assert (
        await sender.rate_limit(
            saved, retry, before_send=True, local_budget=True, refill_window=window
        )
        == "pending"
    )
    after = time.time()
    saved = await sender.outbox.load(identity)
    assert before + expected <= saved.retry_at <= after + expected
    assert saved.attempts == 0 and saved.status_reason == "request_budget_deferred"
    assert not chat.calls
    async with db.sessions() as session:
        assert await session.get(DeliveryLane, "realm") is None


@pytest.mark.parametrize(
    ("local", "window"),
    [(True, value) for value in [False, 0, -1, 0.5, 3601, float("nan"), float("inf"), "60"]]
    + [(False, 60)],
)
async def test_invalid_refill_window_cannot_change_delivery_state(db, local, window):
    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("invalid-refill", binding.id, 1, "Exact output")
    before = await sender.outbox.load(identity)
    with pytest.raises(ValueError, match="invalid_delivery_budget_refill_window"):
        await sender.rate_limit(
            before, 6, before_send=True, local_budget=local, refill_window=window
        )
    after = await sender.outbox.load(identity)
    assert (after.state, after.version, after.retry_at, after.attempts) == (
        before.state,
        before.version,
        before.retry_at,
        before.attempts,
    )
    assert not chat.calls


@pytest.mark.parametrize("revoked", [False, True])
async def test_whole_window_retry_freshly_checks_grants_and_does_not_delay_other_outputs(
    db, monkeypatch, revoked
):
    from types import SimpleNamespace

    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget, request_lane
    from jt_oz_bridge.services import delivery

    sender, binding, chat = await worker(db)
    identity = await sender.outbox.queue("fresh-refill", binding.id, 1, "Exact output")
    other = await sender.outbox.queue("independent-refill", binding.id, 1, "Other output")
    # Keep the synthetic worker lease live across the scheduling-only 61s jump.
    assert await DurableStore(db).renew_lease(sender.holder, sender.fencing, ttl=120)
    wall = [time.time()]
    clock = [100.0]
    # Only this worker's scheduling clock is synthetic; this does not attest auth TTL.
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: wall[0]))
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    with request_lane("control"):
        for _ in range(180):
            budget.acquire()
            clock[0] += 0.3
    audience = sender.outbox.bindings.audience
    original = audience.inspect
    calls = 0

    async def inspected(*args):
        nonlocal calls
        calls += 1
        budget.acquire()
        return await original(*args)

    audience.inspect = inspected
    assert await sender.advance(identity) == "pending"
    assert calls == 1 and not chat.calls
    assert await sender.advance(identity) == "pending"
    assert calls == 1  # Not due: no repeated partial authorization attempt.
    audience.inspect = original
    assert await sender.advance(other) == "delivered"  # No realm-wide local backoff.
    audience.inspect = inspected
    if revoked:
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).values(active=False))
    wall[0] += 61
    clock[0] += 61
    assert await sender.advance(identity) == ("held" if revoked else "delivered")
    assert calls >= 2  # Fresh scope and current SQL grant, never a prior authority receipt.
    saved = await sender.outbox.load(identity)
    assert saved.attempts == (0 if revoked else 1)
    assert len(chat.calls) == (1 if revoked else 2)


@pytest.mark.parametrize(
    "text, inline",
    [
        ("plain answer", True),
        ("1. first\n2. second", True),
        ("```\ncode\n```", False),
        ("~~~\ncode\n~~~", False),
        ("| a | b |\n| 1 | 2 |", False),
        ("    indented code", False),
        ("trailing newline\n", False),
    ],
)
def test_marker_never_changes_how_the_last_line_renders_and_round_trips(text, inline):
    marker = "jtoz:" + "0" * 36
    content = with_marker(text, marker)
    assert ("\n\n[" not in content) is inline
    assert without_marker(content, marker) == text
    assert marker in content and "`" + marker not in content


def test_marker_identity_must_match_and_legacy_rows_stay_readable():
    marker = "jtoz:" + "0" * 36
    assert without_marker(with_marker("text", marker), "jtoz:" + "1" * 36) is None
    assert without_marker("text", marker) is None
    assert without_marker(f"text\n\n`{marker}`", marker) == "text"
