"""Scheduling only: bounded Bot quota, independent critical headroom and stale headers."""

import asyncio

import pytest

from jt_oz_bridge.adapters.zulip.budget import (
    RequestBudgetDeferred,
    ZulipRequestBudget,
    request_lane,
)
from jt_oz_bridge.config import ZulipBudget


class Clock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def wall(self):
        return 1000 + self.value

    def advance(self, amount):
        self.value += amount


def budget(**kwargs):
    clock = Clock()
    return ZulipRequestBudget(monotonic=clock.monotonic, wall_time=clock.wall, **kwargs), clock


def headers(remaining, reset=1060, limit=200):
    return {
        "x-ratelimit-limit": str(limit),
        "x-ratelimit-remaining": str(remaining),
        "x-ratelimit-reset": str(reset),
    }


def test_normal_traffic_preserves_real_shared_control_and_final_headroom():
    b, clock = budget()
    for _ in range(116):
        b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    for lane in ("control", "final"):
        with request_lane(lane):
            for _ in range(32):
                b.acquire()
    with request_lane("control"), pytest.raises(RequestBudgetDeferred) as raised:
        b.acquire()
    assert raised.value.retry_after == 60 and b.retained_requests == 180
    clock.advance(60)
    assert b.acquire() == 181 and b.retained_requests == 1


def test_context_lane_restores_after_error_and_does_not_leak():
    b, _ = budget(requests=6, reserved=2)
    for _ in range(4):
        b.acquire()
    with request_lane("final"):
        b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with pytest.raises(RuntimeError):
        with request_lane("control"):
            raise RuntimeError("fixture")
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()


async def test_concurrent_admissions_are_atomic_and_contexts_are_task_local():
    b, _ = budget(requests=20, reserved=5)

    async def normal():
        await asyncio.sleep(0)
        try:
            return b.acquire()
        except RequestBudgetDeferred:
            return None

    values = await asyncio.gather(*[normal() for _ in range(100)])
    accepted = [v for v in values if v is not None]
    assert len(accepted) == len(set(accepted)) == 15
    with request_lane("final"):
        for _ in range(5):
            b.acquire()
    assert b.retained_requests == 20


def test_server_headers_reduce_headroom_and_stale_responses_cannot_refill_it():
    b, clock = budget()
    first = b.acquire()
    b.observe(headers(1), first)
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with request_lane("control"):
        second = b.acquire()
        with pytest.raises(RequestBudgetDeferred):
            b.acquire()
    clock.advance(1)
    b.observe(headers(70), second)  # A newer server observation may reflect real refill.
    third = b.acquire()
    b.observe(headers(199), first)  # A delayed older response cannot undo newer usage.
    with request_lane("final"):
        for _ in range(69):
            b.acquire()
        with pytest.raises(RequestBudgetDeferred):
            b.acquire()
    assert third > second


def test_concurrent_calls_after_a_header_request_are_subtracted_conservatively():
    b, _ = budget(requests=10, reserved=0)
    first = b.acquire()
    for _ in range(3):
        b.acquire()
    b.observe(headers(4), first)
    b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()


@pytest.mark.parametrize("bad", ["nan", "-1", "1.0", "١", "9" * 100, "inf"])
def test_invalid_header_fields_never_expand_the_local_budget(bad):
    b, _ = budget(requests=4, reserved=0)
    first = b.acquire()
    h = headers(100)
    h["x-ratelimit-remaining"] = bad
    b.observe(h, first)
    for _ in range(3):
        b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()


def test_missing_headers_have_a_bounded_local_fallback():
    b, _ = budget(requests=4, reserved=0)
    for _ in range(4):
        b.observe({}, b.acquire())
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()


def test_verified_server_throttle_cools_all_lanes_and_recovers_capacity_gradually():
    b, clock = budget(requests=100, reserved=20)
    b.acquire()
    b.rate_limited(5)
    assert b.capacity == 80
    with request_lane("control"), pytest.raises(RequestBudgetDeferred):
        b.acquire()
    clock.advance(5)
    with request_lane("control"):
        b.acquire()
    assert b.capacity == 80
    clock.advance(60)
    b.acquire()
    assert b.capacity == 90
    clock.advance(60)
    b.acquire()
    assert b.capacity == 100


def test_request_history_stays_bounded_over_long_lived_connections():
    b, clock = budget(requests=4, reserved=0)
    for _ in range(20000):
        for _ in range(4):
            b.acquire()
        assert b.retained_requests == 4
        clock.advance(60)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"requests": True},
        {"requests": 3},
        {"requests": 100001},
        {"requests": 10, "reserved": 10},
        {"reserved": -1},
        {"window": float("nan")},
        {"window": 0},
        {"window": True},
    ],
)
def test_invalid_budgets_are_rejected(kwargs):
    with pytest.raises(ValueError):
        budget(**kwargs)


@pytest.mark.parametrize("reported_headers", [False, True])
def test_protected_usage_consumes_its_window_allocation_without_charging_normal_twice(
    reported_headers,
):
    b, _ = budget()
    with request_lane("control"):
        for _ in range(64):
            latest = b.acquire()
    if reported_headers:
        b.observe(headers(136), latest)
    for _ in range(116):
        b.acquire()
    assert b.retained_requests == 180
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with request_lane("final"), pytest.raises(RequestBudgetDeferred):
        b.acquire()


def test_normal_traffic_cannot_consume_the_unused_protected_allocation():
    b, _ = budget(requests=10, reserved=4)
    with request_lane("final"):
        for _ in range(2):
            b.acquire()
    b.observe(headers(8, limit=10), 2)
    for _ in range(6):
        b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with request_lane("control"):
        assert b.acquire() == 9
        assert b.acquire() == 10
        with pytest.raises(RequestBudgetDeferred):
            b.acquire()


def test_normal_partition_retries_when_its_own_oldest_credit_expires():
    b, clock = budget(requests=10, reserved=4)
    with request_lane("control"):
        for _ in range(4):
            b.acquire()
    clock.advance(10)
    for _ in range(6):
        b.acquire()
    clock.advance(50)
    with pytest.raises(RequestBudgetDeferred) as error:
        b.acquire()
    assert error.value.retry_after == 10
    with request_lane("final"):
        for _ in range(4):
            b.acquire()
    clock.advance(10)
    b.acquire()
    assert b.retained_requests == 5


def test_server_headroom_counts_only_the_unused_protected_allocation():
    b, _ = budget(requests=20, reserved=6)
    with request_lane("control"):
        latest = b.acquire()
        latest = b.acquire()
    b.observe(headers(6, limit=20), latest)
    b.acquire()
    b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with request_lane("final"):
        for _ in range(4):
            b.acquire()
        with pytest.raises(RequestBudgetDeferred):
            b.acquire()


@pytest.mark.parametrize("window", [1, 60, 90, 3600])
def test_actual_budget_deferral_carries_exact_scheduling_window(window):
    current, clock = budget(window=window)
    with request_lane("control"):
        for _ in range(180):
            current.acquire()
        with pytest.raises(RequestBudgetDeferred) as raised:
            current.acquire()
    assert raised.value.refill_window == window
    assert raised.value.retry_after == window
    assert (current.limit, current.reserved, current.retained_requests) == (180, 64, 180)


def test_custom_budget_deferral_without_window_keeps_original_retry():
    error = RequestBudgetDeferred(6)
    assert error.retry_after == 6 and error.refill_window is None


@pytest.mark.parametrize(
    "window", [False, True, 0, -1, 0.5, 3601, float("nan"), float("inf"), "60"]
)
def test_budget_deferral_rejects_invalid_optional_refill_window(window):
    with pytest.raises(ValueError, match="invalid_request_budget_refill_window"):
        RequestBudgetDeferred(6, refill_window=window)


@pytest.mark.parametrize(
    "scenario",
    [
        "empty",
        "normal52",
        "normal53",
        "protected80",
        "mixed",
        "server",
        "server_protected",
        "cooldown",
        "shrunken",
        "shrunken_full",
        "window_prune",
        "server_expiry",
    ],
)
def test_normal_headroom_exactly_matches_real_normal_acquire_at_same_snapshot(scenario):
    import copy

    current, clock = budget()

    def spend(lane, count):
        with request_lane(lane):
            for _ in range(count):
                current.acquire()

    if scenario in {"normal52", "normal53"}:
        spend("normal", int(scenario.removeprefix("normal")))
    elif scenario == "protected80":
        spend("control", 40)
        spend("final", 40)
    elif scenario == "mixed":
        spend("normal", 30)
        spend("control", 30)
        spend("draft", 10)
        spend("final", 20)
    elif scenario in {"server", "server_protected"}:
        spend("control", 40 if scenario == "server_protected" else 0)
        current.observe(headers(90), current._sequence)
    elif scenario == "cooldown":
        current.rate_limited(20)
    elif scenario in {"shrunken", "shrunken_full"}:
        spend("normal", 100 if scenario == "shrunken_full" else 10)
        if scenario == "shrunken":
            spend("final", 50)
        current.rate_limited(5)
        clock.advance(6)
    elif scenario == "window_prune":
        spend("normal", 53)
        spend("control", 60)
        clock.advance(60)
    elif scenario == "server_expiry":
        current.observe(headers(20), current._sequence)
        clock.advance(61)

    query = current.normal_headroom
    assert type(query) is int and query >= 0
    # Queries do not record requests, change lanes or consume the available
    # slots. Time pruning/recovery is the same as a real acquire at this instant.
    after_prune = (
        tuple(current._starts),
        current._sequence,
        current.deferred,
        current._normal_started,
        current._protected_started,
        current._server_remaining,
    )
    with request_lane("control"):
        assert current.normal_headroom == query
    assert after_prune == (
        tuple(current._starts),
        current._sequence,
        current.deferred,
        current._normal_started,
        current._protected_started,
        current._server_remaining,
    )
    admitted, snapshot = 0, copy.deepcopy(current)
    with request_lane("normal"):
        while True:
            try:
                snapshot.acquire()
            except RequestBudgetDeferred:
                break
            admitted += 1
            assert admitted <= 180
    assert admitted == query and snapshot.normal_headroom == 0
    assert (current.limit, current.window, current.reserved) == (180, 60, 64)
    if scenario == "protected80":
        assert query == 100  # Total180-80, not a second subtraction of reserve64.
    if scenario == "normal53":
        assert query == 63  # Existing optional typing floor64 still refuses.


def test_normal_headroom_is_scheduling_only_and_cannot_reserve_against_other_calls():
    current, _ = budget()
    for _ in range(52):
        current.acquire()
    assert current.normal_headroom == 64
    current.acquire()
    assert current.normal_headroom == 63
    for _ in range(63):
        current.acquire()
    assert current.normal_headroom == 0
    with pytest.raises(RequestBudgetDeferred):
        current.acquire()
    with request_lane("control"):
        for _ in range(64):
            current.acquire()
        with pytest.raises(RequestBudgetDeferred):
            current.acquire()
    assert current.retained_requests == 180


@pytest.mark.parametrize("limit", [180, 1800])
def test_configured_factory_preserves_exact_window_reserve_and_local_bound(limit):
    clock = Clock()
    policy = ZulipBudget(requests=limit, window_seconds=60.0, reserved_requests=64)
    b = ZulipRequestBudget.from_config(policy, monotonic=clock.monotonic, wall_time=clock.wall)
    assert (b.limit, b.window, b.reserved) == (limit, 60.0, 64)
    for _ in range(limit - 64):
        b.acquire()
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with request_lane("final"):
        for _ in range(64):
            b.acquire()
        with pytest.raises(RequestBudgetDeferred):
            b.acquire()
    assert b.retained_requests == limit
    clock.advance(60)
    assert b.acquire() == limit + 1
    assert b.retained_requests == 1
    assert ZulipBudget().requests == ZulipRequestBudget().limit == 180


@pytest.mark.parametrize("server_limit", [200, 2000])
def test_configured_larger_budget_still_obeys_actual_server_headers(server_limit):
    clock = Clock()
    b = ZulipRequestBudget.from_config(
        ZulipBudget(requests=1800, window_seconds=60.0, reserved_requests=64),
        monotonic=clock.monotonic,
        wall_time=clock.wall,
    )
    first = b.acquire()
    b.observe(headers(64, limit=server_limit), first)
    with pytest.raises(RequestBudgetDeferred):
        b.acquire()
    with request_lane("final"):
        for _ in range(64):
            b.acquire()
        with pytest.raises(RequestBudgetDeferred):
            b.acquire()
    assert b.limit == 1800 and b.retained_requests == 65
    assert b.deferred == 2
