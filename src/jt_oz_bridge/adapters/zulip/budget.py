"""One bounded, fail-fast Bot/realm request budget; no authorization caching."""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Literal, Self

from jt_oz_bridge.domain.delivery import DeliveryRateLimited

if TYPE_CHECKING:
    from jt_oz_bridge.config import ZulipBudget

Lane = Literal["normal", "draft", "control", "final"]
_lane: ContextVar[Lane] = ContextVar("zulip_request_lane", default="normal")


class RequestBudgetDeferred(DeliveryRateLimited):
    """Local no-HTTP refusal; optional refill delay is scheduling, never authority."""

    def __init__(self, retry_after: float, *, refill_window: float | None = None) -> None:
        if refill_window is not None and (
            type(refill_window) not in {int, float}
            or not math.isfinite(refill_window)
            or not 1 <= refill_window <= 3600
        ):
            raise ValueError("invalid_request_budget_refill_window")
        super().__init__(retry_after)
        self.refill_window = float(refill_window) if refill_window is not None else None


@contextmanager
def request_lane(lane: Lane) -> Iterator[None]:
    if lane not in {"normal", "draft", "control", "final"}:
        raise ValueError("invalid_request_budget_lane")
    token = _lane.set(lane)
    try:
        yield
    finally:
        _lane.reset(token)


class ZulipRequestBudget:
    @classmethod
    def from_config(
        cls,
        policy: ZulipBudget,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> Self:
        """Use the enrolled realm's explicit quota without changing default limits."""
        return cls(
            requests=policy.requests,
            window=policy.window_seconds,
            reserved=policy.reserved_requests,
            monotonic=monotonic,
            wall_time=wall_time,
        )

    def __init__(
        self,
        *,
        requests: int = 180,
        window: float = 60,
        reserved: int = 64,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        if (
            type(requests) is not int
            or not 4 <= requests <= 100000
            or type(reserved) is not int
            or not 0 <= reserved < requests
            or type(window) not in {int, float}
            or not math.isfinite(window)
            or not 1 <= window <= 3600
        ):
            raise ValueError("invalid_zulip_request_budget")
        self.limit, self.window, self.reserved = requests, window, reserved
        self.clock, self.wall = monotonic, wall_time
        self.capacity = requests
        self._starts: deque[tuple[float, int, bool]] = deque()
        self._normal_started = 0
        self._protected_started = 0
        self._sequence = 0
        self._cooldown = 0.0
        self._recovery_at = 0.0
        self._server_until = 0.0
        self._server_remaining: int | None = None
        self._header_sequence = 0
        self.deferred = self.rate_limits = 0

    def _prune(self, now: float) -> None:
        while self._starts and self._starts[0][0] <= now - self.window:
            _, _, protected = self._starts.popleft()
            if protected:
                self._protected_started -= 1
            else:
                self._normal_started -= 1
        if self._server_until <= now:
            self._server_remaining = None
        if self.capacity < self.limit and now >= self._recovery_at:
            self.capacity = min(self.limit, self.capacity + max(1, self.limit // 10))
            self._recovery_at = now + self.window

    def acquire(self) -> int:
        """Synchronous admission across concurrent tasks; never wait inside a proof."""
        now = self.clock()
        self._prune(now)
        protected = _lane.get() in {"control", "final"}
        allocation = min(self.reserved, self.capacity - 1)
        # Protected requests already spent part of this window's allocation.
        # Charge them once against the total, not again against the normal lane.
        reserve = 0 if protected else max(0, allocation - self._protected_started)
        retry = self._cooldown - now
        if len(self._starts) >= self.capacity:
            retry = max(retry, self._starts[0][0] + self.window - now)
        if not protected and self._normal_started >= self.capacity - allocation:
            first_normal = next(
                stamp for stamp, _, is_protected in self._starts if not is_protected
            )
            retry = max(retry, first_normal + self.window - now)
        if self._server_remaining is not None and self._server_remaining <= reserve:
            retry = max(retry, self._server_until - now)
        if retry > 0:
            self.deferred += 1
            raise RequestBudgetDeferred(max(0.01, min(3600, retry)), refill_window=self.window)
        self._sequence += 1
        self._starts.append((now, self._sequence, protected))
        if protected:
            self._protected_started += 1
        else:
            self._normal_started += 1
        if self._server_remaining is not None:
            self._server_remaining = max(0, self._server_remaining - 1)
        return self._sequence

    def observe(self, headers: Mapping[str, str], sequence: int) -> None:
        """Headers may reduce scheduling capacity; stale responses never increase it."""
        try:
            raw = tuple(
                headers[key]
                for key in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")
            )
            if any(
                not value.isascii() or not value.isdecimal() or len(value) > 16 for value in raw
            ):
                return
            limit, remaining, reset = map(int, raw)
            if not 1 <= limit <= 1000000 or not 0 <= remaining <= limit:
                return
        except (KeyError, TypeError, ValueError):
            return
        now = self.clock()
        self._prune(now)
        # Do not infer the server's configured window from a response header.
        # The local rolling window stays independently bounded. Applied
        # endpoint/user limits can only restrict current scheduling headroom.
        after_start = self._sequence - sequence
        remaining = max(0, remaining - after_start)
        until = now + max(1, min(3600, reset - self.wall() + 1))
        if self._server_remaining is None or sequence > self._header_sequence:
            self._server_remaining = remaining
            self._server_until = until
        else:
            self._server_remaining = min(self._server_remaining, remaining)
            self._server_until = max(self._server_until, until)
        self._header_sequence = max(self._header_sequence, sequence)

    def rate_limited(self, retry_after: float) -> None:
        now = self.clock()
        delay = max(1, min(3600, retry_after)) if math.isfinite(retry_after) else 60
        self._cooldown = max(self._cooldown, now + delay)
        self.capacity = max(4, int(self.capacity * 0.8))
        self._recovery_at = self._cooldown + self.window
        self.rate_limits += 1

    @property
    def retained_requests(self) -> int:
        self._prune(self.clock())
        return len(self._starts)

    @property
    def normal_headroom(self) -> int:
        """Normal request scheduling capacity now; never scope or write authority.

        Same pruning and unused protected allocation as acquire(), without
        recording a request or consuming any capacity. Actual admission remains
        synchronous acquire() on every individual request, including races.
        """
        now = self.clock()
        self._prune(now)
        if now < self._cooldown:
            return 0
        allocation = min(self.reserved, self.capacity - 1)
        available = min(
            self.capacity - len(self._starts),
            self.capacity - allocation - self._normal_started,
        )
        if self._server_remaining is not None:
            available = min(
                available,
                self._server_remaining - max(0, allocation - self._protected_started),
            )
        return max(0, available)
