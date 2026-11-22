"""Bounded Zulip channel typing protocol, without message or reasoning content."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Self

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.zulip.client import ZulipClient

_WRITE: ContextVar[Callable[[], bool] | None] = ContextVar("typing_write", default=None)


@contextmanager
def typing_write(check: Callable[[], bool]) -> Iterator[None]:
    token = _WRITE.set(check)
    try:
        yield
    finally:
        _WRITE.reset(token)


def check_typing_write() -> None:
    check = _WRITE.get()
    if check is None or check() is not True:
        raise ValueError("typing_current_scope_required")


@dataclass(frozen=True)
class TypingParameters:
    refresh: float
    expiry: float
    stopped_wait: float

    @classmethod
    def parse(cls, registration: Mapping[str, object]) -> Self | None:
        values = tuple(
            registration.get("server_typing_" + key + "_period_milliseconds")
            for key in ("started_wait", "started_expiry", "stopped_wait")
        )
        if any(type(value) is not int or not 100 <= value <= 120000 for value in values):
            return None
        refresh, expiry, stopped = (int(str(value)) / 1000 for value in values)
        if refresh >= expiry:
            return None
        return cls(refresh, expiry, stopped)


class ZulipTyping:
    def __init__(self, client: ZulipClient) -> None:
        self.client = client
        self.attestation, self.identity = client.attestation, client.verify_identity
        self.http = client.client

    @property
    def parameters(self) -> TypingParameters | None:
        enrolled = self.attestation
        if (
            enrolled is None
            or enrolled.feature_level < 248
            or self.client.client is not self.http
            or self.client.attestation is not enrolled
            or self.identity is None
            or self.client.verify_identity is not self.identity
        ):
            return None
        return self.client.typing_parameters

    async def send(self, channel: int, topic: str, operation: Literal["start", "stop"]) -> None:
        if (
            self.parameters is None
            or type(channel) is not int
            or channel <= 0
            or not isinstance(topic, str)
            or not topic
            or self.attestation is None
            or len(topic) > self.attestation.max_topic_length
            or operation not in {"start", "stop"}
        ):
            raise ValueError("typing_contract_unavailable")
        await self.client.request(
            "POST",
            "typing",
            data={"type": "channel", "stream_id": channel, "topic": topic, "op": operation},
        )
