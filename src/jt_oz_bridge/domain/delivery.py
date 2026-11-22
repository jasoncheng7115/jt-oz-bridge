from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol

from pydantic import Field, StrictInt

from jt_oz_bridge.domain.control import ControlModel

# Finding an uncertain post needs the identity in the raw text, not on screen: a
# link around one zero-width space renders as nothing on every Zulip client.
_LINK_TEXT = "\u200b"
MARKER_FOOTER_SIZE = len(f"\n\n[{_LINK_TEXT}](#jtoz:" + "0" * 36 + ")")


def _marker_link(marker: str) -> str:
    return f"[{_LINK_TEXT}](#{marker})"


def with_marker(text: str, marker: str) -> str:
    """Keep the link on the last line unless that would change how the line renders."""
    last = text.rsplit("\n", 1)[-1]
    inline = (
        last.strip()
        and last == last.rstrip()
        and not last.lstrip().startswith(("```", "~~~", "|"))
        and not last.startswith(("    ", "\t"))
        and text.count("```") % 2 == 0
        and text.count("~~~") % 2 == 0
    )
    return text + ("" if inline else "\n\n") + _marker_link(marker)


def without_marker(content: str, marker: str) -> str | None:
    """The page text, or None when this content does not carry this exact identity."""
    for suffix in (f"\n\n{_marker_link(marker)}", f"\n\n`{marker}`", _marker_link(marker)):
        if content.endswith(suffix) and len(content) > len(suffix):
            return content[: -len(suffix)]
    return None


class PostedMessage(ControlModel):
    realm_id: str
    id: StrictInt = Field(gt=0)
    channel_id: StrictInt = Field(gt=0)
    topic: str
    sender_id: StrictInt = Field(gt=0)
    content: str


class DeliveryRateLimited(ValueError):
    """An explicit upstream rate-limit rejection proves no admission."""

    def __init__(self, retry_after: float) -> None:
        super().__init__("delivery_rate_limited")
        self.retry_after = retry_after


class DeliveryRejected(ValueError):
    """A verified upstream response proves no message was accepted."""


class DeliveryNotSent(ValueError):
    """The adapter positively stopped before starting its HTTP mutation."""


_write_witness: ContextVar[Callable[[], bool] | None] = ContextVar(
    "original_delivery_write_witness", default=None
)


@contextmanager
def original_write_witness(witness: Callable[[], bool] | None) -> Iterator[None]:
    token = _write_witness.set(witness)
    try:
        yield
    finally:
        _write_witness.reset(token)


def check_original_write_witness() -> None:
    witness = _write_witness.get()
    if witness is not None and witness() is not True:
        raise DeliveryNotSent("original_witness_expired_before_http_mutation")


class ChatGateway(Protocol):
    realm_id: str
    bot_user_id: int

    @property
    def writes_enabled(self) -> bool: ...

    async def send(self, channel: int, topic: str, content: str, marker: str) -> int: ...
    async def edit(self, message_id: int, content: str) -> None: ...
    async def get(self, message_id: int) -> PostedMessage: ...
    async def find(self, channel: int, topic: str, marker: str) -> tuple[PostedMessage, ...]: ...
