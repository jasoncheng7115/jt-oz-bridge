"""Bounded SSE framing. A truncated frame at EOF is never a committed event."""

from collections.abc import AsyncIterable, AsyncIterator, Iterator
from dataclasses import dataclass

from jt_oz_bridge.adapters.opencode.contracts import ContractError

# A discarded frame keeps only this much of its data for scope attribution.
OVERSIZED_PREFIX_BYTES = 8 * 1024
# Beyond this a frame is a broken stream, not one oversized event.
OVERSIZED_DISCARD_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class SSEFrame:
    event: str
    data: str
    event_id: str | None = None
    # Only a discarding parser sets this. ``data`` is then a bounded leading
    # prefix of the discarded data, never a complete or valid event.
    truncated: bool = False


class SSEParser:
    def __init__(
        self, max_event_bytes: int = 16 * 1024 * 1024, *, discard_oversized: bool = False
    ) -> None:
        if max_event_bytes < 1:
            raise ValueError("positive SSE size limit required")
        self.limit = max_event_bytes
        self.discard_oversized = discard_oversized
        self._line = bytearray()
        self._data: list[str] = []
        self._has_data = False
        self._event = "message"
        self._last_id: str | None = None
        self._size = 0
        self._first_line = True
        self._skip_lf = False
        self._discarding: SSEFrame | None = None
        self._line_empty = True

    def _finish_line(self) -> SSEFrame | None:
        try:
            line = self._line.decode("utf-8")
        except UnicodeError:
            raise ContractError("event_stream_invalid_utf8") from None
        self._line.clear()
        if self._first_line:
            line = line.removeprefix("\ufeff")
            self._first_line = False
        if not line:
            frame = (
                SSEFrame(self._event, "\n".join(self._data), self._last_id)
                if self._has_data
                else None
            )
            self._data.clear()
            self._event, self._size, self._has_data = "message", 0, False
            return frame
        if line.startswith(":"):
            return None
        name, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._data.append(value)
            self._has_data = True
        elif name == "event":
            self._event = value or "message"
        elif name == "id" and "\x00" not in value:
            self._last_id = value
        # Retry hints do not control bridge policy. Unknown fields are ignored.
        return None

    def _start_discard(self) -> None:
        """Keep a bounded data prefix and drop everything else of this frame."""
        # Copy only prefix-sized slices; the buffers themselves may hold the limit.
        line = bytes(self._line[: OVERSIZED_PREFIX_BYTES + 9])
        if self._first_line:
            line = line.removeprefix(b"\xef\xbb\xbf")
        values: list[bytes] = []
        for value in self._data:
            values.append(value[:OVERSIZED_PREFIX_BYTES].encode())
            if sum(len(v) + 1 for v in values) > OVERSIZED_PREFIX_BYTES:
                break
        else:
            if line.startswith(b"data:"):
                values.append(line[5:].removeprefix(b" "))
        prefix = b"\n".join(values)[:OVERSIZED_PREFIX_BYTES]
        try:
            text = prefix.decode("utf-8")
        except UnicodeDecodeError as error:
            # Only a character cut by this prefix may be dropped.
            if error.start < len(prefix) - 3:
                raise ContractError("event_stream_invalid_utf8") from None
            text = prefix[: error.start].decode("utf-8")
        self._discarding = SSEFrame(self._event, text, self._last_id, truncated=True)
        self._line_empty = not self._line
        self._line.clear()
        self._data.clear()
        self._first_line = False

    def _discard(self, chunk: bytes, position: int) -> tuple[int, SSEFrame | None]:
        """Skip to the blank line ending the discarded frame; nothing is buffered."""
        end = len(chunk)
        while position < end:
            byte = chunk[position]
            if self._skip_lf:
                self._skip_lf = False
                if byte == 10:
                    position += 1
                    continue
            if byte in {10, 13}:
                self._skip_lf = byte == 13
                position += 1
                if self._line_empty:
                    frame, self._discarding = self._discarding, None
                    self._event, self._size, self._has_data = "message", 0, False
                    return position, frame
                self._line_empty = True
                continue
            stop = chunk.find(10, position)
            stop = end if stop < 0 else stop
            carriage = chunk.find(13, position, stop)
            stop = stop if carriage < 0 else carriage
            self._size += stop - position
            if self._size > OVERSIZED_DISCARD_BYTES:
                raise ContractError("event_stream_frame_too_large")
            self._line_empty = False
            position = stop
        return position, None

    def feed(self, chunk: bytes) -> Iterator[SSEFrame]:
        position = 0
        while position < len(chunk):
            if self._discarding is not None:
                position, frame = self._discard(chunk, position)
                if frame is not None:
                    yield frame
                continue
            byte = chunk[position]
            position += 1
            if self._skip_lf:
                self._skip_lf = False
                if byte == 10:
                    continue
            self._size += 1
            if self._size > self.limit:
                if not self.discard_oversized:
                    raise ContractError("event_stream_frame_too_large")
                self._start_discard()
                position -= 1  # Classify this byte within the discarded frame.
                continue
            if byte in {10, 13}:
                self._skip_lf = byte == 13
                frame = self._finish_line()
                if frame is not None:
                    yield frame
            else:
                self._line.append(byte)

    def finish(self) -> None:
        # Do not reinterpret transport truncation as a complete JSON/event frame.
        self._line.clear()
        self._data.clear()
        self._has_data = False
        self._discarding = None
        self._event, self._size, self._skip_lf, self._line_empty = "message", 0, False, True


async def iter_sse(
    chunks: AsyncIterable[bytes],
    *,
    max_event_bytes: int = 16 * 1024 * 1024,
    discard_oversized: bool = False,
) -> AsyncIterator[SSEFrame]:
    parser = SSEParser(max_event_bytes, discard_oversized=discard_oversized)
    try:
        async for chunk in chunks:
            for frame in parser.feed(chunk):
                yield frame
    finally:
        parser.finish()
