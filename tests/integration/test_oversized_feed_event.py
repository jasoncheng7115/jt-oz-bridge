"""One oversized Native event fails closed for its own Root, not the process.

Synthetic HTTP and event shapes from the installed v2.0.32 fixtures only. No
Native, Zulip, Human or mobile evidence.
"""

import asyncio
import copy
import json
import logging
import tracemalloc
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.live import (
    FRAME_ALLOWANCE,
    V2PublicFeed,
    VolatileFeedIndex,
    leading_members,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, READS
from jt_oz_bridge.adapters.opencode.sse import (
    OVERSIZED_DISCARD_BYTES,
    OVERSIZED_PREFIX_BYTES,
    SSEFrame,
    SSEParser,
)
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.services.runtime import RuntimeWorker, SupervisedRuntime
from jt_oz_bridge.services.runtime_enrollment import BackendRuntimeObserver
from jt_oz_bridge.storage.durable import DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.contract.test_leaf_resources import finish
from tests.contract.test_leaf_resources import setup as leaf_setup
from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, REAL, REF, frame

OTHER = REF.model_copy(update={"upstream_session_id": "ses_other_enrolled_root"})
FOREIGN = REF.model_copy(update={"upstream_session_id": "ses_not_enrolled_here"})
FILL = b"A" * 65536
MIB = 1024 * 1024
LIMIT = 1024 * 1024 + FRAME_ALLOWANCE  # What the feed asks its parser for.


def scoped(ref, event_id, base=None):
    raw = copy.deepcopy(base or REAL[0])
    raw = json.loads(json.dumps(raw).replace(REF.upstream_session_id, ref.upstream_session_id))
    raw["id"] = event_id
    raw.pop("durable", None)
    return raw


def wire(raw):
    return ("event: message\ndata: " + json.dumps(raw) + "\n\n").encode()


def oversized_chunks(ref, size, event_id="evt_oversized_read", *, session=True, directory=None):
    """Wire order of an installed tool result whose text is ``size`` bytes."""
    tool = next(e for e in REAL if e["type"] == "session.tool.success")
    head = json.dumps(
        {
            "id": event_id,
            "created": tool["created"],
            "type": tool["type"],
            "location": {"directory": directory or ref.canonical_directory},
        }
    )[:-1]
    data = json.dumps(
        {
            **({"sessionID": ref.upstream_session_id} if session else {}),
            "assistantMessageID": tool["data"]["assistantMessageID"],
            "id": tool["data"]["id"],
        }
    )[:-1]
    yield ("event: message\ndata: " + head + ', "data": ' + data).encode()
    yield b', "content": [{"type": "text", "text": "'
    for _ in range(size // len(FILL)):
        yield FILL
    yield b'"}], "metadata": {"truncated": false}, "executed": false}}\n\n'


def complete_oversized(ref, extra=64 * 1024):
    """A whole parsed event just above the 1 MiB retained-event limit."""
    raw = scoped(
        ref, "evt_parsed_oversized", next(e for e in REAL if e["type"] == "session.tool.success")
    )
    raw["data"]["content"][0]["text"] = "B" * (MIB + extra - 4096)
    assert MIB < len(json.dumps(raw)) < LIMIT
    return raw


def truncated(chunks):
    parser = SSEParser(LIMIT, discard_oversized=True)
    frames = [f for chunk in chunks for f in parser.feed(chunk)]
    assert len(frames) == 1 and frames[0].truncated
    return frames[0]


class Receipts:
    async def record_many(self, values):
        return tuple(True for _ in values)


def feed(chunks, *, receipts=None, refs=(REF, OTHER)):
    """Actual transport/parser/feed over one synthetic loopback stream."""
    sent, go = asyncio.Event(), asyncio.Event()

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield wire(CONNECTED)
            await go.wait()  # Released once the runtime is running, as live.
            for chunk in chunks:
                yield chunk
            sent.set()
            await asyncio.Event().wait()

    def handle(request):
        assert request.method == "GET" and request.url.path == "/api/event"
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Stream())

    transport = V2HTTPTransport(
        "http://127.0.0.1:4096",
        PROFILE,
        attestation=ContractAttestation(PROFILE.sha256, REF.backend_identity, "2.0.32", READS),
        transport=httpx.MockTransport(handle),
        verify_identity=AsyncMock(return_value=True),
    )
    owner = SimpleNamespace(
        enrollment=SimpleNamespace(
            backend_id=REF.backend_id,
            backend_identity=REF.backend_identity,
            version="2.0.32",
            url="http://127.0.0.1:4096",
        ),
        read=AsyncMock(return_value=SimpleNamespace(owner_epoch=OWNER)),
    )
    result = V2PublicFeed(transport, owner, refs, receipts=receipts)
    return result, SimpleNamespace(sent=sent, go=go)


async def settle(result, stream, committed):
    stream.go.set()
    for _ in range(3000):
        if result.task.done() or stream.sent.is_set() and result.index.revision >= committed:
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)


async def close(result):
    await result.close()
    await result.transport.close()


async def test_oversized_scoped_event_keeps_the_owner_feed_worker_and_runtime_running(db, caplog):
    # A 20 MiB read result in one enrolled Root must not end the feed, raise in
    # the owner-feed worker or make the process exit.
    chunks = [
        wire(scoped(OTHER, "evt_other_before")),
        *oversized_chunks(REF, 20 * MIB),
        wire(scoped(OTHER, "evt_other_after")),
        wire(scoped(REF, "evt_root_after")),
    ]
    result, stream = feed(chunks, receipts=Receipts())
    observer = BackendRuntimeObserver(result, ())

    async def pulse():
        # The composed consumer's native-owner-feed worker loop.
        while True:
            await observer.pulse()
            await asyncio.sleep(0.01)

    number = await DurableStore(db).acquire_lease("oversized-feed")
    runtime = SupervisedRuntime(
        db,
        ConsumerFence("oversized-feed", number),
        (),
        (RuntimeWorker("native-owner-feed", pulse),),
    )
    await result.start()
    await runtime.start()
    try:
        with caplog.at_level(logging.WARNING):
            await settle(result, stream, 3)
        assert runtime.healthy and runtime.failure_detail is None
        assert not result.task.done() and not result.index.closed
        # Other Root before/after and this Root's next event were all admitted.
        assert result.index.revision == 3
        assert (await result.current_owner()).owner_epoch == OWNER
        lines = [r.getMessage() for r in caplog.records if "discarded" in r.getMessage()]
        assert lines == [
            "public_feed_event_discarded reason=oversized session=" + REF.upstream_session_id
        ]
        assert "AAAA" not in caplog.text
    finally:
        await runtime.close()
        await close(result)


@pytest.mark.parametrize("receipted", [False, True])
@pytest.mark.parametrize("size", ["parsed", "streamed"])
async def test_only_the_affected_roots_fences_change_and_peers_keep_receiving(receipted, size):
    big = (
        [wire(complete_oversized(REF))]
        if size == "parsed"
        else list(oversized_chunks(REF, 3 * MIB))
    )
    chunks = [*big, wire(scoped(OTHER, "evt_other_after"))]
    result, stream = feed(chunks, receipts=Receipts() if receipted else None)
    await result.start()
    try:
        index = result.index
        before = index.revision_for(REF), index.state_revision_for(REF)
        await settle(result, stream, 1)
        assert not result.task.done() and not index.closed
        assert index.revision_for(REF) > before[0] and index.state_revision_for(REF) > before[1]
        # Nothing of the discarded event is retained, receipted or positioned.
        item = index.pop()
        assert item.reference == OTHER and item.native_id == "evt_other_after"
        assert index.pop() is None and index._retained_bytes == 0
        assert "evt_oversized_read" not in index._seen and "evt_parsed_oversized" not in index._seen
        assert index.observed_position(REF) is None
        assert (await result.current_owner()).owner_epoch == OWNER
    finally:
        await close(result)


async def test_streamed_oversized_event_is_never_held_in_memory():
    result, stream = feed(list(oversized_chunks(REF, 20 * MIB)), receipts=Receipts())
    await result.start()
    try:
        tracemalloc.start()
        try:
            await settle(result, stream, 0)
            assert stream.sent.is_set()
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert not result.task.done()
        # Bounded by the 1 MiB + framing reader cap, not the 20 MiB event.
        assert peak < 4 * MIB, peak
        # Only the connection marker ever entered the raw batch queue.
        assert result.buffer_peak_bytes == len(json.dumps(CONNECTED))
    finally:
        await close(result)


def test_discarding_parser_buffers_nothing_beyond_its_limit_and_resumes():
    parser = SSEParser(1024, discard_oversized=True)
    out = list(parser.feed(b'event: message\ndata: {"id":"evt_a","type":"session.x",'))
    for _ in range(64):
        out += parser.feed(b"x" * 4096)
        assert len(parser._line) == 0 and not parser._data
    out += parser.feed(b'"}\r\n\r\ndata: {"next":1}\n\n')
    assert [f.truncated for f in out] == [True, False]
    assert out[0].data.startswith('{"id":"evt_a"') and len(out[0].data) <= 1024
    assert out[0].event == "message" and out[1] == SSEFrame("message", '{"next":1}')


@pytest.mark.parametrize("split", [1, 7, 4096])
def test_discard_handles_every_chunk_split_and_line_ending(split):
    raw = b'data: {"id":"e","type":"t","pad":"' + b"y" * 3000 + b'"}\r\n\r\ndata: 2\r\n\r\n'
    parser, out = SSEParser(512, discard_oversized=True), []
    for at in range(0, len(raw), split):
        out += parser.feed(raw[at : at + split])
    assert [(f.truncated, f.data[:9]) for f in out] == [(True, '{"id":"e"'), (False, "2")]


def test_prefix_is_bounded_and_a_cut_character_is_dropped_not_invalid():
    parser = SSEParser(OVERSIZED_PREFIX_BYTES + 100, discard_oversized=True)
    body = b"data: " + b"a" * (OVERSIZED_PREFIX_BYTES - 1) + "é".encode() * 400
    (result,) = parser.feed(body + b"\n\n")
    assert result.truncated and result.data == "a" * (OVERSIZED_PREFIX_BYTES - 1)
    with pytest.raises(ContractError, match="utf8"):
        list(SSEParser(16, discard_oversized=True).feed(b"data: \xff" + b"z" * 64 + b"\n\n"))


def test_endless_frame_and_default_parser_still_fail_as_a_broken_stream():
    with pytest.raises(ContractError, match="too_large"):
        list(SSEParser(12).feed(b"data: " + b"z" * 64))
    parser = SSEParser(16, discard_oversized=True)
    block = b"z" * MIB
    with pytest.raises(ContractError, match="too_large"):
        for _ in range(OVERSIZED_DISCARD_BYTES // MIB + 1):
            list(parser.feed(block))
    parser = SSEParser(16, discard_oversized=True)
    assert list(parser.feed(b"data: " + b"z" * 64)) == []
    parser.finish()  # A frame cut by EOF is not an event, not even a discard.
    assert list(parser.feed(b"\n\ndata: 1\n\n")) == [SSEFrame("message", "1")]


def test_leading_members_reads_only_complete_values_before_the_cut():
    text = json.dumps(
        {"id": "evt_x", "created": 17, "type": "session.tool.success", "data": {"sessionID": "s"}}
    )
    assert leading_members(text) == json.loads(text)
    cut = '{"id": "evt_x", "type": "session.tool.success", "data": {"sessionID": "s", "n": 12'
    assert leading_members(cut) == {
        "id": "evt_x",
        "type": "session.tool.success",
        "data": {"sessionID": "s"},
    }
    assert leading_members('{"id": "evt_x", "created": 1792') == {"id": "evt_x"}
    nested = '{"id": "e", "location": {"directory": "/cut'
    assert leading_members(nested) == {"id": "e"}
    for bad in ["", "[1,", '{"id": "e" "type"', '{"id": 1, "id": 2,', '{"x": NaN,']:
        with pytest.raises(ValueError):
            leading_members(bad)


def index_for(*refs):
    result = VolatileFeedIndex(PROFILE, refs, OWNER)
    result.accept(frame(CONNECTED))
    return result


def test_foreign_oversized_event_changes_only_the_whole_stream_fence():
    i = index_for(REF, OTHER)
    fence = i.stream_fence(state_only=True)
    assert i.accept(truncated(oversized_chunks(FOREIGN, 2 * MIB))) is None
    assert not i.closed and i.stream_fence(state_only=True) != fence
    assert i.revision_for(REF) == i.revision_for(OTHER) == 0
    raw = complete_oversized(FOREIGN)
    assert i.accept(SSEFrame("message", json.dumps(raw))) is None
    assert i.revision_for(REF) == i.revision_for(OTHER) == 0 and not i.closed


def test_unattributable_oversized_session_event_changes_every_enrolled_roots_fences(caplog):
    i = index_for(REF, OTHER)
    with caplog.at_level(logging.WARNING):
        assert i.accept(truncated(oversized_chunks(REF, 2 * MIB, session=False))) is None
    assert not i.closed
    assert i.state_revision_for(REF) == i.state_revision_for(OTHER) == 1
    assert "session=unattributed" in caplog.text
    # Non-session kinds stay out of per-Root fences, as when parsed.
    plugin = (
        b'data: {"id": "evt_p", "type": "file.watcher.updated", "data": {"x": "'
        + b"z" * (2 * MIB)
        + b'"}}\n\n'
    )
    assert i.accept(truncated([plugin])) is None
    assert i.revision_for(REF) == 1 and not i.closed


@pytest.mark.parametrize(
    "prefix",
    [
        b"data: not json at all",
        b'data: {"created": 1, "data": {"sessionID": "x"',
        b'data: {"id": "evt_c", "type": "server.connected", "data": {"pad": "',
        b'data: {"id": "evt_l", "type": "session.tool.success", "location": "/x", "data": {"',
    ],
)
def test_structurally_broken_oversized_frame_still_ends_the_generation(prefix):
    i = index_for(REF, OTHER)
    with pytest.raises(ContractError, match="invalid_frame"):
        i.accept(truncated([prefix, b"z" * (2 * MIB), b"\n\n"]))
    assert i.closed


def test_conflicting_visible_scope_in_a_discarded_prefix_still_ends_the_generation():
    i = index_for(REF, OTHER)
    with pytest.raises(ContractError, match="conflicting"):
        i.accept(truncated(oversized_chunks(REF, 2 * MIB, directory="/foreign")))
    assert i.closed


async def test_oversized_event_invalidates_this_roots_proof_and_a_fresh_get_restores_it():
    p, t, d, _ = await leaf_setup()
    p.feed.references = (REF, OTHER)
    p.feed.index = index_for(REF, OTHER)
    try:
        await p.watch(REF)
        info = digest(d["session.get"]["data"])
        proof = await p.prove(REF, INSTALLED_SCHEMA, info)
        assert p.feed.index.accept(truncated(oversized_chunks(REF, 2 * MIB))) is None
        # Work holding the old proof defers; the Root keeps its watch and owner.
        assert not p.valid_fence(REF, proof.resource_fence)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == proof.connection_epoch
        assert p.holds_watch(REF)
        assert p.feed.index.revision_for(OTHER) == 0
        fresh = await p.prove(REF, INSTALLED_SCHEMA, info)
        assert p.valid_fence(REF, fresh.resource_fence)
        assert fresh.resource_fence != proof.resource_fence
    finally:
        await finish(p, t)


async def test_owner_change_after_an_oversized_event_still_ends_the_generation():
    result, stream = feed(list(oversized_chunks(REF, 2 * MIB)), receipts=Receipts())
    await result.start()
    try:
        await settle(result, stream, 0)
        assert not result.task.done()
        result.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
        with pytest.raises(ContractError, match="owner_changed"):
            await result.current_owner()
        assert result.index.closed
    finally:
        await close(result)


async def test_discarded_frame_before_the_connection_marker_is_rejected():
    i = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    with pytest.raises(ContractError):
        i.accept(truncated(oversized_chunks(REF, 2 * MIB)))
    assert i.closed
