import asyncio
import json
from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.log import DurableLogItem, LogRead, LogSynced
from jt_oz_bridge.adapters.opencode.sse import SSEFrame, SSEParser
from jt_oz_bridge.adapters.opencode.transport import TransportError, V2HTTPTransport
from tests.support import REF


def frame(value):
    return SSEFrame("message", json.dumps(value))


def event(seq=0, **changes):
    return {
        "id": "evt_original",
        "type": "session.renamed",
        "created": 123,
        "durable": {"aggregateID": REF.upstream_session_id, "seq": seq, "version": 1},
        "location": {"directory": REF.canonical_directory},
        "data": {"sessionID": REF.upstream_session_id, "title": "Original"},
        **changes,
    }


@pytest.mark.parametrize("width", [1, 2, 3, 9, 65536])
def test_sse_chunk_boundaries_bom_utf8_crlf_comments_and_multiple_lines(width):
    data = (
        "\ufeff: heartbeat\r\nid: source-id\r\nevent: message\r\n"
        'data: {"note":\r\ndata: "繁體中文"}\r\n\r\n'
        ": idle\n\ndata: second\r\rdata: truncated"
    ).encode()
    parser, output = SSEParser(), []
    for i in range(0, len(data), width):
        output.extend(parser.feed(data[i : i + width]))
    parser.finish()
    assert output == [
        SSEFrame("message", '{"note":\n"繁體中文"}', "source-id"),
        SSEFrame("message", "second", "source-id"),
    ]


def test_sse_empty_data_unknown_fields_and_nul_id_do_not_change_identity():
    parser = SSEParser()
    assert list(
        parser.feed(b"id: original\n\nretry: 0\nfuture: ignored\nid: bad\x00id\ndata:\n\n")
    ) == [SSEFrame("message", "", "original")]


def test_sse_bounds_comments_and_data_and_rejects_invalid_utf8():
    with pytest.raises(ContractError, match="too_large"):
        list(SSEParser(12).feed(b": unbounded comment"))
    with pytest.raises(ContractError, match="utf8"):
        list(SSEParser().feed(b"data: \xff\n\n"))
    parser = SSEParser(12)
    assert len(list(parser.feed(b"data: x\n\n" * 100))) == 100


def test_durable_log_allows_filtered_sequence_gaps_and_later_sync_watermark():
    read = LogRead(REF, 1)
    assert isinstance(read.accept(frame(event(3))), DurableLogItem)
    assert isinstance(read.accept(frame(event(4))), DurableLogItem)
    assert isinstance(
        read.accept(
            frame({"type": "log.synced", "aggregateID": REF.upstream_session_id, "seq": 6})
        ),
        LogSynced,
    )
    assert read.position == 6 and read.synced
    read.accept(frame(event(8)))
    assert read.position == 8
    with pytest.raises(ContractError, match="increasing"):
        read.accept(frame(event(8)))


def test_empty_migrated_log_and_replayed_sync_markers_are_not_invented_cursors():
    marker = frame({"type": "log.synced", "aggregateID": REF.upstream_session_id})
    read = LogRead(REF)
    read.accept(marker)
    assert read.position is None and read.synced
    with pytest.raises(ContractError):
        read.accept(marker)
    with pytest.raises(ContractError):
        LogRead(REF, 2).accept(marker)
    with pytest.raises(ContractError, match="regressed"):
        LogRead(REF, 2).accept(
            frame({"type": "log.synced", "aggregateID": REF.upstream_session_id, "seq": 1})
        )


@pytest.mark.parametrize(
    "raw",
    [
        event(data={"sessionID": "other"}),
        event(location={"directory": "/other-project"}),
        event(durable={"aggregateID": "other", "seq": 0, "version": 1}),
        event(durable={"aggregateID": REF.upstream_session_id, "seq": True, "version": 1}),
        event(created=float("nan")),
        "PRIVATE-MARKER",
    ],
)
def test_unknown_or_wrong_session_envelopes_fail_without_echoing_payload(raw):
    with pytest.raises(ContractError) as error:
        LogRead(REF).accept(frame(raw))
    assert "PRIVATE-MARKER" not in str(error.value)


class PausingStream(httpx.AsyncByteStream):
    def __init__(self, payload):
        self.payload, self.closed, self.more = payload, False, asyncio.Event()

    async def __aiter__(self):
        yield self.payload
        await self.more.wait()

    async def aclose(self):
        self.closed = True


async def test_small_live_frame_is_yielded_before_eof_or_64k_and_stream_is_closed():
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.30-openapi.json")
    )
    stream = PausingStream(b'data: {"type":"example"}\n\n')
    captured = []

    def handle(request):
        captured.append(request)
        return httpx.Response(
            200, headers={"content-type": "text/event-stream; charset=utf-8"}, stream=stream
        )

    client = V2HTTPTransport(
        "http://127.0.0.1:4096", profile, transport=httpx.MockTransport(handle)
    )
    events = client.events(
        "session.log", path={"sessionID": "ses_original"}, query={"after": "0", "follow": "true"}
    )
    try:
        item = await asyncio.wait_for(anext(events), 1)
        assert item.data == '{"type":"example"}'
        assert captured[0].url.params["after"] == "0"
    finally:
        await events.aclose()
        await client.close()
    assert stream.closed


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, headers={"content-type": "text/html"}, text="PRIVATE-MARKER"),
        httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text="event: effect/http-api/stream/failure\ndata: PRIVATE-MARKER\n\n",
        ),
        httpx.Response(401, json={"_tag": "UnauthorizedError", "message": "PRIVATE-MARKER"}),
    ],
)
async def test_stream_failure_content_type_and_auth_never_become_event_data(response):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.30-openapi.json")
    )
    client = V2HTTPTransport(
        "http://127.0.0.1:4096", profile, transport=httpx.MockTransport(lambda request: response)
    )
    try:
        with pytest.raises((TransportError, ContractError)) as error:
            _ = [item async for item in client.events("event.subscribe")]
        assert "PRIVATE-MARKER" not in str(error.value)
    finally:
        await client.close()


@pytest.mark.parametrize(
    "raw",
    [
        '{"type":"log.synced","aggregateID":"original-session","seq":1,"seq":2}',
        '{"type":"log.synced","aggregateID":"original-session","seq":1e400}',
        '{"type":"log.synced","aggregateID":"other","aggregateID":"original-session","seq":1}',
        '{"id":"evt_original","type":"session.renamed","created":1,"durable":{"aggregateID":"original-session","seq":1,"version":1},"data":{"sessionID":"original-session","nested":{"x":1,"x":2}}}',
    ],
)
def test_log_json_rejects_duplicate_authority_keys_and_nonfinite_extensions(raw):
    read = LogRead(REF)
    with pytest.raises(ContractError):
        read.accept(SSEFrame("message", raw))
    assert read.position is None and not read.synced
