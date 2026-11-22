"""Native resource history, not a Human/TUI/phone or durable-replay certificate."""

import copy
from dataclasses import replace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.transcript import (
    NativeTranscriptPage,
    V2TranscriptReader,
    project_message,
)
from jt_oz_bridge.domain.control import ExecutionState
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_public_live_feed import REAL, frame, text_delta
from tests.contract.test_turn_resources import setup


async def prepared(hook=None):
    p, t, d, messages, qualified, _ = await setup()
    reads = []
    original = t.client._transport
    older = [
        {
            "id": "msg_old_" + str(i),
            "type": "user",
            "time": {"created": 900 - i},
            "text": "original input " + str(i),
        }
        for i in range(25)
    ]
    all_messages = messages + older

    def handler(request):
        if request.url.path.endswith("/message") and request.url.params.get("limit") != "1":
            assert request.method == "GET"
            # Installed session.message.list rejects these together, even
            # though their individual OpenAPI field schemas accept strings.
            if "cursor" in request.url.params and "order" in request.url.params:
                return httpx.Response(400, json={"error": "cursor_and_order"})
            reads.append(request)
            start = (
                int(request.url.params["cursor"].removeprefix("opaque:"))
                if "cursor" in request.url.params
                else 0
            )
            count = int(request.url.params["limit"])
            value = {"data": copy.deepcopy(all_messages[start : start + count]), "cursor": {}}
            if start + count < len(all_messages):
                value["cursor"]["next"] = "opaque:" + str(start + count)
            if hook:
                hook(len(reads), value, p, t, d)
            return httpx.Response(200, json=value)
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    return p, t, d, messages, V2TranscriptReader(qualified), reads


async def test_original_user_and_assistant_pages_follow_server_order_and_opaque_cursor():
    p, t, d, m, r, reads = await prepared()
    try:
        first = await r.capture(REF)
        assert r.current(first) and len(first.entries) == 20 and first.next_cursor == "opaque:20"
        second = await r.capture(REF, cursor=first.next_cursor)
        assert len(second.entries) == 8 and second.next_cursor is None
        assert [e.native_id for e in first.entries[:3]] == [e["id"] for e in m]
        # A deliberately later timestamp must not reorder an older native row.
        assert first.entries[3].projection()["time"]["created"] == 900
        assert len({e.native_id for e in (*first.entries, *second.entries)}) == 28
        assert all(
            "order" not in req.url.params
            if "cursor" in req.url.params
            else req.url.params["order"] == "desc"
            for req in reads
        )
        serialized = first.model_dump_json()
        assert "exact fixture text" in serialized and "Exact final answer" in serialized
        assert "NEVER_RETAIN" not in serialized
        assert "jt_oz_bridge" not in serialized
        copy_value = first.entries[1].projection()
        copy_value["content"].clear()
        assert first.entries[1].projection()["content"]
        assert not r.current(NativeTranscriptPage.model_validate(first.model_dump()))
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change",
    [
        "duplicate",
        "empty-next",
        "same-cursor",
        "changed-page",
        "scope",
        "owner",
        "event",
        "qualification",
    ],
)
async def test_page_or_original_boundary_changes_never_yield_current_history(change):
    def hook(number, value, p, t, d):
        if change == "duplicate":
            value["data"][1] = copy.deepcopy(value["data"][0])
        elif change == "empty-next":
            value["data"] = []
            value["cursor"]["next"] = "next"
        elif change == "same-cursor":
            value["cursor"]["next"] = "opaque:20"
        elif change == "changed-page" and number == 2:
            value["data"][-1]["text"] = "changed between observations"
        elif change == "scope" and number == 1:
            d["session.get"]["data"]["location"]["directory"] = "/foreign"
        elif change == "owner" and number == 1:
            p.feed.owner.read.side_effect = ContractError("owner_lost")
        elif change == "event" and number == 1:
            p.feed.index.accept(frame(REAL[0]))
        elif change == "qualification" and number == 1:
            r.qualified.attestation = None

    p, t, d, m, r, reads = await prepared(hook)
    try:
        with pytest.raises((ContractError, ValueError)):
            await r.capture(REF, cursor="opaque:20" if change == "same-cursor" else None)
        assert not r._pages
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "cursor,limit", [(None, True), (None, 0), (None, 21), ("", 10), ("x" * 8193, 10), (1, 10)]
)
async def test_invalid_page_request_rejected_before_native_requests(cursor, limit):
    p, t, d, m, r, reads = await prepared()
    try:
        with pytest.raises(ValueError):
            await r.capture(REF, cursor=cursor, limit=limit)
        assert not reads
    finally:
        await finish(p, t)


async def test_active_history_does_not_need_the_original_busy_period_to_finish():
    def hook(number, value, p, t, d):
        p.feed.index.accept(frame(text_delta("evt_history_delta_" + str(number))))

    p, t, d, m, r, reads = await prepared(hook)
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    try:
        page = await r.capture(REF, limit=10)
        assert page.state == ExecutionState.RUNNING and r.current(page)
        assert page.entries[2].kind == "user"
        p.feed.index.accept(frame(REAL[0]))
        assert not r.current(page)
    finally:
        await finish(p, t)


async def test_current_page_expires_and_qualification_replacement_revokes_it(monkeypatch):
    p, t, d, m, r, reads = await prepared()
    try:
        page = await r.capture(REF)
        original = r.qualified.attestation
        r.qualified.attestation = replace(original)
        assert not r.current(page)
        r.qualified.attestation = original
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.transcript.time.time", lambda: page.expires_at + 1
        )
        assert not r.current(page)
    finally:
        await finish(p, t)


async def test_unenrolled_reference_cannot_read_native_messages():
    p, t, d, m, r, reads = await prepared()
    try:
        with pytest.raises(ContractError):
            await r.capture(REF.model_copy(update={"canonical_directory": "/foreign"}))
        assert not reads
    finally:
        await finish(p, t)


def test_tool_summary_keeps_status_and_exit_without_private_body():
    raw = {
        "id": "msg_tool",
        "type": "assistant",
        "time": {"created": 1},
        "agent": "build",
        "model": {"id": "fixture", "providerID": "fixture"},
        "content": [
            {"type": "reasoning", "text": "PRIVATE_REASONING"},
            {
                "type": "tool",
                "id": "tool_1",
                "name": "bash",
                "time": {"created": 1},
                "state": {
                    "status": "completed",
                    "input": {"command": "PRIVATE_COMMAND"},
                    "content": [{"type": "text", "text": "PRIVATE_OUTPUT"}],
                    "metadata": {"exit": 17},
                },
            },
        ],
    }
    entry = project_message(raw)
    assert "PRIVATE_" not in entry.projection_json
    tool = entry.projection()["content"][0]
    assert tool["status"] == "completed" and tool["exit_code"] == 17
    assert tool["index"] == 1
