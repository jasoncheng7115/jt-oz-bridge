import json
from urllib.parse import parse_qs

import httpx
import pytest

from jt_oz_bridge.adapters.zulip.client import (
    ZulipAttestation,
    ZulipClient,
    ZulipError,
    ZulipReadUnavailable,
)
from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway
from jt_oz_bridge.domain.delivery import DeliveryRateLimited, DeliveryRejected


async def identity():
    return True


def client(handle, **kwargs):
    return ZulipClient(
        "https://zulip.invalid",
        "fixture-bot",
        "fixture-key",
        attestation=ZulipAttestation("https://zulip.invalid", "realm", 77, 500, 10000, 60),
        verify_identity=identity,
        transport=httpx.MockTransport(handle),
        **kwargs,
    )


def message(**changes):
    return {
        "id": 123,
        "stream_id": 10,
        "subject": "Original",
        "sender_id": 77,
        "content": "Exact raw text",
        "content_type": "text/x-markdown",
        "type": "stream",
        **changes,
    }


async def test_unattested_message_mutations_never_reach_the_network():
    def fail(request):
        pytest.fail("unattested write reached network")

    c = ZulipClient(
        "https://zulip.invalid", "fixture-bot", "fixture-key", transport=httpx.MockTransport(fail)
    )
    try:
        with pytest.raises(ZulipError, match="not_attested"):
            await c.request("POST", "messages", data={"content": "private"})
        with pytest.raises(ZulipError, match="not_allowed"):
            await c.request("GET", "messages/123", auth="override")
    finally:
        await c.close()


async def test_numeric_channel_raw_content_and_local_echo_fields_preserve_literals():
    observed = []

    def handle(request):
        observed.append(request)
        if request.method == "POST":
            values = parse_qs(request.content.decode())
            assert values["to"] == ["10"] and values["content"] == ["  exact\noutput  "]
            assert values["queue_id"] == ["fixture-queue"] and values["local_id"] == [
                "jtoz:fixture"
            ]
            return httpx.Response(200, json={"result": "success", "id": 123})
        assert request.url.params["apply_markdown"] == "false"
        return httpx.Response(200, json={"result": "success", "message": message()})

    c = client(handle)
    gateway = ZulipGateway(c, queue_id="fixture-queue")
    try:
        assert await gateway.send(10, "Original", "  exact\noutput  ", "jtoz:fixture") == 123
        assert (await gateway.get(123)).content == "Exact raw text"
        assert len(observed) == 2
    finally:
        await c.close()


async def test_identity_guard_cannot_change_a_prepared_message():
    values = {"content": "previewed"}

    async def guard():
        values["content"] = "changed while checking identity"
        return True

    def handle(request):
        assert parse_qs(request.content.decode())["content"] == ["previewed"]
        return httpx.Response(200, json={"result": "success", "id": 123})

    c = client(handle)
    c.verify_identity = guard
    try:
        await c.request("POST", "messages", data=values)
    finally:
        await c.close()


@pytest.mark.parametrize(
    "status,data,expected",
    [
        (
            429,
            {"result": "error", "code": "RATE_LIMIT_HIT", "retry-after": 28.5},
            DeliveryRateLimited,
        ),
        (429, {"result": "error", "msg": "PRIVATE-MARKER"}, ZulipError),
        (400, {"result": "error", "msg": "PRIVATE-MARKER"}, DeliveryRejected),
        (403, {"result": "error", "msg": "PRIVATE-MARKER"}, DeliveryRejected),
        (500, {"result": "error", "msg": "PRIVATE-MARKER"}, ZulipError),
        (
            200,
            {"result": "success", "id": 123, "ignored_parameters_unsupported": ["to"]},
            ZulipError,
        ),
    ],
)
async def test_only_explicit_rate_limit_is_retryable_and_errors_never_echo_content(
    status, data, expected
):
    c = client(lambda request: httpx.Response(status, json=data))
    try:
        with pytest.raises(expected) as error:
            await c.request("POST", "messages", data={"content": "PRIVATE-MARKER"})
        assert "PRIVATE-MARKER" not in str(error.value)
        assert not isinstance(error.value, ZulipReadUnavailable)
        if isinstance(error.value, DeliveryRateLimited):
            assert error.value.retry_after == 28.5
    finally:
        await c.close()


@pytest.mark.parametrize(
    "raw",
    [message(content_type="text/html"), message(type="private"), message(id=True), message(id=124)],
)
async def test_wrong_or_rendered_single_messages_cannot_be_reconciliation_proof(raw):
    c = client(lambda request: httpx.Response(200, json={"result": "success", "message": raw}))
    try:
        with pytest.raises(ZulipError):
            await ZulipGateway(c).get(123)
    finally:
        await c.close()


async def test_history_is_bounded_narrowed_and_does_not_search_other_channels():
    def handle(request):
        narrow = json.loads(request.url.params["narrow"])
        assert narrow == [
            {"operator": "channel", "operand": 10},
            {"operator": "topic", "operand": "Original"},
        ]
        assert request.url.params["num_before"] == "100"
        return httpx.Response(
            200,
            json={
                "result": "success",
                "messages": [
                    message(content="body jtoz:fixture"),
                    message(id=124, sender_id=8, content="forged jtoz:fixture"),
                    message(id=125, stream_id=99, content="wrong channel jtoz:fixture"),
                ],
            },
        )

    c = client(handle)
    try:
        assert [item.id for item in await ZulipGateway(c).find(10, "Original", "jtoz:fixture")] == [
            123
        ]
    finally:
        await c.close()


@pytest.mark.parametrize(
    "method,route", [("GET", "server_settings"), ("POST", "messages"), ("PATCH", "messages/123")]
)
async def test_local_request_budget_refusal_is_before_http_for_reads_posts_and_edits(method, route):
    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget

    seen = []
    b = ZulipRequestBudget(requests=4, reserved=1)
    for _ in range(3):
        b.acquire()
    c = client(lambda request: seen.append(request), budget=b)
    try:
        with pytest.raises(RequestBudgetDeferred):
            await c.request(method, route, data={"content": "fixture"} if method != "GET" else {})
        assert not seen
    finally:
        await c.close()


async def test_verified_429_updates_shared_budget_and_does_not_automatically_retry_mutation():
    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget

    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(
            429, headers={"Retry-After": "2"}, json={"result": "error", "code": "RATE_LIMIT_HIT"}
        )

    b = ZulipRequestBudget(requests=10, reserved=2)
    c = client(handle, budget=b)
    try:
        with pytest.raises(DeliveryRateLimited):
            await c.request("POST", "messages", data={"content": "fixture"})
        assert len(seen) == 1 and b.rate_limits == 1 and b.capacity == 8
        with pytest.raises(RequestBudgetDeferred):
            await c.server_settings()
        assert len(seen) == 1
    finally:
        await c.close()


async def test_unverified_429_does_not_supply_adaptive_throttle_authority():
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget

    b = ZulipRequestBudget(requests=10, reserved=2)
    c = client(
        lambda request: httpx.Response(429, json={"result": "error", "code": "OTHER"}), budget=b
    )
    try:
        with pytest.raises(ZulipError, match="unverified_rate_limit"):
            await c.server_settings()
        assert b.rate_limits == 0 and b.capacity == 10
    finally:
        await c.close()
