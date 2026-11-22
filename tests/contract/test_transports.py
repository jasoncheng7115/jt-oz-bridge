import json

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.base import UpstreamError
from jt_oz_bridge.adapters.opencode.v1 import OpenCodeV1Adapter
from jt_oz_bridge.adapters.opencode.v2 import OpenCodeV2Adapter
from jt_oz_bridge.adapters.zulip.client import ZulipClient, ZulipError, ZulipReadUnavailable


async def test_v1_probe_is_read_only_and_not_identity_certification():
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"healthy": True, "version": "fixture-only"})

    client = OpenCodeV1Adapter("http://127.0.0.1:4096", transport=httpx.MockTransport(handle))
    try:
        result = await client.probe()
        assert result["certified"] is False and result["identity_verified"] is False
        assert str(seen[0].url).endswith("/global/health")
        assert all(request.method == "GET" for request in seen)
        assert not any(cap.supported for cap in client.capabilities().values())
    finally:
        await client.close()


@pytest.mark.parametrize("status", [401, 403, 302, 404])
async def test_no_protocol_fallback_or_redirect_on_error(status):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(
            status, headers={"location": "https://evil.invalid"}, json={"password": "SECRET"}
        )

    client = OpenCodeV1Adapter("https://private.invalid", transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(UpstreamError) as error:
            await client.probe()
        assert len(seen) == 1 and "SECRET" not in str(error.value)
    finally:
        await client.close()


async def test_v2_keeps_separate_route_and_does_not_guess_identity():
    def handle(request):
        assert request.url.path == "/api/info"
        return httpx.Response(200, json={"unknown_schema": "do-not-expose"})

    client = OpenCodeV2Adapter("https://private.invalid", transport=httpx.MockTransport(handle))
    try:
        result = await client.probe()
        assert result["certified"] is False
        assert "do-not-expose" not in str(result)
    finally:
        await client.close()


async def test_zulip_registration_form_and_queue_expiry():
    def handle(request):
        if request.url.path.endswith("/register"):
            assert request.method == "POST"
            assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
            assert b"event_types=" in request.content
            return httpx.Response(
                200, json={"result": "success", "queue_id": "fixture", "last_event_id": -1}
            )
        return httpx.Response(400, json={"result": "error", "code": "BAD_EVENT_QUEUE_ID"})

    client = ZulipClient(
        "https://zulip.invalid",
        "bot@example.invalid",
        "test-only",
        transport=httpx.MockTransport(handle),
    )
    try:
        assert (await client.register_events())["queue_id"] == "fixture"
        with pytest.raises(ZulipError, match="queue_expired"):
            await client.events("expired", 1)
    finally:
        await client.close()


def test_fixture_provenance_hashes():
    import hashlib
    from pathlib import Path

    path = Path("tests/fixtures/contracts")
    manifest = json.loads((path / "manifest.json").read_text())
    for item in manifest["fixtures"]:
        assert hashlib.sha256((path / item["path"]).read_bytes()).hexdigest() == item["sha256"]
        assert item["verification"] == "documentation_derived_not_live"


async def test_absolute_urls_cannot_forward_credentials():
    def handle(request):
        pytest.fail("unsafe request reached transport")

    transport = httpx.MockTransport(handle)
    z = ZulipClient("https://zulip.invalid", "bot", "secret", transport=transport)
    o = OpenCodeV1Adapter("https://backend.invalid", transport=transport)
    try:
        with pytest.raises(ZulipError, match="route_not_allowed"):
            await z.request("GET", "https://evil.invalid")
        with pytest.raises(UpstreamError, match="route_not_allowed"):
            await o.get_object("https://evil.invalid")
    finally:
        await z.close()
        await o.close()


@pytest.mark.parametrize("status", [500, 502, 503, 504])
@pytest.mark.parametrize("encoding", ["json", "html"])
async def test_zulip_unavailable_get_is_typed_without_retrying_or_retaining_error_body(
    status, encoding
):
    seen = []

    def handle(request):
        seen.append(request)
        return (
            httpx.Response(status, json={"result": "error", "msg": "PRIVATE_UPSTREAM_ERROR"})
            if encoding == "json"
            else httpx.Response(status, text="<html>PRIVATE_UPSTREAM_ERROR</html>")
        )

    c = ZulipClient("https://zulip.invalid", "bot", "secret", transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(ZulipReadUnavailable) as error:
            await c.events("same-queue", 123)
        assert len(seen) == 1 and "PRIVATE_" not in str(error.value)
    finally:
        await c.close()


@pytest.mark.parametrize("status", [200, 302, 400, 401, 403, 404, 429, 501])
async def test_other_read_failures_do_not_gain_transient_retry_authority(status):
    c = ZulipClient(
        "https://zulip.invalid",
        "bot",
        "secret",
        transport=httpx.MockTransport(lambda request: httpx.Response(status, text="PRIVATE_ERROR")),
    )
    try:
        with pytest.raises(ZulipError) as error:
            await c.events("same-queue", 123)
        assert not isinstance(error.value, ZulipReadUnavailable)
        assert "PRIVATE_" not in str(error.value)
    finally:
        await c.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "failure", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError]
)
async def test_only_get_transport_failures_are_transient_and_never_retried(method, failure):
    seen = []

    def handle(request):
        seen.append(request)
        raise failure("PRIVATE_ERROR", request=request)

    c = ZulipClient("https://zulip.invalid", "bot", "secret", transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(ZulipError) as error:
            await c.request(method, "events" if method == "GET" else "register")
        assert isinstance(error.value, ZulipReadUnavailable) == (method == "GET")
        assert len(seen) == 1 and "PRIVATE_" not in str(error.value)
    finally:
        await c.close()


@pytest.mark.parametrize("encoding", ["json", "html"])
async def test_registration_503_is_not_treated_as_a_retryable_read(encoding):
    seen = []

    def handle(request):
        seen.append(request)
        return (
            httpx.Response(503, json={"result": "error", "msg": "PRIVATE_ERROR"})
            if encoding == "json"
            else httpx.Response(503, text="PRIVATE_ERROR")
        )

    c = ZulipClient("https://zulip.invalid", "bot", "secret", transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(ZulipError) as error:
            await c.register_events()
        assert not isinstance(error.value, ZulipReadUnavailable) and len(seen) == 1
    finally:
        await c.close()


async def test_large_503_does_not_bypass_read_response_size_limit():
    c = ZulipClient(
        "https://zulip.invalid",
        "bot",
        "secret",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(503, content=b"x" * (8 * 1024 * 1024 + 1))
        ),
    )
    try:
        with pytest.raises(ZulipError, match="response_too_large") as error:
            await c.server_settings()
        assert not isinstance(error.value, ZulipReadUnavailable)
    finally:
        await c.close()
