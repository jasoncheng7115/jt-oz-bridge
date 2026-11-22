import logging

import httpx
import pytest

from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.security.downloads import DownloadDenied, DownloadOrigin, DownloadPolicy


class DNS:
    def __init__(self, addresses=("8.8.8.8",)):
        self.addresses, self.calls = addresses, []

    async def resolve(self, host, port):
        self.calls.append((host, port))
        return self.addresses


async def test_validated_ip_host_header_sni_and_signed_url_never_appear_in_logs(caplog):
    dns = DNS()
    policy = DownloadPolicy((DownloadOrigin("https://files.example"),), dns)

    def handle(request):
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == "files.example"
        assert request.extensions["sni_hostname"] == "files.example"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"exact bytes")

    download = SafeDownloader(policy, transport=httpx.MockTransport(handle))
    try:
        with caplog.at_level(logging.INFO):
            async with download.open(
                "https://files.example/file?signature=PRIVATE-MARKER"
            ) as response:
                assert b"".join([chunk async for chunk in response.chunks()]) == b"exact bytes"
                assert "PRIVATE-MARKER" not in repr(response)
        assert "PRIVATE-MARKER" not in caplog.text
        assert dns.calls == [("files.example", 443)]
    finally:
        await download.close()


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("169.254.169.254",),
        ("10.0.0.25",),
        ("8.8.8.8", "10.0.0.1"),
        ("::1",),
        ("::ffff:127.0.0.1",),
        ("fe80::1",),
        ("224.0.0.1",),
        ("0.0.0.0",),
        ("64:ff9b::a9fe:a9fe",),
        ("2002:a9fe:a9fe::1",),
    ],
)
async def test_private_metadata_mixed_dns_loopback_mapped_and_multicast_are_denied(addresses):
    policy = DownloadPolicy((DownloadOrigin("https://files.example"),), DNS(addresses))
    with pytest.raises(DownloadDenied):
        await policy.pin("https://files.example/file")


async def test_private_origin_exception_is_narrow_and_does_not_allow_another_private_host():
    origin = DownloadOrigin("https://chat.example", ("10.0.0.25/32",), ("/user_uploads/",))
    dns = DNS(("10.0.0.25",))
    policy = DownloadPolicy((origin,), dns)
    _, pinned = await policy.pin("https://chat.example/user_uploads/temporary/token")
    assert pinned.host == "10.0.0.25"
    dns.addresses = ("10.0.0.26",)
    with pytest.raises(DownloadDenied):
        await policy.pin("https://chat.example/user_uploads/token")
    dns.addresses = ("8.8.8.8",)
    with pytest.raises(DownloadDenied):
        await policy.pin("https://chat.example/user_uploads/token")
    with pytest.raises(DownloadDenied):
        await policy.pin("https://chat.example/login/")
    with pytest.raises(DownloadDenied):
        DownloadOrigin("https://chat.example", ("169.254.0.0/16",))


async def test_cross_origin_redirect_requires_enrollment_and_drops_all_cookies():
    dns = DNS()
    policy = DownloadPolicy(
        (DownloadOrigin("https://files.example"), DownloadOrigin("https://cdn.example")), dns
    )
    seen = []

    def handle(request):
        seen.append(request)
        assert "cookie" not in request.headers and "authorization" not in request.headers
        if len(seen) == 1:
            return httpx.Response(
                302,
                headers={
                    "location": "https://cdn.example/blob?signature=PRIVATE-MARKER",
                    "set-cookie": "private=PRIVATE-MARKER; Path=/",
                },
            )
        assert request.extensions["sni_hostname"] == "cdn.example"
        return httpx.Response(200, content=b"downloaded")

    client = SafeDownloader(
        policy, allow_cross_origin_redirects=True, transport=httpx.MockTransport(handle)
    )
    try:
        async with client.open("https://files.example/file") as response:
            assert b"".join([chunk async for chunk in response.chunks()]) == b"downloaded"
        assert len(seen) == 2 and len(dns.calls) == 2
    finally:
        await client.close()


async def test_redirect_is_denied_before_a_second_dns_lookup_when_cross_origin_is_disabled():
    dns = DNS()
    policy = DownloadPolicy(
        (DownloadOrigin("https://files.example"), DownloadOrigin("https://cdn.example")), dns
    )
    client = SafeDownloader(
        policy,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"location": "https://cdn.example/blob"})
        ),
    )
    try:
        with pytest.raises(DownloadDenied, match="cross_origin"):
            async with client.open("https://files.example/file"):
                pytest.fail("redirect followed")
        assert len(dns.calls) == 1
    finally:
        await client.close()


@pytest.mark.parametrize(
    "headers,body",
    [
        ({"content-length": "999"}, b"small"),
        ({"content-length": "1"}, b"too long"),
        ({"content-length": "-1"}, b"small"),
        ({"content-encoding": "gzip"}, b"invalid compressed body"),
        ({}, b"x" * 101),
    ],
)
async def test_download_size_and_encoding_errors_do_not_become_successful_files(headers, body):
    policy = DownloadPolicy((DownloadOrigin("https://files.example"),), DNS())
    client = SafeDownloader(
        policy,
        maximum_file_bytes=100,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers=headers, content=body)
        ),
    )
    try:
        with pytest.raises(DownloadDenied):
            async with client.open("https://files.example/file") as response:
                _ = [chunk async for chunk in response.chunks()]
    finally:
        await client.close()
