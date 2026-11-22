"""Bounded unauthenticated retrieval of immediately consumed signed file URLs."""

import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

import httpx

from jt_oz_bridge.security.downloads import DownloadDenied, DownloadPolicy, checked_url, origin_key
from jt_oz_bridge.security.network_logging import protect_network_logs


@dataclass
class Download:
    mime_type: str
    declared_size: int | None
    _response: httpx.Response = field(repr=False)
    _maximum: int = field(repr=False)
    _consumed: bool = field(default=False, repr=False)

    async def chunks(self) -> AsyncIterator[bytes]:
        if self._consumed:
            raise DownloadDenied("download_stream_already_consumed")
        self._consumed = True
        received = 0
        try:
            async for chunk in self._response.aiter_bytes(chunk_size=65536):
                received += len(chunk)
                if received > self._maximum or (
                    self.declared_size is not None and received > self.declared_size
                ):
                    raise DownloadDenied("download_body_exceeds_limit")
                yield chunk
        except httpx.HTTPError:
            raise DownloadDenied("download_stream_failed") from None
        if self.declared_size is not None and received != self.declared_size:
            raise DownloadDenied("download_size_mismatch")


class SafeDownloader:
    def __init__(
        self,
        policy: DownloadPolicy,
        *,
        maximum_file_bytes: int = 20 * 1024**2,
        allow_cross_origin_redirects: bool = False,
        ca_file: Path | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not 0 < maximum_file_bytes <= 128 * 1024**2:
            raise ValueError("invalid download limit")
        protect_network_logs()
        self.policy, self.maximum, self.cross_origin = (
            policy,
            maximum_file_bytes,
            allow_cross_origin_redirects,
        )
        verify = ssl.create_default_context(cafile=str(ca_file)) if ca_file else True
        self.client = httpx.AsyncClient(
            verify=verify,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(60, connect=10),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
            transport=transport,
        )

    @asynccontextmanager
    async def open(self, value: str) -> AsyncIterator[Download]:
        original_origin = None
        for attempt in range(4):
            candidate = checked_url(value)
            if original_origin is None:
                original_origin = origin_key(candidate)
            elif origin_key(candidate) != original_origin and not self.cross_origin:
                raise DownloadDenied("cross_origin_download_redirect_disabled")
            original, pinned = await self.policy.pin(value)
            request = self.client.build_request(
                "GET",
                pinned,
                headers={"host": original.netloc.decode("ascii"), "accept-encoding": "identity"},
                extensions={"sni_hostname": original.raw_host.decode("ascii")},
            )
            request.headers.pop("cookie", None)
            request.headers.pop("authorization", None)
            # No Bot credentials exist in this client. Signed URLs stay in memory.
            try:
                response = await self.client.send(request, stream=True, auth=None)
            except httpx.HTTPError:
                raise DownloadDenied("download_connection_or_tls_failed") from None
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                await response.aclose()
                if not location or attempt == 3:
                    raise DownloadDenied("download_redirect_limit_or_location_invalid")
                value = urljoin(str(original), location)
                continue
            try:
                if response.status_code != 200:
                    raise DownloadDenied("download_rejected")
                if response.headers.get("content-encoding", "identity").lower() not in {
                    "",
                    "identity",
                }:
                    raise DownloadDenied("encoded_download_response_not_allowed")
                length = response.headers.get("content-length")
                if length is not None and (not length.isdigit() or int(length) > self.maximum):
                    raise DownloadDenied("download_declared_size_rejected")
                declared = int(length) if length is not None else None
                mime_type = (
                    response.headers.get("content-type", "application/octet-stream")
                    .partition(";")[0]
                    .strip()
                    .lower()
                )
                yield Download(mime_type, declared, response, self.maximum)
                return
            finally:
                await response.aclose()

    async def close(self) -> None:
        await self.client.aclose()
