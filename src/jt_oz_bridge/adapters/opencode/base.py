from typing import Any, Protocol

import httpx

from jt_oz_bridge.config import validate_endpoint
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.security.network_logging import protect_network_logs


class UpstreamError(ValueError):
    """Safe code only; never propagates upstream response bodies or credential URLs."""


class OpenCodeAdapter(Protocol):
    async def probe(self) -> dict[str, Any]: ...
    def capabilities(self) -> dict[str, Capability]: ...


class ReadOnlyTransport:
    def __init__(
        self,
        base_url: str,
        *,
        auth: httpx.Auth | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        validate_endpoint(base_url)
        protect_network_logs()
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            auth=auth,
            timeout=15,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def get_object(self, route: str) -> dict[str, Any]:
        if route not in {"global/health", "api/info"}:
            raise UpstreamError("route_not_allowed")
        try:
            async with self.client.stream("GET", route) as response:
                if response.status_code in {401, 403}:
                    raise UpstreamError("authentication_failed")
                if response.status_code != 200:
                    raise UpstreamError("unexpected_status")
                payload = bytearray()
                async for part in response.aiter_bytes():
                    payload.extend(part)
                    if len(payload) > 1024 * 1024:
                        raise UpstreamError("response_too_large")
                import json

                data = json.loads(payload)
                if not isinstance(data, dict):
                    raise UpstreamError("schema_mismatch")
                return data
        except (httpx.HTTPError, ValueError) as error:
            if isinstance(error, UpstreamError):
                raise
            raise UpstreamError("transport_or_schema_error") from None

    async def close(self) -> None:
        await self.client.aclose()

    def capabilities(self) -> dict[str, Capability]:
        return {
            name: Capability(scope="backend", reason="installed_contract_not_certified")
            for name in [
                "bind",
                "prompt",
                "interrupt",
                "permission_reply",
                "form_reply",
                "files",
                "git",
                "models",
                "events",
            ]
        }
