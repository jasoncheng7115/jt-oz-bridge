import json
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.typing import TypingParameters, check_typing_write
from jt_oz_bridge.config import validate_endpoint
from jt_oz_bridge.domain.delivery import (
    DeliveryNotSent,
    DeliveryRateLimited,
    DeliveryRejected,
    check_original_write_witness,
)
from jt_oz_bridge.security.network_logging import protect_network_logs


class ZulipError(ValueError):
    pass


class ZulipSourceUnavailable(ZulipError):
    """A verified original-message 400/404; no replacement Source is inferred."""


class ZulipAuthenticationFailed(ZulipError):
    """Credential/authorization rejection; never a transient GET outage."""


class ZulipReadUnavailable(ZulipError):
    """Transient GET failure; never evidence that a write can be replayed."""


@dataclass(frozen=True)
class ZulipAttestation:
    """Trusted installed-server enrollment, never derived from a chat command."""

    url: str
    realm_id: str
    bot_user_id: int
    feature_level: int
    max_message_length: int
    max_topic_length: int
    verified_file_operations: frozenset[str] = frozenset()
    verified_scope_operations: frozenset[str] = frozenset()
    verified_event_operations: frozenset[str] = frozenset()


class ZulipClient:
    def __init__(
        self,
        url: str,
        email: str,
        api_key: str,
        *,
        attestation: ZulipAttestation | None = None,
        verify_identity: Callable[[], Awaitable[bool]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        budget: ZulipRequestBudget | None = None,
    ) -> None:
        validate_endpoint(url, False)
        protect_network_logs()
        self.url = url
        self.typing_parameters: TypingParameters | None = None
        self.budget = budget
        if attestation and (
            attestation.url.rstrip("/") != url.rstrip("/")
            or attestation.bot_user_id <= 0
            or not attestation.realm_id
        ):
            raise ZulipError("enrollment_scope_mismatch")
        self.attestation, self.verify_identity = attestation, verify_identity
        self.client = httpx.AsyncClient(
            base_url=url.rstrip("/") + "/api/v1/",
            auth=httpx.BasicAuth(email, api_key),
            timeout=httpx.Timeout(90, connect=10),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def request(self, method: str, route: str, **kwargs: Any) -> dict[str, Any]:
        message_route = re.fullmatch(r"messages/[1-9][0-9]{0,17}", route) is not None
        scope_operation = next(
            (
                operation
                for pattern, operation in (
                    (r"users/me/subscriptions", "channel.info"),
                    (r"users", "user.info"),
                    (r"streams/[1-9][0-9]{0,17}", "channel.info"),
                    (r"streams/[1-9][0-9]{0,17}/members", "channel.members"),
                    (r"users/[1-9][0-9]{0,17}", "user.info"),
                    (r"users/me/[1-9][0-9]{0,17}/topics", "topic.list"),
                )
                if method == "GET" and re.fullmatch(pattern, route)
            ),
            None,
        )
        if method == "GET" and route in {"users", "users/me/subscriptions"}:
            params = kwargs.get("params")
            if type(params) is not dict:
                raise ZulipError("bounded_bulk_scope_parameters_required")
            if route == "users":
                if (
                    set(params) != {"user_ids", "client_gravatar", "include_custom_profile_fields"}
                    or params["client_gravatar"] != "false"
                    or params["include_custom_profile_fields"] != "false"
                    or type(params["user_ids"]) is not str
                    or len(params["user_ids"]) > 220000
                ):
                    raise ZulipError("explicit_numeric_user_filter_required")
                try:
                    ids = json.loads(params["user_ids"])
                except (ValueError, RecursionError):
                    raise ZulipError("explicit_numeric_user_filter_required") from None
                if (
                    type(ids) is not list
                    or not 1 <= len(ids) <= 10000
                    or any(type(v) is not int or not 0 < v < 10**18 for v in ids)
                    or len(set(ids)) != len(ids)
                ):
                    raise ZulipError("explicit_numeric_user_filter_required")
            elif (
                params != {"include_subscribers": "true"}
                or self.attestation is None
                or not {"channel.info", "channel.members"}
                <= self.attestation.verified_scope_operations
            ):
                raise ZulipError("complete_subscription_scope_required")
        upload_route = False
        if method == "GET" and route.startswith("user_uploads/"):
            from jt_oz_bridge.adapters.zulip.uploads import upload_reference

            upload_route = upload_reference("/" + route, self.url).api_route == route
        mutation = (method, route) == ("POST", "messages") or (method == "PATCH" and message_route)
        if (
            (method, route)
            not in {
                ("GET", "server_settings"),
                ("GET", "events"),
                ("POST", "register"),
                ("GET", "messages"),
                ("GET", "users/me"),
                ("POST", "messages"),
                ("POST", "typing"),
                ("DELETE", "events"),
            }
            and not (method in {"GET", "PATCH"} and message_route)
            and not upload_route
            and scope_operation is None
        ):
            raise ZulipError("route_not_allowed")
        if not kwargs.keys() <= {"params", "data"}:
            raise ZulipError("request_override_not_allowed")
        try:
            encoded = json.dumps(kwargs, allow_nan=False)
            if len(encoded.encode()) > 32 * 1024 * 1024:
                raise ZulipError("request_too_large")
            kwargs = json.loads(encoded)
        except (TypeError, ValueError, RecursionError):
            raise ZulipError("invalid_request_encoding") from None
        typing = (method, route) == ("POST", "typing")
        if typing and (
            self.typing_parameters is None
            or self.attestation is None
            or self.attestation.feature_level < 248
            or self.verify_identity is None
            or not await self.verify_identity()
        ):
            raise ZulipError("typing_not_attested")
        if mutation and (
            not self.attestation or not self.verify_identity or not await self.verify_identity()
        ):
            raise ZulipError("message_mutation_not_attested")
        if (method, route) == ("DELETE", "events") and (
            self.attestation is None
            or "cleanup" not in self.attestation.verified_event_operations
            or self.verify_identity is None
            or not await self.verify_identity()
        ):
            raise ZulipError("event_cleanup_not_attested")
        if upload_route and (
            not self.attestation
            or "download" not in self.attestation.verified_file_operations
            or not self.verify_identity
            or not await self.verify_identity()
        ):
            raise ZulipError("file_download_contract_not_attested")
        if scope_operation is not None:
            guard = self.verify_identity
            scoped = getattr(type(guard), "scope_read", None)
            if (
                self.attestation is None
                or scope_operation not in self.attestation.verified_scope_operations
                or guard is None
                or not await (scoped(guard) if callable(scoped) else guard())
            ):
                raise ZulipError("scope_read_contract_or_identity_not_attested")
        try:
            sequence = self.budget.acquire() if self.budget is not None else 0
            if typing:
                check_typing_write()
            if mutation:
                # No await between this final check and starting HTTP. Identity
                # verification above may have yielded after the worker's claim.
                check_original_write_witness()
            async with self.client.stream(method, route, **kwargs) as response:
                payload = bytearray()
                async for part in response.aiter_bytes():
                    payload.extend(part)
                    if len(payload) > 8 * 1024 * 1024:
                        raise ZulipError("response_too_large")
                if method == "GET" and response.status_code in {500, 502, 503, 504}:
                    # A restarting proxy may return HTML. Classify the bounded
                    # read before JSON decoding, without retaining its body.
                    raise ZulipReadUnavailable("zulip_read_service_unavailable")
                data = json.loads(payload)
            if not isinstance(data, dict):
                raise ZulipError("schema_mismatch")
            if response.status_code == 429:
                if data.get("result") != "error" or data.get("code") != "RATE_LIMIT_HIT":
                    raise ZulipError("unverified_rate_limit_response")
                try:
                    retry = float(response.headers.get("retry-after", data.get("retry-after", 60)))
                except ValueError:
                    retry = 60
                if not math.isfinite(retry):
                    retry = 60
                retry = max(1, min(3600, retry))
                if self.budget is not None:
                    self.budget.rate_limited(retry)
                raise DeliveryRateLimited(retry)
            if response.status_code in {401, 403}:
                if mutation and data.get("result") == "error":
                    raise DeliveryRejected("zulip_authentication_rejected")
                raise ZulipAuthenticationFailed("authentication_failed")
            if (
                method == "GET"
                and re.fullmatch(r"messages/[0-9]+", route)
                and response.status_code in {400, 404}
                and data.get("result") == "error"
            ):
                raise ZulipSourceUnavailable("original_message_unavailable")
            if data.get("code") == "BAD_EVENT_QUEUE_ID":
                raise ZulipError("queue_expired")
            if response.status_code != 200 or data.get("result") != "success":
                if (
                    mutation
                    and response.status_code in {400, 404}
                    and data.get("result") == "error"
                ):
                    raise DeliveryRejected("zulip_message_rejected")
                raise ZulipError("upstream_rejected")
            if data.get("ignored_parameters_unsupported"):
                raise ZulipError("upstream_ignored_required_parameters")
            if self.budget is not None:
                self.budget.observe(response.headers, sequence)
            return data
        except httpx.TransportError:
            if method == "GET":
                raise ZulipReadUnavailable("zulip_read_transport_unavailable") from None
            raise ZulipError("transport_or_schema_error") from None
        except (httpx.HTTPError, ValueError, TypeError, RecursionError) as error:
            if isinstance(
                error, (ZulipError, DeliveryRateLimited, DeliveryRejected, DeliveryNotSent)
            ):
                raise
            raise ZulipError("transport_or_schema_error") from None

    async def server_settings(self) -> dict[str, Any]:
        return await self.request("GET", "server_settings")

    async def register_events(self, *, typing_status: bool = False) -> dict[str, Any]:
        self.typing_parameters = None
        registration = await self.request(
            "POST",
            "register",
            data={
                "event_types": json.dumps(
                    [
                        "message",
                        "update_message",
                        "delete_message",
                        "heartbeat",
                        "stream",
                        "subscription",
                        "realm_user",
                        "realm",
                    ]
                ),
                "fetch_event_types": json.dumps(["realm"]) if typing_status else "[]",
                "all_public_streams": "false",
                "apply_markdown": "false",
                "client_gravatar": "false",
            },
        )

        if typing_status:
            self.typing_parameters = TypingParameters.parse(registration)
        return registration

    async def events(
        self, queue_id: str, last_event_id: int, *, dont_block: bool = False
    ) -> dict[str, Any]:
        return await self.request(
            "GET",
            "events",
            params={
                "queue_id": queue_id,
                "last_event_id": last_event_id,
                "dont_block": "true" if dont_block else "false",
            },
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def delete_events(self, queue_id: str) -> dict[str, Any]:
        if (
            self.attestation is None
            or "cleanup" not in self.attestation.verified_event_operations
            or self.verify_identity is None
            or not await self.verify_identity()
        ):
            raise ZulipError("event_cleanup_not_attested")
        return await self.request("DELETE", "events", params={"queue_id": queue_id})

    async def temporary_file_url(self, upload_path: str) -> str:
        from jt_oz_bridge.adapters.zulip.uploads import upload_reference
        from jt_oz_bridge.security.downloads import checked_url

        reference = upload_reference(upload_path, self.url)
        data = await self.request("GET", reference.api_route)
        value = data.get("url")
        if not isinstance(value, str) or not value or len(value) > 16384:
            raise ZulipError("temporary_file_url_contract_mismatch")
        try:
            if value.startswith("/"):
                # The pinned self-hosted endpoint returns reverse()'s relative
                # unauthed-file URL, not an absolute signed download URL.
                if not value.startswith("/user_uploads/"):
                    raise ValueError("unexpected_relative_file_route")
                value = self.url.rstrip("/") + value
            absolute = checked_url(value)
        except ValueError:
            raise ZulipError("temporary_file_url_contract_mismatch") from None
        # This only resolves URL syntax. SafeDownloader still applies explicit
        # origin/DNS/path policy with no Bot credentials, including redirects.
        return str(absolute)  # Immediate consumption only; never persist or log it.
