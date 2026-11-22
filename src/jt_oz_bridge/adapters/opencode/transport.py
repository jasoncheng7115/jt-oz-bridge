"""Contract-checked V2 HTTP transport, with mutations disabled without attestation."""

import json
import ssl
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never

import httpcore
import httpx

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.sse import SSEFrame, iter_sse
from jt_oz_bridge.config import validate_endpoint
from jt_oz_bridge.domain.execution import AnswerRejected, MutationRejected
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.network_logging import protect_network_logs

READ_OPERATIONS = frozenset(
    {
        "server.info",
        "location.get",
        "session.list",
        "session.get",
        "session.active",
        "session.context",
        "session.message.list",
        "session.message.get",
        "session.inbox.list",
        "session.diff",
        "session.form.list",
        "session.form.get",
        "session.permission.list",
        "session.permission.get",
        "permission.request.list",
        "project.list",
        "model.list",
        "model.default",
        "agent.list",
        "agent.get",
        "plugin.list",
        "permission.saved.list",
        "command.list",
        "skill.list",
        "mcp.list",
        "filesystem.read",
        "filesystem.list",
        "filesystem.find",
        "fs.list",
        "fs.find",
        "vcs.get",
        "vcs.base",
        "vcs.branch.list",
        "vcs.status",
        "vcs.diff",
        "worktree.list",
        "shell.list",
        "shell.get",
        "experimental.session.instructions.entry.list",
    }
)
MUTATION_OPERATIONS = frozenset(
    {
        "session.shell",
        "worktree.create",
        "session.prompt",
        "session.interrupt",
        "session.permission.reply",
        "session.form.reply",
        "session.form.cancel",
        "session.inbox.cancel",
        "session.inbox.update",
        "session.switchAgent",
        "session.switchModel",
        "session.command",
        "session.compact",
        "session.update",
        "session.create",
        "session.fork",
        "session.remove",
        "session.revert.stage",
        "session.revert.clear",
        "session.revert.commit",
        "experimental.session.instructions.entry.put",
    }
)

# V2 projects decoded attachment bytes back as Base64 in these JSON resources.
# A 20 MiB attachment needs ~27 MiB before JSON/metadata. All other resources
# retain their existing bound; catalog pages are never unlimited aggregates.
ATTACHMENT_JSON_RESPONSES = frozenset(
    {"session.prompt", "session.message.get", "session.message.list", "session.inbox.list"}
)


class TransportError(ValueError):
    pass


class TransportNotSent(TransportError):
    """The fixed transport rejected a mutation before opening its HTTP request."""


@dataclass(frozen=True)
class ContractAttestation:
    """Trusted enrollment input; never construct from chat/AI/request data.

    A public documentation hash alone does not justify this object. The registry
    must associate installed-contract tests, auth and backend identity evidence.
    """

    schema_sha256: str
    backend_identity: str
    upstream_version: str
    verified_operations: frozenset[str]


class _MutationSendBoundary:
    """One HTTP1 attempt; callbacks may only revalidate the same durable intent.

    HTTPCore's headers-started trace is after pool/connect/state-lock awaits.
    Body-started rechecks after any headers write wait. Neither is a distributed
    transaction with Native: once headers start, a failure stays uncertain, except
    a refusal at the start of a non-empty body. No body byte has left then, and a
    request is incomplete without the body its Content-Length announced, so
    Native cannot act on it: that send is known unsent.
    """

    def __init__(
        self,
        method: str,
        url: httpx.URL,
        body: bytes,
        attestation: ContractAttestation | None,
        current: Callable[[], ContractAttestation | None],
        authorize: Callable[[], Awaitable[None]] | None,
        ready: Callable[[], None] | None,
    ) -> None:
        self.method, self.url, self.body = method, url, body
        self.attestation, self.current = attestation, current
        self.authorize, self.ready = authorize, ready
        self.phase = "queued"

    def reject(self) -> Never:
        if self.phase == "queued":
            raise TransportNotSent("native_mutation_write_boundary_rejected") from None
        if self.phase == "body-check" and self.body:
            raise TransportNotSent("native_mutation_body_withheld") from None
        raise TransportError("native_mutation_write_outcome_unknown") from None

    async def guard(self) -> None:
        try:
            if self.current() is not self.attestation:
                self.reject()
            if self.authorize is not None:
                await self.authorize()
            if self.current() is not self.attestation:
                self.reject()
            if self.ready is not None:
                self.ready()
        except Exception:
            self.reject()

    async def request(self, request: httpx.Request, transport: httpx.AsyncBaseTransport) -> None:
        # Context-local state survives Auth constructing a new Request without
        # extensions. A second physical Auth request never acquires a new gate.
        if self.phase != "queued":
            self.reject()
        try:
            if (
                request.method != self.method
                or request.url != self.url
                or request.content != self.body
            ):
                self.reject()
        except Exception:
            self.reject()
        if type(transport) is httpx.MockTransport:
            # Synthetic compatibility only: Mock has no pool, connect or wire.
            await self.guard()
            self.phase = "mock-attempted"
            return
        pool = getattr(transport, "_pool", None)
        if (
            type(transport) is not httpx.AsyncHTTPTransport
            or type(pool) is not httpcore.AsyncConnectionPool
            or httpx.__version__ != "0.28.1"
            or httpcore.__version__ != "1.0.9"
            or getattr(pool, "_http1", None) is not True
            or getattr(pool, "_http2", None) is not False
            or getattr(pool, "_retries", None) != 0
        ):
            self.reject()
        request.extensions["trace"] = self.trace

    async def trace(self, name: str, _info: dict[str, Any]) -> None:
        # Never inspect/log trace info: it may contain credentials and bodies.
        if name == "http11.send_request_headers.started":
            if self.phase != "queued":
                self.reject()
            await self.guard()
            self.phase = "headers-attempted"
        elif name == "http11.send_request_body.started":
            if self.phase != "headers-attempted":
                self.reject()
            self.phase = "body-check"
            await self.guard()
            self.phase = "body-attempted"
        elif name == "http2.send_request_headers.started":
            self.reject()


class V2HTTPTransport:
    def __init__(
        self,
        url: str,
        profile: OpenAPIProfile,
        *,
        auth: httpx.Auth | None = None,
        attestation: ContractAttestation | None = None,
        ca_file: Path | None = None,
        verify_identity: Callable[[], Awaitable[bool]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        validate_endpoint(url)
        protect_network_logs()
        if attestation and attestation.schema_sha256 != profile.sha256:
            raise ContractError("attestation_contract_hash_mismatch")
        self.profile, self.attestation = profile, attestation
        self.verify_identity = verify_identity
        self._send_boundary: ContextVar[_MutationSendBoundary | None] = ContextVar(
            "native_mutation_send_boundary", default=None
        )
        verify = ssl.create_default_context(cafile=str(ca_file)) if ca_file else True
        self.client = httpx.AsyncClient(
            base_url=url.rstrip("/") + "/",
            auth=auth,
            verify=verify,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(30, connect=10),
            transport=transport,
            http2=False,
            event_hooks={"request": [self._request_boundary]},
        )

    async def _request_boundary(self, request: httpx.Request) -> None:
        boundary = self._send_boundary.get()
        if boundary is not None:
            await boundary.request(request, self.client._transport_for_url(request.url))

    async def request(
        self,
        operation_id: str,
        *,
        path: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        before_send: Callable[[], None] | None = None,
        authorize_send: Callable[[], Awaitable[None]] | None = None,
    ) -> Any:
        path = dict(path or {})
        prepared = self.profile.prepare(operation_id, path=path, query=query, body=body)
        mutation = prepared.method != "GET"
        allowed = MUTATION_OPERATIONS if mutation else READ_OPERATIONS
        if operation_id not in allowed:
            raise TransportNotSent("operation_not_allowed")
        if mutation and (
            not self.attestation or operation_id not in self.attestation.verified_operations
        ):
            raise TransportNotSent("installed_contract_not_attested")
        if mutation:
            captured_attestation = self.attestation
            try:
                verified = self.verify_identity is not None and await self.verify_identity()
            except Exception:
                raise TransportNotSent("backend_identity_verification_unavailable") from None
            if not verified:
                raise TransportNotSent("backend_identity_not_verified")
            if self.attestation is not captured_attestation:
                raise TransportNotSent("backend_attestation_changed")
        if operation_id in {"session.shell", "worktree.create"} and authorize_send is None:
            raise TransportNotSent("original_check_human_authority_required")
        if authorize_send is not None:
            if operation_id not in {"session.shell", "worktree.create"} or not mutation:
                raise TransportNotSent("check_authority_operation_mismatch")
            try:
                await authorize_send()
            except Exception:
                raise TransportNotSent("original_check_human_authority_changed") from None
            if self.attestation is not captured_attestation:
                raise TransportNotSent("backend_attestation_changed_during_check_authority")
        kwargs: dict[str, Any] = {"params": list(prepared.query)}
        encoded = b""
        if prepared.body is not None:
            encoded = json.dumps(prepared.body, ensure_ascii=False, allow_nan=False).encode()
            if len(encoded) > 32 * 1024 * 1024:
                raise TransportNotSent("request_body_too_large")
            kwargs.update(content=encoded, headers={"content-type": "application/json"})
        if before_send is not None:
            if not mutation:
                raise TransportNotSent("mutation_guard_requires_mutation")
            try:
                before_send()
            except Exception:
                raise TransportNotSent("mutation_guard_rejected") from None
        boundary = (
            _MutationSendBoundary(
                prepared.method,
                self.client.base_url.join(prepared.path).copy_merge_params(list(prepared.query)),
                encoded,
                captured_attestation,
                lambda: self.attestation,
                authorize_send,
                before_send,
            )
            if mutation
            else None
        )
        context = self._send_boundary.set(boundary)
        try:
            async with self.client.stream(prepared.method, prepared.path, **kwargs) as response:
                raw = bytearray()
                response_limit = (
                    32 * 1024 * 1024
                    if operation_id in ATTACHMENT_JSON_RESPONSES
                    else 16 * 1024 * 1024
                )
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > response_limit:
                        raise TransportError("response_too_large")
                value = None if not raw else strict_loads(raw)
                self.profile.response(operation_id, response.status_code, value)
                if response.status_code in {400, 401, 403, 404}:
                    if mutation:
                        if (
                            operation_id == "session.form.reply"
                            and response.status_code == 400
                            and isinstance(value, dict)
                            and value.get("_tag") == "FormInvalidAnswerError"
                        ):
                            if value.get("id") != path.get("formID"):
                                raise ContractError("upstream_form_error_identity_mismatch")
                            raise AnswerRejected("upstream_form_answer_rejected")
                        raise MutationRejected("upstream_rejected_request")
                    raise TransportError("upstream_rejected_request")
                if not 200 <= response.status_code < 300:
                    raise TransportError("upstream_outcome_requires_reconciliation")
                if boundary is not None and boundary.phase == "queued":
                    raise TransportError("native_mutation_write_boundary_missing")
                return value
        except (httpx.HTTPError, ValueError, RecursionError) as error:
            if isinstance(error, (TransportError, MutationRejected, ContractError)):
                raise
            raise TransportError("upstream_transport_or_encoding_error") from None
        finally:
            self._send_boundary.reset(context)

    async def close(self) -> None:
        await self.client.aclose()

    async def events(
        self,
        operation_id: str,
        *,
        path: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        oversized_event_bytes: int | None = None,
    ) -> AsyncGenerator[SSEFrame]:
        """One read-only stream attempt. Its caller owns reconnection/checkpoints.

        With ``oversized_event_bytes`` a larger frame is discarded while it is
        read and yielded only as a ``truncated`` prefix the caller must handle;
        it is never schema-validated or passed on as an event.
        """
        prepared = self.profile.prepare(operation_id, path=path, query=query)
        if prepared.method != "GET" or operation_id not in {"event.subscribe", "session.log"}:
            raise TransportError("event_operation_not_allowed")
        try:
            async with self.client.stream(
                "GET",
                prepared.path,
                params=list(prepared.query),
                headers={"accept": "text/event-stream"},
                timeout=httpx.Timeout(45, connect=10),
            ) as response:
                if response.status_code != 200:
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 1024 * 1024:
                            raise TransportError("event_error_response_too_large")
                    self.profile.response(operation_id, response.status_code, strict_loads(raw))
                    raise TransportError("event_stream_rejected")
                if (
                    response.headers.get("content-type", "").partition(";")[0].strip().lower()
                    != "text/event-stream"
                ):
                    raise TransportError("event_stream_content_type_mismatch")
                frames = (
                    iter_sse(response.aiter_bytes())
                    if oversized_event_bytes is None
                    else iter_sse(
                        response.aiter_bytes(),
                        max_event_bytes=oversized_event_bytes,
                        discard_oversized=True,
                    )
                )
                async for frame in frames:
                    if frame.event == "effect/http-api/stream/failure":
                        raise TransportError("upstream_event_stream_failed")
                    if frame.event != "message":
                        raise ContractError("unknown_event_stream_frame")
                    if frame.truncated:
                        yield frame
                        continue
                    self.profile.sse_frame(
                        operation_id, event=frame.event, data=frame.data, event_id=frame.event_id
                    )
                    yield frame
        except (httpx.HTTPError, ValueError, RecursionError) as error:
            if isinstance(error, (TransportError, ContractError)):
                raise
            raise TransportError("event_stream_transport_or_encoding_error") from None
