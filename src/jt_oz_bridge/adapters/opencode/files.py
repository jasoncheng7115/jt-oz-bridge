"""Qualified bounded reads from the original Native project filesystem.

No shell, arbitrary URL, local-path illusion or JSON decoding of file bodies.
A trusted service must additionally authorize its requester/binding before use.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import quote
from weakref import ReferenceType
from weakref import ref as weakref

import httpx
from pydantic import Field

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.resources import (
    INSTALLED_SCHEMA,
    ReadOnlyRootScope,
    V2LeafResourceProofs,
)
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.durable import digest


@dataclass(frozen=True)
class BinaryReadResponse:
    projection: NativeAttachmentProjection
    etag: str
    content: bytes = field(repr=False)


def relative_file(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= 4096
        or value.startswith("/")
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or any(
            not part or part in {".", ".."} or len(part.encode("utf-8")) > 255
            for part in value.split("/")
        )
    ):
        raise ContractError("native_file_relative_canonical_path_required")
    return value


async def _read_once(
    transport: V2HTTPTransport,
    reference: SessionRef,
    path: str,
    *,
    maximum_bytes: int = MAX_ATTACHMENT_BYTES,
) -> BinaryReadResponse:
    """Fixed fs.read, never an arbitrary URL/operation/headers from chat."""
    path = relative_file(path)
    if type(maximum_bytes) is not int or not 0 <= maximum_bytes <= MAX_ATTACHMENT_BYTES:
        raise ContractError("native_file_bound_required")
    prepared = transport.profile.prepare(
        "fs.read", query={"location": {"directory": reference.canonical_directory}}
    )
    operation = transport.profile.operations["fs.read"]
    if (
        transport.profile.sha256
        != "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"
        or prepared.method != "GET"
        or prepared.path != "/api/fs/read/*"
        or operation[2]["responses"]["200"]["content"]["application/octet-stream"]["schema"]
        != {"type": "string", "format": "binary"}
    ):
        raise ContractError("native_binary_read_schema_not_qualified")
    route = prepared.path[:-1] + quote(path, safe="/")
    try:
        async with transport.client.stream(
            "GET",
            route,
            params=list(prepared.query),
            headers={"accept": "application/octet-stream", "accept-encoding": "identity"},
            timeout=httpx.Timeout(30, connect=10),
        ) as response:
            if response.status_code != 200:
                if response.status_code in {400, 401, 404}:
                    error = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(error) + len(chunk) > 32768:
                            raise TransportError("native_file_error_response_too_large")
                        error.extend(chunk)
                    transport.profile.response("fs.read", response.status_code, strict_loads(error))
                raise TransportError("native_file_read_rejected")
            lengths = response.headers.get_list("content-length")
            if len(lengths) != 1 or re.fullmatch(r"0|[1-9][0-9]{0,15}", lengths[0]) is None:
                raise TransportError("native_file_exact_length_required")
            length = int(lengths[0])
            if length > maximum_bytes:
                raise TransportError("native_file_too_large")
            if response.headers.get("content-encoding", "").lower() not in {"", "identity"}:
                raise TransportError("native_file_encoding_changed")
            if "content-range" in response.headers:
                raise TransportError("native_file_partial_response_not_supported")
            etag = response.headers.get("etag", "")
            if not 1 <= len(etag) <= 255 or any(ord(c) < 32 or ord(c) == 127 for c in etag):
                raise TransportError("native_file_validator_required")
            mime = response.headers.get("content-type", "").partition(";")[0].strip().lower()
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > min(maximum_bytes, length):
                    raise TransportError("native_file_stream_exceeded_length")
                data.extend(chunk)
            if len(data) != length:
                raise TransportError("native_file_stream_incomplete")
            return BinaryReadResponse(
                projection=NativeAttachmentProjection(
                    filename=path.rsplit("/", 1)[-1],
                    mime_type=mime,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                ),
                etag=etag,
                content=bytes(data),
            )
    except httpx.HTTPError:
        raise TransportError("native_file_transport_failed") from None


FILE_SOURCES = {
    "filesystem.ts": "0bdfe1daeb41e9bfe4447e262f88036f78ea8eb2e22151157f6cfc834cc841f6",
    "handlers/fs.ts": "001cb251827a000c4891b8587278063b872330cf9fb51aacc080ffaf3eaed2a1",
}
FILE_SEMANTICS = digest(
    {
        "version": "2.0.32",
        "sources": FILE_SOURCES,
        "read_authority": "original-owner-read-scope-without-mutation-watch-v1",
        "deadline": "first-read-scope-issued-at-plus-five-seconds",
    }
)
FILE_FEATURES = frozenset(
    {
        "bounded-binary-full-read",
        "empty-file",
        "utf8-filename",
        "html-file",
        "outside-symlink-rejected",
        "missing-json-not-file",
        "read-scope-without-mutation-watch",
    }
)


@dataclass(frozen=True)
class BinaryReadAttestation:
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    native_policy_sha256: str
    verified_features: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "verified_features", frozenset(self.verified_features))


class NativeFileEvidence(ControlModel):
    format: Literal["v2-native-file-read-v1"] = "v2-native-file-read-v1"
    reference: SessionRef
    relative_path: str
    projection: NativeAttachmentProjection
    etag: str
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    native_policy_sha256: str
    owner_epoch: str
    connection_epoch: str
    resource_fence: str
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class NativeReadFile:
    evidence: NativeFileEvidence
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class _ReadContext:
    original: ReferenceType[NativeReadFile]
    scope: ReadOnlyRootScope
    attestation: BinaryReadAttestation
    transport_attestation: ContractAttestation | None
    feed_context: tuple[object, object, object]
    resource_fence: str
    deadline: float
    monotonic_deadline: float


class V2NativeFileReader:
    def __init__(
        self, client: V2ExecutionClient, *, attestation: BinaryReadAttestation | None = None
    ) -> None:
        if not isinstance(client.proofs, V2LeafResourceProofs) or not isinstance(
            client.scope_guard, V2ProjectPolicyGuard
        ):
            raise ValueError("original_native_file_owner_and_policy_required")
        if (
            client.scope_guard.proofs is not client.proofs
            or client.transport is not client.proofs.feed.transport
        ):
            raise ValueError("native_file_scope_dependencies_must_match")
        self.client, self.proofs, self.guard = client, client.proofs, client.scope_guard
        self.attestation = attestation
        self._witnesses: dict[tuple[SessionRef, str], _ReadContext] = {}

    def require(self, reference: SessionRef) -> BinaryReadAttestation:
        self.proofs.select(reference)
        attestation, transport = self.attestation, self.client.transport
        policy = self.guard.enrollments.get(reference)
        if (
            self.client.proofs is not self.proofs
            or self.client.scope_guard is not self.guard
            or self.guard.proofs is not self.proofs
            or transport is not self.proofs.feed.transport
            or attestation is None
            or policy is None
            or transport.attestation is None
            or attestation.reference != reference
            or attestation.contract_sha256 != transport.profile.sha256
            or transport.profile.sha256 != INSTALLED_SCHEMA
            or transport.attestation.schema_sha256 != INSTALLED_SCHEMA
            or transport.attestation.upstream_version != "2.0.32"
            or transport.attestation.backend_identity != reference.backend_identity
            or "fs.read" not in transport.attestation.verified_operations
            or attestation.semantics_sha256 != FILE_SEMANTICS
            or not FILE_FEATURES <= attestation.verified_features
            or attestation.native_policy_sha256 != policy.fingerprint_sha256
            or re.fullmatch("[0-9a-f]{64}", attestation.installed_evidence_sha256) is None
        ):
            raise ContractError("native_binary_file_read_not_qualified")
        return attestation

    async def read(
        self, reference: SessionRef, path: str, *, maximum_bytes: int = MAX_ATTACHMENT_BYTES
    ) -> NativeReadFile:
        path = relative_file(path)
        attestation = self.require(reference)
        self._witnesses.pop((reference, path), None)
        transport_attestation = self.client.transport.attestation
        feed_context = (self.proofs.feed, self.proofs.feed.index, self.proofs.feed.task)
        monotonic_deadline = time.monotonic() + 5
        before = await self.proofs.read_scope(reference)
        deadline = before.expires_at
        resource_fence = self.proofs.fence(reference)
        policy_before = await self.guard.bundle(reference)
        if policy_before != (attestation.native_policy_sha256, before.session_info_sha256):
            raise ContractError("native_file_project_policy_changed")
        first = await _read_once(
            self.client.transport, reference, path, maximum_bytes=maximum_bytes
        )
        second = await _read_once(
            self.client.transport, reference, path, maximum_bytes=maximum_bytes
        )
        after = await self.proofs.read_scope(reference)
        policy_after = await self.guard.bundle(reference)
        now = time.time()
        if (
            self.require(reference) is not attestation
            or self.client.transport.attestation is not transport_attestation
            or self.proofs.feed is not feed_context[0]
            or self.proofs.feed.index is not feed_context[1]
            or self.proofs.feed.task is not feed_context[2]
            or first != second
            or policy_after != policy_before
            or before.session_info_sha256 != after.session_info_sha256
            or before.owner_epoch != after.owner_epoch
            or before.connection_epoch != after.connection_epoch
            or self.proofs.read_epoch(reference, INSTALLED_SCHEMA) != before.connection_epoch
            or self.proofs.fence(reference) != resource_fence
            or not before.issued_at <= now < deadline
            or time.monotonic() >= monotonic_deadline
        ):
            raise ContractError("native_file_content_or_original_owner_changed")
        result = NativeReadFile(
            evidence=NativeFileEvidence(
                reference=reference,
                relative_path=path,
                projection=second.projection,
                etag=second.etag,
                contract_sha256=INSTALLED_SCHEMA,
                semantics_sha256=FILE_SEMANTICS,
                installed_evidence_sha256=attestation.installed_evidence_sha256,
                native_policy_sha256=attestation.native_policy_sha256,
                owner_epoch=after.owner_epoch,
                connection_epoch=after.connection_epoch,
                resource_fence=resource_fence,
                observed_at=before.issued_at,
                expires_at=deadline,
            ),
            content=second.content,
        )
        while len(self._witnesses) >= 32:
            self._witnesses.pop(next(iter(self._witnesses)))
        self._witnesses[(reference, path)] = _ReadContext(
            weakref(result),
            after,
            attestation,
            transport_attestation,
            feed_context,
            resource_fence,
            deadline,
            monotonic_deadline,
        )
        if not self.current(result):
            self._witnesses.pop((reference, path), None)
            raise ContractError("native_file_original_read_boundary_expired")
        return result

    def current(self, file: NativeReadFile) -> bool:
        try:
            evidence = file.evidence
            witness = self._witnesses.get((evidence.reference, evidence.relative_path))
            if (
                witness is None
                or witness.original() is not file
                or self.require(evidence.reference) is not witness.attestation
                or self.client.transport.attestation is not witness.transport_attestation
                or self.proofs.feed is not witness.feed_context[0]
                or self.proofs.feed.index is not witness.feed_context[1]
                or self.proofs.feed.task is not witness.feed_context[2]
            ):
                return False
            content_sha256 = hashlib.sha256(file.content).hexdigest()
            epoch = self.proofs.read_epoch(evidence.reference, INSTALLED_SCHEMA)
            resource_fence = self.proofs.fence(evidence.reference)
            now = time.time()
            return bool(
                evidence.observed_at <= now < evidence.expires_at == witness.deadline
                and time.monotonic() < witness.monotonic_deadline
                and epoch == witness.scope.connection_epoch
                and evidence.resource_fence == witness.resource_fence == resource_fence
                and evidence.connection_epoch == witness.scope.connection_epoch
                and evidence.projection.size == len(file.content)
                and evidence.projection.sha256 == content_sha256
            )
        except (ValueError, TypeError):
            return False
