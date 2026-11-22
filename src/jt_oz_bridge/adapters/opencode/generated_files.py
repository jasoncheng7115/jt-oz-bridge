"""Correlated output candidates and bounded byte capture; never a publication grant.

Snapshot paths and completed-tool file values are separate origins. No model
text, tool input, reasoning, arbitrary URL fetch or local filesystem lookup is
used. A trusted application must still authorize capture and publication.
"""

import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import unquote_to_bytes, urlsplit
from weakref import ReferenceType
from weakref import ref as weakref

from pydantic import Field, model_validator

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.files import (
    FILE_SEMANTICS,
    NativeFileEvidence,
    NativeReadFile,
    V2NativeFileReader,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    NativeResourceTurn,
    ProjectedTurn,
    TurnCorrelation,
    V2TurnResourceReader,
    match_isolated_turn,
    selected_message,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

OUTPUT_SOURCES = {
    "packages/core/src/tool.ts": "53d4b68ad8d7cf4ff4c88bf2c12ab028a0696fd5dfa41fa26951df55d633a2d4",
    "packages/schema/src/tool.ts": "b5e35a5a5208f48bf564705563f4f77e5d46d7d57fd8c0091847b38772990e06",
}
OUTPUT_SEMANTICS = digest(
    {"version": "2.0.32", "schema": INSTALLED_SCHEMA, "sources": OUTPUT_SOURCES}
)
OUTPUT_FEATURES = frozenset(
    {"assistant-snapshot-paths", "completed-tool-files", "inline-data-metadata", "owned-turn"}
)
BYTE_FEATURES = frozenset(
    {
        "inline-exact-bytes",
        "workspace-qualified-binary",
        "original-deadline",
        "stable-original-output",
    }
)
BYTE_SEMANTICS = digest(
    {"format": "generated-bytes-v1", "outputs": OUTPUT_SEMANTICS, "workspace": FILE_SEMANTICS}
)
MAX_OUTPUTS = 1000
MAX_TURN_BYTES = 32 * 1024 * 1024


class GeneratedFile(ControlModel):
    origin: Literal["snapshot", "tool"]
    assistant_id: str = Field(min_length=1, max_length=255)
    content_index: int | None = Field(default=None, ge=0)
    file_index: int = Field(ge=0)
    tool_id: str | None = Field(default=None, min_length=1, max_length=255)
    kind: Literal["workspace", "inline"]
    path: str | None = None
    name: str | None = Field(default=None, max_length=255)
    mime_type: str | None = Field(
        default=None,
        max_length=255,
        pattern=r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$",
    )
    size: int | None = Field(default=None, ge=0, le=MAX_ATTACHMENT_BYTES)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    uri_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def origin_and_bytes(self) -> "GeneratedFile":
        if self.kind == "workspace":
            if self.path is None or disclosed_path(self.path) != self.path:
                raise ValueError("generated_workspace_path_required")
            if self.size is not None or self.sha256 is not None:
                raise ValueError("generated_path_has_no_byte_authority")
        elif (
            self.path is not None
            or self.size is None
            or self.sha256 is None
            or self.mime_type is None
            or self.uri_sha256 is None
        ):
            raise ValueError("generated_inline_metadata_required")
        if self.origin == "snapshot":
            if (
                self.kind != "workspace"
                or self.path is None
                or self.tool_id is not None
                or self.content_index is not None
                or self.uri_sha256 is not None
                or self.mime_type is not None
                or self.name != self.path.rsplit("/", 1)[-1]
            ):
                raise ValueError("generated_snapshot_origin_changed")
        elif self.tool_id is None or self.content_index is None or self.uri_sha256 is None:
            raise ValueError("generated_tool_origin_required")
        if self.name is not None:
            disclosed_path(self.name)
            NativeAttachmentProjection(
                filename=self.name,
                mime_type=self.mime_type or "application/octet-stream",
                size=0,
                sha256="0" * 64,
            )
        return self


GENERATED_ORIGINS = frozenset(
    {("workspace", "snapshot"), ("workspace", "tool"), ("inline", "tool")}
)


@dataclass(frozen=True)
class GeneratedScope:
    """Origins and byte size actually qualified for one Root, never a request.

    Outputs outside it are counted unsupported at capture and refused at read.
    """

    origins: frozenset[tuple[str, str]]
    max_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "origins", frozenset(self.origins))
        if (
            not self.origins
            or not self.origins <= GENERATED_ORIGINS
            or type(self.max_bytes) is not int
            or not 0 < self.max_bytes <= MAX_ATTACHMENT_BYTES
        ):
            raise ValueError("generated_scope_invalid")

    def admits(self, file: GeneratedFile) -> bool:
        return (file.kind, file.origin) in self.origins and (
            file.size is None or file.size <= self.max_bytes
        )


# Legacy v1 evidence qualified every origin at the hard 20 MiB bound.
FULL_SCOPE = GeneratedScope(GENERATED_ORIGINS, MAX_ATTACHMENT_BYTES)


def scoped_projection(
    projection: tuple[tuple[GeneratedFile, ...], int, int], scope: GeneratedScope
) -> tuple[tuple[GeneratedFile, ...], int, int]:
    """Out-of-scope outputs join the unsupported count, as unknown URIs already do."""
    files, hidden, unsupported = projection
    kept = tuple(f for f in files if scope.admits(f))
    return kept, hidden, unsupported + len(files) - len(kept)


@dataclass(frozen=True)
class GeneratedFileAttestation:
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    verified_features: frozenset[str]
    scope: GeneratedScope = FULL_SCOPE

    def __post_init__(self) -> None:
        object.__setattr__(self, "verified_features", frozenset(self.verified_features))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GeneratedFiles:
    reference: SessionRef
    action_id: str
    operation_digest: str
    owner_epoch: str
    outcome: Literal["succeeded", "failed", "interrupted"]
    files: tuple[GeneratedFile, ...]
    hidden_count: int
    unsupported_count: int
    evidence_sha256: str
    observed_at: float
    expires_at: float
    metadata_only: Literal[True] = True

    @property
    def projection_sha256(self) -> str:
        """Stable comparison key, never a substitute for this live object."""
        return digest(
            {
                "reference": self.reference.model_dump(mode="json"),
                "action": self.action_id,
                "operation": self.operation_digest,
                "owner": self.owner_epoch,
                "outcome": self.outcome,
                "files": [file.model_dump(mode="json") for file in self.files],
                "hidden": self.hidden_count,
                "unsupported": self.unsupported_count,
                "semantics": OUTPUT_SEMANTICS,
            }
        )


def workspace_uri(uri: str, reference: SessionRef) -> str:
    # These are Native paths, never paths to open/resolve on the Bridge host.
    if any(ord(c) < 32 or ord(c) == 127 for c in uri):
        raise ValueError("generated_file_uri_control_character")
    parsed = urlsplit(uri)
    if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("generated_local_file_uri_required")
    try:
        path = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("generated_file_uri_encoding_invalid") from None
    if re.search(r"%(?![0-9a-fA-F]{2})", parsed.path) or re.search(
        r"%(?:2f|5c)", parsed.path, re.IGNORECASE
    ):
        raise ValueError("generated_file_uri_ambiguous_encoding")
    prefix = reference.canonical_directory.rstrip("/") + "/"
    if not path.startswith(prefix):
        raise ValueError("generated_file_uri_outside_workspace")
    return disclosed_path(path[len(prefix) :])


def _inline_bytes(uri: str, mime: str) -> bytes:
    header, separator, encoded = uri.partition(",")
    if (
        not separator
        or len(header) > 255
        or header != "data:" + mime + ";base64"
        or re.fullmatch(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*", mime) is None
        or len(encoded) > 4 * ((MAX_ATTACHMENT_BYTES + 2) // 3)
    ):
        raise ContractError("generated_inline_shape_or_capacity_invalid")
    try:
        content = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        raise ContractError("generated_inline_encoding_invalid") from None
    if len(content) > MAX_ATTACHMENT_BYTES or base64.b64encode(content).decode() != encoded:
        raise ContractError("generated_inline_encoding_or_size_changed")
    return content


def inline_metadata(uri: str, mime: str) -> tuple[int, str]:
    content = _inline_bytes(uri, mime)
    return len(content), hashlib.sha256(content).hexdigest()


def own_messages(descending: list[dict[str, Any]], turn: ProjectedTurn) -> list[dict[str, Any]]:
    """Oldest first, only this input's own replies: not a later steer's or turn's."""
    own = set(turn.ordered_message_ids)
    return [m for m in reversed(descending) if m["id"] in own]


def output_projection(
    reference: SessionRef, ascending: list[dict[str, Any]]
) -> tuple[tuple[GeneratedFile, ...], int, int]:
    """Metadata parser only; it cannot attest a caller's message dictionaries."""
    files: list[GeneratedFile] = []
    hidden = unsupported = 0
    for message in ascending:
        if message["type"] != "assistant":
            continue
        for index, path in enumerate(message.get("snapshot", {}).get("files", [])):
            if len(files) + hidden + unsupported >= MAX_OUTPUTS:
                raise ContractError("generated_output_count_capacity")
            try:
                path = disclosed_path(path)
            except (AccessDenied, ValueError):
                hidden += 1
                continue
            files.append(
                GeneratedFile(
                    origin="snapshot",
                    assistant_id=message["id"],
                    file_index=index,
                    kind="workspace",
                    path=path,
                    name=path.rsplit("/", 1)[-1],
                )
            )
        for part_index, part in enumerate(message["content"]):
            if part["type"] != "tool" or part["state"]["status"] != "completed":
                continue
            for index, item in enumerate(part["state"]["content"]):
                if item["type"] != "file":
                    continue
                if len(files) + hidden + unsupported >= MAX_OUTPUTS:
                    raise ContractError("generated_output_count_capacity")
                uri, mime = item["uri"], item["mime"]
                try:
                    uri_sha256 = hashlib.sha256(uri.encode()).hexdigest()
                except UnicodeError:
                    raise ContractError("generated_output_uri_invalid_unicode") from None
                base = dict(
                    origin="tool",
                    assistant_id=message["id"],
                    content_index=part_index,
                    file_index=index,
                    tool_id=part["id"],
                    name=item.get("name"),
                    mime_type=mime,
                    uri_sha256=uri_sha256,
                )
                try:
                    if uri.startswith("file:"):
                        file = GeneratedFile(
                            **base, kind="workspace", path=workspace_uri(uri, reference)
                        )
                    elif uri.startswith("data:"):
                        size, checksum = inline_metadata(uri, mime)
                        file = GeneratedFile(**base, kind="inline", size=size, sha256=checksum)
                    else:
                        unsupported += 1
                        continue
                except AccessDenied:
                    hidden += 1
                    continue
                except ValueError as error:
                    if isinstance(error, ContractError):
                        raise
                    hidden += 1
                    continue
                files.append(file)
        if len(files) + hidden + unsupported > MAX_OUTPUTS:
            raise ContractError("generated_output_count_capacity")
    return tuple(files), hidden, unsupported


@dataclass(frozen=True)
class GeneratedBytesAttestation:
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    verified_features: frozenset[str]
    scope: GeneratedScope = FULL_SCOPE

    def __post_init__(self) -> None:
        object.__setattr__(self, "verified_features", frozenset(self.verified_features))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GeneratedFileBytes:
    outputs: GeneratedFiles
    selection: GeneratedFile
    projection: NativeAttachmentProjection
    content: bytes = field(repr=False)
    observed_at: float
    expires_at: float
    publication_authorized: Literal[False] = False


class GeneratedDiscoveryEvidence(ControlModel):
    """Original structured output inventory history, including an empty inventory."""

    format: Literal["generated-discovery-evidence-v1"] = "generated-discovery-evidence-v1"
    turn: NativeResourceTurn
    files: tuple[GeneratedFile, ...] = Field(max_length=MAX_OUTPUTS)
    hidden_count: int = Field(strict=True, ge=0, le=MAX_OUTPUTS)
    unsupported_count: int = Field(strict=True, ge=0, le=MAX_OUTPUTS)
    metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def original_projection(self) -> "GeneratedDiscoveryEvidence":
        if (
            self.turn.contract_sha256 != INSTALLED_SCHEMA
            or self.turn.semantics_sha256 != RESOURCE_SEMANTICS
            or not self.turn.observed_at < self.turn.expires_at <= self.turn.observed_at + 5
            or len(self.files) + self.hidden_count + self.unsupported_count > MAX_OUTPUTS
            or self.metadata_sha256
            != digest(
                {
                    "turn": self.turn.model_dump(mode="json"),
                    "outputs": [f.model_dump(mode="json") for f in self.files],
                    "hidden": self.hidden_count,
                    "unsupported": self.unsupported_count,
                    "semantics": OUTPUT_SEMANTICS,
                }
            )
        ):
            raise ValueError("generated_discovery_original_projection_changed")
        return self

    @property
    def stable_sha256(self) -> str:
        value = self.model_dump(mode="json", exclude={"metadata_sha256"})
        value["turn"] = self.turn.model_dump(
            mode="json", exclude={"observed_at", "expires_at", "resource_fence", "connection_epoch"}
        )
        return digest(value)


class GeneratedByteEvidence(ControlModel):
    """Sealed capture history; deserializing this never grants live authority."""

    format: Literal["generated-byte-evidence-v1"] = "generated-byte-evidence-v1"
    turn: NativeResourceTurn
    selection: GeneratedFile
    files: tuple[GeneratedFile, ...] = Field(min_length=1, max_length=MAX_OUTPUTS)
    hidden_count: int = Field(ge=0, le=MAX_OUTPUTS)
    unsupported_count: int = Field(ge=0, le=MAX_OUTPUTS)
    metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_semantics_sha256: str = Field(default=BYTE_SEMANTICS, pattern=r"^[0-9a-f]{64}$")
    projection: NativeAttachmentProjection
    native: NativeFileEvidence | None = None
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def exact_origin(self) -> "GeneratedByteEvidence":
        expected = digest(
            {
                "turn": self.turn.model_dump(mode="json"),
                "outputs": [f.model_dump(mode="json") for f in self.files],
                "hidden": self.hidden_count,
                "unsupported": self.unsupported_count,
                "semantics": OUTPUT_SEMANTICS,
            }
        )
        if (
            self.selection not in self.files
            or self.selection.assistant_id not in self.turn.turn.ordered_message_ids
            or self.turn.contract_sha256 != INSTALLED_SCHEMA
            or self.turn.semantics_sha256 != RESOURCE_SEMANTICS
            or len(self.files) + self.hidden_count + self.unsupported_count > MAX_OUTPUTS
            or self.metadata_sha256 != expected
            or self.byte_semantics_sha256 != BYTE_SEMANTICS
            or not self.turn.observed_at
            <= self.observed_at
            < self.expires_at
            <= self.turn.expires_at
            <= self.turn.observed_at + 5
            or self.projection.filename
            != (
                self.selection.path.rsplit("/", 1)[-1]
                if self.selection.path
                else self.selection.name or "output.bin"
            )
        ):
            raise ValueError("generated_byte_history_origin_changed")
        if self.selection.kind == "workspace":
            if (
                self.native is None
                or self.native.contract_sha256 != INSTALLED_SCHEMA
                or self.native.semantics_sha256 != FILE_SEMANTICS
                or self.native.reference != self.turn.correlation.reference
                or self.native.relative_path != self.selection.path
                or self.native.projection != self.projection
                or self.native.owner_epoch != self.turn.owner_epoch
                or self.native.connection_epoch != self.turn.connection_epoch
                or self.native.resource_fence != self.turn.resource_fence
                or self.expires_at > self.native.expires_at
                or not self.native.observed_at
                < self.native.expires_at
                <= self.native.observed_at + 5
            ):
                raise ValueError("generated_byte_history_workspace_changed")
        elif self.native is not None or (
            self.projection.size,
            self.projection.sha256,
            self.projection.mime_type,
        ) != (self.selection.size, self.selection.sha256, self.selection.mime_type):
            raise ValueError("generated_byte_history_inline_changed")
        return self

    @property
    def stable_sha256(self) -> str:
        """Comparison across real re-reads, never a proof-expiry extension."""
        value = self.model_dump(
            mode="json", exclude={"observed_at", "expires_at", "metadata_sha256"}
        )
        value["turn"] = self.turn.model_dump(
            exclude={"observed_at", "expires_at", "resource_fence", "connection_epoch"}
        )
        if self.native is not None:
            value["native"] = self.native.model_dump(
                exclude={"observed_at", "expires_at", "resource_fence", "connection_epoch"}
            )
        return digest(value)

    def discovery(self) -> GeneratedDiscoveryEvidence:
        return GeneratedDiscoveryEvidence(
            turn=self.turn,
            files=self.files,
            hidden_count=self.hidden_count,
            unsupported_count=self.unsupported_count,
            metadata_sha256=self.metadata_sha256,
            metadata_attestation_sha256=self.metadata_attestation_sha256,
        )


class V2GeneratedFileReader:
    def __init__(
        self,
        turns: V2TurnResourceReader,
        *,
        attestation: GeneratedFileAttestation | None = None,
        file_reader: V2NativeFileReader | None = None,
        byte_attestation: GeneratedBytesAttestation | None = None,
    ) -> None:
        if not isinstance(turns, V2TurnResourceReader):
            raise ValueError("generated_original_turn_reader_required")
        if file_reader is not None and (
            not isinstance(file_reader, V2NativeFileReader)
            or file_reader.client is not turns.client
        ):
            raise ValueError("generated_file_original_reader_required")
        self.file_reader = self._file_reader = file_reader
        self.byte_attestation = byte_attestation
        self.turns, self.attestation = turns, attestation
        self._original = turns, turns.client, turns.proofs, turns.client.transport
        self._issued: dict[
            int,
            tuple[
                ReferenceType[GeneratedFiles],
                NativeResourceTurn,
                GeneratedFileAttestation,
                TurnCorrelation,
            ],
        ] = {}
        self._bytes: dict[
            int,
            tuple[
                ReferenceType[GeneratedFileBytes], NativeReadFile | None, GeneratedBytesAttestation
            ],
        ] = {}

    def require(self, ref: SessionRef) -> GeneratedFileAttestation:
        a = self.attestation
        if (
            a is None
            or self.file_reader is not self._file_reader
            or (self.file_reader is not None and self.file_reader.client is not self.turns.client)
            or any(
                x is not y
                for x, y in zip(
                    (self.turns, self.turns.client, self.turns.proofs, self.turns.client.transport),
                    self._original,
                    strict=True,
                )
            )
            or a.reference != ref
            or a.contract_sha256 != INSTALLED_SCHEMA
            or self.turns.client.transport.profile.sha256 != INSTALLED_SCHEMA
            or a.semantics_sha256 != OUTPUT_SEMANTICS
            or a.verified_features != OUTPUT_FEATURES
            or not isinstance(a.scope, GeneratedScope)
            or re.fullmatch(r"[0-9a-f]{64}", a.installed_evidence_sha256) is None
        ):
            raise ContractError("generated_output_semantics_unqualified")
        self.turns.qualify(ref)
        return a

    async def page(self, c: TurnCorrelation) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        ids: set[str] = set()
        cursors: set[str] = set()
        cursor = None
        size = 0
        for _ in range(20):
            value = await self.turns.client.transport.request(
                "session.message.list",
                path={"sessionID": c.reference.upstream_session_id},
                query={"limit": "50", **({"cursor": cursor} if cursor else {"order": "desc"})},
            )
            if not 1 <= len(value["data"]) <= 50:
                raise ContractError("generated_output_original_turn_missing")
            for raw in value["data"]:
                try:
                    size += len(
                        json.dumps(
                            raw, separators=(",", ":"), ensure_ascii=False, allow_nan=False
                        ).encode()
                    )
                except (ValueError, TypeError, RecursionError):
                    raise ContractError("generated_output_invalid_unicode_or_json") from None
                if raw["id"] in ids or size > MAX_TURN_BYTES:
                    raise ContractError("generated_output_duplicate_or_byte_capacity")
                ids.add(raw["id"])
                selected.append(raw)
                if raw["id"] == c.upstream_id:
                    return selected
            cursor = value["cursor"].get("next")
            if not isinstance(cursor, str) or not cursor or len(cursor) > 8192 or cursor in cursors:
                raise ContractError("generated_output_original_cursor_invalid")
            cursors.add(cursor)
        raise ContractError("generated_output_page_capacity")

    async def capture(self, correlation: TurnCorrelation) -> GeneratedFiles:
        c = TurnCorrelation.model_validate(strict_loads(checked_json(correlation.model_dump())))
        attestation = self.require(c.reference)
        turn = await self.turns.capture(c)
        projections = []
        for _ in range(2):
            raw = await self.page(c)
            legacy = [
                selected_message(
                    m, with_attachment_receipts=bool(c.attachments) and m["id"] == c.upstream_id
                )
                for m in raw
            ]
            matched = match_isolated_turn(
                c, legacy, allow_model_settings=self.turns.proofs.model_settings is not None
            )
            if matched != turn.turn:
                raise ContractError("generated_output_original_turn_changed")
            projections.append(output_projection(c.reference, own_messages(raw, matched)))
        final_owner = await self.turns.proofs.feed.current_owner()
        _, final = await self.turns.client.qualified_snapshot(c.reference)
        self.turns.client.current(c.reference, final)
        if (
            projections[0] != projections[1]
            or self.require(c.reference) is not attestation
            or not self.turns.current(turn)
            or final_owner.owner_epoch != turn.owner_epoch
            or final.session_info_sha256 != turn.session_info_sha256
            or final.resource_fence != turn.resource_fence
            or final.connection_epoch != turn.connection_epoch
        ):
            raise ContractError("generated_output_projection_or_owner_changed")
        files, hidden, unsupported = scoped_projection(projections[0], attestation.scope)
        self._issued = {
            k: v for k, v in self._issued.items() if v[0]() is not None and self.turns.current(v[1])
        }
        if len(self._issued) >= 32:
            raise ContractError("generated_output_witness_capacity")
        result = GeneratedFiles(
            c.reference,
            c.action_id,
            c.operation_digest,
            turn.owner_epoch,
            turn.turn.outcome,
            files,
            hidden,
            unsupported,
            digest(
                {
                    "turn": turn.model_dump(mode="json"),
                    "outputs": [f.model_dump(mode="json") for f in files],
                    "hidden": hidden,
                    "unsupported": unsupported,
                    "semantics": OUTPUT_SEMANTICS,
                }
            ),
            turn.observed_at,
            turn.expires_at,
        )
        self._issued[id(result)] = weakref(result), turn, attestation, c
        return result

    def current(self, result: GeneratedFiles) -> bool:
        try:
            saved = self._issued.get(id(result))
            return bool(
                saved is not None
                and saved[0]() is result
                and self.require(result.reference) is saved[2]
                and self.turns.current(saved[1])
                and result.observed_at <= time.time() < result.expires_at
            )
        except (ValueError, TypeError):
            return False

    def discovery_evidence(self, result: GeneratedFiles) -> GeneratedDiscoveryEvidence:
        if not self.current(result):
            raise ContractError("generated_original_discovery_witness_required")
        _, turn, attestation, _ = self._issued[id(result)]
        value = GeneratedDiscoveryEvidence(
            turn=turn,
            files=result.files,
            hidden_count=result.hidden_count,
            unsupported_count=result.unsupported_count,
            metadata_sha256=result.evidence_sha256,
            metadata_attestation_sha256=attestation.installed_evidence_sha256,
        )
        if not self.current(result):
            raise ContractError("generated_original_discovery_witness_expired")
        return value

    def require_bytes(self, reference: SessionRef) -> GeneratedBytesAttestation:
        metadata = self.require(reference)
        a = self.byte_attestation
        if (
            a is None
            or a.scope != metadata.scope
            or a.reference != reference
            or a.contract_sha256 != INSTALLED_SCHEMA
            or a.semantics_sha256 != BYTE_SEMANTICS
            or a.verified_features != BYTE_FEATURES
            or re.fullmatch(r"[0-9a-f]{64}", a.installed_evidence_sha256) is None
        ):
            raise ContractError("generated_bytes_semantics_unqualified")
        return a

    async def read(self, outputs: GeneratedFiles, selection: GeneratedFile) -> GeneratedFileBytes:
        """Exact bytes only; caller must separately authorize Human, action and publication."""
        if not self.current(outputs) or not any(selection is f for f in outputs.files):
            raise ContractError("generated_original_selection_required")
        byte_attestation = self.require_bytes(outputs.reference)
        _, turn, attestation, c = self._issued[id(outputs)]
        scope = attestation.scope
        if not scope.admits(selection):
            raise ContractError("generated_output_outside_qualified_scope")
        native: NativeReadFile | None = None
        if selection.kind == "workspace":
            if self.file_reader is None or selection.path is None:
                raise ContractError("generated_qualified_workspace_reader_required")
            # A path carries no size: the qualified maximum bounds the Native read.
            native = await self.file_reader.read(
                outputs.reference, selection.path, maximum_bytes=scope.max_bytes
            )
        pages = []
        for _ in range(2):
            raw = await self.page(c)
            legacy = [
                selected_message(
                    m, with_attachment_receipts=bool(c.attachments) and m["id"] == c.upstream_id
                )
                for m in raw
            ]
            if match_isolated_turn(
                c, legacy, allow_model_settings=self.turns.proofs.model_settings is not None
            ) != turn.turn or scoped_projection(
                output_projection(c.reference, own_messages(raw, turn.turn)), scope
            ) != (
                outputs.files,
                outputs.hidden_count,
                outputs.unsupported_count,
            ):
                raise ContractError("generated_selected_output_changed")
            pages = raw
        if native is not None:
            content, projection = native.content, native.evidence.projection
        else:
            message = next(m for m in pages if m["id"] == selection.assistant_id)
            if selection.content_index is None:
                raise ContractError("generated_inline_tool_origin_required")
            item = message["content"][selection.content_index]["state"]["content"][
                selection.file_index
            ]
            content = _inline_bytes(item["uri"], item["mime"])
            projection = NativeAttachmentProjection(
                filename=selection.name or "output.bin",
                mime_type=item["mime"],
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
            if projection.size != selection.size or projection.sha256 != selection.sha256:
                raise ContractError("generated_inline_bytes_changed")
        if projection.size > scope.max_bytes:
            raise ContractError("generated_output_outside_qualified_size")
        owner = await self.turns.proofs.feed.current_owner()
        _, final = await self.turns.client.qualified_snapshot(c.reference)
        self.turns.client.current(c.reference, final)
        if (
            not self.current(outputs)
            or self.require_bytes(c.reference) is not byte_attestation
            or self.require(c.reference) is not attestation
            or owner.owner_epoch != turn.owner_epoch
            or final.session_info_sha256 != turn.session_info_sha256
            or final.resource_fence != turn.resource_fence
            or final.connection_epoch != turn.connection_epoch
            or (
                native is not None
                and (
                    self.file_reader is None
                    or not self.file_reader.current(native)
                    or native.evidence.owner_epoch != turn.owner_epoch
                    or native.evidence.connection_epoch != turn.connection_epoch
                    or native.evidence.resource_fence != turn.resource_fence
                )
            )
        ):
            raise ContractError("generated_bytes_original_proof_changed")
        now = time.time()
        result = GeneratedFileBytes(
            outputs,
            selection,
            projection,
            content,
            now,
            min(outputs.expires_at, native.evidence.expires_at if native else outputs.expires_at),
        )
        self._bytes = {k: v for k, v in self._bytes.items() if v[0]() is not None}
        if len(self._bytes) >= 32:
            raise ContractError("generated_bytes_witness_capacity")
        self._bytes[id(result)] = weakref(result), native, byte_attestation
        if not self.current_bytes(result):
            self._bytes.pop(id(result), None)
            raise ContractError("generated_bytes_original_deadline_expired")
        return result

    def current_bytes(self, result: GeneratedFileBytes) -> bool:
        try:
            saved = self._bytes.get(id(result))
            return bool(
                saved is not None
                and saved[0]() is result
                and self.require_bytes(result.outputs.reference) is saved[2]
                and self.current(result.outputs)
                and any(result.selection is f for f in result.outputs.files)
                and result.observed_at <= time.time() < result.expires_at
                and result.expires_at <= result.outputs.expires_at
                and result.projection.size == len(result.content)
                and result.projection.sha256 == hashlib.sha256(result.content).hexdigest()
                and (
                    saved[1] is None
                    or (self.file_reader is not None and self.file_reader.current(saved[1]))
                )
            )
        except (ValueError, TypeError):
            return False

    def evidence(self, result: GeneratedFileBytes) -> GeneratedByteEvidence:
        if not self.current_bytes(result):
            raise ContractError("generated_original_byte_evidence_required")
        _, native, byte_attestation = self._bytes[id(result)]
        _, turn, metadata_attestation, _ = self._issued[id(result.outputs)]
        evidence = GeneratedByteEvidence(
            turn=turn,
            selection=result.selection,
            files=result.outputs.files,
            hidden_count=result.outputs.hidden_count,
            unsupported_count=result.outputs.unsupported_count,
            metadata_sha256=result.outputs.evidence_sha256,
            metadata_attestation_sha256=metadata_attestation.installed_evidence_sha256,
            byte_attestation_sha256=byte_attestation.installed_evidence_sha256,
            projection=result.projection,
            native=native.evidence if native is not None else None,
            observed_at=result.observed_at,
            expires_at=result.expires_at,
        )
        if not self.current_bytes(result):
            raise ContractError("generated_original_byte_evidence_expired")
        return evidence
