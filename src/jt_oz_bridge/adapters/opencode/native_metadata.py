"""Original-owner/location checked catalogs; no tools or credential RPCs."""

import asyncio
import hashlib
from typing import Any

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof, V2ExecutionClient
from jt_oz_bridge.domain.git import NativeGitContext
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.native_metadata import (
    AgentMetadata,
    CommandMetadata,
    GitFileMetadata,
    McpMetadata,
    MetadataItem,
    MetadataKind,
    NativeMetadataSnapshot,
    NativeUsage,
    SkillMetadata,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.workspace_paths import canonical_relative, disclosed_path
from jt_oz_bridge.storage.durable import digest

OPERATIONS: dict[MetadataKind, str] = {
    "agents": "agent.list",
    "commands": "command.list",
    "skills": "skill.list",
    "mcp": "mcp.list",
    "usage": "session.get",
    "git": "vcs.get",
}


GIT_OPERATIONS = frozenset({"vcs.get", "vcs.status", "location.get"})


def required_operations(kind: MetadataKind) -> frozenset[str]:
    return GIT_OPERATIONS if kind == "git" else frozenset({OPERATIONS[kind]})


def project_git(
    info: dict[str, Any], files: list[dict[str, Any]], *, root_sha256: str
) -> tuple[NativeGitContext, tuple[MetadataItem, ...]]:
    if len(files) > 4096:
        raise ContractError("native_git_status_capacity_exceeded")
    branch = info["branch"]
    visible = []
    seen = set()
    hidden = 0
    for row in files:
        path = canonical_relative(row["file"])
        if path in seen:
            raise ContractError("native_git_status_duplicate_file")
        seen.add(path)
        try:
            disclosed_path(path)
        except AccessDenied:
            hidden += 1
            continue
        visible.append(
            GitFileMetadata(
                native_id=hashlib.sha256(path.encode()).hexdigest(),
                name=path,
                change=row["status"],
                additions=row["additions"],
                deletions=row["deletions"],
            )
        )
    context = NativeGitContext(
        provider=info.get("provider"),
        branch=branch.get("current"),
        default_branch=branch.get("default"),
        reported_files=len(files),
        hidden_files=hidden,
        native_project_root_sha256=root_sha256,
    )
    return context, tuple(sorted(visible, key=lambda item: item.name))


def project_items(kind: MetadataKind, rows: list[dict[str, Any]]) -> tuple[MetadataItem, ...]:
    if len(rows) > 4096:
        raise ContractError("native_metadata_catalog_capacity_exceeded")
    items: list[MetadataItem] = []
    identities = []
    for raw in rows:
        identity = raw["id"] if kind in {"agents", "skills"} else raw["name"]
        identities.append(identity)
        if kind == "agents":
            item: MetadataItem = AgentMetadata(
                native_id=identity, name=raw["name"], mode=raw["mode"]
            )
            if not raw["hidden"]:
                items.append(item)
        elif kind == "commands":
            items.append(CommandMetadata(native_id=identity, name=raw["name"]))
        elif kind == "skills":
            items.append(
                SkillMetadata(
                    native_id=identity, name=raw["name"], autoinvoke=raw.get("autoinvoke")
                )
            )
        elif kind == "mcp":
            items.append(
                McpMetadata(native_id=identity, name=raw["name"], status=raw["status"]["status"])
            )
        else:
            raise ContractError("usage_has_no_catalog")
    if len(identities) != len(set(identities)):
        raise ContractError("native_metadata_duplicate_identity")
    # Deliberately exclude descriptions, agent request/system/permissions,
    # skill path/content and MCP raw errors/integration configuration. None of
    # those fields enter catalog hashes, page tokens or persisted DTOs.
    return tuple(sorted(items, key=lambda item: item.native_id))


def project_usage(info: dict[str, Any]) -> NativeUsage:
    tokens = info["tokens"]
    return NativeUsage(
        cost_usd=info["cost"],
        input=tokens["input"],
        output=tokens["output"],
        reasoning=tokens["reasoning"],
        cache_read=tokens["cache"]["read"],
        cache_write=tokens["cache"]["write"],
    )


class V2NativeMetadataReader:
    def __init__(self, client: V2ExecutionClient, reference: SessionRef) -> None:
        self.client, self.reference = client, reference
        client.contract_for(reference)
        self._observed: dict[
            int, tuple[NativeMetadataSnapshot, OriginalExecutionProof, object, int]
        ] = {}
        self._observed_bytes = 0

    def contract_for(self, reference: SessionRef) -> str:
        if reference != self.reference:
            raise ContractError("native_metadata_original_root_not_enrolled")
        return self.client.contract_for(reference)

    def available_kinds(self, reference: SessionRef) -> frozenset[MetadataKind]:
        self.contract_for(reference)
        attestation = self.client.transport.attestation
        if attestation is None:
            return frozenset()
        return frozenset(
            k for k in OPERATIONS if required_operations(k) <= attestation.verified_operations
        )

    async def read(self, reference: SessionRef, kind: MetadataKind) -> NativeMetadataSnapshot:
        contract = self.contract_for(reference)
        if kind not in self.available_kinds(reference):
            raise ContractError("native_metadata_read_operation_not_installed_qualified")
        transport = self.client.transport
        attestation = transport.attestation
        _, before = await self.client.qualified_snapshot(reference)
        if kind == "usage":
            value = await transport.request(
                "session.get", path={"sessionID": reference.upstream_session_id}
            )
            info = value["data"]
            project = self.client.selected(reference)
            if (
                info["id"] != reference.upstream_session_id
                or info["projectID"] != project.upstream_project_id
                or info["location"]["directory"] != reference.canonical_directory
            ):
                raise ContractError("native_metadata_original_usage_scope_changed")
            snapshot = NativeMetadataSnapshot(
                reference=reference,
                contract_sha256=contract,
                kind=kind,
                usage=project_usage(value["data"]),
            )
        elif kind == "git":
            query = {"location": {"directory": reference.canonical_directory}}

            async def root_location() -> dict[str, Any]:
                location = await transport.request("location.get", query=query)
                if not isinstance(location, dict):
                    raise ContractError("native_git_location_object_required")
                project = self.client.selected(reference)
                if (
                    location["directory"] != reference.canonical_directory
                    or location["project"]["directory"] != reference.canonical_directory
                    or location["project"]["id"] != project.upstream_project_id
                ):
                    raise ContractError("native_git_requires_exact_project_root_not_subdirectory")
                return location

            async def observe() -> tuple[NativeGitContext, tuple[MetadataItem, ...]]:
                location_before = await root_location()
                info, status = await asyncio.gather(
                    transport.request("vcs.get", query=query),
                    transport.request("vcs.status", query=query),
                )
                if any(
                    response["location"] != {"directory": reference.canonical_directory}
                    for response in (info, status)
                ):
                    raise ContractError("native_git_status_location_changed")
                location_after = await root_location()
                if location_after != location_before:
                    raise ContractError("native_git_project_root_changed_during_read")
                return project_git(
                    info["data"], status["data"], root_sha256=digest(location_before)
                )

            first, second = await observe(), await observe()
            if first != second:
                raise ContractError("native_git_status_changed_during_read")
            snapshot = NativeMetadataSnapshot(
                reference=reference,
                contract_sha256=contract,
                kind=kind,
                git=first[0],
                items=first[1],
            )
        else:
            query = {"location": {"directory": reference.canonical_directory}}
            first = await transport.request(OPERATIONS[kind], query=query)
            second = await transport.request(OPERATIONS[kind], query=query)
            if any(
                row["location"]["directory"] != reference.canonical_directory
                for row in (first, second)
            ):
                raise ContractError("native_metadata_location_changed")
            items = project_items(kind, first["data"])
            if items != project_items(kind, second["data"]):
                raise ContractError("native_metadata_catalog_changed_during_read")
            snapshot = NativeMetadataSnapshot(
                reference=reference, contract_sha256=contract, kind=kind, items=items
            )
        _, after = await self.client.qualified_snapshot(reference)
        self.client.current(reference, after)
        if (
            transport.attestation is not attestation
            or before.connection_epoch != after.connection_epoch
        ):
            raise ContractError("native_metadata_original_owner_or_session_changed")
        size = len(snapshot.model_dump_json().encode())
        if size > 2 * 1024 * 1024:
            raise ContractError("native_metadata_safe_snapshot_capacity_exceeded")
        while self._observed and (
            len(self._observed) >= 8 or self._observed_bytes + size > 4 * 1024 * 1024
        ):
            old = self._observed.pop(next(iter(self._observed)))
            self._observed_bytes -= old[3]
        self._observed[id(snapshot)] = (snapshot, after, attestation, size)
        self._observed_bytes += size
        return snapshot

    def current(self, snapshot: NativeMetadataSnapshot) -> bool:
        try:
            entry = self._observed.get(id(snapshot))
            if (
                entry is None
                or entry[0] is not snapshot
                or self.client.transport.attestation is not entry[2]
            ):
                return False
            self.client.current(snapshot.reference, entry[1])
            return snapshot.kind in self.available_kinds(snapshot.reference)
        except (ValueError, KeyError):
            return False
