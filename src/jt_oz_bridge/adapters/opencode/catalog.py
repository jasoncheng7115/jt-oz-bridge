"""Exact read-only V2 project/session catalogs, separately attested from ownership."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.transport import V2HTTPTransport
from jt_oz_bridge.domain.catalog import CatalogPage, CatalogSession, ProjectScope
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.models import SessionRef


@dataclass(frozen=True)
class V2CatalogProject:
    scope: ProjectScope
    upstream_project_id: str

    def __post_init__(self) -> None:
        if not self.upstream_project_id or len(self.upstream_project_id) > 255:
            raise ValueError("explicit_native_project_identity_required")


def epoch_seconds(milliseconds: object) -> float | None:
    """Native session times are milliseconds; anything else is simply not shown."""
    if type(milliseconds) not in {int, float} or not 0 <= milliseconds < 1e15:  # type: ignore[operator]
        return None
    return float(milliseconds) / 1000  # type: ignore[arg-type]


class V2SessionCatalog:
    def __init__(
        self,
        transport: V2HTTPTransport,
        projects: Mapping[str, V2CatalogProject],
        *,
        root_projects: frozenset[str] = frozenset(),
    ) -> None:
        if not projects or any(key != value.scope.project_id for key, value in projects.items()):
            raise ValueError("invalid_v2_catalog_project_registration")
        identities = {
            (value.scope.backend_id, value.scope.backend_identity) for value in projects.values()
        }
        if len(identities) != 1:
            raise ValueError("v2_catalog_cannot_mix_backend_instances")
        if type(root_projects) is not frozenset or not root_projects <= projects.keys():
            raise ValueError("v2_catalog_explicit_root_project_scope_required")
        self.transport, self.projects = transport, MappingProxyType(dict(projects))
        self.root_projects = root_projects

    def selected(self, scope: ProjectScope) -> V2CatalogProject:
        entry = self.projects.get(scope.project_id)
        if entry is None or entry.scope != scope:
            raise ContractError("v2_catalog_project_scope_mismatch")
        attestation = self.transport.attestation
        if (
            attestation is None
            or attestation.backend_identity != scope.backend_identity
            or attestation.schema_sha256 != self.transport.profile.sha256
            or "session.list" not in attestation.verified_operations
        ):
            raise ContractError("v2_catalog_installed_read_contract_not_attested")
        return entry

    def contract_for_project(self, scope: ProjectScope) -> str:
        self.selected(scope)
        return self.transport.profile.sha256

    async def identity(self) -> None:
        if self.transport.verify_identity is None or not await self.transport.verify_identity():
            raise ContractError("v2_catalog_backend_identity_unverified")

    async def list_sessions(
        self, scope: ProjectScope, *, search: str, cursor: str | None, limit: int
    ) -> CatalogPage:
        if (
            type(limit) is not int
            or not 1 <= limit <= 10
            or len(search) > 256
            or cursor is not None
            and (not cursor or len(cursor) > 8192)
        ):
            raise ValueError("invalid_v2_session_catalog_query")
        entry = self.selected(scope)
        await self.identity()
        self.selected(scope)
        # The published V2 query declares limit as string, not JSON number.
        query = {
            "directory": scope.canonical_directory,
            "project": entry.upstream_project_id,
            "limit": str(limit),
            "order": "desc",
            "search": search,
        }
        if scope.project_id in self.root_projects:
            query["parentID"] = "null"
        if cursor is not None:
            query["cursor"] = cursor
        value = await self.transport.request("session.list", query=query)
        self.selected(scope)
        await self.identity()
        self.selected(scope)
        items = []
        for raw in value["data"]:
            if (
                raw["projectID"] != entry.upstream_project_id
                or raw["location"]["directory"] != scope.canonical_directory
                or scope.project_id in self.root_projects
                and raw.get("parentID") is not None
            ):
                raise ContractError("v2_catalog_returned_foreign_project_or_workspace")
            # Validate a native ID as an inert path component before publishing
            # it as a selectable entry; this performs no session.get request.
            self.transport.profile.prepare("session.get", path={"sessionID": raw["id"]})
            # Session.active reports root coordinator ownership, including a
            # backgrounded root; it does not certify children/jobs or idle.
            items.append(
                CatalogSession(
                    reference=SessionRef(**scope.model_dump(), upstream_session_id=raw["id"]),
                    title=raw.get("title", raw["id"]),
                    state=ExecutionState.UNKNOWN,
                    archived="archived" in raw["time"],
                    updated_at=epoch_seconds(raw["time"].get("updated")),
                )
            )
        return CatalogPage(
            scope=scope,
            contract_sha256=self.transport.profile.sha256,
            search=search,
            cursor=cursor,
            items=tuple(items),
            next_cursor=value["cursor"].get("next"),
        )
