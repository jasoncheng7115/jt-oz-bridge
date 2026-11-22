"""Read-only catalogs; listing a session is not proof of execution ownership."""

from typing import Protocol, Self

from pydantic import Field, StrictBool, model_validator

from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection


class ProjectScope(ControlModel):
    backend_id: str = Field(min_length=1, max_length=255)
    backend_identity: str = Field(min_length=1, max_length=255)
    project_id: str = Field(min_length=1, max_length=255)
    canonical_directory: str = Field(min_length=1, max_length=8192)

    def contains(self, reference: SessionRef) -> bool:
        return all(getattr(reference, key) == value for key, value in self.model_dump().items())


class CatalogProject(ControlModel):
    scope: ProjectScope
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    backend_version: str


class CatalogBackend(ControlModel):
    backend_id: str
    backend_identity: str
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: str


class BackendPage(ControlModel):
    items: tuple[CatalogBackend, ...] = Field(max_length=10)
    after: str | None = None
    next_after: str | None = None


class ProjectPage(ControlModel):
    items: tuple[CatalogProject, ...] = Field(max_length=10)
    after: str | None = None
    next_after: str | None = None


class CatalogSession(ControlModel):
    reference: SessionRef
    title: str = Field(max_length=100000)
    state: ExecutionState = ExecutionState.UNKNOWN
    archived: StrictBool = False
    updated_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    selection: ExistingSessionSelection | None = None


class CatalogPage(ControlModel):
    scope: ProjectScope
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    search: str = Field(max_length=256)
    cursor: str | None = Field(default=None, max_length=8192)
    items: tuple[CatalogSession, ...] = Field(max_length=10)
    next_cursor: str | None = Field(default=None, min_length=1, max_length=8192)

    @model_validator(mode="after")
    def scoped(self) -> Self:
        identities = [item.reference for item in self.items]
        if len(set(identities)) != len(identities) or any(
            not self.scope.contains(ref) or not ref.upstream_session_id for ref in identities
        ):
            raise ValueError("catalog_session_scope_or_identity_mismatch")
        if any(
            item.selection is not None
            and (
                item.selection.reference != item.reference
                or item.selection.contract_sha256 != self.contract_sha256
            )
            for item in self.items
        ):
            raise ValueError("catalog_original_selection_identity_mismatch")
        if self.next_cursor is not None and self.next_cursor == self.cursor:
            raise ValueError("catalog_cursor_did_not_advance")
        return self


class RecentSession(ControlModel):
    reference: SessionRef
    title_at_binding: str
    bound_at: float = Field(ge=0, allow_inf_nan=False)


class SessionCatalog(Protocol):
    def contract_for_project(self, scope: ProjectScope) -> str: ...

    async def list_sessions(
        self, scope: ProjectScope, *, search: str, cursor: str | None, limit: int
    ) -> CatalogPage: ...
