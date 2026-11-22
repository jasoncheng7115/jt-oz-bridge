"""Authorize a complete private audience before reading a project/session catalog."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from sqlalchemy import func, select, true
from sqlalchemy.sql import Select

from jt_oz_bridge.domain.catalog import (
    BackendPage,
    CatalogBackend,
    CatalogPage,
    CatalogProject,
    ProjectPage,
    ProjectScope,
    RecentSession,
    SessionCatalog,
)
from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Grant


@dataclass(frozen=True)
class RegisteredCatalog:
    backend_identity: str
    contract_sha256: str
    projects: Mapping[str, str]
    client: SessionCatalog

    def __post_init__(self) -> None:
        if (
            not self.backend_identity
            or not re.fullmatch(r"[0-9a-f]{64}", self.contract_sha256)
            or not self.projects
        ):
            raise ValueError("invalid_catalog_registration")
        object.__setattr__(self, "projects", MappingProxyType(dict(self.projects)))


class DiscoveryService:
    def __init__(
        self,
        bindings: BindingService,
        catalogs: Mapping[str, RegisteredCatalog],
        *,
        adoption: SessionAdoptionService | None = None,
        channel_projects: Mapping[int, frozenset[str]] | None = None,
    ) -> None:
        if adoption is not None and adoption.bindings is not bindings:
            raise ValueError("discovery_adoption_original_bindings_required")
        self.bindings, self.db = bindings, bindings.db
        self.catalogs = MappingProxyType(dict(catalogs))
        self.adoption = adoption
        self.channel_projects = MappingProxyType(dict(channel_projects or {}))

    async def audience(
        self, message: HumanMessage, *, allow_edited_static: bool = False
    ) -> AudienceSnapshot:
        if message.is_bot or message.deleted or message.revision != 0 and not allow_edited_static:
            raise AccessDenied("discovery_requires_current_original_human_message")
        audience = await self.bindings.audience.inspect(
            message.realm_id, message.channel_id, message.topic
        )
        if (audience.realm_id, audience.channel_id, audience.canonical_topic) != (
            message.realm_id,
            message.channel_id,
            message.topic,
        ):
            raise Conflict("discovery_topic_not_canonical")
        if (
            not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
        ):
            raise AccessDenied("discovery_requires_private_verified_audience")
        return audience

    async def project(
        self, message: HumanMessage, identity: str
    ) -> tuple[CatalogProject, AudienceSnapshot]:
        audience = await self.audience(message)
        return await self._project_in_audience(message, identity, audience), audience

    async def inspect_projects(
        self,
        message: HumanMessage,
        identities: tuple[str, ...],
        *,
        allow_edited_static: bool = False,
    ) -> tuple[tuple[CatalogProject, ...], AudienceSnapshot]:
        """One fresh complete audience inspection for one local scope check.

        No observation is cached or accepted from a caller. Project/grant reads
        remain fresh; output transactions repeat their local predicates.
        """
        if (
            len(identities) > 10
            or len(set(identities)) != len(identities)
            or identities
            and allow_edited_static
        ):
            raise ValueError("invalid_discovery_project_inspection")
        audience = await self.audience(message, allow_edited_static=allow_edited_static)
        projects = tuple(
            [
                await self._project_in_audience(message, identity, audience)
                for identity in identities
            ]
        )
        return projects, audience

    async def _project_in_audience(
        self, message: HumanMessage, identity: str, audience: AudienceSnapshot
    ) -> CatalogProject:
        # Only callers which just inspected the complete audience use this
        # local helper. It performs no remote read and retains every SQL ACL.
        async with self.db.sessions() as session:
            project = await session.get(EnrolledProject, identity)
            backend = await session.get(EnrolledBackend, project.backend_id) if project else None
        if (
            not project
            or not backend
            or project.realm_id != message.realm_id
            or not project.enabled
            or not backend.enabled
            or not backend.verified
            or message.channel_id in self.channel_projects
            and project.id not in self.channel_projects[message.channel_id]
        ):
            raise AccessDenied("discovery_project_unavailable")
        await self.bindings.policy.require(
            message.realm_id, message.author_id, project.id, Permission.VIEW
        )
        await self.bindings.require_audience(audience, project.id)
        scope = ProjectScope(
            backend_id=backend.id,
            backend_identity=backend.identity,
            project_id=project.id,
            canonical_directory=project.canonical_directory,
        )
        registered = self.catalogs.get(backend.id)
        if (
            registered is None
            or registered.backend_identity != backend.identity
            or registered.contract_sha256 != backend.contract_hash
            or registered.projects.get(project.id) != project.canonical_directory
            or registered.client.contract_for_project(scope) != backend.contract_hash
        ):
            raise Conflict("discovery_installed_catalog_contract_unavailable")
        return CatalogProject(
            scope=scope, contract_sha256=backend.contract_hash, backend_version=backend.version
        )

    def candidate_projects(
        self, message: HumanMessage, audience: AudienceSnapshot
    ) -> Select[tuple[str]]:
        roles = [role for role, permissions in ROLES.items() if Permission.VIEW in permissions]
        # COUNT(DISTINCT actor) handles multiple roles without mistaking them for
        # complete channel membership. The author is already in this audience.
        return (
            select(EnrolledProject.id)
            .join(EnrolledBackend, EnrolledBackend.id == EnrolledProject.backend_id)
            .join(Grant, Grant.project_id == EnrolledProject.id)
            .where(
                EnrolledProject.realm_id == message.realm_id,
                EnrolledProject.enabled.is_(True),
                EnrolledBackend.enabled.is_(True),
                EnrolledBackend.verified.is_(True),
                Grant.realm_id == message.realm_id,
                Grant.user_id.in_(audience.user_ids),
                Grant.active.is_(True),
                Grant.role.in_(roles),
            )
            .where(
                EnrolledProject.id.in_(self.channel_projects[message.channel_id])
                if message.channel_id in self.channel_projects
                else true()
            )
            .group_by(EnrolledProject.id)
            .having(func.count(func.distinct(Grant.user_id)) == len(audience.user_ids))
        )

    async def backends(self, message: HumanMessage, *, after: str | None = None) -> BackendPage:
        audience = await self.audience(message)
        async with self.db.sessions() as session:
            query = (
                select(EnrolledBackend)
                .join(EnrolledProject, EnrolledProject.backend_id == EnrolledBackend.id)
                .where(EnrolledProject.id.in_(self.candidate_projects(message, audience)))
            )
            if after is not None:
                query = query.where(EnrolledBackend.id > after)
            rows = list(
                (
                    await session.scalars(query.distinct().order_by(EnrolledBackend.id).limit(11))
                ).all()
            )
        # Validate a current authorized project/client in each disclosed backend.
        items = []
        checked = []
        for backend in rows[:10]:
            async with self.db.sessions() as session:
                ids = list(
                    (
                        await session.scalars(
                            self.candidate_projects(message, audience)
                            .where(EnrolledProject.backend_id == backend.id)
                            .order_by(EnrolledProject.id)
                            .limit(100)
                        )
                    ).all()
                )
            project = None
            for identity in ids:
                try:
                    project = await self._project_in_audience(message, identity, audience)
                except AccessDenied:
                    continue
                break
            if project is None:
                raise Conflict("discovery_backend_audience_changed")
            if (
                project.scope.backend_identity,
                project.contract_sha256,
                project.backend_version,
            ) != (backend.identity, backend.contract_hash, backend.version):
                raise Conflict("discovery_backend_enrollment_changed")
            items.append(
                CatalogBackend(
                    backend_id=backend.id,
                    backend_identity=backend.identity,
                    contract_sha256=backend.contract_hash,
                    version=backend.version,
                )
            )
            checked.append(project)
        current_audience = await self.audience(message)
        if current_audience != audience:
            raise Conflict("discovery_backend_audience_changed")
        for project in checked:
            if (
                await self._project_in_audience(message, project.scope.project_id, current_audience)
                != project
            ):
                raise Conflict("discovery_backend_enrollment_changed")
        return BackendPage(
            items=tuple(items), after=after, next_after=rows[9].id if len(rows) > 10 else None
        )

    async def projects(
        self, message: HumanMessage, *, after: str | None = None, backend_id: str | None = None
    ) -> ProjectPage:
        page, _audience = await self._projects_observed(message, after=after, backend_id=backend_id)
        return page

    async def _projects_observed(
        self, message: HumanMessage, *, after: str | None = None, backend_id: str | None = None
    ) -> tuple[ProjectPage, AudienceSnapshot]:
        # Internal same-operation observation for menu context construction only.
        # Output preparation/commit and delivery still independently authorize.
        initial_audience = await self.audience(message)
        async with self.db.sessions() as session:
            query = self.candidate_projects(message, initial_audience)
            if after is not None:
                query = query.where(EnrolledProject.id > after)
            if backend_id is not None:
                query = query.where(EnrolledProject.backend_id == backend_id)
            ids = list((await session.scalars(query.order_by(EnrolledProject.id).limit(101))).all())
        visible: list[CatalogProject] = []
        next_after = None
        scanned = None
        for position, identity in enumerate(ids[:100]):
            scanned = identity
            try:
                project = await self._project_in_audience(message, identity, initial_audience)
            except AccessDenied:
                continue
            visible.append(project)
            if len(visible) == 10:
                if position + 1 < len(ids):
                    next_after = identity
                break
        else:
            if len(ids) > 100:
                next_after = scanned
        # Recheck each disclosed scope after asynchronous policy/audience reads.
        audience = await self.audience(message)
        if audience != initial_audience:
            raise Conflict("discovery_audience_changed_during_project_page")
        for project in visible:
            current = await self._project_in_audience(message, project.scope.project_id, audience)
            if current != project or audience != initial_audience:
                raise Conflict("discovery_project_page_changed")
        return ProjectPage(items=tuple(visible), after=after, next_after=next_after), audience

    async def sessions(
        self, message: HumanMessage, project_id: str, *, search: str = "", cursor: str | None = None
    ) -> CatalogPage:
        if len(search) > 256 or cursor is not None and (not cursor or len(cursor) > 8192):
            raise ValueError("invalid_catalog_query")
        project, audience = await self.project(message, project_id)
        page = await self.catalogs[project.scope.backend_id].client.list_sessions(
            project.scope, search=search, cursor=cursor, limit=10
        )
        page = CatalogPage.model_validate(page.model_dump(mode="json"))
        page = await self._with_original_selections(message, project_id, page)
        current, current_audience = await self.project(message, project_id)
        if (
            current != project
            or current_audience != audience
            or page.scope != project.scope
            or page.contract_sha256 != project.contract_sha256
            or page.search != search
            or page.cursor != cursor
        ):
            raise Conflict("discovery_catalog_scope_or_authorization_changed")
        return page

    async def _with_original_selections(
        self,
        message: HumanMessage,
        project_id: str,
        page: CatalogPage,
        audience: AudienceSnapshot | None = None,
    ) -> CatalogPage:
        if self.adoption is not None and project_id in self.adoption.factories:
            items = []
            for item in page.items:
                if item.archived:
                    # Retain the page boundary; archived rows are not adopted.
                    items.append(item)
                    continue
                selected = (
                    await self.adoption.selection_observed(message, item.reference, audience)
                    if audience is not None
                    else await self.adoption.selection(message, item.reference)
                )
                items.append(item.model_copy(update={"selection": selected}))
            page = page.model_copy(update={"items": tuple(items)})
        return page

    async def _projects_in_operation(
        self, message: HumanMessage, audience: AudienceSnapshot
    ) -> ProjectPage:
        """Local catalog reads inside the closed observer, never standalone authority."""
        async with self.db.sessions() as session:
            ids = list(
                (
                    await session.scalars(
                        self.candidate_projects(message, audience)
                        .order_by(EnrolledProject.id)
                        .limit(101)
                    )
                ).all()
            )
        visible: list[CatalogProject] = []
        next_after = None
        scanned = None
        for position, identity in enumerate(ids[:100]):
            scanned = identity
            try:
                project = await self._project_in_audience(message, identity, audience)
            except AccessDenied:
                continue
            visible.append(project)
            if len(visible) == 10:
                if position + 1 < len(ids):
                    next_after = identity
                break
        else:
            if len(ids) > 100:
                next_after = scanned
        return ProjectPage(items=tuple(visible), next_after=next_after)

    async def _sessions_in_operation(
        self, message: HumanMessage, project_id: str, audience: AudienceSnapshot
    ) -> tuple[CatalogPage, CatalogProject]:
        """Fresh SQL admission and original Native GET within one closed observation."""
        project = await self._project_in_audience(message, project_id, audience)
        page = await self.catalogs[project.scope.backend_id].client.list_sessions(
            project.scope, search="", cursor=None, limit=10
        )
        page = CatalogPage.model_validate(page.model_dump(mode="json"))
        page = await self._with_original_selections(message, project_id, page, audience)
        current = await self._project_in_audience(message, project_id, audience)
        if (
            current != project
            or page.scope != project.scope
            or page.contract_sha256 != project.contract_sha256
            or page.search != ""
            or page.cursor is not None
        ):
            raise Conflict("discovery_operation_catalog_or_authority_changed")
        return page, project

    async def recent(self, message: HumanMessage) -> tuple[RecentSession, ...]:
        await self.audience(message)
        async with self.db.sessions() as session:
            rows = list(
                (
                    await session.scalars(
                        select(Binding)
                        .where(
                            Binding.realm_id == message.realm_id,
                            Binding.owner_id == message.author_id,
                        )
                        .order_by(Binding.created_at.desc(), Binding.id.desc())
                        .limit(100)
                    )
                ).all()
            )
        results, seen = [], set()
        for binding in rows:
            try:
                project, _audience = await self.project(message, binding.project_id)
            except AccessDenied:
                continue
            ref = reference(binding)
            if not project.scope.contains(ref) or ref in seen:
                continue
            seen.add(ref)
            results.append(
                RecentSession(
                    reference=ref, title_at_binding=binding.title, bound_at=binding.created_at
                )
            )
            if len(results) == 10:
                break
        return tuple(results)
