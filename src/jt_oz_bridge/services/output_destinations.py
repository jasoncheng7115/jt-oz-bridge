"""Persist/recheck private discovery authorization without inventing a session."""

import time
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import and_, distinct, func, literal, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.output_target import (
    DiscoveryTarget,
    WorktreeSwitchPreviewTarget,
    output_target,
)
from jt_oz_bridge.presentation.commands import is_unbound_text, parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import topic_key
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AuditEvent, Grant
from jt_oz_bridge.storage.output_models import OutputDestination
from jt_oz_bridge.storage.statements import insert

if TYPE_CHECKING:
    from jt_oz_bridge.services.worktree_switch_output import WorktreeSwitchPreviews


class OutputDestinations:
    def __init__(
        self, discovery: DiscoveryService, reader: SourceReader, fence: ConsumerFence
    ) -> None:
        self.discovery, self.db, self.reader, self.fence = discovery, discovery.db, reader, fence
        self.switch_previews: WorktreeSwitchPreviews | None = None

    async def unbound(self, source: HumanMessage) -> None:
        async with self.db.sessions() as session:
            existing = await session.scalar(
                select(Binding.id).where(
                    Binding.topic_key
                    == topic_key(source.realm_id, source.channel_id, source.topic),
                    Binding.state == "active",
                )
            )
        if existing is not None:
            raise Conflict("discovery_output_topic_became_bound")

    async def prepare(
        self, source: HumanMessage, project_ids: tuple[str, ...], *, ttl: int = 900
    ) -> DiscoveryTarget:
        if (
            type(ttl) is not int
            or not 1 <= ttl <= 900
            or len(project_ids) > 10
            or len(set(project_ids)) != len(project_ids)
        ):
            raise ValueError("invalid_discovery_output_scope")
        parsed = parse_input(source.text)
        if (
            parsed.kind != "command"
            and not (
                not project_ids
                and (parsed.kind in {"unknown", "invalid"} or source.revision > 0)
                or source.revision == 0
                and is_unbound_text(source.text)
            )
            or await self.reader.read(source.realm_id, source.message_id) != source
        ):
            raise AccessDenied("discovery_output_source_changed")
        projects, audience = await self.discovery.inspect_projects(
            source, project_ids, allow_edited_static=not project_ids
        )
        await self.unbound(source)
        now = time.time()
        target = DiscoveryTarget(
            id=uuid4(),
            source=source,
            audience=audience,
            projects=projects,
            purpose="catalog" if projects else "static",
            issued_at=now,
            expires_at=now + ttl,
        )
        return target

    @staticmethod
    def validate_source_kind(target: DiscoveryTarget) -> None:
        if isinstance(target, WorktreeSwitchPreviewTarget):
            parsed = parse_input(target.source.text, bound=True)
            if parsed.kind != "command" or parsed.command not in {"worktree", "worktrees"}:
                raise AccessDenied("worktree_preview_requires_original_control")
            return
        parsed = parse_input(target.source.text)
        if parsed.kind != "command" and not (
            not target.projects
            and (parsed.kind in {"unknown", "invalid"} or target.source.revision > 0)
            or target.source.revision == 0
            and is_unbound_text(target.source.text)
        ):
            raise AccessDenied("discovery_output_requires_control_source")

    async def authorize(self, target: DiscoveryTarget) -> None:
        if isinstance(target, WorktreeSwitchPreviewTarget):
            if self.switch_previews is None:
                raise AccessDenied("worktree_preview_issuer_not_configured")
            await self.switch_previews.authorize(target)
            return
        target = output_target(target.model_dump(mode="json"))
        self.validate_source_kind(target)
        if target.expires_at <= time.time() or target.issued_at > time.time() + 5:
            raise Conflict("discovery_output_authorization_expired")
        if (
            await self.reader.read(target.source.realm_id, target.source.message_id)
            != target.source
        ):
            raise AccessDenied("discovery_output_source_changed")
        projects, audience = await self.discovery.inspect_projects(
            target.source,
            tuple(project.scope.project_id for project in target.projects),
            allow_edited_static=target.purpose == "static",
        )
        if audience != target.audience:
            raise AccessDenied("discovery_output_audience_changed")
        if projects != target.projects:
            raise Conflict("discovery_output_project_changed")
        await self.unbound(target.source)

    async def _authorize_observed(
        self, target: DiscoveryTarget, audience: AudienceSnapshot
    ) -> None:
        """Local read-only checks inside the same issuer's closed observation.

        Not a standalone authorization API. The observer must still finish its
        second complete Source/audience read, then be consumed synchronously.
        Delivery claim independently repeats every current local SQL predicate.
        """
        target = output_target(target.model_dump(mode="json"))
        if isinstance(target, WorktreeSwitchPreviewTarget):
            if self.switch_previews is None:
                raise AccessDenied("worktree_preview_issuer_not_configured")
            await self.switch_previews.authorize_observed(target, audience)
            return
        self.validate_source_kind(target)
        if audience != target.audience:
            raise AccessDenied("discovery_output_audience_changed")
        projects = tuple(
            [
                await self.discovery._project_in_audience(
                    target.source, project.scope.project_id, audience
                )
                for project in target.projects
            ]
        )
        if projects != target.projects:
            raise Conflict("discovery_output_project_changed")
        await self.unbound(target.source)
        if target.expires_at <= time.time() or target.issued_at > time.time() + 5:
            raise Conflict("discovery_output_authorization_expired")

    @staticmethod
    def guards(target: DiscoveryTarget) -> tuple[ColumnElement[bool], ...]:
        source, audience = target.source, target.audience
        if isinstance(target, WorktreeSwitchPreviewTarget):
            from jt_oz_bridge.services.worktree_switch_output import preview_binding_guards

            conditions = list(preview_binding_guards(target))
        else:
            conditions = [
                ~select(Binding.id)
                .where(
                    Binding.topic_key
                    == topic_key(source.realm_id, source.channel_id, source.topic),
                    Binding.state == "active",
                )
                .exists()
            ]
        allowed_roles = [
            role for role, permissions in ROLES.items() if Permission.VIEW in permissions
        ]
        for project in target.projects:
            scope = project.scope
            conditions.extend(
                (
                    select(EnrolledBackend.id)
                    .where(
                        EnrolledBackend.id == scope.backend_id,
                        EnrolledBackend.identity == scope.backend_identity,
                        EnrolledBackend.contract_hash == project.contract_sha256,
                        EnrolledBackend.version == project.backend_version,
                        EnrolledBackend.enabled.is_(True),
                        EnrolledBackend.verified.is_(True),
                    )
                    .exists(),
                    select(EnrolledProject.id)
                    .where(
                        EnrolledProject.id == scope.project_id,
                        EnrolledProject.backend_id == scope.backend_id,
                        EnrolledProject.realm_id == source.realm_id,
                        EnrolledProject.canonical_directory == scope.canonical_directory,
                        EnrolledProject.enabled.is_(True),
                    )
                    .exists(),
                    select(func.count(distinct(Grant.user_id)))
                    .where(
                        Grant.realm_id == source.realm_id,
                        Grant.project_id == scope.project_id,
                        Grant.user_id.in_(audience.user_ids),
                        Grant.role.in_(allowed_roles),
                        Grant.active.is_(True),
                    )
                    .scalar_subquery()
                    == len(audience.user_ids),
                )
            )
        return tuple(conditions)

    async def persist_in_session(
        self, session: AsyncSession, source_key: str, target: DiscoveryTarget
    ) -> str:
        if isinstance(target, WorktreeSwitchPreviewTarget):
            if self.switch_previews is None:
                raise AccessDenied("worktree_preview_issuer_not_configured")
            return await self.switch_previews.persist_in_session(session, source_key, target)
        if not source_key or len(source_key) > 255:
            raise ValueError("invalid_discovery_output_key")
        target = output_target(target.model_dump(mode="json"))
        self.validate_source_kind(target)
        await self.fence.lock(session)
        if not await session.scalar(select(and_(*self.guards(target)))):
            raise AccessDenied("discovery_output_local_authorization_changed")
        if target.expires_at <= time.time() or target.issued_at > time.time() + 5:
            raise Conflict("discovery_output_authorization_expired")
        saved = await session.scalar(
            select(OutputDestination).where(OutputDestination.dedupe_key == source_key)
        )
        if saved is None:
            saved = await session.get(OutputDestination, str(target.id))
        data = target.model_dump(mode="json")
        if saved is not None:
            previous = self.decode(saved)
            if previous != target:
                raise Conflict("discovery_output_key_reused")
            return saved.id
        columns = [
            "id",
            "dedupe_key",
            "realm_id",
            "authorization",
            "authorization_hash",
            "state",
            "expires_at",
            "created_at",
        ]
        values = select(
            literal(str(target.id)),
            literal(source_key),
            literal(target.source.realm_id),
            literal(data, type_=OutputDestination.__table__.c.authorization.type),
            literal(digest(data)),
            literal("active"),
            literal(target.expires_at),
            literal(time.time()),
        ).where(*self.guards(target))
        created = (
            await session.execute(
                insert(self.db, OutputDestination)
                .from_select(columns, values, include_defaults=False)
                .on_conflict_do_nothing(index_elements=["dedupe_key"])
                .returning(OutputDestination.id)
            )
        ).scalar_one_or_none()
        if created is None:
            raise AccessDenied("discovery_output_local_authorization_changed")
        session.add(
            AuditEvent(
                actor=f"{target.source.realm_id}:{target.source.author_id}",
                event="output_destination_created",
                object_id=str(target.id),
            )
        )
        await session.flush()
        return str(target.id)

    @staticmethod
    def decode(saved: OutputDestination) -> DiscoveryTarget:
        if saved.payload_compacted_at is not None:
            raise Conflict("discovery_output_authorization_retired")
        target = output_target(saved.authorization)
        if (
            saved.state != "active"
            or saved.authorization_hash != digest(saved.authorization)
            or str(target.id) != saved.id
            or saved.realm_id != target.source.realm_id
            or saved.expires_at != target.expires_at
        ):
            raise Conflict("discovery_output_destination_changed")
        return target

    async def save(self, source_key: str, target: DiscoveryTarget) -> str:
        await self.authorize(target)
        async with self.db.sessions.begin() as session:
            return await self.persist_in_session(session, source_key, target)

    async def cached(self, source_key: str) -> DiscoveryTarget | None:
        async with self.db.sessions() as session:
            saved = await session.scalar(
                select(OutputDestination).where(OutputDestination.dedupe_key == source_key)
            )
        if saved is None:
            return None
        target = self.decode(saved)
        await self.authorize(target)
        return target

    async def snapshot(self, identity: str) -> DiscoveryTarget:
        """Internal immutable evidence only; callers must authorize before disclosure."""
        async with self.db.sessions() as session:
            saved = await session.get(OutputDestination, identity)
        if saved is None:
            raise Conflict("discovery_output_destination_missing")
        return self.decode(saved)

    async def load(self, identity: str) -> DiscoveryTarget:
        target = await self.snapshot(identity)
        await self.authorize(target)
        return target

    async def revoke(self, identity: str) -> None:
        # Trusted operations primitive; no public/chat endpoint invokes this.
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await session.execute(
                update(OutputDestination)
                .where(OutputDestination.id == identity, OutputDestination.state == "active")
                .values(state="revoked")
            )
