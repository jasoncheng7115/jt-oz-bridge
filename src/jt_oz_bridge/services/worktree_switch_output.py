"""Explicit bound, dual-project output; legacy discovery stays unbound."""

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4
from weakref import ReferenceType, ref

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.output_target import WorktreeSwitchPreviewTarget
from jt_oz_bridge.domain.worktree_switch import ObservedWorktreeSwitch
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import scope
from jt_oz_bridge.services.output_destinations import OutputDestinations
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Grant
from jt_oz_bridge.storage.output_models import OutputDestination


def preview_binding_guards(target: WorktreeSwitchPreviewTarget) -> tuple[ColumnElement[bool], ...]:
    original, source = target.original_scope, target.source
    old = original.reference
    conditions: list[ColumnElement[bool]] = [
        select(Binding.id)
        .where(
            Binding.id == original.binding_id,
            Binding.state == "active",
            Binding.revision == original.revision,
            Binding.realm_id == original.realm_id,
            Binding.channel_id == original.channel_id,
            Binding.topic == original.topic,
            Binding.backend_id == old.backend_id,
            Binding.backend_identity == old.backend_identity,
            Binding.project_id == old.project_id,
            Binding.canonical_directory == old.canonical_directory,
            Binding.session_id == old.upstream_session_id,
            Binding.owner_id == original.owner_id,
            Binding.anchor_message_id == original.anchor_message_id,
            Binding.audience_revision == original.audience_revision,
            Binding.audience_user_ids == sorted(original.audience_user_ids),
        )
        .exists()
    ]
    for project, permission in (
        (old.project_id, Permission.MANAGE),
        (target.target_reference.project_id, Permission.OPERATE),
    ):
        conditions.append(
            select(Grant.id)
            .where(
                Grant.realm_id == source.realm_id,
                Grant.user_id == source.author_id,
                Grant.project_id == project,
                Grant.active.is_(True),
                Grant.role.in_([r for r, p in ROLES.items() if permission in p]),
            )
            .exists()
        )
    return tuple(conditions)


@dataclass
class _Issued:
    target: ReferenceType[WorktreeSwitchPreviewTarget]
    permit: ZulipLocalWritePermit
    source: HumanMessage
    audience: AudienceSnapshot
    native: ObservedWorktreeSwitch
    session: AsyncSession | None = None


if TYPE_CHECKING:
    from jt_oz_bridge.services.worktree_switch import WorktreeSwitchCommands


class WorktreeSwitchPreviews:
    def __init__(self, destinations: OutputDestinations, owner: "WorktreeSwitchCommands") -> None:
        reader = destinations.reader
        if (
            type(reader) is not ZulipSourceReader
            or destinations.discovery.bindings.audience is not reader.scope
            or destinations.switch_previews is not None
        ):
            raise ValueError("worktree_previews_require_original_scope_issuer")
        self.destinations, self.reader, self.owner = destinations, reader, owner
        self._issued: dict[int, _Issued] = {}
        destinations.switch_previews = self

    async def issue(
        self,
        source: HumanMessage,
        audience: AudienceSnapshot,
        binding: Binding,
        target: SessionRef,
        operation_sha256: str,
        native: ObservedWorktreeSwitch,
    ) -> WorktreeSwitchPreviewTarget:
        self.owner.require_native(native, source, target)
        permit = self.reader.scope.local_write_permit(self.reader, source, audience)
        self.reader.scope.require_read_permit(permit, self.reader, source, audience)
        projects = tuple(
            [
                await self.destinations.discovery._project_in_audience(source, p, audience)
                for p in (binding.project_id, target.project_id)
            ]
        )
        self.reader.scope.require_read_permit(permit, self.reader, source, audience)
        now = time.time()
        result = WorktreeSwitchPreviewTarget(
            id=uuid4(),
            source=source,
            audience=audience,
            projects=projects,
            purpose="catalog",
            issued_at=now,
            expires_at=now + 60,
            original_scope=scope(binding),
            target_reference=target,
            operation_sha256=operation_sha256,
        )
        await self.authorize_observed(result, audience)
        self.reader.scope.require_read_permit(permit, self.reader, source, audience)
        if len(self._issued) >= 1000:
            raise Conflict("worktree_preview_capacity")
        key = id(result)
        self._issued[key] = _Issued(
            ref(result, lambda _: self._issued.pop(key, None)), permit, source, audience, native
        )
        return result

    def require_write(self, target: WorktreeSwitchPreviewTarget, session: AsyncSession) -> None:
        saved = self._issued.get(id(target))
        if (
            self.destinations.switch_previews is not self
            or self.destinations.reader is not self.reader
            or self.destinations.discovery.bindings.audience is not self.reader.scope
            or saved is None
            or saved.target() is not target
            or saved.session is not None
            and saved.session is not session
        ):
            raise AccessDenied("worktree_preview_original_issuer_required")
        self.reader.scope.require_write_permit(
            saved.permit, self.reader, saved.source, saved.audience
        )
        self.owner.require_native(saved.native, saved.source, target.target_reference)
        saved.session = session

    async def authorize_observed(
        self, target: WorktreeSwitchPreviewTarget, audience: AudienceSnapshot
    ) -> None:
        target = WorktreeSwitchPreviewTarget.model_validate(target.model_dump(mode="json"))
        self.destinations.validate_source_kind(target)
        if audience != target.audience or not target.issued_at <= time.time() < target.expires_at:
            raise AccessDenied("worktree_preview_current_audience_or_expiry_changed")
        projects = tuple(
            [
                await self.destinations.discovery._project_in_audience(
                    target.source, p.scope.project_id, audience
                )
                for p in target.projects
            ]
        )
        if projects != target.projects:
            raise Conflict("worktree_preview_project_changed")
        async with self.destinations.db.sessions() as session:
            if not await session.scalar(select(and_(*self.destinations.guards(target)))):
                raise AccessDenied("worktree_preview_scope_or_grants_changed")

    async def authorize(self, target: WorktreeSwitchPreviewTarget) -> None:
        """Fresh closed Source observation for every page; no reusable write proof."""
        reader, scope_reader = self.reader, self.reader.scope
        if self.destinations.reader is not reader:
            raise Conflict("worktree_preview_reader_changed")

        async def read_only(audience: AudienceSnapshot) -> None:
            await self.authorize_observed(target, audience)

        sources = (target.source,)
        observation = await scope_reader.observe_sources(reader, sources, read_only=read_only)
        completed = scope_reader.consume_observation(observation, reader, sources)
        if completed.audience != target.audience:
            raise AccessDenied("worktree_preview_final_audience_changed")

    async def persist_in_session(
        self, session: AsyncSession, source_key: str, target: WorktreeSwitchPreviewTarget
    ) -> str:
        if not source_key or len(source_key) > 255:
            raise ValueError("worktree_preview_output_key_invalid")
        self.require_write(target, session)
        await self.destinations.fence.lock(session)
        self.require_write(target, session)
        if not await session.scalar(select(and_(*self.destinations.guards(target)))):
            raise AccessDenied("worktree_preview_final_local_scope_changed")
        self.require_write(target, session)
        stored = await session.scalar(
            select(OutputDestination).where(OutputDestination.dedupe_key == source_key)
        )
        self.require_write(target, session)
        if stored is not None:
            if self.destinations.decode(stored) != target:
                raise Conflict("worktree_preview_output_key_reused")
        else:
            data = target.model_dump(mode="json")
            session.add(
                OutputDestination(
                    id=str(target.id),
                    dedupe_key=source_key,
                    realm_id=target.source.realm_id,
                    authorization=data,
                    authorization_hash=digest(data),
                    state="active",
                    expires_at=target.expires_at,
                )
            )
            await session.flush()
            self.require_write(target, session)
        if not await session.scalar(select(and_(*self.destinations.guards(target)))):
            raise AccessDenied("worktree_preview_final_local_scope_changed")
        self.require_write(target, session)
        return str(target.id)
