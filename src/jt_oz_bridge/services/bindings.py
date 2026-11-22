"""Existing-session binding. No method in this service can create/fork/prompt a backend."""

from collections.abc import Awaitable, Callable

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import AudienceProvider, AudienceSnapshot, SessionControl
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission, Policy
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import (
    Binding,
    ControlToken,
    EnrolledBackend,
    EnrolledProject,
)
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AuditEvent, Grant


def reference(binding: Binding) -> SessionRef:
    return SessionRef(
        backend_id=binding.backend_id,
        backend_identity=binding.backend_identity,
        upstream_session_id=binding.session_id,
        project_id=binding.project_id,
        canonical_directory=binding.canonical_directory,
    )


def topic_key(realm: str, channel: int, canonical_topic: str) -> str:
    # Name is supplied by the verified server-specific resolver, never casefolded here.
    return digest({"realm": realm, "channel": channel, "topic": canonical_topic})


class BindingService:
    def __init__(self, db: Database, control: SessionControl, audience: AudienceProvider) -> None:
        self.db, self.control, self.audience = db, control, audience
        self.policy = Policy(db)

    async def enrolled(self, selected: SessionRef, realm: str) -> None:
        async with self.db.sessions() as session:
            backend = await session.get(EnrolledBackend, selected.backend_id)
            project = await session.get(EnrolledProject, selected.project_id)
        if (
            not backend
            or not project
            or not backend.enabled
            or not backend.verified
            or not project.enabled
        ):
            raise AccessDenied("backend/project not certified and enabled")
        if (
            backend.identity != selected.backend_identity
            or backend.contract_hash != self.control.contract_for(selected)
            or project.backend_id != backend.id
            or project.realm_id != realm
            or project.canonical_directory != selected.canonical_directory
        ):
            raise AccessDenied("backend/project identity mismatch")

    async def require_audience(self, audience: AudienceSnapshot, project: str) -> None:
        if audience.untrusted_bot_ids:
            raise AccessDenied("unapproved bot audience")
        await self.policy.require_audience(
            audience.realm_id, set(audience.user_ids), project, private=audience.private
        )

    async def bind(
        self,
        realm: str,
        user_id: int,
        channel: int,
        topic: str,
        selected: SessionRef,
        locale: Locale = "en",
        *,
        confirmation: tuple[TokenService, ControlToken] | None = None,
        fence: ConsumerFence | None = None,
        anchor_message_id: int | None = None,
        validate_source: Callable[[], Awaitable[None]] | None = None,
        selection: ExistingSessionSelection | None = None,
        validate_current: Callable[[], bool] | None = None,
        before_write: Callable[[], None] | None = None,
    ) -> Binding:
        if (
            (selection is None) != (validate_current is None)
            or selection is not None
            and (confirmation is None or selection.reference != selected)
        ):
            raise ValueError("binding_original_selection_and_final_fence_required")
        if confirmation is not None and validate_source is None:
            raise ValueError("binding_confirmation_source_verifier_required")
        if confirmation is not None and confirmation[0].db is not self.db:
            raise ValueError("binding_confirmation_database_mismatch")
        if anchor_message_id is not None and (
            type(anchor_message_id) is not int or anchor_message_id <= 0
        ):
            raise ValueError("binding_anchor_message_invalid")
        await self.policy.require(realm, user_id, selected.project_id, Permission.OPERATE)
        await self.enrolled(selected, realm)
        audience = await self.audience.inspect(realm, channel, topic)
        if audience.realm_id != realm or audience.channel_id != channel:
            raise AccessDenied("audience identity mismatch")
        await self.require_audience(audience, selected.project_id)
        if user_id not in audience.user_ids:
            raise AccessDenied("actor is not in the channel audience")
        snapshot = await self.control.snapshot(selected)
        if snapshot.reference != selected or not snapshot.reconciled:
            raise Conflict("original execution identity or synchronization unverified")
        # Recheck after network awaits; do not keep a SQL transaction over transport I/O.
        current = await self.audience.inspect(realm, channel, audience.canonical_topic)
        if current != audience:
            raise Conflict("audience changed while binding")
        await self.policy.require(realm, user_id, selected.project_id, Permission.OPERATE)
        await self.require_audience(current, selected.project_id)
        await self.enrolled(selected, realm)
        if confirmation is not None:
            _tokens, token = confirmation
            expected = {
                "reference": selected.model_dump(mode="json"),
                "channel_id": channel,
                "topic": current.canonical_topic,
                "audience_hash": digest(current.model_dump(mode="json")),
                "title": snapshot.title,
            }
            if selection is not None:
                expected["selection"] = selection.model_dump(mode="json")
            if (
                token.kind != "binding-confirm"
                or token.realm_id != realm
                or token.user_id != user_id
                or token.binding_id is not None
                or token.context != expected
            ):
                raise Conflict("binding_confirmation_scope_or_title_changed")
        if validate_source is not None:
            await validate_source()
        binding = Binding(
            realm_id=realm,
            anchor_message_id=anchor_message_id,
            channel_id=channel,
            topic=current.canonical_topic,
            backend_id=selected.backend_id,
            backend_identity=selected.backend_identity,
            session_id=selected.upstream_session_id,
            project_id=selected.project_id,
            canonical_directory=selected.canonical_directory,
            title=snapshot.title,
            owner_id=user_id,
            locale=locale,
            audience_revision=current.revision,
            audience_user_ids=sorted(current.user_ids),
            observed_cursor=snapshot.cursor,
            session_key=digest(
                {
                    "realm": realm,
                    "backend": selected.backend_id,
                    "identity": selected.backend_identity,
                    "session": selected.upstream_session_id,
                }
            ),
            topic_key=topic_key(realm, channel, current.canonical_topic),
        )
        # Signal the irreversible-attempt boundary before acquiring a write
        # transaction. Callers may retry proven GET-only preparation failures,
        # but never classify failures beyond this point as preparation.
        if before_write is not None:
            before_write()
        try:
            async with self.db.sessions.begin() as session:
                if fence is not None:
                    await fence.lock(session)
                if confirmation is not None:
                    await confirmation[0].consume_in_session(session, confirmation[1])
                # Lock and recheck mutable enrollment/grants after network awaits.
                # SQLite already holds BEGIN IMMEDIATE; PostgreSQL locks these
                # exact rows so revocation cannot cross the binding commit.
                backend = await session.scalar(
                    select(EnrolledBackend)
                    .where(EnrolledBackend.id == selected.backend_id)
                    .with_for_update()
                )
                project = await session.scalar(
                    select(EnrolledProject)
                    .where(EnrolledProject.id == selected.project_id)
                    .with_for_update()
                )
                if (
                    not backend
                    or not project
                    or not backend.enabled
                    or not backend.verified
                    or not project.enabled
                    or backend.identity != selected.backend_identity
                    or backend.contract_hash != self.control.contract_for(selected)
                    or project.backend_id != backend.id
                    or project.realm_id != realm
                    or project.canonical_directory != selected.canonical_directory
                ):
                    raise AccessDenied("binding_enrollment_changed_before_commit")
                grants = list(
                    (
                        await session.scalars(
                            select(Grant)
                            .where(
                                Grant.realm_id == realm,
                                Grant.project_id == selected.project_id,
                                Grant.user_id.in_(current.user_ids),
                                Grant.active.is_(True),
                            )
                            .order_by(Grant.id)
                            .with_for_update()
                        )
                    ).all()
                )
                viewers = {
                    grant.user_id
                    for grant in grants
                    if Permission.VIEW in ROLES.get(grant.role, set())
                }
                if viewers != set(current.user_ids) or not any(
                    grant.user_id == user_id and Permission.OPERATE in ROLES.get(grant.role, set())
                    for grant in grants
                ):
                    raise AccessDenied("binding_grants_changed_before_commit")
                session.add(binding)
                await session.flush()
                session.add(
                    AuditEvent(
                        actor=f"{realm}:{user_id}", event="session_bound", object_id=binding.id
                    )
                )
                if validate_current is not None:
                    await session.flush()
                    if validate_current() is not True:
                        raise Conflict("binding_original_selection_changed_before_commit")
        except IntegrityError:
            raise Conflict("session or topic already has a writable binding") from None
        return binding

    async def get(
        self, binding_id: str, realm: str, user_id: int, permission: Permission = Permission.VIEW
    ) -> Binding:
        async with self.db.sessions() as session:
            binding = await session.get(Binding, binding_id)
        if not binding or binding.realm_id != realm or binding.state != "active":
            raise AccessDenied("binding unavailable")
        await self.policy.require(realm, user_id, binding.project_id, permission)
        await self.enrolled(reference(binding), realm)
        audience = await self.audience_for_output(binding)
        if user_id not in audience.user_ids:
            raise AccessDenied("actor is not in the channel audience")
        return binding

    async def unbind(self, binding_id: str, realm: str, user_id: int, revision: int) -> None:
        binding = await self.get(binding_id, realm, user_id, Permission.MANAGE)
        async with self.db.sessions.begin() as session:
            await self.unbind_in_session(session, binding.id, realm, user_id, revision)

    @staticmethod
    async def unbind_in_session(
        session: AsyncSession, binding_id: str, realm: str, user_id: int, revision: int
    ) -> None:
        """The caller has already checked MANAGE."""
        result = await session.execute(
            update(Binding)
            .where(
                Binding.id == binding_id,
                Binding.revision == revision,
                Binding.state == "active",
            )
            .values(
                state="unbound",
                revision=revision + 1,
                session_key=None,
                topic_key=None,
                dispatch_paused=True,
            )
        )
        if result.rowcount != 1:  # type: ignore[attr-defined]
            raise Conflict("binding revision changed")
        session.add(
            AuditEvent(actor=f"{realm}:{user_id}", event="session_unbound", object_id=binding_id)
        )

    async def move(
        self,
        binding_id: str,
        realm: str,
        user_id: int,
        revision: int,
        channel: int,
        topic: str,
        *,
        whole_topic: bool,
    ) -> None:
        binding = await self.get(binding_id, realm, user_id, Permission.MANAGE)
        if not whole_topic:
            raise Conflict("single-message move cannot rebind a session")
        audience = await self.audience.inspect(realm, channel, topic)
        if audience.realm_id != realm or audience.channel_id != channel:
            raise AccessDenied("audience identity mismatch")
        await self.require_audience(audience, binding.project_id)
        if await self.audience.inspect(realm, channel, audience.canonical_topic) != audience:
            raise Conflict("destination audience changed while moving")
        from jt_oz_bridge.services.binding_scope_history import move_event, scope
        from jt_oz_bridge.services.scope_lock import lock_output_scope

        # Future dispatch and interactions must recheck the new binding revision.
        try:
            async with self.db.sessions.begin() as session:
                current = await lock_output_scope(self, session, binding)
                if current.revision != revision:
                    raise Conflict("binding revision changed")
                readers = list(
                    (
                        await session.scalars(
                            select(Grant)
                            .where(
                                Grant.realm_id == realm,
                                Grant.project_id == binding.project_id,
                                Grant.user_id.in_(set(audience.user_ids) | {user_id}),
                                Grant.active.is_(True),
                            )
                            .order_by(Grant.id)
                            .with_for_update()
                        )
                    ).all()
                )
                if not any(
                    g.user_id == user_id and Permission.MANAGE in ROLES.get(g.role, set())
                    for g in readers
                ) or {
                    g.user_id
                    for g in readers
                    if g.user_id in audience.user_ids
                    and Permission.VIEW in ROLES.get(g.role, set())
                } != set(audience.user_ids):
                    raise AccessDenied("move_authority_or_destination_grants_changed")
                before = scope(current)
                after = before.model_copy(
                    update={
                        "revision": revision + 1,
                        "channel_id": channel,
                        "topic": audience.canonical_topic,
                        "audience_revision": audience.revision,
                        "audience_user_ids": audience.user_ids,
                    }
                )
                result = await session.execute(
                    update(Binding)
                    .where(
                        Binding.id == binding_id,
                        Binding.revision == revision,
                        Binding.state == "active",
                    )
                    .values(
                        channel_id=channel,
                        topic=audience.canonical_topic,
                        topic_key=topic_key(realm, channel, audience.canonical_topic),
                        audience_revision=audience.revision,
                        audience_user_ids=sorted(audience.user_ids),
                        revision=revision + 1,
                        dispatch_paused=True,
                    )
                )
                if result.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("binding revision changed")
                session.add(move_event(before, after, user_id))
                session.add(
                    AuditEvent(
                        actor=f"{realm}:{user_id}", event="binding_moved_held", object_id=binding_id
                    )
                )
        except IntegrityError:
            raise Conflict("destination already bound") from None

    async def audience_for_output(self, binding: Binding) -> AudienceSnapshot:
        audience = await self.audience.inspect(binding.realm_id, binding.channel_id, binding.topic)
        await self.require_output_audience(binding, audience)
        return audience

    async def require_output_audience(self, binding: Binding, audience: AudienceSnapshot) -> None:
        if (
            audience.realm_id != binding.realm_id
            or audience.channel_id != binding.channel_id
            or audience.canonical_topic != binding.topic
            or audience.revision != binding.audience_revision
            or set(audience.user_ids) != set(binding.audience_user_ids)
        ):
            raise Conflict("audience changed; output held for review")
        await self.require_audience(audience, binding.project_id)

    def supports_read_capture(self) -> bool:
        from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader

        return isinstance(self.audience, ZulipScopeReader) and self.audience.supports_read_capture()

    async def capture_output[T](
        self,
        binding: Binding,
        read: Callable[[], Awaitable[T]],
        *,
        actor_id: int | None = None,
    ) -> T:
        """GET-only Native capture; neither admits nor dispatches an Action."""
        from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader

        audience_provider, control = self.audience, self.control
        original = (
            binding.id,
            binding.revision,
            binding.realm_id,
            reference(binding),
            binding.channel_id,
            binding.topic,
            binding.audience_revision,
            tuple(binding.audience_user_ids),
            binding.owner_id,
            binding.state,
        )

        async def authorize(audience: AudienceSnapshot) -> None:
            if (
                self.audience is not audience_provider
                or self.control is not control
                or original
                != (
                    binding.id,
                    binding.revision,
                    binding.realm_id,
                    reference(binding),
                    binding.channel_id,
                    binding.topic,
                    binding.audience_revision,
                    tuple(binding.audience_user_ids),
                    binding.owner_id,
                    binding.state,
                )
            ):
                raise Conflict("read_capture_binding_provider_changed")
            await self.enrolled(reference(binding), binding.realm_id)
            await self.require_output_audience(binding, audience)
            if actor_id is not None:
                await self.policy.require(
                    binding.realm_id, actor_id, binding.project_id, Permission.VIEW
                )
                if actor_id not in audience.user_ids:
                    raise AccessDenied("actor is not in the channel audience")

        if isinstance(audience_provider, ZulipScopeReader) and self.supports_read_capture():

            async def capture(audience: AudienceSnapshot) -> T:
                await authorize(audience)
                return await read()

            audience, value = await audience_provider.capture_readonly(
                binding.realm_id, binding.channel_id, binding.topic, capture
            )
            await authorize(audience)
            return value
        # Existing custom providers retain their original two complete reads.
        await authorize(
            await audience_provider.inspect(binding.realm_id, binding.channel_id, binding.topic)
        )
        value = await read()
        await authorize(
            await audience_provider.inspect(binding.realm_id, binding.channel_id, binding.topic)
        )
        return value
