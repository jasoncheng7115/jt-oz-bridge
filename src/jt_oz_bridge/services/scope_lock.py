"""Network-free current output-scope checks inside a caller's fenced transaction."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Grant


async def lock_output_scope(
    bindings: BindingService, session: AsyncSession, expected: Binding
) -> Binding:
    current = await session.scalar(
        select(Binding).where(Binding.id == expected.id).with_for_update()
    )
    if (
        current is None
        or current.state != "active"
        or expected.state != "active"
        or current.revision != expected.revision
        or current.realm_id != expected.realm_id
        or reference(current) != reference(expected)
        or (current.channel_id, current.topic, current.audience_revision, current.audience_user_ids)
        != (
            expected.channel_id,
            expected.topic,
            expected.audience_revision,
            expected.audience_user_ids,
        )
    ):
        raise Conflict("output_scope_binding_changed_before_commit")
    backend = await session.scalar(
        select(EnrolledBackend).where(EnrolledBackend.id == current.backend_id).with_for_update()
    )
    project = await session.scalar(
        select(EnrolledProject).where(EnrolledProject.id == current.project_id).with_for_update()
    )
    if (
        not backend
        or not backend.enabled
        or not backend.verified
        or backend.identity != current.backend_identity
        or backend.contract_hash != bindings.control.contract_for(reference(current))
        or not project
        or not project.enabled
        or project.backend_id != current.backend_id
        or project.realm_id != current.realm_id
        or project.canonical_directory != current.canonical_directory
    ):
        raise AccessDenied("output_scope_enrollment_changed_before_commit")
    grants = list(
        (
            await session.scalars(
                select(Grant)
                .where(
                    Grant.realm_id == current.realm_id,
                    Grant.project_id == current.project_id,
                    Grant.user_id.in_(current.audience_user_ids),
                    Grant.active.is_(True),
                )
                .order_by(Grant.id)
                .with_for_update()
            )
        ).all()
    )
    if not current.audience_user_ids or {
        grant.user_id for grant in grants if Permission.VIEW in ROLES.get(grant.role, set())
    } != set(current.audience_user_ids):
        raise AccessDenied("output_scope_audience_grants_changed_before_commit")
    return current
