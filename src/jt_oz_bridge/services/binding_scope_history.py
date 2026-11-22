"""Owned append-only scope links in existing audit storage; no inferred moves.

Only BindingService's authorized transaction writes links. They authorize no
Native action or output, and remain necessary while a created Root is active.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import AuditEvent

EVENT = "binding_rescope_v1"
MAX_MOVES = 1000


def scope(binding: Binding) -> BindingScope:
    if (
        not isinstance(binding.audience_user_ids, list)
        or any(type(user) is not int or user <= 0 for user in binding.audience_user_ids)
        or binding.audience_user_ids != sorted(set(binding.audience_user_ids))
    ):
        raise Conflict("binding_scope_current_audience_not_canonical")
    return BindingScope(
        binding_id=binding.id,
        revision=binding.revision,
        realm_id=binding.realm_id,
        channel_id=binding.channel_id,
        topic=binding.topic,
        reference=SessionRef(
            backend_id=binding.backend_id,
            backend_identity=binding.backend_identity,
            upstream_session_id=binding.session_id,
            project_id=binding.project_id,
            canonical_directory=binding.canonical_directory,
        ),
        owner_id=binding.owner_id,
        anchor_message_id=binding.anchor_message_id,
        audience_revision=binding.audience_revision,
        audience_user_ids=frozenset(binding.audience_user_ids),
    )


def checksum(value: BindingScope) -> str:
    data = value.model_dump(mode="json")
    data["audience_user_ids"] = sorted(value.audience_user_ids)
    return digest(data)


def move_event(before: BindingScope, after: BindingScope, actor: int) -> AuditEvent:
    if (
        before.binding_id != after.binding_id
        or after.revision != before.revision + 1
        or (before.realm_id, before.reference, before.owner_id, before.anchor_message_id)
        != (after.realm_id, after.reference, after.owner_id, after.anchor_message_id)
        or type(actor) is not int
        or actor <= 0
    ):
        raise Conflict("binding_scope_move_identity_changed")
    return AuditEvent(
        actor=f"{before.realm_id}:{actor}",
        event=EVENT,
        object_id=f"{before.binding_id}:{before.revision}:{after.revision}:{checksum(before)}:{checksum(after)}",
    )


async def validate_history(
    session: AsyncSession,
    original: BindingScope,
    current: BindingScope,
    *,
    lock: bool = False,
) -> None:
    if (
        original.binding_id,
        original.realm_id,
        original.reference,
        original.owner_id,
        original.anchor_message_id,
    ) != (
        current.binding_id,
        current.realm_id,
        current.reference,
        current.owner_id,
        current.anchor_message_id,
    ) or not 0 <= current.revision - original.revision <= MAX_MOVES:
        raise Conflict("binding_scope_restore_outside_original_identity")
    if original.revision == current.revision:
        if current != original:
            raise Conflict("binding_scope_changed_without_revision")
        return
    query = (
        select(AuditEvent)
        .where(
            AuditEvent.event == EVENT,
            AuditEvent.object_id.startswith(original.binding_id + ":"),
        )
        .order_by(AuditEvent.id)
        .limit(MAX_MOVES + 1)
    )
    if lock:
        query = query.with_for_update()
    rows = list((await session.scalars(query)).all())
    if len(rows) != current.revision - original.revision:
        raise Conflict("binding_scope_restore_chain_missing_or_ambiguous")
    links = {}
    for row in rows:
        parts = row.object_id.split(":")
        if len(parts) != 5 or parts[0] != original.binding_id:
            raise Conflict("binding_scope_restore_link_invalid")
        before, after, first, second = parts[1:]
        actor = row.actor.removeprefix(original.realm_id + ":")
        if (
            not before.isascii()
            or not before.isdecimal()
            or not after.isascii()
            or not after.isdecimal()
            or str(int(before)) != before
            or str(int(after)) != after
            or int(after) != int(before) + 1
            or int(before) in links
            or any(
                len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)
                for sha in (first, second)
            )
            or not row.actor.startswith(original.realm_id + ":")
            or not actor.isascii()
            or not actor.isdecimal()
            or str(int(actor)) != actor
            or int(actor) <= 0
        ):
            raise Conflict("binding_scope_restore_link_invalid")
        links[int(before)] = (int(after), first, second)
    expected = checksum(original)
    for revision in range(original.revision, current.revision):
        link = links.get(revision)
        if link is None or link[:2] != (revision + 1, expected):
            raise Conflict("binding_scope_restore_chain_discontinuous")
        expected = link[2]
    if expected != checksum(current):
        raise Conflict("binding_scope_restore_current_scope_changed")
