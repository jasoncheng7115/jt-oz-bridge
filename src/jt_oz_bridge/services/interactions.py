"""Durable decisions. Queuing a reply never claims upstream approval/completion."""

import hashlib
import re
import time
from typing import Literal

from sqlalchemy import delete, select, update

from jt_oz_bridge.domain.control import (
    AudienceSnapshot,
    FieldAnswer,
    InteractionSnapshot,
    draft_answers,
    validate_answers,
)
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.form_input import skipped_fields
from jt_oz_bridge.domain.operations import current_operation
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import (
    Binding,
    ControlToken,
    EnrolledBackend,
    EnrolledProject,
    FormDraft,
    PendingInteraction,
)
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, uid
from jt_oz_bridge.storage.statements import insert


def short_code(interaction_id: str) -> str:
    """Four digits a phone can type; a clash among pending requests is refused, never guessed."""
    return str(1000 + int(hashlib.sha256(interaction_id.encode()).hexdigest()[:8], 16) % 9000)


class InteractionService:
    def __init__(self, bindings: BindingService, *, fence: ConsumerFence | None = None) -> None:
        self.bindings, self.db = bindings, bindings.db
        self.fence = fence
        self.tokens = TokenService(self.db, fence=fence)

    async def lineage(self, binding: Binding, snapshot: InteractionSnapshot) -> None:
        root = reference(binding)
        latest = await self.bindings.control.snapshot(root)
        if latest.reference != root or not latest.reconciled:
            raise Conflict("session synchronization unavailable")
        permitted = (root, *latest.descendants)
        if snapshot.reference not in permitted:
            raise AccessDenied("request is not in the bound session lineage")
        for child in permitted:
            if (
                child.backend_id != root.backend_id
                or child.backend_identity != root.backend_identity
                or child.project_id != root.project_id
                or child.canonical_directory != root.canonical_directory
            ):
                raise AccessDenied("descendant scope mismatch")

    async def observe(
        self,
        binding: Binding,
        snapshot: InteractionSnapshot,
        *,
        ttl: int = 900,
        audience: AudienceSnapshot | None = None,
    ) -> str:
        """Record one pending request for its bound topic.

        ``audience`` is only for a caller that read Zulip in full for this
        same decision moments ago and reads it in full again before its own
        commit; then only the owned SQL scope is re-checked here.
        """
        if ttl <= 0 or ttl > 3600:
            raise ValueError("invalid interaction lifetime")
        await self.bindings.enrolled(reference(binding), binding.realm_id)
        if audience is None:
            await self.bindings.audience_for_output(binding)
        else:
            await self.bindings.require_output_audience(binding, audience)
        await self.lineage(binding, snapshot)
        data = snapshot.model_dump(mode="json")
        # Preserve hashes for the original form/synthetic snapshot layout. Native
        # permission previews use their own versioned normalization generation.
        if snapshot.permission_details is None:
            data.pop("permission_details", None)
        identity = digest(
            {
                "reference": snapshot.reference.model_dump(),
                "request": snapshot.upstream_request_id,
                "generation": snapshot.generation,
            }
        )
        async with self.db.sessions() as session:
            prior = await session.scalar(
                select(PendingInteraction).where(PendingInteraction.identity_key == identity)
            )
            prior_binding = await session.get(Binding, prior.binding_id) if prior else None
        rescope = prior is not None and (
            prior.binding_id != binding.id or prior.binding_revision != binding.revision
        )
        if rescope:
            if (
                prior is None
                or prior_binding is None
                or prior.state != "pending"
                or prior.action_id is not None
                or prior.winner_user_id is not None
                or prior.snapshot_hash != digest(data)
                or not snapshot.pending
                or prior_binding.realm_id != binding.realm_id
                or prior.binding_id != binding.id
                and prior_binding.state != "unbound"
            ):
                raise Conflict("pending_request_cannot_change_binding")
            # All native I/O stays outside the local write transaction. Neither
            # a replayed event nor an old cached binding can authorize a transfer.
            try:
                current = await self.bindings.control.interaction(
                    snapshot.reference, snapshot.upstream_request_id
                )
            except Exception:
                raise Conflict("pending_request_freshness_unavailable") from None
            if current != snapshot or not current.pending:
                raise Conflict("pending_request_changed_before_rescope")
            await self.lineage(binding, snapshot)
            await self.bindings.enrolled(reference(binding), binding.realm_id)
            await self.bindings.audience_for_output(binding)
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            locked = list(
                (
                    await session.scalars(
                        select(Binding)
                        .where(
                            Binding.id.in_({binding.id, prior.binding_id if prior else binding.id})
                        )
                        .order_by(Binding.id)
                        .with_for_update()
                    )
                ).all()
            )
            actual = next((row for row in locked if row.id == binding.id), None)
            if (
                actual is None
                or actual.state != "active"
                or binding.state != "active"
                or actual.revision != binding.revision
                or actual.realm_id != binding.realm_id
                or reference(actual) != reference(binding)
                or (
                    actual.channel_id,
                    actual.topic,
                    actual.audience_revision,
                    actual.audience_user_ids,
                )
                != (
                    binding.channel_id,
                    binding.topic,
                    binding.audience_revision,
                    binding.audience_user_ids,
                )
            ):
                raise Conflict("interaction_binding_changed_before_commit")
            backend = await session.scalar(
                select(EnrolledBackend)
                .where(EnrolledBackend.id == binding.backend_id)
                .with_for_update()
            )
            project = await session.scalar(
                select(EnrolledProject)
                .where(EnrolledProject.id == binding.project_id)
                .with_for_update()
            )
            if (
                not backend
                or not backend.enabled
                or not backend.verified
                or backend.identity != binding.backend_identity
                or backend.contract_hash != self.bindings.control.contract_for(reference(binding))
                or not project
                or not project.enabled
                or project.backend_id != binding.backend_id
                or project.realm_id != binding.realm_id
                or project.canonical_directory != binding.canonical_directory
            ):
                raise AccessDenied("interaction_enrollment_changed_before_commit")
            grants = list(
                (
                    await session.scalars(
                        select(Grant)
                        .where(
                            Grant.realm_id == binding.realm_id,
                            Grant.project_id == binding.project_id,
                            Grant.user_id.in_(binding.audience_user_ids),
                            Grant.active.is_(True),
                        )
                        .order_by(Grant.id)
                        .with_for_update()
                    )
                ).all()
            )
            if {
                grant.user_id for grant in grants if Permission.VIEW in ROLES.get(grant.role, set())
            } != set(binding.audience_user_ids):
                raise AccessDenied("interaction_audience_grants_changed_before_commit")
            interaction_id = (
                await session.execute(
                    insert(self.db, PendingInteraction)
                    .values(
                        identity_key=identity,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                        snapshot=data,
                        snapshot_hash=digest(data),
                        expires_at=time.time() + ttl,
                        state="pending" if snapshot.pending else "resolved",
                    )
                    .on_conflict_do_nothing(index_elements=["identity_key"])
                    .returning(PendingInteraction.id)
                )
            ).scalar_one_or_none()
            if interaction_id:
                return str(interaction_id)
            existing = (
                await session.scalars(
                    select(PendingInteraction)
                    .where(PendingInteraction.identity_key == identity)
                    .with_for_update()
                )
            ).one()
            if existing.binding_id != binding.id or existing.binding_revision != binding.revision:
                old_binding = next((row for row in locked if row.id == existing.binding_id), None)
                if (
                    not rescope
                    or prior is None
                    or prior_binding is None
                    or existing.version != prior.version
                    or existing.snapshot_hash != digest(data)
                    or existing.binding_id != prior.binding_id
                    or existing.binding_revision != prior.binding_revision
                    or existing.state != "pending"
                    or existing.action_id is not None
                    or existing.winner_user_id is not None
                    or not snapshot.pending
                    or old_binding is None
                    or old_binding.realm_id != binding.realm_id
                    or old_binding.revision != prior_binding.revision
                    or existing.binding_id != binding.id
                    and old_binding.state != "unbound"
                ):
                    raise Conflict("pending_request_cannot_change_binding")
                existing.binding_id = binding.id
                existing.binding_revision = binding.revision
                existing.version += 1
                # Do not carry unsubmitted private answers to another topic, nor
                # prolong the original expiry through background observation.
                await session.execute(
                    delete(FormDraft).where(FormDraft.interaction_id == existing.id)
                )
                session.add(
                    AuditEvent(
                        actor="worker",
                        event="unadmitted_interaction_rescoped",
                        object_id=existing.id,
                    )
                )
            if existing.state == "pending" and not snapshot.pending:
                existing.state, existing.version = "resolved", existing.version + 1
            elif existing.state == "pending" and existing.snapshot_hash != digest(data):
                raise Conflict("request schema changed; reconcile before issuing replies")
            return existing.id

    async def request(self, interaction_id: str) -> PendingInteraction:
        async with self.db.sessions() as session:
            saved = await session.get(PendingInteraction, interaction_id)
        if not saved or saved.state != "pending" or saved.expires_at <= time.time():
            raise Conflict("interaction resolved, expired or unavailable")
        return saved

    async def refresh_expired(
        self, interaction_id: str, realm: str, user_id: int, *, ttl: int = 900
    ) -> bool:
        """Explicit human inspection may renew a still-pending verified request.

        Old tokens remain invalid; this neither queues a decision nor cancels upstream.
        """
        if ttl <= 0 or ttl > 3600:
            raise ValueError("invalid_interaction_lifetime")
        async with self.db.sessions() as session:
            saved = await session.get(PendingInteraction, interaction_id)
        if (
            not saved
            or saved.state != "pending"
            or saved.action_id is not None
            or saved.winner_user_id is not None
        ):
            raise Conflict("interaction_not_available_for_refresh")
        if saved.expires_at > time.time():
            return False
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        needed = Permission.APPROVE if snapshot.kind == "permission" else Permission.OPERATE
        binding = await self.bindings.get(saved.binding_id, realm, user_id, needed)
        if binding.revision != saved.binding_revision:
            raise Conflict("interaction_binding_changed")
        await self.lineage(binding, snapshot)
        current = await self.bindings.control.interaction(
            snapshot.reference, snapshot.upstream_request_id
        )
        if current == snapshot.model_copy(update={"pending": False}):
            async with self.db.sessions.begin() as session:
                if self.fence is not None:
                    await self.fence.lock(session)
                await session.execute(
                    update(PendingInteraction)
                    .where(
                        PendingInteraction.id == saved.id,
                        PendingInteraction.state == "pending",
                        PendingInteraction.version == saved.version,
                    )
                    .values(state="resolved", version=PendingInteraction.version + 1)
                )
            raise Conflict("expired_interaction_resolved_upstream")
        if current != snapshot or not current.pending:
            raise Conflict("expired_interaction_not_pending_upstream")
        now = time.time()
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            changed = await session.execute(
                update(PendingInteraction)
                .where(
                    PendingInteraction.id == saved.id,
                    PendingInteraction.state == "pending",
                    PendingInteraction.version == saved.version,
                    PendingInteraction.expires_at <= now,
                    PendingInteraction.snapshot_hash == saved.snapshot_hash,
                    PendingInteraction.action_id.is_(None),
                    PendingInteraction.winner_user_id.is_(None),
                    select(Binding.id)
                    .where(
                        Binding.id == binding.id,
                        Binding.state == "active",
                        Binding.revision == saved.binding_revision,
                    )
                    .exists(),
                )
                .values(expires_at=now + ttl, version=PendingInteraction.version + 1)
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("interaction_changed_during_refresh")
            session.add(
                AuditEvent(
                    actor=f"{realm}:{user_id}", event="interaction_refreshed", object_id=saved.id
                )
            )
        return True

    async def issue(self, interaction_id: str, realm: str, user_id: int) -> str:
        saved = await self.request(interaction_id)
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        permission = Permission.APPROVE if snapshot.kind == "permission" else Permission.OPERATE
        binding = await self.bindings.get(saved.binding_id, realm, user_id, permission)
        if binding.revision != saved.binding_revision:
            raise Conflict("interaction binding changed")
        await self.bindings.audience_for_output(binding)
        return await self.tokens.issue(
            "interaction",
            realm,
            user_id,
            {
                "interaction_id": saved.id,
                "snapshot_hash": saved.snapshot_hash,
                "interaction_version": saved.version,
            },
            ttl=max(1, min(900, int(saved.expires_at - time.time()))),
            binding_id=binding.id,
            binding_revision=binding.revision,
        )

    async def save_answer(
        self,
        token: str,
        realm: str,
        user_id: int,
        field_id: str,
        answer: FieldAnswer,
        expected_revision: int = 0,
    ) -> int:
        control = await self.tokens.inspect(token, "interaction", realm, user_id)
        saved = await self.request(control.context["interaction_id"])
        if (
            control.context.get("interaction_version") != saved.version
            or control.context["snapshot_hash"] != saved.snapshot_hash
        ):
            raise Conflict("request changed")
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        if snapshot.kind != "form":
            raise Conflict("interaction is not a form")
        await self.bindings.get(saved.binding_id, realm, user_id, Permission.OPERATE)
        key = digest({"request": saved.id, "user": user_id})
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            if expected_revision == 0:
                answers = draft_answers(snapshot.fields, {}, field_id, answer)
                inserted = (
                    await session.execute(
                        insert(self.db, FormDraft)
                        .values(
                            key=key,
                            interaction_id=saved.id,
                            user_id=user_id,
                            snapshot_hash=saved.snapshot_hash,
                            progress={"skipped": []},
                            answers={
                                key: value.model_dump(mode="json") for key, value in answers.items()
                            },
                            revision=1,
                        )
                        .on_conflict_do_nothing(index_elements=["key"])
                        .returning(FormDraft.key)
                    )
                ).scalar_one_or_none()
                if inserted:
                    return 1
                raise Conflict("draft revision changed")
            draft = await session.get(FormDraft, key)
            if (
                not draft
                or draft.snapshot_hash != saved.snapshot_hash
                or draft.interaction_id != saved.id
                or draft.user_id != user_id
            ):
                raise Conflict("draft unavailable or belongs to another snapshot")
            answers = draft_answers(
                snapshot.fields,
                {key: FieldAnswer.model_validate(value) for key, value in draft.answers.items()},
                field_id,
                answer,
            )
            result = await session.execute(
                update(FormDraft)
                .where(FormDraft.key == key, FormDraft.revision == expected_revision)
                .values(
                    answers={key: value.model_dump(mode="json") for key, value in answers.items()},
                    progress={
                        "skipped": sorted(skipped_fields(draft.progress, snapshot.fields, answers))
                    },
                    revision=expected_revision + 1,
                )
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("draft revision changed")
            return expected_revision + 1

    async def reply(
        self,
        token: str,
        realm: str,
        user_id: int,
        *,
        decision: Literal["once", "reject", "always"] | None = None,
        answers: dict[str, FieldAnswer] | None = None,
        reason: str | None = None,
        source: HumanMessage | None = None,
        confirmation: ControlToken | None = None,
        draft_revision: int | None = None,
        cancel: bool = False,
        code: str | None = None,
    ) -> str:
        control = await self.tokens.inspect(token, "interaction", realm, user_id)
        saved = await self.request(control.context["interaction_id"])
        if (
            control.context["snapshot_hash"] != saved.snapshot_hash
            or control.context.get("interaction_version") != saved.version
        ):
            raise Conflict("request changed")
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        needed = Permission.APPROVE if snapshot.kind == "permission" else Permission.OPERATE
        binding = await self.bindings.get(saved.binding_id, realm, user_id, needed)
        if source is not None and (
            source.is_bot
            or source.deleted
            or (source.realm_id, source.author_id, source.channel_id, source.topic)
            != (realm, user_id, binding.channel_id, binding.topic)
        ):
            raise AccessDenied("interaction_source_outside_binding")
        if source is not None:
            parsed = parse_input(source.text, bound=True)
            expected = (
                "confirm"
                if cancel
                else "answer"
                if snapshot.kind == "form"
                else "approve"
                if decision == "once"
                else "deny"
            )
            if (
                parsed.kind != "command"
                or parsed.command != expected
                or (
                    snapshot.kind == "permission"
                    and code is None
                    and parsed.arguments.split(maxsplit=1)[0:1] != [token]
                )
                # A notice code names this exact request in the human's own message.
                or code is not None
                and (
                    cancel
                    or code != short_code(saved.id)
                    or parsed.arguments.split(maxsplit=1)[0:1] != [code]
                )
            ):
                raise AccessDenied("interaction_source_operation_mismatch")
        if reason is not None and (
            snapshot.kind != "permission" or decision != "reject" or len(reason) > 10000
        ):
            raise ValueError("invalid_permission_denial_reason")
        if cancel and (
            snapshot.kind != "form"
            or confirmation is None
            or answers is not None
            or decision is not None
            or reason is not None
        ):
            raise AccessDenied("form_cancel_requires_scoped_confirmation")
        if cancel:
            pass  # Cancellation carries no answers; required fields may remain empty.
        elif snapshot.kind == "permission":
            if answers is not None or decision not in {"once", "reject"}:
                raise AccessDenied("permission decision unavailable; broad authorization disabled")
        else:
            if decision is not None:
                raise ValueError("form reply requires field answers")
            if answers is None:
                async with self.db.sessions() as session:
                    draft = await session.get(
                        FormDraft, digest({"request": saved.id, "user": user_id})
                    )
                    if draft and (
                        draft.snapshot_hash != saved.snapshot_hash
                        or draft.interaction_id != saved.id
                        or draft.user_id != user_id
                    ):
                        raise Conflict("draft snapshot or actor changed")
                    answers = (
                        {
                            key: FieldAnswer.model_validate(value)
                            for key, value in draft.answers.items()
                        }
                        if draft
                        else {}
                    )
            validate_answers(snapshot.fields, answers)
        await self.lineage(binding, snapshot)
        current = await self.bindings.control.interaction(
            snapshot.reference, snapshot.upstream_request_id
        )
        if not current.pending:
            if current != snapshot.model_copy(update={"pending": False}):
                raise Conflict("resolved_interaction_identity_changed")
            async with self.db.sessions.begin() as session:
                if self.fence is not None:
                    await self.fence.lock(session)
                await session.execute(
                    update(PendingInteraction)
                    .where(PendingInteraction.id == saved.id, PendingInteraction.state == "pending")
                    .values(state="resolved", version=PendingInteraction.version + 1)
                )
            raise Conflict("interaction resolved upstream")
        if current != snapshot:
            raise Conflict("upstream interaction changed")
        await self.bindings.policy.require(realm, user_id, binding.project_id, needed)
        await self.bindings.enrolled(reference(binding), realm)
        await self.bindings.audience_for_output(binding)
        action_id = uid()
        payload = {
            "operation": "form.cancel" if cancel else f"{snapshot.kind}.reply",
            "interaction_id": saved.id,
            "reference": snapshot.reference.model_dump(),
            "request_id": snapshot.upstream_request_id,
            "generation": snapshot.generation,
            "decision": decision,
            "answers": {
                key: value.model_dump(mode="json") for key, value in (answers or {}).items()
            },
        }
        if cancel:
            payload.pop("answers")
            payload.pop("decision")
        if reason is not None:
            payload["reason"] = reason
        if source is not None:
            payload["source"] = source.model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            if confirmation is not None:
                confirmation_source = parse_input(source.text, bound=True) if source else None
                pattern = r"([A-Za-z0-9_-]{32})" if cancel else r"([A-Za-z0-9_-]{32})[ \t\n]submit"
                confirmed = (
                    re.fullmatch(pattern, confirmation_source.arguments)
                    if confirmation_source
                    else None
                )
                if (
                    source is None
                    or source.revision != 0
                    or confirmation_source is None
                    or confirmation_source.command != ("confirm" if cancel else "answer")
                    or confirmed is None
                    or token_hash(confirmed[1]) != confirmation.token_hash
                ):
                    raise AccessDenied("form_explicit_review_confirmation_required")
                if (
                    snapshot.kind != "form"
                    or confirmation.kind != ("form-cancel" if cancel else "form-submit")
                    or confirmation.realm_id != realm
                    or confirmation.user_id != user_id
                    or confirmation.binding_id != binding.id
                    or confirmation.binding_revision != binding.revision
                    or confirmation.context.get("root") != token
                    or type(draft_revision) is not int
                    or confirmation.context.get("revision") != draft_revision
                ):
                    raise Conflict("form_confirmation_scope_changed")
                draft = await session.get(FormDraft, digest({"request": saved.id, "user": user_id}))
                actual_answers = draft.answers if draft else {}
                progress = draft.progress if draft else {"skipped": []}
                if (
                    (draft.revision if draft else 0) != draft_revision
                    or draft is not None
                    and (
                        draft.snapshot_hash != saved.snapshot_hash
                        or draft.interaction_id != saved.id
                        or draft.user_id != user_id
                    )
                    or not cancel
                    and actual_answers != payload["answers"]
                    or confirmation.context.get("fingerprint")
                    != digest(
                        {
                            "answers": actual_answers,
                            "skipped": sorted(
                                skipped_fields(
                                    progress,
                                    snapshot.fields,
                                    {
                                        k: FieldAnswer.model_validate(v)
                                        for k, v in actual_answers.items()
                                    },
                                )
                            ),
                        }
                    )
                ):
                    raise Conflict("form_reviewed_draft_changed")
                await self.tokens.consume_in_session(session, confirmation)
            elif draft_revision is not None:
                raise Conflict("form_confirmation_required")
            binding_exists = (
                select(Binding.id)
                .where(
                    Binding.id == binding.id,
                    Binding.state == "active",
                    Binding.revision == saved.binding_revision,
                )
                .exists()
            )
            result = await session.execute(
                update(PendingInteraction)
                .where(
                    PendingInteraction.id == saved.id,
                    PendingInteraction.state == "pending",
                    PendingInteraction.snapshot_hash == saved.snapshot_hash,
                    PendingInteraction.version == saved.version,
                    PendingInteraction.expires_at > time.time(),
                    binding_exists,
                )
                .values(
                    state="reply_queued",
                    winner_user_id=user_id,
                    action_id=action_id,
                    version=saved.version + 1,
                )
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("another decision or binding revision won")
            consumed = await session.execute(
                update(ControlToken)
                .where(
                    ControlToken.token_hash == token_hash(token),
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                    ControlToken.context_hash == control.context_hash,
                    ControlToken.user_id == user_id,
                    ControlToken.realm_id == realm,
                )
                .values(used=True)
            )
            if consumed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("interaction token expired or already used")
            session.add(
                Action(
                    id=action_id,
                    dedupe_key=f"interaction:{saved.id}:{saved.version}",
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=user_id,
                    operation_digest=digest(payload),
                    payload=payload,
                    operation=current_operation(payload),
                    state="held" if binding.dispatch_paused else "queued",
                )
            )
            session.add(
                AuditEvent(
                    actor=f"{realm}:{user_id}", event="interaction_reply_queued", object_id=saved.id
                )
            )
        return action_id
