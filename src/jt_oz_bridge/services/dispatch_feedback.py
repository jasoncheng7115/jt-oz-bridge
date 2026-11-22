"""Durable, scoped feedback for an adapter-proven unsent Native mutation.

Only newly recorded typed failures are eligible. The action UUID in the
renderer identifies its immutable batch without changing schema32 or changing
any historical payload. It is an index, never authorization or execution proof.
"""

import time
from collections.abc import Callable
from typing import cast
from uuid import UUID

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_lifecycle import LIFECYCLE_OPERATIONS
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.outbox import Outbox, QueuedBatch, batch_digest
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant

NOT_SENT = "native_mutation_not_sent"
ATTACHMENTS_OFF = "attachments_not_qualified"
PREFIX = "unsent-native-v1:"
# Nothing else tells a person their message stopped, so each stop that is not going
# away by itself says so once. An import still in progress is expected to continue.
NOTICES = {
    ("rejected", NOT_SENT): "action.not_sent",
    ("rejected", ATTACHMENTS_OFF): "action.attachments_off",
    ("held", "installed_contract_not_certified"): "action.held",
    ("held", "operation_index_changed"): "action.held",
    ("held", "queue_paused"): "action.held",
    ("held", "source_or_identity_changed"): "action.held",
    ("rejected", "source_or_identity_changed"): "action.source_changed",
    ("rejected", "preflight_unavailable"): "action.not_sent_unavailable",
    ("rejected", "native_state_unconfirmed"): "action.not_sent_unconfirmed",
    ("rejected", "native_prompt_never_arrived"): "action.not_sent_never_arrived",
    ("rejected", "session_unavailable"): "action.not_sent_session_unavailable",
    ("rejected", "schedule_unavailable"): "action.not_sent_schedule_off",
    ("held", "workspace_attachments_not_qualified"): "action.held",
    ("rejected", "lifecycle_confirmation_expired"): "lifecycle.expired",
    ("rejected", "lifecycle_session_busy"): "lifecycle.busy",
    ("rejected", "lifecycle_queue_paused"): "lifecycle.paused",
    ("rejected", "lifecycle_not_available"): "lifecycle.unavailable",
    ("rejected", "lifecycle_native_refused"): "lifecycle.refused",
    ("rejected", "git_publish_confirmation_expired"): "git_publish.expired",
    ("rejected", "git_publish_source_changed"): "git_publish.refused",
    ("rejected", "git_publish_queue_paused"): "git_publish.paused",
    ("rejected", "git_publish_not_available"): "git_publish.unavailable",
}
OPERATIONS = LIFECYCLE_OPERATIONS | frozenset(
    {
        "git.publish",
        "prompt",
        "interrupt",
        "model.switch",
        "session.rename",
        "check.run",
        "permission.reply",
        "form.reply",
        "form.cancel",
    }
)


def renderer(action_id: str, version: int) -> str:
    if (
        str(UUID(action_id)) != action_id
        or type(version) is not int
        or not 1 <= version <= 2147483647
    ):
        raise Conflict("unsent_feedback_action_identity_invalid")
    return PREFIX + action_id + ":" + str(version)


def action_for_batch(batch: DeliveryBatch) -> tuple[str, int] | None:
    if not batch.renderer_version.startswith(PREFIX):
        return None
    identity, separator, raw_version = batch.renderer_version.removeprefix(PREFIX).partition(":")
    if not separator or not raw_version.isascii() or not raw_version.isdecimal():
        raise Conflict("unsent_feedback_renderer_invalid")
    version = int(raw_version)
    if renderer(identity, version) != batch.renderer_version:
        raise Conflict("unsent_feedback_renderer_invalid")
    return identity, version


def evidence(action: Action, binding: Binding) -> HumanMessage:
    source = HumanMessage.model_validate(action.payload.get("source"))
    selected = SessionRef.model_validate(action.payload.get("reference"))
    root = reference(binding)
    if (
        (action.state, action.status_reason) not in NOTICES
        or action.upstream_id is not None
        or action.owner != "bridge"
        or action.admission
        or action.native_result
        or action.operation not in OPERATIONS
        or action.operation != action.payload.get("operation")
        or action.operation_digest != digest(action.payload)
        or binding.state != "active"
        or (action.binding_id, action.binding_revision) != (binding.id, binding.revision)
        or source.is_bot
        or source.deleted
        or source.author_id != action.actor_id
        or action.actor_id not in binding.audience_user_ids
        or (source.realm_id, source.channel_id, source.topic)
        != (binding.realm_id, binding.channel_id, binding.topic)
        or (
            selected.backend_id,
            selected.backend_identity,
            selected.project_id,
            selected.canonical_directory,
        )
        != (
            root.backend_id,
            root.backend_identity,
            root.project_id,
            root.canonical_directory,
        )
        or selected != root
        and action.operation not in {"permission.reply", "form.reply", "form.cancel"}
    ):
        raise Conflict("unsent_feedback_original_action_or_scope_changed")
    return source


class DispatchFeedback:
    def __init__(
        self,
        outbox: Outbox,
        reader: SourceReader,
        *,
        realm_id: str,
        message_limit: int,
        topic_limit: int,
    ) -> None:
        if outbox.fence is None or message_limit < 173 or topic_limit < 1 or not realm_id:
            raise ValueError("unsent_feedback_original_scope_and_fence_required")
        self.outbox, self.reader, self.db = outbox, reader, outbox.db
        self.realm_id, self.message_limit, self.topic_limit = realm_id, message_limit, topic_limit
        self.tr = Translator()
        self._retry: dict[str, float] = {}

    @staticmethod
    def permission(action: Action) -> Permission:
        return Permission.APPROVE if action.operation == "permission.reply" else Permission.OPERATE

    async def next_pending(self) -> str | None:
        now = time.monotonic()
        self._retry = {key: until for key, until in self._retry.items() if until > now}
        async with self.db.sessions() as session:
            identity = await session.scalar(
                select(Action.id)
                .join(Binding, Binding.id == Action.binding_id)
                .where(
                    Binding.realm_id == self.realm_id,
                    Binding.state == "active",
                    Binding.revision == Action.binding_revision,
                    tuple_(Action.state, Action.status_reason).in_(tuple(NOTICES)),
                    Action.id.not_in(tuple(self._retry)),
                    ~select(DeliveryBatch.id)
                    .where(DeliveryBatch.renderer_version.like(PREFIX + Action.id + ":%"))
                    .correlate(Action)
                    .exists(),
                )
                .order_by(Action.created_at, Action.id)
                .limit(1)
            )
            return str(identity) if identity is not None else None

    def defer(self, action_id: str, seconds: float = 5) -> None:
        if len(self._retry) < 256 or action_id in self._retry:
            self._retry[action_id] = time.monotonic() + max(1, min(3600, seconds))

    async def load(self, action_id: str) -> tuple[Action, Binding, HumanMessage]:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
            binding = await session.get(Binding, action.binding_id) if action else None
        if action is None or binding is None or binding.realm_id != self.realm_id:
            raise Conflict("unsent_feedback_original_scope_missing")
        return action, binding, evidence(action, binding)

    async def authorize(
        self, action: Action, binding: Binding, source: HumanMessage
    ) -> Callable[[], bool]:
        # Never probe or submit Native: policy drift is precisely one reason
        # this feedback must remain available. Enrollment is still mandatory.
        deadline = time.monotonic() + 5
        bindings, reader, outbox = self.outbox.bindings, self.reader, self.outbox
        control, audience = bindings.control, bindings.audience
        if await reader.read(source.realm_id, source.message_id) != source:
            raise Conflict("unsent_feedback_source_changed")
        current = await bindings.get(
            binding.id, binding.realm_id, action.actor_id, self.permission(action)
        )
        evidence(action, current)
        if await reader.read(source.realm_id, source.message_id) != source:
            raise Conflict("unsent_feedback_source_changed")
        return lambda: (
            time.monotonic() < deadline
            and self.outbox is outbox
            and self.reader is reader
            and outbox.bindings is bindings
            and bindings.control is control
            and bindings.audience is audience
        )

    def pages(self, action: Action) -> tuple[str, ...]:
        language = action.payload.get("reply_locale", "en")
        if language not in {"en", "zh-TW"}:
            raise Conflict("unsent_feedback_locale_invalid")
        locale = cast(Locale, language)
        text = self.tr.render(NOTICES[(action.state, str(action.status_reason))], locale)
        header = self.tr.page_prefix(locale, 100, 100)
        reserved = len(header) + MARKER_FOOTER_SIZE
        rendered = MobileMarkdown(locale=locale).render(
            text, self.message_limit, reserved_characters=reserved
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("unsent_feedback_output_capacity")
        return tuple(
            self.tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )

    async def lock_action(
        self, session: AsyncSession, action: Action, binding: Binding, *, expected_version: int
    ) -> None:
        # The delivery path already loaded this Action in the same session.
        # populate_existing may refresh that identical ORM object below: copy
        # the immutable expectations before any await, including the renderer's
        # original version, rather than comparing the refreshed object to itself.
        expected = (expected_version, action.operation_digest, action.actor_id)
        assert self.outbox.fence is not None
        await self.outbox.fence.lock(session)
        current_binding = await lock_output_scope(self.outbox.bindings, session, binding)
        current = await session.scalar(
            select(Action)
            .where(Action.id == action.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            current is None
            or (current.version, current.operation_digest, current.actor_id) != expected
        ):
            raise Conflict("unsent_feedback_action_changed_before_commit")
        evidence(current, current_binding)
        roles = await session.scalars(
            select(Grant.role)
            .where(
                Grant.realm_id == binding.realm_id,
                Grant.project_id == binding.project_id,
                Grant.user_id == action.actor_id,
                Grant.active.is_(True),
            )
            .with_for_update()
        )
        if not any(self.permission(action) in ROLES.get(role, set()) for role in roles):
            raise AccessDenied("unsent_feedback_actor_revoked")

    async def publish(self, action_id: str) -> QueuedBatch:
        action, binding, source = await self.load(action_id)
        current = await self.authorize(action, binding, source)
        async with self.db.sessions.begin() as session:
            await self.lock_action(session, action, binding, expected_version=action.version)
            if not current():
                raise Conflict("unsent_feedback_source_witness_expired")
            result = await self.outbox.queue_batch_in_session(
                session,
                "dispatch-unsent:" + action.id,
                binding,
                self.pages(action),
                renderer_version=renderer(action.id, action.version),
                message_limit=self.message_limit,
                topic_limit=self.topic_limit,
                priority=5,
            )
            if not current():
                raise Conflict("unsent_feedback_source_witness_expired")
            return result

    async def delivery_witness(self, saved: Delivery) -> Callable[[], bool] | None:
        if saved.batch_id is None:
            return None
        async with self.db.sessions() as session:
            batch = await session.get(DeliveryBatch, saved.batch_id)
        index = action_for_batch(batch) if batch is not None else None
        if index is None:
            return None
        assert batch is not None
        identity, version = index
        action, binding, source = await self.load(identity)
        if (saved.binding_id, saved.binding_revision, action.version) != (
            binding.id,
            binding.revision,
            version,
        ):
            raise Conflict("unsent_feedback_delivery_binding_changed")
        await self.outbox._validated_batch(binding, batch)
        if batch.plan_hash != batch_digest(
            self.pages(action), renderer(identity, version), self.message_limit, self.topic_limit
        ) or batch.dedupe_key != "reply-batch:" + digest(
            {
                "key": "dispatch-unsent:" + identity,
                "binding": binding.id,
                "revision": binding.revision,
            }
        ):
            raise Conflict("unsent_feedback_delivery_plan_changed")
        return await self.authorize(action, binding, source)

    async def lock_delivery(self, session: AsyncSession, saved: Delivery) -> None:
        batch = await session.get(DeliveryBatch, saved.batch_id) if saved.batch_id else None
        index = action_for_batch(batch) if batch is not None else None
        if index is None:
            return
        identity, version = index
        action = await session.get(Action, identity)
        binding = await session.get(Binding, saved.binding_id)
        if action is None or binding is None or action.version != version:
            raise Conflict("unsent_feedback_delivery_source_missing")
        await self.lock_action(session, action, binding, expected_version=version)
