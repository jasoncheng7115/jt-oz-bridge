"""Truthful Agent-setting notices; a setting is never reported as a finished turn.

Reuses the generic sealed setting publication table. Mirrored transcripts stay in
charge of Native history; this Bridge-owned notice reports only the attempt outcome.
"""

from collections.abc import Callable

from sqlalchemy import func, select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.agent_selection import AgentPolicyEndpoint
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.services.agent_switch_coordinator import CONFIGURATION_HELD
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.outbox import QueuedBatch
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.publication_models import ModelSettingPublication
from jt_oz_bridge.storage.session_configuration_heads import AgentSwitchIntent

RENDERER_VERSION = "agent-setting-notice-v1"
TERMINAL = ("completed", "rejected", "ambiguous")


class AgentSettingPublisher:
    def __init__(
        self,
        replies: RoutedOutbox,
        *,
        ready: Callable[[SessionRef, AgentSwitchIntent], bool],
    ) -> None:
        self.replies, self.db, self.ready = replies, replies.outbox.db, ready
        self.tr = Translator()
        for locale in ("en", "zh-TW"):
            header = self.tr.page_prefix(locale, 100, 100)
            if replies.message_limit - FOOTER_SIZE - len(header) < 128:
                raise ValueError("agent_setting_confirmation_render_contract_too_small")

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(Action)
                    .join(Binding, Binding.id == Action.binding_id)
                    .outerjoin(
                        ModelSettingPublication,
                        ModelSettingPublication.action_id == Action.id,
                    )
                    .where(
                        Action.operation == "agent.switch",
                        Action.state.in_(TERMINAL),
                        Binding.state == "active",
                        Binding.revision == Action.binding_revision,
                        Binding.realm_id == self.replies.realm_id,
                        ModelSettingPublication.action_id.is_(None),
                    )
                    .order_by(Action.created_at, Action.id)
                    .limit(16)
                )
            ).all()
        for action in rows:
            if action.state != "completed" or self.ready(
                SessionRef.model_validate(action.payload["reference"]),
                AgentSwitchIntent.model_validate(action.payload),
            ):
                return str(action.id)
        return None

    def text(self, action: Action, held: int) -> tuple[str, Locale]:
        intent = AgentSwitchIntent.model_validate(action.payload)
        locale: Locale = intent.reply_locale or "en"
        before = AgentPolicyEndpoint.model_validate(intent.before_endpoint).definition.label
        after = AgentPolicyEndpoint.model_validate(intent.after_endpoint).definition.label
        if action.state == "completed":
            text = self.tr.render("agents.applied", locale, after=after)
            if held:
                text += "\n\n" + self.tr.render("agents.queue_held", locale, count=held)
            return text, locale
        if action.state == "rejected":
            return self.tr.render("agents.not_sent", locale, current=before), locale
        return self.tr.render("agents.uncertain", locale), locale

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None or action.operation != "agent.switch" or action.state not in TERMINAL:
            raise Conflict("agent_setting_terminal_action_required")
        binding = await self.replies.outbox.target(action.binding_id, action.binding_revision)
        if (
            binding.realm_id != self.replies.realm_id
            or SessionRef.model_validate(action.payload["reference"]) != reference(binding)
            or digest(action.payload) != action.operation_digest
        ):
            raise Conflict("agent_setting_publication_scope_changed")
        checksum = digest(
            {
                "state": action.state,
                "version": action.version,
                "native_result": action.native_result,
                "admission": action.admission,
                "reason": action.status_reason,
            }
        )
        async with self.db.sessions() as session:
            cached = await session.get(ModelSettingPublication, action.id)
            held = await session.scalar(
                select(func.count())
                .select_from(Action)
                .where(
                    Action.binding_id == binding.id,
                    Action.state == "held",
                    Action.status_reason == CONFIGURATION_HELD,
                )
            )
        if cached is not None:
            if (cached.binding_id, cached.binding_revision) != (binding.id, binding.revision):
                raise Conflict("agent_setting_publication_source_changed")
            return await self.replies.outbox.batch_by_id(
                cached.batch_id, binding.id, binding.revision
            )
        text, locale = self.text(action, int(held or 0))
        header = self.tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("agent_setting_confirmation_size_unavailable")
        pages = tuple(
            self.tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )
        fence = self.replies.outbox.fence
        assert fence is not None
        async with self.db.sessions.begin() as session:
            await fence.lock(session)
            await lock_output_scope(self.replies.outbox.bindings, session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            if (
                current is None
                or current.state != action.state
                or current.version != action.version
            ):
                raise Conflict("agent_setting_action_changed_before_publication")
            planned = await session.get(ModelSettingPublication, action.id)
            if planned is not None:
                batch_id = planned.batch_id
            else:
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    "agent-setting:" + action.id,
                    binding,
                    pages,
                    renderer_version=RENDERER_VERSION,
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=10,
                )
                session.add(
                    ModelSettingPublication(
                        action_id=action.id,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                        source_hash=checksum,
                        batch_id=batch.id,
                    )
                )
                batch_id = batch.id
        return await self.replies.outbox.batch_by_id(batch_id, binding.id, binding.revision)
