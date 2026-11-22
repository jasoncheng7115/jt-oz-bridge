"""Short Source-bound Agent menus, one-use previews and durable confirmations.

Every step rereads the original Human Source, grant, audience and Native state.
Confirmation records one Action; only the dedicated coordinator may send Native.
"""

import time
import uuid
from typing import Literal

from pydantic import Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.agent_settings import agent_transition_preview
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.agent_selection import (
    AgentCandidate,
    AgentObservation,
    AgentPolicyEndpoint,
)
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_publish import CONFIRM_TOKEN as PUBLISH_CONFIRM
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_lifecycle import LIFECYCLE_TOKEN_KINDS
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.agent_configuration import (
    AgentConfigurationRegistry,
    effective_configuration,
    same_configuration,
)
from jt_oz_bridge.services.agent_switch_coordinator import hold_unsent_root_work
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant
from jt_oz_bridge.storage.session_configuration_heads import (
    AgentSwitchIntent,
    ConfigurationSnapshot,
    ConfigurationToken,
)

MENU_KIND = "native-agent-menu"
CONFIRM_KIND = "native-agent-confirm"
MENU_TTL = 300
CONFIRM_TTL = 120
COMMANDS = frozenset({"agent", "choose", "confirm"})


class AgentMenuItem(ControlModel):
    agent_id: str = Field(min_length=1, max_length=128)
    label: str = Field(max_length=512)
    mode: Literal["primary", "subagent", "all"]
    transition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentMenu(ControlModel):
    reference: SessionRef
    source: HumanMessage
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: tuple[AgentMenuItem, ...] = Field(min_length=1, max_length=10)


class AgentConfirmation(ControlModel):
    mode: Literal["switch", "adopt"]
    reference: SessionRef
    token: ConfigurationToken
    before: AgentPolicyEndpoint | None
    after: AgentPolicyEndpoint
    transition_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    preview_source: HumanMessage


def _unavailable_for_state(observation: AgentObservation) -> str | None:
    if observation.state != ExecutionState.IDLE:
        return "agents.busy"
    if not observation.settings_tail_ready:
        return "agents.first_message"
    return None


class AgentCommands:
    def __init__(
        self,
        bindings: BindingService,
        registry: AgentConfigurationRegistry,
        tokens: TokenService,
        reader: SourceReader,
    ) -> None:
        if tokens.db is not bindings.db or tokens.fence is None:
            raise ValueError("agent_commands_require_shared_database_and_consumer_fence")
        self.bindings, self.db, self.registry = bindings, bindings.db, registry
        self.tokens, self.reader, self.fence = tokens, reader, tokens.fence
        self.tr = Translator()

    def available(self, binding: Binding) -> bool:
        client = self.registry.client(reference(binding))
        return client is not None and client.available(reference(binding))

    async def current(
        self, binding: Binding, message: HumanMessage, permission: Permission = Permission.VIEW
    ) -> Binding:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in COMMANDS
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("agent_command_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, permission
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("agent_command_binding_changed")
        return current

    async def _latest(
        self, kind: str, binding: Binding, message: HumanMessage
    ) -> ControlToken | None:
        async with self.db.sessions() as session:
            saved: ControlToken | None = await session.scalar(
                select(ControlToken)
                .where(
                    ControlToken.kind == kind,
                    ControlToken.realm_id == message.realm_id,
                    ControlToken.user_id == message.author_id,
                    ControlToken.binding_id == binding.id,
                    ControlToken.binding_revision == binding.revision,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                )
                .order_by(ControlToken.expires_at.desc())
                .limit(1)
            )
        if saved is not None and saved.context_hash != digest(saved.context):
            raise Conflict("agent_command_token_context_changed")
        return saved

    async def owns_choice(self, binding: Binding, message: HumanMessage) -> bool:
        return await self._latest(MENU_KIND, binding, message) is not None

    async def owns_confirm(self, binding: Binding, message: HumanMessage) -> bool:
        return await self._latest(CONFIRM_KIND, binding, message) is not None

    async def _retire(self, session: AsyncSession, binding: Binding, message: HumanMessage) -> None:
        # One live Agent control per actor/topic: an older menu cannot resurface.
        await session.execute(
            update(ControlToken)
            .where(
                ControlToken.kind.in_(
                    [MENU_KIND, CONFIRM_KIND, *LIFECYCLE_TOKEN_KINDS, PUBLISH_CONFIRM]
                ),
                ControlToken.realm_id == message.realm_id,
                ControlToken.user_id == message.author_id,
                ControlToken.binding_id == binding.id,
                ControlToken.used.is_(False),
            )
            .values(used=True)
        )

    async def _lock_operator(
        self, session: AsyncSession, binding: Binding, message: HumanMessage
    ) -> Binding:
        await self.fence.lock(session)
        current = await lock_output_scope(self.bindings, session, binding)
        grant = await session.scalar(
            select(Grant.id)
            .where(
                Grant.realm_id == message.realm_id,
                Grant.user_id == message.author_id,
                Grant.project_id == binding.project_id,
                Grant.active.is_(True),
                Grant.role.in_(
                    [r for r, permissions in ROLES.items() if Permission.OPERATE in permissions]
                ),
            )
            .with_for_update()
        )
        if grant is None:
            raise AccessDenied("agent_switch_operate_grant_changed")
        return current

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        if command == "agent":
            if arguments.strip():
                raise ValueError("agent_command_takes_no_arguments")
            return await self.menu(binding, message, locale)
        if command == "choose":
            return await self.choose(binding, message, locale, arguments)
        if command == "confirm":
            return await self.confirm(binding, message, locale)
        raise Conflict("agent_command_route_changed")

    async def _review(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        saved: ConfigurationSnapshot,
        observation: AgentObservation,
    ) -> str:
        """Same-Root unresolved state: read-only, with one explicit local release."""
        phase = saved.token.phase
        if phase in {"dispatching", "activation_prepared"}:
            return self.tr.render("agents.in_progress", locale)
        same = same_configuration(saved.effective, observation.endpoint)
        current = observation.endpoint.definition.label
        key = "agents.unknown_result" if phase == "quarantined" else "agents.external_change"
        lines = [self.tr.render(key, locale, current=current)]
        transition = None
        if not same:
            transition = next(
                (
                    target.transition_sha256
                    for target in self._approved(saved)
                    if target.endpoint == observation.endpoint
                ),
                None,
            )
            if transition is None:
                lines.append(self.tr.render("agents.not_approved", locale))
                await self.current(binding, message)
                return "\n\n".join(lines)
        try:
            await self.bindings.policy.require(
                message.realm_id, message.author_id, binding.project_id, Permission.OPERATE
            )
        except AccessDenied:
            lines.append(self.tr.render("agents.operator_required", locale))
            await self.current(binding, message)
            return "\n\n".join(lines)
        lines.append(self.tr.render("agents.adopt_prompt", locale, current=current))
        await self.current(binding, message)
        async with self.db.sessions.begin() as session:
            await self._lock_operator(session, binding, message)
            await self._retire(session, binding, message)
        await self.tokens.issue(
            CONFIRM_KIND,
            message.realm_id,
            message.author_id,
            AgentConfirmation(
                mode="adopt",
                reference=reference(binding),
                token=saved.token,
                before=None,
                after=observation.endpoint,
                transition_sha256=transition,
                preview_source=message,
            ).model_dump(mode="json"),
            ttl=CONFIRM_TTL,
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return "\n\n".join(lines)

    def _approved(self, saved: ConfigurationSnapshot) -> tuple[AgentCandidate, ...]:
        """Root-enrolled targets leaving the exact currently approved configuration."""
        client = self.registry.client(saved.origin.root)
        rows = client.transitions if client is not None else ()
        return tuple(
            AgentCandidate(endpoint=item.after, transition_sha256=item.enrollment_sha256)
            for item in rows
            if same_configuration(saved.effective, item.before)
        )

    async def menu(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        binding = await self.current(binding, message)
        ref = reference(binding)
        client = self.registry.client(ref)
        if client is None or not client.available(ref):
            return self.tr.render("agents.unavailable", locale)
        await self.registry.restore(ref)
        observation = await client.observe(ref)
        saved = await self.registry.snapshot(ref)
        if saved is not None and saved.token.phase != "stable":
            return await self._review(binding, message, locale, saved, observation)
        if (
            saved is None
            and observation.endpoint.policy_sha256 != (self.registry.original_policies[ref])
        ):
            return self.tr.render("agents.changed_before_enrollment", locale)
        items = tuple(
            AgentMenuItem(
                agent_id=candidate.endpoint.definition.agent_id,
                label=candidate.endpoint.definition.label,
                mode=candidate.endpoint.definition.mode,
                transition_sha256=candidate.transition_sha256,
            )
            for candidate in observation.candidates
            if candidate.endpoint.definition.root_selectable
        )[:10]
        lines = [
            self.tr.render("agents.current", locale, current=observation.endpoint.definition.label)
        ]
        lines += [
            f"{index}. **{item.label}** · "
            + self.tr.render("metadata.agent_mode." + item.mode, locale)
            for index, item in enumerate(items, 1)
        ]
        offered = {item.agent_id for item in items} | {observation.agent_id}
        others = [
            row.label
            for row in observation.catalog.items
            if row.root_selectable and row.agent_id not in offered
        ]
        if others:
            lines.append(self.tr.render("agents.not_offered", locale, names="、".join(others[:10])))
        await self.current(binding, message)
        can_choose = bool(items)
        try:
            await self.bindings.policy.require(
                message.realm_id, message.author_id, binding.project_id, Permission.OPERATE
            )
        except AccessDenied:
            can_choose = False
        if not items:
            lines.append(self.tr.render("agents.none_enabled", locale))
        elif not can_choose:
            lines.append(self.tr.render("agents.operator_required", locale))
        else:
            async with self.db.sessions.begin() as session:
                await self._lock_operator(session, binding, message)
                await self._retire(session, binding, message)
            await self.tokens.issue(
                MENU_KIND,
                message.realm_id,
                message.author_id,
                AgentMenu(
                    reference=ref,
                    source=message,
                    catalog_sha256=observation.catalog.catalog_sha256,
                    before_policy_sha256=observation.endpoint.policy_sha256,
                    items=items,
                ).model_dump(mode="json"),
                ttl=MENU_TTL,
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            choices = "`!1`" if len(items) == 1 else f"`!1`–`!{len(items)}`"
            lines.append(self.tr.render("agents.choose", locale, choices=choices))
        state_note = _unavailable_for_state(observation)
        if state_note is not None:
            lines.append(self.tr.render(state_note, locale))
        return "\n\n".join(lines)

    async def choose(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        binding = await self.current(binding, message, Permission.OPERATE)
        saved = await self._latest(MENU_KIND, binding, message)
        if saved is None:
            raise Conflict("agent_menu_unavailable")
        menu = AgentMenu.model_validate(saved.context)
        ref = reference(binding)
        client = self.registry.client(ref)
        number = arguments.strip()
        if (
            client is None
            or menu.reference != ref
            or not number.isascii()
            or not number.isdecimal()
            or not 1 <= int(number) <= len(menu.items)
            or await self.reader.read(menu.source.realm_id, menu.source.message_id) != menu.source
        ):
            raise Conflict("agent_menu_choice_invalid")
        item = menu.items[int(number) - 1]
        observation = await client.observe(ref)
        await self.current(binding, message, Permission.OPERATE)
        candidate = observation.candidate(item.agent_id)
        if (
            observation.catalog.catalog_sha256 != menu.catalog_sha256
            or observation.endpoint.policy_sha256 != menu.before_policy_sha256
            or candidate is None
            or candidate.transition_sha256 != item.transition_sha256
        ):
            raise Conflict("agent_menu_observation_changed")
        state_note = _unavailable_for_state(observation)
        if state_note is not None:
            return self.tr.render(state_note, locale)

        async def locked(session: AsyncSession) -> None:
            await lock_output_scope(self.bindings, session, binding)

        head = await self.registry.ensure_head(
            observation, lock_authority=locked, current=lambda: True
        )
        if head.token.phase == "stable" and not same_configuration(
            head.effective, observation.endpoint
        ):
            await self.registry.restore(ref)
            refreshed = await self.registry.snapshot(ref)
            if refreshed is None:
                raise Conflict("agent_configuration_head_missing")
            head = refreshed
        if head.token.phase != "stable":
            return await self._review(binding, message, locale, head, observation)
        transition = next(
            (row for row in client.transitions if row.enrollment_sha256 == item.transition_sha256),
            None,
        )
        if transition is None:
            raise Conflict("agent_transition_enrollment_changed")
        preview = agent_transition_preview(transition)
        await self.current(binding, message, Permission.OPERATE)
        async with self.db.sessions.begin() as session:
            await self._lock_operator(session, binding, message)
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, binding, message)
        await self.tokens.issue(
            CONFIRM_KIND,
            message.realm_id,
            message.author_id,
            AgentConfirmation(
                mode="switch",
                reference=ref,
                token=head.token,
                before=observation.endpoint,
                after=candidate.endpoint,
                transition_sha256=candidate.transition_sha256,
                preview_source=message,
            ).model_dump(mode="json"),
            ttl=CONFIRM_TTL,
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        lines = [
            self.tr.render(
                "agents.preview", locale, before=preview.before_label, after=preview.after_label
            )
        ]
        if preview.permissions_differ:
            lines.append(self.tr.render("agents.permissions_differ", locale))
        lines.append(self.tr.render("agents.effect", locale))
        lines.append(self.tr.render("agents.confirm", locale))
        return "\n\n".join(lines)

    async def confirm(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        binding = await self.current(binding, message, Permission.OPERATE)
        saved = await self._latest(CONFIRM_KIND, binding, message)
        if saved is None:
            raise Conflict("agent_confirmation_unavailable")
        confirmation = AgentConfirmation.model_validate(saved.context)
        ref = reference(binding)
        client = self.registry.client(ref)
        source = confirmation.preview_source
        if (
            client is None
            or confirmation.reference != ref
            or source.message_id == message.message_id
            or source.author_id != message.author_id
            or (source.channel_id, source.topic) != (message.channel_id, message.topic)
            or await self.reader.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("agent_confirmation_source_changed")
        observation = await client.observe(ref)
        await self.current(binding, message, Permission.OPERATE)
        head = await self.registry.snapshot(ref)
        if head is None or head.token != confirmation.token:
            raise Conflict("agent_confirmation_configuration_changed")
        if confirmation.mode == "adopt":
            return await self._adopt(binding, message, locale, saved, confirmation, observation)
        candidate = observation.candidate(confirmation.after.definition.agent_id)
        if (
            confirmation.before is None
            or head.token.phase != "stable"
            or observation.endpoint != confirmation.before
            or candidate is None
            or candidate.endpoint != confirmation.after
            or candidate.transition_sha256 != confirmation.transition_sha256
        ):
            raise Conflict("agent_confirmation_observation_changed")
        state_note = _unavailable_for_state(observation)
        if state_note is not None:
            return self.tr.render(state_note, locale)
        identity = str(uuid.uuid4())
        intent = self._intent(
            identity,
            "agent.switch",
            binding,
            message,
            locale,
            head,
            observation,
            confirmation.before,
            confirmation.after,
            saved,
            confirmation,
            expires_at=time.time() + CONFIRM_TTL,
        )
        payload = intent.model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(session, binding, message)
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, binding, message)
            session.add(
                Action(
                    id=identity,
                    dedupe_key="agent-choice:" + saved.token_hash,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=message.author_id,
                    payload=payload,
                    operation="agent.switch",
                    operation_digest=digest(payload),
                    state="held" if current.dispatch_paused else "queued",
                    version=1,
                    owner="bridge",
                )
            )
            await session.flush()
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="agent_setting_queued",
                    object_id=identity,
                )
            )
        return self.tr.render("agents.sending", locale)

    def _intent(
        self,
        identity: str,
        operation: Literal["agent.switch", "agent.adopt"],
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        head: ConfigurationSnapshot,
        observation: AgentObservation,
        before: AgentPolicyEndpoint | None,
        after: AgentPolicyEndpoint,
        saved: ControlToken,
        confirmation: AgentConfirmation,
        *,
        expires_at: float | None,
        resolves: str | None = None,
    ) -> AgentSwitchIntent:
        client = self.registry.clients[reference(binding)]
        guarded = (before,) if before is not None else ()
        return AgentSwitchIntent(
            operation=operation,
            action_id=identity,
            realm_id=message.realm_id,
            binding_id=binding.id,
            binding_revision=binding.revision,
            actor_id=message.author_id,
            queued_action_version=1,
            reference=head.origin.root,
            root_key=head.token.root_key,
            origin_sha256=digest(head.origin.model_dump(mode="json")),
            expected_revision=head.token.revision,
            before_configuration_sha256=head.token.effective_sha256,
            after=effective_configuration(observation, after, client.attestation, guarded=guarded),
            source_sha256=digest(message.model_dump(mode="json")),
            preview_sha256=digest(confirmation.preview_source.model_dump(mode="json")),
            confirmation_sha256=saved.token_hash,
            transition_certificate_sha256=confirmation.transition_sha256 or "0" * 64,
            affected_scope_sha256=digest(
                {
                    "binding": binding.id,
                    "revision": binding.revision,
                    "project": binding.project_id,
                    "audience": binding.audience_revision,
                }
            ),
            owner_epoch_sha256=observation.owner_evidence_sha256,
            source=message.model_dump(mode="json"),
            preview_source=confirmation.preview_source.model_dump(mode="json"),
            reply_locale=locale,
            before_endpoint=before.model_dump(mode="json") if before is not None else None,
            after_endpoint=after.model_dump(mode="json"),
            confirmation_expires_at=expires_at,
            resolves_action_id=resolves,
        )

    async def _adopt(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        saved: ControlToken,
        confirmation: AgentConfirmation,
        observation: AgentObservation,
    ) -> str:
        """Local review only: no Native request, and old evidence is left unchanged."""
        ref = reference(binding)
        head = await self.registry.snapshot(ref)
        if (
            head is None
            or head.token != confirmation.token
            or head.token.phase not in {"external_unqualified", "quarantined"}
            or observation.endpoint != confirmation.after
        ):
            raise Conflict("agent_adoption_observation_changed")
        same = same_configuration(head.effective, observation.endpoint)
        approved = next(
            (target for target in self._approved(head) if target.endpoint == observation.endpoint),
            None,
        )
        if not same and (
            approved is None or approved.transition_sha256 != confirmation.transition_sha256
        ):
            raise Conflict("agent_adoption_exact_root_approval_required")
        identity = str(uuid.uuid4())
        intent = self._intent(
            identity,
            "agent.adopt",
            binding,
            message,
            locale,
            head,
            observation,
            None,
            observation.endpoint,
            saved,
            confirmation,
            expires_at=None,
            resolves=head.token.active_action_id,
        )

        async def lock(session: AsyncSession) -> None:
            await self._lock_operator(session, binding, message)
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, binding, message)

        async def activated(session: AsyncSession) -> None:
            await hold_unsent_root_work(session, binding)

        async with self.registry.gate(ref):
            snapshot, _action = await self.registry.heads.adopt_observed(
                head.token,
                intent,
                digest(observation.model_dump(mode="json")),
                dedupe_key="agent-adopt:" + saved.token_hash,
                lock_authority=lock,
                current=lambda: True,
                observed_at=observation.observed_at,
                on_activated=activated,
            )
            self.registry.publish_snapshot(snapshot, reason=None)
        return self.tr.render(
            "agents.adopted", locale, current=observation.endpoint.definition.label
        )

    async def barrier_note(self, binding: Binding, locale: Locale) -> str | None:
        """Visible reason for input that cannot start; it grants and changes nothing."""
        status = self.registry.status(reference(binding))
        keys = {
            "transition": "agents.input_waiting",
            "review_required": "agents.input_review",
            "external_change": "agents.input_review",
            "activation_unverified": "agents.input_waiting",
        }
        key = keys.get(status)
        return self.tr.render(key, locale) if key is not None else None
