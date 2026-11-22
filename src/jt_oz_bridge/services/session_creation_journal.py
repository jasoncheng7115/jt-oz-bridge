"""Durable, project-scoped new-Root admission; registration is a separate proof.

No chat-selected path, implicit grant, automatic POST retry or completed binding.
Only trusted runtime composition may supply CreationProject / V2SessionCreation.
"""

import time
from collections.abc import Awaitable, Callable, Mapping
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel
from jt_oz_bridge.domain.execution import HumanMessage, MutationNotSent, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import (
    CreatedRootActivation,
    CreatedRootObservation,
    NewSessionCandidate,
    RootCreationTemplate,
    SessionCreationIntent,
)
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import scope as binding_scope
from jt_oz_bridge.services.binding_scope_history import validate_history
from jt_oz_bridge.services.bindings import BindingService, reference, topic_key
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, WorkerLease


class CreationProject(ControlModel):
    """Root-reviewed runtime input, not a live response or a user selection."""

    template: RootCreationTemplate
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def checksum(self) -> str:
        # The operator RPC epoch is evidence of one past Native process. Durable
        # creations must survive later restarts, so it is not part of identity.
        return digest(self.model_dump(mode="json", exclude={"owner_epoch"}))


def first_prompt(source: HumanMessage, raw: object) -> HumanMessage:
    """The plain message that opened the menu, sent once the new Root is bound."""
    prompt = HumanMessage.model_validate(raw)
    if (
        (prompt.realm_id, prompt.channel_id, prompt.topic, prompt.author_id)
        != (source.realm_id, source.channel_id, source.topic, source.author_id)
        or prompt.is_bot
        or prompt.deleted
        or prompt.revision != 0
        or prompt.message_id >= source.message_id
        or parse_input(prompt.text).kind != "ignore"
    ):
        raise Conflict("creation_first_prompt_scope_changed")
    return prompt


class SessionCreationJournal:
    def __init__(
        self,
        bindings: BindingService,
        reader: SourceReader,
        fence: ConsumerFence,
        projects: Mapping[str, CreationProject],
        epochs: Mapping[str, Callable[[], Awaitable[str]]] | None = None,
    ) -> None:
        if (
            not projects
            or len(projects) > 1000
            or any(key != project.template.scope.project_id for key, project in projects.items())
        ):
            raise ValueError("explicit_creation_project_enrollment_required")
        self.bindings, self.db, self.reader, self.fence = bindings, bindings.db, reader, fence
        self.projects = MappingProxyType(dict(projects))
        self.epochs = MappingProxyType(dict(epochs or {}))
        self.tokens = TokenService(self.db, fence=fence)

    async def source(self, message: HumanMessage) -> None:
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("creation_original_human_source_changed")

    async def authority(self, message: HumanMessage, project: CreationProject) -> AudienceSnapshot:
        await self.source(message)
        audience = await self.bindings.audience.inspect(
            message.realm_id, message.channel_id, message.topic
        )
        if (
            (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != (message.realm_id, message.channel_id, message.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
        ):
            raise AccessDenied("creation_private_canonical_audience_required")
        scope = project.template.scope
        await self.bindings.policy.require(
            message.realm_id, message.author_id, scope.project_id, Permission.OPERATE
        )
        await self.bindings.require_audience(audience, scope.project_id)
        await self.source(message)
        return audience

    async def lock_authority(
        self,
        session: AsyncSession,
        message: HumanMessage,
        project: CreationProject,
        audience: AudienceSnapshot,
        *,
        require_operator: bool = True,
    ) -> None:
        scope = project.template.scope
        backend = await session.scalar(
            select(EnrolledBackend).where(EnrolledBackend.id == scope.backend_id).with_for_update()
        )
        enrolled = await session.scalar(
            select(EnrolledProject).where(EnrolledProject.id == scope.project_id).with_for_update()
        )
        if (
            not backend
            or not backend.enabled
            or not backend.verified
            or backend.identity != scope.backend_identity
            or backend.contract_hash != project.contract_sha256
            or not enrolled
            or not enrolled.enabled
            or enrolled.backend_id != scope.backend_id
            or enrolled.realm_id != message.realm_id
            or enrolled.canonical_directory != scope.canonical_directory
        ):
            raise AccessDenied("creation_project_enrollment_changed")
        grants = list(
            (
                await session.scalars(
                    select(Grant)
                    .where(
                        Grant.realm_id == message.realm_id,
                        Grant.project_id == scope.project_id,
                        Grant.user_id.in_(audience.user_ids),
                        Grant.active.is_(True),
                    )
                    .order_by(Grant.id)
                    .with_for_update()
                )
            ).all()
        )
        if (
            {g.user_id for g in grants if Permission.VIEW in ROLES.get(g.role, set())}
            != set(audience.user_ids)
            or require_operator
            and not any(
                g.user_id == message.author_id and Permission.OPERATE in ROLES.get(g.role, set())
                for g in grants
            )
        ):
            raise AccessDenied("creation_grants_changed_before_commit")

    def context(self, project: CreationProject, audience: AudienceSnapshot) -> dict[str, Any]:
        return {
            "project_id": project.template.scope.project_id,
            "project_sha256": project.checksum(),
            "audience_sha256": digest(audience.model_dump(mode="json")),
        }

    async def offer(self, project_id: str, message: HumanMessage) -> str:
        project = self.projects.get(project_id)
        if project is None:
            raise AccessDenied("creation_project_unavailable")
        audience = await self.authority(message, project)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock_authority(session, message, project, audience)
        return await self.tokens.issue(
            "session-create",
            message.realm_id,
            message.author_id,
            {
                **self.context(project, audience),
                "channel_id": message.channel_id,
                "topic": message.topic,
            },
        )

    def payload(
        self, action: Action, binding: Binding
    ) -> tuple[CreationProject, SessionCreationIntent, HumanMessage]:
        payload = action.payload
        intent = SessionCreationIntent.model_validate(payload.get("intent"))
        source = HumanMessage.model_validate(payload.get("source"))
        audience = AudienceSnapshot.model_validate(payload.get("audience"))
        project = self.projects.get(intent.scope.project_id)
        selected = SessionRef(
            **intent.scope.model_dump(), upstream_session_id=intent.native_session_id
        )
        if (
            action.operation != "session.create"
            or payload.get("operation") != "session.create"
            or action.operation_digest != digest(payload)
            or project is None
            or project.template.scope != intent.scope
            or project.checksum() != payload.get("project_sha256")
            or action.binding_id != binding.id
            or action.binding_revision <= 0
            or action.binding_revision > binding.revision
            or action.state != "completed"
            and action.binding_revision != binding.revision
            or reference(binding) != selected
            or action.actor_id != source.author_id
            or binding.owner_id != source.author_id
            or binding.anchor_message_id != source.message_id
            or binding.topic_key != topic_key(binding.realm_id, binding.channel_id, binding.topic)
            or binding.session_key
            != digest(
                {
                    "realm": binding.realm_id,
                    "backend": intent.scope.backend_id,
                    "identity": intent.scope.backend_identity,
                    "session": intent.native_session_id,
                }
            )
            or source.realm_id != binding.realm_id
            or intent.source_sha256 != digest(source.model_dump(mode="json"))
            or source.is_bot
            or source.deleted
            or source.revision != 0
            or binding.state not in {"creating", "active"}
            or not audience.private
            or audience.untrusted_bot_ids
            or source.author_id not in audience.user_ids
            or (
                audience.realm_id,
                audience.channel_id,
                audience.canonical_topic,
            )
            != (
                source.realm_id,
                source.channel_id,
                source.topic,
            )
        ):
            raise Conflict("creation_durable_intent_or_reserved_topic_changed")
        parsed = parse_input(source.text)
        arguments = parsed.arguments.split(maxsplit=1)
        choice = payload.get("menu_choice")
        if choice is not None:
            # `!N` on a new-topic menu row that offered this project.
            if (
                type(choice) is not int
                or parsed.kind != "command"
                or parsed.command != "choose"
                or parsed.arguments != str(choice)
                or intent.title is not None
            ):
                raise Conflict("creation_original_command_changed")
        elif (
            parsed.kind != "command"
            or parsed.command != "new"
            or not arguments
            or (arguments[1].strip() if len(arguments) == 2 else None) != intent.title
        ):
            raise Conflict("creation_original_command_changed")
        if payload.get("prompt") is not None:
            first_prompt(source, payload["prompt"])
        if binding.state == "active":
            activation = CreatedRootActivation.model_validate(
                action.native_result.get("activation")
            )
            candidate = NewSessionCandidate.model_validate(action.native_result.get("candidate"))
            if (
                action.state != "completed"
                or action.status_reason != "creation_registered_bound"
                or activation.reference != selected
                or activation.action_id != action.id
                or (activation.binding_id, activation.binding_revision)
                != (binding.id, action.binding_revision)
                or activation.intent_sha256 != digest(intent.model_dump(mode="json"))
                or activation.creation_receipt_sha256 != digest(candidate.model_dump(mode="json"))
                or activation.project_sha256 != project.checksum()
                or activation.contract_sha256 != project.contract_sha256
                or candidate.reference != selected
                or candidate.intent_id != intent.intent_id
                or candidate.intent_sha256 != activation.intent_sha256
                or candidate.owner_epoch != intent.owner_epoch
            ):
                raise Conflict("creation_active_binding_receipt_changed")
        elif action.native_result.get("activation") is not None or action.state == "completed":
            raise Conflict("creation_activation_receipt_without_active_binding")
        if action.state != "completed" and binding_scope(binding) != self.origin_scope(
            action, binding
        ):
            raise Conflict("creation_reserved_scope_changed")
        return project, intent, source

    def origin_scope(self, action: Action, binding: Binding) -> BindingScope:
        """Historical scope from the owned creation payload; never a live Binding."""
        source = HumanMessage.model_validate(action.payload.get("source"))
        audience = AudienceSnapshot.model_validate(action.payload.get("audience"))
        return BindingScope(
            binding_id=action.binding_id,
            revision=action.binding_revision,
            realm_id=source.realm_id,
            channel_id=source.channel_id,
            topic=source.topic,
            reference=reference(binding),
            owner_id=source.author_id,
            anchor_message_id=source.message_id,
            audience_revision=audience.revision,
            audience_user_ids=audience.user_ids,
        )

    async def validate_scope(
        self, session: AsyncSession, action: Action, binding: Binding, *, lock: bool = False
    ) -> None:
        self.payload(action, binding)
        await validate_history(
            session, self.origin_scope(action, binding), binding_scope(binding), lock=lock
        )

    def require_attempt(self, action: Action, intent: SessionCreationIntent) -> None:
        """A fixed ID/nonce alone is not a committed one-attempt admission."""
        attempt = action.admission
        if (
            attempt.get("format") != "creation-one-attempt-v1"
            or attempt.get("intent_sha256") != digest(intent.model_dump(mode="json"))
            or not isinstance(attempt.get("attempt_id"), str)
            or len(attempt["attempt_id"]) != 32
            or any(c not in "0123456789abcdef" for c in attempt["attempt_id"])
            or not isinstance(attempt.get("holder"), str)
            or not attempt["holder"]
            or type(attempt.get("fencing")) is not int
            or attempt["fencing"] <= 0
        ):
            raise Conflict("creation_owned_attempt_required")

    def candidate(self, action: Action, binding: Binding) -> NewSessionCandidate:
        """Validate owned one-attempt creation data, including after activation."""
        project, intent, _ = self.payload(action, binding)
        self.require_attempt(action, intent)
        candidate = NewSessionCandidate.model_validate(action.native_result.get("candidate"))
        if (
            action.state not in {"admitted", "completed"}
            or action.native_result.get("format") != "creation-observed-v1"
            or action.native_result.get("project_sha256") != project.checksum()
            or candidate.reference != reference(binding)
            or candidate.intent_id != intent.intent_id
            or candidate.intent_sha256 != digest(intent.model_dump(mode="json"))
            or candidate.owner_epoch != intent.owner_epoch
        ):
            raise Conflict("creation_owned_readback_required")
        if action.native_result.get("recovery") is not None:
            observation = CreatedRootObservation.model_validate(action.native_result["recovery"])
            if (
                observation.reference != candidate.reference
                or observation.intent_sha256 != candidate.intent_sha256
                or observation.creation_receipt_sha256 != digest(candidate.model_dump(mode="json"))
                or observation.owner_epoch != candidate.owner_epoch
                or observation.native_created_at != candidate.native_created_at
                or observation.observed_at < candidate.observed_at
            ):
                raise Conflict("creation_owned_recovery_receipt_changed")
        return candidate

    async def load(self, identity: str) -> tuple[Action, Binding]:
        async with self.db.sessions() as session:
            action = await session.get(Action, identity)
            binding = await session.get(Binding, action.binding_id) if action else None
            if action is None or binding is None:
                raise Conflict("creation_action_unavailable")
            await self.validate_scope(session, action, binding)
        return action, binding

    async def duplicate(self, identity: str, message: HumanMessage) -> str:
        action, binding = await self.load(identity)
        project, _, original = self.payload(action, binding)
        audience = await self.authority(message, project)
        if original != message or (audience.revision, sorted(audience.user_ids)) != (
            binding.audience_revision,
            binding.audience_user_ids,
        ):
            raise Conflict("creation_duplicate_source_or_audience_changed")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock_authority(session, message, project, audience)
        return action.id

    async def reserve(
        self,
        message: HumanMessage,
        locale: Locale = "en",
        *,
        offer: str | None = None,
        choice: int | None = None,
        prompt: HumanMessage | None = None,
    ) -> str:
        """Reserve from `!oz new <token> [title]`, or from `!N` on a menu row carrying an offer."""
        parsed = parse_input(message.text)
        arguments = parsed.arguments.split(maxsplit=1)
        if offer is None:
            if parsed.kind != "command" or parsed.command != "new" or not arguments:
                raise Conflict("creation_explicit_project_selection_required")
        elif (
            choice is None
            or parsed.kind != "command"
            or parsed.command != "choose"
            or parsed.arguments != str(choice)
        ):
            raise Conflict("creation_explicit_project_selection_required")
        if prompt is not None:
            first_prompt(message, prompt.model_dump(mode="json"))
            await self.source(prompt)
        await self.source(message)
        key = "session-create:" + digest({"realm": message.realm_id, "message": message.message_id})
        async with self.db.sessions() as session:
            existing = await session.scalar(select(Action).where(Action.dedupe_key == key))
        if existing is not None:
            return await self.duplicate(existing.id, message)
        try:
            token = await self.tokens.inspect(
                offer if offer is not None else arguments[0],
                "session-create",
                message.realm_id,
                message.author_id,
            )
        except Conflict:
            # Another consumer call may have atomically consumed this same token
            # and inserted its action after our first lookup. Recover only that
            # exact source receipt; an unrelated used token is still rejected.
            async with self.db.sessions() as session:
                raced = await session.scalar(select(Action).where(Action.dedupe_key == key))
            if raced is None:
                raise
            return await self.duplicate(raced.id, message)
        project = self.projects.get(token.context.get("project_id", ""))
        if project is None:
            raise AccessDenied("creation_project_unavailable")
        audience = await self.authority(message, project)
        if token.context != {
            **self.context(project, audience),
            "channel_id": message.channel_id,
            "topic": message.topic,
        }:
            raise Conflict("creation_selection_project_or_audience_changed")
        epoch = self.epochs.get(project.template.scope.project_id)
        intent = SessionCreationIntent(
            intent_id=uuid4().hex,
            scope=project.template.scope,
            native_session_id="ses_jtoz_" + uuid4().hex,
            source_sha256=digest(message.model_dump(mode="json")),
            owner_epoch=await epoch() if epoch is not None else project.owner_epoch,
            title=arguments[1].strip() if offer is None and len(arguments) == 2 else None,
        )
        binding = Binding(
            realm_id=message.realm_id,
            channel_id=message.channel_id,
            topic=message.topic,
            anchor_message_id=message.message_id,
            **intent.scope.model_dump(exclude={"project_id"}),
            project_id=intent.scope.project_id,
            session_id=intent.native_session_id,
            title=intent.title or "",
            owner_id=message.author_id,
            locale=locale,
            state="creating",
            audience_revision=audience.revision,
            audience_user_ids=sorted(audience.user_ids),
            observed_cursor="",
            topic_key=topic_key(message.realm_id, message.channel_id, message.topic),
            session_key=digest(
                {
                    "realm": message.realm_id,
                    "backend": intent.scope.backend_id,
                    "identity": intent.scope.backend_identity,
                    "session": intent.native_session_id,
                }
            ),
        )
        payload: dict[str, Any] = {
            "operation": "session.create",
            "intent": intent.model_dump(mode="json"),
            "source": message.model_dump(mode="json"),
            "project_sha256": project.checksum(),
            "audience": audience.model_dump(mode="json"),
        }
        if choice is not None:
            payload["menu_choice"] = choice
        if prompt is not None:
            payload["prompt"] = prompt.model_dump(mode="json")
        try:
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                await self.lock_authority(session, message, project, audience)
                # Concurrent duplicate delivery recovers the original ID, never a second reservation.
                previous = await session.scalar(select(Action).where(Action.dedupe_key == key))
                if previous is not None:
                    if previous.payload.get("source") != payload["source"]:
                        raise Conflict("creation_concurrent_source_changed")
                    return previous.id
                await self.tokens.consume_in_session(session, token)
                session.add(binding)
                await session.flush()
                action = Action(
                    dedupe_key=key,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=message.author_id,
                    operation="session.create",
                    payload=payload,
                    operation_digest=digest(payload),
                    state="queued",
                )
                session.add(action)
                await session.flush()
                session.add(
                    AuditEvent(
                        actor=f"{message.realm_id}:{message.author_id}",
                        event="session_create_reserved",
                        object_id=action.id,
                    )
                )
                return action.id
        except IntegrityError:
            raise Conflict("creation_topic_already_reserved_or_bound") from None

    async def authorized(self, action: Action, binding: Binding) -> AudienceSnapshot:
        project, _, source = self.payload(action, binding)
        if action.state == "completed":
            # Reconstructing an already owned Root is read-only. The original
            # command is historical evidence, not a new command in the moved
            # topic. Every current reader still needs a current project grant.
            return await self.bindings.audience_for_output(binding)
        audience = await self.authority(source, project)
        if (audience.revision, sorted(audience.user_ids)) != (
            binding.audience_revision,
            binding.audience_user_ids,
        ):
            raise Conflict("creation_reserved_audience_changed")
        return audience

    async def claim(self, identity: str) -> tuple[Action, Binding, float] | None:
        action, binding = await self.load(identity)
        if action.state != "queued":
            return None
        project, intent, source = self.payload(action, binding)
        audience = await self.authorized(action, binding)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock_authority(session, source, project, audience)
            current = await session.scalar(
                select(Action).where(Action.id == identity).with_for_update()
            )
            reserved = await session.scalar(
                select(Binding).where(Binding.id == binding.id).with_for_update()
            )
            if current is None or reserved is None:
                raise Conflict("creation_reservation_removed")
            self.payload(current, reserved)
            if current.state != "queued" or current.version != action.version:
                return None
            if reserved.dispatch_paused:
                return None
            lease = await session.get(WorkerLease, "consumer")
            assert lease is not None
            deadline = min(lease.expires_at, time.time() + 5)
            current.state, current.version = "dispatching", current.version + 1
            current.admission = {
                "format": "creation-one-attempt-v1",
                "attempt_id": uuid4().hex,
                "intent_sha256": digest(intent.model_dump(mode="json")),
                "holder": self.fence.holder,
                "fencing": self.fence.fencing,
            }
            await session.flush()
            return current, reserved, deadline

    async def settle(self, action: Action, state: str, reason: str) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            if current and current.version == action.version and current.state == action.state:
                current.state, current.status_reason = state, reason
                current.version += 1

    async def record(
        self,
        action: Action,
        client: V2SessionCreation,
        candidate: NewSessionCandidate,
        *,
        observation: CreatedRootObservation | None = None,
    ) -> str:
        current, binding = await self.load(action.id)
        project, intent, source = self.payload(current, binding)
        if current.version != action.version or current.state not in {"dispatching", "ambiguous"}:
            return current.state
        self.require_attempt(current, intent)
        valid = (
            await client.existing_current(intent, candidate, observation)
            if observation is not None
            else await client.current(intent, candidate)
        )
        if not valid:
            raise Conflict("creation_readback_no_longer_current")
        audience = await self.authorized(current, binding)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock_authority(session, source, project, audience)
            saved = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            reserved = await session.scalar(
                select(Binding).where(Binding.id == binding.id).with_for_update()
            )
            if saved is None or reserved is None:
                raise Conflict("creation_reservation_removed")
            self.payload(saved, reserved)
            if saved.version != action.version or saved.state != action.state:
                return saved.state
            if not 0 <= time.time() - candidate.observed_at < 5:
                raise Conflict("creation_readback_expired_before_commit")
            saved.native_result = {
                **saved.native_result,
                "format": "creation-observed-v1",
                "candidate": candidate.model_dump(mode="json"),
                "project_sha256": project.checksum(),
            }
            if observation is not None:
                saved.native_result = {
                    **saved.native_result,
                    "recovery": observation.model_dump(mode="json"),
                }
            saved.state, saved.version, saved.status_reason = (
                "admitted",
                saved.version + 1,
                "registration_pending",
            )
            # No active binding or completion is asserted by a creation readback.
            return saved.state

    async def advance(
        self, identity: str, client: V2SessionCreation, *, recover_existing: bool = False
    ) -> str:
        action, binding = await self.load(identity)
        project, intent, _ = self.payload(action, binding)
        if (
            client.templates.get(intent.scope.project_id) != project.template
            or client.transport.profile.sha256 != project.contract_sha256
        ):
            raise Conflict("creation_adapter_template_mismatch")
        if action.state not in {"queued", "ambiguous"}:
            return action.state
        if action.state == "ambiguous":
            self.require_attempt(action, intent)
            await self.authorized(action, binding)
            if recover_existing:
                candidate, observation = await client.recover(intent)
                return await self.record(action, client, candidate, observation=observation)
            candidate = await client.observe(intent)  # GET only, even after a lost ACK/restart.
            return await self.record(action, client, candidate)
        claim = await self.claim(identity)
        if claim is None:
            return (await self.load(identity))[0].state
        action, binding, deadline = claim

        def before_send() -> None:
            if not time.time() < deadline:
                raise Conflict("creation_committed_claim_expired_before_send")

        try:
            candidate = await client.create(intent, before_send=before_send)
            return await self.record(action, client, candidate)
        except MutationNotSent:
            await self.settle(action, "rejected", "creation_proven_not_sent")
        except Exception:
            await self.settle(action, "ambiguous", "creation_send_or_registration_uncertain")
        return (await self.load(identity))[0].state
