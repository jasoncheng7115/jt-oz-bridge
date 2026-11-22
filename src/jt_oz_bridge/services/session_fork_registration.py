"""A confirmed fork's own topic: reserve it, wait for its first post, then bind.

Native created the fork once, for one confirmed lifecycle Action. Every step
here is GET-only on Native: the fork is never created, retried or replaced, and
the original Root and its topic are never rebound or changed.

A bridge post cannot open a new Zulip topic, because every audience check
resolves the topic from a message already on the server. So the reserved topic
is opened by a person's first message there, which also becomes the fork's
first prompt. Steps, each one durable:

1. reserve: a completed fork Action -> a `creating` Binding for a new topic in
   the same channel, a registration Action and a link notice in the original
   topic, in one commit;
2. open: the first message in that topic from an operator of the same audience;
3. bind: GET-only registration of the fork as a created Root with its source
   Root's own policy, then the active Binding, the first prompt and a notice in
   one commit. A restart repeats only GET-only work; completed forks are
   restored from their sealed receipt.
"""

import asyncio
import logging
import re
import time
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import quote
from uuid import uuid4

from sqlalchemy import exists, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.session_fork import V2ForkedRootObserver, V2ForkPolicy
from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.session_creation import NewSessionCandidate
from jt_oz_bridge.domain.session_fork import (
    FORK_REGISTRATION,
    ForkedRootActivation,
    ForkedRootIntent,
)
from jt_oz_bridge.domain.session_lifecycle import SessionLifecycleOutcome, SessionLifecycleRequest
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.presentation.markdown import literal as inert
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.backend_registry import BackendRegistry
from jt_oz_bridge.services.binding_scope_history import scope as binding_scope
from jt_oz_bridge.services.binding_scope_history import validate_history
from jt_oz_bridge.services.bindings import reference, topic_key
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.session_creation_journal import CreationProject, SessionCreationJournal
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent

LOG = logging.getLogger(__name__)
CODE = re.compile(r"[a-z][a-z0-9_]{0,99}")
KEY = "session-fork-register:"
LINK_RENDERER = "session-fork-link-v1"
RENDERER_VERSION = "session-fork-connected-v1"
WAITING, OPENED, BOUND = (
    "fork_topic_waiting_for_first_post",
    "fork_topic_opened",
    "fork_registered_bound",
)
# A fork confirmed longer ago than this never gets a topic by surprise later.
RESERVE_WINDOW = 86400
RETRY_SECONDS = 30
# Zulip's own topic-hash encoding (`internal_url.encodeHashComponent`).
HASH = {"%": ".", "(": ".28", ")": ".29", ".": ".2E"}


def topic_hash(topic: str) -> str:
    return re.sub(r"[%().]", lambda m: HASH[m.group()], quote(topic, safe="!*'()"))


class SessionForkRegistration:
    def __init__(
        self,
        journal: SessionCreationJournal,
        factories: Mapping[str, V2CreatedRootFactory],
        replies: RoutedOutbox,
        *,
        realm_url: str | None = None,
    ) -> None:
        if (
            not factories
            or len(factories) > 1000
            or not set(factories) <= set(journal.projects)
            or replies.outbox.bindings is not journal.bindings
            or replies.outbox.fence != journal.fence
        ):
            raise ValueError("fork_registration_original_composition_required")
        control = journal.bindings.control
        for project_id, factory in factories.items():
            project = journal.projects[project_id]
            anchor = factory.policies.template.source.reference
            registry = (
                control.selected(anchor).client if isinstance(control, BackendRegistry) else control
            )
            if (
                not isinstance(factory.creator, V2ForkedRootObserver)
                or not isinstance(factory.policies, V2ForkPolicy)
                or registry is not factory.registry
                or factory.creator.templates.get(project_id) != project.template
                or factory.creator.transport.profile.sha256 != project.contract_sha256
                or factory.policies.template.checksum() != project.policy_template_sha256
            ):
                raise ValueError("fork_registration_project_factory_mismatch")
        self.journal, self.db, self.replies = journal, journal.db, replies
        self.factories = MappingProxyType(dict(factories))
        self.realm_url = realm_url.rstrip("/") if realm_url else None
        self.tr = replies.tr
        self._control = control
        self._lock, self._worker = asyncio.Lock(), asyncio.Lock()
        # Per-process backoff only; durable state never depends on it.
        self._skipped: set[str] = set()
        self._retry_at: dict[str, float] = {}
        self._unrestored: set[str] = set()

    # Names and notices

    def topic_name(self, base: str, fork_id: str, locale: Locale) -> str:
        code = digest({"fork": fork_id})[:4]
        suffix = f"（分支 {code}）" if locale == "zh-TW" else f" (fork {code})"
        room = self.replies.topic_limit - len(suffix)
        if room < 2:
            raise Conflict("fork_topic_name_does_not_fit")
        base = " ".join(base.split())
        if len(base) > room:
            base = base[: room - 1].rstrip() + "…"
        return base + suffix

    def link(self, channel_id: int, topic: str) -> str:
        if self.realm_url is None:
            return "**" + inert(topic) + "**"
        address = f"{self.realm_url}/#narrow/channel/{channel_id}/topic/{topic_hash(topic)}"
        return f"**[{inert(topic)}]({address})**"

    def pages(self, key: str, locale: Locale, **params: Any) -> tuple[str, ...]:
        text = self.tr.render(key, locale, **params)
        header = self.tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("fork_topic_notice_unavailable")
        return tuple(
            self.tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )

    # The confirmed fork this registration comes from

    def fork_outcome(
        self, action: Action, binding: Binding
    ) -> tuple[SessionLifecycleRequest, SessionLifecycleOutcome]:
        """The sealed positive Native receipt of one confirmed fork, and nothing newer."""
        request = SessionLifecycleRequest.model_validate(action.payload)
        source = request.source
        receipt = native_receipt(action)
        if (
            action.operation != "session.fork"
            or request.operation != "session.fork"
            or action.state != "completed"
            or action.operation_digest != digest(action.payload)
            or action.binding_id != binding.id
            or action.binding_revision != binding.revision
            or binding.state != "active"
            or binding.realm_id != self.replies.realm_id
            or request.reference != reference(binding)
            or (source.realm_id, source.channel_id, source.topic, source.author_id)
            != (binding.realm_id, binding.channel_id, binding.topic, action.actor_id)
            or receipt is None
            or receipt.reference != reference(binding)
            or receipt.admission.status != "completed"
            or receipt.admission.owner != "opencode"
            or receipt.admission.upstream_id is not None
            or receipt.contract_sha256 != self._control.contract_for(reference(binding))
        ):
            raise Conflict("fork_registration_positive_native_fork_required")
        outcome = SessionLifecycleOutcome.model_validate(receipt.admission.details)
        if (
            outcome.operation != "session.fork"
            or outcome.change != request.change
            or outcome.session_id != binding.session_id
            or outcome.new_session_id is None
        ):
            raise Conflict("fork_registration_native_outcome_changed")
        return request, outcome

    # The owned registration record

    @staticmethod
    def stamp(action: Action, binding: Binding) -> str:
        return digest(
            {
                "action": action.id,
                "version": action.version,
                "state": action.state,
                "operation_digest": action.operation_digest,
                "native_result": action.native_result,
                "binding": binding.id,
                "revision": binding.revision,
                "binding_state": binding.state,
                "paused": binding.dispatch_paused,
            }
        )

    def payload(
        self, action: Action, binding: Binding
    ) -> tuple[CreationProject, ForkedRootIntent, HumanMessage, AudienceSnapshot]:
        payload = action.payload
        intent = ForkedRootIntent.model_validate(payload.get("intent"))
        source = HumanMessage.model_validate(payload.get("source"))
        audience = AudienceSnapshot.model_validate(payload.get("audience"))
        project = self.journal.projects.get(intent.scope.project_id)
        selected = reference(binding)
        if (
            action.operation != FORK_REGISTRATION
            or payload.get("operation") != FORK_REGISTRATION
            or action.operation_digest != digest(payload)
            or project is None
            or intent.scope.project_id not in self.factories
            or project.template.scope != intent.scope
            or project.checksum() != payload.get("project_sha256")
            or payload.get("fork_action_id") != intent.fork_action_id
            or action.dedupe_key != KEY + intent.fork_action_id
            or action.binding_id != binding.id
            or action.binding_revision != 1
            or ProjectScope(**selected.model_dump(exclude={"upstream_session_id"})) != intent.scope
            or selected.upstream_session_id != intent.native_session_id
            or action.actor_id != source.author_id
            or binding.owner_id != source.author_id
            or binding.anchor_message_id != source.message_id
            or binding.realm_id != source.realm_id
            or binding.channel_id != source.channel_id
            or intent.source_sha256 != digest(source.model_dump(mode="json"))
            or source.is_bot
            or source.deleted
            or source.revision != 0
            or not audience.private
            or audience.untrusted_bot_ids
            or source.author_id not in audience.user_ids
            or (audience.realm_id, audience.channel_id) != (source.realm_id, source.channel_id)
            or binding.state not in {"creating", "active"}
        ):
            raise Conflict("fork_registration_owned_record_changed")
        if binding.state == "creating":
            if (
                action.state != "admitted"
                or "activation" in action.native_result
                or binding.revision != 1
                or binding.topic != payload.get("topic")
                or binding.topic_key
                != topic_key(binding.realm_id, binding.channel_id, binding.topic)
                or binding.session_key != self.session_key(binding.realm_id, intent)
                or (binding.audience_revision, binding.audience_user_ids)
                != (audience.revision, sorted(audience.user_ids))
            ):
                raise Conflict("fork_registration_reserved_topic_changed")
        else:
            activation = self.activation(action)
            if (
                action.state != "completed"
                or action.status_reason != BOUND
                or activation.reference != selected
                or activation.action_id != action.id
                or activation.fork_action_id != intent.fork_action_id
                or activation.intent_sha256 != digest(intent.model_dump(mode="json"))
                or activation.project_sha256 != project.checksum()
                or activation.contract_sha256 != project.contract_sha256
                or activation.fork_of.upstream_session_id != intent.fork_of
            ):
                raise Conflict("fork_registration_active_receipt_changed")
        return project, intent, source, audience

    @staticmethod
    def activation(action: Action) -> ForkedRootActivation:
        return ForkedRootActivation.model_validate(action.native_result.get("activation"))

    @staticmethod
    def session_key(realm_id: str, intent: ForkedRootIntent) -> str:
        return digest(
            {
                "realm": realm_id,
                "backend": intent.scope.backend_id,
                "identity": intent.scope.backend_identity,
                "session": intent.native_session_id,
            }
        )

    def opening(self, action: Action, binding: Binding) -> HumanMessage:
        """The first post that opened the reserved topic; its author operates the fork."""
        raw = action.native_result.get("opening")
        if raw is None:
            raise Conflict("fork_topic_not_opened_yet")
        opening = HumanMessage.model_validate(raw)
        audience = AudienceSnapshot.model_validate(action.native_result.get("opening_audience"))
        if (
            (opening.realm_id, opening.channel_id, opening.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or opening.message_id <= (binding.anchor_message_id or 0)
            or opening.is_bot
            or opening.deleted
            or opening.revision != 0
            or (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != (opening.realm_id, opening.channel_id, opening.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or opening.author_id not in audience.user_ids
            or (
                binding.state == "creating"
                and sorted(audience.user_ids) != binding.audience_user_ids
            )
        ):
            raise Conflict("fork_topic_opening_changed")
        return opening

    async def load(self, identity: str) -> tuple[Action, Binding]:
        async with self.db.sessions() as session:
            action = await session.get(Action, identity)
            binding = await session.get(Binding, action.binding_id) if action else None
            if action is None or binding is None:
                raise Conflict("fork_registration_action_unavailable")
            self.payload(action, binding)
            if binding.state == "active":
                await validate_history(
                    session, self.activation(action).scope, binding_scope(binding)
                )
        return action, binding

    # 1. Reserve the topic for one completed fork

    async def unreserved(self) -> tuple[str, ...]:
        registered = aliased(Action)
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Action.operation == "session.fork",
                            Action.state == "completed",
                            Action.created_at >= time.time() - RESERVE_WINDOW,
                            Binding.state == "active",
                            Binding.revision == Action.binding_revision,
                            Binding.realm_id == self.replies.realm_id,
                            Binding.project_id.in_(self.factories),
                            ~exists().where(
                                registered.dedupe_key == literal(KEY).concat(Action.id)
                            ),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(20)
                    )
                ).all()
            )
        return tuple(identity for identity in ids if identity not in self._skipped)[:10]

    async def reserve(self, fork_action_id: str) -> str:
        key = KEY + fork_action_id
        async with self.db.sessions() as session:
            existing = await session.scalar(select(Action.id).where(Action.dedupe_key == key))
            fork = await session.get(Action, fork_action_id)
            origin = await session.get(Binding, fork.binding_id) if fork else None
        if existing is not None:
            return str(existing)
        if fork is None or origin is None:
            raise Conflict("fork_registration_fork_action_unavailable")
        request, outcome = self.fork_outcome(fork, origin)
        assert outcome.new_session_id is not None
        project = self.journal.projects.get(origin.project_id)
        factory = self.factories.get(origin.project_id)
        if (
            project is None
            or factory is None
            or project.template.scope
            != ProjectScope(**reference(origin).model_dump(exclude={"upstream_session_id"}))
        ):
            raise AccessDenied("fork_registration_project_not_enrolled")
        audience = await self.journal.authority(request.source, project)
        if (audience.revision, sorted(audience.user_ids)) != (
            origin.audience_revision,
            origin.audience_user_ids,
        ):
            raise Conflict("fork_registration_source_audience_changed")
        intent = ForkedRootIntent(
            intent_id=uuid4().hex,
            scope=project.template.scope,
            native_session_id=outcome.new_session_id,
            source_sha256=digest(request.source.model_dump(mode="json")),
            owner_epoch=await factory.creator.live_epoch(origin.project_id),
            fork_of=origin.session_id,
            fork_action_id=fork.id,
            before=request.change.message_id,
        )
        locale = request.reply_locale
        topic = self.topic_name(origin.topic, intent.native_session_id, locale)
        binding = Binding(
            realm_id=origin.realm_id,
            channel_id=origin.channel_id,
            topic=topic,
            anchor_message_id=request.source.message_id,
            **intent.scope.model_dump(exclude={"project_id"}),
            project_id=intent.scope.project_id,
            session_id=intent.native_session_id,
            title="",
            owner_id=request.source.author_id,
            locale=origin.locale,
            state="creating",
            audience_revision=audience.revision,
            audience_user_ids=sorted(audience.user_ids),
            observed_cursor="",
            topic_key=topic_key(origin.realm_id, origin.channel_id, topic),
            session_key=self.session_key(origin.realm_id, intent),
        )
        payload: dict[str, Any] = {
            "operation": FORK_REGISTRATION,
            "intent": intent.model_dump(mode="json"),
            "source": request.source.model_dump(mode="json"),
            "fork_action_id": fork.id,
            "topic": topic,
            "source_binding_id": origin.id,
            "source_binding_revision": origin.revision,
            "project_sha256": project.checksum(),
            "audience": audience.model_dump(mode="json"),
        }
        pages = self.pages(
            "lifecycle.fork_topic",
            locale,
            topic=self.link(origin.channel_id, topic),
            session_id=visible(intent.native_session_id),
        )
        try:
            async with self.db.sessions.begin() as session:
                await self.journal.fence.lock(session)
                await self.journal.lock_authority(session, request.source, project, audience)
                current = await lock_output_scope(self.journal.bindings, session, origin)
                saved = await session.get(Action, fork.id, with_for_update=True)
                if saved is None or (saved.version, saved.state, saved.admission) != (
                    fork.version,
                    "completed",
                    fork.admission,
                ):
                    raise Conflict("fork_registration_fork_action_changed")
                previous = await session.scalar(select(Action).where(Action.dedupe_key == key))
                if previous is not None:
                    return str(previous.id)
                session.add(binding)
                await session.flush()
                action = Action(
                    dedupe_key=key,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=request.source.author_id,
                    operation=FORK_REGISTRATION,
                    payload=payload,
                    operation_digest=digest(payload),
                    state="admitted",
                    status_reason=WAITING,
                )
                session.add(action)
                await session.flush()
                # The link goes to the original topic in the same commit as the reservation.
                await self.replies.outbox.queue_batch_in_session(
                    session,
                    "session-fork-topic:" + action.id,
                    current,
                    pages,
                    renderer_version=LINK_RENDERER,
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=10,
                )
                session.add(
                    AuditEvent(
                        actor=f"{request.source.realm_id}:{request.source.author_id}",
                        event="session_fork_topic_reserved",
                        object_id=action.id,
                    )
                )
                return str(action.id)
        except IntegrityError:
            raise Conflict("fork_registration_topic_or_session_already_bound") from None

    # 2. The first post opens the reserved topic

    async def reserved(self, message: HumanMessage) -> tuple[Action, Binding] | None:
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.realm_id == message.realm_id,
                            Binding.topic_key
                            == topic_key(message.realm_id, message.channel_id, message.topic),
                            Binding.state == "creating",
                            Action.operation == FORK_REGISTRATION,
                        )
                        .limit(2)
                    )
                ).all()
            )
        if len(ids) > 1:
            raise Conflict("fork_topic_has_multiple_owned_actions")
        return await self.load(ids[0]) if ids else None

    async def opened(self, message: HumanMessage, locale: Locale) -> tuple[str, str] | None:
        """(status text, project) when this topic was reserved for a fork; never a prompt."""
        selected = await self.reserved(message)
        if selected is None:
            return None
        action, binding = selected
        project, _, source, _ = self.payload(action, binding)
        if message.message_id <= source.message_id:
            raise Conflict("fork_topic_opening_predates_the_fork")
        # The topic exists now: its audience can be read like any other topic's.
        audience = await self.journal.authority(message, project)
        if (
            sorted(audience.user_ids) != binding.audience_user_ids
            or audience.channel_id != binding.channel_id
        ):
            raise AccessDenied("fork_topic_audience_changed")
        if action.native_result.get("opening") is None:
            expected = self.stamp(action, binding)
            async with self.db.sessions.begin() as session:
                await self.journal.fence.lock(session)
                await self.journal.lock_authority(session, message, project, audience)
                saved = await session.get(Action, action.id, with_for_update=True)
                reserved = await session.get(Binding, binding.id, with_for_update=True)
                if saved is None or reserved is None or self.stamp(saved, reserved) != expected:
                    raise Conflict("fork_topic_reservation_changed")
                self.payload(saved, reserved)
                saved.native_result = {
                    **saved.native_result,
                    "opening": message.model_dump(mode="json"),
                    "opening_audience": audience.model_dump(mode="json"),
                }
                saved.status_reason, saved.version = OPENED, saved.version + 1
                session.add(
                    AuditEvent(
                        actor=f"{message.realm_id}:{message.author_id}",
                        event="session_fork_topic_opened",
                        object_id=saved.id,
                    )
                )
            self._retry_at.pop(action.id, None)
        return self.tr.render("lifecycle.fork_connecting", locale), binding.project_id

    # 3. Register and bind, or restore after a restart

    async def authority(
        self, identity: str, expected: str, audience: AudienceSnapshot | None = None
    ) -> AudienceSnapshot:
        """Zulip and owned SQL authority; a given audience skips only the Zulip reads."""
        action, binding = await self.load(identity)
        if (
            self.stamp(action, binding) != expected
            or binding.realm_id != self.replies.realm_id
            or self.journal.bindings.control is not self._control
        ):
            raise Conflict("fork_registration_owned_state_changed")
        project, _, source, _ = self.payload(action, binding)
        completed = action.state == "completed"
        actor = source if completed else self.opening(action, binding)
        if audience is None:
            if completed:
                audience = await self.journal.bindings.audience_for_output(binding)
            else:
                audience = await self.journal.authority(actor, project)
                if sorted(audience.user_ids) != binding.audience_user_ids:
                    raise AccessDenied("fork_topic_audience_changed")
        async with self.db.sessions.begin() as session:
            await self.journal.fence.lock(session)
            await self.journal.lock_authority(
                session, actor, project, audience, require_operator=not completed
            )
            saved = await session.get(Action, identity, with_for_update=True)
            reserved = await session.get(Binding, binding.id, with_for_update=True)
            if saved is None or reserved is None or self.stamp(saved, reserved) != expected:
                raise Conflict("fork_registration_claim_changed")
            self.payload(saved, reserved)
        return audience

    async def reconcile(self, identity: str) -> Binding:
        async with self._lock:
            action, binding = await self.load(identity)
            project, intent, _, _ = self.payload(action, binding)
            opening = self.opening(action, binding) if binding.state == "creating" else None
            factory = self.factories[intent.scope.project_id]
            if (
                project.policy_template_sha256 != factory.policies.template.checksum()
                or factory.creator.templates.get(intent.scope.project_id) != project.template
                or factory.creator.transport.profile.sha256 != project.contract_sha256
            ):
                raise Conflict("fork_registration_project_template_changed")
            expected = self.stamp(action, binding)
            checked: AudienceSnapshot | None = None

            async def authorized() -> bool:
                nonlocal checked
                checked = await self.authority(identity, expected)
                return True

            async def still_authorized() -> bool:
                # As for chat-created Roots: the 5 s readback windows cannot hold
                # a full Zulip read per Native read, so only the owned grants,
                # enrollment and reservation are re-read in between.
                assert checked is not None
                await self.authority(identity, expected, checked)
                return True

            await authorized()
            if action.state == "completed":
                receipt = NewSessionCandidate.model_validate(action.native_result.get("candidate"))
                activation = self.activation(action)
                if (
                    digest(receipt.model_dump(mode="json")) != activation.receipt_sha256
                    or receipt.native_created_at != activation.native_created_at
                ):
                    raise Conflict("fork_registration_sealed_receipt_changed")
            else:
                # GET only: the fork exists already, so this never creates anything.
                receipt, _ = await factory.creator.recover(intent)
            entry = await factory.register(
                intent, receipt, authorize=still_authorized, restore=True
            )
            execution = entry.execution
            if not isinstance(execution, V2ExecutionClient) or not isinstance(
                execution.scope_guard, V2ProjectPolicyGuard
            ):
                raise Conflict("fork_registration_original_execution_required")
            enrollment = execution.scope_guard.enrollments[entry.reference]
            policies = cast(V2ForkPolicy, factory.policies)
            source_ref, source_guard = policies.source(intent)
            if not enrollment.operations <= source_guard.enrollments[source_ref].operations:
                raise Conflict("fork_registration_policy_broader_than_source")
            snapshot, proof = await execution.qualified_snapshot(entry.reference)
            if not snapshot.reconciled:
                raise Conflict("fork_registration_snapshot_not_reconciled")
            witness = await factory.observe_policy(intent, receipt, entry, proof)
            if action.state == "completed":
                if self.activation(action).policy_fingerprint_sha256 != (
                    enrollment.fingerprint_sha256
                ):
                    raise Conflict("fork_registration_registered_policy_changed")
                await authorized()
                factory.registered(intent, receipt, entry)
                execution.current(entry.reference, proof)
                factory.policy_current(intent, receipt, entry, proof, witness)
                return binding
            assert opening is not None
            audience = await self.authority(identity, expected)
            prompt: HumanMessage | None = (
                opening if parse_input(opening.text).kind == "ignore" else None
            )
            if prompt is not None:
                try:
                    await self.journal.source(prompt)
                except (ZulipReadUnavailable, DeliveryRateLimited):
                    raise  # Transient: binding retries with the prompt intact.
                except (Conflict, ValueError):
                    prompt = None  # Edited or deleted since: never send stale text.
            async with self.db.sessions.begin() as session:
                await self.journal.fence.lock(session)
                saved = await session.get(Action, identity, with_for_update=True)
                reserved = await session.get(Binding, binding.id, with_for_update=True)
                if saved is None or reserved is None or self.stamp(saved, reserved) != expected:
                    raise Conflict("fork_registration_reservation_changed_before_commit")
                current_project, _, source, _ = self.payload(saved, reserved)
                await self.journal.lock_authority(session, opening, current_project, audience)
                if current_project != project or reserved.dispatch_paused:
                    raise Conflict("fork_registration_project_or_queue_changed")
                origin = await session.get(Binding, saved.payload["source_binding_id"])
                reserved.state, reserved.title, reserved.observed_cursor = (
                    "active",
                    snapshot.title,
                    snapshot.cursor,
                )
                # The reservation used the original topic's audience; the opened
                # topic has the same people and now its own server revision.
                reserved.audience_revision = audience.revision
                reserved.audience_user_ids = sorted(audience.user_ids)
                await session.flush()
                if prompt is not None:
                    # Same commit as the binding: the first message is queued exactly once.
                    await QueueService(self.journal.bindings)._receive_in_session(
                        session, reserved, prompt
                    )
                locale = cast(Locale, reserved.locale if reserved.locale == "zh-TW" else "en")
                pages = self.pages(
                    "lifecycle.fork_connected",
                    locale,
                    session_id=visible(intent.native_session_id),
                    topic=self.link(reserved.channel_id, saved.payload["topic"])
                    if origin is None
                    else self.link(origin.channel_id, origin.topic),
                )
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    "session-fork-connected:" + identity,
                    reserved,
                    pages,
                    renderer_version=RENDERER_VERSION,
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=10,
                )
                activation = ForkedRootActivation(
                    reference=entry.reference,
                    fork_of=source_ref,
                    action_id=saved.id,
                    fork_action_id=intent.fork_action_id,
                    scope=binding_scope(reserved),
                    intent_sha256=digest(intent.model_dump(mode="json")),
                    receipt_sha256=digest(receipt.model_dump(mode="json")),
                    project_sha256=project.checksum(),
                    contract_sha256=project.contract_sha256,
                    policy_fingerprint_sha256=enrollment.fingerprint_sha256,
                    notice_batch_id=batch.id,
                    first_prompt_queued=prompt is not None,
                    activated_at=time.time(),
                    native_created_at=receipt.native_created_at,
                )
                saved.native_result = {
                    **saved.native_result,
                    "candidate": receipt.model_dump(mode="json"),
                    "activation": activation.model_dump(mode="json"),
                }
                saved.state, saved.status_reason, saved.version = (
                    "completed",
                    BOUND,
                    saved.version + 1,
                )
                session.add(
                    AuditEvent(
                        actor=f"{source.realm_id}:{opening.author_id}",
                        event="session_fork_topic_bound",
                        object_id=saved.id,
                    )
                )
                # SQL awaits may receive new Native events. Roll back the whole
                # binding, prompt and notice unless the final fence survives.
                factory.registered(intent, receipt, entry)
                execution.current(entry.reference, proof)
                factory.policy_current(intent, receipt, entry, proof, witness)
            return reserved

    async def opened_ids(self) -> tuple[str, ...]:
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Action.operation == FORK_REGISTRATION,
                            Action.state == "admitted",
                            Action.status_reason == OPENED,
                            Binding.state == "creating",
                            Binding.realm_id == self.replies.realm_id,
                            Binding.project_id.in_(self.factories),
                            Binding.dispatch_paused.is_(False),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(10)
                    )
                ).all()
            )
        now = time.monotonic()
        return tuple(i for i in ids if self._retry_at.get(i, 0) <= now)

    def _held(self, kind: str, identity: str, error: Exception) -> None:
        # Only a fixed code: other ValueErrors may quote saved content.
        code = str(error) if CODE.fullmatch(str(error)) else "-"
        LOG.warning(
            "fork_registration_held step=%s action=%s kind=%s code=%s",
            kind,
            identity,
            type(error).__name__,
            code,
        )

    async def once(self) -> None:
        """Reserve topics for new forks, then bind the topics people opened."""
        async with self._worker:
            for fork_id in await self.unreserved():
                try:
                    await self.reserve(fork_id)
                except (ZulipReadUnavailable, DeliveryRateLimited):
                    raise
                except (AccessDenied, Conflict, ValueError) as error:
                    # Fail closed: this fork keeps no topic until a restart retries.
                    self._skipped.add(fork_id)
                    self._held("reserve", fork_id, error)
            now = time.monotonic()
            restore = tuple(i for i in sorted(self._unrestored) if self._retry_at.get(i, 0) <= now)
            for identity in (*await self.opened_ids(), *restore):
                try:
                    await self.reconcile(identity)
                    self._retry_at.pop(identity, None)
                    self._unrestored.discard(identity)
                except (ZulipReadUnavailable, DeliveryRateLimited):
                    raise
                except (AccessDenied, Conflict, ValueError) as error:
                    # Every retry is GET-only on Native; the topic stays unbound meanwhile.
                    self._retry_at[identity] = time.monotonic() + RETRY_SECONDS
                    self._held("bind", identity, error)

    async def restore_active(self) -> tuple[str, ...]:
        """Startup: GET-only re-registration of bound forks from their sealed receipts."""
        async with self.db.sessions() as session:
            ids = tuple(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Action.operation == FORK_REGISTRATION,
                            Action.state == "completed",
                            Binding.state == "active",
                            Binding.realm_id == self.replies.realm_id,
                            Binding.project_id.in_(self.factories),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(1001)
                    )
                ).all()
            )
        if len(ids) > 1000:
            raise Conflict("fork_registration_restore_capacity_exceeded")
        restored = []
        for identity in ids:
            try:
                await self.reconcile(identity)
                restored.append(identity)
            except (ZulipReadUnavailable, DeliveryRateLimited):
                raise
            except (AccessDenied, Conflict, ValueError) as error:
                # One fork that does not read back never stops the bridge. Until a
                # later GET-only retry registers it, its topic cannot reach OpenCode.
                self._unrestored.add(identity)
                self._retry_at[identity] = time.monotonic() + RETRY_SECONDS
                self._held("restore", identity, error)
        return tuple(restored)
