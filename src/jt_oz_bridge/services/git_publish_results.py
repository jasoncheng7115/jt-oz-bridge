"""After a confirmed Git prompt's turn ends: read Git again, record facts, post one notice.

The turn's end comes from the qualified resource reader (an idle terminal, or the
aborted tail a declined permission leaves). The facts come only from the `vcs.*`
GET readings before and after; the agent's own reply is never a source. Both
the Action and the result are in ownDB, so a restart neither resends the prompt
nor loses the check: an admitted Action is simply read again.
"""

import time
from collections.abc import Mapping
from types import MappingProxyType

from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.git_publish import (
    GIT_PUBLISH,
    GitPublishReader,
    GitPublishRequest,
    GitPublishResult,
    GitPublishState,
    verify,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.outbox import QueuedBatch
from jt_oz_bridge.services.resource_execution_results import ResourceTurnReader
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent
from jt_oz_bridge.storage.publication_models import ModelSettingPublication

RENDERER_VERSION = "git-publish-notice-v1"
NOTICE_STATES = ("completed", "ambiguous")


def request_of(action: Action, binding: Binding) -> GitPublishRequest:
    request = GitPublishRequest.model_validate(action.payload)
    source = request.source
    if (
        action.operation != GIT_PUBLISH
        or action.operation_digest != digest(action.payload)
        or action.dedupe_key != "git-publish:" + request.confirmation_token_sha256
        or request.reference != reference(binding)
        or (source.realm_id, source.channel_id, source.topic, source.author_id)
        != (binding.realm_id, binding.channel_id, binding.topic, action.actor_id)
    ):
        raise Conflict("git_publish_action_identity_changed")
    return request


class GitPublishResults:
    """Turns an admitted Git prompt into a sealed, GET-verified result. Never sends."""

    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, GitPublishReader],
        turns: Mapping[str, ResourceTurnReader],
        fence: ConsumerFence,
    ) -> None:
        self.bindings, self.db, self.fence = bindings, bindings.db, fence
        self.readers = MappingProxyType(dict(readers))
        self.turns = MappingProxyType(dict(turns))

    async def pending(self, realm: str) -> list[str]:
        async with self.db.sessions() as session:
            return [
                str(identity)
                for identity in (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.realm_id == realm,
                            Binding.state == "active",
                            Binding.revision == Action.binding_revision,
                            Action.operation == GIT_PUBLISH,
                            Action.state.in_(["admitted", "running"]),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(100)
                    )
                ).all()
            ]

    async def collect(self, action_id: str, realm: str) -> bool:
        """True once the result is recorded; False (or a typed error) means read again later."""
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
            binding = await session.get(Binding, action.binding_id) if action else None
        if (
            action is None
            or binding is None
            or action.state not in {"admitted", "running"}
            or binding.realm_id != realm
            or binding.revision != action.binding_revision
            or binding.state != "active"
        ):
            raise Conflict("git_publish_reconcilable_action_required")
        request = request_of(action, binding)
        receipt = native_receipt(action)
        ref = reference(binding)
        reader, turns = self.readers.get(ref), self.turns.get(binding.backend_id)
        if (
            receipt is None
            or receipt.reference != ref
            or receipt.admission.status != "admitted"
            or receipt.admission.upstream_id is None
            or receipt.admission.details.get("operation") != GIT_PUBLISH
            or reader is None
            or turns is None
        ):
            raise Conflict("git_publish_positive_admission_and_readers_required")
        # Raises until this exact prompt's turn has ended and the Root is idle.
        turn = await turns.capture(
            TurnCorrelation(
                reference=ref,
                action_id=action.id,
                operation_digest=action.operation_digest,
                upstream_id=receipt.admission.upstream_id,
                text=request.text,
            )
        )
        if turn.turn.user_id != receipt.admission.upstream_id or not turns.current(turn):
            raise Conflict("git_publish_turn_evidence_changed")
        plan = request.plan
        after = await reader.read(
            ref,
            remote=plan.remote,
            compare="fixed",
            base=plan.tracking if plan.kind == "push" else request.before.comparison,
        )
        after = GitPublishState.model_validate(after.model_dump(mode="json"))
        if after.reference != ref or not turns.current(turn):
            raise Conflict("git_publish_after_reading_changed")
        result = GitPublishResult(
            action_id=action.id,
            operation_digest=action.operation_digest,
            turn_outcome=turn.turn.outcome,
            turn_user_id=turn.turn.user_id,
            after=after,
            verification=verify(plan, request.before, after),
            verified_at=time.time(),
        ).model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            changed = await session.execute(
                update(Action)
                .where(
                    Action.id == action.id,
                    Action.version == action.version,
                    Action.state == action.state,
                )
                .values(state="completed", native_result=result, version=Action.version + 1)
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("git_publish_action_changed_during_check")
            session.add(
                AuditEvent(
                    actor="bridge",
                    event="git_publish_" + result["verification"]["outcome"],
                    object_id=action.id,
                )
            )
        return True


class GitPublishResultPublisher:
    """One notice per confirmed Git Action, saying only what the readings show."""

    def __init__(self, replies: RoutedOutbox) -> None:
        self.replies, self.db = replies, replies.outbox.db
        self.tr = Translator()
        for locale in ("en", "zh-TW"):
            header = self.tr.page_prefix(locale, 100, 100)
            if replies.message_limit - FOOTER_SIZE - len(header) < 128:
                raise ValueError("git_publish_notice_render_contract_too_small")

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            found = await session.scalar(
                select(Action.id)
                .join(Binding, Binding.id == Action.binding_id)
                .outerjoin(
                    ModelSettingPublication,
                    ModelSettingPublication.action_id == Action.id,
                )
                .where(
                    Action.operation == GIT_PUBLISH,
                    Action.state.in_(NOTICE_STATES),
                    Binding.state == "active",
                    Binding.revision == Action.binding_revision,
                    Binding.realm_id == self.replies.realm_id,
                    ModelSettingPublication.action_id.is_(None),
                )
                .order_by(Action.created_at, Action.id)
                .limit(1)
            )
            return str(found) if found is not None else None

    def render(self, action: Action, request: GitPublishRequest) -> tuple[str, str]:
        """(notice text, checksum) from the sealed Action and nothing newer."""
        locale: Locale = request.reply_locale
        tr = self.tr.render
        plan = request.plan
        if action.state == "ambiguous":
            return (
                tr("git_publish.unknown_result", locale, kind=plan.kind),
                digest({"action": action.id, "state": "ambiguous"}),
            )
        result = GitPublishResult.model_validate(action.native_result)
        if (
            result.action_id != action.id
            or result.operation_digest != action.operation_digest
            or result.verification != verify(plan, request.before, result.after)
        ):
            raise Conflict("git_publish_result_changed")
        verification = result.verification
        if verification.outcome == "verified":
            head = tr(
                "git_publish.result_verified." + plan.kind, locale, branch=visible(plan.branch)
            )
        elif verification.outcome == "not_done":
            head = tr(
                "git_publish.result_not_done." + plan.kind,
                locale,
                turn=tr("git_publish.turn." + result.turn_outcome, locale),
            )
        else:
            head = tr("git_publish.result_not_verified." + plan.kind, locale)
        lines = [head]
        for check in verification.checks:
            values = {key: visible(value) for key, value in check.values.items()}
            mark = "✓" if check.passed else "✗"
            lines.append(
                f"- {mark} "
                + tr(
                    "git_publish.check." + check.key + (".pass" if check.passed else ".fail"),
                    locale,
                    **values,
                )
            )
        lines.append(
            tr(
                "git_publish.unverifiable",
                locale,
                items=", ".join(
                    tr("git_publish.gap." + key, locale) for key in verification.unverifiable
                ),
            )
        )
        return "\n".join(lines), digest(result.model_dump(mode="json"))

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None or action.operation != GIT_PUBLISH or action.state not in NOTICE_STATES:
            raise Conflict("git_publish_terminal_action_required")
        binding = await self.replies.outbox.target(action.binding_id, action.binding_revision)
        if binding.realm_id != self.replies.realm_id:
            raise Conflict("git_publish_publication_realm_changed")
        request = request_of(action, binding)
        text, checksum = self.render(action, request)
        async with self.db.sessions() as session:
            cached = await session.get(ModelSettingPublication, action.id)
        if cached is not None:
            if (cached.binding_id, cached.binding_revision, cached.source_hash) != (
                binding.id,
                binding.revision,
                checksum,
            ):
                raise Conflict("git_publish_publication_source_changed")
            return await self.replies.outbox.batch_by_id(
                cached.batch_id, binding.id, binding.revision
            )
        locale: Locale = request.reply_locale
        header = self.tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("git_publish_notice_size_unavailable")
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
                or (current.state, current.operation) != (action.state, action.operation)
                or current.native_result != action.native_result
            ):
                raise Conflict("git_publish_state_changed_before_publication")
            planned = await session.get(ModelSettingPublication, action.id)
            if planned is not None:
                if (planned.binding_id, planned.binding_revision, planned.source_hash) != (
                    binding.id,
                    binding.revision,
                    checksum,
                ):
                    raise Conflict("git_publish_publication_source_changed")
                batch_id = planned.batch_id
            else:
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    "git-publish-result:" + action.id,
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
