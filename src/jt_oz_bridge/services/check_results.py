"""Original shell result reconciliation and fenced same-topic publication."""

from collections.abc import Awaitable, Callable, Mapping
from types import MappingProxyType
from typing import Literal, cast

from pydantic import Field
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.checks import CheckExecutionAttestation, KnownCheck
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.checks import (
    CheckObservation,
    CheckReader,
    CheckSelection,
    check_message_id,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, sanitize_controls
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt, native_receipt
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.outbox import QueuedBatch
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent
from jt_oz_bridge.storage.publication_models import ModelSettingPublication

PENDING = "project_check_result_pending"
PUBLISHED = "project_check_result_published"
STATES = {
    "passed": "completed",
    "failed": "failed",
    "timeout": "failed",
    "killed": "cancelled",
    "unknown": "ambiguous",
}


class CheckExecutionResult(ControlModel):
    format: Literal["native-check-result-v1"] = "native-check-result-v1"
    action_id: str
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_id: str
    binding_revision: int = Field(ge=1)
    realm_id: str
    channel_id: int = Field(gt=0)
    topic: str
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observation: CheckObservation


def check_result(action: Action) -> CheckExecutionResult | None:
    if not action.native_result:
        return None
    result = CheckExecutionResult.model_validate(action.native_result)
    receipt = native_receipt(action)
    selection = CheckSelection.model_validate(action.payload.get("selection"))
    if (
        action.operation != "check.run"
        or action.payload.get("operation") != "check.run"
        or digest(action.payload) != action.operation_digest
        or result.action_id != action.id
        or result.operation_digest != action.operation_digest
        or result.binding_id != action.binding_id
        or result.binding_revision != action.binding_revision
        or result.reference != selection.reference
        or result.observation.reference != result.reference
        or result.observation.action_id != action.id
        or result.observation.check != selection.check
        or result.observation.qualification_sha256 != selection.qualification_sha256
        or STATES.get(result.observation.outcome) != action.state
        or receipt is None
        or receipt.reference != result.reference
        or receipt.contract_sha256 != result.contract_sha256
        or receipt.admission.upstream_id != check_message_id(action.id)
        or receipt.admission.owner != "opencode"
    ):
        raise Conflict("check_execution_result_identity_changed")
    return result


class CheckResultCollector:
    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, CheckReader],
        fence: ConsumerFence,
    ) -> None:
        self.bindings, self.db, self.fence = bindings, bindings.db, fence
        self.readers = MappingProxyType(dict(readers))

    async def collect(self, action_id: str, realm: str) -> bool:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if (
            action is None
            or action.operation != "check.run"
            or action.state not in {"admitted", "running", "ambiguous"}
        ):
            raise Conflict("check_reconcilable_action_required")
        async with self.db.sessions() as session:
            binding = await session.get(Binding, action.binding_id)
        if (
            binding is None
            or binding.realm_id != realm
            or binding.revision != action.binding_revision
            or binding.state != "active"
        ):
            raise Conflict("check_original_binding_unavailable")
        await self.bindings.audience_for_output(binding)
        selection = CheckSelection.model_validate(action.payload.get("selection"))
        reader = self.readers.get(reference(binding))
        contract = self.bindings.control.contract_for(reference(binding))
        if (
            reader is None
            or selection.reference != reference(binding)
            or reader.contract_for(reference(binding)) != contract
            or digest(action.payload) != action.operation_digest
        ):
            raise Conflict("check_original_reader_or_operation_changed")
        observed = await reader.observe(reference(binding), action.id, selection.check)
        if observed is None:
            return False  # Missing evidence never authorizes another POST.
        observation = CheckObservation.model_validate(observed.model_dump(mode="python"))
        if (
            observation.reference != reference(binding)
            or observation.action_id != action.id
            or observation.check != selection.check
            or observation.qualification_sha256 != selection.qualification_sha256
            or reader.qualification_for(reference(binding)) != selection.qualification_sha256
        ):
            raise Conflict("check_original_observation_changed")
        if reader.contract_for(reference(binding)) != contract:
            raise Conflict("check_original_reader_contract_changed")
        await self.bindings.audience_for_output(binding)
        receipt = native_receipt(action)
        if receipt is None:
            if action.state != "ambiguous":
                raise Conflict("check_admission_missing")
            # Exact original shell/message association proves this one request
            # reached Native. This reconciles a lost ACK without sending again.
            receipt = ExecutionReceipt(
                action_id=action.id,
                operation_digest=action.operation_digest,
                reference=reference(binding),
                contract_sha256=contract,
                admission=Admission(
                    status="admitted",
                    upstream_id=check_message_id(action.id),
                    details={
                        "operation": "check.run",
                        "reconciled_original_shell": True,
                        "turn_completed": False,
                        "check_passed": False,
                    },
                ),
            )
        if (
            receipt.reference != reference(binding)
            or receipt.contract_sha256 != contract
            or receipt.admission.upstream_id != check_message_id(action.id)
        ):
            raise Conflict("check_admission_or_scope_changed")
        if observation.outcome == "running" and action.native_result:
            raise Conflict("check_terminal_observation_cannot_regress")
        result = None
        if observation.outcome != "running":
            result = CheckExecutionResult(
                action_id=action.id,
                operation_digest=action.operation_digest,
                binding_id=binding.id,
                binding_revision=binding.revision,
                realm_id=realm,
                channel_id=binding.channel_id,
                topic=binding.topic,
                reference=reference(binding),
                contract_sha256=contract,
                observation=observation,
            )
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            if (
                current is None
                or current.state != action.state
                or current.version != action.version
                or current.operation_digest != action.operation_digest
                or current.payload != action.payload
                or current.binding_revision != binding.revision
            ):
                raise Conflict("check_result_changed_before_save")
            if result is None:
                if current.state != "running" or not current.admission:
                    current.state, current.admission = "running", receipt.model_dump(mode="json")
                    current.owner, current.upstream_id = (
                        receipt.admission.owner,
                        receipt.admission.upstream_id,
                    )
                    current.version += 1
                return False
            document = result.model_dump(mode="json")
            if current.native_result == document:
                return False
            current.state = STATES[observation.outcome]
            current.admission = receipt.model_dump(mode="json")
            current.upstream_id, current.owner = observation.message_id, "opencode"
            current.native_result, current.status_reason = document, PENDING
            current.version += 1
            session.add(
                AuditEvent(actor="worker", event="project_check_observed", object_id=action.id)
            )
        return True


class CheckResultPublisher:
    def __init__(self, replies: RoutedOutbox) -> None:
        self.replies, self.db, self.tr = replies, replies.outbox.db, Translator()

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            found = await session.scalar(
                select(Action.id)
                .join(Binding, Binding.id == Action.binding_id)
                .where(
                    Action.operation == "check.run",
                    Action.status_reason == PENDING,
                    Binding.realm_id == self.replies.realm_id,
                    Binding.state == "active",
                    Binding.revision == Action.binding_revision,
                )
                .order_by(Action.created_at, Action.id)
                .limit(1)
            )

            return str(found) if found is not None else None

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        result = check_result(action) if action is not None else None
        if action is None or result is None:
            raise Conflict("check_original_result_required")
        binding = await self.replies.outbox.target(action.binding_id, action.binding_revision)
        if (
            (result.realm_id, result.channel_id, result.topic, result.reference)
            != (binding.realm_id, binding.channel_id, binding.topic, reference(binding))
            or binding.realm_id != self.replies.realm_id
            or result.contract_sha256
            != self.replies.outbox.bindings.control.contract_for(result.reference)
        ):
            raise Conflict("check_result_publication_scope_changed")
        locale = action.payload.get("reply_locale", "en")
        if locale not in {"en", "zh-TW"}:
            raise Conflict("check_result_locale_changed")
        locale = cast(Locale, locale)
        observed = result.observation
        text = self.tr.render(
            "checks.result",
            locale,
            title=visible(observed.check.title),
            outcome=self.tr.render("checks.outcome." + observed.outcome, locale),
            exit_code=str(observed.exit_code) if observed.exit_code is not None else "?",
            action_id=action.id,
        )
        output = redact_text(sanitize_controls(observed.output)[0])[0]
        truncated = observed.output_truncated or len(output) > 4000
        if output:
            # Literal encoding keeps logs inert; original Native output remains
            # the source of truth. Never execute embedded commands/HTML/mentions.
            from jt_oz_bridge.presentation.markdown import literal

            text += "\n\n" + literal(output[:4000])
        if truncated:
            text += "\n\n" + self.tr.render("checks.output_truncated", locale)
        header = self.tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("check_result_publication_budget_unavailable")
        pages = tuple(
            self.tr.page_prefix(locale, i, len(rendered.pages)) + body
            for i, body in enumerate(rendered.pages, 1)
        )
        checksum = digest(result.model_dump(mode="json"))
        fence = self.replies.outbox.fence
        assert fence is not None
        async with self.db.sessions.begin() as session:
            await fence.lock(session)
            await lock_output_scope(self.replies.outbox.bindings, session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            current_result = check_result(current) if current is not None else None
            if current is None or current_result != result:
                raise Conflict("check_result_changed_before_publication")
            cached = await session.get(ModelSettingPublication, action.id)
            if cached is not None and cached.source_hash == checksum:
                batch_id = cached.batch_id
            else:
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    "check-result:" + action.id + ":" + checksum,
                    binding,
                    pages,
                    renderer_version="project-check-result-v1",
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=10,
                )
                if cached is None:
                    session.add(
                        ModelSettingPublication(
                            action_id=action.id,
                            binding_id=binding.id,
                            binding_revision=binding.revision,
                            source_hash=checksum,
                            batch_id=batch.id,
                        )
                    )
                else:
                    if (cached.binding_id, cached.binding_revision) != (
                        binding.id,
                        binding.revision,
                    ):
                        raise Conflict("check_previous_publication_scope_changed")
                    cached.source_hash, cached.batch_id = checksum, batch.id
                batch_id = batch.id
            current.status_reason = PUBLISHED
        return await self.replies.outbox.batch_by_id(batch_id, binding.id, binding.revision)


async def known_check_tail(
    db: Database, ref: SessionRef, qualification: CheckExecutionAttestation, message_id: str
) -> KnownCheck:
    """Bounded own-DB recognition of a shell input already eligible for one send.

    Native history never creates an Action or approval. Current token expiry
    cannot undo an admitted historical request; an unacknowledged dispatch
    still needs its exact consumed local choice.
    """
    from jt_oz_bridge.domain.execution import HumanMessage
    from jt_oz_bridge.presentation.commands import parse_input
    from jt_oz_bridge.security.admin import token_hash
    from jt_oz_bridge.storage.control_models import ControlToken

    async with db.sessions() as session:
        candidates = list(
            (
                await session.scalars(
                    select(Action)
                    .join(Binding, Binding.id == Action.binding_id)
                    .where(
                        Binding.backend_id == ref.backend_id,
                        Binding.backend_identity == ref.backend_identity,
                        Binding.project_id == ref.project_id,
                        Binding.canonical_directory == ref.canonical_directory,
                        Binding.session_id == ref.upstream_session_id,
                        Action.operation == "check.run",
                        Action.state.in_(
                            [
                                "dispatching",
                                "admitted",
                                "running",
                                "ambiguous",
                                "completed",
                                "failed",
                                "cancelled",
                            ]
                        ),
                        (Action.upstream_id == message_id)
                        | (
                            (Action.upstream_id.is_(None))
                            & Action.state.in_(["dispatching", "ambiguous"])
                        ),
                    )
                    .order_by(Action.created_at.desc(), Action.id)
                    .limit(101)
                )
            ).all()
        )
        if len(candidates) > 100:
            raise Conflict("owned_check_tail_lookup_capacity")
        matches = [action for action in candidates if check_message_id(action.id) == message_id]
        if len(matches) != 1:
            raise Conflict("owned_check_tail_action_not_found")
        action = matches[0]
        selection = CheckSelection.model_validate(action.payload.get("selection"))
        source = HumanMessage.model_validate(action.payload.get("source"))
        parsed = parse_input(source.text, bound=True)
        if (
            action.payload.get("operation") != "check.run"
            or action.operation_digest != digest(action.payload)
            or selection.reference != ref
            or SessionRef.model_validate(action.payload.get("reference")) != ref
            or selection.check not in qualification.catalog.checks
            or selection.catalog_sha256 != digest(qualification.catalog.model_dump(mode="json"))
            or selection.qualification_sha256 != qualification.enrollment_sha256
            or source.is_bot
            or source.deleted
            or source.revision != 0
            or source.author_id != action.actor_id
            or parsed.kind != "command"
            or parsed.command != "check"
            or token_hash(parsed.arguments) != action.payload.get("selection_token_sha256")
        ):
            raise Conflict("owned_check_tail_original_source_changed")
        receipt = native_receipt(action)
        if receipt is None:
            token = await session.get(ControlToken, action.payload.get("selection_token_sha256"))
            if (
                action.state not in {"dispatching", "ambiguous"}
                or token is None
                or not token.used
                or token.kind != "native-check-choice"
                or token.user_id != action.actor_id
                or token.realm_id != source.realm_id
                or token.binding_id != action.binding_id
                or token.binding_revision != action.binding_revision
                or token.context_hash != digest(selection.model_dump(mode="json"))
                or token.context != selection.model_dump(mode="json")
            ):
                raise Conflict("owned_check_tail_consumed_choice_required")
        elif (
            receipt.admission.upstream_id != message_id
            or receipt.reference != ref
            or receipt.contract_sha256 != qualification.catalog.contract_sha256
        ):
            raise Conflict("owned_check_tail_admission_scope_changed")
        return KnownCheck(
            action.id, action.operation_digest, selection.check, selection.qualification_sha256
        )


def owned_check_lookup(
    db: Database, qualification: CheckExecutionAttestation
) -> Callable[[SessionRef, str], Awaitable[KnownCheck]]:
    async def known(ref: SessionRef, message_id: str) -> KnownCheck:
        return await known_check_tail(db, ref, qualification, message_id)

    return known
