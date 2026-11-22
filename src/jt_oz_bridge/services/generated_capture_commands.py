"""Human-only capture status/retry and scoped, single-use loss acknowledgement."""

import time

from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.binding_scope_history import scope, validate_history
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.file_returns import read_plan
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService, origin
from jt_oz_bridge.services.generated_capture_plans import CapturePlan, LossAuthority, read_capture
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob, GeneratedOutputRecord
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant
from jt_oz_bridge.storage.resource_models import ResourceResultRecord


class GeneratedCaptureCommands:
    def __init__(
        self,
        bindings: BindingService,
        source: SourceReader,
        tokens: TokenService,
        capture: GeneratedCaptureService | None = None,
    ) -> None:
        if (
            tokens.db is not bindings.db
            or tokens.fence is None
            or capture is not None
            and (
                capture.bindings is not bindings
                or capture.journal.source is not source
                or capture.fence != tokens.fence
            )
        ):
            raise ValueError("generated_commands_original_scope_required")
        self.bindings, self.source, self.tokens, self.capture = bindings, source, tokens, capture
        self.db, self.fence, self.tr = bindings.db, tokens.fence, Translator()

    def capability(self, binding: Binding, locale: Locale) -> str:
        if self.capture is None:
            key = "generated.capability_disabled"
        elif reference(binding) not in self.capture.journal.generated_readers:
            key = "generated.capability_not_enrolled"
        else:
            key = "generated.capability_enabled"
        return self.tr.render(key, locale)

    async def current(self, binding: Binding, source: HumanMessage) -> Binding:
        if (
            source.is_bot
            or source.deleted
            or await self.source.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("generated_control_original_human_required")
        current = await self.bindings.get(
            binding.id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (current.revision, current.channel_id, current.topic) != (
            binding.revision,
            source.channel_id,
            source.topic,
        ):
            raise Conflict("generated_control_current_binding_changed")
        return current

    async def lock(
        self, session: AsyncSession, binding: Binding, actor: int, *, administrator: bool = False
    ) -> None:
        await lock_output_scope(self.bindings, session, binding)
        grant = await session.scalar(
            select(Grant)
            .where(
                Grant.realm_id == binding.realm_id,
                Grant.project_id == binding.project_id,
                Grant.user_id == actor,
                Grant.active.is_(True),
                Grant.role.in_(
                    ("administrator",) if administrator else ("operator", "administrator")
                ),
            )
            .with_for_update()
        )
        if grant is None:
            raise Conflict("generated_control_operator_revoked")

    async def owned(
        self, identity: str, binding: Binding, source: HumanMessage, *, allow_admin: bool = False
    ) -> tuple[GeneratedCaptureJob, CapturePlan]:
        async with self.db.sessions() as session:
            row = await session.get(GeneratedCaptureJob, identity)
        if row is None:
            raise Conflict("generated_control_capture_missing")
        plan = read_capture(row)
        if (
            plan.origin.reference != reference(binding)
            or plan.origin.binding_id != binding.id
            or plan.origin.source.realm_id != source.realm_id
        ):
            raise Conflict("generated_control_original_binding_required")
        if plan.origin.source.author_id != source.author_id:
            if not allow_admin:
                raise Conflict("generated_control_original_owner_required")
            await self.bindings.policy.require(
                source.realm_id, source.author_id, binding.project_id, Permission.MANAGE
            )
        return row, plan

    async def scope_history(
        self, session: AsyncSession, plan: CapturePlan, binding: Binding, *, lock: bool = False
    ) -> None:
        if plan.original_scope is None:
            # A pre-scope job cannot infer an old audience or legal move chain.
            if (
                plan.origin.binding_revision,
                plan.origin.source.channel_id,
                plan.origin.source.topic,
            ) != (binding.revision, binding.channel_id, binding.topic):
                raise Conflict("generated_control_legacy_move_unverified")
        else:
            await validate_history(session, plan.original_scope, scope(binding), lock=lock)

    async def authority(
        self, plan: CapturePlan, binding: Binding, source: HumanMessage
    ) -> LossAuthority:
        async with self.db.sessions() as session:
            await self.scope_history(session, plan, binding)
        return LossAuthority(
            role="original_actor"
            if source.author_id == plan.origin.source.author_id
            else "project_administrator",
            scope=scope(binding),
        )

    async def execute(
        self, binding: Binding, source: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        binding = await self.current(binding, source)
        parsed = parse_input(source.text, bound=True)
        if parsed.kind != "command" or parsed.command != "outputs" or parsed.arguments != arguments:
            raise Conflict("generated_control_original_command_required")
        parts = arguments.split()
        if not parts or parts == ["status"]:
            async with self.db.sessions() as session:
                rows = (
                    await session.scalars(
                        select(GeneratedCaptureJob)
                        .join(Binding, Binding.id == GeneratedCaptureJob.binding_id)
                        .where(
                            Binding.backend_id == binding.backend_id,
                            Binding.backend_identity == binding.backend_identity,
                            Binding.session_id == binding.session_id,
                        )
                        .order_by(
                            case(
                                (GeneratedCaptureJob.state.in_(("frozen", "skipped")), 1), else_=0
                            ),
                            GeneratedCaptureJob.created_at.desc(),
                        )
                        .limit(3)
                    )
                ).all()
            if not rows:
                return (
                    self.capability(binding, locale)
                    + "\n"
                    + self.tr.render("generated.none", locale)
                )
            lines = [self.capability(binding, locale), self.tr.render("generated.status", locale)]
            for row in rows:
                plan = read_capture(row)
                if (
                    plan.origin.source.realm_id != source.realm_id
                    or plan.origin.reference != reference(binding)
                ):
                    raise Conflict("generated_control_status_scope_changed")
                total = len(plan.discovery.files) if plan.discovery is not None else "?"
                lines.append(f"`{row.action_id}` {row.state} {plan.next_index}/{total}")
                if plan.discovery is not None:
                    lines.append(
                        self.tr.render(
                            "generated.omissions",
                            locale,
                            hidden=plan.discovery.hidden_count,
                            unsupported=plan.discovery.unsupported_count,
                        )
                    )
            return "\n".join(lines)
        if len(parts) != 2 or parts[0] not in {"retry", "skip", "confirm"}:
            raise ValueError("generated_control_arguments_invalid")
        if parts[0] == "confirm":
            return await self.confirm(binding, source, locale, parts[1])
        row, plan = await self.owned(parts[1], binding, source, allow_admin=parts[0] == "skip")
        if row.state != "held":
            raise Conflict("generated_control_held_capture_required")
        if parts[0] == "skip":
            authority = await self.authority(plan, binding, source)
            token = await self.tokens.issue(
                "generated-skip",
                source.realm_id,
                source.author_id,
                {
                    "action_id": row.action_id,
                    "version": row.version,
                    "payload_hash": row.payload_hash,
                    "authority": authority.model_dump(mode="json"),
                },
                ttl=600,
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            # URL-safe server-issued characters are safe inside the command's
            # code span. Encoding punctuation here would break copy/paste.
            return self.tr.render(
                "generated.confirm_admin_skip"
                if authority.role == "project_administrator"
                else "generated.confirm_skip",
                locale,
                token=token,
            )
        if (
            self.capture is None
            or plan.origin.reference not in self.capture.journal.generated_readers
        ):
            return self.tr.render("router.not_integrated", locale)
        await self.capture.current(plan)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock(session, binding, source.author_id)
            await self.capture.context(session, plan, lock=True)
            current = await session.get(GeneratedCaptureJob, row.action_id, with_for_update=True)
            if current is None or (current.version, current.state, current.payload_hash) != (
                row.version,
                "held",
                row.payload_hash,
            ):
                raise Conflict("generated_control_retry_changed")
            current.state, current.status_reason, current.retry_at = "pending", "human_retry", 0
            current.version += 1
            current.updated_at = time.time()
            session.add(
                AuditEvent(
                    actor=f"{source.realm_id}:{source.author_id}",
                    event="generated_capture_retry",
                    object_id=row.action_id,
                )
            )
        return self.tr.render("generated.retry", locale)

    async def confirm(
        self, binding: Binding, source: HumanMessage, locale: Locale, token: str
    ) -> str:
        saved = await self.tokens.inspect(
            token, "generated-skip", source.realm_id, source.author_id
        )
        if (saved.binding_id, saved.binding_revision) != (binding.id, binding.revision) or set(
            saved.context
        ) not in (
            {"action_id", "version", "payload_hash"},
            {"action_id", "version", "payload_hash", "authority"},
        ):
            raise Conflict("generated_control_ack_scope_changed")
        row, plan = await self.owned(saved.context["action_id"], binding, source, allow_admin=True)
        authority = await self.authority(plan, binding, source)
        if "authority" in saved.context:
            if saved.context["authority"] != authority.model_dump(mode="json"):
                raise Conflict("generated_control_ack_authority_changed")
        elif authority.role != "original_actor" or binding.revision != plan.origin.binding_revision:
            raise Conflict("generated_control_legacy_ack_requires_original_scope_and_actor")
        if (row.state, row.version, row.payload_hash) != (
            "held",
            saved.context["version"],
            saved.context["payload_hash"],
        ):
            raise Conflict("generated_control_ack_capture_changed")
        await self.current(binding, source)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock(
                session,
                binding,
                source.author_id,
                administrator=authority.role == "project_administrator",
            )
            await self.scope_history(session, plan, binding, lock=True)
            action = await session.get(Action, row.action_id, with_for_update=True)
            index = await session.get(ResourceResultRecord, row.action_id, with_for_update=True)
            if action is None or index is None or origin(action, index) != plan.origin:
                raise Conflict("generated_control_ack_origin_changed")
            current = await session.get(GeneratedCaptureJob, row.action_id, with_for_update=True)
            if current is None or (current.state, current.version, current.payload_hash) != (
                "held",
                row.version,
                row.payload_hash,
            ):
                raise Conflict("generated_control_ack_changed_before_commit")
            transfers = (
                await session.scalars(
                    select(FileTransfer)
                    .join(
                        GeneratedOutputRecord, GeneratedOutputRecord.transfer_id == FileTransfer.id
                    )
                    .where(GeneratedOutputRecord.action_id == row.action_id)
                    .with_for_update()
                )
            ).all()
            for transfer in transfers:
                returned = read_plan(transfer)
                if (
                    transfer.attempts != 0
                    or transfer.batch_id is not None
                    or returned.upload is not None
                    or transfer.state not in {"prepared", "held", "rejected"}
                ):
                    raise Conflict("generated_control_cannot_abandon_acknowledged_upload")
                transfer.state, transfer.status_reason = (
                    "rejected",
                    "human_capture_loss_acknowledged",
                )
                transfer.version += 1
                transfer.updated_at = time.time()
                read_plan(transfer)
            await self.tokens.consume_in_session(session, saved)
            changed = plan.model_copy(
                update={"acknowledgement": source, "acknowledgement_authority": authority}
            )
            current.payload = changed.model_dump(mode="json")
            current.payload_hash = digest(current.payload)
            current.state, current.status_reason = "skipped", "human_capture_loss_acknowledged"
            current.version += 1
            current.updated_at = time.time()
            read_capture(current)
            session.add(
                AuditEvent(
                    actor=f"{source.realm_id}:{source.author_id}",
                    event="generated_capture_admin_loss_acknowledged"
                    if authority.role == "project_administrator"
                    else "generated_capture_loss_acknowledged",
                    object_id=row.action_id,
                )
            )
        return self.tr.render("generated.skipped", locale)
