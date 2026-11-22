"""Read real encrypted completed check journals; no execution/publication wiring."""

import time
from collections.abc import Mapping
from types import MappingProxyType
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.checks import CheckReader, CheckSelection
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_evidence import (
    GitEvidenceView,
    RootReviewedGitEvidencePin,
    parse_git_evidence,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.check_dispatch_records import dispatch_preflight
from jt_oz_bridge.services.check_results import check_result
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, WorkerLease


class GitEvidenceResults:
    def __init__(
        self,
        bindings: BindingService,
        source: SourceReader,
        readers: Mapping[SessionRef, CheckReader],
        *,
        fence: ConsumerFence,
        pins: Mapping[SessionRef, RootReviewedGitEvidencePin] | None = None,
    ) -> None:
        self.bindings, self.db, self.source, self.fence = bindings, bindings.db, source, fence
        self.readers = MappingProxyType(dict(readers))
        validated = {
            key: RootReviewedGitEvidencePin.model_validate(value.model_dump(mode="python"))
            for key, value in (pins or {}).items()
        }
        if any(key != pin.reference for key, pin in validated.items()):
            raise ValueError("git_evidence_pin_reference_mismatch")
        self.pins = MappingProxyType(validated)

    async def _view_request_current(
        self,
        binding: Binding,
        message: HumanMessage,
        action_id: str,
        page_token: str | None = None,
    ) -> None:
        """Authenticate the new view request independently of its old check."""
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "git"
            or parsed.arguments.split()
            != ["evidence", action_id] + ([page_token] if page_token else [])
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("git_evidence_view_request_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.VIEW
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or current.audience_revision != binding.audience_revision
            or current.audience_user_ids != binding.audience_user_ids
            or not self.available(binding)
        ):
            raise Conflict("git_evidence_view_scope_changed")

    async def read_for_request(
        self,
        binding: Binding,
        request: HumanMessage,
        action_id: str,
        *,
        page_token: str | None = None,
    ) -> GitEvidenceView:
        """Read a completed check for a separately authenticated current viewer.

        The original Human Source is loaded from the encrypted, binding-scoped
        Action. It is never reconstructed from the new request or a caller DTO.
        This method executes no check and supplies no Git mutation permission.
        """
        if not self.available(binding):
            raise Conflict("git_evidence_not_qualified")
        if type(action_id) is not str or len(action_id) != 36 or str(UUID(action_id)) != action_id:
            raise ValueError("git_evidence_canonical_action_id_required")
        request = HumanMessage.model_validate(request.model_dump(mode="python"))
        await self._view_request_current(binding, request, action_id, page_token)
        async with self.db.sessions() as session:
            # Filter scope before SQLAlchemy decrypts the retained payload.
            action = await session.scalar(
                select(Action).where(
                    Action.id == action_id,
                    Action.binding_id == binding.id,
                    Action.binding_revision == binding.revision,
                    Action.state == "completed",
                )
            )
            if action is None:
                raise Conflict("git_evidence_completed_original_journals_required")
            original = HumanMessage.model_validate(action.payload.get("source"))
        await self._view_request_current(binding, request, action_id, page_token)
        first = await self.read(binding, original, action_id)
        await self._view_request_current(binding, request, action_id, page_token)
        async with self.db.sessions() as session:
            async with session.begin():
                await lock_output_scope(self.bindings, session, binding)
                second = await self._read(session, binding, original, action_id)
                lease = await session.scalar(
                    select(WorkerLease).where(WorkerLease.role == "consumer")
                )
                if (
                    first != second
                    or lease is None
                    or (lease.holder, lease.fencing) != (self.fence.holder, self.fence.fencing)
                    or lease.expires_at <= time.time()
                    or not self.available(binding)
                ):
                    raise Conflict("git_evidence_view_final_journal_or_lease_changed")
        if lease.expires_at <= time.time():
            raise Conflict("git_evidence_view_final_lease_expired")
        return second

    def available(self, binding: Binding) -> bool:
        ref = reference(binding)
        pin, reader = self.pins.get(ref), self.readers.get(ref)
        if pin is None or reader is None:
            return False
        try:
            return (
                pin.reference == ref
                and pin.contract_sha256 == self.bindings.control.contract_for(ref)
                and reader.contract_for(ref) == pin.contract_sha256
                and reader.qualification_for(ref) == pin.qualification_sha256
                and digest(reader.catalog(ref).model_dump(mode="json")) == pin.catalog_sha256
                and pin.check in reader.catalog(ref).checks
            )
        except (ValueError, TypeError):
            return False

    async def _current(self, binding: Binding, message: HumanMessage) -> None:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "check"
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("git_evidence_original_check_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.VIEW
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or current.audience_revision != binding.audience_revision
            or current.audience_user_ids != binding.audience_user_ids
        ):
            raise Conflict("git_evidence_current_binding_changed")
        if not self.available(binding):
            raise Conflict("git_evidence_not_qualified")

    async def _read(
        self, session: AsyncSession, binding: Binding, message: HumanMessage, action_id: str
    ) -> GitEvidenceView:
        action = await session.scalar(
            select(Action).where(
                Action.id == action_id,
                Action.binding_id == binding.id,
                Action.binding_revision == binding.revision,
                Action.actor_id == message.author_id,
                Action.state == "completed",
            )
        )
        if action is None:
            raise Conflict("git_evidence_completed_original_journals_required")
        row = await session.get(CheckDispatchRecord, action_id)
        if action is None or row is None or action.state != "completed":
            raise Conflict("git_evidence_completed_original_journals_required")
        result, preflight = check_result(action), dispatch_preflight(row, action)
        pin = self.pins[reference(binding)]
        selection = CheckSelection.model_validate(action.payload.get("selection"))
        parsed = parse_input(message.text, bound=True)
        token = await session.get(ControlToken, token_hash(parsed.arguments))
        if (
            result is None
            or result.observation.outcome != "passed"
            or result.observation.output_truncated
            or (action.binding_id, action.binding_revision, action.actor_id)
            != (binding.id, binding.revision, message.author_id)
            or HumanMessage.model_validate(action.payload.get("source")) != message
            or (result.realm_id, result.channel_id, result.topic, result.reference)
            != (binding.realm_id, binding.channel_id, binding.topic, reference(binding))
            or selection.check != pin.check
            or selection.catalog_sha256 != pin.catalog_sha256
            or selection.qualification_sha256 != pin.qualification_sha256
            or result.contract_sha256 != pin.contract_sha256
            or preflight.contract_sha256 != pin.contract_sha256
            or action.payload.get("selection_token_sha256") != token_hash(parsed.arguments)
            or token is None
            or not token.used
            or token.kind != "native-check-choice"
            or (token.user_id, token.realm_id, token.binding_id, token.binding_revision)
            != (message.author_id, message.realm_id, binding.id, binding.revision)
            or token.context != selection.model_dump(mode="json")
            or token.context_hash != digest(token.context)
        ):
            raise Conflict("git_evidence_original_result_scope_or_choice_changed")
        evidence = parse_git_evidence(result.observation.output, pin=pin)
        return GitEvidenceView(
            action_id=action.id,
            result_sha256=digest(result.model_dump(mode="json")),
            preflight_sha256=digest(preflight.model_dump(mode="json")),
            evidence=evidence,
        )

    async def read(
        self, binding: Binding, message: HumanMessage, action_id: str
    ) -> GitEvidenceView:
        # A value is historical data, never a reusable authorization permit.
        if not self.available(binding):
            raise Conflict("git_evidence_not_qualified")
        message = HumanMessage.model_validate(message.model_dump(mode="python"))
        await self._current(binding, message)
        async with self.db.sessions() as session:
            first = await self._read(session, binding, message, action_id)
        await self._current(binding, message)
        async with self.db.sessions() as session:
            async with session.begin():
                await lock_output_scope(self.bindings, session, binding)
                second = await self._read(session, binding, message, action_id)
                lease = await session.scalar(
                    select(WorkerLease).where(WorkerLease.role == "consumer")
                )
                if (
                    first != second
                    or lease is None
                    or (lease.holder, lease.fencing) != (self.fence.holder, self.fence.fencing)
                    or lease.expires_at <= time.time()
                    or not self.available(binding)
                ):
                    raise Conflict("git_evidence_final_journal_scope_or_lease_changed")
        if lease.expires_at <= time.time():
            raise Conflict("git_evidence_final_lease_expired")
        return second
