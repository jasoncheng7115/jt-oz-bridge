"""Fenced original-owner preflight journal; no send/admission or replay authority."""

from sqlalchemy import func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.checks import CheckSelection
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import ROLES, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord
from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from jt_oz_bridge.storage.statements import insert


def dispatch_preflight(row: CheckDispatchRecord, action: Action) -> CheckDispatchPreflight:
    """Decode immutable historical evidence without substituting current identity."""
    try:
        result = CheckDispatchPreflight.model_validate(row.payload)
        selection = CheckSelection.model_validate(action.payload.get("selection"))
        if (
            row.payload_hash != digest(row.payload)
            or row.action_id != action.id
            or result.action_id != action.id
            or action.operation != "check.run"
            or action.payload.get("operation") != "check.run"
            or digest(action.payload) != action.operation_digest
            or result.operation_digest != action.operation_digest
            or result.binding_id != action.binding_id
            or result.binding_revision != action.binding_revision
            or action.payload.get("binding_id") != action.binding_id
            or action.payload.get("binding_revision") != action.binding_revision
            or result.reference != selection.reference
            or result.reference != SessionRef.model_validate(action.payload.get("reference"))
            or result.qualification_sha256 != selection.qualification_sha256
            or action.upstream_id not in {None, result.message_id}
        ):
            raise ValueError("identity mismatch")
        return result
    except (ValueError, TypeError):
        raise Conflict("check_dispatch_original_record_invalid") from None


class CheckDispatchRecords:
    def __init__(self, bindings: BindingService, fence: ConsumerFence) -> None:
        self.bindings, self.db, self.fence = bindings, bindings.db, fence

    async def record_in_session(
        self,
        session: AsyncSession,
        preflight: CheckDispatchPreflight,
        *,
        expected_action_version: int,
    ) -> CheckDispatchPreflight:
        """Save before one send, in the caller's current fenced transaction.

        Source/Native/network authority is the caller's responsibility. This
        network-free method locks persisted local identity and SQL deadlines;
        it never commits, marks admission or renews an existing proof.
        """
        if (
            not session.in_transaction()
            or session.get_bind().engine.pool is not self.db.engine.sync_engine.pool
            or type(expected_action_version) is not int
            or expected_action_version < 1
        ):
            raise Conflict("check_dispatch_caller_transaction_required")
        proof = CheckDispatchPreflight.model_validate(preflight.model_dump(mode="python"))
        await self.fence.lock(session)
        action = await session.scalar(
            select(Action).where(Action.id == proof.action_id).with_for_update()
        )
        binding = await session.scalar(
            select(Binding).where(Binding.id == proof.binding_id).with_for_update()
        )
        if (
            action is None
            or binding is None
            or action.state != "dispatching"
            or action.version != expected_action_version
            or action.admission
            or action.native_result
            or action.upstream_id is not None
            or binding.state != "active"
            or binding.dispatch_paused
            or binding.revision != proof.binding_revision
            or reference(binding) != proof.reference
            or self.bindings.control.contract_for(proof.reference) != proof.contract_sha256
        ):
            raise Conflict("check_dispatch_current_action_or_binding_changed")
        payload = proof.model_dump(mode="json")
        checksum = digest(payload)
        candidate = CheckDispatchRecord(
            action_id=proof.action_id, payload=payload, payload_hash=checksum
        )
        dispatch_preflight(candidate, action)
        source = HumanMessage.model_validate(action.payload.get("source"))
        if (
            source.is_bot
            or source.deleted
            or source.author_id != action.actor_id
            or source.realm_id != binding.realm_id
            or source.channel_id != binding.channel_id
            or source.topic != binding.topic
        ):
            raise Conflict("check_dispatch_original_human_scope_changed")
        await lock_output_scope(self.bindings, session, binding)
        clock = (
            (func.julianday("now") - 2440587.5) * 86400.0
            if self.db.engine.dialect.name == "sqlite"
            else func.extract("epoch", func.clock_timestamp())
        )
        grant = (
            select(Grant.id)
            .where(
                Grant.realm_id == binding.realm_id,
                Grant.project_id == binding.project_id,
                Grant.user_id == action.actor_id,
                Grant.active.is_(True),
                Grant.role.in_([r for r, p in ROLES.items() if Permission.OPERATE in p]),
            )
            .exists()
        )
        lease = (
            select(WorkerLease.role)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == self.fence.holder,
                WorkerLease.fencing == self.fence.fencing,
                WorkerLease.expires_at > clock,
            )
            .exists()
        )
        token = await session.scalar(
            select(ControlToken)
            .where(
                ControlToken.token_hash == action.payload.get("selection_token_sha256"),
                ControlToken.kind == "native-check-choice",
            )
            .with_for_update()
        )
        selection = CheckSelection.model_validate(action.payload.get("selection"))
        if (
            token is None
            or token.context_hash != digest(token.context)
            or token.context != selection.model_dump(mode="json")
            or token.realm_id != binding.realm_id
            or token.user_id != action.actor_id
            or token.binding_id != binding.id
            or token.binding_revision != binding.revision
            or token.expires_at != action.payload.get("choice_expires_at")
            or not token.used
        ):
            raise Conflict("check_dispatch_consumed_choice_changed")
        authority = (
            lease,
            grant,
            literal(proof.issued_at) <= clock,
            literal(proof.expires_at) > clock,
            literal(token.expires_at) > clock,
        )
        # Encrypt/encode before SQL evaluates the real clock. This rejects an
        # expired proof/lease/choice even after a slow parameter encoder.
        inserted = await session.scalar(
            insert(self.db, CheckDispatchRecord)
            .from_select(
                ["action_id", "payload", "payload_hash", "created_at"],
                select(
                    literal(proof.action_id),
                    literal(payload, type_=EncryptedJSON("check_dispatch_records", "payload")),
                    literal(checksum),
                    clock,
                ).where(*authority),
            )
            .on_conflict_do_nothing(index_elements=["action_id"])
            .returning(CheckDispatchRecord.action_id)
        )
        if inserted is None:
            if await session.scalar(select(literal(1)).where(*authority)) is None:
                raise Conflict("check_dispatch_sql_authority_or_proof_expired")
            existing = await session.get(CheckDispatchRecord, proof.action_id)
            if (
                existing is None
                or dispatch_preflight(existing, action) != proof
                or existing.payload_hash != checksum
            ):
                raise Conflict("check_dispatch_original_owner_must_not_be_overwritten")
        return proof

    async def owner_for(
        self,
        action_id: str,
        operation_digest: str,
        reference: SessionRef,
        qualification_sha256: str,
    ) -> CheckDispatchPreflight:
        """Read the original record; missing evidence never borrows today's owner.

        Expired historical timestamps remain unchanged. They cannot authorize a
        mutation, admission, successful check result or automatic POST retry.
        """
        try:
            async with self.db.sessions() as session:
                row = await session.get(CheckDispatchRecord, action_id)
                action = await session.get(Action, action_id)
            if row is None or action is None:
                raise Conflict("check_dispatch_original_owner_missing")
            result = dispatch_preflight(row, action)
            if (
                result.operation_digest != operation_digest
                or result.reference != reference
                or result.qualification_sha256 != qualification_sha256
            ):
                raise Conflict("check_dispatch_original_owner_scope_changed")
            return result
        except (ValueError, TypeError):
            raise Conflict("check_dispatch_original_owner_unavailable") from None
