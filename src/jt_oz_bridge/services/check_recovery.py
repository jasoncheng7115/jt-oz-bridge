"""Read-only recovery of exactly owned checks; never admission or mutation authority."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.checks import V2CheckRunner
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.resources import BackgroundRootWork, V2LeafResourceProofs
from jt_oz_bridge.domain.checks import check_message_id
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.check_results import known_check_tail
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action

# The deployment supplies an immutable pre-send owner journal, not the current
# feed owner or a guessed owner copied into an old Action after restart.
if TYPE_CHECKING:
    from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight

OriginalCheckOwner = Callable[[str, str, SessionRef, str], Awaitable["CheckDispatchPreflight"]]


@dataclass(frozen=True)
class OwnedRunningCheck:
    reference: SessionRef
    owner_epoch: str
    connection_epoch: str
    qualification_sha256: str
    action_ids: tuple[str, ...]
    shell_ids: tuple[str, ...]


class OwnedCheckRecovery:
    def __init__(
        self,
        db: Database,
        proofs: V2LeafResourceProofs,
        reader: V2CheckRunner,
        *,
        owner_for: OriginalCheckOwner | None = None,
    ) -> None:
        self.db, self.proofs, self.reader, self.owner_for = db, proofs, reader, owner_for

    async def classify(self, work: BackgroundRootWork) -> OwnedRunningCheck:
        if not self.proofs.is_current_background(work):
            raise SnapshotBoundaryChanged("check_recovery_background_not_current")
        ref = work.reference
        qualification = self.reader.attestations.get(ref)
        if qualification is None or self.owner_for is None:
            raise ContractError("check_recovery_original_owner_journal_required")
        qualification.require(ref, work.contract_sha256)
        shells = work.running_shell_ids
        if not shells or len(shells) > 100 or len(set(shells)) != len(shells):
            raise ContractError("check_recovery_bounded_unique_running_shells_required")
        scope = await self.proofs.read_scope(ref)
        self._scope(work, scope.owner_epoch, scope.connection_epoch, scope.session_info_sha256)
        async with self.db.sessions() as session:
            candidates = list(
                (
                    await session.execute(
                        select(Action.id, Action.operation_digest)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.backend_id == ref.backend_id,
                            Binding.backend_identity == ref.backend_identity,
                            Binding.project_id == ref.project_id,
                            Binding.canonical_directory == ref.canonical_directory,
                            Binding.session_id == ref.upstream_session_id,
                            Action.operation == "check.run",
                            Action.state.in_(["dispatching", "admitted", "running", "ambiguous"]),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(101)
                    )
                ).all()
            )
        if not candidates or len(candidates) > 100:
            raise Conflict("check_recovery_original_action_capacity_or_missing")
        matched: dict[str, str] = {}
        for identity, operation_digest in candidates:
            known = await known_check_tail(self.db, ref, qualification, check_message_id(identity))
            if known.operation_digest != operation_digest:
                raise Conflict("check_recovery_original_action_changed")
            original = await self.owner_for(
                identity, operation_digest, ref, qualification.enrollment_sha256
            )
            if (
                original.action_id != identity
                or original.operation_digest != operation_digest
                or original.reference != ref
                or original.qualification_sha256 != qualification.enrollment_sha256
                or original.contract_sha256 != work.contract_sha256
                or original.message_id != check_message_id(identity)
                or original.state != "idle"
                or original.owner_epoch != work.owner_epoch
            ):
                raise ContractError("check_recovery_original_owner_not_proven")
            observed = await self.reader.observe(ref, identity, known.check)
            if (
                observed.reference != ref
                or observed.action_id != identity
                or observed.message_id != check_message_id(identity)
                or observed.check != known.check
                or observed.qualification_sha256 != qualification.enrollment_sha256
            ):
                raise ContractError("check_recovery_original_observation_changed")
            if observed.shell_id not in shells:
                continue
            if observed.outcome != "running" or observed.shell_id in matched:
                raise SnapshotBoundaryChanged("check_recovery_running_shell_changed")
            matched[observed.shell_id] = identity
        if set(matched) != set(shells):
            raise ContractError("check_recovery_unowned_running_shell")
        scope = await self.proofs.read_scope(ref)
        self._scope(work, scope.owner_epoch, scope.connection_epoch, scope.session_info_sha256)
        if self.reader.attestations.get(
            ref
        ) is not qualification or not self.proofs.is_current_background(work):
            raise SnapshotBoundaryChanged("check_recovery_qualification_or_boundary_changed")
        return OwnedRunningCheck(
            ref,
            work.owner_epoch,
            work.connection_epoch,
            qualification.enrollment_sha256,
            tuple(sorted(matched.values())),
            tuple(sorted(matched)),
        )

    @staticmethod
    def _scope(work: BackgroundRootWork, owner: str, epoch: str, info: str) -> None:
        if (owner, epoch, info) != (
            work.owner_epoch,
            work.connection_epoch,
            work.session_info_sha256,
        ):
            raise SnapshotBoundaryChanged("check_recovery_original_scope_changed")
