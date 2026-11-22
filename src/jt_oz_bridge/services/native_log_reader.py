"""One attested V2 stream attempt into durable capture; no background startup."""

from pydantic import Field

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.native_events import LogProvenance
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.log_ingestion import LogCapture
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict


class LogReadSummary(ControlModel):
    source: str
    capture_epoch: str
    captured_records: int = Field(ge=0)
    replay_synced: bool
    position: int | None


class V2LogReader:
    def __init__(
        self, bindings: BindingService, execution: V2ExecutionClient, holder: str, fencing: int
    ) -> None:
        self.bindings, self.execution = bindings, execution
        self.holder, self.fencing = holder, fencing

    def check(self, binding: Binding, epoch: str) -> None:
        ref = reference(binding)
        contract = self.execution.contract_for(ref)
        attestation = self.execution.transport.attestation
        if (
            contract != self.bindings.control.contract_for(ref)
            or attestation is None
            or "session.log" not in attestation.verified_operations
            or self.execution.epoch(ref) != epoch
        ):
            raise ContractError("native_log_contract_or_execution_epoch_changed")

    async def run(self, binding_id: str, *, follow: bool = False) -> LogReadSummary:
        if type(follow) is not bool:
            raise ValueError("native_log_follow_boolean_required")
        async with self.bindings.db.sessions() as session:
            binding = await session.get(Binding, binding_id)
        if binding is None or binding.state != "active":
            raise Conflict("native_log_binding_unavailable")
        ref = reference(binding)
        epoch = self.execution.epoch(ref)
        self.check(binding, epoch)
        _, proof = await self.execution.qualified_snapshot(ref)
        if proof.connection_epoch != epoch:
            raise Conflict("native_log_execution_changed_before_capture")
        provenance = LogProvenance(
            binding_id=binding.id,
            binding_revision=binding.revision,
            realm_id=binding.realm_id,
            reference=ref,
            contract_sha256=proof.contract_sha256,
            execution_epoch=epoch,
            ownership_evidence_sha256=proof.ownership_evidence_sha256,
            session_info_sha256=proof.session_info_sha256,
        )
        capture = await LogCapture.open(
            self.bindings, binding_id, self.holder, self.fencing, provenance=provenance
        )
        await self.execution.peer(ref)
        self.check(binding, epoch)
        query = {"follow": "true" if follow else "false"}
        if capture.read.position is not None:
            query["after"] = str(capture.read.position)
        self.execution.transport.profile.prepare(
            "session.log", path={"sessionID": ref.upstream_session_id}, query=query
        )
        events = self.execution.transport.events(
            "session.log", path={"sessionID": ref.upstream_session_id}, query=query
        )
        captured = 0
        try:
            async for frame in events:
                self.check(binding, epoch)
                if not follow and capture.read.synced:
                    raise ContractError("native_nonfollowing_log_continued_after_sync")
                _, inserted = await capture.accept(frame)
                captured += int(inserted)
        finally:
            await events.aclose()
        await self.execution.peer(ref)
        self.check(binding, epoch)
        if follow or not capture.read.synced:
            raise Conflict("native_log_stream_ended_without_continuity")
        return LogReadSummary(
            source=capture.source,
            capture_epoch=capture.epoch,
            captured_records=captured,
            replay_synced=True,
            position=capture.read.position,
        )
