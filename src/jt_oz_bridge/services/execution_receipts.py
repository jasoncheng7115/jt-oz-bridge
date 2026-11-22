"""Qualified native evidence, not a claim that an admitted prompt has completed."""

from pydantic import Field

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action


class ExecutionReceipt(ControlModel):
    action_id: str
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    admission: Admission


def native_receipt(action: Action) -> ExecutionReceipt | None:
    if not action.admission:
        return None  # Legacy/no captured receipt; this is not proof of no admission.
    receipt = ExecutionReceipt.model_validate(action.admission)
    if (
        digest(action.payload) != action.operation_digest
        or receipt.action_id != action.id
        or receipt.operation_digest != action.operation_digest
        or receipt.admission.owner != action.owner
        or receipt.admission.upstream_id != action.upstream_id
    ):
        raise Conflict("native_execution_receipt_identity_changed")
    if "reference" in action.payload and receipt.reference != SessionRef.model_validate(
        action.payload["reference"]
    ):
        raise Conflict("native_execution_receipt_target_changed")
    return receipt


async def read_receipt(
    bindings: BindingService, action_id: str, realm: str, actor: int
) -> ExecutionReceipt | None:
    async with bindings.db.sessions() as session:
        action = await session.get(Action, action_id)
    if action is None:
        raise Conflict("native_execution_action_missing")
    binding = await bindings.get(action.binding_id, realm, actor)
    if binding.revision != action.binding_revision:
        raise Conflict("native_execution_receipt_binding_changed")
    receipt = native_receipt(action)
    if receipt and "reference" not in action.payload and receipt.reference != reference(binding):
        raise Conflict("native_execution_receipt_target_changed")
    if receipt and (
        receipt.reference.backend_id,
        receipt.reference.backend_identity,
        receipt.reference.project_id,
        receipt.reference.canonical_directory,
    ) != (
        binding.backend_id,
        binding.backend_identity,
        binding.project_id,
        binding.canonical_directory,
    ):
        raise Conflict("native_execution_receipt_scope_changed")
    return receipt
