"""Native prompt result evidence, kept independently of its initial admission."""

from typing import Literal

from pydantic import Field, StrictInt

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.check_results import CheckExecutionResult, check_result
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.resource_execution_results import (
    ResourceExecutionResult,
    resource_result,
)
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action


class NativeExecutionResult(ControlModel):
    action_id: str
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_id: str
    binding_revision: StrictInt = Field(ge=1)
    realm_id: str
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_semantic_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    delivery_input_id: str
    delivery_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_input_id: str
    terminal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: Literal["completed", "failed", "cancelled"]


def native_result(
    action: Action,
) -> NativeExecutionResult | ResourceExecutionResult | CheckExecutionResult | None:
    if not action.native_result:
        return None
    if action.native_result.get("format") == "native-check-result-v1":
        return check_result(action)
    if action.native_result.get("format") == "native-resource-execution-v1":
        return resource_result(action)
    result = NativeExecutionResult.model_validate(action.native_result)
    receipt = native_receipt(action)
    if (
        action.operation != "prompt"
        or action.payload.get("operation") != "prompt"
        or receipt is None
        or result.action_id != action.id
        or result.operation_digest != action.operation_digest
        or result.admission_sha256 != digest(action.admission)
        or result.binding_id != action.binding_id
        or result.binding_revision != action.binding_revision
        or result.reference != receipt.reference
        or result.contract_sha256 != receipt.contract_sha256
        or result.outcome != action.state
    ):
        raise Conflict("native_execution_result_identity_changed")
    return result


async def read_result(
    bindings: BindingService, action_id: str, realm: str, actor: int
) -> NativeExecutionResult | ResourceExecutionResult | CheckExecutionResult | None:
    async with bindings.db.sessions() as session:
        action = await session.get(Action, action_id)
    if action is None:
        raise Conflict("native_execution_action_missing")
    binding = await bindings.get(action.binding_id, realm, actor)
    if binding.revision != action.binding_revision:
        raise Conflict("native_execution_result_binding_changed")
    result = native_result(action)
    if result is not None and (result.realm_id != realm or result.reference != reference(binding)):
        raise Conflict("native_execution_result_realm_changed")
    if isinstance(result, ResourceExecutionResult) and (result.channel_id, result.topic) != (
        binding.channel_id,
        binding.topic,
    ):
        raise Conflict("native_resource_result_topic_changed")
    return result
