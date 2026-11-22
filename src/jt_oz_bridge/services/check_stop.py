"""Conservative own-Root background check stop reporting; no Native mutations.

An ownDB in-flight row is a reason to withhold coordinator interrupt, never
proof that a shell exists or that it was killed. Actual process termination
remains unqualified. The caller pauses its queue in the same fenced transaction.
"""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action

BACKGROUND_STOP_UNQUALIFIED = "background_stop_unqualified"
IN_FLIGHT_CHECK_STATES = ("dispatching", "admitted", "running", "ambiguous")


@dataclass(frozen=True)
class StopReceipt:
    interrupt_action_id: str | None
    background_stop_unqualified: bool


class UnqualifiedBackgroundStop(Conflict):
    """The original request withheld interrupt; a replay never changes the queue."""


def prior_stop_receipt(
    action: Action, binding: Binding, user_id: int, payload: dict[str, Any]
) -> StopReceipt:
    if (
        action.binding_id != binding.id
        or action.actor_id != user_id
        or action.binding_revision != binding.revision
    ):
        raise Conflict("stop_action_identity_conflict")
    if action.status_reason == BACKGROUND_STOP_UNQUALIFIED:
        if (
            action.operation != "interrupt"
            or action.state != "rejected"
            or action.owner != "bridge"
            or action.upstream_id is not None
            or action.admission
            or action.native_result
            or action.payload != payload
            or action.operation_digest != digest(payload)
        ):
            raise Conflict("background_stop_receipt_changed")
        return StopReceipt(None, True)
    return StopReceipt(action.id, False)


async def has_in_flight_check(session: AsyncSession, binding: Binding) -> bool:
    # Include earlier binding revisions and origins of this exact original Root.
    # Do not expose another topic's IDs or infer current shell/process liveness.
    return (
        await session.scalar(
            select(Action.id)
            .join(Binding, Binding.id == Action.binding_id)
            .where(
                Binding.backend_id == binding.backend_id,
                Binding.backend_identity == binding.backend_identity,
                Binding.session_id == binding.session_id,
                Action.operation == "check.run",
                Action.state.in_(IN_FLIGHT_CHECK_STATES),
            )
            .limit(1)
        )
    ) is not None
