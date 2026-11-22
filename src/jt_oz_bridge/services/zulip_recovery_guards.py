"""A recovered prompt needs its exact fresh Human review, never a bulk resume."""

from __future__ import annotations

import asyncio
import math
import time
import weakref
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.services.binding_scope_history import checksum, scope
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, InputEvent
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem


class ReviewWitness:
    pass


@dataclass(frozen=True)
class _Witness:
    item: str
    version: int
    receipt: str
    receipt_hash: str
    action_id: str
    action_digest: str
    scope_hash: str
    token: str
    task: object
    until: float


_issued: weakref.WeakKeyDictionary[ReviewWitness, _Witness] = weakref.WeakKeyDictionary()


async def verify_review(
    bindings: BindingService,
    reader: SourceReader,
    action: Action,
    binding: Binding,
    holder: str,
    fencing: int,
) -> ReviewWitness | None:
    async with bindings.db.sessions() as session:
        item = await session.scalar(
            select(ZulipRecoveryItem).where(ZulipRecoveryItem.action_id == action.id)
        )
        if item is None:
            return None
        if item.state != "reviewed" or item.review_receipt_id is None:
            raise Conflict("recovery_explicit_current_review_required")
        receipt = await session.get(InputEvent, item.review_receipt_id)
        value = receipt.payload if receipt is not None else None
        if (
            receipt is None
            or type(value) is not dict
            or receipt.payload_hash != digest(value)
            or receipt.source != "zulip-recovery-review:" + item.source
            or value.get("format") != "zulip-recovery-review-v1"
            or receipt.state != "zulip_recovery_reviewed"
            or (value.get("holder"), value.get("fencing")) != (holder, fencing)
            or value.get("scope_sha256") != checksum(scope(binding))
            or value.get("actor_id") != action.actor_id
            or value.get("items", {}).get(action.id)
            != {
                "item": item.id,
                "version": item.version,
                "action_digest": action.operation_digest,
                "source_hash": digest(action.payload["source"]),
            }
        ):
            raise Conflict("recovery_review_scope_or_original_action_changed")
        token = await session.get(ControlToken, value["token_sha256"])
        if (
            token is None
            or token.kind != "zulip-recovery-review"
            or not token.used
            or token.context_hash != digest(token.context)
            or token.user_id != action.actor_id
            or token.binding_id != binding.id
            or token.binding_revision != binding.revision
            or token.realm_id != binding.realm_id
        ):
            raise Conflict("recovery_review_token_changed_or_expired")
        confirmed_at = value.get("confirmed_at")
        if (
            type(confirmed_at) is not float
            or not math.isfinite(confirmed_at)
            or confirmed_at <= 0
            or confirmed_at >= token.expires_at
            or value.get("token_expires_at") != token.expires_at
            or value.get("token_context_sha256") != token.context_hash
        ):
            raise Conflict("recovery_original_consumption_deadline_changed")
        context = token.context
        if (
            context.get("scope_sha256") != value["scope_sha256"]
            or (context.get("holder"), context.get("fencing"), context.get("run_id"))
            != (holder, fencing, value.get("run_id"))
            or context.get("items", {}).get(action.id, {}).get("action_digest")
            != action.operation_digest
            or context.get("items", {}).get(action.id, {}).get("source_hash")
            != digest(action.payload["source"])
        ):
            raise Conflict("recovery_review_token_original_selection_changed")
        source = HumanMessage.model_validate(value["source"])
        parsed = parse_input(source.text, bound=True)
        parts = parsed.arguments.split()
        if (
            parsed.kind != "command"
            or parsed.command != "recovery"
            or len(parts) != 2
            or parts[0] != "confirm"
            or token_hash(parts[1]) != token.token_hash
            or source.revision != 0
        ):
            raise Conflict("recovery_review_actual_confirmation_required")
        expected_hash = receipt.payload_hash
    started = time.monotonic()
    # Genuine source reads, not the saved DTO, issue this task/5s witness.
    if (
        source.author_id != action.actor_id
        or source.is_bot
        or source.deleted
        or (source.realm_id, source.channel_id, source.topic)
        != (binding.realm_id, binding.channel_id, binding.topic)
        or await reader.read(source.realm_id, source.message_id) != source
        or time.monotonic() > started + 5
    ):
        raise Conflict("recovery_new_human_confirmation_changed")
    witness = ReviewWitness()
    _issued[witness] = _Witness(
        item.id,
        item.version,
        item.review_receipt_id,
        expected_hash,
        action.id,
        action.operation_digest,
        checksum(scope(binding)),
        token.token_hash,
        asyncio.current_task(),
        started + 5,
    )
    return witness


async def require_claim_review(
    session: AsyncSession, action: Action, binding: Binding, witness: ReviewWitness | None
) -> None:
    item = await session.scalar(
        select(ZulipRecoveryItem).where(ZulipRecoveryItem.action_id == action.id).with_for_update()
    )
    if item is None:
        return
    observed = _issued.pop(witness, None) if isinstance(witness, ReviewWitness) else None
    if (
        observed is None
        or observed.task is not asyncio.current_task()
        or time.monotonic() > observed.until
        or observed.action_id != action.id
        or observed.action_digest != action.operation_digest
        or observed.scope_hash != checksum(scope(binding))
        or (item.id, item.version, item.state, item.review_receipt_id)
        != (observed.item, observed.version, "reviewed", observed.receipt)
    ):
        raise Conflict("recovery_current_single_use_review_witness_required")
    receipt = await session.get(InputEvent, observed.receipt)
    token = await session.get(ControlToken, observed.token)
    if (
        receipt is None
        or receipt.state != "zulip_recovery_reviewed"
        or receipt.payload_hash != observed.receipt_hash
        or digest(receipt.payload) != observed.receipt_hash
        or token is None
        or not token.used
        or token.kind != "zulip-recovery-review"
        or (token.realm_id, token.user_id, token.binding_id, token.binding_revision)
        != (binding.realm_id, action.actor_id, binding.id, binding.revision)
        or token.context_hash != digest(token.context)
        or token.context_hash != receipt.payload.get("token_context_sha256")
        or token.expires_at != receipt.payload.get("token_expires_at")
    ):
        raise Conflict("recovery_review_changed_before_final_claim")
