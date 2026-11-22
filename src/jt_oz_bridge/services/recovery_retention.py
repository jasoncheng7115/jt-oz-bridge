"""Retire recovery bodies only after all execution/provenance consumers settle.

Identity rows, checkpoint high-water marks and current epoch proofs remain. This
is payload TTL, not a promise that the number of identity/epoch rows is bounded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, InputEvent, MaintenanceFlag
from jt_oz_bridge.storage.retained_payloads import retained_scope, tombstone
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem

if TYPE_CHECKING:
    from jt_oz_bridge.services.retention import RetentionExecutor

TERMINAL = frozenset({"completed", "cancelled", "rejected", "failed"})
RECOVERY_STATES = frozenset(
    {
        "zulip_history_held",
        "zulip_history_unqualified",
        "zulip_recovery_captured",
        "zulip_recovery_reviewed",
    }
)


class RecoveryRetention:
    def __init__(self, owner: RetentionExecutor) -> None:
        self.owner = owner

    @staticmethod
    def terminal_history(row: InputEvent) -> bool:
        if not row.source.startswith("zulip-history:") or row.state not in {
            "zulip_history_held",
            "zulip_history_unqualified",
        }:
            return False
        if row.payload_compacted_at is not None:
            retained_scope(
                row.payload,
                kind="recovery_input:payload",
                identity=row.id,
                when=row.payload_compacted_at,
                checksum=row.payload_hash,
            )
        elif (
            row.payload.get("format") != "zulip-history-capture-v1"
            or digest(row.payload) != row.payload_hash
        ):
            raise Conflict("retention_recovery_source_changed")
        return True

    async def fits_storage(self, session: AsyncSession, row: InputEvent, now: float) -> bool:
        # Tombstones must not increase this Source's actual stored byte total,
        # including a possibly longer current encryption key ID after rotation.
        body = tombstone(
            "recovery_input:payload", row.id, digest(row.payload), now, self.scope(row)
        )
        encoded = EncryptedJSON("input_events", "payload").process_bind_param(
            body, session.bind.dialect
        )
        original = await session.scalar(
            select(func.length(InputEvent.payload)).where(InputEvent.id == row.id)
        )
        return encoded is not None and original is not None and len(encoded) <= original

    async def blocked_by_restore(self, session: AsyncSession) -> bool:
        return (
            await session.scalar(
                select(MaintenanceFlag.name).where(MaintenanceFlag.pending.is_(True)).limit(1)
            )
            is not None
        )

    async def files(
        self, session: AsyncSession, realm: str, mid: int, action: str | None = None
    ) -> bool:
        # These original metadata correlations deliberately have no SQL FK.
        conditions: list[ColumnElement[bool]] = [
            (Artifact.realm_id == realm) & (Artifact.source_message_id == mid)
        ]
        if action is not None:
            conditions.append(Artifact.action_id == action)
        return (
            await session.scalar(select(Artifact.id).where(or_(*conditions)).limit(1)) is not None
            or await session.scalar(
                select(FileTransfer.id)
                .where(FileTransfer.realm_id == realm, FileTransfer.source_message_id == mid)
                .limit(1)
            )
            is not None
        )

    async def action_safe(self, session: AsyncSession, action: Action) -> bool:
        if action.state not in TERMINAL or action.upstream_id is not None:
            return False
        if action.payload_compacted_at is not None:
            # Original compaction may retire only empty Native evidence. Verify
            # those tombstones rather than mistaking their nonempty wrappers
            # for an actual admission, or accepting an arbitrary wrapper.
            retained_scope(
                action.payload,
                kind="action:payload",
                identity=action.id,
                when=action.payload_compacted_at,
                checksum=action.operation_digest,
            )
            for name in ("admission", "native_result"):
                retained_scope(
                    getattr(action, name),
                    kind="action:" + name,
                    identity=action.id,
                    when=action.payload_compacted_at,
                    checksum=digest({}),
                )
            return True
        if action.admission or action.native_result:
            return False
        original = HumanMessage.model_validate(action.payload.get("source"))
        return not (
            await self.owner._referenced(
                session, "actions.id", action.id, exclude=frozenset({"zulip_recovery_items"})
            )
            or await self.owner._binding_pending(session, action.binding_id)
            or await self.files(session, original.realm_id, original.message_id, action.id)
        )

    async def retired_item(self, session: AsyncSession, item: ZulipRecoveryItem) -> bool:
        if item.state != "retired":
            return False
        original = await session.get(InputEvent, item.input_event_id)
        if original is None or original.payload_compacted_at is None:
            return False
        kind = (
            "recovery_input:payload"
            if original.source.startswith("zulip-history:")
            else "input:payload"
        )
        proof = retained_scope(
            original.payload,
            kind=kind,
            identity=original.id,
            when=original.payload_compacted_at,
            checksum=original.payload_hash,
        )
        if kind == "recovery_input:payload" and proof.get("message_id") != item.message_id:
            raise Conflict("retention_retired_source_message_changed")
        return True

    async def source_safe(self, session: AsyncSession, row: InputEvent) -> bool:
        if await self.blocked_by_restore(session):
            return False
        items = list(
            (
                await session.scalars(
                    select(ZulipRecoveryItem)
                    .where(ZulipRecoveryItem.input_event_id == row.id)
                    .limit(2)
                )
            ).all()
        )
        if len(items) > 1:
            return False  # A Source has one original message; unknown correlation stays intact.
        for item in items:
            if item.state == "retired":
                return False  # A full Source cannot use a plain retired flag as eligibility.
            if item.action_id is None:
                if item.state != "rejected":
                    return False  # Captured/held commands are never an expiry-based approval.
            else:
                action = await session.get(Action, item.action_id)
                if (
                    action is None
                    or action.payload_compacted_at is not None
                    or (action.binding_id, action.binding_revision, action.actor_id)
                    != (item.binding_id, item.binding_revision, item.actor_id)
                    or not await self.action_safe(session, action)
                ):
                    return False
            if await self.owner._binding_pending(session, item.binding_id):
                return False
        return True

    async def safe_input(self, session: AsyncSession, row: InputEvent) -> bool:
        if await self.blocked_by_restore(session):
            return False
        if row.state not in RECOVERY_STATES or digest(row.payload) != row.payload_hash:
            raise Conflict("retention_recovery_receipt_changed")
        value = row.payload
        if row.source.startswith("zulip-history:"):
            if value.get(
                "format"
            ) != "zulip-history-capture-v1" or row.source != "zulip-history:" + value.get(
                "source", ""
            ):
                raise Conflict("retention_recovery_history_identity_changed")
            message = value["message"]
            if await self.files(session, value["realm_id"], message["id"]):
                return False
            if await self.owner._source_pending(session, value["realm_id"], message["id"]):
                return False
            if not await self.source_safe(session, row):
                return False
        elif row.source.startswith("zulip-recovery-review:"):
            if value.get("format") != "zulip-recovery-review-v1":
                return False
            if type(value.get("items")) is not dict or len(value["items"]) > 20:
                raise Conflict("retention_recovery_review_identity_changed")
            # A saved review and its consumed-token proof remain intact until
            # each selected original Source has independently retired safely.
            if (
                await session.scalar(
                    select(ZulipRecoveryItem.id)
                    .where(
                        ZulipRecoveryItem.review_receipt_id == row.id,
                        ZulipRecoveryItem.state != "retired",
                    )
                    .limit(1)
                )
                is not None
            ):
                return False
            for identity, link in value["items"].items():
                item = await session.get(ZulipRecoveryItem, link["item"])
                action = await session.get(Action, identity)
                if (
                    item is None
                    or item.action_id != identity
                    or not await self.retired_item(session, item)
                    or action is None
                    or not await self.action_safe(session, action)
                ):
                    return False
            original = HumanMessage.model_validate(value["source"])
            if await self.owner._source_pending(
                session, original.realm_id, original.message_id
            ) or await self.files(session, original.realm_id, original.message_id):
                return False
        elif row.source.startswith("zulip-recovery:"):
            if value.get("format") != "zulip-recovery-run-v1":
                return False
            if (
                row.source != "zulip-recovery:" + value.get("source", "")
                or value.get("id") != row.id
            ):
                raise Conflict("retention_recovery_epoch_identity_changed")
            # Current checkpoint/run proof is never reconstructed from a hash.
            if (
                await session.scalar(
                    select(ZulipRecoveryCheckpoint.source)
                    .where(ZulipRecoveryCheckpoint.run_id == row.id)
                    .limit(1)
                )
                is not None
            ):
                return False
            if (
                await session.scalar(
                    select(ZulipRecoveryItem.id)
                    .where(
                        ZulipRecoveryItem.run_id == row.id,
                    )
                    .limit(1)
                )
                is not None
            ):
                return False
        else:
            raise Conflict("retention_recovery_source_namespace_changed")
        return not await self.owner._referenced(
            session,
            "input_events.id",
            row.id,
            exclude=frozenset({"zulip_recovery_items", "zulip_message_index"}),
        )

    async def token_safe(self, session: AsyncSession, row: ControlToken) -> bool:
        if row.kind != "zulip-recovery-review":
            return True
        if await self.blocked_by_restore(session):
            return False
        items = row.context.get("items")
        if type(items) is not dict or len(items) > 20:
            raise Conflict("retention_recovery_token_identity_changed")
        for identity, link in items.items():
            item = await session.get(ZulipRecoveryItem, link["item"])
            action = await session.get(Action, identity)
            if (
                item is None
                or item.action_id != identity
                or not await self.retired_item(session, item)
                or action is None
                or not await self.action_safe(session, action)
            ):
                return False
        return True

    async def retire_items(self, session: AsyncSession, identity: str) -> None:
        # source_safe was checked under the same fenced write transaction. No
        # await crosses a publication or grants new authority from this marker.
        for item in (
            await session.scalars(
                select(ZulipRecoveryItem)
                .where(ZulipRecoveryItem.input_event_id == identity)
                .limit(2)
            )
        ).all():
            if item.state != "retired":
                item.state = "retired"
                item.version += 1

    @staticmethod
    def scope(row: InputEvent) -> dict[str, Any]:
        value = row.payload
        result = {
            "original_format": value["format"],
            "source": row.source,
            "source_id": row.source_id,
            "revision": row.revision,
        }
        if row.source.startswith("zulip-history:"):
            result.update(
                {
                    "realm_id": value["realm_id"],
                    "bot_user_id": value["bot_user_id"],
                    "channel_id": value["channel_id"],
                    "message_id": value["message"]["id"],
                    "canonical_response_sha256": value["canonical_response_sha256"],
                    "run_id": value["run_id"],
                }
            )
        return result
