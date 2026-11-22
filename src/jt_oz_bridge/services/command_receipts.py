"""One attempt per immutable human command; authorization belongs to the router.

The inbox itself never executes an operation. A processing receipt after a crash
is ambiguous; replay cannot issue a second menu/token or repeat a mutation.
"""

import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.presentation.commands import KNOWN, parse_input
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.retained_payloads import retained_scope

READONLY_DISCOVERY_COMMANDS = frozenset(
    {"backends", "projects", "sessions", "next", "choose", "bind"}
)


if TYPE_CHECKING:
    from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
    from jt_oz_bridge.domain.control import AudienceSnapshot


@dataclass(frozen=True)
class CommandClaim:
    id: str
    version: int
    status: Literal["claimed", "replay", "held", "busy", "ambiguous", "changed"]
    response: dict[str, Any]


class CommandInbox:
    def __init__(self, db: Database, holder: str, fencing: int) -> None:
        self.db, self.holder, self.fencing = db, holder, fencing
        self.fence = ConsumerFence(holder, fencing)

    async def _scope(self, session: AsyncSession, receipt: CommandReceipt) -> None:
        if receipt.binding_id is None:
            return
        binding = await session.get(Binding, receipt.binding_id)
        if not binding or (
            binding.state,
            binding.revision,
            binding.realm_id,
            binding.channel_id,
            binding.topic,
        ) != (
            "active",
            receipt.binding_revision,
            receipt.realm_id,
            receipt.channel_id,
            receipt.topic,
        ):
            raise Conflict("command_binding_changed")

    async def find(self, realm: str, message_id: int) -> CommandReceipt | None:
        """Internal routing guard only; no authorization or delivery is implied."""
        async with self.db.sessions() as session:
            return cast(
                CommandReceipt | None,
                await session.scalar(
                    select(CommandReceipt).where(
                        CommandReceipt.realm_id == realm, CommandReceipt.message_id == message_id
                    )
                ),
            )

    async def claim(
        self,
        message: HumanMessage,
        command: str,
        *,
        binding_id: str | None = None,
        binding_revision: int | None = None,
        recovered: bool = False,
        unbound_literal_control: bool = False,
        unbound_plain_menu: bool = False,
    ) -> CommandClaim:
        if message.is_bot or message.deleted:
            raise AccessDenied("only_current_human_commands")
        if (binding_id is None) != (binding_revision is None):
            raise ValueError("binding_revision_required")
        if command not in KNOWN and command != "unknown":
            raise ValueError("unregistered_command")
        parsed = parse_input(message.text, bound=True)
        if binding_id is None:
            # `!go` picks a conversation before a topic is connected and continues after.
            unbound = parse_input(message.text, bound=False)
            if unbound.kind == "command" and unbound.command != parsed.command:
                parsed = unbound
        unbound_literal = (
            unbound_literal_control
            and binding_id is None
            and command == "send"
            and parsed.kind == "prompt"
            and parse_input(message.text, bound=False).kind == "invalid"
            and parse_input(message.text, bound=False).command == "send"
        )
        plain_menu = (
            unbound_plain_menu
            and binding_id is None
            and command == "go"
            and parse_input(message.text, bound=False).kind == "ignore"
        )
        if (
            not unbound_literal
            and not plain_menu
            and (
                parsed.kind not in {"command", "unknown", "invalid"}
                or command != ("unknown" if parsed.kind == "unknown" else parsed.command)
            )
        ):
            raise ValueError("command_does_not_match_source")
        checksum = digest(message.model_dump(mode="json"))
        async with self.db.sessions.begin() as session:
            return await self._claim_in_session(
                session,
                message,
                command,
                checksum,
                binding_id=binding_id,
                binding_revision=binding_revision,
                recovered=recovered,
            )

    async def _claim_in_session(
        self,
        session: AsyncSession,
        message: HumanMessage,
        command: str,
        checksum: str,
        *,
        binding_id: str | None,
        binding_revision: int | None,
        recovered: bool,
    ) -> CommandClaim:
        """Original schema32 receipt SQL; caller owns the public or issuer guard."""
        await self.fence.lock(session)
        receipt = await session.scalar(
            select(CommandReceipt).where(
                CommandReceipt.realm_id == message.realm_id,
                CommandReceipt.message_id == message.message_id,
            )
        )
        if receipt:
            if (
                receipt.actor_id,
                receipt.channel_id,
                receipt.topic,
                receipt.binding_id,
                receipt.binding_revision,
            ) != (
                message.author_id,
                message.channel_id,
                message.topic,
                binding_id,
                binding_revision,
            ):
                raise Conflict("command_receipt_scope_changed")
            await self._scope(session, receipt)
            if receipt.source_hash != checksum or receipt.command != command:
                return CommandClaim(receipt.id, receipt.version, "changed", {})
            if receipt.payload_compacted_at is not None:
                if receipt.state != "completed":
                    raise Conflict("retired_command_must_remain_completed")
                retained_scope(
                    receipt.response,
                    kind="command:response",
                    identity=receipt.id,
                    when=receipt.payload_compacted_at,
                )
                # A retired completed receipt still dedupes this Human ID.
                # It cannot regenerate a token, binding, action or output.
                return CommandClaim(receipt.id, receipt.version, "held", {})
            if (
                receipt.state == "deferred"
                and command in READONLY_DISCOVERY_COMMANDS | {"confirm", "go"}
                and receipt.binding_id is None
                and receipt.response == {}
            ):
                receipt.state = "processing"
                receipt.holder, receipt.fencing = self.holder, self.fencing
                receipt.version += 1
                receipt.updated_at = time.time()
                return CommandClaim(receipt.id, receipt.version, "claimed", {})
            status = {"completed": "replay", "held": "held", "ambiguous": "ambiguous"}.get(
                receipt.state, "busy"
            )
            if receipt.state == "processing" and (receipt.holder, receipt.fencing) != (
                self.holder,
                self.fencing,
            ):
                status = "ambiguous"
            return CommandClaim(receipt.id, receipt.version, status, dict(receipt.response))  # type: ignore[arg-type]
        receipt = CommandReceipt(
            realm_id=message.realm_id,
            message_id=message.message_id,
            actor_id=message.author_id,
            channel_id=message.channel_id,
            topic=message.topic,
            source_revision=message.revision,
            source_hash=checksum,
            command=command,
            binding_id=binding_id,
            binding_revision=binding_revision,
            holder=self.holder,
            fencing=self.fencing,
            state="held" if recovered else "processing",
            response={},
        )
        await self._scope(session, receipt)
        session.add(receipt)
        await session.flush()
        return CommandClaim(receipt.id, receipt.version, "held" if recovered else "claimed", {})

    async def record_reply(
        self,
        message: HumanMessage,
        command: str,
        response: dict[str, Any],
        *,
        binding_id: str,
        binding_revision: int,
    ) -> CommandClaim:
        """Keep a reply Bridge gave instead of acting, so an edit or retry finds it.

        Nothing runs and no token or action is created; the receipt only dedupes
        this Human message ID like any command receipt.
        """
        if message.is_bot or message.deleted:
            raise AccessDenied("only_current_human_commands")
        checksum = digest(message.model_dump(mode="json"))
        async with self.db.sessions.begin() as session:
            claim = await self._claim_in_session(
                session,
                message,
                command,
                checksum,
                binding_id=binding_id,
                binding_revision=binding_revision,
                recovered=False,
            )
            if claim.status != "claimed":
                return claim
            updated = await session.execute(
                update(CommandReceipt)
                .where(
                    CommandReceipt.id == claim.id,
                    CommandReceipt.version == claim.version,
                    CommandReceipt.state == "processing",
                    CommandReceipt.holder == self.holder,
                    CommandReceipt.fencing == self.fencing,
                )
                .values(
                    state="completed",
                    version=CommandReceipt.version + 1,
                    response=response,
                    updated_at=time.time(),
                )
            )
            if updated.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("command_receipt_changed")
        return claim

    async def _claim_bound_prompt(
        self,
        message: HumanMessage,
        binding_id: str,
        binding_revision: int,
        *,
        reader: "ZulipSourceReader",
        permit: "ZulipLocalWritePermit",
        audience: "AudienceSnapshot",
    ) -> CommandClaim:
        """Closed Source issuer capability, never a DTO/boolean command bypass."""
        from jt_oz_bridge.adapters.zulip.scope import ZulipSourceReader

        if (
            not isinstance(reader, ZulipSourceReader)
            or message.is_bot
            or message.deleted
            or message.revision != 0
            or parse_input(message.text, bound=True).kind != "prompt"
        ):
            raise AccessDenied("only_closed_current_human_prompt")
        reader.scope.require_write_permit(permit, reader, message, audience)
        async with self.db.sessions.begin() as session:
            result = await self._claim_in_session(
                session,
                message,
                "prompt",
                digest(message.model_dump(mode="json")),
                binding_id=binding_id,
                binding_revision=binding_revision,
                recovered=False,
            )
            reader.scope.require_write_permit(permit, reader, message, audience)
            return result

    async def finish(
        self,
        claim: CommandClaim,
        response: dict[str, Any],
        *,
        commit: Callable[[AsyncSession], Awaitable[None]] | None = None,
    ) -> None:
        if claim.status != "claimed":
            raise Conflict("command_attempt_not_owned")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            receipt = await session.get(CommandReceipt, claim.id)
            if receipt is None:
                raise Conflict("command_receipt_unavailable")
            await self._scope(session, receipt)
            updated = await session.execute(
                update(CommandReceipt)
                .where(
                    CommandReceipt.id == claim.id,
                    CommandReceipt.version == claim.version,
                    CommandReceipt.state == "processing",
                    CommandReceipt.holder == self.holder,
                    CommandReceipt.fencing == self.fencing,
                )
                .values(
                    state="completed",
                    version=CommandReceipt.version + 1,
                    response=response,
                    updated_at=time.time(),
                )
            )
            if updated.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("command_receipt_changed")
            if commit is not None:
                await commit(session)

    async def defer_catalog(self, claim: CommandClaim) -> None:
        """Only a discarded, unpublished token plan makes a retry provably safe."""
        await self._defer_read_only(claim, READONLY_DISCOVERY_COMMANDS)

    async def defer_confirmation(self, claim: CommandClaim) -> None:
        """Caller must positively prove Binding preparation never reached writes."""
        await self._defer_read_only(claim, frozenset({"confirm", "choose", "go"}))

    async def _defer_read_only(self, claim: CommandClaim, commands: frozenset[str]) -> None:
        if claim.status != "claimed":
            raise Conflict("command_attempt_not_owned")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            receipt = await session.get(CommandReceipt, claim.id)
            if (
                receipt is None
                or receipt.command not in commands
                or receipt.binding_id is not None
                or receipt.response != {}
            ):
                raise Conflict("only_unpublished_catalog_attempt_may_defer")
            if receipt.command in {"confirm", "choose", "go"} and await session.scalar(
                select(Binding.id).where(
                    Binding.realm_id == receipt.realm_id,
                    Binding.channel_id == receipt.channel_id,
                    Binding.topic == receipt.topic,
                    Binding.state == "active",
                )
            ):
                raise Conflict("binding_confirmation_already_has_effects")
            changed = await session.execute(
                update(CommandReceipt)
                .where(
                    CommandReceipt.id == claim.id,
                    CommandReceipt.version == claim.version,
                    CommandReceipt.state == "processing",
                    CommandReceipt.holder == self.holder,
                    CommandReceipt.fencing == self.fencing,
                )
                .values(state="deferred", version=claim.version + 1, updated_at=time.time())
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("command_receipt_changed")

    async def abandon(self, claim: CommandClaim) -> None:
        """Preserve uncertain local side effects; never make an attempt claimable again."""
        if claim.status != "claimed":
            raise Conflict("command_attempt_not_owned")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            changed = await session.execute(
                update(CommandReceipt)
                .where(
                    CommandReceipt.id == claim.id,
                    CommandReceipt.version == claim.version,
                    CommandReceipt.state == "processing",
                    CommandReceipt.holder == self.holder,
                    CommandReceipt.fencing == self.fencing,
                )
                .values(
                    state="ambiguous", version=CommandReceipt.version + 1, updated_at=time.time()
                )
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("command_receipt_changed")

    async def recover(self, *, cutoff: float) -> int:
        if not math.isfinite(cutoff) or cutoff > time.time():
            raise ValueError("invalid_command_recovery_cutoff")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            updated = await session.execute(
                update(CommandReceipt)
                .where(
                    CommandReceipt.state == "processing",
                    CommandReceipt.created_at <= cutoff,
                    or_(
                        CommandReceipt.holder != self.holder, CommandReceipt.fencing != self.fencing
                    ),
                )
                .values(
                    state="ambiguous", version=CommandReceipt.version + 1, updated_at=time.time()
                )
            )
            return updated.rowcount  # type: ignore[attr-defined,no-any-return]
