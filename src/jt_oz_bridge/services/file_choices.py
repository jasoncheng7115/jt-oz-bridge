"""Actor-bound one-use file choices; keep the actual Human command unchanged."""

import re
import time
from collections.abc import Mapping
from typing import Any, Literal, cast

from pydantic import Field, field_validator
from sqlalchemy import select, true, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_catalog import (
    WorkspaceCatalogReader,
    WorkspaceEntry,
    WorkspaceListing,
)
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.command_receipts import CommandClaim
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Grant

CHOICE_KIND = "workspace-file-choice"


def file_argument(source: HumanMessage) -> str:
    parsed = parse_input(source.text, is_bot=source.is_bot, bound=True)
    if (
        source.deleted
        or source.revision != 0
        or parsed.kind != "command"
        or parsed.command != "file"
    ):
        raise AccessDenied("file_return_requires_original_unedited_human_file_command")
    value = parsed.arguments.strip()
    if not value:
        raise ValueError("file_argument_required")
    return value


class FileChoice(ControlModel):
    format: Literal["original-workspace-file-choice-v1"] = "original-workspace-file-choice-v1"
    reference: SessionRef
    path: str
    directory: str
    query: str = Field(max_length=255)
    listing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issuer_source: HumanMessage

    @field_validator("path")
    @classmethod
    def safe(cls, value: str) -> str:
        return disclosed_path(value)


class FileTokenUse(ControlModel):
    command_id: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: SessionRef
    path: str

    @field_validator("path")
    @classmethod
    def safe(cls, value: str) -> str:
        return disclosed_path(value)

    def checked(self, source: HumanMessage, ref: SessionRef) -> str:
        argument = file_argument(source)
        if (
            not argument.startswith("file:")
            or token_hash(argument[5:]) != self.token_sha256
            or self.reference != ref
            or self.source_sha256 != digest(source.model_dump(mode="json"))
        ):
            raise Conflict("file_choice_original_source_changed")
        return disclosed_path(self.path)


async def verify_file_use(
    bindings: BindingService, source: HumanMessage, use: FileTokenUse
) -> None:
    use.checked(source, use.reference)
    async with bindings.db.sessions() as session:
        saved = await session.get(ControlToken, use.token_sha256)
        command = await session.get(CommandReceipt, use.command_id)
    if (
        saved is None
        or command is None
        or not saved.used
        or saved.kind != CHOICE_KIND
        or saved.context_hash != use.context_sha256
        or digest(saved.context) != saved.context_hash
        or saved.realm_id != source.realm_id
        or saved.user_id != source.author_id
        or command.realm_id != source.realm_id
        or command.message_id != source.message_id
        or command.actor_id != source.author_id
        or command.command != "file"
        or command.source_hash != use.source_sha256
        or command.binding_id != saved.binding_id
        or command.binding_revision != saved.binding_revision
        or saved.context.get("use")
        != {"command_id": use.command_id, "source_sha256": use.source_sha256}
    ):
        raise Conflict("file_choice_consumed_command_receipt_required")
    choice = FileChoice.model_validate(saved.context.get("choice"))
    if choice.reference != use.reference or choice.path != use.path:
        raise Conflict("file_choice_stored_original_path_changed")


class FileChoices:
    def __init__(
        self,
        bindings: BindingService,
        source: SourceReader,
        tokens: TokenService,
        catalogs: Mapping[SessionRef, WorkspaceCatalogReader],
    ) -> None:
        if tokens.db is not bindings.db or tokens.fence is None:
            raise ValueError("file_choices_require_original_fenced_database")
        self.bindings, self.source, self.tokens, self.catalogs = (
            bindings,
            source,
            tokens,
            readonly_enrollment(catalogs),
        )
        self.fence = tokens.fence

    async def current(self, binding: Binding, source: HumanMessage) -> None:
        if (
            source.is_bot
            or source.deleted
            or source.revision != 0
            or await self.source.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("file_choice_original_human_source_changed")
        latest = await self.bindings.get(
            binding.id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (latest.revision, reference(latest), source.channel_id, source.topic) != (
            binding.revision,
            reference(binding),
            binding.channel_id,
            binding.topic,
        ):
            raise Conflict("file_choice_original_binding_changed")

    async def lock_scope(
        self, session: AsyncSession, binding: Binding, source: HumanMessage
    ) -> None:
        await lock_output_scope(self.bindings, session, binding)
        roles = (
            await session.scalars(
                select(Grant.role)
                .where(
                    Grant.realm_id == source.realm_id,
                    Grant.project_id == binding.project_id,
                    Grant.user_id == source.author_id,
                    Grant.active.is_(True),
                )
                .with_for_update()
            )
        ).all()
        if not any(Permission.OPERATE in ROLES.get(role, set()) for role in roles):
            raise AccessDenied("file_choice_operator_grant_changed")

    async def issue(
        self,
        binding: Binding,
        source: HumanMessage,
        listing: WorkspaceListing,
        entry: WorkspaceEntry,
    ) -> str:
        await self.current(binding, source)
        reader = self.catalogs.get(reference(binding))
        if (
            reader is None
            or not reader.current(listing)
            or listing.reference != reference(binding)
            or entry not in listing.entries
            or entry.kind != "file"
        ):
            raise Conflict("file_choice_current_original_listing_required")
        choice = FileChoice(
            reference=listing.reference,
            path=entry.path,
            directory=listing.directory,
            query=listing.query,
            listing_sha256=listing.sha256,
            issuer_source=source,
        )
        token = await self.tokens.issue(
            CHOICE_KIND,
            source.realm_id,
            source.author_id,
            {"choice": choice.model_dump(mode="json")},
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return "file:" + token

    async def resolve(
        self, binding: Binding, source: HumanMessage, claim: CommandClaim
    ) -> FileTokenUse:
        argument = file_argument(source)
        if not re.fullmatch(r"file:[A-Za-z0-9_-]{32}", argument):
            raise Conflict("file_choice_opaque_token_required")
        await self.current(binding, source)
        # A consumed choice can only resume its exact still-owned command after
        # capture failed before sealing a transfer. It never authorizes another
        # message or bypasses a fresh source, scope and Native listing check.
        use_data = {"command_id": claim.id, "source_sha256": digest(source.model_dump(mode="json"))}
        async with self.bindings.db.sessions() as session:
            saved = await session.get(ControlToken, token_hash(argument[5:]))
        if saved is not None and saved.used:
            if (
                saved.kind != CHOICE_KIND
                or saved.realm_id != source.realm_id
                or saved.user_id != source.author_id
                or digest(saved.context) != saved.context_hash
                or saved.context.get("use") != use_data
            ):
                raise Conflict("file_choice_consumed_for_another_command")
        else:
            saved = await self.tokens.inspect(
                argument[5:], CHOICE_KIND, source.realm_id, source.author_id
            )
        if (saved.binding_id, saved.binding_revision) != (binding.id, binding.revision):
            raise Conflict("file_choice_original_binding_token_required")
        choice = FileChoice.model_validate(saved.context.get("choice"))
        ref = reference(binding)
        reader = self.catalogs.get(ref)
        if (
            choice.reference != ref
            or reader is None
            or await self.source.read(
                choice.issuer_source.realm_id, choice.issuer_source.message_id
            )
            != choice.issuer_source
        ):
            raise Conflict("file_choice_original_menu_source_changed")
        listing = await reader.listing(ref, directory=choice.directory, query=choice.query)
        if listing.sha256 != choice.listing_sha256 or not any(
            e.path == choice.path and e.kind == "file" for e in listing.entries
        ):
            raise Conflict("file_choice_original_listing_changed")
        await self.current(binding, source)
        use_data = {"command_id": claim.id, "source_sha256": digest(source.model_dump(mode="json"))}
        context = {"choice": choice.model_dump(mode="json"), "use": use_data}
        async with self.bindings.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.lock_scope(session, binding, source)
            command = await session.get(CommandReceipt, claim.id)
            if (
                claim.status != "claimed"
                or command is None
                or command.state != "processing"
                or command.version != claim.version
                or command.source_hash != use_data["source_sha256"]
                or (command.holder, command.fencing) != (self.fence.holder, self.fence.fencing)
                or command.binding_id != binding.id
                or command.binding_revision != binding.revision
                or not reader.current(listing)
            ):
                raise Conflict("file_choice_current_original_command_required")
            changed = await session.execute(
                update(ControlToken)
                .where(
                    ControlToken.token_hash == saved.token_hash,
                    ControlToken.kind == CHOICE_KIND,
                    ControlToken.context_hash == saved.context_hash,
                    ControlToken.used.is_(saved.used),
                    true() if saved.used else ControlToken.expires_at > time.time(),
                    ControlToken.binding_id == binding.id,
                    ControlToken.binding_revision == binding.revision,
                    ControlToken.realm_id == source.realm_id,
                    ControlToken.user_id == source.author_id,
                )
                .values(used=True, context=context, context_hash=digest(context))
            )
            if cast(CursorResult[Any], changed).rowcount != 1:
                raise Conflict("file_choice_already_used_or_changed")
        result = FileTokenUse(
            command_id=claim.id,
            source_sha256=use_data["source_sha256"],
            token_sha256=saved.token_hash,
            context_sha256=digest(context),
            reference=ref,
            path=choice.path,
        )
        await verify_file_use(self.bindings, source, result)
        return result
