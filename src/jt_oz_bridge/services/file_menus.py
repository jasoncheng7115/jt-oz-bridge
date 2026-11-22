"""Scoped file search/navigation and paginated diff views, no native mutations."""

from collections.abc import Mapping
from typing import Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_catalog import (
    WorkspaceCatalogReader,
    WorkspaceChanges,
    WorkspaceListing,
    WorkspaceTurns,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal, sanitize_controls
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.file_choices import FileChoices
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest

MENU_KIND = "workspace-file-menu"


class FileMenuState(ControlModel):
    mode: Literal[
        "directory", "listing-page", "diff-file", "diff-page", "changes-page", "turn", "turns-page"
    ]
    reference: SessionRef
    directory: str = Field(default="", max_length=4096)
    query: str = Field(default="", max_length=255)
    path: str = Field(default="", max_length=4096)
    offset: StrictInt = Field(default=0, ge=0, le=65536)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    message_limit: StrictInt = Field(ge=512, le=1000000)
    issuer: HumanMessage
    from_message: str | None = Field(default=None, pattern=r"^msg_[A-Za-z0-9_-]+$", max_length=255)
    turn_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)

    @model_validator(mode="after")
    def selected_turn(self) -> "FileMenuState":
        if (self.from_message is None) != (self.turn_sha256 is None) or (
            self.mode == "turn" and self.from_message is None
        ):
            raise ValueError("file_menu_selected_turn_identity_required")
        if (
            self.mode in {"directory", "listing-page", "turns-page"}
            and self.from_message is not None
        ):
            raise ValueError("file_menu_turn_mode_changed")
        return self

    @field_validator("directory", "path")
    @classmethod
    def safe(cls, value: str) -> str:
        return disclosed_path(value) if value else ""


def visible_path(path: str, maximum: int = 96) -> str:
    value, _ = redact_text(sanitize_controls(path)[0])
    if len(literal(value)) <= maximum:
        return literal(value)
    end = min(maximum - 1, len(value))
    while end and len(literal(value[:end] + "…")) > maximum:
        end -= 1
    return literal(value[:end] + "…")


class FileMenus:
    def __init__(
        self,
        bindings: BindingService,
        source: SourceReader,
        tokens: TokenService,
        catalogs: Mapping[SessionRef, WorkspaceCatalogReader],
        *,
        message_limit: int,
    ) -> None:
        if type(message_limit) is not int or not 512 <= message_limit <= 1000000:
            raise ValueError("file_menu_message_bound_required")
        self.bindings, self.source, self.tokens = bindings, source, tokens
        # A live view keeps Roots created from chat later; a plain dict stays frozen.
        self.choices = FileChoices(bindings, source, tokens, readonly_enrollment(catalogs))
        self.catalogs = self.choices.catalogs
        self.fence = self.choices.fence
        self.message_limit, self.tr = message_limit, Translator()

    def available(self, binding: Binding, command: str) -> bool:
        reader = self.catalogs.get(reference(binding))
        return bool(
            reader is not None
            and reader.qualified(reference(binding), "diff" if command == "diff" else "list")
        )

    async def issue(
        self, binding: Binding, source: HumanMessage, state: FileMenuState, prefix: str
    ) -> str:
        token = await self.tokens.issue(
            MENU_KIND,
            source.realm_id,
            source.author_id,
            state.model_dump(mode="json"),
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return prefix + ":" + token

    async def token(
        self, binding: Binding, source: HumanMessage, value: str
    ) -> tuple[FileMenuState, object]:
        prefix, separator, raw = value.partition(":")
        if (
            not separator
            or prefix not in {"dir", "page", "diff", "diffpage", "diffs", "turn", "turns"}
            or not 1 <= len(raw) <= 128
        ):
            raise Conflict("file_menu_opaque_control_required")
        saved = await self.tokens.inspect(raw, MENU_KIND, source.realm_id, source.author_id)
        state = FileMenuState.model_validate(saved.context)
        modes = {
            "dir": "directory",
            "page": "listing-page",
            "diff": "diff-file",
            "diffpage": "diff-page",
            "diffs": "changes-page",
            "turn": "turn",
            "turns": "turns-page",
        }
        if (
            saved.binding_id,
            saved.binding_revision,
            state.reference,
            state.message_limit,
            state.mode,
        ) != (
            binding.id,
            binding.revision,
            reference(binding),
            self.message_limit,
            modes[prefix],
        ) or await self.source.read(state.issuer.realm_id, state.issuer.message_id) != state.issuer:
            raise Conflict("file_menu_original_scope_or_issuer_changed")
        return state, saved

    async def consume(
        self,
        binding: Binding,
        source: HumanMessage,
        saved: object,
        snapshot: WorkspaceListing | WorkspaceChanges | WorkspaceTurns,
        reader: WorkspaceCatalogReader,
    ) -> None:
        from jt_oz_bridge.storage.control_models import ControlToken

        if not isinstance(saved, ControlToken):
            raise Conflict("file_menu_original_token_required")
        await self.choices.current(binding, source)
        async with self.bindings.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.choices.lock_scope(session, binding, source)
            if not reader.current(snapshot):
                raise Conflict("file_menu_original_snapshot_expired")
            await self.tokens.consume_in_session(session, saved)

    async def route(
        self, binding: Binding, source: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        parsed = parse_input(source.text, bound=True)
        if (
            parsed.kind != "command"
            or parsed.command != command
            or parsed.arguments != arguments
            or command not in {"files", "diff"}
        ):
            raise Conflict("file_menu_original_control_source_required")
        await self.choices.current(binding, source)
        if not self.available(binding, command):
            return self.tr.render("filemenu.unavailable", locale)
        reader = self.catalogs[reference(binding)]
        state = None
        saved = None
        value = arguments.strip()
        if value.startswith(("dir:", "page:", "diff:", "diffpage:", "diffs:", "turn:", "turns:")):
            state, saved = await self.token(binding, source, value)
        snapshot: WorkspaceListing | WorkspaceChanges | WorkspaceTurns
        if command == "diff" and (
            value == "turns" or state is not None and state.mode == "turns-page"
        ):
            if not reader.qualified(reference(binding), "turns") or not reader.qualified(
                reference(binding), "turn-diff"
            ):
                return self.tr.render("filemenu.unavailable", locale)
            turns = await reader.turns(reference(binding), cursor=state.cursor if state else None)
            if (
                state is not None
                and state.offset
                and state.snapshot_sha256 != digest(turns.model_dump(mode="json"))
            ):
                raise Conflict("file_turn_original_page_changed")
            if saved is not None:
                await self.consume(binding, source, saved, turns, reader)
            text = await self.render_turns(
                binding, source, locale, turns, state.offset if state else 0
            )
            snapshot = turns
        elif command == "files":
            if state is not None and state.mode not in {"directory", "listing-page"}:
                raise Conflict("file_menu_token_kind_changed")
            query = state.query if state is not None else value
            directory = state.directory if state is not None else ""
            listing = await reader.listing(reference(binding), directory=directory, query=query)
            offset = state.offset if state is not None and state.mode == "listing-page" else 0
            if (
                state is not None
                and state.mode == "listing-page"
                and state.snapshot_sha256 != listing.sha256
            ):
                raise Conflict("file_menu_listing_changed")
            if offset > len(listing.entries):
                raise Conflict("file_menu_page_outside_listing")
            if saved is not None:
                await self.consume(binding, source, saved, listing, reader)
            text = await self.render_listing(binding, source, locale, listing, offset)
            snapshot = listing
        else:
            if value and state is None:
                raise Conflict("file_diff_token_required")
            if state is not None and state.mode not in {
                "diff-file",
                "diff-page",
                "changes-page",
                "turn",
            }:
                raise Conflict("file_menu_token_kind_changed")
            if state is not None and state.from_message is not None:
                if not reader.qualified(reference(binding), "turn-diff"):
                    return self.tr.render("filemenu.unavailable", locale)
                changes = await reader.diff(
                    reference(binding),
                    from_message=state.from_message,
                    turn_sha256=state.turn_sha256,
                )
                if (changes.from_message, changes.turn_sha256) != (
                    state.from_message,
                    state.turn_sha256,
                ):
                    raise Conflict("file_diff_selected_turn_changed")
            else:
                if state is not None and state.mode == "turn":
                    raise Conflict("file_diff_original_user_turn_required")
                changes = await reader.diff(reference(binding))
            fingerprint = digest(changes.model_dump(mode="json"))
            if state is not None and state.mode != "turn" and state.snapshot_sha256 != fingerprint:
                raise Conflict("file_diff_original_snapshot_changed")
            if saved is not None:
                await self.consume(binding, source, saved, changes, reader)
            text = await self.render_diff(binding, source, locale, changes, state)
            snapshot = changes
        await self.choices.current(binding, source)
        if not reader.current(snapshot) or len(text) > self.message_limit - 100:
            raise Conflict("file_menu_scope_or_message_capacity_changed")
        if command == "diff" and (
            isinstance(snapshot, WorkspaceTurns)
            or isinstance(snapshot, WorkspaceChanges)
            and snapshot.from_message is not None
        ):
            async with self.bindings.db.sessions.begin() as session:
                await self.fence.lock(session)
                await self.choices.lock_scope(session, binding, source)
                if not reader.current(snapshot):
                    raise Conflict("file_diff_final_original_scope_changed")
        return text

    async def render_turns(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        turns: WorkspaceTurns,
        offset: int,
    ) -> str:
        lines = [self.tr.render("filemenu.turns", locale)]
        # Page ordinals and IDs only; no prompt/attachment preview or guessed timestamp unit.
        if offset > len(turns.entries):
            raise Conflict("file_turn_page_outside_list")
        end = offset
        for entry in turns.entries[offset:]:
            estimate = self.tr.render(
                "filemenu.turn",
                locale,
                turn=visible_path(entry.native_id),
                token="turn:" + "a" * 32,
                index=end + 1,
            )
            if len("\n\n".join([*lines, estimate])) > self.message_limit - 220:
                if end == offset:
                    raise Conflict("file_turn_menu_message_capacity")
                break
            state = FileMenuState(
                mode="turn",
                reference=turns.reference,
                from_message=entry.native_id,
                turn_sha256=entry.message_sha256,
                snapshot_sha256=entry.message_sha256,
                message_limit=self.message_limit,
                issuer=source,
            )
            control = await self.issue(binding, source, state, "turn")
            row = self.tr.render(
                "filemenu.turn",
                locale,
                turn=visible_path(entry.native_id),
                token=control,
                index=end + 1,
            )
            lines.append(row)
            end += 1
        if not turns.entries:
            lines.append(self.tr.render("filemenu.empty_turns", locale))
        if end < len(turns.entries) or turns.next_cursor is not None:
            state = FileMenuState(
                mode="turns-page",
                reference=turns.reference,
                cursor=turns.cursor if end < len(turns.entries) else turns.next_cursor,
                offset=end if end < len(turns.entries) else 0,
                snapshot_sha256=digest(turns.model_dump(mode="json")),
                message_limit=self.message_limit,
                issuer=source,
            )
            control = await self.issue(binding, source, state, "turns")
            lines.append(self.tr.render("filemenu.more_diff", locale, token=control))
        return "\n\n".join(lines)

    async def render_listing(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        snapshot: WorkspaceListing,
        offset: int,
    ) -> str:
        lines = [
            self.tr.render("filemenu.title", locale),
            self.tr.render("filemenu.current_bytes", locale),
        ]
        end = offset
        for entry in snapshot.entries[offset : offset + 10]:
            name = visible_path(entry.path)
            estimated = f"{end + 1}. {name}\n`!oz files dir:" + ("a" * 32) + "`"
            if len("\n\n".join([*lines, estimated])) > self.message_limit - 320 and end > offset:
                break
            if entry.kind == "directory":
                state = FileMenuState(
                    mode="directory",
                    reference=snapshot.reference,
                    directory=entry.path,
                    snapshot_sha256=snapshot.sha256,
                    message_limit=self.message_limit,
                    issuer=source,
                )
                token = await self.issue(binding, source, state, "dir")
                row = f"{end + 1}. {name}/\n`!oz files {token}`"
            else:
                token = await self.choices.issue(binding, source, snapshot, entry)
                row = f"{end + 1}. {name}\n`!oz file {token}`"
            lines.append(row)
            end += 1
        if not snapshot.entries:
            lines.append(self.tr.render("filemenu.empty", locale))
        if end < len(snapshot.entries):
            page = FileMenuState(
                mode="listing-page",
                reference=snapshot.reference,
                directory=snapshot.directory,
                query=snapshot.query,
                offset=end,
                snapshot_sha256=snapshot.sha256,
                message_limit=self.message_limit,
                issuer=source,
            )
            token = await self.issue(binding, source, page, "page")
            lines.append(self.tr.render("filemenu.more_files", locale, token=token))
        if not snapshot.complete:
            lines.append(self.tr.render("filemenu.incomplete", locale))
        if snapshot.hidden_count:
            lines.append(self.tr.render("filemenu.hidden", locale, count=snapshot.hidden_count))
        return "\n\n".join(lines)

    async def render_diff(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        changes: WorkspaceChanges,
        state: FileMenuState | None,
    ) -> str:
        fingerprint = digest(changes.model_dump(mode="json"))
        if state is not None and state.mode in {"diff-file", "diff-page"}:
            file = next((f for f in changes.files if f.path == state.path), None)
            if file is None:
                raise Conflict("file_diff_original_file_changed")
            patch, controls = sanitize_controls(file.patch)
            patch, redactions = redact_text(patch)
            headers = [self.tr.render("filemenu.diff_title", locale, path=visible_path(file.path))]
            if changes.from_message is not None:
                headers.append(
                    self.tr.render(
                        "filemenu.patch_turn", locale, turn=visible_path(changes.from_message, 32)
                    )
                )
            reserve = [self.tr.render("filemenu.more_diff", locale, token="diffpage:" + "a" * 32)]
            if controls or redactions:
                reserve.append(self.tr.render("filemenu.sanitized", locale))
            budget = self.message_limit - 100 - len("\n\n".join([*headers, *reserve])) - 4
            if budget <= 64:
                raise Conflict("file_diff_header_message_capacity")
            pages = MobileMarkdown.code_pages(patch, budget, "diff")
            offset = state.offset if state.mode == "diff-page" else 0
            if offset >= len(pages):
                raise Conflict("file_diff_page_changed")
            lines = [*headers, pages[offset]]
            if controls or redactions:
                lines.append(self.tr.render("filemenu.sanitized", locale))
            if offset + 1 < len(pages):
                next_state = state.model_copy(
                    update={"mode": "diff-page", "offset": offset + 1, "issuer": source}
                )
                token = await self.issue(binding, source, next_state, "diffpage")
                lines.append(self.tr.render("filemenu.more_diff", locale, token=token))
            return "\n\n".join(lines)
        offset = state.offset if state is not None else 0
        if offset > len(changes.files):
            raise Conflict("file_diff_page_outside_changes")
        lines = [self.tr.render("filemenu.changes", locale)]
        if changes.from_message is not None:
            lines.append(
                self.tr.render(
                    "filemenu.selected_turn", locale, turn=visible_path(changes.from_message)
                )
            )
        else:
            lines.append(self.tr.render("filemenu.default_turn", locale))
        end = offset
        for file in changes.files[offset : offset + 10]:
            estimate = (
                f"{end + 1}. {visible_path(file.path)} +{file.additions}/-{file.deletions}\n`!oz diff diff:"
                + ("a" * 32)
                + "`"
            )
            if len("\n\n".join([*lines, estimate])) > self.message_limit - 280 and end > offset:
                break
            choice = FileMenuState(
                mode="diff-file",
                reference=changes.reference,
                from_message=changes.from_message,
                turn_sha256=changes.turn_sha256,
                path=file.path,
                snapshot_sha256=fingerprint,
                message_limit=self.message_limit,
                issuer=source,
            )
            token = await self.issue(binding, source, choice, "diff")
            lines.append(
                f"{end + 1}. {visible_path(file.path)} +{file.additions}/-{file.deletions}\n`!oz diff {token}`"
            )
            end += 1
        if not changes.files:
            lines.append(self.tr.render("filemenu.empty_diff", locale))
        if end < len(changes.files):
            next_state = FileMenuState(
                mode="changes-page",
                reference=changes.reference,
                from_message=changes.from_message,
                turn_sha256=changes.turn_sha256,
                offset=end,
                snapshot_sha256=fingerprint,
                message_limit=self.message_limit,
                issuer=source,
            )
            token = await self.issue(binding, source, next_state, "diffs")
            lines.append(self.tr.render("filemenu.more_diff", locale, token=token))
        if changes.hidden_count:
            lines.append(self.tr.render("filemenu.hidden", locale, count=changes.hidden_count))
        return "\n\n".join(lines)
