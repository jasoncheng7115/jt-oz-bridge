"""Read-only Native metadata menus with current Human/audience and page fences."""

from collections.abc import Mapping

from pydantic import Field, StrictInt

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.native_metadata import (
    AgentMetadata,
    GitFileMetadata,
    McpMetadata,
    MetadataItem,
    MetadataKind,
    NativeMetadataReader,
    NativeMetadataSnapshot,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import literal, sanitize_controls
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest

COMMANDS: frozenset[MetadataKind] = frozenset(
    {"agents", "commands", "skills", "mcp", "usage", "git"}
)
PAGE_KIND = "native-metadata-page"


class MetadataPage(ControlModel):
    reference: SessionRef
    kind: MetadataKind
    offset: StrictInt = Field(ge=1, le=4096)
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    message_limit: StrictInt = Field(ge=512, le=1000000)


def visible(value: str, maximum: int) -> str:
    text = sanitize_controls(value)[0].replace("\n", " ").replace("\t", " ")
    text, _ = redact_text(text)
    return literal(text if len(text) <= maximum else text[: maximum - 1] + "…")


class NativeMetadataCommands:
    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, NativeMetadataReader],
        tokens: TokenService,
        reader: SourceReader,
        *,
        message_limit: int,
    ) -> None:
        if (
            tokens.db is not bindings.db
            or tokens.fence is None
            or type(message_limit) is not int
            or not 512 <= message_limit <= 1000000
        ):
            raise ValueError("native_metadata_requires_shared_fenced_scope_and_output_limit")
        self.bindings, self.db = bindings, bindings.db
        self.readers = readonly_enrollment(readers)
        self.tokens, self.reader, self.fence = tokens, reader, tokens.fence
        self.message_limit, self.tr = message_limit, Translator()

    def available(self, binding: Binding, command: str) -> bool:
        ref = reference(binding)
        selected = self.readers.get(ref)
        try:
            return (
                selected is not None
                and command in COMMANDS
                and command in selected.available_kinds(ref)
                and selected.contract_for(ref) == self.bindings.control.contract_for(ref)
            )
        except ValueError:
            return False

    async def current(self, binding: Binding, message: HumanMessage) -> None:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in COMMANDS
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("native_metadata_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.VIEW
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("native_metadata_binding_changed")

    async def catalog(
        self, binding: Binding, message: HumanMessage, kind: MetadataKind
    ) -> tuple[NativeMetadataReader, NativeMetadataSnapshot]:
        await self.current(binding, message)
        ref = reference(binding)
        selected = self.readers.get(ref)
        if selected is None or not self.available(binding, kind):
            raise Conflict("native_metadata_not_enrolled")
        snapshot = await selected.read(ref, kind)
        NativeMetadataSnapshot.model_validate(snapshot.model_dump(mode="json"))
        await self.current(binding, message)
        if (
            snapshot.reference != ref
            or snapshot.kind != kind
            or snapshot.contract_sha256 != selected.contract_for(ref)
            or not selected.current(snapshot)
        ):
            raise Conflict("native_metadata_original_snapshot_changed")
        return selected, snapshot

    def row(self, item: MetadataItem, locale: Locale, index: int, compact: bool = False) -> str:
        name = visible(item.name, 16 if compact else 120) or self.tr.render(
            "metadata.unnamed", locale
        )
        detail = ""
        if isinstance(item, AgentMetadata):
            detail = self.tr.render("metadata.agent_mode." + item.mode, locale)
        elif isinstance(item, McpMetadata):
            detail = self.tr.render("metadata.mcp_status." + item.status, locale)
        elif isinstance(item, GitFileMetadata):
            detail = self.tr.render("git.change." + item.change, locale)
            if not compact:
                detail += f" · +{item.additions}/−{item.deletions}"
        return f"{index}. {name}" + (" · " + detail if detail else "")

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        parsed = parse_input(message.text, bound=True)
        if command not in COMMANDS or parsed.command != command or parsed.arguments != arguments:
            raise Conflict("native_metadata_route_source_mismatch")
        kind = command
        parts = arguments.split()
        if kind == "git":
            if parts and parts[0] == "status":
                parts = parts[1:]
            elif parts and parts[0] in {
                "commit",
                "push",
                "diff",
                "branch",
                "checkout",
                "reset",
                "clean",
                "worktree",
                "check",
                "checks",
            }:
                await self.current(binding, message)
                return self.tr.render("git.operation_unavailable", locale)
        if len(parts) > 1 or parts and len(parts[0]) > 128 or kind == "usage" and parts:
            raise ValueError("native_metadata_requires_at_most_one_page_token")
        await self.current(binding, message)
        if not self.available(binding, command):
            return self.tr.render("metadata.unavailable", locale)
        selected, snapshot = await self.catalog(binding, message, kind)
        offset = 0
        fingerprint = digest(snapshot.model_dump(mode="json"))
        if parts:
            saved = await self.tokens.inspect(
                parts[0], PAGE_KIND, message.realm_id, message.author_id
            )
            page = MetadataPage.model_validate(saved.context)
            if (
                saved.binding_id != binding.id
                or saved.binding_revision != binding.revision
                or page.reference != reference(binding)
                or page.kind != kind
                or page.message_limit != self.message_limit
                or page.catalog_sha256 != fingerprint
                or page.offset >= len(snapshot.items)
            ):
                raise Conflict("native_metadata_page_scope_or_catalog_changed")
            await self.current(binding, message)
            if not selected.current(snapshot):
                raise Conflict("native_metadata_page_snapshot_expired")
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                await lock_output_scope(self.bindings, session, binding)
                await self.tokens.consume_in_session(session, saved)
            offset = page.offset
        lines = [self.tr.render("metadata.title." + kind, locale)]
        if kind == "git":
            report = snapshot.git
            if report is None:
                raise Conflict("native_git_report_missing")
            branch = report.branch or self.tr.render("git.not_reported", locale)
            # Budget serialized entities, not just source character count.
            maximum = 120 if self.message_limit >= 1024 else 8 if report.hidden_files else 16
            shown = visible(branch, maximum)
            while len(shown) > min(256, self.message_limit // 5) and maximum > 1:
                maximum //= 2
                shown = visible(branch, maximum)
            lines += [
                self.tr.render("git.branch", locale, branch=shown),
                self.tr.render("git.scope", locale),
            ]
            if report.hidden_files:
                lines.append(self.tr.render("git.hidden", locale, count=report.hidden_files))
            if self.message_limit >= 1024:
                lines.append(
                    self.tr.render(
                        "git.workspace",
                        locale,
                        path=visible(snapshot.reference.canonical_directory, 48),
                    )
                )
        if kind == "usage":
            usage = snapshot.usage
            if usage is None:
                raise Conflict("native_metadata_usage_missing")
            lines.append(
                self.tr.render(
                    "metadata.usage",
                    locale,
                    **{k: literal(str(v)) for k, v in usage.model_dump().items()},
                )
            )
        else:
            end = offset
            # Reserve the page control, explanatory note and caller's wrapper.
            budget = self.message_limit - 300
            if kind == "git":
                footer = self.tr.render("git.read_only", locale)
                more = self.tr.render("metadata.more", locale, command=kind, token="x" * 32)
                budget = self.message_limit - 100 - len(footer) - len(more) - 4
            for item in snapshot.items[offset : offset + 9]:
                row = self.row(item, locale, end + 1)
                if len("\n\n".join([*lines, row])) > budget:
                    if end > offset:
                        break
                    row = self.row(item, locale, end + 1, compact=True)
                    if kind == "git" and len("\n\n".join([*lines, row])) > budget:
                        raise Conflict("native_git_minimum_page_budget_exceeded")
                lines.append(row)
                end += 1
            if not snapshot.items:
                lines.append(
                    self.tr.render(
                        "git.no_disclosable"
                        if kind == "git" and snapshot.git and snapshot.git.hidden_files
                        else "git.empty"
                        if kind == "git"
                        else "metadata.empty",
                        locale,
                    )
                )
            if end < len(snapshot.items):
                token = await self.tokens.issue(
                    PAGE_KIND,
                    message.realm_id,
                    message.author_id,
                    MetadataPage(
                        reference=reference(binding),
                        kind=kind,
                        offset=end,
                        catalog_sha256=fingerprint,
                        message_limit=self.message_limit,
                    ).model_dump(mode="json"),
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                )
                lines.append(self.tr.render("metadata.more", locale, command=kind, token=token))
            lines.append(
                self.tr.render("git.read_only" if kind == "git" else "metadata.read_only", locale)
            )
        result = "\n\n".join(lines)
        if len(result) > self.message_limit - 100:
            raise Conflict("native_metadata_message_budget_changed")
        await self.current(binding, message)
        if not selected.current(snapshot):
            raise Conflict("native_metadata_snapshot_no_longer_current")
        return result
