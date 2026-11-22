"""Opaque single-use history menus and bounded balanced-Markdown text pages."""

import re
from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal, sanitize_controls
from jt_oz_bridge.security.redaction import RedactionError, redact_text
from jt_oz_bridge.services import menu_shortcuts
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.native_history import StoredHistory
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict

RENDERER_VERSION = "stored-native-text-v2"


class PartChoice(ControlModel):
    record_id: str
    record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class HistoryContext(ControlModel):
    route: Literal["menu", "page", "text"]
    choices: tuple[PartChoice, ...] = Field(default=(), max_length=10)
    before: StrictInt | None = Field(default=None, ge=1)
    part: PartChoice | None = None
    page: StrictInt = Field(default=0, ge=0, le=1000000)
    renderer_version: str = RENDERER_VERSION
    message_limit: StrictInt = Field(ge=512, le=1000000)
    render_locale: Locale = "en"

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.route == "menu":
            valid = (
                bool(self.choices) and self.before is None and self.part is None and self.page == 0
            )
        elif self.route == "page":
            valid = (
                not self.choices
                and self.before is not None
                and self.part is None
                and self.page == 0
            )
        else:
            valid = not self.choices and self.before is None and self.part is not None
        if not valid:
            raise ValueError("invalid_history_route_context")
        return self


class HistoryCommands:
    def __init__(
        self,
        history: StoredHistory,
        tokens: TokenService,
        reader: SourceReader,
        *,
        message_limit: int,
    ) -> None:
        if (
            tokens.db is not history.db
            or tokens.fence is None
            or type(message_limit) is not int
            or not 512 <= message_limit <= 1000000
        ):
            raise ValueError("verified_history_output_contract_and_fence_required")
        self.history, self.tokens, self.reader = history, tokens, reader
        self.fence = tokens.fence
        self.message_limit, self.tr = message_limit, Translator()

    async def source(
        self,
        binding: Binding,
        message: HumanMessage,
        # `!oz output` is the same reader, opened at the newest reply.
        commands: frozenset[str] = frozenset({"history", "output"}),
    ) -> Binding:
        parsed = menu_shortcuts.current(message.text)
        if (
            parsed.kind != "command"
            or parsed.command not in commands
            or message.deleted
            or message.is_bot
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("stored_history_source_changed")
        current = await self.history.current(binding.id, message.realm_id, message.author_id)
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("stored_history_binding_changed")
        return current

    async def issue(
        self, binding: Binding, message: HumanMessage, kind: str, context: HistoryContext
    ) -> str:
        await self.source(binding, message)
        return await self.tokens.issue(
            kind,
            message.realm_id,
            message.author_id,
            context.model_dump(mode="json"),
            binding_id=binding.id,
            binding_revision=binding.revision,
        )

    async def consume(self, binding: Binding, message: HumanMessage, saved: ControlToken) -> None:
        await self.source(binding, message)
        async with self.history.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.history.bindings, session, binding)
            await self.tokens.consume_in_session(session, saved)

    async def menu(
        self, binding: Binding, message: HumanMessage, locale: Locale, before: int | None = None
    ) -> str:
        page = await self.history.page(
            binding.id, message.realm_id, message.author_id, before=before
        )
        await self.source(binding, message)
        if not page.items:
            return self.tr.render("history.empty", locale)
        context = HistoryContext(
            route="menu",
            choices=tuple(
                PartChoice(record_id=part.record_id, record_hash=part.record_hash)
                for part in page.items
            ),
            message_limit=self.message_limit,
        )
        token = await self.issue(binding, message, "history-menu", context)
        lines = [self.tr.render("history.title", locale)]
        lines.extend(
            self.tr.render("history.item", locale, index=index, part=part.part_ordinal + 1)
            for index, part in enumerate(page.items, 1)
        )
        lines.append(self.tr.render("history.choose", locale, token=literal(token)))
        if page.next_before is not None:
            next_token = await self.issue(
                binding,
                message,
                "history-page",
                HistoryContext(
                    route="page", before=page.next_before, message_limit=self.message_limit
                ),
            )
            lines.append(self.tr.render("history.next", locale, token=literal(next_token)))
        return "\n\n".join(lines)

    async def text(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        choice: PartChoice,
        page_number: int,
        render_locale: Locale | None = None,
    ) -> str:
        part = await self.history.part(
            binding.id, message.realm_id, message.author_id, choice.record_id, choice.record_hash
        )
        try:
            normalized, _ = sanitize_controls(part.text)
            displayed, redactions = redact_text(normalized)
            # Token entities can be longer than their 32 visible characters.
            # Reserve the actual longest footer before slicing body pages.
            reserved = (
                100
                + 6
                + len(self.tr.render("history.text_page", locale, index=10000, total=10000))
                + len(self.tr.render("history.next", locale, token=literal("_" * 32)))
            )
            if redactions:
                reserved += len(self.tr.render("history.redacted", locale))
            rendered = MobileMarkdown(locale=render_locale or locale).render(
                displayed, self.message_limit, reserved_characters=reserved
            )
        except (ValueError, RedactionError):
            return self.tr.render("history.unpreviewable", locale)
        if not rendered.pages:
            return self.tr.render("history.no_text", locale)
        if page_number >= len(rendered.pages):
            raise Conflict("stored_history_page_changed")
        body = (
            self.tr.render(
                "history.text_page", locale, index=page_number + 1, total=len(rendered.pages)
            )
            + "\n\n"
            + rendered.pages[page_number]
        )
        if redactions:
            body += "\n\n" + self.tr.render("history.redacted", locale)
        if page_number + 1 < len(rendered.pages):
            opaque = await self.issue(
                binding,
                message,
                "history-text",
                HistoryContext(
                    route="text",
                    part=choice,
                    page=page_number + 1,
                    message_limit=self.message_limit,
                    render_locale=render_locale or locale,
                ),
            )
            body += "\n\n" + self.tr.render("history.next", locale, token=literal(opaque))
        if len(body) > self.message_limit - 100:
            raise Conflict("stored_history_page_budget_changed")
        await self.source(binding, message)
        return body

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        await self.source(binding, message)
        if menu_shortcuts.current(message.text).arguments != arguments:
            raise Conflict("stored_history_source_arguments_changed")
        if not arguments.strip():
            return await self.menu(binding, message, locale)
        match = re.fullmatch(r"([A-Za-z0-9_-]{32})(?:[ \t]+(10|[1-9]))?", arguments.strip())
        if not match:
            raise ValueError("invalid_history_selection")
        saved = await self.tokens.inspect_allowed(
            match[1],
            frozenset({"history-menu", "history-page", "history-text"}),
            message.realm_id,
            message.author_id,
        )
        if saved.binding_id != binding.id or saved.binding_revision != binding.revision:
            raise Conflict("stored_history_token_scope_changed")
        context = HistoryContext.model_validate(saved.context)
        if (
            context.message_limit != self.message_limit
            or context.renderer_version != RENDERER_VERSION
        ):
            raise Conflict("stored_history_renderer_changed")
        if saved.kind == "history-menu":
            if (
                context.route != "menu"
                or match[2] is None
                or not 1 <= int(match[2]) <= len(context.choices)
            ):
                raise Conflict("stored_history_selection_changed")
            text = await self.text(binding, message, locale, context.choices[int(match[2]) - 1], 0)
        else:
            if match[2] is not None:
                raise ValueError("unexpected_history_item")
            if (
                saved.kind == "history-page"
                and context.route == "page"
                and context.before is not None
            ):
                text = await self.menu(binding, message, locale, context.before)
            elif (
                saved.kind == "history-text"
                and context.route == "text"
                and context.part is not None
            ):
                text = await self.text(
                    binding, message, locale, context.part, context.page, context.render_locale
                )
            else:
                raise Conflict("stored_history_token_route_changed")
        await self.consume(binding, message, saved)
        return text

    async def output(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        """The newest stored reply text in full pages; a token continues like history."""
        await self.source(binding, message, frozenset({"output"}))
        if menu_shortcuts.current(message.text).arguments != arguments:
            raise Conflict("stored_output_source_arguments_changed")
        if arguments.strip():
            return await self.route(binding, message, locale, arguments)
        page = await self.history.page(binding.id, message.realm_id, message.author_id)
        await self.source(binding, message, frozenset({"output"}))
        if not page.items:
            return self.tr.render("output.none", locale)
        newest = page.items[0]
        return await self.text(
            binding,
            message,
            locale,
            PartChoice(record_id=newest.record_id, record_hash=newest.record_hash),
            0,
        )

    async def status(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        await self.source(binding, message, frozenset({"status", "choose"}))
        state = await self.history.latest_state(binding.id, message.realm_id, message.author_id)
        checked = await self.source(binding, message, frozenset({"status", "choose"}))
        paused = self.tr.render("router.yes" if checked.dispatch_paused else "router.no", locale)
        return (
            self.tr.render("history.no_state", locale, paused=paused)
            if state is None
            else self.tr.render(
                "history.saved_status",
                locale,
                state=self.tr.render("status." + state.status.value, locale),
                paused=paused,
            )
        )
