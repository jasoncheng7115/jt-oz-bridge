"""Read the original transcript through scoped, expiring chat history menus."""

import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.adapters.opencode.transcript import (
    ERROR_TYPE,
    NativeTranscriptPage,
    TranscriptEntry,
    TranscriptReader,
)
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel, SessionSnapshot
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal, sanitize_controls
from jt_oz_bridge.security.redaction import RedactionError, redact_text
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.services.resource_history import ResourceHistory
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest

RENDERER: Literal["native-transcript-history-v2"] = "native-transcript-history-v2"


def model_label(model: dict[str, Any]) -> str:
    value = model["providerID"] + "/" + model["id"]
    if "variant" in model:
        value += " [" + model["variant"] + "]"
    return literal(value)


type FailureKind = Literal[
    "auth", "rate_limited", "timeout", "service", "too_long", "stopped", "type", "unknown"
]
TIMEOUT = re.compile(r"time[_.:-]?out|timed[_.:-]?out")


def failure_kind(error: object) -> FailureKind:
    """What an OpenCode error summary ({type?, status?}) says went wrong, in one word.

    The HTTP status decides first; then words in the error type. A type that is
    not a safe identifier counts as missing.
    """
    raw = error if isinstance(error, Mapping) else {}
    status = raw.get("status")
    status = status if type(status) is int and 100 <= status <= 599 else None
    kind = raw.get("type")
    kind = kind if isinstance(kind, str) and ERROR_TYPE.fullmatch(kind) else None
    lowered = kind.lower() if kind else ""
    if status in {401, 403}:
        return "auth"
    if status == 429:
        return "rate_limited"
    if status in {408, 504} or TIMEOUT.search(lowered):
        return "timeout"
    if status is not None and status >= 500:
        return "service"
    if "overflow" in lowered or "context" in lowered:
        return "too_long"
    if "abort" in lowered:
        return "stopped"
    return "type" if kind else "unknown"


def failure_reason(tr: Translator, locale: Locale, error: object) -> str:
    """Why OpenCode failed, for a person; never the error's own message or body."""
    kind = failure_kind(error)
    if kind == "type":
        assert isinstance(error, Mapping)
        # A safe identifier has no backtick, so the code span holds it as is.
        return tr.render("transcript.failure.type", locale, type=error["type"])
    return tr.render("transcript.failure." + kind, locale)


def compaction_line(tr: Translator, locale: Locale, data: Mapping[str, Any]) -> str:
    """One line for OpenCode's compaction of the conversation, by its status."""
    status = data.get("status")
    if status == "running":
        key = "auto" if data.get("reason") == "auto" else "manual"
        return tr.render("transcript.compaction.running_" + key, locale)
    if status == "failed":
        return tr.render(
            "transcript.compaction.failed",
            locale,
            reason=failure_reason(tr, locale, data.get("error")),
        )
    return tr.render("transcript.compaction.completed", locale)


def reply_signature(entry: TranscriptEntry) -> tuple[str, str] | None:
    """The model and Agent an assistant reply's footer names; None for other entries."""
    if entry.kind != "assistant":
        return None
    data = entry.projection()
    return model_label(data["model"]), literal(data["agent"])


def history_preview(source: str, limit: int) -> str:
    """Flatten formatted history to visible text, then escape its preview once.

    Read text/code tokens rather than unescaping upstream HTML. In particular,
    metadata's literal entities are decoded by the same HTML-disabled Markdown
    parser as the final output, while code keeps its actual source characters.
    """
    source, _ = sanitize_controls(source)
    source, _ = redact_text(source)
    blocks = []
    for token in MobileMarkdown().parser.parse(source):
        if token.type == "inline":
            blocks.append(
                "".join(
                    " " if child.type in {"softbreak", "hardbreak"} else child.content
                    for child in token.children or []
                )
            )
        elif token.type in {"fence", "code_block"}:
            blocks.append(token.content)
    text, _ = sanitize_controls(" ".join(blocks))
    text, _ = redact_text(text)
    return literal(" ".join(text.split())[:limit])


class TranscriptChoice(ControlModel):
    native_id: str = Field(min_length=1, max_length=255)
    projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TranscriptContext(ControlModel):
    route: Literal["menu", "older", "text"]
    reference_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cursor: str | None = Field(default=None, min_length=1, max_length=8192)
    choices: tuple[TranscriptChoice, ...] = Field(default=(), max_length=10)
    choice: TranscriptChoice | None = None
    page: StrictInt = Field(default=0, ge=0, le=1000000)
    message_limit: StrictInt = Field(ge=512, le=1000000)
    render_locale: Locale = "en"
    renderer: Literal["native-transcript-history-v2"] = RENDERER

    @model_validator(mode="after")
    def coherent(self) -> "TranscriptContext":
        if self.route == "menu":
            valid = bool(self.choices) and self.choice is None and self.page == 0
        elif self.route == "older":
            valid = (
                self.cursor is not None
                and not self.choices
                and self.choice is None
                and self.page == 0
            )
        else:
            valid = not self.choices and self.choice is not None
        if not valid:
            raise ValueError("original_history_context_route_changed")
        return self


class NativeTranscriptCommands(HistoryCommands):
    def __init__(
        self,
        bindings: BindingService,
        tokens: TokenService,
        source: SourceReader,
        readers: Mapping[SessionRef, TranscriptReader],
        *,
        message_limit: int,
    ) -> None:
        super().__init__(ResourceHistory(bindings), tokens, source, message_limit=message_limit)
        self.readers: Mapping[SessionRef, TranscriptReader] = readonly_enrollment(readers)
        for ref, reader in self.readers.items():
            if reader.contract_for(ref) != bindings.control.contract_for(ref):
                raise ValueError("native_history_reader_contract_changed")
        self.menu_limit = max(1, min(10, (message_limit - 400) // 100))

    def selected(self, binding: Binding) -> TranscriptReader:
        reader = self.readers.get(reference(binding))
        if reader is None:
            raise Conflict("original_transcript_reader_not_enrolled")
        return reader

    def context(
        self, binding: Binding, route: Literal["menu", "older", "text"], **values: Any
    ) -> TranscriptContext:
        ref = reference(binding)
        return TranscriptContext(
            route=route,
            reference_sha256=digest(ref.model_dump()),
            contract_sha256=self.selected(binding).contract_for(ref),
            message_limit=self.message_limit,
            **values,
        )

    async def issue_native(
        self, binding: Binding, message: HumanMessage, context: TranscriptContext
    ) -> str:
        await self.source(binding, message)
        return await self.tokens.issue(
            "transcript-" + context.route,
            message.realm_id,
            message.author_id,
            context.model_dump(mode="json"),
            binding_id=binding.id,
            binding_revision=binding.revision,
        )

    async def read(
        self, binding: Binding, message: HumanMessage, cursor: str | None
    ) -> tuple[TranscriptReader, NativeTranscriptPage]:
        await self.source(binding, message)
        reader = self.selected(binding)
        ref = reference(binding)
        page = await reader.capture(ref, cursor=cursor, limit=self.menu_limit)
        if (
            page.reference != ref
            or page.contract_sha256 != reader.contract_for(ref)
            or page.cursor != cursor
            or page.limit != self.menu_limit
            or len(page.entries) > self.menu_limit
            or len({e.native_id for e in page.entries}) != len(page.entries)
            or not reader.current(page)
        ):
            raise Conflict("original_transcript_page_scope_changed")
        await self.source(binding, message)
        if not reader.current(page):
            raise Conflict("original_transcript_page_no_longer_current")
        return reader, page

    def body(self, entry: TranscriptEntry, locale: Locale, *, footer: bool = True) -> str:
        """``footer=False`` leaves out an assistant reply's model/Agent line only."""
        data = entry.projection()
        if entry.kind == "user":
            text = data["text"]
            if not isinstance(text, str):
                raise Conflict("original_history_user_text_not_string")
            return text
        if entry.kind == "assistant":
            lines = []
            for part in data["content"]:
                if part["type"] == "text":
                    lines.append(part["text"])
                else:
                    lines.append(
                        self.tr.render(
                            "transcript.tool",
                            locale,
                            name=literal(part["name"]),
                            status=self.tr.render(
                                "transcript.tool_status." + part["status"], locale
                            ),
                            exit=part.get("exit_code", "—"),
                        )
                    )
            if "error" in data and failure_kind(data["error"]) != "stopped":
                # A step `!stop` ended says so in its outcome, not as a failure.
                lines.append(
                    self.tr.render(
                        "transcript.step_failed",
                        locale,
                        reason=failure_reason(self.tr, locale, data["error"]),
                    )
                )
            if footer:
                model = data["model"]
                lines.append(
                    self.tr.render("transcript.model", locale, model=model_label(model))
                    + " · "
                    + self.tr.render("transcript.agent", locale, agent=literal(data["agent"]))
                )
            if "completed" not in data["time"]:
                lines.append(self.tr.render("transcript.incomplete", locale))
            return "\n\n".join(lines)
        if entry.kind == "idle":
            if data["outcome"] == "failed" and "error" in data:
                return self.tr.render(
                    "transcript.outcome_failed_reason",
                    locale,
                    reason=failure_reason(self.tr, locale, data["error"]),
                )
            return self.tr.render(
                "transcript.outcome",
                locale,
                outcome=self.tr.render("transcript.outcome." + data["outcome"], locale),
            )
        if entry.kind == "model-switched":
            model = data["model"]
            return self.tr.render("transcript.model", locale, model=model_label(model))
        if entry.kind == "agent-switched":
            return self.tr.render("transcript.agent", locale, agent=literal(data["agent"]))
        if entry.kind == "compaction":
            return compaction_line(self.tr, locale, data)
        if entry.kind == "shell":
            return self.tr.render(
                "transcript.control_status",
                locale,
                status=self.tr.render("transcript.control_state." + data["status"], locale),
            )
        return self.tr.render("transcript.internal_omitted", locale)

    async def native_menu(
        self, binding: Binding, message: HumanMessage, locale: Locale, cursor: str | None = None
    ) -> str:
        reader, page = await self.read(binding, message, cursor)
        if not page.entries:
            return self.tr.render("transcript.empty", locale)
        choices = tuple(
            TranscriptChoice(native_id=e.native_id, projection_sha256=e.projection_sha256)
            for e in page.entries
        )
        opaque = await self.issue_native(
            binding, message, self.context(binding, "menu", cursor=cursor, choices=choices)
        )
        lines = [self.tr.render("transcript.title", locale)]
        for index, entry in enumerate(page.entries, 1):
            try:
                text, _ = sanitize_controls(self.body(entry, locale))
                preview = history_preview(text, 20) if self.message_limit >= 1000 else ""
            except (ValueError, RedactionError):
                preview = ""
            lines.append(
                self.tr.render(
                    "transcript.item",
                    locale,
                    index=index,
                    kind=self.tr.render("transcript.kind." + entry.kind, locale),
                    preview=preview,
                )
            )
        lines.append(self.tr.render("transcript.choose", locale, token=literal(opaque)))
        if page.next_cursor is not None:
            older = await self.issue_native(
                binding, message, self.context(binding, "older", cursor=page.next_cursor)
            )
            lines.append(self.tr.render("history.next", locale, token=literal(older)))
        await self.source(binding, message)
        if not reader.current(page):
            raise Conflict("original_transcript_menu_changed")
        body = "\n\n".join(lines)
        if len(body) > self.message_limit - 100:
            raise Conflict("original_transcript_menu_budget_changed")
        return body

    async def native_text(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        context: TranscriptContext,
        choice: TranscriptChoice,
        page_number: int,
    ) -> str:
        reader, page = await self.read(binding, message, context.cursor)
        entry = next((e for e in page.entries if e.native_id == choice.native_id), None)
        if entry is None or entry.projection_sha256 != choice.projection_sha256:
            raise Conflict("original_transcript_selection_changed")
        try:
            normalized, _ = sanitize_controls(self.body(entry, context.render_locale))
            text, redactions = redact_text(normalized)
            reserved = (
                100
                + 6
                + len(
                    self.tr.render(
                        "transcript.text_page",
                        locale,
                        kind=self.tr.render("transcript.kind." + entry.kind, locale),
                        index=10000,
                        total=10000,
                    )
                )
                + len(self.tr.render("history.next", locale, token=literal("_" * 32)))
            )
            if redactions:
                reserved += len(self.tr.render("history.redacted", locale))
            rendered = MobileMarkdown(locale=context.render_locale).render(
                text, self.message_limit, reserved_characters=reserved
            )
        except (ValueError, RedactionError):
            return self.tr.render("transcript.unpreviewable", locale)
        if not rendered.pages:
            return self.tr.render("transcript.no_text", locale)
        if page_number >= len(rendered.pages):
            raise Conflict("original_transcript_text_page_changed")
        body = (
            self.tr.render(
                "transcript.text_page",
                locale,
                kind=self.tr.render("transcript.kind." + entry.kind, locale),
                index=page_number + 1,
                total=len(rendered.pages),
            )
            + "\n\n"
            + rendered.pages[page_number]
        )
        if redactions:
            body += "\n\n" + self.tr.render("history.redacted", locale)
        if page_number + 1 < len(rendered.pages):
            opaque = await self.issue_native(
                binding,
                message,
                self.context(
                    binding,
                    "text",
                    cursor=context.cursor,
                    choice=choice,
                    page=page_number + 1,
                    render_locale=context.render_locale,
                ),
            )
            body += "\n\n" + self.tr.render("history.next", locale, token=literal(opaque))
        await self.source(binding, message)
        if not reader.current(page) or len(body) > self.message_limit - 100:
            raise Conflict("original_transcript_text_or_budget_changed")
        return body

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        if reference(binding) not in self.readers:
            return await super().route(binding, message, locale, arguments)
        await self.source(binding, message)
        if parse_input(message.text, bound=True).arguments != arguments:
            raise Conflict("original_history_source_arguments_changed")
        if not arguments.strip():
            return await self.native_menu(binding, message, locale)
        match = re.fullmatch(r"([A-Za-z0-9_-]{32})(?:[ \t]+(10|[1-9]))?", arguments.strip())
        if not match:
            raise ValueError("invalid_original_history_selection")
        saved = await self.tokens.inspect_allowed(
            match[1],
            frozenset({"transcript-menu", "transcript-older", "transcript-text"}),
            message.realm_id,
            message.author_id,
        )
        context = TranscriptContext.model_validate(saved.context)
        if (
            saved.binding_id != binding.id
            or saved.binding_revision != binding.revision
            or context.message_limit != self.message_limit
            or context.reference_sha256 != digest(reference(binding).model_dump())
            or context.contract_sha256 != self.selected(binding).contract_for(reference(binding))
            or saved.kind != "transcript-" + context.route
        ):
            raise Conflict("original_history_token_scope_changed")
        if context.route == "menu":
            if match[2] is None or not 1 <= int(match[2]) <= len(context.choices):
                raise ValueError("original_history_item_required")
            text = await self.native_text(
                binding,
                message,
                locale,
                context.model_copy(update={"render_locale": locale}),
                context.choices[int(match[2]) - 1],
                0,
            )
        else:
            if match[2] is not None:
                raise ValueError("unexpected_original_history_item")
            if context.route == "older" and context.cursor is not None:
                text = await self.native_menu(binding, message, locale, context.cursor)
            elif context.route == "text" and context.choice is not None:
                text = await self.native_text(
                    binding, message, locale, context, context.choice, context.page
                )
            else:
                raise Conflict("original_history_token_route_changed")
        await self.consume(binding, message, saved)
        return text

    async def output(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        """The newest finished OpenCode reply on the first page, in full text pages.

        Tool input/output stays out exactly as in history: only its name and status show.
        """
        if reference(binding) not in self.readers or arguments.strip():
            return await super().output(binding, message, locale, arguments)
        await self.source(binding, message, frozenset({"output"}))
        if parse_input(message.text, bound=True).arguments != arguments:
            raise Conflict("original_output_source_arguments_changed")
        _reader, page = await self.read(binding, message, None)
        newest = next(
            (
                entry
                for entry in page.entries
                if entry.kind == "assistant"
                and "completed" in entry.projection()["time"]
                and any(
                    part["type"] == "text" and part["text"].strip()
                    for part in entry.projection()["content"]
                )
            ),
            None,
        )
        if newest is None:
            return self.tr.render("output.none", locale)
        choice = TranscriptChoice(
            native_id=newest.native_id, projection_sha256=newest.projection_sha256
        )
        context = self.context(binding, "text", choice=choice, render_locale=locale)
        return await self.native_text(binding, message, locale, context, choice, 0)

    async def status(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        if reference(binding) not in self.readers:
            return await super().status(binding, message, locale)
        await self.source(binding, message, frozenset({"status", "choose"}))
        ref = reference(binding)
        reader = self.selected(binding)
        try:
            state: SessionSnapshot | None = await reader.snapshot(ref)
        except (ValueError, TimeoutError, ConnectionError):
            # The router asks here after its own live check failed. While a tool
            # runs, OpenCode's evidence can change mid-check: that is an answer
            # for `!status`, not a stale request.
            state = None
        checked = await self.source(binding, message, frozenset({"status", "choose"}))
        paused = self.tr.render("router.yes" if checked.dispatch_paused else "router.no", locale)
        if state is None or not state.reconciled:
            return self.tr.render("transcript.status_unconfirmed", locale, paused=paused)
        if state.reference != ref:
            raise Conflict("original_history_status_not_current")
        return self.tr.render(
            "transcript.live_status",
            locale,
            state=self.tr.render("status." + state.state.value, locale),
            paused=paused,
        )
