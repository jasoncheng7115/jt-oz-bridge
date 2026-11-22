"""Official-app text discovery with immutable receipts and explicit original binding."""

import asyncio
import contextlib
import json
import time
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Literal, Self, cast

from pydantic import model_validator
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.client import ZulipError, ZulipSourceUnavailable
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.catalog import CatalogProject, CatalogSession
from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel, ExecutionState
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.domain.routing import RoutedInput, RoutingRateDeferred
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection
from jt_oz_bridge.i18n import Translator, clear_locale, message_locale, save_locale
from jt_oz_bridge.presentation.commands import KNOWN, ParsedInput, is_unbound_text, parse_input
from jt_oz_bridge.presentation.markdown import code_span, literal
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.redaction import redact_json
from jt_oz_bridge.services.binding_confirmation import (
    BindingConfirmation,
    BindingPreparationDeferred,
)
from jt_oz_bridge.services.closed_menu_operations import (
    ClosedConfirmationOperations,
    ClosedMenuOperations,
)
from jt_oz_bridge.services.command_receipts import (
    READONLY_DISCOVERY_COMMANDS,
    CommandClaim,
    CommandInbox,
)
from jt_oz_bridge.services.creation_commands import CreationCommands, SavedCreationReply
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox
from jt_oz_bridge.services.discovery_shortcuts import DiscoveryShortcuts, DiscoveryShortcutService
from jt_oz_bridge.services.output_destinations import OutputDestinations
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest

# What `!stop`, `!go` and `!no` do in a topic whose new conversation is being created.
CREATION_WORDS: dict[str, Literal["pause", "resume", "cancel"]] = {
    "stop": "pause",
    "go": "resume",
    "decline": "cancel",
}


# The stop notice and standby post here (`ops/server/bridge_notice.py`); never a conversation.
STATUS_TOPIC = "Bridge 狀態"


class SavedDiscoveryReply(ControlModel):
    origin: Literal["discovery"]
    text: str
    locale: Locale
    target: DiscoveryTarget | None = None
    binding_id: str | None = None
    binding_revision: int | None = None
    shortcuts: DiscoveryShortcuts | None = None
    queued_batch_id: str | None = None
    confirmation_source: HumanMessage | None = None
    confirmed_reference: SessionRef | None = None
    confirmed_title: str | None = None
    widget: str | None = None

    @model_validator(mode="after")
    def one_target(self) -> Self:
        bound = self.binding_id is not None and self.binding_revision is not None
        if (self.binding_id is None) != (self.binding_revision is None) or (
            self.target is not None
        ) == bound:
            raise ValueError("discovery_reply_requires_exactly_one_target")
        if (
            any(
                item is not None
                for item in (
                    self.confirmation_source,
                    self.confirmed_reference,
                    self.confirmed_title,
                )
            )
            and not bound
        ):
            raise ValueError("confirmation_source_requires_bound_reply")
        return self


@dataclass(frozen=True)
class DiscoveryResult:
    text: str
    projects: tuple[str, ...] = ()
    binding: Binding | None = None
    locale: Locale | None = None
    creation: SavedCreationReply | None = None
    shortcuts: DiscoveryShortcuts | None = None
    widget: str | None = None


def label(value: str, maximum: int = 180) -> str:
    return literal(redact_json(value).value[:maximum])


class UnboundRouter:
    def __init__(
        self,
        discovery: DiscoveryService,
        reader: SourceReader,
        inbox: CommandInbox,
        creation: CreationCommands | None = None,
    ) -> None:
        if discovery.db is not inbox.db:
            raise ValueError("discovery_router_database_mismatch")
        self.discovery, self.bindings, self.db = discovery, discovery.bindings, discovery.db
        self.reader, self.inbox, self.tr = reader, inbox, Translator()
        self.tokens = TokenService(self.db, fence=inbox.fence)
        self.shortcuts = DiscoveryShortcutService(self.db, reader)
        self.destinations = OutputDestinations(discovery, reader, inbox.fence)
        self.confirmations = BindingConfirmation(discovery, self.tokens, reader)
        self._direct_tokens: dict[tuple[str, int, int, SessionRef], str] = {}
        self.closed_menus: ClosedMenuOperations | None = None
        self.closed_confirmation: ClosedConfirmationOperations | None = None
        if creation is not None and (
            creation.discovery is not discovery
            or creation.reader is not reader
            or creation.inbox is not inbox
        ):
            raise ValueError("unbound_creation_requires_original_components")
        self.creation = creation

    def configure_closed_menus(
        self, outbox: DiscoveryOutbox, *, realm_id: str, message_limit: int, topic_limit: int
    ) -> None:
        if self.closed_menus is not None:
            raise Conflict("closed_menu_composition_already_configured")
        self.closed_menus = ClosedMenuOperations(
            self, outbox, realm_id=realm_id, message_limit=message_limit, topic_limit=topic_limit
        )
        self.closed_confirmation = ClosedConfirmationOperations(
            self, outbox, realm_id=realm_id, message_limit=message_limit, topic_limit=topic_limit
        )

    def closed_operation(
        self, message: HumanMessage, parsed: ParsedInput
    ) -> ClosedMenuOperations | None:
        operation = self.closed_confirmation if parsed.command == "confirm" else self.closed_menus
        return operation if operation is not None and operation.eligible(message, parsed) else None

    async def try_closed_route(
        self, message: HumanMessage, *, recovered: bool = False
    ) -> RoutedInput | None:
        """None declines before effects; a selected operation never falls back on error."""
        parsed = parse_input(message.text)
        operation = self.closed_operation(message, parsed)
        if operation is None:
            return None
        readonly = parsed.command in READONLY_DISCOVERY_COMMANDS
        with self.tokens.planning() if readonly else nullcontext():
            return await operation.route(message, parsed, recovered=recovered)

    async def context(
        self, message: HumanMessage, scopes: tuple[CatalogProject, ...]
    ) -> dict[str, Any]:
        current_projects, audience = await self.discovery.inspect_projects(
            message, tuple(scope.scope.project_id for scope in scopes)
        )
        if current_projects != scopes:
            raise Conflict("discovery_menu_scope_changed")
        return await self.context_from_audience(message, scopes, audience)

    async def context_from_audience(
        self, message: HumanMessage, scopes: tuple[CatalogProject, ...], audience: AudienceSnapshot
    ) -> dict[str, Any]:
        # Only a just-completed scope inspection in this task supplies this
        # observation. Fresh output authorization must match it at commit.
        await self.destinations.unbound(message)
        if await self.reader.read(message.realm_id, message.message_id) != message:
            raise Conflict("discovery_menu_source_changed")
        return {
            "channel_id": message.channel_id,
            "topic": message.topic,
            "audience_hash": digest(audience.model_dump(mode="json")),
            "projects": [scope.model_dump(mode="json") for scope in scopes],
        }

    async def issue(
        self,
        kind: str,
        message: HumanMessage,
        scopes: tuple[CatalogProject, ...],
        data: dict[str, Any],
        *,
        checked_context: dict[str, Any] | None = None,
    ) -> str:
        if checked_context is not None:
            if self.tokens.active_plan is None:
                raise Conflict("catalog_context_requires_atomic_output_plan")
            self.tokens.active_plan.require_output_source(message)
        context = (
            dict(checked_context)
            if checked_context is not None
            else await self.context(message, scopes)
        )
        if context.get("projects") != [scope.model_dump(mode="json") for scope in scopes]:
            raise Conflict("catalog_context_scope_mismatch")
        context["data"] = data
        return await self.tokens.issue(kind, message.realm_id, message.author_id, context)

    async def guard(self, token: ControlToken, message: HumanMessage) -> tuple[CatalogProject, ...]:
        if token.binding_id is not None or token.binding_revision is not None:
            raise AccessDenied("discovery_token_is_not_unbound")
        raw = token.context.get("projects")
        if not isinstance(raw, list) or len(raw) > 10:
            raise Conflict("discovery_menu_scope_invalid")
        scopes = tuple(CatalogProject.model_validate(value) for value in raw)
        expected = await self.context(message, scopes)
        if any(token.context.get(key) != value for key, value in expected.items()):
            raise Conflict("discovery_token_actor_target_or_audience_changed")
        return scopes

    async def page_token(
        self,
        message: HumanMessage,
        scopes: tuple[CatalogProject, ...],
        route: str,
        data: dict[str, Any],
        *,
        checked_context: dict[str, Any] | None = None,
    ) -> str:
        return await self.issue(
            "discover-page",
            message,
            scopes,
            {"route": route, **data},
            checked_context=checked_context,
        )

    async def menu(
        self,
        message: HumanMessage,
        locale: Locale,
        title: str,
        entries: list[dict[str, Any]],
        lines: list[str],
        scopes: tuple[CatalogProject, ...],
        *,
        more: tuple[str, dict[str, Any]] | None = None,
        checked_context: dict[str, Any] | None = None,
    ) -> DiscoveryResult:
        if len(entries) > 10 or len(lines) != len(entries):
            raise ValueError("discovery_menu_bounds")
        if not entries:
            shortcut_links = DiscoveryShortcuts(inactive=True)
            body = self.tr.render("discovery.empty", locale)
            if more is not None:
                route, data = more
                token = await self.page_token(
                    message, scopes, route, data, checked_context=checked_context
                )
                shortcut_links = DiscoveryShortcuts(next_token=token, next_command=cast(Any, route))
                body += "\n\n" + self.tr.render(
                    "discovery.next", locale, command=route, token=token
                )
            return DiscoveryResult(
                body, tuple(scope.scope.project_id for scope in scopes), shortcuts=shortcut_links
            )
        # Render labels before allocating control tokens; unpreviewable strings
        # fail closed without leaking a partial native title/path.
        body = (
            self.tr.render(title, locale)
            + "\n\n"
            + "\n\n".join(f"{index}. {line}" for index, line in enumerate(lines, 1))
        )
        token = await self.issue(
            "discover-menu", message, scopes, {"items": entries}, checked_context=checked_context
        )
        choose_key = {
            "discovery.backends": "discovery.choose_backend",
            "discovery.projects": "discovery.choose_project",
            "discovery.sessions": "discovery.choose_session",
            "discovery.recent": "discovery.choose_session",
            "discovery.go": "discovery.choose_go",
            "discovery.go_plain": "discovery.choose_go",
        }.get(title, "discovery.choose")
        body += "\n\n" + (
            self.tr.render(choose_key, locale)
            if choose_key == "discovery.choose_go"
            else self.tr.render(choose_key, locale, menu_id=token, item_number=1)
        )
        shortcut_links = DiscoveryShortcuts(choose=token)
        if more is not None:
            route, data = more
            page = await self.page_token(
                message, scopes, route, data, checked_context=checked_context
            )
            shortcut_links = DiscoveryShortcuts(
                choose=token, next_token=page, next_command=cast(Any, route)
            )
            body += "\n\n" + self.tr.render("discovery.next", locale, command=route, token=page)
        return DiscoveryResult(
            body, tuple(scope.scope.project_id for scope in scopes), shortcuts=shortcut_links
        )

    async def backends(
        self, message: HumanMessage, locale: Locale, after: str | None = None
    ) -> DiscoveryResult:
        page = await self.discovery.backends(message, after=after)
        scopes, entries, lines = [], [], []
        for backend in page.items:
            projects = await self.discovery.projects(message, backend_id=backend.backend_id)
            if not projects.items:
                raise Conflict("discovery_backend_no_authorized_project")
            scopes.append(projects.items[0])
            entries.append({"kind": "backend", "id": backend.backend_id})
            lines.append(label(backend.backend_id) + " — " + label(backend.version))
        return await self.menu(
            message,
            locale,
            "discovery.backends",
            entries,
            lines,
            tuple(scopes),
            more=("backends", {"after": page.next_after}) if page.next_after else None,
        )

    async def projects(
        self,
        message: HumanMessage,
        locale: Locale,
        *,
        backend: str | None = None,
        after: str | None = None,
    ) -> DiscoveryResult:
        page, audience = await self.discovery._projects_observed(
            message, backend_id=backend, after=after
        )
        entries, lines = [], []
        batch_context = (
            await self.context_from_audience(message, page.items, audience)
            if self.tokens.active_plan is not None and page.items
            else None
        )
        for project in page.items:
            selected = await self.issue(
                "discover-project",
                message,
                (project,),
                {"project": project.scope.project_id},
                checked_context={**batch_context, "projects": [project.model_dump(mode="json")]}
                if batch_context is not None
                else None,
            )
            entries.append({"kind": "project", "id": project.scope.project_id})
            lines.append(
                label(project.scope.backend_id)
                + " / "
                + label(project.scope.project_id)
                + " — "
                + label(project.scope.canonical_directory)
                + "\n\n```spoiler "
                + self.tr.render("menu.advanced", locale)
                + "\n"
                + code_span("!oz sessions " + selected)
                + "\n```"
            )
        return await self.menu(
            message,
            locale,
            "discovery.projects",
            entries,
            lines,
            page.items,
            checked_context=batch_context,
            more=("projects", {"backend": backend, "after": page.next_after})
            if page.next_after
            else None,
        )

    async def sessions(
        self,
        message: HumanMessage,
        locale: Locale,
        project_id: str,
        *,
        search: str = "",
        cursor: str | None = None,
    ) -> DiscoveryResult:
        page = await self.discovery.sessions(message, project_id, search=search, cursor=cursor)
        project, current_audience = await self.discovery.project(message, project_id)
        batch_context = (
            await self.context_from_audience(message, (project,), current_audience)
            if self.tokens.active_plan is not None
            else None
        )
        entries, lines = [], []
        for item in page.items:
            data: dict[str, Any] = {"reference": item.reference.model_dump(mode="json")}
            if item.selection is not None:
                data["selection"] = item.selection.model_dump(mode="json")
            selected = await self.issue(
                "discover-session",
                message,
                (project,),
                data,
                checked_context=batch_context,
            )
            entries.append({"kind": "session", **data})
            lines.append(
                label(item.title)
                + " — "
                + label(item.reference.upstream_session_id)
                + " — "
                + self.tr.render("status." + item.state.value, locale)
                + (" / " + self.tr.render("discovery.archived", locale) if item.archived else "")
                + "\n\n```spoiler "
                + self.tr.render("menu.advanced", locale)
                + "\n"
                + code_span("!oz bind " + selected)
                + "\n```"
            )
        return await self.menu(
            message,
            locale,
            "discovery.sessions",
            entries,
            lines,
            (project,),
            checked_context=batch_context,
            more=("sessions", {"project": project_id, "search": search, "cursor": page.next_cursor})
            if page.next_cursor
            else None,
        )

    async def recent(self, message: HumanMessage, locale: Locale) -> DiscoveryResult:
        rows = await self.discovery.recent(message)
        scopes: dict[str, CatalogProject] = {}
        entries, lines = [], []
        for row in rows:
            project, _audience = await self.discovery.project(message, row.reference.project_id)
            scopes[project.scope.project_id] = project
            data: dict[str, Any] = {"reference": row.reference.model_dump(mode="json")}
            adoption = self.discovery.adoption
            if adoption is not None and row.reference.project_id in adoption.factories:
                data["selection"] = (await adoption.selection(message, row.reference)).model_dump(
                    mode="json"
                )
            selected = await self.issue(
                "discover-session",
                message,
                (project,),
                data,
            )
            entries.append({"kind": "session", **data})
            lines.append(
                label(row.title_at_binding)
                + " — "
                + label(row.reference.upstream_session_id)
                + "\n\n```spoiler "
                + self.tr.render("menu.advanced", locale)
                + "\n"
                + code_span("!oz bind " + selected)
                + "\n```"
            )
        return await self.menu(
            message, locale, "discovery.recent", entries, lines, tuple(scopes.values())
        )

    async def go(self, message: HumanMessage, locale: Locale, query: str) -> DiscoveryResult:
        """Every authorized session in one list; choosing connects immediately."""
        plain = parse_input(message.text).kind == "ignore"
        if self.creation is not None:
            with contextlib.suppress(AccessDenied):
                reserved = await self.creation.reserved_here(message, locale)
                if reserved is not None:
                    return DiscoveryResult(reserved.text, reserved.projects)
        rows = []
        with self._pre_binding():
            page, _audience = await self.discovery._projects_observed(message)
            for project in page.items:
                listed = await self.discovery.sessions(
                    message, project.scope.project_id, search=query
                )
                rows += [(item, project) for item in listed.items if not item.archived]
        rows.sort(key=lambda row: row[0].updated_at or 0.0, reverse=True)
        async with self.db.sessions() as session:
            taken = set(
                (
                    await session.scalars(
                        select(Binding.session_id).where(
                            Binding.realm_id == message.realm_id, Binding.state == "active"
                        )
                    )
                ).all()
            )
        elsewhere = [row for row in rows if row[0].reference.upstream_session_id in taken]
        # Each project that may create a Root also offers a fresh conversation.
        offers: list[tuple[CatalogProject, str]] = []
        if self.creation is not None and not query:
            for project in page.items:
                if project.scope.project_id in self.creation.journal.projects:
                    with contextlib.suppress(AccessDenied):
                        offers.append(
                            (
                                project,
                                await self.creation.journal.offer(
                                    project.scope.project_id, message
                                ),
                            )
                        )
        offers = offers[:10]
        free = [row for row in rows if row[0].reference.upstream_session_id not in taken][
            : 10 - len(offers)
        ]
        if query and len(free) == 1:
            item = free[0][0]
            return await self.selected(
                message, locale, item.reference, item.selection, connect_now=True, title=item.title
            )
        # The plain message that opened this menu goes to whichever conversation is chosen.
        carried = {"prompt": message.model_dump(mode="json")} if plain else {}
        entries, lines = [], []
        buttons: list[dict[str, str]] = []
        for project, offer in offers:
            entries.append(
                {"kind": "new", "project": project.scope.project_id, "offer": offer, **carried}
            )
            lines.append(
                self.tr.render("discovery.go_new", locale, project=label(project.scope.project_id))
            )
            buttons.append(
                {
                    "type": "multiple_choice",
                    "short_name": str(len(buttons) + 1),
                    "long_name": self.tr.render(
                        "discovery.go_new_button", locale, project=project.scope.project_id
                    ),
                    "reply": f"!{len(buttons) + 1}",
                }
            )
        for item, project in free:
            data: dict[str, Any] = {
                "reference": item.reference.model_dump(mode="json"),
                "title": item.title,
            }
            if item.selection is not None:
                data["selection"] = item.selection.model_dump(mode="json")
            entries.append({"kind": "session", **data, **carried})
            lines.append(self._choice_line(item, project.scope.project_id, locale))
            buttons.append(
                {
                    "type": "multiple_choice",
                    "short_name": str(len(buttons) + 1),
                    "long_name": self._button_label(item, project.scope.project_id, locale),
                    "reply": f"!{len(buttons) + 1}",
                }
            )
        scopes = tuple(
            {
                project.scope.project_id: project
                for project in (*(row[0] for row in offers), *(row[1] for row in free))
            }.values()
        )
        note = (
            "\n\n"
            + self.tr.render(
                "discovery.go_elsewhere",
                locale,
                titles="、".join(label(row[0].title) for row in elsewhere[:5]),
            )
            if elsewhere
            else ""
        )
        if not entries:
            return DiscoveryResult(
                self.tr.render("discovery.go_none", locale) + note,
                tuple(project.scope.project_id for project in page.items),
                shortcuts=DiscoveryShortcuts(inactive=True),
            )
        result = await self.menu(
            message,
            locale,
            "discovery.go_plain" if plain else "discovery.go",
            entries,
            lines,
            scopes,
        )
        # Web clients replace the message text with this plain-text widget.
        heading = [
            self.tr.render("discovery.go_plain" if plain else "discovery.go", locale),
            self.tr.render("discovery.go_buttons", locale),
        ]
        if elsewhere:
            titles = "、".join(row[0].title.replace("\n", " ")[:60] for row in elsewhere[:5])
            heading.append(self.tr.render("discovery.go_elsewhere", locale, titles=titles))
        widget = json.dumps(
            {
                "widget_type": "zform",
                "extra_data": {
                    "type": "choices",
                    "heading": " ".join(heading),
                    "choices": buttons,
                },
            },
            ensure_ascii=False,
        )
        return replace(result, text=result.text + note, widget=widget)

    def _choice_line(self, item: CatalogSession, project: str, locale: Locale) -> str:
        """One readable row: name first, then only the facts that help choose."""
        facts = [label(project)]
        if item.state not in {ExecutionState.UNKNOWN, ExecutionState.IDLE}:
            facts.append(self.tr.render("status." + item.state.value, locale))
        if item.updated_at is not None:
            moment = datetime.fromtimestamp(item.updated_at, UTC).isoformat(timespec="seconds")
            facts.append(self.tr.render("discovery.go_updated", locale, time=f"<time:{moment}>"))
        return "**" + label(item.title) + "**\n   " + " · ".join(facts)

    def _button_label(self, item: CatalogSession, project: str, locale: Locale) -> str:
        """Web clients show the widget instead of the message text, so it carries the facts."""
        facts = [item.title.replace("\n", " ")[:60], project]
        if item.updated_at is not None:
            minutes = max(0, int(time.time() - item.updated_at) // 60)
            if minutes < 60:
                facts.append(self.tr.render("discovery.go_age_minutes", locale, count=minutes))
            elif minutes < 1440:
                facts.append(self.tr.render("discovery.go_age_hours", locale, count=minutes // 60))
            else:
                facts.append(self.tr.render("discovery.go_age_days", locale, count=minutes // 1440))
        return " · ".join(facts)

    async def _choice_connects(self, message: HumanMessage, parsed: ParsedInput) -> bool:
        """Effect-free peek: a bare number on a visible session row binds at once."""
        if parsed.kind != "command" or parsed.command != "choose" or not parsed.arguments.isdigit():
            return False
        try:
            links = (await self.shortcuts.observation_sources(message)).links
            if links.choose is None:
                return False
            token = await self.tokens.inspect(
                links.choose, "discover-menu", message.realm_id, message.author_id
            )
            items = token.context["data"]["items"]
            item = items[int(parsed.arguments) - 1]
            return bool(item["kind"] == "session" and item.get("selection") is None)
        except (AccessDenied, Conflict, ValueError, LookupError, TypeError):
            return False

    async def selected(
        self,
        message: HumanMessage,
        locale: Locale,
        reference: SessionRef,
        selection: ExistingSessionSelection | None = None,
        *,
        connect_now: bool = False,
        title: str | None = None,
    ) -> DiscoveryResult:
        # A deferred retry must not spend its whole request window preparing again,
        # or one connection larger than the window could never finish. Confirm still
        # re-reads the source, audience and target, so the saved token grants nothing.
        direct = connect_now and selection is None
        key = (message.realm_id, message.message_id, message.revision, reference)
        opaque = self._direct_tokens.get(key) if direct else None
        preview = None
        if opaque is None:
            with self._pre_binding():
                preview = await self.confirmations.prepare(
                    message, reference, locale, selection=selection
                )
            opaque = preview.token
        # Adoption keeps its visible preview: that proof spans two original observations.
        if direct and opaque:
            self._direct_tokens[key] = opaque
            while len(self._direct_tokens) > 64:
                self._direct_tokens.pop(next(iter(self._direct_tokens)))
            try:
                binding = await self.confirmations.confirm(message, opaque, locale, direct=True)
            except BindingPreparationDeferred:
                raise
            except BaseException:
                self._direct_tokens.pop(key, None)
                raise
            self._direct_tokens.pop(key, None)
            return DiscoveryResult(
                self.tr.render(
                    "discovery.connected",
                    locale,
                    title=label(title or binding.title),
                    project=label(reference.project_id),
                ),
                binding=binding,
            )
        assert preview is not None
        return DiscoveryResult(
            preview.text,
            (reference.project_id,) if preview.token else (),
            shortcuts=DiscoveryShortcuts(confirm=preview.token) if preview.token else None,
        )

    async def carry_prompt(
        self, binding: Binding, raw: object
    ) -> Literal["sent", "changed", "failed"]:
        """Queue the menu's opening message in the new connection, if still unedited."""
        try:
            prompt = HumanMessage.model_validate(raw)
            if (
                (prompt.realm_id, prompt.channel_id, prompt.topic)
                != (binding.realm_id, binding.channel_id, binding.topic)
                or prompt.revision != 0
                or await self.reader.read(prompt.realm_id, prompt.message_id) != prompt
            ):
                return "changed"
            await QueueService(self.bindings, fence=self.inbox.fence).receive(binding.id, prompt)
        except ZulipSourceUnavailable:
            return "changed"  # Deleted since: nothing to send, nothing to report.
        except (AccessDenied, Conflict, ValueError, ZulipError):
            return "failed"  # Not queued; the person is told to send it again.
        return "sent"

    @contextlib.contextmanager
    def _pre_binding(self) -> Iterator[None]:
        """Without a token plan only a direct connection gets here, before any Binding write."""
        try:
            yield
        except BindingPreparationDeferred:
            raise
        except DeliveryRateLimited as error:
            if self.tokens.active_plan is not None:
                raise
            raise BindingPreparationDeferred(error.retry_after) from None

    async def execute(
        self,
        message: HumanMessage,
        parsed: ParsedInput,
        locale: Locale,
        claim: CommandClaim | None = None,
    ) -> DiscoveryResult:
        command, args = parsed.command, parsed.arguments
        if parsed.kind == "invalid" and parsed.command == "send":
            return DiscoveryResult(self.tr.render("discovery.bind_first", locale))
        if parsed.kind in {"unknown", "invalid"}:
            return DiscoveryResult(self.tr.render("router.invalid", locale))
        if (
            command in CREATION_WORDS
            and not args.strip()
            and self.creation is not None
            # Typed, not plain text that only shows the menu.
            and parse_input(message.text).command == command
        ):
            if claim is None:
                raise Conflict("creation_requires_owned_command_claim")
            # `!stop`/`!go`/`!no` act on a new conversation still being created here.
            word = await self.creation.word(
                message, locale, claim, command, CREATION_WORDS[command]
            )
            if word is not None:
                return DiscoveryResult(word.text, word.projects, creation=word.receipt)
        if command in {"stop", "decline"}:
            return DiscoveryResult(self.tr.render("discovery.bind_first", locale))
        if command == "new" and self.creation is not None:
            if claim is None:
                raise Conflict("creation_requires_owned_command_claim")
            result = await self.creation.command(message, args, locale, claim)
            return DiscoveryResult(result.text, result.projects, creation=result.receipt)
        if command in {"help", "menu", "settings"}:
            if command == "help" and args.strip() == "new" and self.creation is not None:
                return DiscoveryResult(
                    self.tr.render("creation.menu", locale)
                    + "\n\n"
                    + self.tr.render("discovery.new_hint", locale)
                )
            if command == "help" and args.strip() in KNOWN:
                return DiscoveryResult(self.tr.render("discovery.start", locale))
            if args.strip():
                raise ValueError("unexpected_discovery_arguments")
            return DiscoveryResult(
                self.tr.render("discovery.start", locale)
                + (
                    "\n\n" + self.tr.render("discovery.new_hint", locale)
                    if self.creation is not None
                    else ""
                )
            )
        if command == "lang":
            choice = args.strip()
            if choice not in {"en", "zh-TW", "auto"}:
                raise ValueError("invalid_locale")
            await self.context(message, ())
            principal = f"user:{message.realm_id}:{message.author_id}"
            if choice == "auto":
                await clear_locale(self.db, principal, fence=self.inbox.fence)
                selected = await message_locale(self.db, self.reader, message)
            else:
                selected = cast(Locale, choice)
                await save_locale(self.db, principal, selected, fence=self.inbox.fence)
            return DiscoveryResult(
                self.tr.render(
                    "settings.personal_automatic"
                    if choice == "auto"
                    else "settings.personal_saved",
                    selected,
                    locale=selected,
                )
                + "\n\n"
                + self.tr.render("settings.agent_language_unchanged", selected),
                locale=selected,
            )
        if command == "go":
            return await self.go(message, locale, args.strip())
        if command == "confirm":
            binding = await self.confirmations.confirm(message, args)
            return DiscoveryResult(
                self.tr.render("discovery.bound", locale),
                binding=binding,
            )
        if command == "bind":
            token = await self.tokens.inspect(
                args, "discover-session", message.realm_id, message.author_id
            )
            await self.guard(token, message)
            await self.tokens.consume(args, "discover-session", message.realm_id, message.author_id)
            return await self.selected(
                message,
                locale,
                SessionRef.model_validate(token.context["data"]["reference"]),
                ExistingSessionSelection.model_validate(token.context["data"]["selection"])
                if token.context["data"].get("selection") is not None
                else None,
            )
        if command == "next":
            if args.strip():
                raise ValueError("unexpected_shortcut_arguments")
            links = await self.shortcuts.latest(message)
            if links.next_token is None or links.next_command is None:
                raise Conflict("shortcut_current_reply_has_no_next_page")
            return await self.execute(
                message, ParsedInput("command", links.next_command, links.next_token), locale, claim
            )
        if command == "choose":
            parts = args.split()
            shortcut_number = len(parts) == 1
            if (
                len(parts) == 1
                and parts[0].isascii()
                and parts[0].isdigit()
                and 1 <= len(parts[0]) <= 2
            ):
                with self._pre_binding():
                    parts = [await self.shortcuts.token(message, "choose"), parts[0]]
            if (
                len(parts) != 2
                or not parts[1].isascii()
                or not parts[1].isdigit()
                or len(parts[1]) > 2
            ):
                raise ValueError("invalid_discovery_choice")
            token = await self.tokens.inspect(
                parts[0], "discover-menu", message.realm_id, message.author_id
            )
            with self._pre_binding():
                await self.guard(token, message)
            items = token.context["data"]["items"]
            if (
                not isinstance(items, list)
                or not 1 <= len(items) <= 10
                or not 1 <= int(parts[1]) <= len(items)
            ):
                raise Conflict("discovery_choice_unavailable")
            item = items[int(parts[1]) - 1]
            if item["kind"] == "new":
                if not shortcut_number or self.creation is None or claim is None:
                    raise Conflict("creation_menu_row_requires_short_choice")
                prompt = item.get("prompt")
                created = await self.creation.choose(
                    message,
                    locale,
                    claim,
                    item["offer"],
                    int(parts[1]),
                    HumanMessage.model_validate(prompt) if prompt is not None else None,
                )
                with contextlib.suppress(Conflict):
                    await self.tokens.consume(
                        parts[0], "discover-menu", message.realm_id, message.author_id
                    )
                return DiscoveryResult(created.text, created.projects, creation=created.receipt)
            if shortcut_number and item["kind"] == "session" and item.get("selection") is None:
                # A rate deferral before the Binding must retry this same menu row,
                # so the row is spent only once the Binding exists.
                connected = await self.selected(
                    message,
                    locale,
                    SessionRef.model_validate(item["reference"]),
                    connect_now=True,
                    title=item.get("title"),
                )
                with contextlib.suppress(Conflict):
                    await self.tokens.consume(
                        parts[0], "discover-menu", message.realm_id, message.author_id
                    )
                if item.get("prompt") is not None and connected.binding is not None:
                    carried = await self.carry_prompt(connected.binding, item["prompt"])
                    if carried != "changed":
                        connected = replace(
                            connected,
                            text=connected.text
                            + "\n\n"
                            + self.tr.render(
                                "discovery.prompt_sent"
                                if carried == "sent"
                                else "discovery.prompt_failed",
                                locale,
                            ),
                        )
                return connected
            await self.tokens.consume(
                parts[0], "discover-menu", message.realm_id, message.author_id
            )
            if item["kind"] == "backend":
                return await self.projects(message, locale, backend=item["id"])
            if item["kind"] == "project":
                return await self.sessions(message, locale, item["id"])
            if item["kind"] == "session":
                return await self.selected(
                    message,
                    locale,
                    SessionRef.model_validate(item["reference"]),
                    ExistingSessionSelection.model_validate(item["selection"])
                    if item.get("selection") is not None
                    else None,
                )
            raise Conflict("discovery_choice_kind_unknown")
        if command == "sessions" and args == "recent":
            return await self.recent(message, locale)
        if command in {"backends", "projects", "sessions"}:
            if not args:
                return (
                    await self.backends(message, locale)
                    if command == "backends"
                    else await self.projects(message, locale)
                )
            opaque, separator, tail = args.partition(" -- ")
            kinds = (
                frozenset({"discover-page", "discover-project"})
                if command == "sessions"
                else frozenset({"discover-page"})
            )
            token = await self.tokens.inspect_allowed(
                opaque, kinds, message.realm_id, message.author_id
            )
            await self.guard(token, message)
            data = token.context["data"]
            if token.kind == "discover-project":
                await self.tokens.consume(opaque, token.kind, message.realm_id, message.author_id)
                return await self.sessions(
                    message, locale, data["project"], search=tail if separator else ""
                )
            if separator or data.get("route") != command:
                raise Conflict("discovery_page_route_changed")
            await self.tokens.consume(opaque, token.kind, message.realm_id, message.author_id)
            if command == "backends":
                return await self.backends(message, locale, data.get("after"))
            if command == "projects":
                return await self.projects(
                    message, locale, backend=data.get("backend"), after=data.get("after")
                )
            return await self.sessions(
                message, locale, data["project"], search=data["search"], cursor=data["cursor"]
            )
        return DiscoveryResult(self.tr.render("discovery.bind_first", locale))

    async def current_bound(self, identity: str, revision: int, message: HumanMessage) -> Binding:
        binding = await self.bindings.get(identity, message.realm_id, message.author_id)
        if (binding.revision, binding.channel_id, binding.topic) != (
            revision,
            message.channel_id,
            message.topic,
        ):
            raise Conflict("discovery_binding_ack_changed")
        return binding

    async def notice(
        self,
        message: HumanMessage,
        locale: Locale,
        text_key: str,
        key: str,
        *,
        state: Literal["reply", "busy", "held", "ambiguous"] = "reply",
        binding: Binding | None = None,
    ) -> RoutedInput:
        text = self.tr.render(text_key, locale)
        if binding is not None:
            await self.current_bound(binding.id, binding.revision, message)
            return RoutedInput(state, binding.id, binding.revision, text, key, locale=locale)
        if state == "busy":
            return RoutedInput("busy", text=text, locale=locale)
        cached = await self.destinations.cached(DiscoveryOutbox.scope_key(key, message.realm_id))
        target = cached if cached is not None else await self.destinations.prepare(message, ())
        if target.source != message:
            raise Conflict("discovery_notice_source_changed")
        return RoutedInput(
            state, text=text, delivery_key=key, locale=locale, discovery_target=target
        )

    async def route(
        self,
        event: HumanMessage,
        *,
        recovered: bool = False,
        current_binding: Binding | None = None,
    ) -> RoutedInput:
        parsed = parse_input(event.text)
        status_topic = current_binding is None and event.topic == STATUS_TOPIC
        connects = (
            current_binding is None
            and not status_topic
            and await self._choice_connects(event, parsed)
        )
        readonly = (
            parsed.kind == "command"
            and parsed.command in READONLY_DISCOVERY_COMMANDS
            and not connects
        )
        if current_binding is None and not connects and not status_topic:
            closed = await self.try_closed_route(event, recovered=recovered)
            if closed is not None:
                return closed
        with self.tokens.planning() if readonly else nullcontext():
            try:
                return await self._route(
                    event, recovered=recovered, current_binding=current_binding
                )
            except DeliveryRateLimited as error:
                # No new attempt has begun, or its immutable result was already
                # committed. Retry output/current reads, never repeat a mutation.
                receipt = await self.inbox.find(event.realm_id, event.message_id)
                if receipt is None or receipt.state in {"completed", "deferred"}:
                    raise RoutingRateDeferred(error.retry_after) from None
                raise

    async def _route(
        self,
        event: HumanMessage,
        *,
        recovered: bool = False,
        current_binding: Binding | None = None,
    ) -> RoutedInput:
        if (
            event.is_bot
            or event.deleted
            or await self.reader.read(event.realm_id, event.message_id) != event
        ):
            return RoutedInput("ignore")
        try:
            await self.discovery.audience(event, allow_edited_static=True)
        except (AccessDenied, Conflict):
            return RoutedInput("ignore")
        parsed = parse_input(event.text)
        previous = await self.inbox.find(event.realm_id, event.message_id)
        locale = await message_locale(self.db, self.reader, event)
        if current_binding is None and event.topic == STATUS_TOPIC:
            # Answering proves Bridge runs; offering a conversation menu here would
            # connect the notice topic itself.
            return await self.notice(
                event,
                locale,
                "router.status_topic",
                f"status-topic:{event.realm_id}:{event.message_id}:{event.revision}",
            )
        plain_menu = (
            parsed.kind == "ignore"
            and current_binding is None
            and not recovered
            and event.revision == 0
            and is_unbound_text(event.text)
            and (previous is None or previous.command == "go")
        )
        if plain_menu:
            parsed = ParsedInput("command", "go")
        if parsed.kind == "ignore":
            if previous is None:
                return RoutedInput("ignore")
            return await self.notice(
                event,
                locale,
                "router.changed",
                f"command-state:{previous.id}:changed:{event.revision}",
                binding=current_binding,
            )
        command = "unknown" if parsed.kind == "unknown" else parsed.command
        claim = await self.inbox.claim(
            event,
            command,
            recovered=recovered or event.revision > 0,
            unbound_literal_control=True,
            unbound_plain_menu=plain_menu,
        )
        if claim.status == "replay":
            if claim.response.get("origin") == "creation":
                if self.creation is None:
                    raise Conflict("creation_receipt_runtime_not_enrolled")
                saved_creation = SavedCreationReply.model_validate(claim.response)
                await self.creation.replay(saved_creation, event)
                return RoutedInput("ignore", action_id=saved_creation.action_id)
            saved = SavedDiscoveryReply.model_validate(claim.response)
            if saved.binding_id is not None and saved.binding_revision is not None:
                await self.current_bound(saved.binding_id, saved.binding_revision, event)
                return RoutedInput(
                    "reply",
                    saved.binding_id,
                    saved.binding_revision,
                    saved.text,
                    "command:" + claim.id,
                    locale=saved.locale,
                )
            if saved.target is None or saved.target.source != event:
                raise Conflict("discovery_cached_reply_target_missing_or_source_changed")
            await self.destinations.authorize(saved.target)
            return RoutedInput(
                "reply",
                text=saved.text,
                delivery_key="command:" + claim.id,
                locale=saved.locale,
                discovery_target=saved.target,
                widget=saved.widget,
            )
        if claim.status != "claimed":
            state = claim.status if claim.status != "changed" else "reply"
            return await self.notice(
                event,
                locale,
                "router." + claim.status,
                "command-state:" + claim.id + ":" + claim.status + ":" + str(event.revision),
                state=state,
                binding=current_binding,
            )
        try:
            try:
                result = await self.execute(event, parsed, locale, claim)
            except DeliveryRateLimited:
                # Scheduling refusals are ValueError subclasses. Preserve the
                # typed pre-write boundary or the unknown-effect hold below;
                # never turn a throttle into a stale menu reply.
                raise
            except AccessDenied:
                result = DiscoveryResult(self.tr.render("permission.denied", locale))
            except (Conflict, ValueError):
                result = DiscoveryResult(self.tr.render("router.stale", locale))
            reply_locale = result.locale or locale
            if result.creation is not None:
                # No stale unbound ACK can race the new active Binding. The
                # worker's completed activation owns the canonical notice.
                await self.inbox.finish(claim, result.creation.model_dump(mode="json"))
                return RoutedInput(
                    "ignore", action_id=result.creation.action_id, locale=result.creation.locale
                )
            if result.binding is not None:
                binding = result.binding
                saved = SavedDiscoveryReply(
                    origin="discovery",
                    text=result.text,
                    locale=reply_locale,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                )
                # The binding transaction has finished. Persist that result
                # before another remote check can defer: replay must not bind again.
                await self.inbox.finish(claim, saved.model_dump(mode="json", exclude_none=True))
                binding = await self.current_bound(binding.id, binding.revision, event)
                routed = RoutedInput(
                    "reply",
                    binding.id,
                    binding.revision,
                    result.text,
                    "command:" + claim.id,
                    locale=reply_locale,
                )
            else:
                with self._pre_binding() if command == "go" else nullcontext():
                    target = await self.destinations.prepare(event, result.projects)
                saved = SavedDiscoveryReply(
                    origin="discovery",
                    text=result.text,
                    locale=reply_locale,
                    target=target,
                    shortcuts=result.shortcuts,
                    widget=result.widget,
                )
                routed = RoutedInput(
                    "reply",
                    text=result.text,
                    delivery_key="command:" + claim.id,
                    locale=reply_locale,
                    discovery_target=target,
                    widget=result.widget,
                )
            if result.binding is None:
                plan = self.tokens.active_plan

                async def commit_tokens(session: AsyncSession) -> None:
                    assert plan is not None and saved.target is not None
                    if not await session.scalar(
                        select(and_(*self.destinations.guards(saved.target)))
                    ):
                        raise AccessDenied("catalog_output_local_authority_changed")
                    await plan.commit(session, target=saved.target)

                await self.inbox.finish(
                    claim,
                    saved.model_dump(mode="json", exclude_none=True),
                    commit=commit_tokens if plan is not None else None,
                )
            return routed
        except BaseException as error:
            plan = self.tokens.active_plan
            if isinstance(error, BindingPreparationDeferred) and command in {
                "confirm",
                "choose",
                "go",
            }:
                # A dedicated pre-write signal, not a guess based on empty
                # output, permits fresh reads without repeating a binding.
                await asyncio.shield(self.inbox.defer_confirmation(claim))
                raise RoutingRateDeferred(error.retry_after) from None
            if isinstance(error, DeliveryRateLimited) and plan is not None and not plan.committed:
                # Every catalog token write/consume was only staged in this task.
                # Discard the plan and retain an explicit safe retry receipt.
                await asyncio.shield(self.inbox.defer_catalog(claim))
                raise RoutingRateDeferred(error.retry_after) from None
            try:
                await asyncio.shield(self.inbox.abandon(claim))
            except (Conflict, asyncio.CancelledError):
                pass
            raise
