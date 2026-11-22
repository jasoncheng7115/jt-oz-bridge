"""Closed read-only menu production; observed data never authorizes future delivery."""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.client import ZulipError
from jt_oz_bridge.adapters.zulip.scope import ZulipSourceReader
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.catalog import CatalogProject
from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE, DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.domain.routing import RoutedInput, RoutingRateDeferred
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection
from jt_oz_bridge.i18n import message_locale
from jt_oz_bridge.presentation.commands import ParsedInput
from jt_oz_bridge.presentation.markdown import MobileMarkdown, code_span
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_confirmation import ObservedBindingConfirmation
from jt_oz_bridge.services.command_receipts import CommandClaim
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox
from jt_oz_bridge.services.discovery_shortcuts import DiscoveryShortcuts
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Grant

if TYPE_CHECKING:
    from jt_oz_bridge.services.session_adoption import ObservedOriginalSelection
    from jt_oz_bridge.services.unbound_router import DiscoveryResult, UnboundRouter


@dataclass(frozen=True)
class _PreparedMenu:
    claim: CommandClaim
    result: "DiscoveryResult"
    projects: tuple[CatalogProject, ...]
    pages: tuple[str, ...]
    operate: tuple[str, ...] = ()
    require_current: Callable[[], None] | None = None
    adoption_stage: "ObservedOriginalSelection | None" = None


class ClosedMenuOperations:
    """Explicit composition of one original-source observer and one SQL commit."""

    def __init__(
        self,
        owner: "UnboundRouter",
        outbox: DiscoveryOutbox,
        *,
        realm_id: str,
        message_limit: int,
        topic_limit: int,
    ) -> None:
        if (
            not isinstance(owner.reader, ZulipSourceReader)
            or outbox.db is not owner.db
            or outbox.destinations.fence != owner.inbox.fence
            or outbox.destinations.discovery is not owner.discovery
            or outbox.destinations.reader is not owner.reader
            or realm_id != owner.reader.scope.enrolled.realm_id
            or outbox.bot_user_id != owner.reader.scope.enrolled.bot_user_id
            or type(message_limit) is not int
            or message_limit < 173
            or type(topic_limit) is not int
            or topic_limit < 1
        ):
            raise ValueError("closed_menu_requires_exact_source_outbox_and_limits")
        self.owner, self.outbox = owner, outbox
        self.reader = owner.reader
        self.realm_id, self.message_limit, self.topic_limit = realm_id, message_limit, topic_limit
        self._guard: object | None = None

    def eligible(self, message: HumanMessage, parsed: ParsedInput) -> bool:
        if (
            parsed.kind != "command"
            or message.realm_id != self.realm_id
            or message.is_bot
            or message.deleted
            or message.revision != 0
            or not (
                parsed.command == "projects"
                and not parsed.arguments
                or parsed.command == "choose"
                and parsed.arguments.isascii()
                and parsed.arguments.isdigit()
                and 1 <= len(parsed.arguments) <= 2
            )
        ):
            return False
        guard = self.reader.scope.client.verify_identity
        if self._guard is None:
            if not callable(getattr(type(guard), "scope_reads", None)):
                return False  # Existing unqualified standalone fixtures retain their API.
            self._guard = guard
        return True

    @staticmethod
    def context(
        message: HumanMessage, projects: tuple[CatalogProject, ...], audience: AudienceSnapshot
    ) -> dict[str, Any]:
        return {
            "channel_id": message.channel_id,
            "topic": message.topic,
            "audience_hash": digest(audience.model_dump(mode="json")),
            "projects": [project.model_dump(mode="json") for project in projects],
        }

    async def _guard_menu(
        self, message: HumanMessage, opaque: str, audience: AudienceSnapshot
    ) -> tuple[ControlToken, tuple[CatalogProject, ...]]:
        owner = self.owner
        token = await owner.tokens.inspect(
            opaque, "discover-menu", message.realm_id, message.author_id
        )
        if token.binding_id is not None or token.binding_revision is not None:
            raise AccessDenied("closed_menu_token_is_bound")
        raw = token.context.get("projects")
        if not isinstance(raw, list) or len(raw) > 10:
            raise Conflict("closed_menu_token_scope_invalid")
        projects = tuple(CatalogProject.model_validate(item) for item in raw)
        for project in projects:
            if (
                await owner.discovery._project_in_audience(
                    message, project.scope.project_id, audience
                )
                != project
            ):
                raise Conflict("closed_menu_token_project_changed")
        context = self.context(message, projects, audience)
        if any(token.context.get(key) != value for key, value in context.items()):
            raise Conflict("closed_menu_token_audience_changed")
        return token, projects

    async def _projects(
        self, message: HumanMessage, audience: AudienceSnapshot, locale: Locale
    ) -> tuple["DiscoveryResult", tuple[CatalogProject, ...]]:
        from jt_oz_bridge.services.unbound_router import label

        owner = self.owner
        page = await owner.discovery._projects_in_operation(message, audience)
        projects = page.items
        context = self.context(message, projects, audience)
        entries, lines = [], []
        for project in projects:
            selected = await owner.issue(
                "discover-project",
                message,
                (project,),
                {"project": project.scope.project_id},
                checked_context={**context, "projects": [project.model_dump(mode="json")]},
            )
            entries.append({"kind": "project", "id": project.scope.project_id})
            lines.append(
                label(project.scope.backend_id)
                + " / "
                + label(project.scope.project_id)
                + " — "
                + label(project.scope.canonical_directory)
                + "\n\n```spoiler "
                + owner.tr.render("menu.advanced", locale)
                + "\n"
                + code_span("!oz sessions " + selected)
                + "\n```"
            )
        result = await owner.menu(
            message,
            locale,
            "discovery.projects",
            entries,
            lines,
            projects,
            checked_context=context,
            more=("projects", {"backend": None, "after": page.next_after})
            if page.next_after
            else None,
        )
        return result, projects

    async def _sessions(
        self, message: HumanMessage, identity: str, audience: AudienceSnapshot, locale: Locale
    ) -> tuple["DiscoveryResult", tuple[CatalogProject, ...]]:
        from jt_oz_bridge.services.unbound_router import label

        owner = self.owner
        page, project = await owner.discovery._sessions_in_operation(message, identity, audience)
        projects = (project,)
        context = self.context(message, projects, audience)
        entries, lines = [], []
        for item in page.items:
            data: dict[str, Any] = {"reference": item.reference.model_dump(mode="json")}
            if item.selection is not None:
                data["selection"] = item.selection.model_dump(mode="json")
            selected = await owner.issue(
                "discover-session",
                message,
                projects,
                data,
                checked_context=context,
            )
            entries.append({"kind": "session", **data})
            lines.append(
                label(item.title)
                + " — "
                + label(item.reference.upstream_session_id)
                + " — "
                + owner.tr.render("status." + item.state.value, locale)
                + (" / " + owner.tr.render("discovery.archived", locale) if item.archived else "")
                + "\n\n```spoiler "
                + owner.tr.render("menu.advanced", locale)
                + "\n"
                + code_span("!oz bind " + selected)
                + "\n```"
            )
        result = await owner.menu(
            message,
            locale,
            "discovery.sessions",
            entries,
            lines,
            projects,
            checked_context=context,
            more=("sessions", {"project": identity, "search": "", "cursor": page.next_cursor})
            if page.next_cursor
            else None,
        )
        return result, projects

    def _render(self, text: str, locale: Locale) -> tuple[str, ...]:
        header = self.owner.tr.page_prefix(locale, 100, 100)
        footer = MARKER_FOOTER_SIZE
        rendered = MobileMarkdown(locale=locale).render(
            text, self.message_limit, reserved_characters=footer + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise ValueError("closed_menu_output_bounds")
        return tuple(
            self.owner.tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )

    async def route(
        self, message: HumanMessage, parsed: ParsedInput, *, recovered: bool
    ) -> RoutedInput | None:
        from jt_oz_bridge.services.unbound_router import DiscoveryResult, SavedDiscoveryReply

        owner = self.owner
        sources: tuple[HumanMessage, ...]
        previous = await owner.inbox.find(message.realm_id, message.message_id)
        if previous is not None and previous.state not in {"deferred", "completed"}:
            return None  # Existing processing/ambiguous recovery remains public and strict.
        if previous is not None and previous.state == "completed":
            # Parent publisher validates the already committed immutable batch.
            saved = SavedDiscoveryReply.model_validate(previous.response)
            if saved.queued_batch_id is None or saved.target is None:
                return None
            selection = None
            sources = (message,)
        else:
            saved = None
            try:
                selection = (
                    await owner.shortcuts.observation_sources(message)
                    if parsed.command == "choose"
                    else None
                )
                if selection is not None:
                    if selection.links.choose is None:
                        return None
                    selected_menu = await owner.tokens.inspect(
                        selection.links.choose, "discover-menu", message.realm_id, message.author_id
                    )
                    menu_data = selected_menu.context.get("data")
                    items = menu_data.get("items") if isinstance(menu_data, dict) else None
                    number = int(parsed.arguments)
                    if (
                        not isinstance(items, list)
                        or not 1 <= len(items) <= 10
                        or any(not isinstance(item, dict) for item in items)
                        or not 1 <= number <= len(items)
                        or items[number - 1].get("kind") not in {"project", "session"}
                    ):
                        return None
            except (Conflict, ValueError):
                return None  # Before any Native/read-only work, retain strict stale-menu replies.
            sources = (message,) + (selection.sources if selection else ())
            if len(sources) > 8:
                return None  # Long multipart menus keep existing fully checked API.
        locale = await message_locale(owner.db, owner.reader, message)
        claim: CommandClaim | None = None
        write_started = False

        def mark_write_started() -> None:
            nonlocal write_started
            write_started = True

        async def read_only(audience: AudienceSnapshot) -> _PreparedMenu | SavedDiscoveryReply:
            nonlocal claim
            if self.reader.scope.client.verify_identity is not self._guard:
                raise ZulipError("closed_menu_original_guard_changed")
            await owner.destinations.unbound(message)
            if saved is not None:
                if (
                    saved.target is None
                    or saved.target.source != message
                    or saved.target.audience != audience
                ):
                    raise Conflict("closed_menu_replay_source_or_audience_changed")
                for project in saved.target.projects:
                    if (
                        await owner.discovery._project_in_audience(
                            message, project.scope.project_id, audience
                        )
                        != project
                    ):
                        raise Conflict("closed_menu_replay_project_changed")
                return saved
            claim = await owner.inbox.claim(
                message, parsed.command, recovered=recovered, unbound_literal_control=True
            )
            if claim.status != "claimed":
                raise Conflict("closed_menu_command_claim_changed")
            operate: tuple[str, ...] = ()
            require_current = None
            adoption_stage = None
            if parsed.command == "projects":
                result, projects = await self._projects(message, audience, locale)
            else:
                assert selection is not None
                opaque = selection.links.choose
                if opaque is None:
                    raise Conflict("shortcut_current_reply_has_no_choose")
                token, _ = await self._guard_menu(message, opaque, audience)
                menu_data = token.context.get("data")
                items = menu_data.get("items") if isinstance(menu_data, dict) else None
                number = int(parsed.arguments)
                if (
                    not isinstance(items, list)
                    or not 1 <= len(items) <= 10
                    or any(not isinstance(item, dict) for item in items)
                    or not 1 <= number <= len(items)
                ):
                    raise Conflict("discovery_choice_unavailable")
                item = items[number - 1]
                await owner.tokens.consume(
                    opaque, "discover-menu", message.realm_id, message.author_id
                )
                if item["kind"] == "project":
                    result, projects = await self._sessions(message, item["id"], audience, locale)
                elif item["kind"] == "session":
                    selected = SessionRef.model_validate(item["reference"])
                    original_selection = (
                        ExistingSessionSelection.model_validate(item["selection"])
                        if item.get("selection") is not None
                        else None
                    )
                    preview = await owner.confirmations._prepare_observed(
                        message, selected, audience, locale, selection=original_selection
                    )
                    project = await owner.discovery._project_in_audience(
                        message, selected.project_id, audience
                    )
                    projects = (project,) if preview.token else ()
                    result = DiscoveryResult(
                        preview.text,
                        tuple(p.scope.project_id for p in projects),
                        shortcuts=DiscoveryShortcuts(confirm=preview.token)
                        if preview.token
                        else None,
                    )
                    operate = (selected.project_id,)
                    require_current = preview.require_current
                    adoption_stage = preview.adoption_stage
                else:
                    raise Conflict("closed_menu_choice_kind_not_supported")
            return _PreparedMenu(
                claim,
                result,
                projects,
                self._render(result.text, locale),
                operate,
                require_current,
                adoption_stage,
            )

        try:
            observation = await self.reader.scope.observe_sources(
                self.reader, sources, read_only=read_only
            )
            completed = self.reader.scope.consume_observation(observation, self.reader, sources)
            data = completed.value
            if isinstance(data, SavedDiscoveryReply):
                assert data.target is not None
                return RoutedInput(
                    "reply",
                    text=data.text,
                    delivery_key="command:" + cast(Any, previous).id,
                    locale=data.locale,
                    discovery_target=data.target,
                    queued_batch_id=data.queued_batch_id,
                )
            if data.require_current is not None:
                data.require_current()
            if data.adoption_stage is not None:
                adoption = owner.confirmations.adoption
                if adoption is None:
                    raise Conflict("closed_menu_original_adoption_unavailable")
                await adoption.commit_observed(
                    data.adoption_stage, mark_write_started=mark_write_started
                )
                data.adoption_stage.require_current()
            now = time.time()
            target = DiscoveryTarget(
                id=uuid4(),
                source=message,
                audience=completed.audience,
                projects=data.projects,
                purpose="catalog" if data.projects else "static",
                issued_at=now,
                expires_at=now + 900,
            )
            response = SavedDiscoveryReply(
                origin="discovery",
                text=data.result.text,
                locale=locale,
                target=target,
                shortcuts=data.result.shortcuts,
            )
            plan = owner.tokens.active_plan
            if plan is None:
                raise Conflict("closed_menu_requires_original_token_plan")
            queued_id: str | None = None

            async def commit(session: AsyncSession) -> None:
                nonlocal queued_id
                if data.require_current is not None:
                    data.require_current()
                if not await session.scalar(select(and_(*owner.destinations.guards(target)))):
                    raise AccessDenied("closed_menu_local_authority_changed")
                if selection is not None:
                    await owner.shortcuts.validate_observation_in_session(
                        session, message, selection
                    )
                for identity in data.operate:
                    grants = list(
                        (
                            await session.scalars(
                                select(Grant)
                                .where(
                                    Grant.realm_id == message.realm_id,
                                    Grant.project_id == identity,
                                    Grant.user_id == message.author_id,
                                    Grant.active.is_(True),
                                )
                                .with_for_update()
                            )
                        ).all()
                    )
                    if not any(Permission.OPERATE in ROLES.get(g.role, set()) for g in grants):
                        raise AccessDenied("closed_menu_operate_revoked_before_commit")
                await plan.commit(session, target=target)
                if data.require_current is not None:
                    data.require_current()
                queued = await self.outbox.queue_scope_batch_in_session(
                    session,
                    "command:" + data.claim.id,
                    target,
                    data.pages,
                    renderer_version="discovery-mobile-markdown-v2",
                    message_limit=self.message_limit,
                    topic_limit=self.topic_limit,
                    priority=10,
                )
                queued_id = queued.id
                final_response = {
                    **response.model_dump(mode="json", exclude_none=True),
                    "queued_batch_id": queued.id,
                }
                changed = await session.execute(
                    update(CommandReceipt)
                    .where(
                        CommandReceipt.id == data.claim.id,
                        CommandReceipt.state == "completed",
                        CommandReceipt.version == data.claim.version + 1,
                        CommandReceipt.holder == owner.inbox.holder,
                        CommandReceipt.fencing == owner.inbox.fencing,
                    )
                    .values(response=final_response)
                )
                if changed.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("closed_menu_completed_receipt_changed")
                if data.require_current is not None:
                    data.require_current()

            write_started = True
            await owner.inbox.finish(
                data.claim, response.model_dump(mode="json", exclude_none=True), commit=commit
            )
            assert queued_id is not None
            return RoutedInput(
                "reply",
                text=data.result.text,
                delivery_key="command:" + data.claim.id,
                locale=locale,
                discovery_target=target,
                queued_batch_id=queued_id,
            )
        except BaseException as error:
            if claim is not None and claim.status == "claimed":
                settled = await asyncio.shield(
                    owner.inbox.find(message.realm_id, message.message_id)
                )
                if settled is None or settled.state != "completed":
                    if isinstance(error, DeliveryRateLimited) and not write_started:
                        await asyncio.shield(owner.inbox.defer_catalog(claim))
                    else:
                        # Permanent auth/read failures and every unknown SQL
                        # attempt stay held. A missing response is never proof
                        # that a write transaction failed or may be replayed.
                        try:
                            await asyncio.shield(owner.inbox.abandon(claim))
                        except Conflict:
                            pass
            if isinstance(error, DeliveryRateLimited) and not write_started:
                raise RoutingRateDeferred(error.retry_after) from None
            raise


class ClosedConfirmationOperations(ClosedMenuOperations):
    """Explicit original binding and ACK batch in one fenced SQL transaction."""

    def eligible(self, message: HumanMessage, parsed: ParsedInput) -> bool:
        if (
            parsed.kind != "command"
            or parsed.command != "confirm"
            or parsed.arguments
            or message.realm_id != self.realm_id
            or message.is_bot
            or message.deleted
            or message.revision != 0
        ):
            return False
        guard = self.reader.scope.client.verify_identity
        if self._guard is None:
            if not callable(getattr(type(guard), "scope_reads", None)):
                return False
            self._guard = guard
        return True

    async def route(
        self, message: HumanMessage, parsed: ParsedInput, *, recovered: bool
    ) -> RoutedInput | None:
        from jt_oz_bridge.services.unbound_router import SavedDiscoveryReply

        owner = self.owner
        # None is an effect-free decline only. Every selected attempt below
        # either completes or propagates its failure; it never reroutes.
        if await owner.inbox.find(message.realm_id, message.message_id) is not None:
            return None
        try:
            selection = await owner.shortcuts.observation_sources(message)
        except (Conflict, ValueError):
            return None
        if selection.links.confirm is None or len(selection.sources) >= 8:
            return None
        sources = (message,) + selection.sources
        locale = await message_locale(owner.db, owner.reader, message)
        claim: CommandClaim | None = None
        write_started = False

        def mark_write_started() -> None:
            nonlocal write_started
            write_started = True

        async def read_only(audience: AudienceSnapshot) -> ObservedBindingConfirmation:
            nonlocal claim
            if self.reader.scope.client.verify_identity is not self._guard:
                raise ZulipError("closed_confirmation_original_guard_changed")
            await owner.destinations.unbound(message)
            claim = await owner.inbox.claim(
                message, "confirm", recovered=recovered, unbound_literal_control=True
            )
            if claim.status != "claimed":
                raise Conflict("closed_confirmation_command_claim_changed")
            return await owner.confirmations._prepare_confirmation_observed(
                message, selection.links.confirm or "", audience, locale
            )

        try:
            observation = await self.reader.scope.observe_sources(
                self.reader, sources, read_only=read_only
            )
            completed = self.reader.scope.consume_observation(observation, self.reader, sources)
            prepared = completed.value
            prepared.require_current()
            if completed.audience != prepared.audience or claim is None:
                raise Conflict("closed_confirmation_observed_scope_changed")
            if prepared.adoption_stage is not None:
                adoption = owner.confirmations.adoption
                if adoption is None:
                    raise Conflict("closed_confirmation_original_adoption_unavailable")
                await adoption.commit_observed(
                    prepared.adoption_stage, mark_write_started=mark_write_started
                )
                prepared.require_current()
            owned_claim = claim
            text = owner.tr.render("discovery.bound", locale)
            pages = self._render(text, locale)
            routed: RoutedInput | None = None

            async def commit(session: AsyncSession) -> None:
                nonlocal routed
                prepared.require_current()
                await owner.shortcuts.validate_observation_in_session(session, message, selection)
                binding = await owner.confirmations._commit_confirmation_observed(session, prepared)
                queued = await self.outbox.queue_batch_in_session(
                    session,
                    "command:" + owned_claim.id,
                    binding,
                    pages,
                    renderer_version="router-mobile-markdown-v2",
                    message_limit=self.message_limit,
                    topic_limit=self.topic_limit,
                    priority=10,
                )
                # Repeat after every page flush, so a late local mutation
                # rolls back Binding, token, receipt and all output together.
                await lock_output_scope(owner.bindings, session, binding)
                grants = list(
                    (
                        await session.scalars(
                            select(Grant)
                            .where(
                                Grant.realm_id == message.realm_id,
                                Grant.project_id == prepared.selected.project_id,
                                Grant.user_id == message.author_id,
                                Grant.active.is_(True),
                            )
                            .with_for_update()
                        )
                    ).all()
                )
                if not any(Permission.OPERATE in ROLES.get(g.role, set()) for g in grants):
                    raise AccessDenied("closed_confirmation_operate_revoked_before_commit")
                response = SavedDiscoveryReply(
                    origin="discovery",
                    text=text,
                    locale=locale,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    queued_batch_id=queued.id,
                    confirmation_source=message,
                    confirmed_reference=prepared.selected,
                    confirmed_title=prepared.snapshot.title,
                )
                changed = await session.execute(
                    update(CommandReceipt)
                    .where(
                        CommandReceipt.id == owned_claim.id,
                        CommandReceipt.state == "completed",
                        CommandReceipt.version == owned_claim.version + 1,
                        CommandReceipt.holder == owner.inbox.holder,
                        CommandReceipt.fencing == owner.inbox.fencing,
                    )
                    .values(response=response.model_dump(mode="json", exclude_none=True))
                )
                if changed.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("closed_confirmation_completed_receipt_changed")
                await owner.inbox.fence.lock(session)
                prepared.require_current()
                routed = RoutedInput(
                    "reply",
                    binding.id,
                    binding.revision,
                    text,
                    "command:" + owned_claim.id,
                    locale=locale,
                    queued_batch_id=queued.id,
                )

            write_started = True
            await owner.inbox.finish(owned_claim, {}, commit=commit)
            if routed is None:
                raise Conflict("closed_confirmation_commit_result_missing")
            return routed
        except BaseException as error:
            if claim is not None and claim.status == "claimed":
                settled = await asyncio.shield(
                    owner.inbox.find(message.realm_id, message.message_id)
                )
                if settled is None or settled.state != "completed":
                    if isinstance(error, DeliveryRateLimited) and not write_started:
                        await asyncio.shield(owner.inbox.defer_confirmation(claim))
                    else:
                        try:
                            await asyncio.shield(owner.inbox.abandon(claim))
                        except Conflict:
                            pass
            if isinstance(error, DeliveryRateLimited) and not write_started:
                raise RoutingRateDeferred(error.retry_after) from None
            raise
