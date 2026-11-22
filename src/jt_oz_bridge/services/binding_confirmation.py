"""Explicit original-session preview/confirmation, with no upstream mutations."""

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import AudienceSnapshot, SessionSnapshot
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import code_block, code_span, spoiler_block
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.security.redaction import RedactionError, redact_json
from jt_oz_bridge.services.backend_registry import BackendRegistry
from jt_oz_bridge.services.bindings import topic_key
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.discovery_shortcuts import DiscoveryShortcutService
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import AuditEvent, Grant, uid

if TYPE_CHECKING:
    from jt_oz_bridge.services.session_adoption import ObservedOriginalSelection


class BindingPreparationDeferred(DeliveryRateLimited):
    """A confirmation failed during reads, before any Binding/token write began."""


@dataclass(frozen=True)
class BindingPreview:
    text: str
    token: str | None


@dataclass(frozen=True)
class ObservedBindingPreview(BindingPreview):
    """Unpublished data with an original synchronous Native witness check."""

    require_current: Callable[[], None]
    adoption_stage: "ObservedOriginalSelection | None" = None


@dataclass(frozen=True)
class ObservedBindingConfirmation:
    """Unpublished preparation; only the closing observer may admit its SQL write."""

    message: HumanMessage
    selected: SessionRef
    audience: AudienceSnapshot
    snapshot: SessionSnapshot
    token: ControlToken
    locale: Locale
    require_current: Callable[[], None]
    selection: ExistingSessionSelection | None = None
    adoption_stage: "ObservedOriginalSelection | None" = None


class BindingConfirmation:
    def __init__(
        self, discovery: DiscoveryService, tokens: TokenService, reader: SourceReader
    ) -> None:
        if discovery.db is not tokens.db:
            raise ValueError("binding_confirmation_database_mismatch")
        self.discovery, self.bindings = discovery, discovery.bindings
        self.tokens, self.reader, self.tr = tokens, reader, Translator()
        self.adoption = discovery.adoption
        if self.adoption is not None and (
            self.adoption.reader is not reader or self.adoption.journal.fence != tokens.fence
        ):
            raise ValueError("binding_confirmation_original_adoption_composition_required")

    async def _prepare_confirmation_observed(
        self,
        message: HumanMessage,
        opaque: str,
        audience: AudienceSnapshot,
        locale: Locale = "en",
    ) -> ObservedBindingConfirmation:
        """GET-only work inside the issuer's current closed Source observation."""
        parsed = parse_input(message.text)
        if (
            self.tokens.active_plan is not None
            or self.tokens.fence is None
            or message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "confirm"
            or parsed.arguments not in {"", opaque}
            or not re.fullmatch(r"[A-Za-z0-9_-]{32}", opaque)
            or (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != (message.realm_id, message.channel_id, message.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
        ):
            raise AccessDenied("closed_confirmation_requires_current_original_control")
        token = await self.tokens.inspect(
            opaque, "binding-confirm", message.realm_id, message.author_id
        )
        selected = SessionRef.model_validate(token.context["reference"])
        selection = (
            ExistingSessionSelection.model_validate(token.context["selection"])
            if token.context.get("selection") is not None
            else None
        )
        project = await self.discovery._project_in_audience(message, selected.project_id, audience)
        if not project.scope.contains(selected):
            raise AccessDenied("binding_selection_outside_project")
        await self.bindings.policy.require(
            message.realm_id, message.author_id, selected.project_id, Permission.OPERATE
        )
        snapshot, require_current, stage = await self._observe_original_selection(
            message, selected, audience, selection
        )
        result = ObservedBindingConfirmation(
            message,
            selected,
            audience,
            snapshot,
            token,
            locale,
            require_current,
            selection,
            stage,
        )
        self._confirmation_context(result)
        require_current()
        return result

    @staticmethod
    def _confirmation_context(prepared: ObservedBindingConfirmation) -> None:
        message, selected, audience, snapshot, token = (
            prepared.message,
            prepared.selected,
            prepared.audience,
            prepared.snapshot,
            prepared.token,
        )
        expected = {
            "reference": selected.model_dump(mode="json"),
            "channel_id": message.channel_id,
            "topic": message.topic,
            "audience_hash": digest(audience.model_dump(mode="json")),
            "title": snapshot.title,
        }
        if prepared.selection is not None:
            if prepared.selection.reference != selected:
                raise Conflict("binding_original_menu_selection_required")
            expected["selection"] = prepared.selection.model_dump(mode="json")
        if (
            snapshot.reference != selected
            or not snapshot.reconciled
            or token.kind != "binding-confirm"
            or token.realm_id != message.realm_id
            or token.user_id != message.author_id
            or token.binding_id is not None
            or token.binding_revision is not None
            or token.context != expected
            or token.context_hash != digest(expected)
        ):
            raise Conflict("binding_confirmation_scope_or_title_changed")

    async def _commit_confirmation_observed(
        self, session: AsyncSession, prepared: ObservedBindingConfirmation
    ) -> Binding:
        """Internal SQL writer; no network, transaction, or authorization receipt cache.

        The caller must close and synchronously consume its Source/audience
        observation first, and atomically commit this Binding, command result
        and complete ACK batch in this same transaction.
        """
        if self.tokens.active_plan is not None or self.tokens.fence is None:
            raise Conflict("closed_confirmation_requires_direct_owned_transaction")
        self._confirmation_context(prepared)
        prepared.require_current()
        await self.tokens.fence.lock(session)
        await self.tokens.consume_in_session(session, prepared.token)
        message, selected, audience, snapshot = (
            prepared.message,
            prepared.selected,
            prepared.audience,
            prepared.snapshot,
        )
        binding = Binding(
            id=uid(),
            realm_id=message.realm_id,
            channel_id=message.channel_id,
            topic=message.topic,
            anchor_message_id=message.message_id,
            backend_id=selected.backend_id,
            backend_identity=selected.backend_identity,
            session_id=selected.upstream_session_id,
            project_id=selected.project_id,
            canonical_directory=selected.canonical_directory,
            title=snapshot.title,
            owner_id=message.author_id,
            locale=prepared.locale,
            revision=1,
            state="active",
            audience_revision=audience.revision,
            audience_user_ids=sorted(audience.user_ids),
            observed_cursor=snapshot.cursor,
            session_key=digest(
                {
                    "realm": message.realm_id,
                    "backend": selected.backend_id,
                    "identity": selected.backend_identity,
                    "session": selected.upstream_session_id,
                }
            ),
            topic_key=topic_key(message.realm_id, message.channel_id, message.topic),
        )
        session.add(binding)
        await session.flush()
        await lock_output_scope(self.bindings, session, binding)
        grants = list(
            (
                await session.scalars(
                    select(Grant)
                    .where(
                        Grant.realm_id == message.realm_id,
                        Grant.project_id == selected.project_id,
                        Grant.user_id == message.author_id,
                        Grant.active.is_(True),
                    )
                    .with_for_update()
                )
            ).all()
        )
        if not any(Permission.OPERATE in ROLES.get(grant.role, set()) for grant in grants):
            raise AccessDenied("binding_grants_changed_before_commit")
        prepared.require_current()
        session.add(
            AuditEvent(
                actor=f"{message.realm_id}:{message.author_id}",
                event="session_bound",
                object_id=binding.id,
            )
        )
        return binding

    async def source(self, message: HumanMessage, commands: frozenset[str]) -> AudienceSnapshot:
        audience = await self.discovery.audience(message)
        parsed = parse_input(message.text)
        if (
            parsed.kind != "command"
            or parsed.command not in commands
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise AccessDenied("binding_control_source_changed")
        return audience

    async def prepare(
        self,
        message: HumanMessage,
        selected: SessionRef,
        locale: Locale = "en",
        *,
        selection: ExistingSessionSelection | None = None,
    ) -> BindingPreview:
        await self.source(message, frozenset({"choose", "bind", "go"}))
        project, audience = await self.discovery.project(message, selected.project_id)
        if not project.scope.contains(selected):
            raise AccessDenied("binding_selection_outside_project")
        await self.bindings.policy.require(
            message.realm_id, message.author_id, selected.project_id, Permission.OPERATE
        )
        adoption_enabled = (
            self.adoption is not None and selected.project_id in self.adoption.factories
        )
        if adoption_enabled or selection is not None:
            if self.adoption is None or selection is None or selection.reference != selected:
                raise Conflict("binding_original_menu_selection_required")
            await self.adoption.prepare_selection(message, selection)
        await self.bindings.enrolled(selected, message.realm_id)
        snapshot = await self.bindings.control.snapshot(selected)
        if snapshot.reference != selected or not snapshot.reconciled:
            raise Conflict("binding_original_execution_unverified")
        proof_current = (
            await self.adoption.guard_selection(message, selection)
            if self.adoption is not None and selection is not None
            else None
        )
        current, current_audience = await self.discovery.project(message, selected.project_id)
        if current != project or current_audience != audience:
            raise Conflict("binding_preview_scope_changed")
        await self.bindings.policy.require(
            message.realm_id, message.author_id, selected.project_id, Permission.OPERATE
        )
        plan = self.tokens.active_plan
        if plan is None:
            await self.source(message, frozenset({"choose", "bind", "go"}))
        else:
            # Planned previews cannot become durable until the router has read
            # this exact source again and checked the complete output audience.
            plan.require_output_source(message)

        return await self._issue_preview(
            message,
            selected,
            audience,
            snapshot,
            locale,
            selection=selection,
            proof_current=proof_current,
        )

    async def _prepare_observed(
        self,
        message: HumanMessage,
        selected: SessionRef,
        audience: AudienceSnapshot,
        locale: Locale = "en",
        *,
        selection: ExistingSessionSelection | None = None,
    ) -> ObservedBindingPreview:
        """Internal closed-read callback only; never a standalone authorization.

        This only stages data in the caller's unpublished token plan. The
        closed Source/audience observer must finish before queueing, then the
        caller must recheck this original Native witness and all SQL guards.
        An unsupported control may supply preview data but its current guard
        refuses publication; it cannot mint a resource proof or widen scope.
        """
        plan = self.tokens.active_plan
        parsed = parse_input(message.text)
        if (
            plan is None
            or plan.committed
            or message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in {"choose", "bind"}
            or (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != (message.realm_id, message.channel_id, message.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
        ):
            raise AccessDenied("closed_preview_requires_owned_plan_and_current_human")
        project = await self.discovery._project_in_audience(message, selected.project_id, audience)
        if not project.scope.contains(selected):
            raise AccessDenied("binding_selection_outside_project")
        await self.bindings.policy.require(
            message.realm_id, message.author_id, selected.project_id, Permission.OPERATE
        )
        snapshot, require_current, stage = await self._observe_original_selection(
            message, selected, audience, selection
        )
        if snapshot.reference != selected or not snapshot.reconciled:
            raise Conflict("binding_original_execution_unverified")
        current = await self.discovery._project_in_audience(message, selected.project_id, audience)
        if current != project:
            raise Conflict("binding_preview_scope_changed")
        await self.bindings.policy.require(
            message.realm_id, message.author_id, selected.project_id, Permission.OPERATE
        )
        if stage is None:
            await self.bindings.enrolled(selected, message.realm_id)
        else:
            require_current()
        plan.require_output_source(message)
        preview = await self._issue_preview(
            message,
            selected,
            audience,
            snapshot,
            locale,
            selection=selection,
            proof_current=require_current if selection is not None else None,
        )
        return ObservedBindingPreview(preview.text, preview.token, require_current, stage)

    async def _observe_original_selection(
        self,
        message: HumanMessage,
        selected: SessionRef,
        audience: AudienceSnapshot,
        selection: ExistingSessionSelection | None,
    ) -> tuple[SessionSnapshot, Callable[[], None], "ObservedOriginalSelection | None"]:
        enabled = self.adoption is not None and selected.project_id in self.adoption.factories
        if enabled or selection is not None:
            if self.adoption is None or selection is None or selection.reference != selected:
                raise Conflict("binding_original_menu_selection_required")
            stage = await self.adoption.observe_selection(message, selection, audience)
            stage.require_current()
            return stage.snapshot, stage.require_current, stage
        await self.bindings.enrolled(selected, message.realm_id)
        snapshot, current = await self._observed_native_snapshot(selected)
        return snapshot, current, None

    async def _observed_native_snapshot(
        self, selected: SessionRef
    ) -> tuple[SessionSnapshot, Callable[[], None]]:
        """Retain the actual enrolled V2 witness; never renew its deadline."""
        control = self.bindings.control
        backend = control.selected(selected) if isinstance(control, BackendRegistry) else None
        client = backend.client if backend is not None else control
        registry = client if isinstance(client, SessionRegistry) else None
        entry = registry.selected(selected) if registry is not None else None
        execution = entry.execution if entry is not None else client
        if not isinstance(execution, V2ExecutionClient):
            snapshot = await control.snapshot(selected)

            def unsupported() -> None:
                raise Conflict("closed_preview_original_native_witness_required")

            return snapshot, unsupported
        # Capture before the first Native await: equivalent replacements are
        # new assemblies, even when their schema, feed epoch and fence match.
        proofs, transport, guard = execution.proofs, execution.transport, execution.scope_guard
        http_client, profile = transport.client, transport.profile
        attestation, verifier = transport.attestation, transport.verify_identity
        projects, project = execution.projects, execution.selected(selected)
        model_settings = getattr(proofs, "model_settings", None)
        feed = getattr(proofs, "feed", None)
        owner = getattr(feed, "owner", None)
        enrollments = getattr(guard, "enrollments", None)
        enrollment_items = tuple(enrollments.items()) if isinstance(enrollments, Mapping) else ()
        guard_proofs = getattr(guard, "proofs", None)

        def require_assembly() -> None:
            if (
                execution.proofs is not proofs
                or execution.transport is not transport
                or execution.scope_guard is not guard
                or transport.client is not http_client
                or transport.profile is not profile
                or transport.attestation is not attestation
                or transport.verify_identity is not verifier
                or execution.projects is not projects
                or execution.selected(selected) is not project
                or getattr(proofs, "model_settings", None) is not model_settings
                or getattr(proofs, "feed", None) is not feed
                or getattr(feed, "owner", None) is not owner
                or getattr(guard, "proofs", None) is not guard_proofs
                or getattr(guard, "enrollments", None) is not enrollments
                or isinstance(enrollments, Mapping)
                and (
                    len(enrollments) != len(enrollment_items)
                    or any(enrollments.get(ref) is not value for ref, value in enrollment_items)
                )
            ):
                raise Conflict("closed_preview_original_native_assembly_changed")

        snapshot, proof = await execution.qualified_snapshot(selected)

        def require_current() -> None:
            require_assembly()
            if (
                self.bindings.control is not control
                or backend is not None
                and (
                    not isinstance(control, BackendRegistry)
                    or control.selected(selected) is not backend
                )
                or registry is not None
                and registry.selected(selected) is not entry
                or entry is not None
                and entry.execution is not execution
                or control.contract_for(selected) != proof.contract_sha256
            ):
                raise Conflict("closed_preview_original_native_assembly_changed")
            execution.current(selected, proof)
            for child in snapshot.descendants:
                if control.contract_for(child) != proof.contract_sha256:
                    raise Conflict("closed_preview_original_native_lineage_changed")

        require_current()
        return snapshot, require_current

    async def _issue_preview(
        self,
        message: HumanMessage,
        selected: SessionRef,
        audience: AudienceSnapshot,
        snapshot: SessionSnapshot,
        locale: Locale,
        *,
        selection: ExistingSessionSelection | None = None,
        proof_current: Callable[[], object] | None = None,
    ) -> BindingPreview:
        if (selection is None) != (proof_current is None) or (
            selection is not None and selection.reference != selected
        ):
            raise Conflict("binding_original_selection_and_preview_fence_required")
        try:
            shown = redact_json(
                {
                    "reference": selected.model_dump(mode="json"),
                    "title": snapshot.title,
                    "state_at_preview": snapshot.state.value,
                    "channel": message.channel_id,
                    "topic": message.topic,
                }
            )
        except RedactionError:
            return BindingPreview(self.tr.render("binding.preview_unavailable", locale), None)
        # An incomplete/redacted target is not an adequate binding confirmation.
        if shown.redactions:
            return BindingPreview(self.tr.render("binding.preview_unavailable", locale), None)
        body = (
            self.tr.render("binding.preview_title", locale)
            + "\n\n"
            + self.tr.render(
                "binding.preview_summary",
                locale,
                title=code_span(snapshot.title.replace("\n", " ")),
                backend=code_span(selected.backend_id),
                project=code_span(selected.project_id),
                directory=code_span(selected.canonical_directory),
                session=code_span(selected.upstream_session_id),
                state=code_span(snapshot.state.value),
                channel=code_span(str(message.channel_id)),
                topic=code_span(message.topic.replace("\n", " ")),
            )
            + "\n\n"
            + spoiler_block(
                code_block(json.dumps(shown.value, ensure_ascii=False, indent=2), "json"),
                self.tr.render("binding.preview_details", locale),
            )
        )
        if len(body) > 1000000 - 2048:
            return BindingPreview(self.tr.render("binding.preview_unavailable", locale), None)
        context = {
            "reference": selected.model_dump(mode="json"),
            "channel_id": message.channel_id,
            "topic": message.topic,
            "audience_hash": digest(audience.model_dump(mode="json")),
            "title": snapshot.title,
        }
        if selection is not None:
            context["selection"] = selection.model_dump(mode="json")
        if proof_current is not None:
            proof_current()
        token = await self.tokens.issue(
            "binding-confirm", message.realm_id, message.author_id, context
        )
        if proof_current is not None:
            proof_current()
        return BindingPreview(
            body + "\n\n" + self.tr.render("binding.preview_confirm", locale, token=token),
            token,
        )

    async def confirm(
        self,
        message: HumanMessage,
        opaque: str,
        topic_locale: Locale = "en",
        *,
        direct: bool = False,
    ) -> Binding:
        """``direct`` commits the token just issued for this same choosing message."""
        write_started = False

        def mark_write_started() -> None:
            nonlocal write_started
            write_started = True

        try:
            return await self._confirm(message, opaque, topic_locale, mark_write_started, direct)
        except DeliveryRateLimited as error:
            if write_started:
                raise
            raise BindingPreparationDeferred(error.retry_after) from None

    async def _confirm(
        self,
        message: HumanMessage,
        opaque: str,
        topic_locale: Locale,
        before_write: Callable[[], None],
        direct: bool = False,
    ) -> Binding:
        commands = frozenset({"choose", "go"}) if direct else frozenset({"confirm"})
        audience = await self.source(message, commands)
        parsed = parse_input(message.text)
        shortcut = not direct and not opaque and not parsed.arguments
        if shortcut:
            opaque = await DiscoveryShortcutService(self.discovery.db, self.reader).token(
                message, "confirm"
            )
        elif not direct and parsed.arguments != opaque:
            raise AccessDenied("binding_confirmation_source_mismatch")
        if not re.fullmatch(r"[A-Za-z0-9_-]{32}", opaque):
            raise ValueError("binding_confirmation_required")
        token = await self.tokens.inspect(
            opaque, "binding-confirm", message.realm_id, message.author_id
        )
        selected = SessionRef.model_validate(token.context["reference"])
        selection = (
            ExistingSessionSelection.model_validate(token.context["selection"])
            if token.context.get("selection") is not None
            else None
        )
        adoption_enabled = (
            self.adoption is not None and selected.project_id in self.adoption.factories
        )
        if adoption_enabled or selection is not None:
            if self.adoption is None or selection is None or selection.reference != selected:
                raise Conflict("binding_original_menu_selection_required")
        project = await self.discovery._project_in_audience(message, selected.project_id, audience)
        if (
            not project.scope.contains(selected)
            or token.context.get("channel_id") != message.channel_id
            or token.context.get("topic") != message.topic
            or token.context.get("audience_hash") != digest(audience.model_dump(mode="json"))
        ):
            raise AccessDenied("binding_confirmation_target_changed")

        current: Callable[[], bool] | None = None

        async def final_source() -> None:
            nonlocal current
            if (
                shortcut
                and await DiscoveryShortcutService(self.discovery.db, self.reader).token(
                    message, "confirm"
                )
                != opaque
            ):
                raise Conflict("binding_shortcut_changed_before_commit")
            latest = await self.source(message, commands)
            if digest(latest.model_dump(mode="json")) != token.context.get("audience_hash"):
                raise Conflict("binding_audience_changed_before_commit")
            if self.adoption is not None and selection is not None:
                current = await self.adoption.guard_selection(message, selection)

        def final_current() -> bool:
            return current is not None and current() is True

        return await self.bindings.bind(
            message.realm_id,
            message.author_id,
            message.channel_id,
            message.topic,
            selected,
            topic_locale,
            confirmation=(self.tokens, token),
            fence=self.tokens.fence,
            anchor_message_id=message.message_id,
            validate_source=final_source,
            selection=selection,
            validate_current=final_current if selection is not None else None,
            before_write=before_write,
        )
