"""Scoped, revisioned phone drafts; only explicit reviewed submission queues a reply."""

import json
import re
import time
from dataclasses import dataclass

from sqlalchemy import select, update

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import (
    FieldAnswer,
    InteractionSnapshot,
    active_field,
    answer_value,
    draft_answers,
    validate_answers,
)
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.form_input import FormInputError, decode_answer, skipped_fields
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import code_block, literal
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.security.redaction import RedactionError, redact_json
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken, FormDraft, PendingInteraction
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import AuditEvent


@dataclass(frozen=True)
class DraftView:
    revision: int
    answers: dict[str, FieldAnswer]
    skipped: frozenset[str]

    def fingerprint(self) -> str:
        return digest(
            {
                "answers": {k: v.model_dump(mode="json") for k, v in self.answers.items()},
                "skipped": sorted(self.skipped),
            }
        )


class FormWizard:
    def __init__(
        self,
        bindings: BindingService,
        tokens: TokenService,
        *,
        capabilities: CapabilityLookup | None = None,
    ) -> None:
        self.bindings, self.tokens, self.db = bindings, tokens, bindings.db
        self.interactions = InteractionService(bindings, fence=tokens.fence)
        self.tr = Translator()
        self.native_capabilities = capabilities

    async def frame(
        self, binding: Binding, message: HumanMessage, root: str
    ) -> tuple[ControlToken, PendingInteraction, InteractionSnapshot, DraftView]:
        if (
            message.is_bot
            or message.deleted
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
        ):
            raise AccessDenied("form_source_outside_binding")
        token = await self.tokens.inspect(root, "interaction", message.realm_id, message.author_id)
        if token.binding_id != binding.id or token.binding_revision != binding.revision:
            raise AccessDenied("form_outside_binding")
        saved = await self.interactions.request(token.context["interaction_id"])
        if (
            token.context.get("snapshot_hash") != saved.snapshot_hash
            or token.context.get("interaction_version") != saved.version
        ):
            raise Conflict("form_snapshot_changed")
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        if snapshot.kind != "form":
            raise AccessDenied("not_a_question_form")
        await self.bindings.get(binding.id, message.realm_id, message.author_id, Permission.OPERATE)
        await self.interactions.lineage(binding, snapshot)
        current = await self.bindings.control.interaction(
            snapshot.reference, snapshot.upstream_request_id
        )
        if current != snapshot or not current.pending:
            raise Conflict("form_changed_upstream")
        latest = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if latest.revision != binding.revision:
            raise Conflict("form_binding_changed")
        return token, saved, snapshot, await self.draft(saved, snapshot, message.author_id)

    async def draft(
        self, saved: PendingInteraction, snapshot: InteractionSnapshot, user: int
    ) -> DraftView:
        async with self.db.sessions() as session:
            row = await session.get(FormDraft, digest({"request": saved.id, "user": user}))
        if row is None:
            return DraftView(0, {}, frozenset())
        if (
            row.snapshot_hash != saved.snapshot_hash
            or row.interaction_id != saved.id
            or row.user_id != user
        ):
            raise Conflict("draft_snapshot_changed")
        answers = {k: FieldAnswer.model_validate(v) for k, v in row.answers.items()}
        validate_answers(snapshot.fields, answers, complete=False)
        return DraftView(
            row.revision, answers, skipped_fields(row.progress, snapshot.fields, answers)
        )

    async def open(
        self, binding: Binding, message: HumanMessage, locale: Locale, identity: str
    ) -> str:
        root = await self.interactions.issue(identity, message.realm_id, message.author_id)
        _token, saved, snapshot, draft = await self.frame(binding, message, root)
        return await self.render(binding, message, locale, root, saved, snapshot, draft)

    async def render(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        root: str,
        saved: PendingInteraction,
        snapshot: InteractionSnapshot,
        draft: DraftView,
        *,
        field_id: str | None = None,
        page: int = 1,
    ) -> str:
        active = [
            field
            for field in snapshot.fields
            if active_field(field, snapshot.fields, draft.answers)
        ]
        if any(
            field.hidden or (field.format or "").lower() in {"password", "secret", "credential"}
            for field in active
        ):
            body = self.tr.render("form.use_tui", locale)
            if self.can_cancel(binding):
                entry = await self.tokens.issue(
                    "form-cancel-entry",
                    message.realm_id,
                    message.author_id,
                    {"root": root, "revision": draft.revision, "fingerprint": draft.fingerprint()},
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    ttl=max(1, min(900, int(saved.expires_at - time.time()))),
                )
                body += "\n\n" + self.tr.render("form.cancel_hint", locale, token=literal(entry))
            return body
        selected = (
            next((field for field in active if field.id == field_id), None)
            if field_id
            else next(
                (
                    field
                    for field in active
                    if field.id not in draft.answers and field.id not in draft.skipped
                ),
                None,
            )
        )
        if field_id and selected is None:
            raise Conflict("form_field_inactive")
        context = {"root": root, "revision": draft.revision, "fingerprint": draft.fingerprint()}
        if selected is not None:
            pages = max(1, (len(selected.choices) + 9) // 10)
            if type(page) is not int or not 1 <= page <= pages:
                raise ValueError("form_page_unavailable")
            context.update(field=selected.id, page=page)
            # Complete constraints are displayed, but native pattern/format validation
            # stays at the backend. Defaults and external URLs are never selected/fetched.
            detail = {
                "request": snapshot.description,
                "field": selected.model_dump(mode="json", exclude={"external_url", "choices"}),
                "choices": [
                    {"number": index + 1, "id": choice.id, "label": choice.label}
                    for index, choice in enumerate(selected.choices)
                    if (page - 1) * 10 <= index < page * 10
                ],
            }
            title = self.tr.render(
                "form.step",
                locale,
                index=snapshot.fields.index(selected) + 1,
                total=len(snapshot.fields),
                page=page,
                pages=pages,
            )
            kind = "form-step"
        else:
            validate_answers(snapshot.fields, draft.answers)
            detail = {
                "request": snapshot.description,
                "answers": [
                    {
                        "number": snapshot.fields.index(field) + 1,
                        "field": field.label,
                        "answer": answer_value(field, draft.answers[field.id])
                        if field.id in draft.answers
                        else {"omitted": True},
                        "selected_labels": [
                            choice.label
                            for choice in field.choices
                            if field.id in draft.answers
                            and choice.id in draft.answers[field.id].selected
                        ],
                    }
                    for field in active
                ],
            }
            title, kind = self.tr.render("form.review", locale), "form-submit"
        detail["scope"] = {
            "backend": binding.backend_id,
            "project": binding.project_id,
            "workspace": binding.canonical_directory,
            "bound_session": binding.session_id,
            "requesting_session": snapshot.reference.upstream_session_id,
            "native_request": snapshot.upstream_request_id,
        }
        try:
            redacted = redact_json(detail)
        except RedactionError:
            return self.tr.render("form.use_tui", locale)
        body = (
            title
            + "\n\n"
            + code_block(json.dumps(redacted.value, ensure_ascii=False, indent=2), "json")
        )
        if redacted.redactions:
            body += "\n\n" + self.tr.render("form.redacted", locale)
        if redacted.control_escapes:
            body += "\n\n" + self.tr.render("pending.controls_escaped", locale)
        if len(body) > 1000000 - 4096:
            return self.tr.render("form.use_tui", locale)
        token = await self.tokens.issue(
            kind,
            message.realm_id,
            message.author_id,
            context,
            binding_id=binding.id,
            binding_revision=binding.revision,
            ttl=max(1, min(900, int(saved.expires_at - time.time()))),
        )
        help_text = self.tr.render(
            "form.step_help" if selected else "form.review_help", locale, token=literal(token)
        )
        if self.can_cancel(binding):
            help_text += "\n\n" + self.tr.render("form.cancel_hint", locale, token=literal(token))
        return body + "\n\n" + help_text

    async def answer(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        # Keep the answer suffix byte-for-byte, including literal spaces/newlines.
        match = re.fullmatch(r"([A-Za-z0-9_-]{32})(?:[ \t]|\n)([\s\S]*)", arguments)
        if not match:
            raise ValueError("form_answer_syntax")
        opaque, raw = match.groups()
        step = await self.tokens.inspect_allowed(
            opaque, frozenset({"form-step", "form-submit"}), message.realm_id, message.author_id
        )
        if step.binding_id != binding.id or step.binding_revision != binding.revision:
            raise AccessDenied("form_token_outside_binding")
        root = step.context["root"]
        token, saved, snapshot, draft = await self.frame(binding, message, root)
        if (
            step.context.get("revision") != draft.revision
            or step.context.get("fingerprint") != draft.fingerprint()
        ):
            raise Conflict("form_draft_revision_changed")
        if step.kind == "form-submit":
            if raw == "submit":
                await self.interactions.reply(
                    root,
                    message.realm_id,
                    message.author_id,
                    answers=draft.answers,
                    source=message,
                    confirmation=step,
                    draft_revision=draft.revision,
                )
                return self.tr.render("form.queued", locale)
            edit = re.fullmatch(r"edit ([0-9]{1,6})", raw, flags=re.ASCII)
            if not edit or not 1 <= int(edit[1]) <= len(snapshot.fields):
                raise ValueError("form_review_command_required")
            edit_field = snapshot.fields[int(edit[1]) - 1]
            if not active_field(edit_field, snapshot.fields, draft.answers):
                raise Conflict("form_edit_field_inactive")
            await self.tokens.consume(opaque, "form-submit", message.realm_id, message.author_id)
            return await self.render(
                binding, message, locale, root, saved, snapshot, draft, field_id=edit_field.id
            )
        field = next(
            (field for field in snapshot.fields if field.id == step.context.get("field")), None
        )
        if field is None or not active_field(field, snapshot.fields, draft.answers):
            raise Conflict("form_field_inactive")
        page_match = re.fullmatch(r"/page ([0-9]{1,6})", raw, flags=re.ASCII)
        if page_match:
            page = int(page_match[1])
            if not 1 <= page <= max(1, (len(field.choices) + 9) // 10):
                raise ValueError("form_page_unavailable")
            await self.tokens.consume(opaque, "form-step", message.realm_id, message.author_id)
            return await self.render(
                binding, message, locale, root, saved, snapshot, draft, field_id=field.id, page=page
            )
        if raw == "/skip":
            if field.required:
                return self.tr.render("form.cannot_skip", locale)
            answers = {key: value for key, value in draft.answers.items() if key != field.id}
            # Skipping an edited conditional source also removes dependent answers.
            answers = self.prune(snapshot, answers)
            skipped = skipped_fields(
                {"skipped": sorted(draft.skipped | {field.id})}, snapshot.fields, answers
            )
        else:
            try:
                answer = decode_answer(field, raw)
            except FormInputError as error:
                return self.tr.render(error.code, locale)
            answers = draft_answers(snapshot.fields, draft.answers, field.id, answer)
            skipped = skipped_fields({"skipped": sorted(draft.skipped)}, snapshot.fields, answers)
        changed = DraftView(draft.revision + 1, answers, skipped)
        await self.commit(binding, message, token, saved, step, draft, changed)
        return await self.render(binding, message, locale, root, saved, snapshot, changed)

    @staticmethod
    def prune(
        snapshot: InteractionSnapshot, candidates: dict[str, FieldAnswer]
    ) -> dict[str, FieldAnswer]:
        answers: dict[str, FieldAnswer] = {}
        for field in snapshot.fields:
            if field.id in candidates and active_field(field, snapshot.fields, answers):
                answers[field.id] = candidates[field.id]
        validate_answers(snapshot.fields, answers, complete=False)
        return answers

    async def commit(
        self,
        binding: Binding,
        message: HumanMessage,
        root: ControlToken,
        saved: PendingInteraction,
        step: ControlToken,
        before: DraftView,
        after: DraftView,
    ) -> None:
        key = digest({"request": saved.id, "user": message.author_id})
        async with self.db.sessions.begin() as session:
            if self.tokens.fence is not None:
                await self.tokens.fence.lock(session)
            current = await session.scalar(
                select(PendingInteraction.id).where(
                    PendingInteraction.id == saved.id,
                    PendingInteraction.state == "pending",
                    PendingInteraction.version == saved.version,
                    PendingInteraction.snapshot_hash == saved.snapshot_hash,
                    PendingInteraction.binding_revision == binding.revision,
                    PendingInteraction.expires_at > time.time(),
                )
            )
            live_root = await session.scalar(
                select(ControlToken.token_hash).where(
                    ControlToken.token_hash == root.token_hash,
                    ControlToken.context_hash == root.context_hash,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                )
            )
            if current is None or live_root is None:
                raise Conflict("form_no_longer_pending")
            await self.tokens.consume_in_session(session, step)
            values = {
                "answers": {k: v.model_dump(mode="json") for k, v in after.answers.items()},
                "progress": {"skipped": sorted(after.skipped)},
                "revision": after.revision,
            }
            existing = await session.get(FormDraft, key)
            if before.revision == 0:
                if existing is not None:
                    raise Conflict("form_draft_already_exists")
                session.add(
                    FormDraft(
                        key=key,
                        interaction_id=saved.id,
                        user_id=message.author_id,
                        snapshot_hash=saved.snapshot_hash,
                        **values,
                    )
                )
            else:
                changed = await session.execute(
                    update(FormDraft)
                    .where(
                        FormDraft.key == key,
                        FormDraft.revision == before.revision,
                        FormDraft.snapshot_hash == saved.snapshot_hash,
                        FormDraft.user_id == message.author_id,
                        FormDraft.interaction_id == saved.id,
                    )
                    .values(**values)
                )
                if changed.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("form_draft_changed")
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="form_draft_updated",
                    object_id=saved.id,
                )
            )

    def can_cancel(self, binding: Binding) -> bool:
        capability = (
            self.native_capabilities(reference(binding)).get("form.cancel")
            if self.native_capabilities
            else None
        )
        return capability is not None and capability.supported

    def cancel_unavailable(self, locale: Locale) -> str:
        return self.tr.render(
            "capability.unsupported",
            locale,
            capability="form.cancel",
            reason=self.tr.render("form.cancel_uncertified", locale),
        )

    async def prepare_cancel(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{32}", arguments):
            raise ValueError("form_cancel_token_required")
        step = await self.tokens.inspect_allowed(
            arguments,
            frozenset({"form-step", "form-submit", "form-cancel-entry"}),
            message.realm_id,
            message.author_id,
        )
        if step.binding_id != binding.id or step.binding_revision != binding.revision:
            raise AccessDenied("form_cancel_outside_binding")
        root = step.context["root"]
        _token, saved, snapshot, draft = await self.frame(binding, message, root)
        if (
            step.context.get("revision") != draft.revision
            or step.context.get("fingerprint") != draft.fingerprint()
        ):
            raise Conflict("form_cancel_draft_changed")
        if not self.can_cancel(binding):
            return self.cancel_unavailable(locale)
        try:
            preview = redact_json(
                {
                    "backend": binding.backend_id,
                    "project": binding.project_id,
                    "workspace": binding.canonical_directory,
                    "bound_session": binding.session_id,
                    "requesting_session": snapshot.reference.upstream_session_id,
                    "native_request": snapshot.upstream_request_id,
                    "description": snapshot.description,
                    "saved_answer_count": len(draft.answers),
                }
            )
        except RedactionError:
            return self.tr.render("form.use_tui", locale)
        body = (
            self.tr.render("form.cancel_preview", locale)
            + "\n\n"
            + code_block(json.dumps(preview.value, ensure_ascii=False, indent=2), "json")
        )
        if preview.redactions:
            body += "\n\n" + self.tr.render("form.redacted", locale)
        if len(body) > 1000000 - 2048:
            return self.tr.render("form.use_tui", locale)
        confirmation = await self.tokens.issue(
            "form-cancel",
            message.realm_id,
            message.author_id,
            {"root": root, "revision": draft.revision, "fingerprint": draft.fingerprint()},
            binding_id=binding.id,
            binding_revision=binding.revision,
            ttl=max(1, min(900, int(saved.expires_at - time.time()))),
        )
        return (
            body
            + "\n\n"
            + self.tr.render("form.cancel_confirm", locale, token=literal(confirmation))
        )

    async def confirm_cancel(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{32}", arguments):
            raise ValueError("form_cancel_confirmation_required")
        confirmation = await self.tokens.inspect(
            arguments, "form-cancel", message.realm_id, message.author_id
        )
        if (
            confirmation.binding_id != binding.id
            or confirmation.binding_revision != binding.revision
        ):
            raise AccessDenied("form_cancel_outside_binding")
        root = confirmation.context["root"]
        _token, _saved, _snapshot, draft = await self.frame(binding, message, root)
        if (
            confirmation.context.get("revision") != draft.revision
            or confirmation.context.get("fingerprint") != draft.fingerprint()
        ):
            raise Conflict("form_cancel_preview_changed")
        if not self.can_cancel(binding):
            return self.cancel_unavailable(locale)
        await self.interactions.reply(
            root,
            message.realm_id,
            message.author_id,
            source=message,
            confirmation=confirmation,
            draft_revision=draft.revision,
            cancel=True,
        )
        return self.tr.render("form.cancel_queued", locale)
