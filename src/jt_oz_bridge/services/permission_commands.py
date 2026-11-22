"""Actor-bound pending menus and explicit permission decisions, never direct POSTs."""

import json
import re
import time
from typing import Literal

from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import InteractionSnapshot, QuestionField, validate_answers
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.form_input import FormInputError, decode_answer
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import code_block, literal
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.redaction import (
    RedactedJSON,
    RedactionError,
    redact_json,
    visible_controls,
)
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.form_wizard import FormWizard
from jt_oz_bridge.services.interactions import InteractionService, short_code
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, PendingInteraction
from jt_oz_bridge.storage.durable import Conflict

QUICK_CODE = re.compile(r"[0-9]{4}")
QUICK_ANSWER = re.compile(r"([0-9]{4})(?:[ \t]|\n)([\s\S]*)")
QUICK_KINDS = frozenset({"single", "multi", "boolean", "text", "integer", "number"})
QUICK_HINTS = {
    "single": "form.quick_choice",
    "multi": "form.quick_multi",
    "boolean": "form.quick_boolean",
    "text": "form.quick_text",
    "integer": "form.quick_number",
    "number": "form.quick_number",
}
NOTICE_LIMIT = 3000


def escaped(value: object) -> str:
    return literal(visible_controls(str(value))[0])


def permission_notice(
    tr: Translator, snapshot: InteractionSnapshot, interaction_id: str, locale: Locale
) -> str | None:
    """The whole decision in one message, or None when chat cannot show it safely."""
    if snapshot.kind != "permission":
        return None
    try:
        shown = redact_json(
            {
                "operation": snapshot.operation or snapshot.description,
                "description": snapshot.description,
                "resources": list(snapshot.resources),
            }
        )
    except RedactionError:
        return None
    values = shown.value
    body = tr.render("permission.notice", locale, operation=escaped(values["operation"]))
    if values["description"] != values["operation"]:
        body += "\n\n" + escaped(values["description"])
    if values["resources"]:
        body += "\n\n" + "\n\n".join(code_block(item, "text") for item in values["resources"])
    details = snapshot.permission_details
    if shown.redactions or details and details.redactions:
        body += "\n\n" + tr.render("pending.redacted", locale)
    if shown.control_escapes or details and details.control_escapes:
        body += "\n\n" + tr.render("pending.controls_escaped", locale)
    body += "\n\n" + tr.render("permission.quick", locale, code=short_code(interaction_id))
    return body if len(body) <= NOTICE_LIMIT else None


def permission_widget(
    tr: Translator, snapshot: InteractionSnapshot, interaction_id: str, locale: Locale
) -> str | None:
    """Desktop and web show these buttons instead of the text; a click sends the same reply."""
    try:
        shown = redact_json(
            {
                "operation": snapshot.operation or snapshot.description,
                "description": snapshot.description,
                "resources": list(snapshot.resources),
            }
        )
    except RedactionError:
        return None
    values = shown.value
    facts = [tr.render("permission.notice", locale, operation=values["operation"])]
    if values["description"] != values["operation"]:
        facts.append(values["description"])
    facts.extend(values["resources"])
    details = snapshot.permission_details
    if shown.redactions or details and details.redactions:
        facts.append(tr.render("pending.redacted", locale))
    heading = " · ".join(" ".join(str(fact).split()) for fact in facts)
    if len(heading) > NOTICE_LIMIT:
        return None
    code = short_code(interaction_id)
    return json.dumps(
        {
            "widget_type": "zform",
            "extra_data": {
                "type": "choices",
                "heading": heading,
                "choices": [
                    {
                        "type": "multiple_choice",
                        "short_name": "1",
                        "long_name": tr.render("permission.button_once", locale),
                        "reply": f"!ok {code}",
                    },
                    {
                        "type": "multiple_choice",
                        "short_name": "2",
                        "long_name": tr.render("permission.button_reject", locale),
                        "reply": f"!no {code}",
                    },
                ],
            },
        },
        ensure_ascii=False,
    )


def with_requester(
    widget: str | None, tr: Translator, locale: Locale, parent: str, session: str
) -> str | None:
    """Buttons replace the notice text on desktop, so they also name a descendant requester.

    None when the heading would grow past the limit: the full text, which names it, is shown.
    """
    if widget is None:
        return None
    value = json.loads(widget)
    line = tr.render(
        "runtime.pending_requester",
        locale,
        parent=visible_controls(parent)[0],
        session=visible_controls(session)[0],
    )
    heading = value["extra_data"]["heading"] + " · " + " ".join(line.split())
    if len(heading) > NOTICE_LIMIT:
        return None
    value["extra_data"]["heading"] = heading
    return json.dumps(value, ensure_ascii=False)


def quick_field(snapshot: InteractionSnapshot) -> QuestionField | None:
    """A one-question form that a single chat message can answer completely."""
    if snapshot.kind != "form" or len(snapshot.fields) != 1:
        return None
    field = snapshot.fields[0]
    if (
        field.kind not in QUICK_KINDS
        or field.hidden
        or field.when
        or (field.format or "").lower() in {"password", "secret", "credential"}
        or field.kind in {"single", "multi"}
        and not 1 <= len(field.choices) <= 10
    ):
        return None
    return field


def _question(snapshot: InteractionSnapshot, field: QuestionField) -> RedactedJSON:
    return redact_json(
        {
            "title": snapshot.description,
            "label": field.label,
            "description": field.description,
            "choices": [choice.label for choice in field.choices],
        }
    )


def form_notice(
    tr: Translator, snapshot: InteractionSnapshot, interaction_id: str, locale: Locale
) -> str | None:
    """The question, its options and the one reply that answers it, or None."""
    field = quick_field(snapshot)
    if field is None:
        return None
    try:
        shown = _question(snapshot, field)
    except RedactionError:
        return None
    values = shown.value
    body = tr.render("form.notice", locale, title=escaped(values["title"]))
    if values["label"] and values["label"] != values["title"]:
        body += "\n\n**" + escaped(values["label"]) + "**"
    if values["description"]:
        body += "\n\n" + escaped(values["description"])
    if values["choices"]:
        body += "\n\n" + "\n".join(
            f"{index}. {escaped(label)}" for index, label in enumerate(values["choices"], 1)
        )
    if shown.redactions:
        body += "\n\n" + tr.render("form.redacted", locale)
    if shown.control_escapes:
        body += "\n\n" + tr.render("pending.controls_escaped", locale)
    code = short_code(interaction_id)
    body += "\n\n" + tr.render(QUICK_HINTS[field.kind], locale, code=code)
    if field.allow_custom_text:
        body += "\n\n" + tr.render("form.quick_custom", locale, code=code)
    body += "\n\n" + tr.render("form.quick_more", locale)
    return body if len(body) <= NOTICE_LIMIT else None


def form_widget(
    tr: Translator, snapshot: InteractionSnapshot, interaction_id: str, locale: Locale
) -> str | None:
    """Buttons for a single choice or yes/no; other answers are typed."""
    field = quick_field(snapshot)
    if field is None or field.kind not in {"single", "boolean"}:
        return None
    try:
        shown = _question(snapshot, field)
    except RedactionError:
        return None
    values, code = shown.value, short_code(interaction_id)
    facts = [tr.render("form.notice", locale, title=values["title"])]
    facts += [values["label"]] if values["label"] != values["title"] else []
    facts += [values["description"]] if values["description"] else []
    if shown.redactions:
        facts.append(tr.render("form.redacted", locale))
    if field.allow_custom_text:
        facts.append(tr.render("form.quick_custom", locale, code=code).replace("`", ""))
    heading = " · ".join(" ".join(str(fact).split()) for fact in facts if fact)
    options = (
        [(label, str(index)) for index, label in enumerate(values["choices"], 1)]
        if field.kind == "single"
        else [
            (tr.render("form.button_yes", locale), "yes"),
            (tr.render("form.button_no", locale), "no"),
        ]
    )
    if len(heading) > NOTICE_LIMIT:
        return None
    return json.dumps(
        {
            "widget_type": "zform",
            "extra_data": {
                "type": "choices",
                "heading": heading,
                "choices": [
                    {
                        "type": "multiple_choice",
                        "short_name": str(index),
                        "long_name": " ".join(str(label).split())[:200],
                        "reply": f"!a {code} {answer}",
                    }
                    for index, (label, answer) in enumerate(options, 1)
                ],
            },
        },
        ensure_ascii=False,
    )


class PermissionCommands:
    def __init__(
        self,
        bindings: BindingService,
        tokens: TokenService,
        *,
        capabilities: CapabilityLookup | None = None,
    ) -> None:
        self.bindings, self.db, self.tokens = bindings, bindings.db, tokens
        self.interactions = InteractionService(bindings, fence=tokens.fence)
        self.tr = Translator()
        self.forms = FormWizard(bindings, tokens, capabilities=capabilities)

    async def pending(
        self, binding: Binding, message: HumanMessage, locale: Locale, *, after: str | None = None
    ) -> str:
        async with self.db.sessions() as session:
            query = select(PendingInteraction).where(
                PendingInteraction.binding_id == binding.id,
                PendingInteraction.binding_revision == binding.revision,
                PendingInteraction.state == "pending",
            )
            if after is not None:
                query = query.where(PendingInteraction.id > after)
            rows = list(
                (await session.scalars(query.order_by(PendingInteraction.id).limit(10))).all()
            )
        if not rows:
            return self.tr.render("pending.empty", locale)
        shown = rows[:9]
        entries = []
        for index, row in enumerate(shown, 1):
            snapshot = InteractionSnapshot.model_validate(row.snapshot)
            try:
                description = redact_json(snapshot.description).value.replace("\n", " ")[:120]
            except RedactionError:
                description = self.tr.render("pending.preview_unavailable_short", locale)
            entries.append(
                f"{index}. "
                + self.tr.render("pending." + snapshot.kind, locale)
                + ": "
                + escaped(description)
                + (
                    " — " + self.tr.render("pending.expired", locale)
                    if row.expires_at <= time.time()
                    else ""
                )
                + self.quick_hint(snapshot, row.id, locale)
            )
        more = shown[-1].id if len(rows) > 9 else None
        if more:
            entries.append(f"{len(shown) + 1}. " + self.tr.render("pending.more", locale))
        token = await self.tokens.issue(
            "interaction-page",
            message.realm_id,
            message.author_id,
            {"ids": [row.id for row in shown], "after": more},
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return (
            self.tr.render("pending.title", locale)
            + "\n\n"
            + "\n".join(entries)
            + "\n\n"
            + self.tr.render("menu.choose", locale, menu_id=literal(token), item_number=1)
        )

    def quick_hint(self, snapshot: InteractionSnapshot, identity: str, locale: Locale) -> str:
        """The one-message reply for a row, so a phone can answer from the list."""
        code = short_code(identity)
        if permission_notice(self.tr, snapshot, identity, locale) is not None:
            return " · " + self.tr.render("pending.quick_permission", locale, code=code)
        if form_notice(self.tr, snapshot, identity, locale) is not None:
            return " · " + self.tr.render("pending.quick_form", locale, code=code)
        return ""

    async def choose(
        self, binding: Binding, message: HumanMessage, locale: Locale, token: str, index: int
    ) -> str:
        saved = await self.tokens.inspect(
            token, "interaction-page", message.realm_id, message.author_id
        )
        if saved.binding_id != binding.id or saved.binding_revision != binding.revision:
            raise AccessDenied("pending_menu_outside_binding")
        identities = saved.context.get("ids")
        after = saved.context.get("after")
        if (
            not isinstance(identities, list)
            or not 1 <= len(identities) <= 9
            or any(not isinstance(identity, str) or len(identity) > 36 for identity in identities)
            or not 1 <= index <= len(identities) + (1 if after else 0)
        ):
            raise Conflict("pending_menu_changed")
        context = await self.tokens.consume(
            token, "interaction-page", message.realm_id, message.author_id
        )
        if index > len(identities):
            if not isinstance(context["after"], str):
                raise Conflict("pending_cursor_changed")
            return await self.pending(binding, message, locale, after=context["after"])
        return await self.open(binding, message, locale, identities[index - 1])

    async def open(
        self, binding: Binding, message: HumanMessage, locale: Locale, interaction_id: str
    ) -> str:
        async with self.db.sessions() as session:
            scoped = await session.get(PendingInteraction, interaction_id)
        if (
            not scoped
            or scoped.binding_id != binding.id
            or scoped.binding_revision != binding.revision
        ):
            raise AccessDenied("interaction_outside_current_topic")
        refreshed = await self.interactions.refresh_expired(
            interaction_id, message.realm_id, message.author_id
        )
        saved = await self.interactions.request(interaction_id)
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        if snapshot.kind == "form":
            return (
                self.tr.render("pending.refreshed", locale) + "\n\n" if refreshed else ""
            ) + await self.forms.open(binding, message, locale, interaction_id)
        await self.interactions.lineage(binding, snapshot)
        current = await self.bindings.control.interaction(
            snapshot.reference, snapshot.upstream_request_id
        )
        if current != snapshot or not current.pending:
            raise Conflict("permission_changed_upstream")
        details = snapshot.permission_details
        try:
            shown = redact_json(
                {
                    "description": snapshot.description,
                    "operation": snapshot.operation or snapshot.description,
                    "resources": list(snapshot.resources),
                    "scopes": list(snapshot.requested_scope),
                    "metadata": json.loads(details.metadata_json)
                    if details and details.metadata_json is not None
                    else None,
                    "requester": json.loads(details.requester_json)
                    if details and details.requester_json is not None
                    else None,
                }
            )
        except (RedactionError, json.JSONDecodeError):
            return self.tr.render("pending.preview_unavailable", locale)
        values = shown.value
        resources = "\n\n".join(
            code_block(item, "text") for item in values["resources"]
        ) or self.tr.render("pending.not_provided", locale)
        scopes = "\n\n".join(
            code_block(item, "text") for item in values["scopes"]
        ) or self.tr.render("pending.not_provided", locale)
        body = (
            self.tr.render("pending.refreshed", locale) + "\n\n" if refreshed else ""
        ) + self.tr.render(
            "pending.preview",
            locale,
            backend=escaped(binding.backend_id),
            project=escaped(binding.project_id),
            directory=escaped(binding.canonical_directory),
            parent=escaped(binding.session_id),
            session=escaped(snapshot.reference.upstream_session_id),
            request=escaped(snapshot.upstream_request_id),
            operation=escaped(values["operation"]),
            description=escaped(values["description"]),
            resources=resources,
            scopes=scopes,
        )
        for key, label in (("requester", "pending.requester"), ("metadata", "pending.metadata")):
            value = values[key]
            body += (
                "\n\n"
                + self.tr.render(label, locale)
                + "\n\n"
                + (
                    code_block(json.dumps(value, ensure_ascii=False, indent=2), "json")
                    if value is not None
                    else self.tr.render("pending.not_provided", locale)
                )
            )
        if shown.redactions or details and details.redactions:
            body += "\n\n" + self.tr.render("pending.redacted", locale)
        if shown.control_escapes or details and details.control_escapes:
            body += "\n\n" + self.tr.render("pending.controls_escaped", locale)
        if len(body) > 1000000 - 2048:
            return self.tr.render("pending.preview_too_large", locale)
        token = await self.interactions.issue(saved.id, message.realm_id, message.author_id)
        return (
            body
            + "\n\n"
            + self.tr.render("permission.once", locale, request_token=literal(token))
            + "\n\n"
            + self.tr.render("permission.deny", locale, request_token=literal(token))
            + (
                "\n\n" + self.tr.render("permission.quick", locale, code=short_code(saved.id))
                if permission_notice(self.tr, snapshot, saved.id, locale) is not None
                else ""
            )
        )

    async def decide(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        parts = arguments.split(maxsplit=1)
        if not parts:
            # A bare `!ok` names no request; show what is waiting instead of guessing.
            return await self.pending(binding, message, locale)
        if QUICK_CODE.fullmatch(parts[0]):
            return await self.decide_by_code(binding, message, locale, command, parts)
        token = parts[0]
        saved = await self.tokens.inspect(token, "interaction", message.realm_id, message.author_id)
        if saved.binding_id != binding.id or saved.binding_revision != binding.revision:
            raise AccessDenied("permission_token_outside_current_topic")
        request = await self.interactions.request(saved.context["interaction_id"])
        if InteractionSnapshot.model_validate(request.snapshot).kind != "permission":
            raise AccessDenied("permission_decision_cannot_answer_form")
        decision: Literal["once", "reject"]
        reason: str | None
        if command == "approve":
            if len(parts) != 2 or parts[1] != "once":
                raise AccessDenied("broad_permission_disabled")
            decision, reason = "once", None
        elif command == "deny":
            decision, reason = "reject", parts[1] if len(parts) == 2 else None
        else:
            raise ValueError("unknown_permission_decision")
        await self.interactions.reply(
            token,
            message.realm_id,
            message.author_id,
            decision=decision,
            reason=reason,
            source=message,
        )
        return self.tr.render("action.received", locale)

    async def decide_by_code(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        command: str,
        parts: list[str],
    ) -> str:
        """Answer the notice that showed this code, under the same checks as a token."""
        saved = await self.by_code(binding, parts[0])
        if saved is None:
            return self.tr.render("permission.resolved", locale)
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        if snapshot.kind != "permission":
            raise AccessDenied("permission_decision_cannot_answer_form")
        # Only a request chat could show in full may be decided from chat.
        if permission_notice(self.tr, snapshot, saved.id, locale) is None:
            return self.tr.render("pending.preview_unavailable", locale)
        decision: Literal["once", "reject"]
        reason: str | None
        if command == "approve":
            if len(parts) != 2 or parts[1] != "once":
                raise AccessDenied("broad_permission_disabled")
            decision, reason = "once", None
        elif command == "deny":
            decision, reason = "reject", parts[1] if len(parts) == 2 else None
        else:
            raise ValueError("unknown_permission_decision")
        await self.interactions.refresh_expired(saved.id, message.realm_id, message.author_id)
        token = await self.interactions.issue(saved.id, message.realm_id, message.author_id)
        await self.interactions.reply(
            token,
            message.realm_id,
            message.author_id,
            decision=decision,
            reason=reason,
            source=message,
            code=parts[0],
        )
        return self.tr.render("action.received", locale)

    async def by_code(self, binding: Binding, code: str) -> PendingInteraction | None:
        """The one waiting request in this topic whose notice showed `code`."""
        async with self.db.sessions() as session:
            rows = list(
                (
                    await session.scalars(
                        select(PendingInteraction)
                        .where(
                            PendingInteraction.binding_id == binding.id,
                            PendingInteraction.binding_revision == binding.revision,
                            PendingInteraction.state == "pending",
                        )
                        .order_by(PendingInteraction.id)
                        .limit(1000)
                    )
                ).all()
            )
        matched = [row for row in rows if short_code(row.id) == code]
        if len(matched) > 1:
            raise Conflict("permission_code_ambiguous")
        return matched[0] if matched else None

    async def answer_by_code(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        """`!a <code> <answer>` answers a one-question form from its notice."""
        match = QUICK_ANSWER.fullmatch(arguments)
        if not match:
            raise ValueError("form_answer_syntax")
        code, raw = match.groups()
        saved = await self.by_code(binding, code)
        if saved is None:
            return self.tr.render("permission.resolved", locale)
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        if snapshot.kind != "form":
            raise AccessDenied("form_answer_cannot_decide_permission")
        field = quick_field(snapshot)
        if field is None or form_notice(self.tr, snapshot, saved.id, locale) is None:
            return self.tr.render("form.quick_unavailable", locale)
        try:
            answer = decode_answer(field, raw)
            validate_answers(snapshot.fields, {field.id: answer})
        except FormInputError as error:
            return self.tr.render(error.code, locale)
        except ValueError:
            return self.tr.render("form.invalid_answer", locale)
        await self.interactions.refresh_expired(saved.id, message.realm_id, message.author_id)
        token = await self.interactions.issue(saved.id, message.realm_id, message.author_id)
        await self.interactions.reply(
            token,
            message.realm_id,
            message.author_id,
            answers={field.id: answer},
            source=message,
            code=code,
        )
        return self.tr.render("form.queued", locale)
