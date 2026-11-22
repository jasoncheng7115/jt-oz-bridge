"""Actor-bound Native provider/model menus and atomic one-use setting actions."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator
from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.model_catalog import (
    ModelCatalog,
    ModelSelection,
    NativeModelCatalog,
    NativeModelRef,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import literal, sanitize_controls
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.services import menu_shortcuts
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant

PAGE_KIND = "native-model-page"
CHOICE_KIND = "native-model-choice"
COMMANDS = frozenset({"models", "model", "variants", "variant"})


class ModelPage(ControlModel):
    reference: SessionRef
    route: Literal["providers", "models", "variants"]
    provider: str | None = Field(default=None, min_length=1, max_length=255)
    offset: StrictInt = Field(default=0, ge=0, le=4096)
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def provider_scope(self) -> Self:
        if (self.route == "models") != (self.provider is not None):
            raise ValueError("invalid_model_page_provider_scope")
        return self


def visible(value: str) -> str:
    normalized = sanitize_controls(value)[0].replace("\n", " ").replace("\t", " ")
    redacted, _ = redact_text(normalized)
    return literal(redacted if len(redacted) <= 240 else redacted[:239] + "…")


class ModelCommands:
    def __init__(
        self,
        bindings: BindingService,
        catalogs: Mapping[str, ModelCatalog],
        tokens: TokenService,
        reader: SourceReader,
        *,
        capabilities: CapabilityLookup | None = None,
    ) -> None:
        if tokens.db is not bindings.db or tokens.fence is None:
            raise ValueError("model_commands_require_shared_database_and_consumer_fence")
        self.bindings, self.db = bindings, bindings.db
        self.catalogs = MappingProxyType(dict(catalogs))
        self.tokens, self.reader, self.capabilities = tokens, reader, capabilities
        self.fence, self.tr = tokens.fence, Translator()

    async def current(
        self, binding: Binding, message: HumanMessage, permission: Permission = Permission.VIEW
    ) -> Binding:
        parsed = menu_shortcuts.current(message.text)
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
            raise Conflict("model_command_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, permission
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("model_command_binding_changed")
        return current

    def switch_available(self, binding: Binding) -> bool:
        capability = (
            self.capabilities(reference(binding)).get("model.switch")
            if self.capabilities is not None
            else None
        )
        return capability is not None and capability.supported

    async def catalog(self, binding: Binding, message: HumanMessage) -> NativeModelCatalog:
        await self.current(binding, message)
        client = self.catalogs.get(binding.backend_id)
        ref = reference(binding)
        if client is None or client.contract_for(ref) != self.bindings.control.contract_for(ref):
            raise Conflict("native_model_catalog_not_enrolled")
        raw = await client.read(ref)
        result = NativeModelCatalog.model_validate(raw.model_dump(mode="json"))
        await self.current(binding, message)
        if result.reference != ref or result.contract_sha256 != client.contract_for(ref):
            raise Conflict("native_model_catalog_scope_changed")
        return result

    async def issue(
        self, binding: Binding, message: HumanMessage, kind: str, context: ControlModel
    ) -> str:
        return await self.tokens.issue(
            kind,
            message.realm_id,
            message.author_id,
            context.model_dump(mode="json"),
            binding_id=binding.id,
            binding_revision=binding.revision,
        )

    async def consume_page(
        self, binding: Binding, message: HumanMessage, saved: ControlToken
    ) -> None:
        await self.current(binding, message)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            await self.tokens.consume_in_session(session, saved)

    def label(self, selected: NativeModelRef | None, locale: Locale) -> str:
        if selected is None:
            return self.tr.render("models.inherited", locale)
        return visible(
            selected.provider_id
            + "/"
            + selected.model_id
            + ("#" + selected.variant if selected.variant is not None else "")
        )

    async def page(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        catalog: NativeModelCatalog,
        page: ModelPage,
    ) -> str:
        fingerprint = digest(catalog.model_dump(mode="json"))
        if page.reference != catalog.reference or page.catalog_sha256 != fingerprint:
            raise Conflict("native_model_menu_catalog_changed")
        can_choose = self.switch_available(binding)
        try:
            await self.bindings.policy.require(
                message.realm_id, message.author_id, binding.project_id, Permission.OPERATE
            )
        except AccessDenied:
            can_choose = False
        lines = [
            self.tr.render(
                "models.current", locale, selection=self.label(catalog.selected, locale)
            ),
            self.tr.render("models.default", locale, selection=self.label(catalog.default, locale)),
        ]
        if page.route == "providers":
            providers = catalog.providers
            lines.insert(0, self.tr.render("models.providers", locale))
            for index, provider in enumerate(providers[page.offset : page.offset + 9], 1):
                token = await self.issue(
                    binding,
                    message,
                    PAGE_KIND,
                    page.model_copy(update={"route": "models", "provider": provider, "offset": 0}),
                )
                lines.append(
                    self.tr.render(
                        "models.provider_item",
                        locale,
                        index=index,
                        provider=visible(provider),
                        count=sum(x.reference.provider_id == provider for x in catalog.items),
                        token=token,
                    )
                )
            total = len(providers)
        else:
            targets: list[tuple[NativeModelRef, str]] = []
            if page.route == "models":
                lines.insert(
                    0,
                    self.tr.render("models.models", locale, provider=visible(page.provider or "")),
                )
                for item in catalog.items:
                    if item.reference.provider_id == page.provider:
                        targets.append(
                            (
                                item.reference,
                                self.tr.render(
                                    "models.model_label",
                                    locale,
                                    provider=visible(item.reference.provider_id),
                                    model=visible(item.reference.model_id),
                                    name=visible(item.name),
                                    status=self.tr.render("models.status." + item.status, locale),
                                ),
                            )
                        )
                origin: Literal["model", "variant"] = "model"
            else:
                if catalog.selected is None:
                    return self.tr.render("models.select_model_first", locale)
                selected = catalog.option(catalog.selected)
                if selected is None:
                    return self.tr.render("models.current_unavailable", locale)
                lines.insert(0, self.tr.render("models.variants", locale))
                targets = [
                    (selected.reference, self.tr.render("models.variant_default", locale)),
                    *(
                        (
                            selected.reference.model_copy(update={"variant": variant}),
                            visible(variant),
                        )
                        for variant in selected.variant_ids
                        if variant != "default"
                    ),
                ]
                origin = "variant"
            total = len(targets)
            for index, (target, label) in enumerate(targets[page.offset : page.offset + 9], 1):
                marker = ""
                if catalog.selected is not None and (
                    target.same_native_selection(catalog.selected)
                    if origin == "variant"
                    else (target.provider_id, target.model_id)
                    == (catalog.selected.provider_id, catalog.selected.model_id)
                ):
                    marker = self.tr.render("models.selected", locale)
                text = f"{index}. {label}{marker}"
                if can_choose:
                    token = await self.issue(
                        binding,
                        message,
                        CHOICE_KIND,
                        ModelSelection(
                            origin=origin,
                            target=target,
                            previous=catalog.selected,
                            catalog_sha256=fingerprint,
                        ),
                    )
                    text += "\n" + self.tr.render(
                        "models.choose", locale, command=origin, token=token
                    )
                lines.append(text)
        if total == 0:
            lines.append(self.tr.render("models.empty", locale))
        if page.offset and page.offset >= total:
            raise Conflict("native_model_menu_offset_changed")
        if page.offset + 9 < total:
            token = await self.issue(
                binding, message, PAGE_KIND, page.model_copy(update={"offset": page.offset + 9})
            )
            lines.append(
                self.tr.render(
                    "models.more",
                    locale,
                    command="variants" if page.route == "variants" else "models",
                    token=token,
                )
            )
        if not can_choose:
            lines.append(self.tr.render("models.selection_unavailable", locale))
        await self.current(binding, message)
        return "\n\n".join(lines)

    async def choose(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, token: str
    ) -> str:
        binding = await self.current(binding, message, Permission.OPERATE)
        if not self.switch_available(binding):
            return self.tr.render("models.selection_unavailable", locale)
        saved = await self.tokens.inspect(token, CHOICE_KIND, message.realm_id, message.author_id)
        if saved.binding_id != binding.id or saved.binding_revision != binding.revision:
            raise Conflict("model_selection_binding_changed")
        choice = ModelSelection.model_validate(saved.context)
        catalog = await self.catalog(binding, message)
        if (
            choice.origin != command
            or choice.catalog_sha256 != digest(catalog.model_dump(mode="json"))
            or choice.previous != catalog.selected
            or catalog.option(choice.target) is None
        ):
            raise Conflict("model_selection_catalog_changed")
        binding = await self.current(binding, message, Permission.OPERATE)
        payload = {
            "operation": "model.switch",
            "reference": reference(binding).model_dump(mode="json"),
            "source": message.model_dump(mode="json"),
            "selection": choice.model_dump(mode="json"),
            "selection_token_sha256": saved.token_hash,
            "reply_locale": locale,
        }
        if (row := menu_shortcuts.EXPANDED.get()) is not None:
            payload["shortcut"] = row  # the phone's `!N` named this model row
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            current = await lock_output_scope(self.bindings, session, binding)
            grant = await session.scalar(
                select(Grant.id)
                .where(
                    Grant.realm_id == message.realm_id,
                    Grant.user_id == message.author_id,
                    Grant.project_id == binding.project_id,
                    Grant.active.is_(True),
                    Grant.role.in_(
                        [r for r, permissions in ROLES.items() if Permission.OPERATE in permissions]
                    ),
                )
                .with_for_update()
            )
            if grant is None:
                raise AccessDenied("model_selection_operate_grant_changed")
            await self.tokens.consume_in_session(session, saved)
            action = Action(
                dedupe_key="model-choice:" + saved.token_hash,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=message.author_id,
                payload=payload,
                operation="model.switch",
                operation_digest=digest(payload),
                state="held" if current.dispatch_paused else "queued",
            )
            session.add(action)
            await session.flush()
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="model_setting_queued",
                    object_id=action.id,
                )
            )
        return self.tr.render(
            "action.held" if action.state == "held" else "action.received",
            locale,
        )

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        parsed = menu_shortcuts.current(message.text)
        if parsed.command != command or parsed.arguments != arguments or command not in COMMANDS:
            raise Conflict("model_command_source_does_not_match_route")
        parts = arguments.split()
        if len(parts) > 1 or parts and len(parts[0]) > 128:
            raise ValueError("model_command_requires_one_opaque_token")
        if command in {"model", "variant"}:
            if not parts:
                raise ValueError("model_selection_token_required")
            return await self.choose(binding, message, locale, command, parts[0])
        catalog = await self.catalog(binding, message)
        if parts:
            saved = await self.tokens.inspect(
                parts[0], PAGE_KIND, message.realm_id, message.author_id
            )
            if saved.binding_id != binding.id or saved.binding_revision != binding.revision:
                raise Conflict("model_page_binding_changed")
            page = ModelPage.model_validate(saved.context)
            if (command == "variants") != (page.route == "variants"):
                raise Conflict("model_page_command_changed")
            if page.reference != reference(binding) or page.catalog_sha256 != digest(
                catalog.model_dump(mode="json")
            ):
                raise Conflict("model_page_catalog_changed")
            await self.consume_page(binding, message, saved)
        else:
            page = ModelPage(
                reference=reference(binding),
                route="variants" if command == "variants" else "providers",
                catalog_sha256=digest(catalog.model_dump(mode="json")),
            )
        return await self.page(binding, message, locale, catalog, page)
