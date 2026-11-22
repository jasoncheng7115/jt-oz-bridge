"""Actor-bound fixed-check choices; chat never supplies a shell command."""

from collections.abc import Mapping
from types import MappingProxyType

from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.checks import CheckCatalog, CheckReader, CheckSelection
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant

CHOICE_KIND = "native-check-choice"
PAGE_KIND = "native-check-page"


class CheckCommands:
    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, CheckReader],
        tokens: TokenService,
        reader: SourceReader,
        capabilities: CapabilityLookup,
        *,
        message_limit: int = 10000,
    ) -> None:
        if tokens.db is not bindings.db or tokens.fence is None or message_limit < 512:
            raise ValueError("check_commands_shared_fence_and_output_budget_required")
        self.bindings, self.db, self.reader = bindings, bindings.db, reader
        self.readers, self.tokens = MappingProxyType(dict(readers)), tokens
        self.capabilities, self.fence = capabilities, tokens.fence
        self.message_limit, self.tr = message_limit, Translator()

    def available(self, binding: Binding) -> bool:
        try:
            target = self.readers.get(reference(binding))
            capability = self.capabilities(reference(binding)).get("check.run")
            return bool(target is not None and capability is not None and capability.supported)
        except ValueError:
            return False

    async def current(
        self, binding: Binding, message: HumanMessage, *, operate: bool = False
    ) -> Binding:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in {"checks", "check"}
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("check_original_human_source_changed")
        current = await self.bindings.get(
            binding.id,
            message.realm_id,
            message.author_id,
            Permission.OPERATE if operate else Permission.VIEW,
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("check_original_binding_changed")
        return current

    def catalog(self, binding: Binding) -> CheckCatalog:
        reader = self.readers.get(reference(binding))
        if reader is None:
            raise Conflict("check_original_reader_missing")
        catalog = CheckCatalog.model_validate(
            reader.catalog(reference(binding)).model_dump(mode="python")
        )
        if catalog.reference != reference(
            binding
        ) or catalog.contract_sha256 != self.bindings.control.contract_for(reference(binding)):
            raise Conflict("check_original_catalog_scope_changed")
        return catalog

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, command: str, arguments: str
    ) -> str:
        binding = await self.current(binding, message, operate=command == "check")
        parsed = parse_input(message.text, bound=True)
        if parsed.command != command or parsed.arguments != arguments:
            raise Conflict("check_original_route_changed")
        if not self.available(binding):
            return self.tr.render("checks.unavailable", locale)
        catalog = self.catalog(binding)
        checksum = digest(catalog.model_dump(mode="json"))
        if command == "checks":
            offset = 0
            if arguments:
                saved = await self.tokens.inspect(
                    arguments, PAGE_KIND, message.realm_id, message.author_id
                )
                if (
                    saved.binding_id != binding.id
                    or saved.binding_revision != binding.revision
                    or saved.context
                    != {
                        "reference": reference(binding).model_dump(mode="json"),
                        "catalog_sha256": checksum,
                        "offset": saved.context.get("offset"),
                        "message_limit": self.message_limit,
                    }
                ):
                    raise Conflict("check_page_scope_changed")
                offset = saved.context["offset"]
                if type(offset) is not int or not 0 < offset < len(catalog.checks):
                    raise Conflict("check_page_offset_changed")
                await self.tokens.consume(arguments, PAGE_KIND, message.realm_id, message.author_id)
            can_run = True
            try:
                await self.bindings.policy.require(
                    message.realm_id, message.author_id, binding.project_id, Permission.OPERATE
                )
            except AccessDenied:
                can_run = False
            lines = [self.tr.render("checks.title", locale)]
            # One choice per page keeps literal titles and 32-character controls
            # readable under the verified minimum512-character Zulip contract.
            selected = catalog.checks[offset : offset + 1]
            for check in selected:
                cap = 20 if self.message_limit < 1000 else 80 if self.message_limit < 2000 else 120
                lines.append(
                    visible(
                        check.title if len(check.title) <= cap else check.title[: cap - 1] + "…"
                    )
                )
                lines.append(
                    self.tr.render(
                        "checks.definition",
                        locale,
                        digest=digest(check.model_dump(mode="json"))[:16],
                    )
                )
                if can_run:
                    choice = CheckSelection(
                        reference=reference(binding),
                        check=check,
                        catalog_sha256=checksum,
                        qualification_sha256=self.readers[reference(binding)].qualification_for(
                            reference(binding)
                        ),
                    )
                    token = await self.tokens.issue(
                        CHOICE_KIND,
                        message.realm_id,
                        message.author_id,
                        choice.model_dump(mode="json"),
                        ttl=300,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                    )
                    lines.append(self.tr.render("checks.choose", locale, token=token))
            if not selected:
                lines.append(self.tr.render("checks.empty", locale))
            if offset + 1 < len(catalog.checks):
                token = await self.tokens.issue(
                    PAGE_KIND,
                    message.realm_id,
                    message.author_id,
                    {
                        "reference": reference(binding).model_dump(mode="json"),
                        "catalog_sha256": checksum,
                        "offset": offset + 1,
                        "message_limit": self.message_limit,
                    },
                    ttl=300,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                )
                lines.append(self.tr.render("checks.more", locale, token=token))
            if not can_run:
                lines.append(self.tr.render("checks.view_only", locale))
            await self.current(binding, message)
            text = "\n\n".join(lines)
            if len(text) > self.message_limit - 100:
                raise Conflict("check_menu_output_budget_exceeded")
            return text
        if command != "check" or len(arguments.split()) != 1:
            raise ValueError("check_choice_token_required")
        saved = await self.tokens.inspect(
            arguments, CHOICE_KIND, message.realm_id, message.author_id
        )
        choice = CheckSelection.model_validate(saved.context)
        if (
            saved.binding_id != binding.id
            or saved.binding_revision != binding.revision
            or choice.reference != reference(binding)
            or choice.catalog_sha256 != checksum
            or choice.check not in catalog.checks
            or choice.qualification_sha256
            != self.readers[reference(binding)].qualification_for(reference(binding))
        ):
            raise Conflict("check_choice_catalog_or_binding_changed")
        binding = await self.current(binding, message, operate=True)
        payload = {
            "operation": "check.run",
            "binding_id": binding.id,
            "binding_revision": binding.revision,
            "reference": reference(binding).model_dump(mode="json"),
            "source": message.model_dump(mode="json"),
            "selection": choice.model_dump(mode="json"),
            "selection_token_sha256": saved.token_hash,
            "choice_expires_at": saved.expires_at,
            "reply_locale": locale,
        }
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
                    Grant.role.in_([r for r, p in ROLES.items() if Permission.OPERATE in p]),
                )
                .with_for_update()
            )
            if grant is None:
                raise AccessDenied("check_operate_grant_changed")
            if not self.available(binding) or self.catalog(binding) != catalog:
                raise Conflict("check_capability_or_catalog_changed")
            await self.tokens.consume_in_session(session, saved, database_deadline=True)
            action = Action(
                dedupe_key="check-choice:" + saved.token_hash,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=message.author_id,
                operation="check.run",
                payload=payload,
                operation_digest=digest(payload),
                state="held" if current.dispatch_paused else "queued",
            )
            session.add(action)
            await session.flush()
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="project_check_queued",
                    object_id=action.id,
                )
            )
        return self.tr.render(
            "action.held" if action.state == "held" else "action.received",
            locale,
        )
