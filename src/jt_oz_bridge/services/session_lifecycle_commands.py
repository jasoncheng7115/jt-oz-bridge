"""Fresh Human lifecycle controls on a bound original session; never implicit creation."""

from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.domain.session_lifecycle import SessionRename
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant


class SessionLifecycleCommands:
    def __init__(
        self,
        bindings: BindingService,
        reader: SourceReader,
        fence: ConsumerFence,
        capabilities: CapabilityLookup,
    ) -> None:
        self.bindings, self.db, self.reader = bindings, bindings.db, reader
        self.fence, self.capabilities, self.tr = fence, capabilities, Translator()

    def available(self, binding: Binding, command: str) -> bool:
        if command != "rename":
            return False
        try:
            capability = self.capabilities(reference(binding)).get("session.rename")
            return capability is not None and capability.supported
        except ValueError:
            return False

    async def current(self, binding: Binding, message: HumanMessage) -> Binding:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "rename"
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("session_lifecycle_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("session_lifecycle_binding_changed")
        return current

    async def rename(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        parsed = parse_input(message.text, bound=True)
        if parsed.arguments != arguments:
            raise Conflict("session_rename_route_source_mismatch")
        binding = await self.current(binding, message)
        if not self.available(binding, "rename"):
            return self.tr.render("lifecycle.rename_unavailable", locale)
        snapshot = await self.bindings.control.snapshot(reference(binding))
        if snapshot.reference != reference(binding) or not snapshot.reconciled:
            raise Conflict("session_rename_original_snapshot_unavailable")
        change = SessionRename(previous_title=snapshot.title, target_title=arguments.strip())
        binding = await self.current(binding, message)
        payload = {
            "operation": "session.rename",
            "reference": reference(binding).model_dump(mode="json"),
            "source": message.model_dump(mode="json"),
            "change": change.model_dump(mode="json"),
            "reply_locale": locale,
        }
        key = "session-rename:" + digest({"realm": message.realm_id, "message": message.message_id})
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
                raise AccessDenied("session_rename_operate_grant_changed")
            if not self.available(binding, "rename"):
                raise Conflict("session_rename_capability_changed")
            action = await session.scalar(select(Action).where(Action.dedupe_key == key))
            if action is not None:
                if action.operation != "session.rename" or action.operation_digest != digest(
                    payload
                ):
                    raise Conflict("session_rename_duplicate_source_changed")
            else:
                action = Action(
                    dedupe_key=key,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=message.author_id,
                    operation="session.rename",
                    payload=payload,
                    operation_digest=digest(payload),
                    state="held" if current.dispatch_paused else "queued",
                )
                session.add(action)
                await session.flush()
                session.add(
                    AuditEvent(
                        actor=f"{message.realm_id}:{message.author_id}",
                        event="session_rename_queued",
                        object_id=action.id,
                    )
                )
        return self.tr.render(
            "action.held" if action.state == "held" else "action.received",
            locale,
        )
