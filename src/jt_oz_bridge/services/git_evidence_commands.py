"""Original completed-check views; no new Action, helper execution or Git write."""

import re
import time
from html import unescape
from typing import Literal
from uuid import UUID

from pydantic import Field, StrictInt
from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.git_evidence import render_git_evidence_page
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.git_evidence import GitEvidenceResults
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import WorkerLease

KIND = "git-evidence-page"


class EvidencePage(ControlModel):
    format: Literal["historical-git-evidence-page-v1"] = "historical-git-evidence-page-v1"
    reference: SessionRef
    action_id: str = Field(min_length=36, max_length=36)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audience_revision: str
    audience_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    offset: StrictInt = Field(ge=1, le=65536)
    issuer: HumanMessage
    message_limit: StrictInt = Field(ge=512, le=1000000)
    locale: Locale


class GitEvidenceCommands:
    def __init__(
        self, results: GitEvidenceResults, tokens: TokenService, *, message_limit: int = 10000
    ) -> None:
        if (
            tokens.db is not results.db
            or tokens.fence != results.fence
            or type(message_limit) is not int
            or not 512 <= message_limit <= 1000000
        ):
            raise ValueError("git_evidence_shared_fenced_scope_required")
        self.results, self.bindings, self.db = results, results.bindings, results.db
        self.source, self.fence, self.tokens = results.source, results.fence, tokens
        self.message_limit, self.tr = message_limit, Translator()

    def available(self, binding: Binding) -> bool:
        return self.results.available(binding)

    async def _current(self, binding: Binding, message: HumanMessage) -> None:
        parsed = parse_input(message.text, bound=True)
        parts = parsed.arguments.split()
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "git"
            or len(parts) not in {2, 3}
            or parts[0] != "evidence"
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("git_evidence_current_request_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.VIEW
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or current.audience_revision != binding.audience_revision
            or current.audience_user_ids != binding.audience_user_ids
        ):
            raise Conflict("git_evidence_current_audience_changed")

    async def _authority(self, binding: Binding) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            await self.fence.lock(session)
            expiry = await session.scalar(
                select(WorkerLease.expires_at)
                .where(
                    WorkerLease.role == "consumer",
                    WorkerLease.holder == self.fence.holder,
                    WorkerLease.fencing == self.fence.fencing,
                )
                .with_for_update()
            )
            if expiry is None or expiry <= time.time():
                raise Conflict("git_evidence_final_lease_changed")
        if expiry <= time.time():
            raise Conflict("git_evidence_final_lease_expired")

    async def route(
        self,
        binding: Binding,
        message: HumanMessage,
        locale: Locale,
        arguments: str,
        *,
        replay_text: str | None = None,
    ) -> str:
        parts = arguments.split()
        if len(parts) not in {2, 3} or parts[0] != "evidence" or str(UUID(parts[1])) != parts[1]:
            raise ValueError("git_evidence_original_action_query_required")
        action_id, page_token = parts[1], parts[2] if len(parts) == 3 else None
        if page_token is not None and re.fullmatch(r"[A-Za-z0-9_-]{32}", page_token) is None:
            raise ValueError("git_evidence_opaque_page_required")
        if parse_input(message.text, bound=True).arguments != arguments:
            raise Conflict("git_evidence_original_arguments_changed")
        await self._current(binding, message)
        await self._authority(binding)
        if not self.available(binding):
            await self._current(binding, message)
            await self._authority(binding)
            return self.tr.render("git_evidence.unavailable", locale)
        state = None
        if page_token is not None:
            saved = await self.tokens.inspect(page_token, KIND, message.realm_id, message.author_id)
            state = EvidencePage.model_validate(saved.context)
            if (
                saved.binding_id != binding.id
                or saved.binding_revision != binding.revision
                or state.reference != reference(binding)
                or state.action_id != action_id
                or state.message_limit != self.message_limit
                or state.audience_revision != binding.audience_revision
                or state.audience_sha256 != digest({"user_ids": binding.audience_user_ids})
                or parse_input(state.issuer.text, bound=True).arguments.split()
                != ["evidence", action_id]
                or (
                    state.issuer.realm_id,
                    state.issuer.channel_id,
                    state.issuer.topic,
                    state.issuer.author_id,
                )
                != (message.realm_id, message.channel_id, message.topic, message.author_id)
            ):
                raise Conflict("git_evidence_original_page_scope_changed")
            await self._current(binding, state.issuer)
        view = await self.results.read_for_request(
            binding, message, action_id, page_token=page_token
        )
        snapshot = digest(view.model_dump(mode="json"))
        if state is not None and state.snapshot_sha256 != snapshot:
            raise Conflict("git_evidence_original_journal_changed")
        shown_locale = state.locale if state is not None else locale
        body, next_offset = render_git_evidence_page(
            view,
            shown_locale,
            offset=state.offset if state is not None else 0,
            message_limit=self.message_limit,
        )
        if next_offset is not None:
            next_state = EvidencePage(
                reference=reference(binding),
                action_id=action_id,
                snapshot_sha256=snapshot,
                audience_revision=binding.audience_revision,
                audience_sha256=digest({"user_ids": binding.audience_user_ids}),
                offset=next_offset,
                issuer=state.issuer if state is not None else message,
                message_limit=self.message_limit,
                locale=shown_locale,
            )
            if replay_text is None:
                token = await self.tokens.issue(
                    KIND,
                    message.realm_id,
                    message.author_id,
                    next_state.model_dump(mode="json"),
                    ttl=300,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                )
            else:
                matches = re.findall(
                    r"!oz git evidence " + re.escape(action_id) + r" ([A-Za-z0-9_-]{32})",
                    unescape(replay_text),
                )
                if len(matches) != 1:
                    raise Conflict("git_evidence_replay_navigation_changed")
                token = matches[0]
                saved_next = await self.tokens.inspect(
                    token, KIND, message.realm_id, message.author_id
                )
                if (
                    saved_next.binding_id != binding.id
                    or saved_next.binding_revision != binding.revision
                    or EvidencePage.model_validate(saved_next.context) != next_state
                ):
                    raise Conflict("git_evidence_replay_next_page_changed")
            body += "\n\n" + self.tr.render(
                "git_evidence.next", shown_locale, action=action_id, token=token
            )
        # Re-authenticate original pagination issuer as well as this request;
        # journal drift during asynchronous publication preparation is refused.
        if state is not None:
            await self._current(binding, state.issuer)
        await self._current(binding, message)
        latest = await self.results.read_for_request(
            binding, message, action_id, page_token=page_token
        )
        if latest != view:
            raise Conflict("git_evidence_final_original_journal_changed")
        await self._authority(binding)
        if len(body) > self.message_limit - 100:
            raise Conflict("git_evidence_final_output_budget_changed")
        if replay_text is not None and body != replay_text:
            raise Conflict("git_evidence_saved_projection_changed")
        return body
