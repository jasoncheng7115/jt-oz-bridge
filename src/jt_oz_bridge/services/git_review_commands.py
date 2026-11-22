"""Fenced VIEW commands for qualified original Native Git review projections.

No Action, Native mutation, mutation proof, or review confirmation is created.
A reader's current snapshot is never substituted for current Human/Binding VIEW.
"""

import time
from collections.abc import Mapping
from typing import Literal

from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.git_review import explicit_base
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_review import (
    NativeGitPatch,
    NativeGitPatchReader,
    NativeGitReview,
    NativeGitReviewReader,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import WorkerLease

type ReviewVerb = Literal["context", "branches", "worktrees", "review"]
type ReviewMode = Literal["working", "branch", "committed"]
VERBS = frozenset({"context", "branches", "worktrees", "review", "patch"})


def query(arguments: str) -> tuple[ReviewVerb, ReviewMode, str | None, str]:
    parts = arguments.split(maxsplit=1)
    if not parts or parts[0] not in VERBS - {"patch"}:
        raise ValueError("git_review_fixed_view_verb_required")
    verb: ReviewVerb = parts[0]  # type: ignore[assignment]
    remainder = parts[1] if len(parts) == 2 else ""
    if verb == "context":
        if remainder:
            raise ValueError("git_review_context_has_no_arguments")
        return verb, "working", None, ""
    if verb in {"branches", "worktrees"}:
        if len(remainder.encode("utf-8")) > 128 or any(
            ord(c) < 32 or ord(c) == 127 for c in remainder
        ):
            raise ValueError("git_review_bounded_search_required")
        return verb, "working", None, remainder
    comparison = remainder.split()
    if not comparison or comparison == ["working"]:
        return verb, "working", None, ""
    if len(comparison) == 2 and comparison[0] in {"branch", "committed"}:
        mode: ReviewMode = comparison[0]  # type: ignore[assignment]
        return verb, mode, explicit_base(comparison[1]), ""
    raise ValueError("git_review_explicit_comparison_required")


class NativeGitReviewCommands:
    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, NativeGitReviewReader],
        tokens: TokenService,
        source: SourceReader,
        *,
        message_limit: int = 10000,
    ) -> None:
        if (
            tokens.db is not bindings.db
            or tokens.fence is None
            or type(message_limit) is not int
            or not 512 <= message_limit <= 1000000
        ):
            raise ValueError("git_review_shared_fenced_view_scope_required")
        self.bindings, self.db = bindings, bindings.db
        self.readers = readonly_enrollment(readers)
        self.tokens, self.source, self.fence = tokens, source, tokens.fence
        self.message_limit, self.tr = message_limit, Translator()

    def handles(self, arguments: str) -> bool:
        parts = arguments.split(maxsplit=1)
        return bool(parts and parts[0] in VERBS)

    def available(self, binding: Binding) -> bool:
        ref = reference(binding)
        selected = self.readers.get(ref)
        try:
            return (
                selected is not None
                and selected.qualified(ref)
                and selected.contract_for(ref) == self.bindings.control.contract_for(ref)
            )
        except ValueError:
            return False

    async def _current(self, binding: Binding, message: HumanMessage, arguments: str) -> None:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command != "git"
            or parsed.arguments != arguments
            or not self.handles(arguments)
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("git_review_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.VIEW
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or (
                current.channel_id,
                current.topic,
                current.audience_revision,
                current.audience_user_ids,
            )
            != (
                binding.channel_id,
                binding.topic,
                binding.audience_revision,
                binding.audience_user_ids,
            )
            or await self.source.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("git_review_original_binding_or_source_changed")

    def _snapshot_current(
        self,
        binding: Binding,
        selected: NativeGitReviewReader | None,
        snapshot: NativeGitReview | NativeGitPatch | None,
    ) -> bool:
        if selected is None:
            return snapshot is None and not self.available(binding)
        if isinstance(snapshot, NativeGitPatch):
            return (
                self.readers.get(reference(binding)) is selected
                and self.available(binding)
                and isinstance(selected, NativeGitPatchReader)
                and selected.qualified_patch(reference(binding))
                and selected.patch_contract_for(reference(binding))
                == self.bindings.control.contract_for(reference(binding))
                and snapshot.reference == reference(binding)
                and selected.current_patch(snapshot)
            )
        return (
            snapshot is not None
            and self.readers.get(reference(binding)) is selected
            and self.available(binding)
            and snapshot.reference == reference(binding)
            and selected.current(snapshot)
        )

    async def _authority(self, binding: Binding) -> float:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            # Scope queries may themselves wait. Recheck the exact consumer lease
            # after them and retain its actual expiry for the final post-commit clock.
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
            if expiry is None or time.time() >= expiry:
                raise Conflict("git_review_final_consumer_lease_changed")
        if time.time() >= expiry:
            raise Conflict("git_review_consumer_lease_expired_after_commit")
        return expiry

    async def _locked_scope(
        self,
        binding: Binding,
        selected: NativeGitReviewReader | None,
        snapshot: NativeGitReview | NativeGitPatch | None,
    ) -> float:
        if not self._snapshot_current(binding, selected, snapshot):
            raise Conflict("git_review_read_scope_changed_before_sql")
        expiry = await self._authority(binding)
        if time.time() >= expiry or not self._snapshot_current(binding, selected, snapshot):
            raise Conflict("git_review_read_scope_changed_after_sql")
        return expiry

    async def _finish(
        self,
        binding: Binding,
        message: HumanMessage,
        arguments: str,
        result: str,
        selected: NativeGitReviewReader | None,
        snapshot: NativeGitReview | NativeGitPatch | None,
    ) -> str:
        if not isinstance(result, str) or len(result) > self.message_limit - 100:
            raise Conflict("git_review_output_budget_changed")
        await self._current(binding, message, arguments)
        await self._locked_scope(binding, selected, snapshot)
        # Re-observe Human/audience after the first SQL output boundary. A final
        # SQL boundary then closes revocation/lease drift during those awaits.
        await self._current(binding, message, arguments)
        expiry = await self._locked_scope(binding, selected, snapshot)
        if time.time() >= expiry or not self._snapshot_current(binding, selected, snapshot):
            raise Conflict("git_review_final_view_no_longer_current")
        return result

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        if arguments.split(maxsplit=1)[0:1] == ["patch"]:
            from jt_oz_bridge.services.git_patch_commands import patch_route

            return await patch_route(self, binding, message, locale, arguments)
        verb, mode, base, search = query(arguments)
        await self._current(binding, message, arguments)
        await self._authority(binding)
        if not self.available(binding):
            return await self._finish(
                binding,
                message,
                arguments,
                self.tr.render("git_review.unavailable", locale),
                None,
                None,
            )
        selected = self.readers[reference(binding)]
        snapshot = await selected.read(
            reference(binding),
            mode=mode,
            base=base,
            search=search if verb == "branches" else "",
            limit=50,
        )
        # Validate model_copy and alternate implementations without replacing the
        # original object whose live read-only provenance selected.current checks.
        NativeGitReview.model_validate(snapshot.model_dump(mode="json"))
        if snapshot.mode != mode or snapshot.requested_base != base:
            raise Conflict("git_review_original_comparison_changed")
        await self._current(binding, message, arguments)
        if not self._snapshot_current(binding, selected, snapshot):
            raise Conflict("git_review_original_native_snapshot_changed")
        # Presentation is separately allowlisted; never serialize the complete DTO.
        from jt_oz_bridge.presentation.git_review import render_git_review

        result = render_git_review(
            snapshot,
            verb,
            locale,
            message_limit=self.message_limit,
            search=search if verb == "worktrees" else "",
        )
        return await self._finish(binding, message, arguments, result, selected, snapshot)
