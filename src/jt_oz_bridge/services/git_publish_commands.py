"""`!oz git commit` / `!oz git push` on a bound original session: preview, one `!confirm`.

The preview reads Git with GETs only and binds a two-minute token to a digest of
exactly that reading and the request. `!confirm` reads again: a different
reading is refused and previewed afresh. A match records one durable Action whose
only Native effect is one ordinary prompt asking the agent to run the fixed
command. The bridge itself runs nothing and grants the agent nothing.
"""

import shlex
import time
from collections.abc import Mapping, Sequence
from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_publish import (
    CONFIRM_TOKEN,
    GIT_PUBLISH,
    MAX_PATHS,
    GitFile,
    GitPublishPlan,
    GitPublishReader,
    GitPublishRequest,
    GitPublishState,
    commit_message,
    safe_branch,
    safe_remote,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.operations import CapabilityLookup
from jt_oz_bridge.domain.session_lifecycle import LIFECYCLE_TOKEN_KINDS
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import code_block
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.security.workspace_paths import canonical_relative, disclosed_path
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant

CONFIRM_TTL = 120
QUEUED_TTL = 120
VERBS = frozenset({"commit", "push"})
DEFAULT_REMOTE = "origin"
SHOWN_FILES = 20
FORCE = frozenset({"-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror"})
# A Git preview replaces any other confirmation still open for this person here.
OTHER_TOKENS = (*LIFECYCLE_TOKEN_KINDS, "native-agent-menu", "native-agent-confirm")


class GitPublishRefused(Exception):
    """A request the bridge answers with a fixed explanation and no token."""

    def __init__(self, key: str, **values: str) -> None:
        super().__init__(key)
        self.key, self.values = key, values


class GitPublishAsk(ControlModel):
    kind: Literal["commit", "push"]
    message: str | None = None
    paths: tuple[str, ...] = ()
    remote: str = DEFAULT_REMOTE
    branch: str | None = None
    explicit: bool = False


class GitPublishConfirmation(ControlModel):
    reference: SessionRef
    preview: HumanMessage
    plan: GitPublishPlan
    before: GitPublishState


def ask(arguments: str) -> GitPublishAsk:
    """`commit -m "<message>" [--] [paths…]` or `push [remote] [branch]`; nothing else."""
    try:
        words = shlex.split(arguments, posix=True)
    except ValueError:
        raise ValueError("git_publish_unbalanced_quotes") from None
    if not words or words[0] not in VERBS:
        raise ValueError("git_publish_verb_required")
    if words[0] == "push":
        rest = words[1:]
        if any(w in FORCE or w.startswith(("+", "--force")) for w in rest):
            raise GitPublishRefused("git_publish.no_force")
        if len(rest) > 2 or any(w.startswith("-") for w in rest):
            raise ValueError("git_publish_push_takes_remote_and_branch_only")
        try:
            remote = safe_remote(rest[0]) if rest else DEFAULT_REMOTE
            branch = safe_branch(rest[1]) if len(rest) == 2 else None
        except ValueError:
            raise GitPublishRefused("git_publish.bad_name") from None
        return GitPublishAsk(kind="push", remote=remote, branch=branch, explicit=bool(rest))
    if len(words) < 3 or words[1] != "-m":
        raise ValueError("git_publish_commit_message_required")
    try:
        message = commit_message(words[2])
    except ValueError:
        raise GitPublishRefused("git_publish.bad_message") from None
    paths = words[3:]
    if paths[:1] == ["--"]:
        paths = paths[1:]
    if any(p.startswith("-") for p in paths):
        raise GitPublishRefused("git_publish.no_options")
    if len(paths) > MAX_PATHS:
        raise GitPublishRefused("git_publish.too_many", limit=str(MAX_PATHS))
    checked = []
    for path in paths:
        try:
            relative = canonical_relative(path.removeprefix("./"))
        except ValueError:
            raise GitPublishRefused("git_publish.outside_root", path=visible(path)) from None
        try:
            checked.append(disclosed_path(relative))
        except AccessDenied:
            raise GitPublishRefused("git_publish.protected_path", path=visible(path)) from None
    return GitPublishAsk(kind="commit", message=message, paths=tuple(sorted(set(checked))))


class GitPublishCommands:
    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, GitPublishReader],
        tokens: TokenService,
        reader: SourceReader,
        capabilities: CapabilityLookup,
        *,
        message_limit: int = 10000,
    ) -> None:
        if tokens.db is not bindings.db or tokens.fence is None or message_limit < 512:
            raise ValueError("git_publish_requires_shared_database_and_consumer_fence")
        self.bindings, self.db, self.tokens = bindings, bindings.db, tokens
        self.readers = readonly_enrollment(readers)
        self.reader, self.fence = reader, tokens.fence
        self.capabilities, self.message_limit, self.tr = capabilities, message_limit, Translator()

    def available(self, binding: Binding) -> bool:
        ref = reference(binding)
        selected = self.readers.get(ref)
        try:
            capability = self.capabilities(ref).get(GIT_PUBLISH)
            return bool(
                selected is not None
                and selected.qualified(ref)
                and capability is not None
                and capability.supported
            )
        except (ValueError, TypeError):
            return False

    async def current(self, binding: Binding, message: HumanMessage) -> Binding:
        parsed = parse_input(message.text, bound=True)
        if (
            message.is_bot
            or message.deleted
            or message.revision != 0
            or parsed.kind != "command"
            or parsed.command not in {"git", "confirm"}
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("git_publish_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("git_publish_binding_changed")
        return current

    async def _token(
        self, binding: Binding, message: HumanMessage, token: str | None
    ) -> ControlToken | None:
        """The named (or newest) open Git confirmation of this person in this topic."""
        query = select(ControlToken).where(
            ControlToken.kind == CONFIRM_TOKEN,
            ControlToken.realm_id == message.realm_id,
            ControlToken.user_id == message.author_id,
            ControlToken.binding_id == binding.id,
            ControlToken.binding_revision == binding.revision,
            ControlToken.used.is_(False),
            ControlToken.expires_at > time.time(),
        )
        if token is not None:
            query = query.where(ControlToken.token_hash == token_hash(token))
        async with self.db.sessions() as session:
            saved: ControlToken | None = await session.scalar(
                query.order_by(ControlToken.expires_at.desc()).limit(1)
            )
        if saved is not None and saved.context_hash != digest(saved.context):
            raise Conflict("git_publish_token_context_changed")
        return saved

    async def _confirmed(self, token: str) -> Action | None:
        async with self.db.sessions() as session:
            found: Action | None = await session.scalar(
                select(Action).where(Action.dedupe_key == "git-publish:" + token_hash(token))
            )
        return found

    async def owns_confirm(self, binding: Binding, message: HumanMessage, arguments: str) -> bool:
        words = arguments.split()
        if len(words) > 1:
            return False
        if not words:
            return await self._token(binding, message, None) is not None
        if await self._token(binding, message, words[0]) is not None:
            return True
        used = await self._confirmed(words[0])
        return used is not None and used.binding_id == binding.id

    async def _retire(self, session: AsyncSession, binding: Binding, message: HumanMessage) -> None:
        await session.execute(
            update(ControlToken)
            .where(
                ControlToken.kind.in_([CONFIRM_TOKEN, *OTHER_TOKENS]),
                ControlToken.realm_id == message.realm_id,
                ControlToken.user_id == message.author_id,
                ControlToken.binding_id == binding.id,
                ControlToken.used.is_(False),
            )
            .values(used=True)
        )

    async def _lock_operator(
        self, session: AsyncSession, binding: Binding, message: HumanMessage
    ) -> Binding:
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
            raise AccessDenied("git_publish_operate_grant_changed")
        return current

    async def _blocked(self, binding: Binding, locale: Locale) -> str | None:
        if binding.dispatch_paused:
            return self.tr.render("git_publish.paused", locale)
        snapshot = await self.bindings.control.snapshot(reference(binding))
        if snapshot.reference != reference(binding) or not snapshot.reconciled:
            raise Conflict("git_publish_original_snapshot_unavailable")
        if snapshot.state != ExecutionState.IDLE:
            return self.tr.render("git_publish.busy", locale)
        return None

    async def _read(self, binding: Binding, request: GitPublishAsk) -> GitPublishState:
        ref = reference(binding)
        state = await self.readers[ref].read(
            ref, remote=request.remote, compare="auto" if request.kind == "commit" else "tracking"
        )
        GitPublishState.model_validate(state.model_dump(mode="json"))
        if state.reference != ref or state.remote != request.remote:
            raise Conflict("git_publish_reading_scope_changed")
        return state

    def _plan(
        self, binding: Binding, request: GitPublishAsk, state: GitPublishState
    ) -> GitPublishPlan:
        """The exact plan for this reading, or GitPublishRefused saying why not."""
        if state.branch is None:
            raise GitPublishRefused("git_publish.detached")
        if state.conflict_files:
            raise GitPublishRefused("git_publish.conflicts", count=str(state.conflict_files))
        changed = state.changed()
        if request.kind == "commit":
            paths = request.paths or tuple(sorted(changed))
            if not paths:
                if state.hidden_files:
                    raise GitPublishRefused(
                        "git_publish.nothing_hidden", count=str(state.hidden_files)
                    )
                raise GitPublishRefused("git_publish.nothing")
            missing = [p for p in paths if p not in changed]
            if missing:
                raise GitPublishRefused("git_publish.not_changed", path=visible(missing[0]))
            return GitPublishPlan(
                kind="commit",
                directory=binding.canonical_directory,
                branch=state.branch,
                remote=state.remote,
                message=request.message,
                paths=paths,
                state_sha256=digest(state.model_dump(mode="json")),
            )
        branch = request.branch or state.branch
        if branch != state.branch:
            raise GitPublishRefused("git_publish.other_branch", branch=visible(state.branch))
        if not state.tracking_present and not request.explicit:
            raise GitPublishRefused(
                "git_publish.no_upstream", remote=visible(state.remote), branch=visible(branch)
            )
        if state.tracking_present and state.ahead == () and not state.ahead_hidden:
            raise GitPublishRefused(
                "git_publish.nothing_to_push", ref=visible(state.tracking or "")
            )
        return GitPublishPlan(
            kind="push",
            directory=binding.canonical_directory,
            branch=branch,
            remote=state.remote,
            state_sha256=digest(state.model_dump(mode="json")),
        )

    def _preview_text(self, plan: GitPublishPlan, state: GitPublishState, locale: Locale) -> str:
        command = plan.command()
        if redact_text(command)[1]:
            # The person must see the exact command; one that would be masked is not offered.
            raise GitPublishRefused("git_publish.secret_like")
        tr = self.tr.render
        lines = []
        if plan.kind == "commit":
            assert plan.message is not None
            lines.append(
                tr("git_publish.commit_preview", locale, branch=visible(plan.branch))
                + "\n"
                + tr("git_publish.message", locale, message=visible(plan.message))
            )
            rows = [f for f in state.files if f.path in set(plan.paths)]
            lines.append(self._files(rows, locale, "git_publish.files"))
            left = len(state.files) - len(rows)
            if left or state.hidden_files:
                lines.append(
                    tr(
                        "git_publish.left_out",
                        locale,
                        count=str(left),
                        hidden=str(state.hidden_files),
                    )
                )
        else:
            lines.append(
                tr(
                    "git_publish.push_preview",
                    locale,
                    branch=visible(plan.branch),
                    remote=visible(plan.remote),
                )
            )
            if state.ahead is None:
                lines.append(
                    tr("git_publish.new_remote_branch", locale, ref=visible(plan.tracking))
                )
            else:
                lines.append(
                    self._files(
                        state.ahead, locale, "git_publish.ahead", ref=visible(plan.tracking)
                    )
                )
                if state.ahead_hidden:
                    lines.append(
                        tr("git_publish.ahead_hidden", locale, count=str(state.ahead_hidden))
                    )
            lines.append(tr("git_publish.fast_forward_unknown", locale))
            if state.files or state.hidden_files:
                lines.append(tr("git_publish.uncommitted_stay", locale))
        lines.append(tr("git_publish.command", locale) + "\n" + code_block(command, "sh"))
        lines.append(tr("git_publish.agent_rules", locale))
        return "\n\n".join(lines)

    def _files(self, rows: Sequence[GitFile], locale: Locale, key: str, **values: str) -> str:
        shown = [
            f"- {visible(f.path)} · "
            + self.tr.render("git.change." + f.status, locale)
            + f" · +{f.additions}/−{f.deletions}"
            for f in rows[:SHOWN_FILES]
        ]
        if len(rows) > SHOWN_FILES:
            shown.append(
                self.tr.render("git_publish.more", locale, count=str(len(rows) - SHOWN_FILES))
            )
        return self.tr.render(key, locale, count=str(len(rows)), **values) + "\n" + "\n".join(shown)

    def _refusal(self, error: GitPublishRefused, locale: Locale) -> str:
        return self.tr.render(error.key, locale, **error.values)

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        parsed = parse_input(message.text, bound=True)
        if parsed.command != "git" or parsed.arguments != arguments:
            raise Conflict("git_publish_route_source_mismatch")
        try:
            request = ask(arguments)
        except GitPublishRefused as error:
            await self.current(binding, message)
            return self._refusal(error, locale)
        binding = await self.current(binding, message)
        if not self.available(binding):
            return self.tr.render("git_publish.unavailable", locale)
        blocked = await self._blocked(binding, locale)
        if blocked is not None:
            return blocked
        state = await self._read(binding, request)
        return await self._preview(binding, message, message, locale, request, state)

    async def _preview(
        self,
        binding: Binding,
        message: HumanMessage,
        preview: HumanMessage,
        locale: Locale,
        request: GitPublishAsk,
        state: GitPublishState,
    ) -> str:
        try:
            plan = self._plan(binding, request, state)
            text = self._preview_text(plan, state, locale)
        except GitPublishRefused as error:
            text, plan = self._refusal(error, locale), None
        if len(text) > self.message_limit - 200:
            text, plan = self.tr.render("git_publish.too_long", locale), None
        binding = await self.current(binding, message)
        async with self.db.sessions.begin() as session:
            await self._lock_operator(session, binding, message)
            await self._retire(session, binding, message)
        if plan is None:
            return text
        token = await self.tokens.issue(
            CONFIRM_TOKEN,
            message.realm_id,
            message.author_id,
            GitPublishConfirmation(
                reference=reference(binding), preview=preview, plan=plan, before=state
            ).model_dump(mode="json"),
            ttl=CONFIRM_TTL,
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return text + "\n\n" + self.tr.render("git_publish.confirm", locale, token=token)

    async def _require_preview(self, preview: HumanMessage, message: HumanMessage) -> None:
        if (
            preview.message_id == message.message_id
            or preview.author_id != message.author_id
            or (preview.realm_id, preview.channel_id, preview.topic)
            != (message.realm_id, message.channel_id, message.topic)
            or preview.revision != 0
            or preview.deleted
            or preview.is_bot
            or await self.reader.read(preview.realm_id, preview.message_id) != preview
        ):
            raise Conflict("git_publish_preview_source_changed")

    async def confirm(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        binding = await self.current(binding, message)
        words = arguments.split()
        saved = await self._token(binding, message, words[0] if words else None)
        if saved is None:
            if words and (used := await self._confirmed(words[0])) is not None:
                if (used.binding_id, used.actor_id) == (binding.id, message.author_id):
                    # Only one Action exists per confirmation; a repeat changes nothing.
                    return self.tr.render("git_publish.already_confirmed", locale)
            raise Conflict("git_publish_confirmation_unavailable")
        confirmation = GitPublishConfirmation.model_validate(saved.context)
        if confirmation.reference != reference(binding):
            raise Conflict("git_publish_confirmation_changed")
        await self._require_preview(confirmation.preview, message)
        if not self.available(binding):
            return self.tr.render("git_publish.unavailable", locale)
        blocked = await self._blocked(binding, locale)
        if blocked is not None:
            return blocked
        request = ask(parse_input(confirmation.preview.text, bound=True).arguments)
        fresh = await self._read(binding, request)
        if digest(fresh.model_dump(mode="json")) != confirmation.plan.state_sha256:
            # Something changed since the preview: that approval is void.
            again = await self._preview(
                binding, message, confirmation.preview, locale, request, fresh
            )
            return self.tr.render("git_publish.changed", locale) + "\n\n" + again
        plan = confirmation.plan
        binding = await self.current(binding, message)
        payload = GitPublishRequest(
            reference=reference(binding),
            source=message,
            preview=confirmation.preview,
            plan=plan,
            before=confirmation.before,
            text=plan.prompt(),
            reply_locale=locale,
            confirm_expires_at=time.time() + QUEUED_TTL,
            confirmation_token_sha256=saved.token_hash,
        ).model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(session, binding, message)
            if current.dispatch_paused:
                return self.tr.render("git_publish.paused", locale)
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, binding, message)
            action = Action(
                dedupe_key="git-publish:" + saved.token_hash,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=message.author_id,
                operation=GIT_PUBLISH,
                payload=payload,
                operation_digest=digest(payload),
                state="queued",
            )
            session.add(action)
            await session.flush()
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="git_publish_queued",
                    object_id=action.id,
                )
            )
        return self.tr.render("git_publish.sending", locale)
