"""Real own-DB VIEW boundaries with synthetic Human and qualified reader fixtures."""

import time
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.git_review import (
    NativeDiffSummary,
    NativeGitReview,
    NativeReviewBase,
    SavedWorktree,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.git_review_commands import NativeGitReviewCommands
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import (
    Binding,
    ControlToken,
    EnrolledBackend,
    EnrolledProject,
)
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_router import Source, message
from tests.support import bound


class ReviewReader:
    def __init__(self, ref, contract):
        self.ref, self.contract = ref, contract
        self.enabled, self.live = True, True
        self.calls, self.hook = [], None
        self.snapshot = None
        self.changed = {}

    def qualified(self, ref):
        return self.enabled and ref == self.ref

    def contract_for(self, ref):
        assert ref == self.ref
        return self.contract

    async def read(self, ref, *, mode="working", base=None, search="", limit=50):
        assert ref == self.ref
        self.calls.append((mode, base, search, limit))
        self.snapshot = NativeGitReview(
            reference=ref,
            provider="git",
            current_branch="feature/original",
            default_branch="main",
            saved_worktrees=(
                SavedWorktree(relative_directory=""),
                SavedWorktree(relative_directory="worktrees/report"),
            ),
            hidden_worktrees=1,
            branches=("feature/original", "main"),
            branches_complete=True,
            inferred_base=NativeReviewBase(name="main", ref="refs/heads/main", source="reflog"),
            mode=mode,
            requested_base=base,
            files=(
                NativeDiffSummary(
                    path="reports/table.py",
                    additions=3,
                    deletions=1,
                    status="modified",
                    patch_sha256="b" * 64,
                    patch_bytes=72,
                ),
            ),
            hidden_files=1,
        ).model_copy(update=self.changed)
        if self.hook:
            await self.hook()
        return self.snapshot

    def current(self, snapshot):
        return self.live and snapshot is self.snapshot


async def setup(db, maximum=10000):
    bindings, binding, control, audience = await bound(db)
    holder = "git-review"
    fencing = await DurableStore(db).acquire_lease(holder, ttl=120)
    tokens = TokenService(db, fence=ConsumerFence(holder, fencing))
    source = Source()
    reader = ReviewReader(reference(binding), control.contract_hash)
    commands = NativeGitReviewCommands(
        bindings, {reader.ref: reader}, tokens, source, message_limit=maximum
    )
    return commands, binding, source, reader, audience


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


async def route(commands, binding, source, text, *, locale="en", **changes):
    item = message("!oz git " + text, **changes)
    source.messages[item.message_id] = item
    return await commands.route(binding, item, locale, text)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize(
    "arguments",
    [
        "context",
        "branches",
        "worktrees",
        "review",
        "review working",
        "review branch refs/heads/main",
        "review committed abc123",
    ],
)
async def test_fixed_view_commands_use_original_root_without_creating_actions_or_tokens(
    db, locale, arguments
):
    commands, binding, source, reader, audience = await setup(db)
    text = await route(commands, binding, source, arguments, locale=locale)
    assert "feature/original" in unescape(text) if arguments == "context" else text
    assert commands.handles(arguments) and commands.available(binding)
    assert len(reader.calls) == 1 and len(source.calls) >= 8
    mode = (
        "branch"
        if " branch " in arguments
        else "committed"
        if " committed " in arguments
        else "working"
    )
    assert reader.calls[0][0] == mode
    assert "mutation_confirmation_usable" not in text and "canonical_directory" not in text
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize("arguments", ["branches feature", "worktrees report"])
async def test_search_has_exact_native_branches_or_local_saved_inventory_semantics(db, arguments):
    commands, binding, source, reader, audience = await setup(db)
    text = await route(commands, binding, source, arguments)
    assert reader.calls[0][2] == ("feature" if arguments.startswith("branches") else "")
    assert text and not await rows(db, Action)


@pytest.mark.parametrize(
    "arguments",
    [
        "status",
        "diff",
        "commit",
        "push",
        "branch",
        "checkout",
        "worktree",
        "reset",
        "clean",
        "checks",
        "ABC_page_token",
    ],
)
async def test_existing_git_commands_and_pages_are_not_intercepted(db, arguments):
    commands, binding, source, reader, audience = await setup(db)
    assert not commands.handles(arguments)
    with pytest.raises(ValueError):
        await route(commands, binding, source, arguments)
    assert not reader.calls


@pytest.mark.parametrize(
    "arguments",
    [
        "context extra",
        "review branch",
        "review committed",
        "review --help",
        "review branch -evil",
        "review working main",
        "review branch main extra",
        "branches " + "x" * 129,
        "worktrees " + "x" * 129,
    ],
)
async def test_invalid_view_queries_cannot_become_prompt_or_unbounded_native_reads(db, arguments):
    commands, binding, source, reader, audience = await setup(db)
    with pytest.raises(ValueError):
        await route(commands, binding, source, arguments)
    assert not reader.calls and not await rows(db, Action)


@pytest.mark.parametrize("fault", ["missing", "not-qualified", "contract"])
@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_no_qualified_exact_reader_returns_localized_unavailable_with_zero_native_reads(
    db, fault, locale
):
    from types import MappingProxyType

    commands, binding, source, reader, audience = await setup(db)
    if fault == "missing":
        commands.readers = MappingProxyType({})
    elif fault == "not-qualified":
        reader.enabled = False
    else:
        reader.contract = "f" * 64
    assert not commands.available(binding)
    text = await route(commands, binding, source, "context", locale=locale)
    assert text and "git_review.unavailable" not in text
    assert not reader.calls and not await rows(db, Action)


@pytest.mark.parametrize(
    "fault",
    [
        "bot",
        "deleted",
        "revision",
        "wrong-channel",
        "wrong-topic",
        "wrong-realm",
        "wrong-author",
        "route-source",
    ],
)
async def test_original_human_source_scope_is_required_before_native_reads(db, fault):
    commands, binding, source, reader, audience = await setup(db)
    changes = {
        "bot": {"is_bot": True},
        "deleted": {"deleted": True},
        "revision": {"revision": 1},
        "wrong-channel": {"channel_id": 11},
        "wrong-topic": {"topic": "foreign"},
        "wrong-realm": {"realm_id": "foreign"},
        "wrong-author": {"author_id": 999},
        "route-source": {},
    }[fault]
    item = message("!oz git " + ("branches" if fault == "route-source" else "context"), **changes)
    source.messages[item.message_id] = item
    with pytest.raises((Conflict, AccessDenied)):
        await commands.route(binding, item, "en", "context")
    assert not reader.calls and not await rows(db, Action)


@pytest.mark.parametrize(
    "fault",
    [
        "grant",
        "audience",
        "binding",
        "unbound",
        "root",
        "backend",
        "project",
        "source-edit",
        "source-delete",
        "source-move",
        "lease",
        "snapshot",
        "reader-enrollment",
    ],
)
async def test_native_read_cannot_outlive_human_binding_grant_enrollment_audience_or_lease(
    db, fault
):
    from types import MappingProxyType

    commands, binding, source, reader, audience = await setup(db)
    item = message("!oz git context")
    source.messages[item.message_id] = item

    async def changed():
        if fault == "audience":
            audience.private = False
        elif fault.startswith("source-"):
            source.messages[item.message_id] = item.model_copy(
                update={"revision": 1}
                if fault == "source-edit"
                else {"deleted": True}
                if fault == "source-delete"
                else {"topic": "moved"}
            )
        elif fault == "snapshot":
            reader.live = False
        elif fault == "reader-enrollment":
            commands.readers = MappingProxyType({})
        else:
            async with db.sessions.begin() as session:
                if fault == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                elif fault in {"binding", "unbound", "root"}:
                    values = (
                        {"revision": binding.revision + 1}
                        if fault == "binding"
                        else {"state": "unbound"}
                        if fault == "unbound"
                        else {"canonical_directory": "/foreign"}
                    )
                    await session.execute(
                        update(Binding).where(Binding.id == binding.id).values(**values)
                    )
                elif fault == "backend":
                    await session.execute(update(EnrolledBackend).values(enabled=False))
                elif fault == "project":
                    await session.execute(update(EnrolledProject).values(enabled=False))
                elif fault == "lease":
                    await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))

    reader.hook = changed
    with pytest.raises((Conflict, AccessDenied)):
        await commands.route(binding, item, "en", "context")
    assert (
        len(reader.calls) == 1 and not await rows(db, Action) and not await rows(db, ControlToken)
    )


@pytest.mark.parametrize(
    "fault", ["reference", "mode", "base", "false-capability", "sensitive-path"]
)
async def test_changed_or_model_copy_bypassed_native_dto_is_not_output(db, fault):
    commands, binding, source, reader, audience = await setup(db)
    reader.changed = (
        {"reference": reference(binding).model_copy(update={"upstream_session_id": "foreign"})}
        if fault == "reference"
        else {"mode": "branch"}
        if fault == "mode"
        else {"requested_base": "main"}
        if fault == "base"
        else {"mutation_confirmation_usable": True}
        if fault == "false-capability"
        else {
            "files": (
                NativeDiffSummary.model_construct(
                    path=".env",
                    additions=1,
                    deletions=0,
                    status="added",
                    patch_sha256="f" * 64,
                    patch_bytes=1,
                ),
            )
        }
    )
    with pytest.raises((ValueError, AccessDenied)):
        await route(commands, binding, source, "context")
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize("fault", ["grant", "source", "lease", "snapshot", "binding"])
async def test_revalidation_after_first_sql_output_scope_closes_late_source_await_drift(
    db, fault, monkeypatch
):
    commands, binding, source, reader, audience = await setup(db)
    item = message("!oz git context")
    source.messages[item.message_id] = item
    original = source.read
    count = 0

    async def changed(realm, mid):
        nonlocal count
        count += 1
        result = await original(realm, mid)
        if count == 8:
            if fault == "source":
                source.messages[mid] = item.model_copy(update={"deleted": True})
                return source.messages[mid]
            if fault == "snapshot":
                reader.live = False
            else:
                async with db.sessions.begin() as session:
                    if fault == "grant":
                        await session.execute(
                            update(Grant).where(Grant.user_id == 8).values(active=False)
                        )
                    elif fault == "lease":
                        await session.execute(
                            update(WorkerLease).values(expires_at=time.time() - 1)
                        )
                    elif fault == "binding":
                        await session.execute(
                            update(Binding)
                            .where(Binding.id == binding.id)
                            .values(revision=binding.revision + 1)
                        )
        return result

    monkeypatch.setattr(source, "read", changed)
    with pytest.raises((Conflict, AccessDenied)):
        await commands.route(binding, item, "en", "context")
    assert count >= 8 and not await rows(db, Action)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("verb", ["context", "branches", "worktrees", "review"])
async def test_minimum_message_limit_still_allows_only_bounded_summary_and_wrapper(
    db, locale, verb
):
    commands, binding, source, reader, audience = await setup(db, maximum=512)
    text = await route(commands, binding, source, verb, locale=locale)
    assert 0 < len(text) <= 412
    assert "canonical_directory" not in text and "backend_identity" not in text
    assert not await rows(db, Action)


@pytest.mark.parametrize("fault", ["missing-fence", "other-db", "bool-limit", "small-limit"])
async def test_service_requires_shared_fenced_scope_even_for_view_only_commands(db, fault):
    commands, binding, source, reader, audience = await setup(db)
    tokens = TokenService(db) if fault == "missing-fence" else commands.tokens
    maximum = True if fault == "bool-limit" else 511 if fault == "small-limit" else 10000
    if fault == "other-db":
        tokens.db = object()
    with pytest.raises(ValueError):
        NativeGitReviewCommands(
            commands.bindings, {reader.ref: reader}, tokens, source, message_limit=maximum
        )


async def test_viewer_only_can_read_without_operate_approve_or_manage_authority(db):
    commands, binding, source, reader, audience = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).values(active=False))
        session.add_all(
            [
                Grant(
                    realm_id=binding.realm_id,
                    user_id=user,
                    project_id=binding.project_id,
                    role="viewer",
                    active=True,
                )
                for user in (7, 8)
            ]
        )
    text = await route(commands, binding, source, "review")
    assert text and len(reader.calls) == 1
    assert not await rows(db, Action) and not await rows(db, ControlToken)


async def test_expired_consumer_cannot_start_even_a_native_view_read(db):
    commands, binding, source, reader, audience = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
    with pytest.raises(Conflict):
        await route(commands, binding, source, "context")
    assert not reader.calls and not await rows(db, Action)


async def test_original_message_body_must_match_source_gateway_even_with_same_id_and_revision(db):
    commands, binding, source, reader, audience = await setup(db)
    item = message("!oz git context")
    source.messages[item.message_id] = item.model_copy(update={"text": "!oz git branches"})
    with pytest.raises(Conflict):
        await commands.route(binding, item, "en", "context")
    assert not reader.calls
