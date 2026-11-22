"""New read-only Git surfaces through real own transactions; synthetic endpoints only."""

from dataclasses import replace
from html import unescape

import pytest
from sqlalchemy import update

from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeGitReview, SavedWorktree
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.git_review_commands import NativeGitReviewCommands
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.models import Action, Grant, Preference
from tests.integration.test_native_metadata_commands import rows, setup
from tests.integration.test_router import message, send


class Review:
    def __init__(self, ref, contract):
        self.ref, self.contract, self.live = ref, contract, True
        self.calls, self.last = [], None

    def qualified(self, ref):
        return self.live and ref == self.ref

    def contract_for(self, ref):
        assert ref == self.ref
        return self.contract

    async def read(self, ref, *, mode, base, search, limit):
        assert ref == self.ref
        self.calls.append((mode, base, search, limit))
        self.last = NativeGitReview(
            reference=ref,
            provider="git",
            current_branch="feature/original",
            default_branch="main",
            saved_worktrees=(SavedWorktree(relative_directory="feature"),),
            hidden_worktrees=0,
            branches=("main", "feature/original"),
            branches_complete=True,
            inferred_base=None,
            mode=mode,
            requested_base=base,
            hidden_files=0,
            files=(
                NativeDiffSummary(
                    path="src/a.py",
                    additions=1,
                    deletions=2,
                    status="modified",
                    patch_sha256="a" * 64,
                    patch_bytes=30,
                ),
            ),
        )
        return self.last

    def current(self, snapshot):
        return self.live and snapshot is self.last


async def configured(db, *, present=True, live=True):
    router, binding, source, catalog, metadata, audience = await setup(db)
    reader = Review(reference(binding), catalog.contract)
    reader.live = live
    service = NativeGitReviewCommands(router.bindings, {reader.ref: reader}, router.tokens, source)
    router = CommandRouter(
        router.bindings,
        source,
        router.inbox,
        metadata=metadata,
        git_review=service if present else None,
    )
    return router, binding, source, catalog, reader, service


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_patch_route_uses_owned_command_receipt_and_replay_preserves_original_reply(
    db, locale
):
    from tests.integration.test_git_patch_commands import PatchReader

    router, binding, source, catalog, original, _ = await configured(db)
    reader = PatchReader(original.ref, original.contract)
    router.git_review = NativeGitReviewCommands(
        router.bindings, {reader.ref: reader}, router.tokens, source
    )
    async with db.sessions.begin() as session:
        session.add(Preference(principal="user:realm:7", locale=locale))
    item = message("!oz git patch src/a.py")
    reply = await send(router, source, item)
    assert reply.state == "reply" and "+new" in reply.text
    assert reply.binding_id == binding.id and len(reader.calls) == 1
    reader.patch = "+newer content must not replace original reply\n"
    assert await router.route(item) == reply and len(reader.calls) == 1
    assert not catalog.calls and not await rows(db, Action)


@pytest.mark.parametrize("present", [False, True])
async def test_patch_without_separate_projection_never_becomes_prompt_or_legacy_page(db, present):
    router, binding, source, catalog, reader, service = await configured(db, present=present)
    reply = await send(router, source, message("!oz git patch src/a.py"))
    assert reply.state == "reply" and "available for this conversation" in reply.text
    assert not reader.calls and not catalog.calls
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize(
    "arguments",
    [
        "context",
        "branches feature",
        "worktrees feature",
        "review",
        "review working",
        "review branch main",
        "review committed main",
    ],
)
async def test_new_surfaces_use_same_original_ref_and_never_legacy_tokens_or_actions(
    db, locale, arguments
):
    router, binding, source, catalog, reader, service = await configured(db)
    async with db.sessions.begin() as session:
        session.add(Preference(principal="user:realm:7", locale=locale))
    reply = await send(router, source, message("!oz git " + arguments))
    assert reply.state == "reply" and reply.binding_id == binding.id
    assert ("僅摘要" if locale == "zh-TW" else "Summary only") in unescape(reply.text)
    assert len(reader.calls) == 1 and catalog.calls == []
    mode, base, search, limit = reader.calls[0]
    assert limit == 50
    assert base == ("main" if mode in {"branch", "committed"} else None)
    assert search == ("feature" if arguments.startswith("branches") else "")
    assert await router.route(source.messages[101]) == reply and len(reader.calls) == 1
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize("present,live", [(False, False), (True, False)])
@pytest.mark.parametrize("verb", ["context", "branches", "worktrees", "review"])
@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_unqualified_new_verbs_never_become_old_page_tokens(db, present, live, verb, locale):
    router, binding, source, catalog, reader, service = await configured(
        db, present=present, live=live
    )
    async with db.sessions.begin() as session:
        session.add(Preference(principal="user:realm:7", locale=locale))
    reply = await send(router, source, message("!oz git " + verb))
    assert ("目前無法" if locale == "zh-TW" else "available for this conversation") in reply.text
    assert not reader.calls and not catalog.calls
    assert not await rows(db, ControlToken) and not await rows(db, Action)


async def test_view_denied_before_any_git_review_or_metadata_read(db):
    router, binding, source, catalog, reader, service = await configured(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).values(active=False))
    with pytest.raises(AccessDenied):
        await send(router, source, message("!oz git context"))
    assert not reader.calls and not catalog.calls


@pytest.mark.parametrize("arguments", ["context", "review"])
async def test_bot_and_edited_source_never_reach_review_reader(db, arguments):
    router, binding, source, catalog, reader, service = await configured(db)
    assert (await router.route(message("!oz git " + arguments, is_bot=True))).state == "ignore"
    event = message("!oz git " + arguments)
    source.messages[101] = event.model_copy(update={"revision": 1})
    assert (await router.route(event)).state == "ignore"
    assert not reader.calls and not catalog.calls


@pytest.mark.parametrize(
    "field", ["bindings", "db", "source", "fence", "tokens-db", "tokens-fence"]
)
async def test_git_review_constructor_rejects_foreign_shared_scope(db, field):
    router, binding, source, catalog, reader, service = await configured(db)
    if field.startswith("tokens-"):
        from jt_oz_bridge.services.tokens import TokenService

        service.tokens = TokenService(db, fence=service.fence)
        if field == "tokens-db":
            service.tokens.db = object()
        else:
            service.tokens.fence = replace(service.fence, holder="foreign")
    else:
        setattr(service, field, object())
    with pytest.raises(ValueError, match="router_git_review_scope_mismatch"):
        CommandRouter(router.bindings, source, router.inbox, git_review=service)


async def test_legacy_status_and_mutations_keep_the_original_metadata_path(db):
    router, binding, source, catalog, reader, service = await configured(db)
    # Existing metadata fixture has no Git qualification: preserve its original
    # unavailable result, rather than accidentally claiming the new review scope.
    status = await send(router, source, message("!oz git status"))
    assert "available for this conversation" in status.text
    for mid, verb in enumerate(["diff", "commit", "push"], 102):
        reply = await send(router, source, message("!oz git " + verb, mid))
        assert "can't be run" in reply.text
    assert not reader.calls and not catalog.calls


async def test_help_git_lists_new_and_old_surfaces_without_querying_native(db):
    router, binding, source, catalog, reader, service = await configured(db)
    reply = await send(router, source, message("!oz help git"))
    for text in [
        "git context",
        "git branches",
        "git worktrees",
        "git review",
        "git status",
        "git commit",
        "git push",
    ]:
        assert text in unescape(reply.text)
    assert not reader.calls and not catalog.calls
