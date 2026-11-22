"""Real isolated own outbox/wrapper/UUID with synthetic review metadata, no live chat."""

import hashlib
import re

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.git_review import (
    NativeDiffSummary,
    NativeGitReview,
    NativeReviewBase,
    SavedWorktree,
)
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.git_review import render_git_review
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Delivery, Grant, WorkerLease
from tests.integration.test_routed_output import setup
from tests.unit.test_markdown import Elements


def page_only(content):
    return re.sub(r"\[\u200b\]\(#jtoz:[0-9a-f-]{36}\)$", "", content)


RAW_PATCH = b"@@ -1 +1 @@\n-SYNTHETIC-RAW-PATCH-MUST-NOT-DISPLAY\n+synthetic\n"
PATCH_HASH = hashlib.sha256(RAW_PATCH).hexdigest()
MODES = ("context", "branches", "worktrees", "review-working", "review-branch", "review-committed")


def report(binding, mode):
    comparison = mode.removeprefix("review-") if mode.startswith("review-") else "working"
    return NativeGitReview(
        reference=reference(binding),
        provider="git",
        current_branch="feature/@**all**",
        default_branch="main",
        branches=("feature/@**all**", "[x](https://evil.invalid)"),
        branches_complete=False,
        saved_worktrees=(SavedWorktree(relative_directory="worktrees/@**all**"),),
        hidden_worktrees=1,
        inferred_base=NativeReviewBase(name="main", ref="refs/heads/main", source="reflog"),
        mode=comparison,
        requested_base=None if comparison == "working" else "refs/heads/main",
        files=tuple(
            NativeDiffSummary(
                path="src/@**all**.py" if n == 0 else f"src/large-{n}.py",
                additions=n + 1,
                deletions=1,
                status="modified",
                patch_sha256=PATCH_HASH,
                patch_bytes=len(RAW_PATCH),
            )
            for n in range(20)
        ),
        hidden_files=1,
    )


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cap", [512, 700, 10000])
async def test_real_routed_outbox_keeps_literal_metadata_full_hash_footer_and_one_page(
    db, locale, mode, cap
):
    outbox, binding, worker, unused_publisher, chat = await setup(db)
    snapshot = report(binding, mode)  # Required valid DTO before asserting behavior.
    verb = mode.split("-")[0]
    body = render_git_review(snapshot, verb, locale, message_limit=cap)
    expected = [
        "feature/@**all**"
        if verb in {"context", "branches"}
        else "worktrees/@**all**"
        if verb == "worktrees"
        else "src/@**all**.py"
    ]
    if verb == "review":
        expected.append(PATCH_HASH)
    if mode in {"review-branch", "review-committed"}:
        expected.append("refs/heads/main")
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=cap, topic_limit=100)
    routed = RoutedInput(
        "reply", binding.id, binding.revision, body, "synthetic-review-body", locale=locale
    )
    batch = await publisher.publish(routed)
    assert batch is not None and len(batch.deliveries) == 1
    saved = await outbox.load(batch.deliveries[0])
    content = saved.payload["content"]
    assert len(content) <= cap and len(body) <= cap - 100
    assert not content.startswith(Translator().render("output.page", locale, index=1, total=1))
    assert re.search(r"\[\u200b\]\(#jtoz:[0-9a-f-]{36}\)$", content)
    assert saved.payload["marker"] == "jtoz:" + saved.id
    parser = Elements()
    parser.feed(MobileMarkdown(locale=locale).preview_html(page_only(content)))
    visible = "".join(parser.text)
    assert all(value in visible for value in expected)
    assert not parser.links and not {"pre", "script", "iframe", "img", "em"} & set(parser.tags)
    assert "@**all**" not in content and "SYNTHETIC-RAW-PATCH-MUST-NOT-DISPLAY" not in visible
    assert "HEAD" in visible and ("暫存區" if locale == "zh-TW" else "index") in visible.lower()
    assert ("都未確認" if locale == "zh-TW" else "are not verified") in visible
    assert ("僅摘要" if locale == "zh-TW" else "Summary only") in visible
    assert "original-session" not in visible and binding.canonical_directory not in visible
    # The safe metadata body must survive a second canonical serialization,
    # rather than merely fitting before the actual outbox expands punctuation.
    again = MobileMarkdown(locale=locale).render(body, cap, reserved_characters=100)
    assert again.pages == (body,) and again.source_fallback_blocks == 0
    assert await publisher.publish(routed) == batch and chat.calls == []
    async with db.sessions() as session:
        assert not (await session.scalars(select(Action))).all()
        assert len((await session.scalars(select(Delivery))).all()) == 1


@pytest.mark.parametrize("fault", ["grant", "lease"])
async def test_safe_summary_is_not_permission_to_publish_after_revocation(db, fault):
    outbox, binding, worker, unused_publisher, chat = await setup(db)
    snapshot = report(binding, "review-working")
    body = render_git_review(snapshot, "review", "en", message_limit=512)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=512, topic_limit=100)
    routed = RoutedInput(
        "reply", binding.id, binding.revision, body, "synthetic-revoked", locale="en"
    )
    async with db.sessions.begin() as session:
        if fault == "grant":
            await session.execute(update(Grant).values(active=False))
        else:
            await session.execute(update(WorkerLease).values(expires_at=0))
    with pytest.raises((Conflict, AccessDenied)):
        await publisher.publish(routed)
    async with db.sessions() as session:
        assert not (await session.scalars(select(Delivery))).all()
    assert chat.calls == []


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("mode", ["review-branch", "review-committed"])
async def test_long_explicit_base_cannot_displace_first_complete_hash_or_footer(db, locale, mode):
    outbox, binding, worker, unused_publisher, chat = await setup(db)
    snapshot = report(binding, mode).model_copy(update={"requested_base": "a" * 255})
    # Original branch/base selection stays in the service; ellipsis is display
    # only, never a confirmation or a replacement comparison reference.
    body = render_git_review(snapshot, "review", locale, message_limit=512)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=512, topic_limit=100)
    batch = await publisher.publish(
        RoutedInput(
            "reply", binding.id, binding.revision, body, "synthetic-long-base", locale=locale
        )
    )
    assert batch is not None and len(batch.deliveries) == 1
    content = (await outbox.load(batch.deliveries[0])).payload["content"]
    parser = Elements()
    parser.feed(MobileMarkdown(locale=locale).preview_html(page_only(content)))
    visible = "".join(parser.text)
    assert len(content) <= 512 and "src/@**all**.py" in visible and PATCH_HASH in visible
    assert "…" in visible and "HEAD" in visible
    assert ("都未確認" if locale == "zh-TW" else "are not verified") in visible
    assert not parser.links and "pre" not in parser.tags and chat.calls == []


@pytest.mark.parametrize("tail", ["last-row", "more-files", "protected-after"])
async def test_saturated_counts_and_maximum_path_keep_first_hash_at_minimum_cap(db, tail):
    outbox, binding, worker, unused_publisher, chat = await setup(db)
    path = "/".join(["a" * 255] * 16)
    first = NativeDiffSummary(
        path=path,
        additions=1000000,
        deletions=1000000,
        status="modified",
        patch_sha256="f" * 64,
        patch_bytes=1048576,
    )
    # Strict DTO validation precedes all behavioral assertions. These are
    # schema-legal counts, not an assertion that Native emits this exact pair.
    files = (first,)
    if tail == "more-files":
        files += (
            NativeDiffSummary(
                path="src/other.py",
                additions=1,
                deletions=1,
                status="modified",
                patch_sha256="e" * 64,
                patch_bytes=1,
            ),
        )
    snapshot = NativeGitReview(
        reference=reference(binding),
        provider="git",
        current_branch="main",
        default_branch="main",
        saved_worktrees=(),
        hidden_worktrees=0,
        branches=(),
        branches_complete=True,
        inferred_base=None,
        mode="committed",
        requested_base="a" * 255,
        files=files,
        hidden_files=1 if tail == "protected-after" else 0,
    )
    body = render_git_review(snapshot, "review", "en", message_limit=512)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=512, topic_limit=100)
    batch = await publisher.publish(
        RoutedInput("reply", binding.id, binding.revision, body, "max-path-counts", locale="en")
    )
    assert batch is not None and len(batch.deliveries) == 1
    content = (await outbox.load(batch.deliveries[0])).payload["content"]
    parser = Elements()
    parser.feed(MobileMarkdown().preview_html(page_only(content)))
    visible = "".join(parser.text)
    assert len(body) <= 412 and len(content) <= 512
    assert "a" * 47 + "…" in visible and "f" * 64 in visible
    assert "are not verified" in visible and "clean state are not verified" in visible
    assert "pre" not in parser.tags and not parser.links and chat.calls == []
    omitted = Translator().render("git_review.truncated", "en")
    assert (omitted in visible) == (tail != "last-row")
