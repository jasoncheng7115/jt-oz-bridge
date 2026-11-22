"""Real ownDB authorization/token tests with synthetic Human and patch readers."""

import hashlib
import re
import time
from html import unescape

import pytest
from sqlalchemy import update

from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeGitPatch
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.services.git_review_commands import NativeGitReviewCommands
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_git_review_commands import ReviewReader, route, rows, setup


class PatchReader(ReviewReader):
    def __init__(self, ref, contract):
        super().__init__(ref, contract)
        self.patch_enabled = True
        self.patch = "--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n"

    def qualified_patch(self, ref):
        return self.patch_enabled and self.qualified(ref)

    def patch_contract_for(self, ref):
        return self.contract_for(ref)

    async def read_patch(self, ref, *, path, mode="working", base=None):
        self.calls.append((path, mode, base))
        content = self.patch.encode()
        self.snapshot = NativeGitPatch(
            reference=ref,
            mode=mode,
            requested_base=base,
            file=NativeDiffSummary(
                path=path,
                additions=1,
                deletions=1,
                status="modified",
                patch_sha256=hashlib.sha256(content).hexdigest(),
                patch_bytes=len(content),
            ),
            patch=self.patch,
            hidden_files=0,
        ).model_copy(update=self.changed)
        if self.hook:
            await self.hook()
        return self.snapshot

    def current_patch(self, snapshot):
        return self.live and self.patch_enabled and snapshot is self.snapshot


async def prepared(db, maximum=10000):
    old, binding, source, original, audience = await setup(db, maximum)
    reader = PatchReader(original.ref, original.contract)
    commands = NativeGitReviewCommands(
        old.bindings, {reader.ref: reader}, old.tokens, source, message_limit=maximum
    )
    return commands, binding, source, reader, audience


def next_page(text):
    match = re.search(r"!oz git patch (page:[A-Za-z0-9_-]{32})", unescape(text))
    return match[1] if match else None


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize(
    "arguments,mode,base,path",
    [
        ("patch src/a.py", "working", None, "src/a.py"),
        ("patch working src/a file.py", "working", None, "src/a file.py"),
        ("patch branch refs/heads/main src/a.py", "branch", "refs/heads/main", "src/a.py"),
        ("patch committed abc123 src/a.py", "committed", "abc123", "src/a.py"),
    ],
)
async def test_patch_uses_exact_original_comparison_and_no_action(
    db, locale, arguments, mode, base, path
):
    commands, binding, source, reader, _ = await prepared(db)
    text = await route(commands, binding, source, arguments, locale=locale)
    assert reader.calls == [(path, mode, base)]
    assert "+new" in text and ("not verified" in text or "都未確認" in text)
    assert not next_page(text)
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("maximum", [512, 1000])
async def test_pages_are_balanced_redacted_and_actor_scoped_with_fresh_reads(db, locale, maximum):
    commands, binding, source, reader, _ = await prepared(db, maximum)
    reader.patch = '+password="do-not-disclose"\n+@**all** <script>alert(1)</script>\n' * 50
    text = await route(commands, binding, source, "patch src/a.py", locale=locale)
    seen = 0
    while True:
        seen += 1
        assert len(text) <= maximum - 100
        assert "do-not-disclose" not in text
        rendered = MobileMarkdown(locale=locale).render(text, maximum, reserved_characters=100)
        assert len(rendered.pages) == 1 and not rendered.source_fallback_blocks
        token = next_page(text)
        if not token:
            break
        assert seen < 300
        text = await route(
            commands, binding, source, "patch " + token, locale=locale, message_id=101 + seen
        )
    assert seen > 1 and len(reader.calls) == seen
    tokens = await rows(db, ControlToken)
    assert all(x.used is True for x in tokens)
    assert all("do-not-disclose" not in str(x.context) for x in tokens)
    assert not await rows(db, Action)


@pytest.mark.parametrize("fault", ["disabled", "summary-only", "missing"])
async def test_unqualified_patch_has_zero_native_reads_and_no_tokens(db, fault):
    commands, binding, source, reader, _ = await prepared(db)
    if fault == "disabled":
        reader.patch_enabled = False
    elif fault == "summary-only":
        commands = NativeGitReviewCommands(
            commands.bindings,
            {reader.ref: ReviewReader(reader.ref, reader.contract)},
            commands.tokens,
            source,
        )
    else:
        commands = NativeGitReviewCommands(commands.bindings, {}, commands.tokens, source)
    text = await route(commands, binding, source, "patch src/a.py")
    assert "available for this conversation" in text
    assert not reader.calls and not await rows(db, ControlToken)


@pytest.mark.parametrize(
    "value",
    [
        "patch",
        "patch ../secret",
        "patch /etc/passwd",
        "patch .env",
        "patch working",
        "patch branch main",
        "patch committed -evil src/a.py",
        "patch page:bad",
        "patch src/\x00bad.py",
    ],
)
async def test_bad_queries_fail_before_native_or_tokens(db, value):
    commands, binding, source, reader, _ = await prepared(db)
    with pytest.raises(ValueError):
        await route(commands, binding, source, value)
    assert not reader.calls and not await rows(db, ControlToken)


@pytest.mark.parametrize("fault", ["actor", "topic", "binding", "issuer", "content", "expired"])
async def test_page_scope_or_content_change_does_not_consume_or_issue_tokens(db, fault):
    commands, binding, source, reader, _ = await prepared(db, 1000)
    reader.patch = "+long normal line\n" * 200
    first = await route(commands, binding, source, "patch src/a.py")
    token = next_page(first)
    assert token
    changes = {"message_id": 102}
    if fault == "actor":
        changes["author_id"] = 8
    elif fault == "topic":
        changes["topic"] = "Another topic"
    elif fault == "binding":
        binding = binding.__class__(
            **{key: value for key, value in binding.__dict__.items() if not key.startswith("_")}
        )
        binding.revision += 1
    elif fault == "issuer":
        source.messages[101] = source.messages[101].model_copy(update={"deleted": True})
    elif fault == "content":
        reader.patch += "+changed\n"
    else:
        async with db.sessions.begin() as session:
            await session.execute(update(ControlToken).values(expires_at=time.time() - 1))
    with pytest.raises(ValueError):
        await route(commands, binding, source, "patch " + token, **changes)
    tokens = await rows(db, ControlToken)
    assert len(tokens) == 1 and tokens[0].used is False


@pytest.mark.parametrize("fault", ["source", "grant", "lease", "snapshot", "audience", "public"])
async def test_revocation_after_native_await_discloses_no_patch_and_no_token(db, fault):
    commands, binding, source, reader, audience = await prepared(db, 1000)
    reader.patch = "+line\n" * 1000

    async def revoke():
        if fault == "source":
            source.messages[101] = source.messages[101].model_copy(update={"text": "changed"})
        elif fault == "snapshot":
            reader.live = False
        elif fault == "audience":
            audience.users = frozenset({7, 8, 999})
        elif fault == "public":
            audience.private = False
        else:
            async with db.sessions.begin() as session:
                if fault == "grant":
                    await session.execute(update(Grant).values(active=False))
                else:
                    await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))

    reader.hook = revoke
    with pytest.raises(ValueError):
        await route(commands, binding, source, "patch src/a.py")
    assert not await rows(db, ControlToken) and not await rows(db, Action)


async def test_incomplete_private_key_cannot_be_split_or_disclosed(db):
    commands, binding, source, reader, _ = await prepared(db, 512)
    reader.patch = "+-----BEGIN PRIVATE KEY-----\n+PRIVATE-CONTENT-WITHOUT-END\n"
    with pytest.raises(ValueError, match="incomplete_private_key"):
        await route(commands, binding, source, "patch src/a.py")
    assert not await rows(db, ControlToken) and not await rows(db, Action)


async def test_page_token_consume_and_next_issuance_rollback_together(db):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    commands, binding, source, reader, _ = await prepared(db, 1000)
    reader.patch = "+line\n" * 1000
    token = next_page(await route(commands, binding, source, "patch src/a.py"))
    assert token

    def fail_on_new_token(session, _context, _instances):
        if any(isinstance(item, ControlToken) for item in session.new):
            raise RuntimeError("injected next page flush failure")

    event.listen(Session, "before_flush", fail_on_new_token)
    try:
        with pytest.raises(RuntimeError, match="next page flush failure"):
            await route(commands, binding, source, "patch " + token, message_id=102)
    finally:
        event.remove(Session, "before_flush", fail_on_new_token)
    tokens = await rows(db, ControlToken)
    assert len(tokens) == 1 and tokens[0].used is False


async def test_page_is_single_use_and_replay_never_selects_another_file(db):
    commands, binding, source, reader, _ = await prepared(db, 1000)
    reader.patch = "+line\n" * 1000
    first = await route(commands, binding, source, "patch src/a.py")
    token = next_page(first)
    assert token
    await route(commands, binding, source, "patch " + token, message_id=102)
    count = len(reader.calls)
    with pytest.raises(Conflict):
        await route(commands, binding, source, "patch " + token, message_id=103)
    assert len(reader.calls) == count


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("maximum", [512, 1000, 10000])
async def test_actual_outbox_preserves_inert_patch_and_copyable_continuation(db, locale, maximum):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.outbox import Outbox
    from jt_oz_bridge.services.routed_output import RoutedOutbox
    from tests.unit.test_markdown import Elements

    commands, binding, source, reader, _ = await prepared(db, maximum)
    reader.patch = "+@**all** [x](https://evil.invalid) <script>bad()</script>\n" * 200
    body = await route(commands, binding, source, "patch src/a.py", locale=locale)
    outbox = Outbox(commands.bindings, 77, fence=commands.fence)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=maximum, topic_limit=100)
    batch = await publisher.publish(
        RoutedInput(
            "reply", binding.id, binding.revision, body, "synthetic-patch-output", locale=locale
        )
    )
    assert batch is not None and len(batch.deliveries) == 1
    content = (await outbox.load(batch.deliveries[0])).payload["content"]
    assert len(content) <= maximum
    parser = Elements()
    parser.feed(MobileMarkdown(locale=locale).preview_html(content))
    assert not [link for link in parser.links if "#jtoz:" not in link] and not {
        "script",
        "iframe",
        "img",
        "em",
    } & set(parser.tags)
    assert "pre" in parser.tags and "@**all**" in "".join(parser.text)
    assert (
        "not verified" in "".join(parser.text)
        if locale == "en"
        else "都未確認" in "".join(parser.text)
    )
    assert next_page(body) == next_page(content)
    assert not await rows(db, Action)
