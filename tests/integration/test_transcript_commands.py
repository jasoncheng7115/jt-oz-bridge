"""Real SQL/token/router boundaries with an explicitly synthetic Native reader."""

import re
import time
from html import unescape
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.transcript import NativeTranscriptPage, project_message
from jt_oz_bridge.domain.control import ExecutionState, SessionSnapshot
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.transcript_commands import NativeTranscriptCommands
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_router import Source, count, message, send
from tests.support import REF, bound


class OriginalReader:
    contract_hash = "a" * 64

    def __init__(self):
        self.messages = [
            project_message(
                {
                    "id": "msg_" + str(i),
                    "type": "user",
                    "text": "Original computer input " + str(i),
                    "time": {"created": 100 - i},
                }
            )
            for i in range(17)
        ]
        self.pages = []
        self.calls = []
        self.alive = True
        self.hook = None
        self.foreign = False
        self.state = ExecutionState.RUNNING
        self.owner_epoch = "d" * 64
        self.connection_epoch = "synthetic-not-installed"

    def contract_for(self, ref):
        assert ref == REF
        return self.contract_hash

    async def capture(self, ref, *, cursor=None, limit=20):
        self.calls.append((ref, cursor, limit))
        start = int(cursor.removeprefix("opaque:")) if cursor else 0
        if self.hook:
            await self.hook()
        page = NativeTranscriptPage(
            reference=ref,
            contract_sha256=self.contract_hash,
            semantics_sha256="b" * 64,
            installed_evidence_sha256="c" * 64,
            owner_epoch=self.owner_epoch,
            connection_epoch=self.connection_epoch,
            resource_fence="e" * 64,
            session_info_sha256="f" * 64,
            state=self.state,
            witness_id=str(uuid4()),
            observed_at=time.time(),
            expires_at=time.time() + 5,
            cursor=cursor,
            limit=limit,
            next_cursor="opaque:" + str(start + limit)
            if start + limit < len(self.messages)
            else None,
            entries=tuple(self.messages[start : start + limit]),
        )
        if self.foreign:
            page = page.model_copy(
                update={"reference": ref.model_copy(update={"project_id": "foreign"})}
            )
        self.pages.append(page)
        return page

    def current(self, page):
        return self.alive and any(p is page for p in self.pages)

    async def snapshot(self, ref):
        return SessionSnapshot(
            reference=ref,
            title="Original computer work",
            state=ExecutionState.RUNNING,
            reconciled=True,
            cursor="synthetic-state",
        )


async def setup(db, cap=2000):
    bindings, binding, control, audience = await bound(db)
    holder = "native-transcript-commands"
    number = await DurableStore(db).acquire_lease(holder)
    fence = ConsumerFence(holder, number)
    source = Source()
    reader = OriginalReader()
    commands = NativeTranscriptCommands(
        bindings, TokenService(db, fence=fence), source, {REF: reader}, message_limit=cap
    )
    router = CommandRouter(bindings, source, CommandInbox(db, holder, number), history=commands)
    return router, binding, source, reader, audience, commands


def tokens(text):
    text = unescape(text)
    return re.findall(r"!oz history ([A-Za-z0-9_-]{32})", text)


async def test_original_computer_input_is_browsable_without_any_bridge_prompt_action(db):
    router, binding, source, native, audience, commands = await setup(db)
    menu = await send(router, source, message("!oz history", 101))
    assert "OpenCode messages" in menu.text
    choice = await send(router, source, message("!oz history " + tokens(menu.text)[0] + " 1", 102))
    assert "Original computer input 0" in choice.text
    assert "OpenCode ·" in choice.text and "Saved reply" not in choice.text
    older = await send(router, source, message("!oz history " + tokens(menu.text)[1], 103))
    choice2 = await send(
        router, source, message("!oz history " + tokens(older.text)[0] + " 1", 104)
    )
    assert "Original computer input 10" in choice2.text
    assert all(call[0] == REF for call in native.calls)
    assert any(call[1] == "opaque:10" for call in native.calls)
    assert await count(db, Action) == 0
    repeat = await router.route(source.messages[102])
    assert repeat == choice
    reused = await send(router, source, message("!oz history " + tokens(menu.text)[0] + " 1", 105))
    assert "Original computer input" not in reused.text


@pytest.mark.parametrize(
    "mode", ["actor", "revision", "projection", "contract", "foreign-reader", "expired-reader"]
)
async def test_history_tokens_cannot_change_actor_binding_or_selected_native_entry(db, mode):
    router, binding, source, native, audience, commands = await setup(db)
    menu = await send(router, source, message("!oz history", 101))
    opaque = tokens(menu.text)[0]
    options = {}
    if mode == "actor":
        options["author_id"] = 8
    elif mode == "revision":
        async with db.sessions.begin() as s:
            await s.execute(update(Binding).where(Binding.id == binding.id).values(revision=2))
    elif mode == "projection":
        native.messages[0] = project_message(
            {
                "id": "msg_0",
                "type": "user",
                "time": {"created": 100},
                "text": "replaced native projection",
            }
        )
    elif mode == "contract":
        native.contract_for = lambda ref: "1" * 64
    elif mode == "foreign-reader":
        native.foreign = True
    else:
        native.alive = False
    denied = await send(router, source, message("!oz history " + opaque + " 1", 102, **options))
    assert "Original computer input 0" not in denied.text
    assert "replaced native projection" not in denied.text
    assert await count(db, Action) == 0


@pytest.mark.parametrize("change", ["audience", "grant", "source"])
async def test_rechecks_private_scope_and_original_human_source_after_native_await(db, change):
    router, binding, source, native, audience, commands = await setup(db)

    async def revoke():
        if change == "audience":
            audience.users = frozenset({7, 8, 999})
        elif change == "grant":
            async with db.sessions.begin() as s:
                await s.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        else:
            source.messages[101] = source.messages[101].model_copy(update={"deleted": True})

    native.hook = revoke
    if change in {"audience", "grant"}:
        with pytest.raises((Conflict, AccessDenied)):
            await send(router, source, message("!oz history", 101))
    else:
        reply = await send(router, source, message("!oz history", 101))
        assert "Original computer input" not in reply.text and not tokens(reply.text)
    assert await count(db, Action) == 0


@pytest.mark.parametrize("cap", [512, 1000, 2000])
async def test_menu_budget_and_text_pages_keep_native_selection_and_neutralize_mentions(db, cap):
    router, binding, source, native, audience, commands = await setup(db, cap)
    original = "@**all**\n```python\n" + ('print("original text")\n' * 90) + "```"
    native.messages[0] = project_message(
        {"id": "msg_0", "type": "user", "time": {"created": 100}, "text": original}
    )
    menu = await send(router, source, message("!oz history", 101))
    assert len(menu.text) <= cap - 100
    selected = await send(
        router, source, message("!oz history " + tokens(menu.text)[0] + " 1", 102)
    )
    assert len(selected.text) <= cap - 100 and "@**all**" not in selected.text
    seen = selected.text
    identity = 103
    while tokens(selected.text):
        selected = await send(
            router, source, message("!oz history " + tokens(selected.text)[0], identity)
        )
        assert len(selected.text) <= cap - 100
        seen += selected.text
        identity += 1
        assert identity < 200
    assert "original text" in seen and await count(db, Action) == 0


@pytest.mark.parametrize("primary_read_failure", [False, True])
async def test_status_is_current_native_state_instead_of_a_saved_action_outcome(
    db, primary_read_failure
):
    router, binding, source, native, audience, commands = await setup(db)
    if primary_read_failure:
        commands.history.bindings.control.snapshot = AsyncMock(side_effect=ConnectionError)
    reply = await send(router, source, message("!oz status", 101))
    assert "Running" in reply.text
    assert "Current status" in reply.text if primary_read_failure else "Conversation" in reply.text
    assert "Last saved" not in reply.text and await count(db, Action) == 0


async def test_status_says_unconfirmed_when_both_live_checks_fail_during_a_tool_run(db):
    # 11-25: `!status` while a shell tool ran got "expired or invalid": the router's
    # live check failed, and the fallback asked the same changing evidence again.
    router, binding, source, native, audience, commands = await setup(db)
    changed = ValueError("v2_execution_owner_or_snapshot_evidence_changed")
    commands.history.bindings.control.snapshot = AsyncMock(side_effect=changed)
    native.snapshot = AsyncMock(side_effect=changed)
    reply = await send(router, source, message("!status", 101))
    assert "could not confirm its live status" in reply.text and "Queue paused: No" in reply.text
    assert "expired" not in reply.text and await count(db, Action) == 0


async def test_bilingual_menu_and_selected_original_input(db):
    router, binding, source, native, audience, commands = await setup(db)
    source.messages[101] = item = message("!oz history", 101)
    text = await commands.route(binding, item, "zh-TW", "")
    assert "OpenCode 訊息" in text and "輸入" in text
    opaque = tokens(text)[0]
    source.messages[102] = item2 = message("!oz history " + opaque + " 1", 102)
    shown = await commands.route(binding, item2, "zh-TW", opaque + " 1")
    assert "Original computer input 0" in shown


async def test_original_tool_status_is_localized_without_tool_input_or_output(db):
    _, _, _, _, _, commands = await setup(db)
    entry = project_message(
        {
            "id": "msg_tool",
            "type": "assistant",
            "time": {"created": 1, "completed": 2},
            "agent": "build",
            "model": {"providerID": "fixture", "id": "test", "variant": "none"},
            "content": [
                {
                    "type": "tool",
                    "id": "tool_1",
                    "name": "bash",
                    "time": {"created": 1, "completed": 2},
                    "state": {
                        "status": "completed",
                        "input": {"command": "PRIVATE_COMMAND"},
                        "content": [{"type": "text", "text": "PRIVATE_OUTPUT"}],
                        "metadata": {"exit": 17},
                    },
                }
            ],
        }
    )
    english = commands.body(entry, "en")
    chinese = commands.body(entry, "zh-TW")
    assert "completed" in english and "已完成" in chinese
    assert "17" in chinese and "none" in chinese and "PRIVATE_" not in chinese


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_model_history_menu_preserves_visible_punctuation_through_real_outbox(db, locale):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.presentation.markdown import MobileMarkdown
    from jt_oz_bridge.services.outbox import Outbox
    from jt_oz_bridge.services.routed_output import RoutedOutbox
    from tests.unit.test_markdown import Elements

    _, binding, source, native, _, commands = await setup(db, cap=10000)
    native.messages = [
        project_message(
            {
                "id": "native_model_menu",
                "type": "model-switched",
                "time": {"created": 1},
                "model": {"providerID": "p", "id": "m.1-x_y", "variant": "v"},
            }
        )
    ]
    source.messages[101] = item = message("!oz history", 101)
    text = await commands.route(binding, item, locale, "")
    outbox = Outbox(commands.history.bindings, 77, fence=commands.tokens.fence)
    reply = RoutedOutbox(outbox, realm_id="realm", message_limit=10000, topic_limit=60)
    batch = await reply.publish(
        RoutedInput(
            "reply", binding.id, binding.revision, text, "history-model-menu", locale=locale
        )
    )
    assert batch is not None
    saved = await outbox.load(batch.deliveries[0])
    parser = Elements()
    parser.feed(MobileMarkdown(locale=locale).preview_html(saved.payload["content"]))
    visible = "".join(parser.text)
    assert "p/m.1-x_y [v]" in visible and "&#" not in visible
    assert not [link for link in parser.links if "#jtoz:" not in link] and not {
        "script",
        "iframe",
        "img",
        "em",
    } & set(parser.tags)
    assert await count(db, Action) == 0


@pytest.mark.parametrize("kind", ["literal-metadata", "inline-code", "fenced-code", "markup"])
def test_history_preview_flattens_safe_tokens_without_activating_or_recursively_decoding(kind):
    from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal
    from jt_oz_bridge.services.transcript_commands import history_preview
    from tests.unit.test_markdown import Elements

    raw = "@**all** [go](https://evil.invalid) <script>x</script> & &#47;"
    source = {
        "literal-metadata": literal(raw),
        "inline-code": "`" + raw + "`",
        "fenced-code": "```text\n" + raw + "\n```",
        "markup": "[go](https://evil.invalid) @**all** <script>x</script>",
    }[kind]
    preview = history_preview(source, 1000)
    parser = Elements()
    parser.feed(MobileMarkdown().preview_html(preview))
    visible = "".join(parser.text).strip()
    if kind == "markup":
        assert visible == "go @all <script>x</script>"
    else:
        assert visible == raw  # Literal user entity text must not be decoded again.
    assert not parser.links and set(parser.tags) <= {"p"}
    assert "@**all**" not in preview and "<script>" not in preview


def test_history_preview_redacts_after_entity_decoding_before_clipping():
    from jt_oz_bridge.presentation.markdown import MobileMarkdown
    from jt_oz_bridge.services.transcript_commands import history_preview
    from tests.unit.test_markdown import Elements

    preview = history_preview("API&#95;KEY=SYNTHETIC_SECRET", 80)
    parser = Elements()
    parser.feed(MobileMarkdown().preview_html(preview))
    visible = "".join(parser.text)
    assert "[REDACTED]" in visible and "SYNTHETIC_SECRET" not in visible


def test_history_preview_strips_controls_and_clips_text_before_literal_encoding():
    from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal
    from jt_oz_bridge.services.transcript_commands import history_preview
    from tests.unit.test_markdown import Elements

    original = "m/x-y_z [v]"
    preview = history_preview("\x1b[31m" + literal(original), 9)
    parser = Elements()
    parser.feed(MobileMarkdown().preview_html(preview))
    assert "".join(parser.text).strip() == original[:9]
    assert "\x1b" not in preview and "&#" not in "".join(parser.text)


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        ({"type": "APIError", "status": 401}, "auth"),
        ({"status": 403}, "auth"),
        ({"type": "ContextOverflowError", "status": 429}, "rate_limited"),
        ({"status": 408}, "timeout"),
        ({"type": "ProviderError", "status": 504}, "timeout"),
        ({"type": "TimeoutError"}, "timeout"),
        ({"type": "request_timed_out"}, "timeout"),
        ({"type": "ETIMEDOUT"}, "timeout"),
        ({"status": 500}, "service"),
        ({"type": "APIError", "status": 599}, "service"),
        ({"type": "ContextOverflowError", "status": 400}, "too_long"),
        ({"type": "context_length_exceeded"}, "too_long"),
        ({"type": "aborted"}, "stopped"),
        ({"type": "MessageAbortedError"}, "stopped"),
        ({"type": "ProviderAuthError", "status": 400}, "type"),
        ({"type": "has space"}, "unknown"),
        ({"type": "x" * 65}, "unknown"),
        ({"type": "Error\n", "status": 600}, "unknown"),
        ({"status": True}, "unknown"),
        ({}, "unknown"),
        (None, "unknown"),
        ("APIError", "unknown"),
    ],
)
def test_one_function_says_what_an_opencode_error_was_from_its_status_then_its_type(error, kind):
    from jt_oz_bridge.services.transcript_commands import failure_kind

    assert failure_kind(error) == kind


@pytest.mark.parametrize(
    ("locale", "error", "text"),
    [
        ("en", {"status": 401}, "model service authentication or permission failed"),
        ("zh-TW", {"status": 401}, "模型服務驗證或權限失敗"),
        ("en", {"status": 429}, "too many requests; the model service is rate limiting"),
        ("zh-TW", {"status": 429}, "請求太多，模型服務暫時限流"),
        ("en", {"status": 504}, "timed out"),
        ("zh-TW", {"type": "TimeoutError"}, "逾時"),
        ("en", {"status": 502}, "model service error"),
        ("zh-TW", {"status": 502}, "模型服務錯誤"),
        (
            "en",
            {"type": "ContextOverflowError"},
            "the conversation is longer than the model allows",
        ),
        ("zh-TW", {"type": "ContextOverflowError"}, "對話超過模型能處理的長度"),
        ("en", {"type": "aborted"}, "stopped"),
        ("zh-TW", {"type": "aborted"}, "已停止"),
        ("en", {"type": "ProviderError"}, "error type: `ProviderError`"),
        ("zh-TW", {"type": "ProviderError"}, "錯誤類型：`ProviderError`"),
        ("en", {"type": "<b>"}, "unknown error"),
        ("zh-TW", None, "未知錯誤"),
    ],
)
def test_a_failure_reason_reads_naturally_in_each_language(locale, error, text):
    from jt_oz_bridge.i18n import Translator
    from jt_oz_bridge.services.transcript_commands import failure_reason

    assert failure_reason(Translator(), locale, error) == text


def native(raw):
    if raw["type"] == "assistant":
        raw = {"agent": "build", "model": {"providerID": "fixture", "id": "test"}, **raw}
    return project_message(raw)


async def test_history_says_why_a_run_or_step_failed_and_what_a_compaction_did(db):
    _, _, _, _, _, commands = await setup(db)
    secret = {"type": "APIError", "status": 429, "message": "PRIVATE", "response": {"body": "P"}}
    outcome = native(
        {"id": "i1", "type": "idle", "time": {"created": 1}, "outcome": "failed", "error": secret}
    )
    assert commands.body(outcome, "en") == (
        "Run failed: too many requests; the model service is rate limiting."
    )
    assert commands.body(outcome, "zh-TW") == "執行失敗：請求太多，模型服務暫時限流。"
    # Without a reported error, as before.
    plain = native({"id": "i2", "type": "idle", "time": {"created": 1}, "outcome": "failed"})
    assert commands.body(plain, "en") == "Run failed."
    step = {
        "id": "s1",
        "type": "assistant",
        "time": {"created": 1, "completed": 2},
        "content": [{"type": "text", "text": "Half"}],
    }
    failed = commands.body(native(step | {"error": {"status": 500, "message": "PRIVATE"}}), "en")
    assert "Half\n\nThis step failed: model service error." in failed and "PRIVATE" not in failed
    # A step `!stop` ended is no failure; its outcome says it was interrupted.
    stopped = commands.body(native(step | {"error": {"type": "aborted", "message": "x"}}), "en")
    assert "failed" not in stopped
    compacted = {"id": "c1", "type": "compaction", "time": {"created": 1}, "summary": "PRIVATE"}
    compacted |= {"recent": "", "reason": "auto"}
    for status, text in [
        ("running", "🗜️ 對話太長，OpenCode 正在自動壓縮"),
        ("completed", "🗜️ 對話已壓縮"),
    ]:
        assert commands.body(native(compacted | {"status": status}), "zh-TW") == text
    lost = native(compacted | {"status": "failed", "error": {"type": "ContextOverflowError"}})
    assert commands.body(lost, "en") == (
        "🗜️ Compaction failed: the conversation is longer than the model allows"
    )
    manual = native(compacted | {"status": "running", "reason": "manual"})
    assert commands.body(manual, "en") == "🗜️ OpenCode is compacting the conversation"
