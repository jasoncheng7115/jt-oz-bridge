import re
from html import unescape
from pathlib import Path

import pytest
from sqlalchemy import delete, func, select, update

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.event_semantics import DATA, SEMANTICS_SHA256
from jt_oz_bridge.i18n import save_locale
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.services.native_history import NativeHistory
from jt_oz_bridge.services.native_projection import EventSemanticAttestation, NativeProjector
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from jt_oz_bridge.storage.projection_models import NativeProjectionRecord
from tests.contract.test_v2_execution import REF
from tests.integration.test_native_log_reader import reader, sse, synced
from tests.integration.test_native_projection import native, project_all
from tests.integration.test_router import Source, message, send


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


async def history(db, profile, texts=None, limit=1000):
    texts = ["Native reply one", "Native reply two"] if texts is None else texts
    events = [native("session.execution.started", 0)]
    for i, text in enumerate(texts, 1):
        events.append(
            native(
                "session.text.ended", i, assistantMessageID="msg_" + str(i), ordinal=0, text=text
            )
        )
    events.append(native("session.execution.succeeded", len(texts) + 1))
    events.append(synced(len(texts) + 1))
    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(value) for value in events]
    )
    projector = NativeProjector(
        pump.bindings,
        ConsumerFence(pump.holder, pump.fencing),
        attestation=EventSemanticAttestation(
            REF.backend_id,
            REF.backend_identity,
            profile.sha256,
            SEMANTICS_SHA256,
            "f" * 64,
            frozenset(DATA),
        ),
    )
    await pump.run(binding.id)
    await project_all(projector)
    stored = NativeHistory(projector)
    source = Source()
    tokens = TokenService(db, fence=projector.fence)
    commands = HistoryCommands(stored, tokens, source, message_limit=limit)
    router = CommandRouter(
        pump.bindings, source, CommandInbox(db, pump.holder, pump.fencing), history=commands
    )
    return router, binding, source, transport, stored, seen


def menu_token(text):
    text = unescape(text)
    return re.search(r"!oz history ([A-Za-z0-9_-]{32}) <", text)[1]


def next_token(text):
    text = unescape(text)
    return re.search(r"!oz history ([A-Za-z0-9_-]{32})(?! <)", text)[1]


async def test_history_routes_explicit_stored_parts_and_caches_same_tokens_without_prompt(
    db, profile
):
    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        native_calls = len(seen)
        menu = await send(router, source, message("!oz history"))
        assert (
            "newest first" in menu.text
            and "msg_" not in menu.text
            and "Native reply" not in menu.text
        )
        token = menu_token(menu.text)
        async with db.sessions() as session:
            tokens_before = await session.scalar(select(func.count()).select_from(ControlToken))
        replay = await router.route(source.messages[101])
        assert replay == menu
        async with db.sessions() as session:
            assert (
                await session.scalar(select(func.count()).select_from(ControlToken))
                == tokens_before
            )
        reply = await send(router, source, message("!oz history " + token + " 1", 102))
        assert "Native reply two" in reply.text and "Native reply one" not in reply.text
        assert await router.route(source.messages[102]) == reply
        again = await send(router, source, message("!oz history " + token + " 1", 103))
        assert "expired" in again.text or "expired" in again.text
        assert len(seen) == native_calls  # Stored history performs no native RPC/mutation.
        async with db.sessions() as session:
            assert await session.scalar(select(Action.id)) is None
    finally:
        await transport.close()


async def test_history_keyset_pages_ten_items_and_never_uses_native_cursor_or_bare_numbers(
    db, profile
):
    router, binding, source, transport, stored, seen = await history(
        db, profile, ["reply " + str(i) for i in range(13)]
    )
    try:
        page = await stored.page(binding.id, "realm", 7)
        assert len(page.items) == 10 and page.next_before is not None
        older = await stored.page(binding.id, "realm", 7, before=page.next_before)
        assert len(older.items) == 3 and older.next_before is None
        assert not {item.record_id for item in page.items} & {
            item.record_id for item in older.items
        }
        menu = await send(router, source, message("!oz history"))
        assert len(re.findall(r"\d+\. Reply text", unescape(menu.text))) == 10
        more = re.findall(r"!oz history ([A-Za-z0-9_-]{32})", unescape(menu.text))[-1]
        second = await send(router, source, message("!oz history " + more, 102))
        assert len(re.findall(r"\d+\. Reply text", unescape(second.text))) == 3
        picked = await send(
            router, source, message("!oz history " + menu_token(second.text) + " 3", 103)
        )
        assert "reply 0" in picked.text
        assert "reply 1" not in picked.text
    finally:
        await transport.close()


async def test_viewer_may_read_history_but_another_actor_cannot_use_their_token(db, profile):
    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        async with db.sessions.begin() as session:
            await session.execute(delete(Grant).where(Grant.user_id == 8))
            session.add(
                Grant(realm_id="realm", user_id=8, project_id=binding.project_id, role="viewer")
            )
        menu = await send(router, source, message("!oz history", author_id=8))
        stolen = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 102)
        )
        assert "Native reply two" not in stolen.text
        own = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 103, author_id=8)
        )
        assert "Native reply two" in own.text
        async with db.sessions() as session:
            assert await session.scalar(select(Action.id)) is None
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["grant", "binding", "record", "expiry"])
async def test_history_selection_revalidates_current_scope_and_exact_immutable_record(
    db, profile, change
):
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.control_models import Binding

    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        menu = await send(router, source, message("!oz history"))
        token = menu_token(menu.text)
        async with db.sessions.begin() as session:
            if change == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
            elif change == "binding":
                await session.execute(update(Binding).values(revision=2))
            elif change == "expiry":
                await session.execute(update(ControlToken).values(expires_at=0))
            else:
                await session.execute(
                    update(NativeProjectionRecord)
                    .where(NativeProjectionRecord.assistant_message_id == "msg_2")
                    .values(payload_hash="0" * 64)
                )
        try:
            reply = await send(router, source, message("!oz history " + token + " 1", 102))
        except (Conflict, AccessDenied):
            pass
        else:
            assert "Native reply two" not in reply.text
    finally:
        await transport.close()


async def test_balanced_native_text_pages_are_explicit_and_preview_credentials_are_redacted_after_ansi(
    db, profile
):
    original = (
        "```python\n"
        + "print('value')\n" * 150
        + "```\n\nAPI_TOKEN=\x1b[31mPRIVATE_VISIBLE_CREDENTIAL\x1b[0m\n"
    )
    router, binding, source, transport, stored, seen = await history(
        db, profile, [original], limit=700
    )
    try:
        menu = await send(router, source, message("!oz history"))
        reply = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 102)
        )
        pages = [reply.text]
        identity = 103
        while (
            match := re.search(r"!oz history ([A-Za-z0-9_-]{32})", unescape(pages[-1]))
        ) is not None:
            reply = await send(router, source, message("!oz history " + match[1], identity))
            pages.append(reply.text)
            identity += 1
            assert identity < 140
        assert len(pages) > 1 and all(len(page) <= 600 for page in pages)
        from markdown_it import MarkdownIt

        fences = [
            token for page in pages for token in MarkdownIt().parse(page) if token.type == "fence"
        ]
        assert sum(token.content.count("print('value')") for token in fences) == 150
        assert all(
            "!oz history" not in token.content and "Saved reply" not in token.content
            for token in fences
        )
        assert "PRIVATE_VISIBLE_CREDENTIAL" not in "".join(pages)
        assert "[REDACTED]" in "".join(MarkdownIt().render(page) for page in pages)
        selected = (await stored.page(binding.id, "realm", 7)).items[0]
        assert selected.text == original  # Display redaction never rewrites preserved original.
    finally:
        await transport.close()


async def test_cached_status_is_explicitly_historical_when_backend_cannot_be_verified(db, profile):
    router, binding, source, transport, stored, seen = await history(db, profile)
    original = router.bindings.control.snapshot

    async def offline(reference):
        raise TimeoutError("PRIVATE_CONNECTION_DETAILS")

    router.bindings.control.snapshot = offline
    try:
        response = await send(router, source, message("!oz status"))
        assert "Last saved status" in response.text and "may be out of date" in response.text
        assert "PRIVATE_CONNECTION_DETAILS" not in response.text
        router.bindings.control.snapshot = original
        live = await send(router, source, message("!oz status", 102))
        assert "Last saved" not in live.text
    finally:
        await transport.close()


async def test_source_changed_during_history_lookup_never_discloses_stored_text(db, profile):
    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        menu = await send(router, source, message("!oz history"))
        original = stored.part
        selecting = message("!oz history " + menu_token(menu.text) + " 1", 102)

        async def changed(*args, **kwargs):
            part = await original(*args, **kwargs)
            source.messages[102] = selecting.model_copy(update={"deleted": True})
            return part

        stored.part = changed
        response = await send(router, source, selecting)
        assert "Native reply two" not in response.text
    finally:
        await transport.close()


async def test_historical_body_and_catalog_follow_current_personal_locale(db, profile):
    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        await save_locale(db, "user:realm:7", "zh-TW", fence=router.inbox.fence)
        menu = await send(router, source, message("!oz history"))
        assert "已儲存" in menu.text and "只有最後文字" in menu.text
        response = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 102)
        )
        assert "已儲存回覆" in response.text and "Native reply two" in response.text
    finally:
        await transport.close()


async def test_text_page_rendering_stays_stable_across_personal_language_change(db, profile):
    from jt_oz_bridge.presentation.markdown import MobileMarkdown

    original = "\n\n".join("![](https://example.invalid/image-" + str(i) + ")" for i in range(30))
    router, binding, source, transport, stored, seen = await history(
        db, profile, [original], limit=700
    )
    try:
        expected = MobileMarkdown(locale="en").render(original, 700, reserved_characters=320).pages
        assert len(expected) > 1
        menu = await send(router, source, message("!oz history"))
        first = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 102)
        )
        assert expected[0] in first.text
        token = re.search(r"!oz history ([A-Za-z0-9_-]{32})", unescape(first.text))[1]
        await save_locale(db, "user:realm:7", "zh-TW", fence=router.inbox.fence)
        second = await send(router, source, message("!oz history " + token, 103))
        assert "已儲存回覆" in second.text and expected[1] in second.text
    finally:
        await transport.close()


async def test_unpreviewable_incomplete_private_key_fails_closed_without_losing_original(
    db, profile
):
    original = "-----BEGIN PRIVATE KEY-----\nPRIVATE_UNFINISHED_VALUE"
    router, binding, source, transport, stored, seen = await history(db, profile, [original])
    try:
        menu = await send(router, source, message("!oz history"))
        reply = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 102)
        )
        assert "previewed here" in reply.text and "PRIVATE_UNFINISHED_VALUE" not in reply.text
        assert (await stored.page(binding.id, "realm", 7)).items[0].text == original
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["contract", "fence", "source", "renderer"])
async def test_history_next_text_page_needs_same_contract_fence_source_and_renderer(
    db, profile, change
):
    from jt_oz_bridge.storage.control_models import EnrolledBackend
    from jt_oz_bridge.storage.models import WorkerLease

    router, binding, source, transport, stored, seen = await history(
        db, profile, ["```python\n" + "print(0)\n" * 100 + "```"], limit=700
    )
    try:
        menu = await send(router, source, message("!oz history"))
        first = await send(
            router, source, message("!oz history " + menu_token(menu.text) + " 1", 102)
        )
        token = re.search(r"!oz history ([A-Za-z0-9_-]{32})", unescape(first.text))[1]
        next_source = message("!oz history " + token, 103)
        if change == "renderer":
            router.history.message_limit = 800
        elif change == "source":
            source.messages[103] = next_source.model_copy(update={"deleted": True})
            assert (await router.route(next_source)).state == "ignore"
            return
        else:
            async with db.sessions.begin() as session:
                if change == "contract":
                    await session.execute(update(EnrolledBackend).values(contract_hash="0" * 64))
                else:
                    await session.execute(update(WorkerLease).values(fencing=2))
        try:
            response = await send(router, source, next_source)
        except (Conflict, ValueError):
            pass
        else:
            assert "print(0)" not in response.text
    finally:
        await transport.close()


async def test_invalid_read_cursor_and_foreign_part_never_disclose_data(db, profile):
    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        for before in (True, -1, 0, 2**63):
            with pytest.raises(ValueError):
                await stored.page(binding.id, "realm", 7, before=before)
        selected = (await stored.page(binding.id, "realm", 7)).items[0]
        with pytest.raises(Conflict):
            await stored.part(binding.id, "realm", 7, selected.record_id, "0" * 64)
        with pytest.raises(Conflict):
            await stored.part(binding.id, "realm", 7, "nonexistent", selected.record_hash)
    finally:
        await transport.close()


async def test_fresh_history_after_whole_topic_move_can_read_same_original_but_old_tokens_fail(
    db, profile
):
    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        old = await send(router, source, message("!oz history"))
        await router.bindings.move(binding.id, "realm", 7, 1, 11, "Moved", whole_topic=True)
        stale = await send(
            router,
            source,
            message(
                "!oz history " + menu_token(old.text) + " 1", 102, channel_id=11, topic="Moved"
            ),
        )
        assert "Native reply two" not in stale.text
        fresh = await send(
            router, source, message("!oz history", 103, channel_id=11, topic="Moved")
        )
        result = await send(
            router,
            source,
            message(
                "!oz history " + menu_token(fresh.text) + " 1", 104, channel_id=11, topic="Moved"
            ),
        )
        assert "Native reply two" in result.text and result.binding_revision == 2
        assert (
            await stored.latest_state(binding.id, "realm", 7)
        ).provenance.binding_revision == 1  # Preserve truthful historical scope.
    finally:
        await transport.close()


async def test_history_does_not_follow_a_binding_to_a_different_original_session(db, profile):
    from jt_oz_bridge.storage.control_models import Binding

    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        old_part = (await stored.page(binding.id, "realm", 7)).items[0]
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(session_id="ses_different", revision=2))
        assert not (await stored.page(binding.id, "realm", 7)).items
        assert await stored.latest_state(binding.id, "realm", 7) is None
        with pytest.raises(Conflict):
            await stored.part(binding.id, "realm", 7, old_part.record_id, old_part.record_hash)
    finally:
        await transport.close()


async def test_missing_saved_status_still_reports_current_bridge_queue_pause_flag(db, profile):
    from jt_oz_bridge.storage.control_models import Binding
    from jt_oz_bridge.storage.projection_models import NativeProjection

    router, binding, source, transport, stored, seen = await history(db, profile)
    try:
        async with db.sessions.begin() as session:
            await session.execute(delete(NativeProjectionRecord))
            await session.execute(delete(NativeProjection))
            await session.execute(update(Binding).values(dispatch_paused=True))

        async def offline(reference):
            raise TimeoutError("fixture")

        router.bindings.control.snapshot = offline
        result = await send(router, source, message("!oz status"))
        assert (
            "No saved status" in result.text
            and "Queue paused" in result.text
            and "Yes" in result.text
        )
    finally:
        await transport.close()
