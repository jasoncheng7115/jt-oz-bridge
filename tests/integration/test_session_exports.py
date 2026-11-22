"""Synthetic HTTP/ownDB export flow; never a live Human/mobile qualification."""

import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from html import unescape
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.session_export_plans import TranscriptExportPlan
from jt_oz_bridge.services.session_exports import (
    SessionExportCommands,
    SessionExportJournal,
    capture_conversation,
    encode_conversation,
)
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding, ControlToken, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, Delivery, Grant, WorkerLease
from tests.integration.test_file_returns import all_rows, multipart_file
from tests.integration.test_file_returns import setup as file_setup
from tests.integration.test_router import message, send
from tests.integration.test_transcript_commands import OriginalReader
from tests.support import REF


@asynccontextmanager
async def setup(db, tmp_path, *, count=17, generated=False):
    async with file_setup(db, tmp_path, initial_artifact=False) as v:
        from jt_oz_bridge.services.session_exports import GeneratedSessionExportJournal

        journal_type = GeneratedSessionExportJournal if generated else SessionExportJournal
        journal = journal_type(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {REF: v.witness},
            message_limit=1000,
            topic_limit=60,
            **({"generated_readers": {}} if generated else {}),
        )
        reader = OriginalReader()
        reader.messages = [
            project_message(
                {
                    "id": "msg_export_" + str(i),
                    "type": "user",
                    "time": {"created": 200 - i},
                    "text": "Original conversation " + str(i),
                }
            )
            for i in range(count)
        ]
        # This issuer is explicitly synthetic; expiry/object identity still apply.
        original_capture = reader.capture

        async def exact_synthetic_capture(*args, **kwargs):
            issued = await original_capture(*args, **kwargs)
            # The reused history double takes two time.time() samples; its
            # expiry can exceed observed_at+5 by a microsecond. This export
            # fixture tightens that synthetic proof to exactly five seconds.
            page = issued.model_copy(update={"expires_at": issued.observed_at + 5})
            reader.pages[-1] = page
            return page

        reader.capture = exact_synthetic_capture
        original_current = reader.current
        reader.current = lambda page: (
            original_current(page)
            and page.observed_at <= time.time() < page.expires_at
            and page.owner_epoch == reader.owner_epoch
            and page.connection_epoch == reader.connection_epoch
            and page.contract_sha256 == reader.contract_hash
        )
        journal.configure_exports({REF: reader})
        commands = SessionExportCommands(journal, TokenService(db, fence=v.store.fence))
        inbox = CommandInbox(db, v.store.fence.holder, v.store.fence.fencing)
        files = FileCommands(journal, {REF: v.witness})
        router = CommandRouter(v.store.bindings, v.source, inbox, files=files, exports=commands)
        remote = SimpleNamespace(
            posts=0,
            mode="success",
            entered=asyncio.Event(),
            content=None,
            mime=None,
            message_posts=0,
        )

        async def api(request):
            if request.method == "POST" and request.url.path == "/api/v1/messages":
                remote.message_posts += 1
                return httpx.Response(200, json={"result": "success", "id": 900})
            if request.method == "POST":
                remote.posts += 1
                assert request.url.path == "/api/v1/user_uploads"
                part, content = multipart_file(request)
                assert bytes(content) == remote.content and part.get_content_type() == remote.mime
                remote.entered.set()
                if remote.mode == "timeout":
                    raise httpx.ReadTimeout("synthetic accepted, unknown response")
                if remote.mode == "cancel":
                    await asyncio.Event().wait()
                filename = (
                    "conversation.json" if remote.mime == "application/json" else "conversation.md"
                )
                return httpx.Response(
                    200,
                    json={
                        "result": "success",
                        "url": "/user_uploads/2/ab/opaque/" + filename,
                        "uri": "/user_uploads/2/ab/opaque/" + filename,
                        "filename": filename,
                    },
                )
            assert request.method == "GET"
            return httpx.Response(
                200,
                json={"result": "success", "url": "/user_uploads/temporary/PRIVATE-SIGNED/file"},
            )

        v.client.client._transport = httpx.MockTransport(api)
        v.service, v.export_reader, v.commands, v.inbox, v.router, v.export_remote = (
            journal,
            reader,
            commands,
            inbox,
            router,
            remote,
        )
        yield v


def preview_token(reply):
    return re.search(r"!oz export confirm ([A-Za-z0-9_-]{32})", unescape(reply.text))[1]


async def preview(v, encoding="json"):
    reply = await send(v.router, v.source, message("!oz export " + encoding))
    assert "conversation export" in reply.text.lower() and "SHA-256" in reply.text
    assert await all_rows(v.store.db, FileTransfer) == []
    return reply, preview_token(reply)


async def confirm(v, token):
    return await send(v.router, v.source, message("!oz export confirm " + token, 102))


async def prepare(v, encoding="json"):
    reply, token = await preview(v, encoding)
    response = await confirm(v, token)
    row = (await all_rows(v.store.db, FileTransfer))[0]
    assert row.id not in response.text and "File status" in response.text
    plan = (await v.service.load(row.id))[1]
    content = await v.store.read(plan.artifact_id, "realm", 7)
    v.export_remote.content, v.export_remote.mime = content.content, content.descriptor.mime_type
    v.remote.body, v.remote.mime = content.content, content.descriptor.mime_type
    return row, plan, reply, response


@pytest.mark.parametrize("encoding", ["json", "markdown"])
async def test_safe_export_requires_preview_confirm_then_shared_one_attempt_upload_readback_and_topic(
    db, tmp_path, encoding
):
    async with setup(db, tmp_path, count=27) as v:
        row, plan, reply, response = await prepare(v, encoding)
        assert isinstance(plan, TranscriptExportPlan) and plan.preview.entry_count == 27
        assert len([c for c in v.export_reader.calls if c[2] == 20]) == 2
        assert any(c[2] == 1 for c in v.export_reader.calls)
        assert all(c[0] == REF for c in v.export_reader.calls)
        assert v.export_remote.posts == 0
        assert await v.router.route(v.source.messages[101]) == reply
        assert await v.router.route(v.source.messages[102]) == response
        assert len(await all_rows(db, Artifact)) == 1 and len(await all_rows(db, FileTransfer)) == 1
        for expected in ("uploaded", "verified", "queued"):
            assert await v.service.advance(row.id) == expected
        assert v.export_remote.posts == 1
        assert await v.service.advance(row.id) == "queued" and v.export_remote.posts == 1
        delivery = (await all_rows(db, Delivery))[0]
        assert (
            delivery.payload["channel_id"] == plan.source.channel_id
            and delivery.payload["topic"] == plan.source.topic
        )
        witness = await v.service.delivery_witness(delivery)
        assert witness is not None and witness()
        async with db.sessions.begin() as session:
            await v.service.lock_delivery(session, delivery)
        content = v.export_remote.content
        assert (
            b"safe-conversation-export-v1" in content and b"complete_raw_native_export" in content
        )
        assert b"Original conversation 26" in content and b"older_omitted" in content
        assert await all_rows(db, Action) == []


async def test_bounded_capture_marks_older_omission_in_both_preview_and_download(db, tmp_path):
    async with setup(db, tmp_path, count=201) as v:
        row, plan, reply, _ = await prepare(v)
        assert plan.preview.older_omitted and plan.preview.entry_count == 200
        assert "Older entries are not included" in reply.text
        value = json.loads(v.export_remote.content)
        assert value["coverage"]["older_omitted"] and len(value["entries"]) == 200
        assert b"Original conversation 200" not in v.export_remote.content


@pytest.mark.parametrize(
    "fault",
    [
        "actor",
        "topic",
        "revision",
        "grant",
        "audience",
        "binding",
        "expiry",
        "token-context",
        "artifact",
    ],
)
async def test_confirmation_cannot_cross_or_reuse_preview_scope(db, tmp_path, fault):
    async with setup(db, tmp_path) as v:
        _, token = await preview(v)
        source = message("!oz export confirm " + token, 102)
        if fault == "actor":
            source = source.model_copy(update={"author_id": 8})
        if fault == "topic":
            source = source.model_copy(update={"topic": "foreign"})
        if fault == "revision":
            source = source.model_copy(update={"revision": 1})
        if fault == "audience":
            v.audience.users = frozenset({7, 8, 999})
        async with db.sessions.begin() as session:
            if fault == "grant":
                await session.execute(update(Grant).values(active=False))
            if fault == "binding":
                await session.execute(update(Binding).values(revision=2))
            if fault == "expiry":
                await session.execute(update(ControlToken).values(expires_at=0))
            if fault == "token-context":
                saved = (await session.scalars(select(ControlToken))).one()
                saved.context = {
                    **saved.context,
                    "projection": {
                        **saved.context["projection"],
                        "sha256": "0" * 64,
                    },
                }
                saved.context_hash = digest(saved.context)
                # A self-consistent token hash cannot change the captured artifact bytes.
            if fault == "artifact":
                await session.execute(update(Artifact).values(checksum="0" * 64))
        try:
            await send(v.router, v.source, source)
        except (Conflict, AccessDenied):
            pass
        assert await all_rows(db, FileTransfer) == [] and v.export_remote.posts == 0


@pytest.mark.parametrize(
    "fault",
    [
        "preview-edit",
        "confirm-edit",
        "grant",
        "audience",
        "enrollment",
        "fence",
        "contract",
        "plan-hash",
    ],
)
async def test_each_upload_attempt_rechecks_source_and_sql_and_never_uses_preview_as_authority(
    db, tmp_path, fault
):
    async with setup(db, tmp_path) as v:
        row, plan, _, _ = await prepare(v)
        if fault == "preview-edit":
            v.source.messages[101] = v.source.messages[101].model_copy(
                update={"text": "changed", "revision": 1}
            )
        if fault == "confirm-edit":
            v.source.messages[102] = v.source.messages[102].model_copy(
                update={"text": "changed", "revision": 1}
            )
        if fault == "audience":
            v.audience.private = False
        if fault == "contract":
            v.export_reader.contract_hash = "b" * 64
        async with db.sessions.begin() as session:
            if fault == "grant":
                await session.execute(update(Grant).values(active=False))
            if fault == "enrollment":
                await session.execute(update(EnrolledProject).values(enabled=False))
            if fault == "fence":
                await session.execute(update(WorkerLease).values(fencing=999))
            if fault == "plan-hash":
                await session.execute(update(FileTransfer).values(payload_hash="0" * 64))
        try:
            assert await v.service.advance(row.id) == "held"
        except (Conflict, AccessDenied):
            pass
        assert v.export_remote.posts == 0


@pytest.mark.parametrize("mode", ["timeout", "cancel"])
async def test_unknown_or_cancelled_upload_is_ambiguous_and_never_posts_again(db, tmp_path, mode):
    async with setup(db, tmp_path) as v:
        row, _, _, _ = await prepare(v)
        v.export_remote.mode = mode
        task = asyncio.create_task(v.service.advance(row.id))
        await asyncio.wait_for(v.export_remote.entered.wait(), 1)
        if mode == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert await task == "ambiguous"
        assert await v.service.advance(row.id) == "ambiguous"
        assert v.export_remote.posts == 1


async def test_processing_receipt_is_not_upload_authority_and_confirmation_consumes_token_once(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        _, token = await preview(v)
        human = message("!oz export confirm " + token, 102)
        v.source.messages[102] = human
        claim = await v.inbox.claim(
            human, "export", binding_id=v.binding.id, binding_revision=v.binding.revision
        )
        text = await v.commands.route(v.binding, human, "en", "confirm " + token, claim)
        row = (await all_rows(db, FileTransfer))[0]
        assert await v.service.advance(row.id) == "prepared" and v.export_remote.posts == 0
        with pytest.raises(Conflict):
            await v.commands.confirm(v.binding, human, "en", claim, token)
        await v.inbox.finish(claim, {"text": text, "locale": "en"})
        another = await send(v.router, v.source, message("!oz export confirm " + token, 103))
        assert "expired" in another.text and len(await all_rows(db, FileTransfer)) == 1


@pytest.mark.parametrize("fault", ["page-owner", "duplicate", "expired", "source", "secret"])
async def test_capture_changes_or_recognizable_secrets_never_issue_a_transfer_or_token(
    db, tmp_path, fault
):
    async with setup(db, tmp_path, count=25) as v:
        original = v.export_reader.capture

        async def capture(*args, **kwargs):
            if fault == "page-owner" and v.export_reader.calls:
                v.export_reader.owner_epoch = "changed"
            page = await original(*args, **kwargs)
            if fault == "duplicate" and page.cursor is not None:
                page = page.model_copy(update={"entries": (v.export_reader.messages[0],)})
                v.export_reader.pages.append(page)
            if fault == "expired":
                page = page.model_copy(update={"expires_at": time.time() - 1})
            if fault == "source":
                v.source.messages[101] = v.source.messages[101].model_copy(update={"revision": 1})
            return page

        v.export_reader.capture = capture
        if fault == "secret":
            v.export_reader.messages[0] = project_message(
                {
                    "id": "msg_secret",
                    "type": "user",
                    "time": {"created": 1},
                    "text": "api_key=abcdefghijklmnopqrstuvwx",
                }
            )
        await send(v.router, v.source, message("!oz export"))
        assert await all_rows(db, FileTransfer) == [] and await all_rows(db, ControlToken) == []
        assert v.export_remote.posts == 0


async def test_real_native_http_reader_preserves_projection_boundary_without_fabricated_endpoint():
    from tests.contract.test_leaf_resources import REF as NATIVE_REF
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_native_transcript import prepared

    p, t, d, m, reader, reads = await prepared()
    try:
        pages = await capture_conversation(reader, NATIVE_REF)
        value = json.loads(encode_conversation(pages, "json"))
        assert len(pages) == 2 and len(reads) == 4 and len(value["entries"]) == 28
        assert value["reference"] == NATIVE_REF.model_dump(mode="json")
        assert not value["coverage"]["older_omitted"]
        serialized = json.dumps(value)
        assert "NEVER_RETAIN" not in serialized and "Exact final answer" in serialized
        assert all(
            request.method == "GET" and request.url.path.endswith("/message") for request in reads
        )
        assert encode_conversation(pages, "markdown").startswith(b"# Safe conversation export")
    finally:
        await finish(p, t)


@pytest.mark.parametrize("field", ["metadata", "reasoning", "tool-result"])
async def test_custom_reader_cannot_widen_the_existing_safe_history_projection(db, tmp_path, field):
    from jt_oz_bridge.adapters.opencode.transcript import TranscriptEntry

    async with setup(db, tmp_path) as v:
        value = v.export_reader.messages[0].projection()
        value[field] = "must not leave bridge"
        v.export_reader.messages[0] = TranscriptEntry(
            native_id=value["id"],
            kind="user",
            projection_json=json.dumps(value),
            projection_sha256=digest(value),
        )
        await send(v.router, v.source, message("!oz export"))
        assert not await all_rows(db, ControlToken) and not await all_rows(db, FileTransfer)
        assert not await all_rows(db, Artifact) and v.export_remote.posts == 0


async def test_token_consumption_and_export_transfer_roll_back_together(db, tmp_path):
    from sqlalchemy import event

    async with setup(db, tmp_path) as v:
        _, token = await preview(v)
        source = message("!oz export confirm " + token, 102)
        v.source.messages[102] = source
        claim = await v.inbox.claim(
            source, "export", binding_id=v.binding.id, binding_revision=v.binding.revision
        )

        def fail(*args):
            raise RuntimeError("synthetic commit failure")

        event.listen(FileTransfer, "before_insert", fail)
        try:
            with pytest.raises(RuntimeError, match="synthetic commit failure"):
                await v.commands.confirm(v.binding, source, "en", claim, token)
        finally:
            event.remove(FileTransfer, "before_insert", fail)
        assert not (await all_rows(db, ControlToken))[0].used
        assert not await all_rows(db, FileTransfer) and v.export_remote.posts == 0


async def test_after_prepare_cancel_keeps_original_sources_but_never_uploads_ambiguous_command(
    db, tmp_path
):
    from unittest.mock import AsyncMock

    async with setup(db, tmp_path) as v:
        _, token = await preview(v)
        v.inbox.finish = AsyncMock(side_effect=asyncio.CancelledError)
        source = message("!oz export confirm " + token, 102)
        with pytest.raises(asyncio.CancelledError):
            await send(v.router, v.source, source)
        row = (await all_rows(db, FileTransfer))[0]
        plan = (await v.service.load(row.id))[1]
        assert plan.source == source and plan.preview.preview_source == v.source.messages[101]
        assert await v.service.advance(row.id) == "held"
        replay = await v.router.route(source)
        assert replay.state == "ambiguous" and len(await all_rows(db, FileTransfer)) == 1
        assert v.export_remote.posts == 0


async def test_late_revocation_during_artifact_read_prevents_confirm_transaction(db, tmp_path):
    async with setup(db, tmp_path) as v:
        _, token = await preview(v)
        original = v.store.read

        async def read(*args, **kwargs):
            result = await original(*args, **kwargs)
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            return result

        v.store.read = read
        try:
            await confirm(v, token)
        except (AccessDenied, Conflict):
            pass
        assert not await all_rows(db, FileTransfer)
        assert not (await all_rows(db, ControlToken))[0].used and v.export_remote.posts == 0


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_explicit_preview_is_renderable_at_minimum_message_limit_without_changing_download(
    db, tmp_path, locale
):
    from jt_oz_bridge.presentation.markdown import MobileMarkdown
    from jt_oz_bridge.services.file_returns import FOOTER_SIZE

    async with setup(db, tmp_path) as v:
        source = message("!oz export markdown")
        v.source.messages[101] = source
        claim = await v.inbox.claim(
            source, "export", binding_id=v.binding.id, binding_revision=v.binding.revision
        )
        text = await v.commands.route(v.binding, source, locale, "markdown", claim)
        pages = (
            MobileMarkdown(locale=locale).render(text, 512, reserved_characters=FOOTER_SIZE).pages
        )
        assert pages and all(len(page) + FOOTER_SIZE <= 512 for page in pages)
        token = re.search(r"!oz export confirm ([A-Za-z0-9_-]{32})", text)[1]
        assert token in unescape("\n".join(pages))


def change_upstream_scope(v, fault):
    if fault == "owner":
        v.export_reader.owner_epoch = "changed-owner"
    elif fault == "connection":
        v.export_reader.connection_epoch = "changed-connection"
    elif fault == "scope":
        v.export_reader.foreign = True
    else:
        original = v.export_reader.capture

        async def changed(*args, **kwargs):
            issued = await original(*args, **kwargs)
            page = issued.model_copy(
                update={
                    "semantics_sha256" if fault == "semantics" else "installed_evidence_sha256": "9"
                    * 64,
                }
            )
            v.export_reader.pages[-1] = page
            return page

        v.export_reader.capture = changed


@pytest.mark.parametrize("fault", ["owner", "connection", "scope", "semantics", "qualification"])
@pytest.mark.parametrize("stage", ["confirm", "upload", "publish", "delivery"])
async def test_historical_artifact_never_authorizes_changed_current_native_scope(
    db, tmp_path, fault, stage
):
    from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway
    from jt_oz_bridge.services.delivery import DeliveryWorker

    async with setup(db, tmp_path) as v:
        if stage == "confirm":
            _, token = await preview(v)
            change_upstream_scope(v, fault)
            result = await confirm(v, token)
            assert "expired" in result.text and not await all_rows(db, FileTransfer)
            assert not (await all_rows(db, ControlToken))[0].used
        else:
            row, _, _, _ = await prepare(v)
            if stage in {"publish", "delivery"}:
                assert await v.service.advance(row.id) == "uploaded"
                assert await v.service.advance(row.id) == "verified"
            if stage == "delivery":
                assert await v.service.advance(row.id) == "queued"
            change_upstream_scope(v, fault)
            if stage == "delivery":
                delivery = (await all_rows(db, Delivery))[0]
                worker = DeliveryWorker(
                    v.outbox,
                    ZulipGateway(v.client),
                    v.store.fence.holder,
                    v.store.fence.fencing,
                    minimum_interval=0,
                    file_returns=v.service,
                )
                assert await worker.advance(delivery.id) == "held"
            else:
                assert await v.service.advance(row.id) == "held"
            assert v.export_remote.posts == (0 if stage == "upload" else 1)
        assert v.export_remote.message_posts == 0


@pytest.mark.parametrize("boundary", ["postclaim", "last-upload-http", "last-message-http"])
async def test_final_native_witness_rejects_changes_after_sql_claim_before_http(
    db, tmp_path, boundary
):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway
    from jt_oz_bridge.services.delivery import DeliveryWorker

    async with setup(db, tmp_path) as v:
        row, _, _, _ = await prepare(v)
        if boundary == "last-message-http":
            for state in ("uploaded", "verified", "queued"):
                assert await v.service.advance(row.id) == state
            delivery = (await all_rows(db, Delivery))[0]
            worker = DeliveryWorker(
                v.outbox,
                ZulipGateway(v.client),
                v.store.fence.holder,
                v.store.fence.fencing,
                minimum_interval=0,
                file_returns=v.service,
            )
        entered = []
        if boundary == "postclaim":
            original = v.service.claim

            async def claim(*args, **kwargs):
                result = await original(*args, **kwargs)
                v.export_reader.connection_epoch = "late-after-claim"
                entered.append(True)
                return result

            v.service.claim = claim
        else:

            async def identity():
                async with db.sessions() as session:
                    if boundary == "last-message-http":
                        assert (await session.get(Delivery, delivery.id)).state == "sending"
                    else:
                        assert (await session.get(FileTransfer, row.id)).state == "uploading"
                entered.append(True)
                v.export_reader.owner_epoch = "late-after-bot-check"
                return True

            v.client.verify_identity = AsyncMock(side_effect=identity)
        if boundary == "last-message-http":
            assert await worker.advance(delivery.id) == "held"
            assert v.export_remote.posts == 1
        else:
            assert await v.service.advance(row.id) == "held"
            assert v.export_remote.posts == 0
        assert entered == [True] and v.export_remote.message_posts == 0


async def test_short_remaining_native_proof_expires_during_last_bot_await_without_widening_five_seconds(
    db, tmp_path
):
    from unittest.mock import AsyncMock

    async with setup(db, tmp_path) as v:
        row, _, _, _ = await prepare(v)
        original = v.export_reader.capture

        async def capture(*args, **kwargs):
            page = await original(*args, **kwargs)
            if kwargs.get("limit") == 1:
                # Tighten this synthetic issued proof, never extend the five-second cap.
                page = page.model_copy(update={"expires_at": page.observed_at + 0.5})
                v.export_reader.pages[-1] = page
            return page

        v.export_reader.capture = capture
        entered = []

        async def identity():
            async with db.sessions() as session:
                assert (await session.get(FileTransfer, row.id)).state == "uploading"
            entered.append(True)
            await asyncio.sleep(0.55)
            return True

        v.client.verify_identity = AsyncMock(side_effect=identity)
        assert await v.service.advance(row.id) == "held"
        assert entered == [True] and v.export_remote.posts == 0


async def test_fresh_scope_page_never_replaces_frozen_export_bytes(db, tmp_path):
    async with setup(db, tmp_path) as v:
        row, plan, _, _ = await prepare(v)
        original = v.export_remote.content
        v.export_reader.messages[0] = project_message(
            {
                "id": "msg_new_after_preview",
                "type": "user",
                "text": "new content must not enter the old download",
                "time": {"created": 300},
            }
        )
        assert await v.service.advance(row.id) == "uploaded"
        assert v.export_remote.content == original
        saved = await v.store.read(plan.artifact_id, "realm", 7)
        assert saved.content == original and b"new content must not enter" not in saved.content
        assert any(c[2] == 1 for c in v.export_reader.calls)


async def test_current_native_scope_witness_is_task_and_exact_transfer_owned(db, tmp_path):
    from uuid import uuid4

    async with setup(db, tmp_path) as v:
        _, plan, _, _ = await prepare(v)
        await v.service.current(plan)
        current = v.service.export_scope_witness(plan)
        assert current()

        async def child():
            assert not current()
            with pytest.raises(Conflict):
                v.service.export_scope_witness(plan)

        await asyncio.create_task(child())
        with pytest.raises(Conflict):
            v.service.export_scope_witness(plan.model_copy(update={"id": str(uuid4())}))


async def test_scope_loss_at_confirmation_transaction_tail_rolls_back_token_and_transfer(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        _, token = await preview(v)
        source = message("!oz export confirm " + token, 102)
        v.source.messages[102] = source
        claim = await v.inbox.claim(
            source, "export", binding_id=v.binding.id, binding_revision=v.binding.revision
        )
        original = v.commands.tokens.consume_in_session

        async def consume(*args, **kwargs):
            await original(*args, **kwargs)
            v.export_reader.connection_epoch = "changed-during-sql"

        v.commands.tokens.consume_in_session = consume
        with pytest.raises(Conflict, match="scope_expired_before_confirmation_commit"):
            await v.commands.confirm(v.binding, source, "en", claim, token)
        assert not (await all_rows(db, ControlToken))[0].used
        assert not await all_rows(db, FileTransfer) and v.export_remote.posts == 0


@pytest.mark.parametrize("encoding", ["json", "markdown"])
async def test_generated_enabled_composite_retains_the_export_origin_guards(db, tmp_path, encoding):
    from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal

    async with setup(db, tmp_path, generated=True) as v:
        assert isinstance(v.service, SessionExportJournal) and isinstance(
            v.service, GeneratedFileReturnJournal
        )
        row, plan, _, _ = await prepare(v, encoding)
        assert isinstance(plan, TranscriptExportPlan)
        for expected in ("uploaded", "verified", "queued"):
            assert await v.service.advance(row.id) == expected
        assert v.export_remote.posts == 1
        assert await v.service.advance(row.id) == "queued" and v.export_remote.posts == 1
        assert v.service.export_scope_witness(plan)()


@pytest.mark.parametrize("kind", ["inline", "workspace"])
async def test_generated_enabled_composite_retains_the_generated_origin_guards(db, tmp_path, kind):
    from jt_oz_bridge.services.session_exports import GeneratedSessionExportJournal
    from tests.integration.test_generated_file_returns import setup as generated_setup

    async with generated_setup(db, tmp_path, kind=kind) as v:
        journal = GeneratedSessionExportJournal(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {},
            generated_readers={REF: v.reader},
            message_limit=10000,
            topic_limit=60,
        )
        journal.configure_exports({})
        identity = await journal.capture_generated(v.action_id, 0)
        for expected in ("uploaded", "verified", "queued"):
            assert await journal.advance(identity) == expected
        assert v.remote.posts == 1
        assert await journal.advance(identity) == "queued" and v.remote.posts == 1


@pytest.mark.parametrize("state", ["prepared", "uploaded", "verified", "queued"])
async def test_generated_disabled_export_journal_holds_persisted_generated_origin_without_io(
    db, tmp_path, state
):
    from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
    from jt_oz_bridge.services.generated_output_plans import GeneratedFileReturnPlan
    from tests.integration.test_generated_file_returns import setup as generated_setup

    async with generated_setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        for expected in ("uploaded", "verified", "queued")[
            : ["prepared", "uploaded", "verified", "queued"].index(state)
        ]:
            assert await v.service.advance(identity) == expected
        disabled = SessionExportJournal(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {},
            message_limit=10000,
            topic_limit=60,
        )
        disabled.configure_exports({})
        assert not isinstance(disabled, GeneratedFileReturnJournal)
        row, plan = await disabled.load(identity)
        assert row.state == state and isinstance(plan, GeneratedFileReturnPlan)
        before = (v.remote.posts, v.reader.calls, v.reader.reads)
        with pytest.raises(Conflict, match="^generated_return_authorizer_not_enrolled$"):
            await disabled.authorize_source(plan)
        async with db.sessions.begin() as session:
            with pytest.raises(Conflict, match="^generated_return_authorizer_not_enrolled$"):
                await disabled.lock_plan(session, plan)
        if state == "queued":
            delivery = (await all_rows(db, Delivery))[0]
            with pytest.raises(Conflict, match="^generated_return_authorizer_not_enrolled$"):
                await disabled.delivery_witness(delivery)
            async with db.sessions.begin() as session:
                with pytest.raises(Conflict, match="^generated_return_authorizer_not_enrolled$"):
                    await disabled.lock_delivery(session, delivery)
            assert await disabled.advance(identity) == "queued"  # No replay or new upload.
        else:
            assert await disabled.advance(identity) == "held"
        assert (v.remote.posts, v.reader.calls, v.reader.reads) == before
        assert (await disabled.load(identity))[1] == plan
