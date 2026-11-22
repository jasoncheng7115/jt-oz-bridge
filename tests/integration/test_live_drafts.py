"""Synthetic original headers + actual wire-shape capture and encrypted SQL/edit chain."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.live import VolatileFeedIndex
from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.live_capture import LiveEventJournal, LiveTextCollector
from jt_oz_bridge.services.live_draft_sources import LiveDraftCollector
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_drafts import TranscriptDraftPublisher
from jt_oz_bridge.services.transcript_publisher import TranscriptPublisher
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.live_models import TranscriptLiveDraftPublication
from jt_oz_bridge.storage.models import Action, Delivery
from jt_oz_bridge.storage.transcript_models import TranscriptDraft, TranscriptVersion
from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, frame
from tests.contract.test_visible_text_capture import event
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_resource_publisher import rows
from tests.integration.test_transcript_collector import setup as collector_setup
from tests.integration.test_transcript_drafts import allow_edit, deliver, finish, live
from tests.integration.test_transcript_publisher import baseline, output
from tests.support import REF


class LiveFixture:
    async def initialize(self, db, locale="en"):
        self.db = db
        previous, self.binding, self.reader, self.audience = await collector_setup(db)
        if locale != self.binding.locale:
            async with db.sessions.begin() as session:
                await session.execute(update(Binding).values(locale=locale))
            self.binding.locale = locale
        previous.bindings.control.contract_hash = INSTALLED_SCHEMA
        self.reader.contract_hash = INSTALLED_SCHEMA
        async with db.sessions.begin() as session:
            await session.execute(update(EnrolledBackend).values(contract_hash=INSTALLED_SCHEMA))
        self.index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
        self.index.accept(frame(CONNECTED))
        self.capture = VisibleTextCapture(self.index)
        original = self.reader.capture

        async def native_header(*args, **kwargs):
            page = await original(*args, **kwargs)
            page = page.model_copy(
                update={"owner_epoch": OWNER, "connection_epoch": self.index.require_live()}
            )
            self.reader.pages.append(page)
            return page

        self.reader.capture = native_header
        self.collector = TranscriptCollector(
            previous.bindings, {REF: self.reader}, previous.fence, drafts_enabled=True
        )
        rendered = output(self.collector, self.reader, limit=1200)
        self.primary = TranscriptPublisher(
            self.collector, rendered.replies, rendered.formatter, drafts_enabled=True
        )
        self.clock = [time.time()]
        self.drafts = TranscriptDraftPublisher(
            self.collector,
            self.primary.replies,
            self.primary.formatter,
            clock=lambda: self.clock[0],
        )
        self.chat = SyntheticChat()
        self.worker = DeliveryWorker(
            self.primary.outbox,
            self.chat,
            self.collector.fence.holder,
            self.collector.fence.fencing,
            minimum_interval=0,
            draft_readers={REF: self.reader},
        )
        self.feed = SimpleNamespace(
            current_owner=AsyncMock(), visible_text=self.capture, check_contract=lambda: None
        )
        self.source = LiveTextCollector(db, self.collector.fence, self.feed)
        self.join = LiveDraftCollector(self.collector, {REF: self.source})
        self.journal = LiveEventJournal(db, self.collector.fence)
        self.number = 0
        await baseline(self.primary, self.collector, self.binding)
        await deliver(self.worker)
        await live(self.collector, self.binding, self.reader, self.primary, text="")
        assert await self.draft_batch() is None  # Empty API text is not fabricated into a preview.
        return self

    async def emit(self, text):
        self.number += 1
        raw = event(self.number, text=text, assistant="native_reply")
        raw["data"]["sessionID"] = REF.upstream_session_id
        raw["location"] = {"directory": REF.canonical_directory}
        (item,) = await self.index.accept_receipted((frame(raw),), self.journal)
        self.capture.observe(item)
        self.index.pop()
        await self.source.collect()
        return await self.join.collect(self.binding)

    async def draft_batch(self):
        for _ in range(50):
            identity = await self.drafts.next_pending()
            if identity is None:
                return None
            batch = await self.drafts.publish(identity)
            if batch:
                return batch
        raise AssertionError("unbounded test draft queue")


async def test_actual_capture_source_with_empty_api_text_posts_edits_and_closes_one_preview(db):
    f = await LiveFixture().initialize(db)
    assert await f.emit("Captured first visible text") == 1
    assert await f.draft_batch()
    await deliver(f.worker)
    first = next(
        message for message in f.chat.messages.values() if "Captured first" in message.content
    )
    assert "there may be gaps" in first.content
    assert f.reader.messages[0].projection()["content"][0]["text"] == ""
    assert await f.emit(" plus the next fragment") == 1
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    await deliver(f.worker)
    assert "next fragment" in f.chat.messages[first.id].content
    await finish(f.collector, f.binding, f.reader, f.primary, text="Complete API reply")
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    await deliver(f.worker)
    assert "succeeded" in f.chat.messages[first.id].content
    assert "Complete API reply" in f.chat.messages[first.id].content
    edits = [item for item in await rows(db, Delivery) if item.payload["operation"] == "edit"]
    assert len(edits) == 2 and all(
        item.posted_message_id == first.id and item.payload["target_message_id"] == first.id
        for item in edits
    )
    assert len(f.chat.messages) == 4  # Digest, input, one preview and full reply.
    assert not await rows(db, Action)


async def test_missing_original_header_waits_without_creating_fake_transcript_or_action(db):
    f = await LiveFixture().initialize(db)
    f.capture._values.clear()
    f.number = 1
    raw = event(100, text="Different assistant", assistant="msg_missing_header")
    raw["data"]["sessionID"] = REF.upstream_session_id
    raw["location"] = {"directory": REF.canonical_directory}
    (item,) = await f.index.accept_receipted((frame(raw),), f.journal)
    f.capture.observe(item)
    f.index.pop()
    await f.source.collect()
    assert await f.join.collect(f.binding) == 0
    assert not await rows(db, TranscriptLiveDraftPublication)
    assert not await rows(db, Action)


async def test_joined_capture_corruption_and_native_header_scope_changes_are_rejected(db):
    f = await LiveFixture().initialize(db)
    await f.emit("Original live text")
    row = (await rows(db, TranscriptLiveDraftPublication))[0]
    async with db.sessions.begin() as session:
        await session.execute(
            update(TranscriptLiveDraftPublication).values(observation_revision=999)
        )
    with pytest.raises(Conflict, match="header_join"):
        await f.drafts.publish(row.id)


async def test_many_capture_versions_coalesce_without_creating_fake_api_text_versions(db):
    f = await LiveFixture().initialize(db)
    before = len(await rows(db, TranscriptVersion))
    for n in range(12):
        await f.emit(str(n) + " ")
    assert len(await rows(db, TranscriptVersion)) == before
    assert await f.draft_batch()
    await deliver(f.worker)
    preview = next(m for m in f.chat.messages.values() if "there may be gaps" in m.content)
    assert "0 1 2 3 4 5 6 7 8 9 10 11" in preview.content
    assert await f.draft_batch() is None
    assert len(f.chat.messages) == 3


@pytest.mark.parametrize("timing", ["publication", "delivery"])
async def test_fresh_private_audience_is_required_after_capture_and_before_the_actual_send(
    db, timing
):
    f = await LiveFixture().initialize(db)
    await f.emit("Private captured content")
    if timing == "delivery":
        assert await f.draft_batch()
    count_before_revoke = len(f.chat.messages)
    f.audience.users = frozenset({7, 8, 999})
    if timing == "publication":
        with pytest.raises(Conflict):
            await f.draft_batch()
    else:
        await deliver(f.worker)
    assert len(f.chat.messages) == count_before_revoke
    assert not any("Private captured content" in m.content for m in f.chat.messages.values())


@pytest.mark.parametrize("held_before_close", [False, True])
async def test_unattempted_edit_is_cancelled_and_terminal_edits_the_last_delivered_parent(
    db, held_before_close
):
    f = await LiveFixture().initialize(db)
    await f.emit("Initial preview")
    assert await f.draft_batch()
    await deliver(f.worker)
    frame = (await rows(db, TranscriptDraft))[0]
    first_delivery = await f.drafts.outbox.load(frame.payload["last_delivery_id"])
    await f.emit(" pending unsent update")
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    frame = (await rows(db, TranscriptDraft))[0]
    pending = await f.drafts.outbox.load(frame.payload["last_delivery_id"])
    assert pending.payload["operation"] == "edit" and pending.attempts == 0
    await finish(f.collector, f.binding, f.reader, f.primary, text="Final authoritative API text")
    if held_before_close:
        assert await f.worker.advance(pending.id) == "held"
        assert (await f.drafts.outbox.load(pending.id)).attempts == 0
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    assert (await f.drafts.outbox.load(pending.id)).state == "cancelled"
    await deliver(f.worker)
    final_frame = (await rows(db, TranscriptDraft))[0]
    last = await f.drafts.outbox.load(final_frame.payload["last_delivery_id"])
    assert last.payload["target_delivery_id"] == first_delivery.id
    assert last.posted_message_id == first_delivery.posted_message_id
    assert "succeeded" in f.chat.messages[last.posted_message_id].content
    assert "Final authoritative API text" in f.chat.messages[last.posted_message_id].content
    assert final_frame.finalized and len(f.chat.messages) == 4


async def test_known_terminal_prevents_a_pending_first_preview_and_closes_its_frame(db):
    f = await LiveFixture().initialize(db)
    await f.emit("Never send stale preview")
    assert await f.draft_batch()
    frame = (await rows(db, TranscriptDraft))[0]
    pending_id = frame.payload["last_delivery_id"]
    await finish(f.collector, f.binding, f.reader, f.primary, text="Only complete answer")
    assert await f.worker.advance(pending_id) == "held"
    assert (await f.drafts.outbox.load(pending_id)).attempts == 0
    assert await f.draft_batch() is None
    await deliver(f.worker)
    assert (await f.drafts.outbox.load(pending_id)).state == "cancelled"
    assert (await rows(db, TranscriptDraft))[0].finalized
    assert len(f.chat.messages) == 3


async def test_persisted_capture_proposals_and_frames_resume_without_a_new_native_action(db):
    f = await LiveFixture().initialize(db)
    await f.emit("Before bridge component restart")
    assert await f.draft_batch()
    await deliver(f.worker)
    f.source = LiveTextCollector(db, f.collector.fence, f.feed)
    await f.source.collect()
    f.join = LiveDraftCollector(f.collector, {REF: f.source})
    assert await f.join.collect(f.binding) == 0
    f.drafts = TranscriptDraftPublisher(
        f.collector, f.primary.replies, f.primary.formatter, clock=lambda: f.clock[0]
    )
    await f.emit(" after restart")
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    await deliver(f.worker)
    assert len(f.chat.messages) == 3
    assert any("after restart" in m.content for m in f.chat.messages.values())
    assert not await rows(db, Action)


async def test_current_original_header_must_match_agent_model_and_created_identity(db):
    from jt_oz_bridge.adapters.opencode.transcript import project_message

    f = await LiveFixture().initialize(db)
    changed = f.reader.messages[0].projection()
    changed["agent"] = "different-agent"
    f.reader.messages[0] = project_message(changed)
    with pytest.raises(Conflict, match="current_header_join"):
        await f.emit("Should not attach to a changed original identity")
    assert not await rows(db, TranscriptLiveDraftPublication)


async def test_restored_native_page_dto_is_not_live_header_authority(db):
    f = await LiveFixture().initialize(db)
    capture = f.reader.capture

    async def restored(*args, **kwargs):
        return (await capture(*args, **kwargs)).model_copy()

    f.reader.capture = restored
    assert await f.emit("No API authority from DTO restoration") == 0
    assert not await rows(db, TranscriptLiveDraftPublication)


async def test_header_witness_lost_during_source_join_rolls_back_the_proposal(db):
    f = await LiveFixture().initialize(db)
    current = f.source.current
    calls = 0

    def lost(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            f.reader.alive = False
        return current(*args)

    f.source.current = lost
    with pytest.raises(Conflict, match="header_changed_before_commit"):
        await f.emit("No stale original header")
    assert not await rows(db, TranscriptLiveDraftPublication)


async def test_capture_prefix_redaction_prevents_credential_fragments_in_any_posted_version(db):
    f = await LiveFixture().initialize(db, locale="zh-TW")
    partial = "sk-proj-abcd"
    await f.emit("Native output " + partial)
    assert await f.draft_batch()
    await deliver(f.worker)
    await f.emit("e" * 32 + "\n```python\nprint(123)\n")
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    await deliver(f.worker)
    bodies = [content for kind, content in f.chat.calls if kind in {"send", "edit"}]
    assert all(partial not in body for body in bodies)
    preview = next(m for m in f.chat.messages.values() if "即時片段" in m.content)
    assert "REDACTED" in preview.content and preview.content.count("```") % 2 == 0
    assert partial in f.capture.snapshots()[0].text  # Display only; the original remains unchanged.


async def test_generic_delivery_checks_the_sealed_fresh_header_facts_hash(db):
    from jt_oz_bridge.storage.durable import digest

    f = await LiveFixture().initialize(db)
    await f.emit("Captured original output")
    assert await f.draft_batch()
    row = (await rows(db, TranscriptLiveDraftPublication))[0]
    async with db.sessions.begin() as session:
        stored = await session.get(TranscriptLiveDraftPublication, row.id)
        stored.plan = {**stored.plan, "live_header_hash": "0" * 64}
        stored.plan_hash = digest(stored.plan)
    frame = (await rows(db, TranscriptDraft))[0]
    assert await f.worker.advance(frame.payload["last_delivery_id"]) == "held"
    assert not any("Captured original output" in m.content for m in f.chat.messages.values())


@pytest.mark.parametrize(
    "change",
    [
        "idle",
        "completed",
        "missing",
        "owner",
        "connection",
        "model",
        "agent",
        "created",
        "semantics",
        "installed",
        "later-terminal",
        "foreign",
        "restored",
        "reader",
    ],
)
async def test_pending_preview_uses_actual_native_state_even_when_own_mirror_has_not_polled(
    db, change
):
    from jt_oz_bridge.domain.control import ExecutionState
    from tests.integration.test_transcript_publisher import assistant

    f = await LiveFixture().initialize(db)
    await deliver(f.worker)
    await f.emit("Preview queued while originally active")
    assert await f.draft_batch()
    frame = (await rows(db, TranscriptDraft))[0]
    identity = frame.payload["last_delivery_id"]
    calls = len(f.chat.calls)
    if change == "idle":
        f.reader.state = ExecutionState.IDLE
    elif change == "completed":
        f.reader.messages[0] = assistant(text="Actual complete answer")
    elif change == "missing":
        f.reader.messages = f.reader.messages[1:]
    elif change == "later-terminal":
        from jt_oz_bridge.adapters.opencode.transcript import project_message

        f.reader.messages.insert(
            0,
            project_message(
                {
                    "id": "newer_actual_idle",
                    "type": "idle",
                    "time": {"created": 4},
                    "outcome": "interrupted",
                }
            ),
        )
    elif change == "foreign":
        f.reader.foreign = True
    elif change == "reader":
        f.worker = DeliveryWorker(
            f.primary.outbox,
            f.chat,
            f.collector.fence.holder,
            f.collector.fence.fencing,
            minimum_interval=0,
        )
    else:
        original = f.reader.capture

        async def changed(*args, **kwargs):
            page = await original(*args, **kwargs)
            if change == "restored":
                return page.model_copy()
            if change in {"model", "agent", "created"}:
                from jt_oz_bridge.adapters.opencode.transcript import project_message

                entries = list(page.entries)
                raw = entries[0].projection()
                if change == "model":
                    raw["model"]["id"] = "other-model"
                elif change == "agent":
                    raw["agent"] = "different-agent"
                else:
                    raw["time"]["created"] = 999
                entries[0] = project_message(raw)
                page = page.model_copy(update={"entries": tuple(entries)})
            else:
                key = {
                    "owner": "owner_epoch",
                    "connection": "connection_epoch",
                    "semantics": "semantics_sha256",
                    "installed": "installed_evidence_sha256",
                }[change]
                page = page.model_copy(update={key: "changed-source-identity"})
            f.reader.pages.append(page)
            return page

        f.reader.capture = changed
    assert await f.worker.advance(identity) == "held"
    saved = await f.worker.outbox.load(identity)
    assert saved.attempts == 0 and saved.posted_message_id is None
    assert len(f.chat.calls) == calls
    assert not await rows(db, Action)


@pytest.mark.parametrize("stage", ["audience", "edit-source", "claim"])
async def test_original_witness_expiring_during_delivery_awaits_sends_nothing_and_still_finalizes(
    db, stage
):
    from jt_oz_bridge.storage.models import AuditEvent

    f = await LiveFixture().initialize(db)
    await f.emit("First positively delivered preview")
    assert await f.draft_batch()
    await deliver(f.worker)
    preview = next(m for m in f.chat.messages.values() if "First positively" in m.content)
    await f.emit(" then an update that becomes obsolete")
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    frame = (await rows(db, TranscriptDraft))[0]
    identity = frame.payload["last_delivery_id"]
    calls = len(f.chat.calls)
    target = (
        f.worker.outbox if stage == "audience" else f.chat if stage == "edit-source" else f.worker
    )
    method = "target" if stage == "audience" else "get" if stage == "edit-source" else "claim"
    original = getattr(target, method)

    async def expire(*args, **kwargs):
        result = await original(*args, **kwargs)
        f.reader.alive = False
        return result

    setattr(target, method, expire)
    assert await f.worker.advance(identity) == "held"
    setattr(target, method, original)
    saved = await f.worker.outbox.load(identity)
    assert saved.attempts == 0 and saved.posted_message_id is None
    assert len(f.chat.calls) == calls
    if stage == "claim":
        assert any(
            a.event == "delivery_claim_aborted_before_http" for a in await rows(db, AuditEvent)
        )
    f.reader.alive = True
    await finish(f.collector, f.binding, f.reader, f.primary, text="Actual complete API answer")
    await allow_edit(f.drafts, db, f.clock)
    assert await f.draft_batch()
    await deliver(f.worker)
    assert (await f.worker.outbox.load(identity)).state == "cancelled"
    assert "succeeded" in f.chat.messages[preview.id].content
    assert "Actual complete API answer" in f.chat.messages[preview.id].content


async def test_positive_reconciliation_of_uncertain_preview_does_not_require_a_still_active_session(
    db,
):
    from jt_oz_bridge.domain.control import ExecutionState

    f = await LiveFixture().initialize(db)
    await deliver(f.worker)
    await f.emit("Accepted before the response was lost")
    assert await f.draft_batch()
    frame = (await rows(db, TranscriptDraft))[0]
    identity = frame.payload["last_delivery_id"]
    f.chat.mode = "timeout"
    assert await f.worker.advance(identity) == "ambiguous"
    calls = len(f.chat.calls)
    f.reader.state = ExecutionState.IDLE
    f.reader.alive = False
    assert await f.worker.reconcile(identity) == "delivered"
    assert len(f.chat.calls) == calls


async def test_real_adapter_checks_original_witness_after_its_identity_await_before_http(db):
    import httpx

    from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
    from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway

    f = await LiveFixture().initialize(db)
    await deliver(f.worker)
    await f.emit("Never export a stale active preview")
    assert await f.draft_batch()
    identity = (await rows(db, TranscriptDraft))[0].payload["last_delivery_id"]
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"result": "success", "id": 1234})

    async def identity_check():
        f.reader.alive = False
        return True

    client = ZulipClient(
        "https://chat.example.test",
        "bot@example.test",
        "fixture-not-a-secret",
        attestation=ZulipAttestation("https://chat.example.test", "realm", 77, 500, 10000, 100),
        verify_identity=identity_check,
        transport=httpx.MockTransport(handler),
    )
    f.worker.gateway = ZulipGateway(client)
    try:
        assert await f.worker.advance(identity) == "held"
        saved = await f.worker.outbox.load(identity)
        assert saved.attempts == 0 and saved.posted_message_id is None
        assert not requests  # The actual HTTP adapter never invoked its transport.
        # The task-local guard is restored even when the adapter aborts a claim.
        await client.request("POST", "messages", data={"content": "Independent synthetic call"})
        assert len(requests) == 1
    finally:
        await client.close()
