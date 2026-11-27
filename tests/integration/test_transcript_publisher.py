"""Original-message projection + real encrypted SQL/outbox; no live Native writes."""

import asyncio
import copy
import html
import json
import time

import pytest
from sqlalchemy import delete, event, select, update

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.domain.delivery import DeliveryRejected
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_commands import NativeTranscriptCommands
from jt_oz_bridge.services.transcript_publisher import TranscriptPublisher
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch, Grant
from jt_oz_bridge.storage.publication_models import BatchDependency
from jt_oz_bridge.storage.transcript_models import (
    TranscriptMessage,
    TranscriptPublication,
    TranscriptStream,
)
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_resource_execution_results import setup as admitted_setup
from tests.integration.test_resource_publisher import rows
from tests.integration.test_router import Source
from tests.integration.test_transcript_collector import entry, versions
from tests.integration.test_transcript_collector import setup as collector_setup
from tests.integration.test_transcript_commands import OriginalReader
from tests.support import REF


def output(collector, reader, *, limit=2000):
    history = NativeTranscriptCommands(
        collector.bindings,
        TokenService(collector.db, fence=collector.fence),
        Source(),
        {REF: reader},
        message_limit=limit,
    )
    return TranscriptPublisher(
        collector,
        RoutedOutbox(
            Outbox(collector.bindings, 77, fence=collector.fence),
            realm_id="realm",
            message_limit=limit,
            topic_limit=60,
        ),
        history.body,
    )


async def setup(db, *, locale="en", limit=2000):
    collector, binding, reader, audience = await collector_setup(db)
    if locale != binding.locale:
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(locale=locale))
        binding.locale = locale
    return output(collector, reader, limit=limit), collector, binding, reader, audience


def assistant(
    identity="native_reply",
    text="Computer result",
    *,
    completed=True,
    tools=(),
    model="model",
    agent="build",
):
    return project_message(
        {
            "id": identity,
            "type": "assistant",
            "agent": agent,
            "model": {"providerID": "fixture", "id": model},
            "time": {"created": 2, **({"completed": 3} if completed else {})},
            "content": [{"type": "text", "text": text}, *tools],
        }
    )


async def baseline(publisher, collector, binding):
    state = await collector.collect(binding)
    assert await publisher.next_pending() == ("bootstrap", state.key)
    batch = await publisher.scope_notice(state.key, "bootstrap")
    assert await publisher.next_pending() is None
    return batch


async def drain(publisher):
    results = []
    while pending := await publisher.next_pending():
        kind, identity = pending
        assert kind == "version"
        results.append(await publisher.publish(identity))
        assert len(results) < 100
    return results


def content(deliveries):
    return "\n".join(row.payload["content"] for row in deliveries)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("limit", [512, 2000])
async def test_initial_twenty_or_fewer_messages_use_one_sealed_digest_not_individual_posts(
    db, locale, limit
):
    publisher, collector, binding, reader, _ = await setup(db, locale=locale, limit=limit)
    batch = await baseline(publisher, collector, binding)
    deliveries = await rows(db, Delivery)
    assert len(deliveries) == 1 and deliveries[0].batch_id == batch
    assert len(await rows(db, TranscriptPublication)) == 17
    assert not await rows(db, Action)
    assert (
        await publisher.scope_notice((await collector.load(binding))[0].key, "bootstrap") == batch
    )
    assert len(await rows(db, Delivery)) == 1
    assert ("最近對話" if locale == "zh-TW" else "Recent conversation") in content(deliveries)
    assert "!history" in content(deliveries)
    assert len(content(deliveries)) <= limit


async def test_native_input_reply_and_outcome_are_ordered_once_without_actions(db):
    publisher, collector, binding, reader, _ = await setup(db)
    first = await baseline(publisher, collector, binding)
    reader.messages[:0] = [
        project_message(
            {"id": "terminal", "type": "idle", "time": {"created": 4}, "outcome": "failed"}
        ),
        assistant(),
        entry("native_input", "Original computer instruction"),
    ]
    await collector.collect(binding)
    batches = await drain(publisher)
    assert len(batches) == 3 and all(batches)
    dependencies = {r.batch_id: r.before_batch_id for r in await rows(db, BatchDependency)}
    assert dependencies == dict(zip(batches, [first, *batches[:-1]], strict=True))
    deliveries = await rows(db, Delivery)
    bodies = [next(d.payload["content"] for d in deliveries if d.batch_id == b) for b in batches]
    assert "Original computer instruction" in bodies[0]
    assert "Computer result" in bodies[1] and "failed" in bodies[2]
    assert not await rows(db, Action)
    for row in (await versions(db))[-3:]:
        assert await publisher.publish(row.id) in batches
    assert len(await rows(db, Delivery)) == 4


async def test_phone_echo_requires_positive_exact_native_admission_and_preserves_reply_locale(db):
    results, binding, action_id, _, execution, _ = await admitted_setup(db, locale="zh-TW")
    reader = OriginalReader()
    reader.contract_hash = INSTALLED_SCHEMA
    collector = TranscriptCollector(results.bindings, {REF: reader}, results.fence)
    publisher = output(collector, reader)
    await baseline(publisher, collector, binding)
    async with db.sessions() as session:
        action = await session.get(Action, action_id)
    reader.messages[:0] = [assistant(), entry(action.upstream_id, action.payload["text"])]
    await collector.collect(binding)
    planned = await drain(publisher)
    assert planned[0] is None and planned[1] is not None
    pub = (await rows(db, TranscriptPublication))[-2:]
    assert pub[0].payload["mode"] == "echo" and pub[1].payload["locale"] == "zh-TW"
    assert len(await rows(db, Action)) == len(execution.submitted) == 1
    assert "Computer result" in content(await rows(db, Delivery))


async def test_identical_native_text_without_admission_never_claims_phone_origin(db):
    publisher, collector, binding, reader, _ = await setup(db)
    await baseline(publisher, collector, binding)
    reader.messages.insert(0, entry("native_without_receipt", "Original exact prompt"))
    await collector.collect(binding)
    assert (await drain(publisher))[0] is not None
    assert (await rows(db, TranscriptPublication))[-1].payload["mode"] == "queued"
    assert not await rows(db, Action)


async def test_incomplete_text_is_not_final_and_completed_same_message_becomes_update(db):
    publisher, collector, binding, reader, _ = await setup(db)
    await baseline(publisher, collector, binding)
    reader.messages.insert(0, assistant(text="Partial unfinished", completed=False))
    await collector.collect(binding)
    assert await drain(publisher) == [None]
    assert "Partial unfinished" not in content(await rows(db, Delivery))
    reader.messages[0] = assistant(text="Final original answer")
    await collector.collect(binding)
    assert (await drain(publisher))[0] is not None
    body = content(await rows(db, Delivery))
    assert "Final original answer" in body and "Updated" not in body


async def test_unplanned_intermediate_versions_are_superseded_not_replayed(db):
    publisher, collector, binding, reader, _ = await setup(db)
    await baseline(publisher, collector, binding)
    reader.messages.insert(0, assistant(text="Earlier value"))
    await collector.collect(binding)
    reader.messages[0] = assistant(text="Latest original value")
    await collector.collect(binding)
    assert (await drain(publisher))[0] is None
    body = content(await rows(db, Delivery))
    assert "Earlier value" not in body and "Latest original value" in body
    assert (await rows(db, TranscriptPublication))[-2].payload["mode"] == "superseded"


async def test_gap_gets_one_independent_priority_notice_and_no_later_content(db):
    publisher, collector, binding, reader, _ = await setup(db)
    await baseline(publisher, collector, binding)
    reader.messages = [entry("after_revert", "Must not silently replace history")]
    state = await collector.collect(binding)
    assert await publisher.next_pending() == ("gap", state.key)
    batch = await publisher.scope_notice(state.key, "gap")
    assert await publisher.scope_notice(state.key, "gap") == batch
    assert await publisher.next_pending() is None
    assert all(r.batch_id != batch for r in await rows(db, BatchDependency))
    assert next(b for b in await rows(db, DeliveryBatch) if b.id == batch).priority == 1
    assert "Must not silently" not in content(await rows(db, Delivery))


async def test_gap_before_first_digest_does_not_retry_blocked_bootstrap_forever(db):
    publisher, collector, binding, reader, _ = await setup(db)
    state = await collector.collect(binding)
    reader.messages = [entry("after_revert")]
    await collector.collect(binding)
    assert await publisher.next_pending() == ("gap", state.key)
    await publisher.scope_notice(state.key, "gap")
    assert await publisher.next_pending() is None
    assert len(await rows(db, Delivery)) == 1


@pytest.mark.parametrize("change", ["audience", "public", "grant", "binding"])
async def test_cached_history_and_new_content_require_current_private_scope(db, change):
    publisher, collector, binding, reader, audience = await setup(db)
    await baseline(publisher, collector, binding)
    reader.messages.insert(0, entry("new"))
    state = await collector.collect(binding)
    identity = (await versions(db))[-1].id
    if change == "audience":
        audience.users = frozenset({7, 8, 999})
    elif change == "public":
        audience.private = False
    else:
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant).values(active=False)
                if change == "grant"
                else update(Binding).values(revision=2)
            )
    for operation in (publisher.publish(identity), publisher.scope_notice(state.key, "bootstrap")):
        with pytest.raises((Conflict, AccessDenied)):
            await operation
    assert len(await rows(db, Delivery)) == 1


async def test_concurrent_planning_is_atomic_and_failed_transaction_can_recover(db):
    publisher, collector, binding, reader, _ = await setup(db)
    await baseline(publisher, collector, binding)
    reader.messages.insert(0, assistant())
    await collector.collect(binding)
    identity = (await versions(db))[-1].id

    def fail(*args):
        raise OSError("synthetic failed plan commit")

    event.listen(TranscriptPublication, "before_insert", fail)
    try:
        with pytest.raises(OSError):
            await publisher.publish(identity)
    finally:
        event.remove(TranscriptPublication, "before_insert", fail)
    assert len(await rows(db, DeliveryBatch)) == 1
    first, second = await asyncio.gather(publisher.publish(identity), publisher.publish(identity))
    assert first == second and len(await rows(db, DeliveryBatch)) == 2


@pytest.mark.parametrize(
    "change", ["dependency", "plan_hash", "source_hash", "page", "notice", "current_hash"]
)
async def test_cached_plans_and_generic_delivery_validation_reject_corruption(db, change):
    publisher, collector, binding, reader, _ = await setup(db)
    bootstrap = await baseline(publisher, collector, binding)
    reader.messages.insert(0, assistant())
    await collector.collect(binding)
    identity = (await versions(db))[-1].id
    batch = await publisher.publish(identity)
    async with db.sessions.begin() as session:
        if change == "dependency":
            await session.execute(delete(BatchDependency).where(BatchDependency.batch_id == batch))
        elif change in {"plan_hash", "source_hash"}:
            row = await session.get(TranscriptPublication, identity)
            payload = copy.deepcopy(row.payload)
            payload[change] = "0" * 64
            row.payload = payload  # deliberately leave authenticated lookup hash unchanged
        elif change == "current_hash":
            await session.execute(
                update(TranscriptMessage)
                .where(TranscriptMessage.native_id == "native_reply")
                .values(current_hash="0" * 64)
            )
        elif change == "notice":
            row = (await session.scalars(select(TranscriptStream))).one()
            row.payload_hash = "0" * 64
        else:
            row = (await session.scalars(select(Delivery).where(Delivery.batch_id == batch))).one()
            row.payload_hash = "0" * 64
    with pytest.raises(Conflict):
        await publisher.publish(identity)
    with pytest.raises(Conflict):
        await publisher.outbox.batch_by_id(
            bootstrap if change == "notice" else batch, binding.id, 1
        )


@pytest.mark.parametrize("kind", ["resource", "model"])
@pytest.mark.parametrize("mode", ["configured", "persisted"])
async def test_old_publishers_cannot_duplicate_output_for_explicit_mirrored_root(db, kind, mode):
    from jt_oz_bridge.services.model_setting_publisher import ModelSettingPublisher
    from jt_oz_bridge.services.resource_publisher import ResourcePublisher
    from tests.integration.test_model_setting_publisher import setup as model_setup
    from tests.integration.test_resource_publisher import setup as resource_setup

    if kind == "resource":
        previous, _, _, identity, _, _ = await resource_setup(db)
        publisher = ResourcePublisher(
            previous.replies,
            excluded_references=frozenset({REF}) if mode == "configured" else frozenset(),
        )
    else:
        previous, _, identity, _, _ = await model_setup(db)
        publisher = ModelSettingPublisher(
            previous.replies,
            excluded_references=frozenset({REF}) if mode == "configured" else frozenset(),
        )
    assert await previous.next_pending() == identity
    if mode == "persisted":
        reader = OriginalReader()
        reader.contract_hash = publisher.replies.outbox.bindings.control.contract_for(REF)
        async with db.sessions() as session:
            binding = await session.get(Binding, (await session.get(Action, identity)).binding_id)
        await TranscriptCollector(
            publisher.replies.outbox.bindings, {REF: reader}, publisher.replies.outbox.fence
        ).collect(binding)
    assert await publisher.next_pending() is None
    with pytest.raises(Conflict, match="output_owned_by_native_transcript"):
        await publisher.publish(identity)
    assert not await rows(db, Delivery)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_bootstrap_model_preview_displays_original_punctuation_in_saved_delivery(db, locale):
    from jt_oz_bridge.presentation.markdown import MobileMarkdown
    from tests.unit.test_markdown import Elements

    publisher, collector, binding, reader, _ = await setup(db, locale=locale, limit=10000)
    model = "example-provider/example1.5-model_next-q3_s [none]"
    reader.messages = [
        project_message(
            {
                "id": "native_model_preview",
                "type": "model-switched",
                "time": {"created": 1},
                "model": {
                    "providerID": "example-provider",
                    "id": "example1.5-model_next-q3_s",
                    "variant": "none",
                },
            }
        )
    ]
    batch = await baseline(publisher, collector, binding)
    saved = await rows(db, Delivery)
    assert len(saved) == 1 and saved[0].batch_id == batch
    parser = Elements()
    parser.feed(MobileMarkdown(locale=locale).preview_html(saved[0].payload["content"]))
    visible = "".join(parser.text)
    assert model in visible and "&#" not in visible
    assert not [link for link in parser.links if "#jtoz:" not in link] and not {
        "script",
        "iframe",
        "img",
        "em",
    } & set(parser.tags)
    assert not await rows(db, Action)


def test_code_mode_tool_names_are_projected_without_their_input_or_output():
    from jt_oz_bridge.adapters.opencode.transcript import project_message

    raw = {
        "id": "msg_1",
        "type": "assistant",
        "time": {"created": 1, "completed": 2},
        "agent": "build",
        "model": {"providerID": "p", "id": "m"},
        "content": [
            {
                "type": "tool",
                "id": "call_1",
                "name": "execute",
                "time": {"created": 1},
                "state": {
                    "status": "completed",
                    "input": {"code": "SECRET_INPUT"},
                    "content": [{"type": "text", "text": "SECRET_OUTPUT"}],
                    "metadata": {
                        "toolCalls": [{"tool": "pve.get_pbs_status", "status": "completed"}]
                    },
                },
            }
        ],
    }
    entry = project_message(raw)
    assert entry.projection()["content"][0]["calls"] == [
        {"tool": "pve.get_pbs_status", "status": "completed"}
    ]
    assert "SECRET" not in entry.projection_json
    plain = raw | {"content": [dict(raw["content"][0], state={"status": "completed"})]}
    assert project_message(plain).projection_sha256 == entry.sha256_before_tool_calls()


async def posted(db, publisher, collector, binding, reader, message):
    """Post one more Native entry and return the text of the delivery it planned."""
    reader.messages.insert(0, message)
    await collector.collect(binding)
    (batch,) = await drain(publisher)
    assert batch is not None
    return html.unescape(content([d for d in await rows(db, Delivery) if d.batch_id == batch]))


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_model_and_agent_line_is_shown_once_then_only_when_it_changes(db, locale):
    publisher, collector, binding, reader, _ = await setup(db, locale=locale)
    await baseline(publisher, collector, binding)
    label = "模型：" if locale == "zh-TW" else "Model: "
    first = await posted(db, publisher, collector, binding, reader, assistant("r1", "One"))
    assert "One" in first and label in first and "build" in first
    again = await posted(db, publisher, collector, binding, reader, assistant("r2", "Two"))
    assert "Two" in again and label not in again and "build" not in again
    # A tool step is progress without the line; it neither shows nor resets it.
    tool = {
        "type": "tool",
        "id": "call_1",
        "name": "bash",
        "time": {"created": 2},
        "state": {"status": "completed"},
    }
    step = await posted(
        db, publisher, collector, binding, reader, assistant("r3", "Look", tools=(tool,))
    )
    assert "\n\n*🔧 bash*" in step and label not in step
    same = await posted(db, publisher, collector, binding, reader, assistant("r4", "Four"))
    assert label not in same
    changed = await posted(
        db, publisher, collector, binding, reader, assistant("r5", "Five", model="other")
    )
    assert label in changed and "other" in changed
    agent = await posted(
        db,
        publisher,
        collector,
        binding,
        reader,
        assistant("r6", "Six", model="other", agent="plan"),
    )
    assert label in agent and "plan" in agent
    quiet = await posted(
        db,
        publisher,
        collector,
        binding,
        reader,
        assistant("r7", "Seven", model="other", agent="plan"),
    )
    assert label not in quiet
    # Sealed plans are reused: publishing again posts nothing new or different.
    count = len(await rows(db, Delivery))
    for version in await versions(db):
        await publisher.publish(version.id)
    assert len(await rows(db, Delivery)) == count


async def test_a_new_publisher_after_restart_keeps_leaving_out_the_shown_line(db):
    publisher, collector, binding, reader, _ = await setup(db)
    await baseline(publisher, collector, binding)
    first = await posted(db, publisher, collector, binding, reader, assistant("r1", "One"))
    assert "Model: " in first
    restarted = output(collector, reader)
    later = await posted(db, restarted, collector, binding, reader, assistant("r2", "Two"))
    assert "Two" in later and "Model: " not in later


async def test_explicit_history_listing_keeps_the_model_line(db):
    publisher, *_ = await setup(db)
    message = assistant("r1", "One")
    shown = publisher.formatter(message, "en")
    assert "Model: " in shown and "Agent: " in shown
    assert "Model: " not in publisher.formatter(message, "en", footer=False)


def tool(name, identity="call_1"):
    return {
        "type": "tool",
        "id": identity,
        "name": name,
        "time": {"created": 2},
        "state": {"status": "completed"},
    }


def step(identity, *names, text=""):
    """A finished assistant step that ran these tools."""
    return assistant(
        identity,
        text,
        tools=tuple(tool(name, f"{identity}_{i}") for i, name in enumerate(names)),
    )


def idle(identity):
    return project_message(
        {"id": identity, "type": "idle", "time": {"created": 4}, "outcome": "succeeded"}
    )


async def deliver(worker):
    """Send what is ready, as the runtime's delivery loop would."""
    for _ in range(100):
        async with worker.db.sessions() as session:
            identity = await session.scalar(worker.next_pending("realm", time.time()))
        if identity is None:
            return
        await worker.advance(identity)
    raise AssertionError("unbounded fixture delivery")


class Turn:
    """Publisher + synthetic Zulip delivery for one bound topic's progress messages."""

    async def initialize(self, db, *, limit=2000, locale="en"):
        publisher, self.collector, self.binding, self.reader, _ = await setup(
            db, limit=limit, locale=locale
        )
        self.db, self.clock = db, [time.time()]
        self.publisher = self.restart(publisher)
        self.chat = SyntheticChat()
        self.worker = DeliveryWorker(
            self.publisher.outbox,
            self.chat,
            self.collector.fence.holder,
            self.collector.fence.fencing,
            minimum_interval=0,
        )
        await baseline(self.publisher, self.collector, self.binding)
        await deliver(self.worker)
        return self

    def restart(self, previous=None):
        previous = previous or self.publisher
        return TranscriptPublisher(
            self.collector, previous.replies, previous.formatter, clock=lambda: self.clock[0]
        )

    async def add(self, *messages, send=True):
        """Native entries in order; each add is one later look at the session."""
        self.reader.messages[:0] = reversed(messages)
        await self.collector.collect(self.binding)
        self.clock[0] += 2  # Past any wait for an earlier progress message.
        planned = await drain(self.publisher)
        while send:
            # As the runtime's loops: send, then plan what waited for that.
            await deliver(self.worker)
            self.clock[0] += 2
            if not (later := await drain(self.publisher)):
                break
            planned += later
        return planned

    def sent(self, kind):
        return [content for call, content in self.chat.calls if call == kind]

    def shown(self):
        """Visible message texts in topic order, without the bootstrap digest."""
        return [
            html.unescape(message.content)
            for _, message in sorted(self.chat.messages.items())
            if "Recent conversation" not in message.content
        ]

    def progress(self):
        return [lines(text) for text in self.shown() if "🔧" in text]

    async def deliveries(self):
        return sorted(await rows(self.db, Delivery), key=lambda d: d.created_at)


def lines(text):
    """Tool lines of a message, without the identity link on its last line."""
    return [line.split("[")[0] for line in text.split("\n") if line.startswith("*🔧")]


async def test_a_turns_tool_steps_share_one_message_edited_in_place_then_the_reply(db):
    t = await Turn().initialize(db)
    await t.add(entry("native_input", "Check the garden"))
    await t.add(step("s1", "garden.plantsSummary", "garden.seedStats"))
    await t.add(step("s2", "search"))
    await t.add(step("s3", "garden.waterStatistics", "garden.listPlants"))
    await t.add(step("s4", "garden.weatherSummary"))
    await t.add(assistant("final", "All plants are fine"))
    # Bootstrap digest, the input, one progress message and the reply.
    assert len(t.sent("send")) == 4 and len(t.sent("edit")) == 3
    assert t.progress() == [
        [
            "*🔧 garden.plantsSummary, garden.seedStats*",
            "*🔧 search*",
            "*🔧 garden.waterStatistics, garden.listPlants*",
            "*🔧 garden.weatherSummary*",
        ]
    ]
    reply = t.shown()[-1]
    assert "All plants are fine" in reply and "🔧" not in reply
    publications = await rows(db, TranscriptPublication)
    modes = [p.payload["mode"] for p in publications if p.batch_id]
    assert modes[-5:] == ["queued", "progress", "progress", "progress", "queued"]
    # Edits stay off the topic's chain: the reply waited only for the first post.
    edits = {p.batch_id for p in publications if p.payload["mode"] == "progress"}
    chained = {x for r in await rows(db, BatchDependency) for x in (r.batch_id, r.before_batch_id)}
    assert len(edits) == 3 and not edits & chained
    # A restarted publisher reuses every sealed plan and sends nothing again.
    count, t.publisher = len(await rows(db, Delivery)), t.restart()
    assert await t.publisher.next_pending() is None
    for version in await versions(db):
        await t.publisher.publish(version.id)
    await deliver(t.worker)
    assert len(await rows(db, Delivery)) == count and len(t.chat.calls) == 7


async def test_each_input_and_each_turn_gets_its_own_progress_message(db):
    t = await Turn().initialize(db)
    await t.add(entry("in1", "First"), step("a1", "bash"), step("a2", "read"))
    # A steer: another input while the same turn still runs owns what follows it.
    await t.add(entry("in2", "Also this"), step("b1", "grep"))
    await t.add(assistant("r1", "Done"), idle("idle1"), step("c1", "glob"))
    assert t.progress() == [["*🔧 bash*", "*🔧 read*"], ["*🔧 grep*"], ["*🔧 glob*"]]
    texts = t.shown()
    steer = next(i for i, text in enumerate(texts) if "Also this" in text)
    assert "grep" in texts[steer + 1]


async def test_a_step_with_words_is_its_own_message_and_later_tools_join_it(db):
    t = await Turn().initialize(db)
    await t.add(step("s1", "bash"), step("s2", "read", text="Found the config"), step("s3", "edit"))
    assert t.progress() == [["*🔧 bash*"], ["*🔧 read*", "*🔧 edit*"]]
    assert "Found the config" in [text for text in t.shown() if "🔧" in text][1]
    assert len(t.sent("send")) == 3 and len(t.sent("edit")) == 1


async def test_the_same_tools_again_count_up_instead_of_repeating(db):
    t = await Turn().initialize(db)
    await t.add(step("s1", "search"), step("s2", "search"), step("s3", "search"))
    await t.add(step("s4", "read"), step("s5", "search"))
    assert t.progress() == [["*🔧 search* ×3", "*🔧 read*", "*🔧 search*"]]


SORRY = "Sorry, I forgot the flag: yes. Adding it now."


def stepped(text):
    """Messages showing a step's words, without the identity link on the last line."""
    return [line.split("[")[0] for line in text.split("\n") if line]


async def test_the_same_step_said_again_counts_up_instead_of_repeating(db):
    t = await Turn().initialize(db)
    await t.add(entry("in1", "Run the scan"))
    # A weak model in a loop: the same words and the same tool, step after step.
    await t.add(*(step(f"s{i}", "search", text=SORRY) for i in range(3)))
    # Only whitespace differs: still the same step.
    await t.add(step("s3", "search", text="Sorry,  I forgot the flag: yes.\nAdding it now. "))
    said = [text for text in t.shown() if SORRY.split(".")[0] in text]
    assert len(said) == 1 and stepped(said[0])[-1] == "*🔧 search* ×4"
    assert said[0].count("Sorry") == 1
    # Posted once; each later step edits it (an unsent edit is folded into the next).
    assert len([text for text in t.sent("send") if "Sorry" in text]) == 1
    assert 1 <= len(t.sent("edit")) <= 3
    modes = [p.payload["mode"] for p in await rows(db, TranscriptPublication) if p.batch_id]
    assert modes[-4:] == ["queued", "progress", "progress", "progress"]
    # The reply still posts after it; a restart sends nothing again.
    await t.add(assistant("final", "Scan started"))
    assert "Scan started" in t.shown()[-1]
    count, t.publisher = len(t.chat.calls), t.restart()
    for version in await versions(db):
        await t.publisher.publish(version.id)
    await deliver(t.worker)
    assert len(t.chat.calls) == count


async def test_a_different_step_in_between_starts_the_count_again(db):
    t = await Turn().initialize(db)
    await t.add(entry("in1", "Run the scan"))
    await t.add(step("a1", "search", text=SORRY), step("a2", "search", text=SORRY))
    await t.add(step("b1", "search", text="Trying another way"))
    await t.add(step("a3", "search", text=SORRY), step("a4", "read", text=SORRY))
    said = [stepped(text) for text in t.shown() if "🔧" in text]
    assert [message[-1] for message in said] == [
        "*🔧 search* ×2",
        "*🔧 search*",
        "*🔧 search*",
        "*🔧 read*",
    ]
    assert len(t.sent("edit")) == 1
    # A new turn never counts on the last one's message.
    await t.add(idle("idle1"), entry("in2", "Again"), step("c1", "read", text=SORRY))
    assert stepped(t.shown()[-1])[-1] == "*🔧 read*"


async def hints(db):
    return [
        d
        for d in await rows(db, Delivery)
        if "!stop" in d.payload["content"] and "🔧" not in d.payload["content"]
    ]


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_the_fifth_same_step_in_a_turn_suggests_stop_once_and_stops_nothing(db, locale):
    from jt_oz_bridge.services.transcript_publisher import (
        REPEAT_HINT_AT,
        REPEAT_HINT_PRIORITY,
        REPEAT_HINT_RENDERER,
    )

    t = await Turn().initialize(db, locale=locale)
    await t.add(entry("in1", "Run the scan"))
    await t.add(*(step(f"s{i}", "search", text=SORRY) for i in range(REPEAT_HINT_AT - 1)))
    assert not await hints(db)
    actions = len(await rows(db, Action))
    await t.add(step("s4", "search", text=SORRY))
    (hint,) = await hints(db)
    words = "已 5 次" if locale == "zh-TW" else "(5 times)"
    assert words in hint.payload["content"] and "!stop" in hint.payload["widget"]
    batch = next(b for b in await rows(db, DeliveryBatch) if b.id == hint.batch_id)
    assert (batch.renderer_version, batch.priority) == (REPEAT_HINT_RENDERER, REPEAT_HINT_PRIORITY)
    assert hint.state == "delivered" and words in t.shown()[-1]
    # Only a suggestion: nothing was sent to OpenCode on the person's behalf.
    assert len(await rows(db, Action)) == actions
    # More repeats, a new message after Zulip's edit limit and a restart: still one.
    await t.add(*(step(f"t{i}", "search", text=SORRY) for i in range(3)))
    t.clock[0] += 600
    await t.add(step("u0", "search", text=SORRY))
    t.clock[0] -= 600  # Back to the fixture's time, so the new message is edited again.
    await t.add(*(step(f"u{i}", "search", text=SORRY) for i in range(1, REPEAT_HINT_AT + 1)))
    said = [stepped(text)[-1] for text in t.shown() if "🔧" in text]
    assert said == ["*🔧 search* ×8", "*🔧 search* ×6"] and len(await hints(db)) == 1
    t.publisher = t.restart()
    for version in await versions(db):
        await t.publisher.publish(version.id)
    await deliver(t.worker)
    assert len(await hints(db)) == 1
    # The next turn may get its own.
    await t.add(idle("idle1"), entry("in2", "Again"))
    await t.add(*(step(f"v{i}", "search", text=SORRY) for i in range(REPEAT_HINT_AT)))
    assert len(await hints(db)) == 2


async def test_tool_lines_alone_never_suggest_stop(db):
    t = await Turn().initialize(db)
    await t.add(entry("in1", "Search everything"))
    await t.add(*(step(f"s{i}", "search") for i in range(8)))
    assert t.progress() == [["*🔧 search* ×8"]] and not await hints(db)


async def test_an_unsent_repeat_hint_is_retired_when_its_turn_ends_and_a_sent_one_stays(db):
    t = await Turn().initialize(db)
    # A hint already sent stays as it is when the turn's reply comes.
    await t.add(entry("in1", "Run the scan"))
    await t.add(*(step(f"s{i}", "search", text=SORRY) for i in range(5)))
    (sent,) = await hints(db)
    await t.add(assistant("r1", "Scan started"), idle("idle1"))
    assert [(h.id, h.state) for h in await hints(db)] == [(sent.id, "delivered")]
    # One not sent yet when the reply comes would only land late: cancelled unsent.
    await t.add(entry("in2", "Again"))
    await t.add(*(step(f"t{i}", "search", text=SORRY) for i in range(4)))
    await t.add(step("t4", "search", text=SORRY), send=False)
    unsent = next(h for h in await hints(db) if h.id != sent.id)
    assert unsent.state == "pending"
    await t.add(assistant("r2", "Scan started again"))
    retired = next(h for h in await hints(db) if h.id == unsent.id)
    assert (retired.state, retired.status_reason) == ("cancelled", "repeat_hint_superseded")
    assert retired.posted_message_id is None
    assert [
        a.object_id
        for a in await rows(db, AuditEvent)
        if a.event == "transcript_repeat_hint_retired"
    ] == [unsent.id]
    assert "Scan started again" in t.shown()[-1]
    assert sum("(5 times)" in text for text in t.shown()) == 1
    assert next(h for h in await hints(db) if h.id == sent.id).state == "delivered"


def finished(identity, text, *, context=None, tokens=None, completed=True, tools=()):
    """A finished step whose model read ``context`` tokens (most of them cached)."""
    raw = {
        "id": identity,
        "type": "assistant",
        "agent": "build",
        "model": {"providerID": "fixture", "id": "model"},
        "time": {"created": 2, **({"completed": 3} if completed else {})},
        "content": [{"type": "text", "text": text}, *tools],
    }
    if context is not None:
        tokens = {
            "input": 1000,
            "output": 50,
            "reasoning": 0,
            "cache": {"read": context - 1200, "write": 200},
        }
    if tokens is not None:
        raw["tokens"] = tokens
    return project_message(raw)


def test_token_counts_enter_the_projection_as_bounded_whole_numbers_only():
    from jt_oz_bridge.adapters.opencode.transcript import TOKEN_LIMIT, same_message

    counts = {"input": 1000.0, "output": 7, "reasoning": 0, "cache": {"read": 94000, "write": 0}}
    reply = finished("r1", "Done", tokens=counts)
    assert reply.projection()["tokens"] == {
        "input": 1000,
        "output": 7,
        "reasoning": 0,
        "cache_read": 94000,
        "cache_write": 0,
    }
    assert all(type(v) is int for v in reply.projection()["tokens"].values())
    assert reply.context_tokens() == 95000
    huge = finished("r1", "Done", tokens=counts | {"input": 1e30})
    assert huge.projection()["tokens"]["input"] == TOKEN_LIMIT
    for bad in (
        counts | {"input": "95000"},
        counts | {"output": True},
        counts | {"input": float("nan")},
        counts | {"reasoning": -1},
        counts | {"cache": {"read": 1}},
        counts | {"cache": "x"},
        {"input": 1},
        "95000",
    ):
        assert "tokens" not in finished("r1", "Done", tokens=bad).projection()
    assert finished("r1", "Done", tokens=bad).context_tokens() is None
    # A running step's counts are left out; they are complete once it finishes.
    assert "tokens" not in finished("r1", "Do", tokens=counts, completed=False).projection()
    # Counts are not content: a reply saved without them, or with others, is the same.
    plain = finished("r1", "Done")
    assert same_message(plain, reply) and same_message(reply, huge)
    assert not same_message(plain, finished("r1", "Done!", tokens=counts))


async def test_a_reply_read_again_with_token_counts_is_not_a_new_version(db):
    t = await Turn().initialize(db)
    await t.add(entry("in1", "Hello"), finished("r1", "Hi there"))
    count, calls = len(await versions(db)), len(t.chat.calls)
    # As after an upgrade: the same finished reply, now read with its token counts.
    index = next(i for i, m in enumerate(t.reader.messages) if m.native_id == "r1")
    t.reader.messages[index] = finished("r1", "Hi there", context=95000)
    await t.add()
    assert len(await versions(db)) == count and len(t.chat.calls) == calls


async def notices(db):
    from jt_oz_bridge.services.transcript_publisher import LONG_CONTEXT_RENDERER

    batches = {
        b.id for b in await rows(db, DeliveryBatch) if b.renderer_version == LONG_CONTEXT_RENDERER
    }
    return [d for d in await rows(db, Delivery) if d.batch_id in batches]


async def test_a_short_conversation_gets_no_long_context_notice(db):
    from jt_oz_bridge.services.transcript_publisher import LONG_CONTEXT_AT

    t = await Turn().initialize(db)
    t.publisher.creates_here = lambda _binding: True
    await t.add(entry("in1", "Hello"), finished("r1", "Hi", context=LONG_CONTEXT_AT - 1))
    # A long tool step is not the reply; only the reply's own step counts.
    await t.add(
        entry("in2", "More"),
        finished("s1", "", context=LONG_CONTEXT_AT, tools=(tool("search", "s1_0"),)),
        finished("r2", "Short again", context=5000),
    )
    assert not await notices(db) and "Short again" in t.shown()[-1]


@pytest.mark.parametrize(
    ("locale", "size", "how"),
    [
        ("en", "about 95k tokens", "open a new topic, send `!new` and pick project project."),
        ("zh-TW", "約 9.5 萬 tokens", "開一個新話題送 `!new`，選專案 project。"),
    ],
)
async def test_a_long_conversation_gets_one_notice_after_the_reply_for_good(db, locale, size, how):
    from jt_oz_bridge.services.transcript_publisher import LONG_CONTEXT_PRIORITY

    t = await Turn().initialize(db, locale=locale)
    t.publisher.creates_here = lambda binding: binding.project_id == "project"
    actions = len(await rows(db, Action))
    await t.add(entry("in1", "Summarize the logs"), finished("r1", "Here it is", context=95000))
    (notice,) = await notices(db)
    assert notice.state == "delivered" and notice.payload.get("widget") is None
    text = html.unescape(notice.payload["content"])
    assert size in text and how in text and text.startswith("💡")
    # It follows the reply: shown after it and queued to wait for it.
    shown = t.shown()
    assert "Here it is" in shown[-2] and size in shown[-1]
    batch = next(b for b in await rows(db, DeliveryBatch) if b.id == notice.batch_id)
    reply = next(d for d in await rows(db, Delivery) if "Here it is" in d.payload["content"])
    assert batch.priority == LONG_CONTEXT_PRIORITY
    dependency = next(r for r in await rows(db, BatchDependency) if r.batch_id == batch.id)
    assert dependency.before_batch_id == reply.batch_id
    # Only a suggestion: nothing reached OpenCode and no conversation was made.
    assert len(await rows(db, Action)) == actions
    # A longer one next turn, a restart and a replay of every plan: still the one.
    await t.add(entry("in2", "And now?"), finished("r2", "Still here", context=123000))
    t.publisher = t.restart()
    t.publisher.creates_here = lambda _binding: True
    for version in await versions(db):
        await t.publisher.publish(version.id)
    await deliver(t.worker)
    await t.add(entry("in3", "Again"), finished("r3", "Yes", context=130000))
    assert len(await notices(db)) == 1
    # The notice shows once; each long reply's own footer only says the size.
    assert sum("💡" in text for text in t.shown()) == 1
    assert sum(size in text and "💡" in text for text in t.shown()) == 1


@pytest.mark.parametrize(
    ("locale", "words"),
    [
        ("en", "can't start new conversations from chat yet; an administrator"),
        ("zh-TW", "這個專案還不能從聊天開新對話，需要管理員先開放。"),
    ],
)
async def test_a_project_that_cannot_create_from_chat_is_told_so_without_a_command(
    db, locale, words
):
    t = await Turn().initialize(db, locale=locale)
    await t.add(entry("in1", "Hello"), finished("r1", "Hi", context=60000))
    (notice,) = await notices(db)
    text = html.unescape(notice.payload["content"])
    assert words in text and "!new" not in text and "!" not in text.split("💡")[1]


def test_long_context_sizes_read_naturally_in_each_language():
    from jt_oz_bridge.services.transcript_publisher import context_size

    assert context_size(95000, "zh-TW") == "9.5 萬"
    assert context_size(60000, "zh-TW") == "6 萬"
    assert context_size(123456, "zh-TW") == "12.3 萬"
    assert context_size(95000, "en") == "95k"
    assert context_size(123456, "en") == "123k"
    assert context_size(1_260_000, "en") == "1.3M"


def test_runtime_names_new_only_for_a_project_enrolled_for_creation():
    from types import SimpleNamespace

    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline

    scope = SimpleNamespace(backend_id="backend", backend_identity="enrolled-installation")
    project = SimpleNamespace(template=SimpleNamespace(scope=scope))
    runtime = SimpleNamespace(
        creation=SimpleNamespace(journal=SimpleNamespace(projects={"project": project}))
    )
    binding = SimpleNamespace(
        project_id="project", backend_id="backend", backend_identity="enrolled-installation"
    )
    assert ConsumerPipeline.creates_here(runtime, binding)
    assert not ConsumerPipeline.creates_here(
        runtime, SimpleNamespace(**{**vars(binding), "project_id": "other"})
    )
    assert not ConsumerPipeline.creates_here(
        runtime, SimpleNamespace(**{**vars(binding), "backend_identity": "elsewhere"})
    )
    assert not ConsumerPipeline.creates_here(SimpleNamespace(creation=None), binding)


async def test_steps_before_the_message_is_sent_wait_then_become_one_edit(db):
    t = await Turn().initialize(db)
    await t.add(step("s1", "bash"), send=False)
    # The next step waits for that post: no plan, and no other work is blocked.
    assert await t.add(step("s2", "read"), send=False) == [None]
    assert await t.publisher.next_pending() is None
    assert not [p for p in await rows(db, TranscriptPublication) if p.payload["mode"] == "progress"]
    await deliver(t.worker)
    await t.add(step("s3", "grep"), send=False)
    # s2's edit is still unsent: s3's plan replaces it with one carrying both lines.
    edits = [d for d in await t.deliveries() if d.payload["operation"] == "edit"]
    assert [d.state for d in edits] == ["cancelled", "pending"]
    await deliver(t.worker)
    assert len(t.sent("edit")) == 1
    assert t.progress() == [["*🔧 bash*", "*🔧 read*", "*🔧 grep*"]]


@pytest.mark.parametrize("failure", ["rejected", "ambiguous", "changed", "restart"])
async def test_an_edit_that_cannot_land_moves_its_lines_to_a_new_message(db, failure):
    t = await Turn().initialize(db)
    await t.add(step("s1", "bash"))
    (first,) = [i for i, message in t.chat.messages.items() if "🔧" in message.content]
    if failure == "rejected":

        async def refused(message_id, content):
            t.chat.calls.append(("edit", content))
            raise DeliveryRejected("edit time limit fixture")

        t.chat.edit = refused
        await t.add(step("s2", "read"))
        del t.chat.edit
    elif failure == "ambiguous":
        t.chat.mode = "timeout"  # The edit lands but its response is lost.
        await t.add(step("s2", "read"))
        t.chat.mode = "success"
    else:
        await t.add(step("s2", "read"), send=False)
        if failure == "changed":
            # Someone changed the message: delivery's GET refuses to edit it.
            t.chat.messages[first] = t.chat.messages[first].model_copy(update={"content": "x"})
            await deliver(t.worker)
        else:
            async with db.sessions.begin() as session:
                await session.execute(
                    update(Delivery)
                    .where(Delivery.state == "pending")
                    .values(state="held", status_reason="restart_unsent")
                )
    (edit,) = [d for d in await t.deliveries() if d.payload["operation"] == "edit"]
    assert edit.state == {"changed": "held", "restart": "held"}.get(failure, failure)
    await t.add(step("s3", "grep"))
    if failure == "restart":
        # Never sent: the next edit carries both lines, with no new message.
        assert t.progress() == [["*🔧 bash*", "*🔧 read*", "*🔧 grep*"]]
    elif failure == "ambiguous":
        # Unknown outcome (here it did land): its line shows again, never lost.
        assert t.progress() == [["*🔧 bash*", "*🔧 read*"], ["*🔧 read*", "*🔧 grep*"]]
    else:
        assert t.progress()[-1] == ["*🔧 read*", "*🔧 grep*"]
        assert len([text for text in t.shown() if "🔧" in text]) == 2 - (failure == "changed")
    states = {d.id: d.state for d in await t.deliveries()}
    # A replaced unsent edit can never be resumed into a duplicate later.
    assert states[edit.id] == {"changed": "cancelled", "restart": "cancelled"}.get(failure, failure)
    assert not {"pending", "sending"} & set(states.values())


async def test_a_long_or_old_progress_message_is_continued_in_a_new_one(db):
    t = await Turn().initialize(db, limit=512)
    names = [f"mcp.tool_number_{i:02d}_with_a_long_name" for i in range(12)]
    for i, name in enumerate(names):
        await t.add(step(f"s{i}", name))
    progress = t.progress()
    assert 1 < len(progress) < len(names)
    assert [line for message in progress for line in message] == [f"*🔧 {n}*" for n in names]
    assert all(len(message.content) <= 512 for message in t.chat.messages.values())
    await t.add(step("late1", "read"))
    count = len(t.progress())
    t.clock[0] += 600  # Past Zulip's default edit limit: a new message, not a refused edit.
    await t.add(step("late2", "grep"))
    assert t.progress()[-1] == ["*🔧 grep*"] and len(t.progress()) == count + 1


@pytest.mark.parametrize("tool", ["task", "subagent"])
async def test_a_subagent_call_is_named_as_one_on_the_phone(db, tool):
    t = await Turn().initialize(db)
    await t.add(step("s1", tool), step("s2", "read"))
    lines = [x for group in t.progress() for x in group]
    assert "*🔧 subagent*" in lines or "*🔧 子 agent*" in lines


def retrying(identity, attempt, error, *tools, completed=False):
    """A step OpenCode waits to run again after its model call failed with ``error``."""
    return project_message(
        {
            "id": identity,
            "type": "assistant",
            "agent": "build",
            "model": {"providerID": "fixture", "id": "model"},
            "time": {"created": 2, **({"completed": 3} if completed else {})},
            "content": list(tools),
            "retry": {"attempt": attempt, "at": 1.5e12, "error": error},
        }
    )


def failed_idle(identity, error):
    return project_message(
        {
            "id": identity,
            "type": "idle",
            "time": {"created": 4},
            "outcome": "failed",
            "error": error,
        }
    )


def failed_step(identity, text, error):
    return project_message(
        {
            "id": identity,
            "type": "assistant",
            "agent": "build",
            "model": {"providerID": "fixture", "id": "model"},
            "time": {"created": 2, "completed": 3},
            "content": [{"type": "text", "text": text}],
            "error": error,
        }
    )


def compaction(identity, status, *, reason="auto", error=None):
    raw = {
        "id": identity,
        "type": "compaction",
        "time": {"created": 3},
        "status": status,
        "reason": reason,
        "summary": "PRIVATE_SUMMARY",
        "recent": "",
    }
    if error is not None:
        raw["error"] = error
    return project_message(raw)


def before_error_summaries(entry):
    """``entry`` as Bridge saved it before error summaries were kept."""
    from jt_oz_bridge.adapters.opencode.transcript import TranscriptEntry
    from jt_oz_bridge.storage.durable import digest

    value = entry.projection()
    value.pop("error")
    return TranscriptEntry(
        native_id=entry.native_id,
        kind=entry.kind,
        projection_json=json.dumps(value),
        projection_sha256=digest(value),
    )


SECRET_ERROR = {
    "type": "APIError",
    "message": "PRIVATE_MESSAGE",
    "status": 429,
    "response": {"body": "PRIVATE_BODY"},
}


def test_only_an_error_type_and_status_enter_the_projection_and_only_when_reported():
    from jt_oz_bridge.adapters.opencode.transcript import error_summary

    failed = failed_idle("i1", SECRET_ERROR)
    assert failed.projection()["error"] == {"type": "APIError", "status": 429}
    assert "PRIVATE" not in failed.projection_json
    waiting = retrying("s1", 2, SECRET_ERROR)
    assert waiting.projection()["retry"] == {
        "attempt": 2,
        "error": {"type": "APIError", "status": 429},
    }
    assert "PRIVATE" not in waiting.projection_json and "1.5e" not in waiting.projection_json
    lost = compaction("c1", "failed", error={"type": "Overflow", "message": "PRIVATE"})
    assert lost.projection()["error"] == {"type": "Overflow"}
    assert "PRIVATE" not in lost.projection_json
    for bad in ({"type": "has space"}, {"type": "x" * 65}, {"type": 7}, {"type": "1abc"}):
        assert error_summary(bad) == {}
    for status in (99, 600, "429", True, 429.0):
        assert error_summary({"type": "E", "status": status}) == {"type": "E"}
    assert error_summary({"type": "Error\n"}) == {} and error_summary("text") == {}
    assert "retry" not in retrying("s1", 0, SECRET_ERROR).projection()
    # Every ordinary entry keeps exactly the projection (and hash) it had before.
    for ordinary in (
        assistant("r1", "Done"),
        idle("i2"),
        compaction("c2", "running"),
        compaction("c3", "completed"),
    ):
        assert not {"error", "retry"} & set(ordinary.projection())


def test_a_settled_entry_saved_before_error_summaries_is_the_same_message():
    from jt_oz_bridge.adapters.opencode.transcript import same_message

    for now in (
        failed_idle("i1", SECRET_ERROR),
        compaction("c1", "failed", error=SECRET_ERROR),
        failed_step("s1", "Partial", {"type": "APIError", "status": 500}),
    ):
        assert same_message(before_error_summaries(now), now)
    assert not same_message(failed_idle("i1", {"status": 500}), failed_idle("i1", {"status": 401}))
    # A retry is live: a running step that gains one, or its next attempt, is new.
    running = finished("s2", "", completed=False)
    assert not same_message(running, retrying("s2", 1, SECRET_ERROR))
    assert not same_message(retrying("s2", 1, SECRET_ERROR), retrying("s2", 2, SECRET_ERROR))


async def test_a_failed_outcome_read_again_with_its_error_is_not_posted_again(db):
    t = await Turn().initialize(db)
    now = failed_idle("i1", SECRET_ERROR)
    await t.add(entry("in1", "Hello"), before_error_summaries(now))
    count, calls = len(await versions(db)), len(t.chat.calls)
    assert "Run failed." in t.shown()[-1]
    # As after an upgrade: the same outcome, now read with its error summary.
    index = next(i for i, m in enumerate(t.reader.messages) if m.native_id == "i1")
    t.reader.messages[index] = now
    await t.add()
    assert len(await versions(db)) == count and len(t.chat.calls) == calls


@pytest.mark.parametrize(
    ("locale", "error", "text"),
    [
        ("en", SECRET_ERROR, "Result\n\nRun failed: too many requests; the model service is"),
        ("zh-TW", {"status": 401}, "執行結果\n\n執行失敗：模型服務驗證或權限失敗。"),
        ("en", {"type": "ContextOverflowError"}, "Result\n\nRun failed: the conversation is"),
        ("zh-TW", {"type": "ProviderError"}, "執行結果\n\n執行失敗：錯誤類型：`ProviderError`。"),
        ("en", {"message": "PRIVATE"}, "Result\n\nRun failed: unknown error."),
    ],
)
async def test_a_failed_outcome_says_why_without_the_error_message(db, locale, error, text):
    t = await Turn().initialize(db, locale=locale)
    await t.add(entry("in1", "Hello"), failed_idle("i1", error))
    shown = t.shown()[-1]
    assert shown.startswith(text) and "PRIVATE" not in shown


@pytest.mark.parametrize(
    ("locale", "running", "done"),
    [
        (
            "en",
            "🗜️ The conversation is long; OpenCode is compacting it",
            "🗜️ Conversation compacted",
        ),
        ("zh-TW", "🗜️ 對話太長，OpenCode 正在自動壓縮", "🗜️ 對話已壓縮"),
    ],
)
async def test_a_compaction_says_so_in_its_own_words_not_as_a_setting(db, locale, running, done):
    t = await Turn().initialize(db, locale=locale)
    await t.add(compaction("c1", "running"))
    await ended(t, compaction("c1", "completed"))
    first, second = t.shown()[-2:]
    assert first.startswith(running) and second.startswith(done)
    assert not any(word in first + second for word in ("Setting changed", "設定變更", "PRIVATE"))


async def ended(t, now):
    """The same Native entry read again once OpenCode changed it."""
    index = next(i for i, m in enumerate(t.reader.messages) if m.native_id == now.native_id)
    t.reader.messages[index] = now
    await t.add()


async def test_a_manual_or_failed_compaction_is_said_plainly(db):
    t = await Turn().initialize(db, locale="zh-TW")
    await t.add(compaction("c1", "running", reason="manual"))
    await ended(t, compaction("c1", "failed", reason="manual", error={"status": 504}))
    first, second = t.shown()[-2:]
    assert first.startswith("🗜️ OpenCode 正在壓縮對話")
    assert second.startswith("🗜️ 壓縮失敗：逾時")


async def test_a_shell_entry_keeps_its_control_wording(db):
    t = await Turn().initialize(db)
    await t.add(
        project_message(
            {
                "id": "sh1",
                "type": "shell",
                "time": {"created": 3},
                "shellID": "x",
                "command": "PRIVATE_COMMAND",
                "status": "running",
            }
        )
    )
    assert t.shown()[-1].startswith("Setting changed\n\nStatus: running.")
    assert "PRIVATE" not in t.shown()[-1]


def changed(identity, *paths, text="", tools=(), context=None, completed=True, snapshot=None):
    """A step whose snapshot says it changed ``paths``; tool steps when ``tools``."""
    raw = {
        "id": identity,
        "type": "assistant",
        "agent": "build",
        "model": {"providerID": "fixture", "id": "model"},
        "time": {"created": 2, **({"completed": 3} if completed else {})},
        "content": [{"type": "text", "text": text}, *tools],
        "snapshot": {"start": "snap0", "end": "snap1", "files": list(paths)}
        if snapshot is None
        else snapshot,
    }
    if context is not None:
        raw["tokens"] = {
            "input": 1000,
            "output": 50,
            "reasoning": 0,
            "cache": {"read": context - 1200, "write": 200},
        }
    return project_message(raw)


def edited(identity, *paths):
    """A tool step that edited ``paths``."""
    return changed(identity, *paths, tools=(tool("edit", f"{identity}_0"),))


def before_changed_files(entry):
    """``entry`` as Bridge saved it before changed files were kept."""
    from jt_oz_bridge.adapters.opencode.transcript import TranscriptEntry
    from jt_oz_bridge.storage.durable import digest

    value = entry.projection()
    value.pop("files")
    value.pop("files_total", None)
    return TranscriptEntry(
        native_id=entry.native_id,
        kind=entry.kind,
        projection_json=json.dumps(value),
        projection_sha256=digest(value),
    )


def test_changed_files_enter_the_projection_as_bounded_relative_paths_only():
    from jt_oz_bridge.adapters.opencode.transcript import FILE_PATH_LIMIT, FILES_LIMIT

    step = changed(
        "s1",
        "src/a.py",
        "/etc/passwd",
        "../outside.txt",
        "src/../../x",
        "dir\\win.txt",
        "bad\nname",
        "",
        "x" * (FILE_PATH_LIMIT + 1),
        "src/a.py",
        7,
        "docs/b.md",
    )
    assert step.projection()["files"] == ["src/a.py", "docs/b.md"]
    assert "files_total" not in step.projection()
    assert step.changed_files() == (("src/a.py", "docs/b.md"), 2)
    assert "snap" not in step.projection_json and "passwd" not in step.projection_json
    many = changed("s2", *(f"f{i}.py" for i in range(FILES_LIMIT + 30)))
    assert len(many.projection()["files"]) == FILES_LIMIT
    assert many.changed_files()[1] == FILES_LIMIT + 30
    # A running step, no snapshot, no files or none kept: no field, the same hash.
    assert "files" not in changed("s3", "a.py", completed=False).projection()
    for snapshot in ({}, {"files": []}, {"files": "a.py"}, "x", {"files": ["/abs"]}):
        quiet = changed("s4", snapshot=snapshot)
        assert "files" not in quiet.projection()
        assert quiet.projection_sha256 == assistant("s4", "").projection_sha256
    assert assistant("r1", "Done").changed_files() == ((), 0)


def test_a_finished_step_saved_before_changed_files_is_the_same_message():
    from jt_oz_bridge.adapters.opencode.transcript import same_message

    for now in (
        changed("s1", "a.py", "b.py", text="Done", context=95000),
        edited("s2", *(f"f{i}.py" for i in range(80))),
    ):
        assert same_message(before_changed_files(now), now)
    # Saved before both error summaries and changed files were kept.
    both = project_message(
        {
            "id": "s4",
            "type": "assistant",
            "agent": "build",
            "model": {"providerID": "fixture", "id": "model"},
            "time": {"created": 2, "completed": 3},
            "content": [{"type": "text", "text": "x"}],
            "error": {"status": 500},
            "snapshot": {"files": ["a.py"]},
        }
    )
    assert same_message(before_error_summaries(before_changed_files(both)), both)
    # Files are content once kept: other files, or a running step finishing with them.
    assert not same_message(changed("s5", "a.py", text="x"), changed("s5", "b.py", text="x"))
    assert not same_message(
        changed("s6", text="x", completed=False, snapshot={}), changed("s6", "a.py", text="x")
    )


async def test_a_step_read_again_with_its_changed_files_is_not_posted_again(db):
    t = await Turn().initialize(db)
    now = edited("s1", "a.py", "b.py")
    await t.add(entry("in1", "Fix it"), before_changed_files(now), assistant("r1", "Fixed"))
    count, calls = len(await versions(db)), len(t.chat.calls)
    assert "Changed" not in t.shown()[-1]
    # As after an upgrade: the same finished step, now read with its changed files.
    index = next(i for i, m in enumerate(t.reader.messages) if m.native_id == "s1")
    t.reader.messages[index] = now
    await t.add()
    assert len(await versions(db)) == count and len(t.chat.calls) == calls


@pytest.mark.parametrize(
    ("locale", "line"),
    [
        ("en", "Changed 3 files: `a.py`, `src/b.py`, `docs/c.md`"),
        ("zh-TW", "改了 3 個檔案：`a.py`、`src/b.py`、`docs/c.md`"),
    ],
)
async def test_a_turns_reply_names_the_files_its_steps_changed(db, locale, line):
    t = await Turn().initialize(db, locale=locale)
    await t.add(entry("in1", "Fix the bug"), edited("s1", "a.py", "src/b.py"))
    # A finished step with no words or tools (reasoning only) shows nothing and ends nothing.
    await t.add(edited("s2", "src/b.py"), assistant("e1", ""))
    await t.add(changed("r1", "docs/c.md", text="Fixed it"))
    reply = t.shown()[-1]
    assert reply.startswith("Fixed it") and line in reply
    assert "!diff" not in reply and "snap" not in reply
    # Only the reply says it: the progress message keeps its tool lines.
    assert t.progress() == [["*🔧 edit* ×2"]]
    # The next turn names only its own files, and one that changed none says nothing.
    await t.add(idle("i1"), entry("in2", "And this"), step("s3", "read"))
    await t.add(assistant("r2", "Done too"))
    assert "Changed" not in t.shown()[-1] and "改了" not in t.shown()[-1]
    await t.add(idle("i2"), entry("in3", "Once more"), edited("s4", "y.py"))
    await t.add(assistant("r3", "Third"))
    third = t.shown()[-1]
    assert "`y.py`" in third and "a.py" not in third and "c.md" not in third


@pytest.mark.parametrize(
    ("locale", "line"),
    [
        (
            "en",
            "Changed 9 files: `f0.py`, `f1.py`, `f2.py`, `f3.py`, `f4.py` … and 4 more"
            " (`!diff` shows the changes)",
        ),
        (
            "zh-TW",
            "改了 9 個檔案：`f0.py`、`f1.py`、`f2.py`、`f3.py`、`f4.py`…等另外 4 個（`!diff` 看差異）",
        ),
    ],
)
async def test_many_changed_files_show_five_names_and_diff_where_it_works(db, locale, line):
    t = await Turn().initialize(db, locale=locale)
    t.publisher.diff_here = lambda binding: binding.id == t.binding.id
    # A secret's name is counted but never shown.
    await t.add(entry("in1", "Refactor"), edited("s1", ".env", *(f"f{i}.py" for i in range(8))))
    await t.add(assistant("r1", "Refactored"))
    reply = t.shown()[-1]
    assert line in reply and ".env" not in reply


async def test_only_hidden_files_are_counted_without_names(db):
    t = await Turn().initialize(db)
    await t.add(entry("in1", "Rotate"), edited("s1", ".env"), assistant("r1", "Rotated"))
    reply = t.shown()[-1]
    assert "Changed 1 file" in reply and "Changed 1 file:" not in reply and ".env" not in reply


@pytest.mark.parametrize(
    ("locale", "line"),
    [("en", "Context: about 95k tokens"), ("zh-TW", "對話已用約 95k token")],
)
async def test_a_long_conversations_reply_says_its_context_size(db, locale, line):
    from jt_oz_bridge.services.transcript_publisher import LONG_CONTEXT_AT

    t = await Turn().initialize(db, locale=locale)
    await t.add(entry("in1", "Hello"), finished("r1", "Hi", context=LONG_CONTEXT_AT - 1))
    assert "token" not in t.shown()[-1].lower()
    await t.add(entry("in2", "More"), changed("r2", "a.py", text="Done", context=95_400))
    reply = next(text for text in t.shown() if text.startswith("Done"))
    # The files line first, then the context line, at the end of the reply.
    files = "Changed 1 file: `a.py`" if locale == "en" else "改了 1 個檔案：`a.py`"
    assert reply.index(files) < reply.index(line)
    # Every later long reply says it again; the one-time notice stays one.
    await t.add(entry("in3", "Again"), finished("r3", "Still", context=123_456))
    later = next(text for text in t.shown() if text.startswith("Still"))
    assert line.replace("95k", "123k") in later
    assert len(await notices(db)) == 1


@pytest.mark.parametrize(
    ("locale", "failed", "error"),
    [
        ("en", "*🔧 bash (exit 1)*", " (error) (exit 2)"),
        ("zh-TW", "*🔧 bash（結束碼 1）*", " (錯誤)（結束碼 2）"),
    ],
)
async def test_a_command_that_failed_says_its_exit_code(db, locale, failed, error):
    def run(identity, code, status="completed"):
        state = {"status": status, "metadata": {"exit": code}}
        if status == "error":
            state["error"] = {"type": "ToolError", "message": "PRIVATE"}
        return {
            "type": "tool",
            "id": identity,
            "name": "bash",
            "time": {"created": 2},
            "state": state,
        }

    t = await Turn().initialize(db, locale=locale)
    await t.add(entry("in1", "Build"), assistant("s1", "", tools=(run("c1", 1),)))
    await t.add(entry("in2", "Again"), assistant("s2", "", tools=(run("c2", 0), tool("read"))))
    await t.add(entry("in3", "Once more"), assistant("s3", "", tools=(run("c3", 2, "error"),)))
    assert t.progress() == [[failed], ["*🔧 bash, read*"], [f"*🔧 bash{error}*"]]
    assert not any("PRIVATE" in text for text in t.shown())


def test_runtime_names_diff_only_where_file_menus_show_it():
    from types import SimpleNamespace

    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline

    asked = []
    menus = SimpleNamespace(available=lambda binding, command: asked.append(command) or True)
    assert ConsumerPipeline.diff_here(SimpleNamespace(file_menus=menus), object())
    assert asked == ["diff"]
    refused = SimpleNamespace(available=lambda binding, command: False)
    assert not ConsumerPipeline.diff_here(SimpleNamespace(file_menus=refused), object())
    assert not ConsumerPipeline.diff_here(SimpleNamespace(file_menus=None), object())
