"""Seven real consumer loops over synthetic servers, including original-origin work."""

import asyncio
from dataclasses import replace

import pytest
import pytest_asyncio

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action
from tests.integration.test_consumer_runtime import (
    post_containing,
    rows,
    until,
    visible,
)
from tests.integration.test_consumer_runtime import (
    setup as pipeline_setup,
)
from tests.integration.test_transcript_collector import entry
from tests.integration.test_transcript_commands import OriginalReader
from tests.integration.test_transcript_publisher import assistant
from tests.support import REF


@pytest_asyncio.fixture(autouse=True)
async def bounded_runtime_diagnostics():
    """Observe a rare full-suite stall without cancelling workers or their receipts.

    No locals, HTTP bodies or exception payloads are printed. A normal case
    completes before the timer. Six snapshots bound a stalled case's log.
    """
    loop = asyncio.get_running_loop()
    remaining = 6
    handle = None

    def dump():
        nonlocal remaining, handle
        remaining -= 1
        print("runtime_test_pending_tasks", flush=True)
        for task in sorted(asyncio.all_tasks(loop), key=lambda task: task.get_name()):
            print("runtime_task", task.get_name(), "cancelling", task.cancelling(), flush=True)
            coro, seen = task.get_coro(), set()
            while coro is not None and id(coro) not in seen:
                seen.add(id(coro))
                frame = (
                    getattr(coro, "cr_frame", None)
                    or getattr(coro, "gi_frame", None)
                    or getattr(coro, "ag_frame", None)
                )
                if frame is not None:
                    print(
                        "runtime_await",
                        frame.f_code.co_filename,
                        frame.f_code.co_name,
                        frame.f_lineno,
                        flush=True,
                    )
                coro = (
                    getattr(coro, "cr_await", None)
                    or getattr(coro, "gi_yieldfrom", None)
                    or getattr(coro, "ag_await", None)
                )
        if remaining:
            handle = loop.call_later(10, dump)

    # The shared result waiter expires after eight seconds. Observe a slow
    # case before that deadline; do not extend it or cancel any worker.
    handle = loop.call_later(6, dump)
    try:
        yield
    finally:
        handle.cancel()


async def setup(db, *, drafts=False):
    previous, server, native, results, binding, pulse = await pipeline_setup(db)
    reader = OriginalReader()
    reader.contract_hash = INSTALLED_SCHEMA
    backend = replace(previous.backends[REF.backend_id], transcripts={REF: reader})
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
        mirror_enabled=True,
        drafts_enabled=drafts,
        draft_interval=0.02,
    )
    return pipeline, server, native, results, binding, reader


async def test_original_computer_work_is_automatically_delivered_without_human_action(db):
    pipeline, server, native, results, binding, reader = await setup(db)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        await post_containing(server, "history")
        start = len(server.posts)
        reader.messages[:0] = [
            project_message(
                {"id": "terminal", "type": "idle", "time": {"created": 4}, "outcome": "succeeded"}
            ),
            assistant(text="Result from original computer"),
            entry("computer_input", "Computer side instruction"),
        ]
        await post_containing(server, "Result from original computer", start=start)
        bodies = [visible(m["content"]) for m in server.posts[start:]]
        assert len(bodies) == 2  # A succeeded run has no separate terminal message.
        assert "Computer side instruction" in bodies[0]
        assert "Result from original computer" in bodies[1]
        assert all(m["subject"] == binding.topic for m in server.posts)
        assert not await rows(db, Action) and not native.submitted and results.calls == 0
        await asyncio.sleep(0.1)
        assert len(server.posts) == start + 2 and runtime.healthy
    finally:
        await runtime.close()


async def test_phone_admission_result_collection_and_native_mirror_do_not_duplicate_replies(db):
    pipeline, server, native, results, binding, reader = await setup(db)
    mirrored = False

    async def include_admitted_input():
        nonlocal mirrored
        actions = await rows(db, Action)
        if not mirrored and actions and actions[0].upstream_id:
            action = actions[0]
            reader.messages[:0] = [
                project_message(
                    {
                        "id": "terminal",
                        "type": "idle",
                        "time": {"created": 4},
                        "outcome": "succeeded",
                    }
                ),
                assistant(text="One mirrored Native answer"),
                entry(action.upstream_id, action.payload["text"]),
            ]
            mirrored = True

    reader.hook = include_admitted_input
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        await post_containing(server, "history")
        start = len(server.posts)
        server.input("Phone instruction in the same original Root")
        await post_containing(server, "One mirrored Native answer", start=start)

        async def completed():
            actions = await rows(db, Action)
            return actions and actions[0].state == "completed"

        await until(completed)
        await asyncio.sleep(0.1)
        bodies = [visible(m["content"]) for m in server.posts[start:]]
        assert sum("One mirrored Native answer" in text for text in bodies) == 1
        assert all("succeeded" not in text for text in bodies)
        assert all("PRIVATE_NATIVE_FINAL_RESULT" not in text for text in bodies)
        assert all("Original computer input" not in text for text in bodies)
        assert sum("Phone instruction in the same original Root" in text for text in bodies) == 0
        assert len(native.submitted) == len(await rows(db, Action)) == 1
        assert results.calls >= 1 and runtime.healthy
    finally:
        await runtime.close()


async def test_schedule_token_only_skips_reads_and_changed_source_still_checks_private_acl(db):
    pipeline, server, native, _, binding, reader = await setup(db)
    token = "initial-token"
    reader.change_token = lambda ref: token
    await pipeline.mirror_once()
    assert len(reader.calls) == 1
    await pipeline.mirror_once()
    assert len(reader.calls) == 1
    token = "structural-change"
    await pipeline.mirror_once()
    assert len(reader.calls) == 2
    key = (binding.id, binding.revision)
    prior = pipeline._mirror_seen[key]
    pipeline._mirror_seen[key] = (prior[0], prior[1] - 31, prior[2])
    await pipeline.mirror_once()
    assert len(reader.calls) == 3 and not native.submitted
    server.private = False
    token = "private-scope-change"
    await pipeline.mirror_once()
    assert len(reader.calls) == 3


async def test_gap_resume_guard_cannot_bypass_review_or_dispatch_prompt(db):
    pipeline, server, native, _, binding, reader = await setup(db)
    await pipeline.mirror_once()
    reader.messages = [entry("after_revert")]
    await pipeline.mirror_once()
    with pytest.raises(Conflict, match="review_and_rebind"):
        await pipeline.router.resume_guard(binding)
    await pipeline.consumer.start()
    server.input("Do not send through unresolved continuity")
    await pipeline.consumer.poll()
    await pipeline.dispatch_once()
    assert not native.submitted


async def test_original_partial_text_is_a_single_updated_draft_and_final_posts_remain_distinct(db):
    from jt_oz_bridge.domain.control import ExecutionState
    from jt_oz_bridge.storage.transcript_models import TranscriptDraft

    pipeline, server, native, _, binding, reader = await setup(db, drafts=True)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        await post_containing(server, "history")
        reader.messages[:0] = [
            assistant(text="Initial streaming text", completed=False),
            entry("original_live_input", "Computer work"),
        ]
        draft = await post_containing(server, "not finished")
        draft_id = draft["id"]
        reader.messages[0] = assistant(
            text="Initial streaming text plus a second chunk", completed=False
        )

        async def edited():
            return next(
                (
                    message
                    for message in server.edits
                    if "second chunk" in visible(message["content"])
                ),
                None,
            )

        edit = await until(edited)
        assert edit["id"] == draft_id
        reader.messages[0] = assistant(text="Complete original final reply")
        reader.messages.insert(
            0,
            project_message(
                {"id": "final_idle", "type": "idle", "time": {"created": 4}, "outcome": "succeeded"}
            ),
        )
        reader.state = ExecutionState.IDLE
        await post_containing(server, "Complete original final reply")

        async def finalized():
            frames = await rows(db, TranscriptDraft)
            return (
                frames
                and frames[0].finalized
                and "succeeded" in visible(server.messages[draft_id]["content"])
            )

        await until(finalized)
        assert (
            len(
                [
                    message
                    for message in server.posts
                    if "not finished" in visible(message["content"])
                ]
            )
            == 1
        )
        assert all(message["id"] == draft_id for message in server.edits)
        assert not await rows(db, Action) and not native.submitted and runtime.healthy
    finally:
        await runtime.close()


async def test_real_seven_loop_graph_projects_separate_captures_with_a_constant_api_header_hint(db):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from jt_oz_bridge.adapters.opencode.live import VolatileFeedIndex
    from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture
    from jt_oz_bridge.domain.control import ExecutionState
    from jt_oz_bridge.services.live_capture import LiveEventJournal, LiveTextCollector
    from jt_oz_bridge.storage.transcript_models import TranscriptDraft
    from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, frame
    from tests.contract.test_visible_text_capture import event

    previous, server, native, _, binding, reader = await setup(db, drafts=True)
    index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    index.accept(frame(CONNECTED))
    capture = VisibleTextCapture(index)
    reader.owner_epoch, reader.connection_epoch = OWNER, index.require_live()
    hint = "initial"
    reader.draft_change_token = lambda ref: hint
    reader.change_token = lambda ref: hint
    feed = SimpleNamespace(
        current_owner=AsyncMock(), visible_text=capture, check_contract=lambda: None
    )
    source = LiveTextCollector(db, previous.fence, feed)
    journal = LiveEventJournal(db, previous.fence)
    original = previous.backends[REF.backend_id]

    async def pulse():
        await original.pulse()
        await source.collect()
        while index.pop() is not None:
            pass

    backend = replace(original, pulse=pulse, live_text={REF: source})
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
        mirror_enabled=True,
        drafts_enabled=True,
        draft_interval=0.02,
    )

    async def emit(n, text):
        raw = event(n, text=text, assistant="native_reply")
        raw["data"]["sessionID"] = REF.upstream_session_id
        raw["location"] = {"directory": REF.canonical_directory}
        (item,) = await index.accept_receipted((frame(raw),), journal)
        capture.observe(item)

    runtime = pipeline.runtime()
    await runtime.start()
    try:
        await post_containing(server, "history")
        reader.messages[:0] = [
            assistant(text="", completed=False),
            entry("native_input", "Computer stream source"),
        ]
        hint = "real-header-observed"
        await post_containing(server, "Computer stream source")
        await emit(1, "Live text from the separate source")
        preview = await post_containing(server, "Live text from the separate source")
        assert reader.messages[0].projection()["content"][0]["text"] == ""
        await emit(2, " with another fragment")

        async def updated():
            return next(
                (m for m in server.edits if "another fragment" in visible(m["content"])), None
            )

        edit = await until(updated)
        assert edit["id"] == preview["id"]
        reader.messages[0] = assistant(text="Authoritative original final reply")
        reader.messages.insert(
            0,
            project_message(
                {"id": "final_idle", "type": "idle", "time": {"created": 4}, "outcome": "succeeded"}
            ),
        )
        reader.state = ExecutionState.IDLE
        hint = "real-terminal-observed"
        await post_containing(server, "Authoritative original final reply")

        async def closed():
            frames = await rows(db, TranscriptDraft)
            return (
                frames
                and frames[0].finalized
                and "succeeded" in visible(server.messages[preview["id"]]["content"])
            )

        await until(closed)
        assert all(m["id"] == preview["id"] for m in server.edits)
        assert len(server.posts) == 4 and len(server.edits) >= 2
        assert not await rows(db, Action) and not native.submitted and runtime.healthy
    finally:
        await runtime.close()


async def test_text_hint_wakes_draft_collection_and_published_data_wakes_the_output_loop(db):
    pipeline, server, native, _, binding, reader = await setup(db, drafts=True)
    text_token = "text0"
    reader.change_token = lambda ref: "same-structural-hint"
    reader.draft_change_token = lambda ref: text_token
    await pipeline.mirror_once()
    assert len(reader.calls) == 1 and pipeline._publication_wake.is_set()
    pipeline._publication_wake.clear()
    await pipeline.mirror_once()
    assert len(reader.calls) == 1 and not pipeline._publication_wake.is_set()
    reader.messages.insert(0, assistant(text="Original text chunk", completed=False))
    text_token = "text1"
    await pipeline.mirror_once()
    assert len(reader.calls) == 2 and pipeline._publication_wake.is_set()
    assert not native.submitted


async def test_text_without_a_draft_hint_is_polled_instead_of_using_state_only_cache(db):
    pipeline, _, _, _, _, reader = await setup(db, drafts=True)
    reader.change_token = lambda ref: "never-changes-on-text"
    await pipeline.mirror_once()
    await pipeline.mirror_once()
    assert len(reader.calls) == 2


async def test_events_during_pagination_trigger_a_fresh_head_scan_after_the_scan_closes(db):
    pipeline, _, _, _, binding, reader = await setup(db)
    token = "initial"
    reader.change_token = lambda ref: token
    await pipeline.mirror_once()
    reader.messages = [entry("new_" + str(i)) for i in range(38)] + reader.messages
    token = "burst"
    await pipeline.mirror_once()
    assert (await pipeline.mirrors.load(binding))[0].status == "scanning"
    token = "event-during-continuation"
    await pipeline.mirror_once()
    assert (await pipeline.mirrors.load(binding))[0].status == "live"
    assert len(reader.calls) == 3
    await pipeline.mirror_once()
    assert len(reader.calls) == 4


async def test_original_state_intake_keeps_final_headroom_when_preview_background_is_deferred(db):
    import time

    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget
    from jt_oz_bridge.storage.transcript_models import TranscriptStream

    pipeline, _, native, _, _, _ = await setup(db)
    budget = ZulipRequestBudget(requests=80, reserved=64)
    pipeline.scope.client.budget = budget
    for _ in range(16):
        budget.acquire()
    pipeline._background_retry_at = time.monotonic() + 60
    try:
        await pipeline.mirror_once()
        streams = await rows(db, TranscriptStream)
        assert len(streams) == 1 and streams[0].payload["status"] == "live"
        assert budget.retained_requests > 16 and budget.deferred == 0
        assert not native.submitted and not await rows(db, Action)
        with pytest.raises(RequestBudgetDeferred):
            budget.acquire()  # The protected lane did not leak back into the caller.
    finally:
        await pipeline.scope.client.close()
