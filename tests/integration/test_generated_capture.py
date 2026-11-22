"""Synthetic original Human/Native, actual fenced encrypted DB and dispatch/journal."""

import re
import time
from dataclasses import replace

import pytest
from sqlalchemy import text, update

from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.services.generated_capture_commands import GeneratedCaptureCommands
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.resource_execution_results import ResourceResultCollector
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob, GeneratedOutputRecord
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_file_returns import all_rows
from tests.integration.test_generated_file_returns import GeneratedReader, journal, setup
from tests.integration.test_resource_execution_results import Reader
from tests.integration.test_router import message
from tests.support import REF


async def second(v, identity=102):
    source = message("Next original task", identity)
    v.source.messages[identity] = source
    queued = await QueueService(v.store.bindings).receive(v.binding.id, source)
    return queued.action_id


async def command(v, body, identity=201, *, capture=True, actor=7):
    source = message("!oz outputs " + body, identity, author_id=actor)
    v.source.messages[identity] = source
    controls = GeneratedCaptureCommands(
        v.store.bindings,
        v.source,
        TokenService(v.store.db, fence=v.store.fence),
        v.capture if capture else None,
    )
    return controls, source


async def held(v):
    assert await v.capture.advance(v.action_id) == "pending"
    v.reader.body = b"different structured output"
    assert await v.capture.advance(v.action_id) == "held"


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("enabled", [False, True])
async def test_empty_status_distinguishes_capture_disabled_from_enrolled_without_jobs(
    db, tmp_path, locale, enabled
):
    async with setup(db, tmp_path) as v:
        if enabled:
            v.capture = GeneratedCaptureService(v.service)
        controls, source = await command(v, "status", capture=enabled)
        reply = await controls.execute(v.binding, source, locale, "status")
        key = "generated.capability_enabled" if enabled else "generated.capability_disabled"
        assert controls.tr.render(key, locale) in reply
        assert controls.tr.render("generated.none", locale) in reply
        assert not await all_rows(db, GeneratedCaptureJob)
        assert not v.reader.calls and not v.remote.posts


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_same_project_other_original_session_is_explicitly_not_enrolled(db, tmp_path, locale):
    async with setup(db, tmp_path, automatic=True) as v:
        other = REF.model_copy(update={"upstream_session_id": "other-original-session"})
        binding = await v.store.bindings.bind("realm", 7, 10, "Other work", other)
        source = message("!oz outputs status", 202, topic="Other work")
        v.source.messages[202] = source
        controls = GeneratedCaptureCommands(
            v.store.bindings, v.source, TokenService(v.store.db, fence=v.store.fence), v.capture
        )
        reply = await controls.execute(binding, source, locale, "status")
        assert controls.tr.render("generated.capability_not_enrolled", locale) in reply
        assert controls.tr.render("generated.capability_enabled", locale) not in reply
        assert controls.tr.render("generated.none", locale) in reply
        assert len(await all_rows(db, GeneratedCaptureJob)) == 1
        assert not v.reader.calls and not v.remote.posts


@pytest.mark.parametrize("state", ["pending", "held"])
async def test_scope_disabled_keeps_old_job_visible_and_native_write_barrier_until_ack(
    db, tmp_path, state
):
    async with setup(db, tmp_path, automatic=True) as v:
        if state == "held":
            await held(v)
        before = (await all_rows(db, GeneratedCaptureJob))[0]
        controls, source = await command(v, "status", capture=False)
        reply = await controls.execute(v.binding, source, "en", "status")
        assert controls.tr.render("generated.capability_disabled", "en") in reply
        assert v.action_id in reply and state in reply
        after = (await all_rows(db, GeneratedCaptureJob))[0]
        assert (after.version, after.state, after.payload_hash) == (
            before.version,
            state,
            before.payload_hash,
        )
        successor = Dispatcher(
            v.store.bindings, v.execution, v.source, v.store.fence.holder, v.store.fence.fencing
        )
        assert await successor.advance(await second(v)) == "queued"
        assert len(v.execution.submitted) == 1 and not v.remote.posts


@pytest.mark.parametrize("state", ["pending", "held"])
async def test_removed_root_keeps_old_job_and_barrier_until_original_authorized_loss_ack(
    db, tmp_path, state
):
    async with setup(db, tmp_path, automatic=True) as v:
        if state == "held":
            await held(v)
        before = (await all_rows(db, GeneratedCaptureJob))[0]
        other = REF.model_copy(update={"upstream_session_id": "other-original-session"})
        selected = GeneratedReader(None, b"other original bytes", "inline", reference=other)
        # A fresh service models an operator-reviewed scope change. The old
        # encrypted job remains in the actual DB while only another Root is selected.
        service = GeneratedFileReturnJournal(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {},
            generated_readers={other: selected},
            message_limit=10000,
            topic_limit=60,
        )
        v.capture = GeneratedCaptureService(service)
        reads = (v.reader.calls, v.reader.reads)
        controls, source = await command(v, "status")
        reply = await controls.execute(v.binding, source, "en", "status")
        assert controls.tr.render("generated.capability_not_enrolled", "en") in reply
        assert v.action_id in reply and state in reply
        after = (await all_rows(db, GeneratedCaptureJob))[0]
        assert (after.version, after.payload_hash, after.state) == (
            before.version,
            before.payload_hash,
            before.state,
        )
        successor = Dispatcher(
            v.store.bindings, v.execution, v.source, v.store.fence.holder, v.store.fence.fencing
        )
        next_action = await second(v)
        assert await successor.advance(next_action) == "queued"
        assert await v.capture.advance(v.action_id) == "held"
        controls, source = await command(v, "skip " + v.action_id, 202)
        reply = await controls.execute(v.binding, source, "en", "skip " + v.action_id)
        token = re.search(r"outputs confirm ([A-Za-z0-9_-]+)", reply).group(1)
        controls, source = await command(v, "confirm " + token, 203, actor=8)
        with pytest.raises(ValueError):
            await controls.execute(v.binding, source, "en", "confirm " + token)
        assert await successor.advance(next_action) == "queued"
        controls, source = await command(v, "confirm " + token, 204)
        assert "dropped" in await controls.execute(v.binding, source, "en", "confirm " + token)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "skipped"
        assert await successor.advance(next_action) == "admitted"
        assert (v.reader.calls, v.reader.reads) == reads
        assert selected.calls == selected.reads == v.remote.posts == 0


async def test_actual_unselected_completion_has_no_capture_job_but_selected_completion_reserves(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        capture = GeneratedCaptureService(v.service)
        other = REF.model_copy(update={"upstream_session_id": "other-original-session"})
        other_binding = await v.store.bindings.bind("realm", 7, 10, "Other work", other)
        collector = ResourceResultCollector(
            v.store.bindings, Reader(), v.store.fence, capture=capture
        )
        for identity, binding, selected in ((103, other_binding, False), (104, v.binding, True)):
            source = message("Original task", identity, topic=binding.topic)
            v.source.messages[identity] = source
            queued = await QueueService(v.store.bindings).receive(binding.id, source)
            assert await v.dispatcher.advance(queued.action_id) == "admitted"
            result = await collector.collect(queued.action_id, "realm")
            assert result.outcome == "completed"
            assert result.reference == (REF if selected else other)
            jobs = await all_rows(db, GeneratedCaptureJob)
            assert len(jobs) == int(selected)
            if selected:
                assert jobs[0].action_id == queued.action_id and jobs[0].state == "pending"
            assert not v.reader.calls and not v.reader.reads and not v.remote.posts


@pytest.mark.parametrize("kind", ["workspace", "inline"])
async def test_result_and_job_commit_together_and_next_native_write_waits_for_exact_files(
    db, tmp_path, kind
):
    async with setup(db, tmp_path, kind=kind, automatic=True) as v:
        job = (await all_rows(db, GeneratedCaptureJob))[0]
        assert job.state == "pending" and job.action_id == v.action_id
        assert not await all_rows(db, Artifact)
        next_action = await second(v)
        assert (
            await v.dispatcher.advance(next_action) == "queued" and len(v.execution.submitted) == 1
        )
        assert await v.service.next_pending() is None
        assert await v.capture.advance(v.action_id) == "pending"
        assert await v.dispatcher.advance(next_action) == "queued"
        assert await v.capture.advance(v.action_id) == "frozen"
        transfer = (await all_rows(db, FileTransfer))[0]
        assert await v.service.next_pending() == transfer.id and v.remote.posts == 0
        assert (
            await v.dispatcher.advance(next_action) == "admitted"
            and len(v.execution.submitted) == 2
        )
        for state in ("uploaded", "verified", "queued"):
            assert await v.service.advance(transfer.id) == state
        assert v.remote.posts == v.remote.downloads == 1
        async with db.engine.connect() as connection:
            kind, ciphertext = (
                await connection.execute(
                    text("SELECT typeof(payload),payload FROM generated_capture_jobs")
                )
            ).one()
        assert kind == "blob" and b"Create the original dashboard" not in ciphertext


async def test_discovery_witness_proves_empty_output_once_then_unblocks_without_upload(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path, automatic=True) as v:
        original = v.reader.capture

        async def empty(c):
            outputs = await original(c)
            sha = digest(
                {
                    "turn": v.reader.turn.model_dump(mode="json"),
                    "outputs": [],
                    "hidden": 0,
                    "unsupported": 0,
                    "semantics": v.reader.metadata.semantics_sha256,
                }
            )
            v.reader.outputs = replace(outputs, files=(), evidence_sha256=sha)
            return v.reader.outputs

        monkeypatch.setattr(v.reader, "capture", empty)
        assert await v.capture.advance(v.action_id) == "pending"
        assert await v.capture.advance(v.action_id) == "frozen"
        assert await v.capture.advance(v.action_id) == "frozen"
        assert v.reader.calls == 1 and v.reader.reads == 0 and not v.remote.posts
        assert not await all_rows(db, GeneratedOutputRecord)
        assert await v.dispatcher.advance(await second(v)) == "admitted"


async def test_inventory_change_holds_before_artifact_and_keeps_root_barrier(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        assert not await all_rows(db, Artifact) and not await all_rows(db, FileTransfer)
        assert await v.capture.next_pending() is None and not v.remote.posts
        assert await v.dispatcher.advance(await second(v)) == "queued"


@pytest.mark.parametrize("change", ["grant", "source", "revision", "result"])
async def test_scope_revocation_before_capture_holds_without_read_or_post(db, tmp_path, change):
    async with setup(db, tmp_path, automatic=True) as v:
        if change == "source":
            v.source.messages[101] = v.human.model_copy(update={"revision": 2, "text": "edited"})
        else:
            async with db.sessions.begin() as session:
                if change == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                elif change == "revision":
                    await session.execute(update(Binding).values(revision=2))
                else:
                    await session.execute(
                        update(Action)
                        .where(Action.id == v.action_id)
                        .values(version=Action.version + 1)
                    )
        assert await v.capture.advance(v.action_id) == "held"
        assert v.reader.calls == v.reader.reads == v.remote.posts == 0


async def test_crash_after_prepare_recovers_same_artifact_without_later_native_read(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path, automatic=True) as v:
        assert await v.capture.advance(v.action_id) == "pending"
        original = v.capture.save

        async def crash(saved, plan, state, **kwargs):
            if plan.next_index:
                raise RuntimeError("synthetic crash before capture checkpoint")
            return await original(saved, plan, state, **kwargs)

        monkeypatch.setattr(v.capture, "save", crash)
        with pytest.raises(RuntimeError):
            await v.capture.advance(v.action_id)
        artifact = (await all_rows(db, Artifact))[0]
        transfer = (await all_rows(db, FileTransfer))[0]
        assert await v.service.next_pending() is None
        assert await v.service.advance(transfer.id) == "prepared" and not v.remote.posts
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=0))
        number = await DurableStore(db).acquire_lease("capture-successor", ttl=120)
        v.store.fence = v.outbox.fence = ConsumerFence("capture-successor", number)
        v.service = journal(v)
        v.capture = GeneratedCaptureService(v.service)
        v.reader.alive = False
        reads = v.reader.reads
        assert await v.capture.recover(before=time.time()) == 1
        assert await v.capture.advance(v.action_id) == "frozen"
        assert v.reader.reads == reads and (await all_rows(db, Artifact))[0].id == artifact.id
        assert (await all_rows(db, FileTransfer))[0].id == transfer.id


async def test_failure_in_atomic_reservation_rolls_back_native_completion(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path) as v:
        async with db.sessions.begin() as session:
            action = await session.get(Action, v.action_id)
            # Build another genuinely admitted synthetic input, rather than forge a result.
        identity = await second(v)
        assert await v.dispatcher.advance(identity) == "admitted"
        from jt_oz_bridge.services.resource_execution_results import ResourceResultCollector
        from tests.integration.test_resource_execution_results import Reader

        capture = GeneratedCaptureService(v.service)

        async def fail(*args):
            raise OSError("synthetic reservation failure")

        monkeypatch.setattr(capture, "reserve_in_session", fail)
        collector = ResourceResultCollector(
            v.store.bindings, Reader(), v.store.fence, capture=capture
        )
        with pytest.raises(OSError):
            await collector.collect(identity, "realm")
        async with db.sessions() as session:
            action = await session.get(Action, identity)
        assert action.state == "admitted" and not action.native_result
        assert not await all_rows(db, GeneratedCaptureJob)


@pytest.mark.parametrize("disabled", [False, True])
async def test_mobile_loss_confirmation_releases_barrier_even_when_capture_is_disabled(
    db, tmp_path, disabled
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        next_action = await second(v)
        controls, source = await command(v, "skip " + v.action_id, capture=not disabled)
        reply = await controls.execute(v.binding, source, "en", "skip " + v.action_id)
        token = re.search(r"outputs confirm ([A-Za-z0-9_-]+)", reply).group(1)
        assert await v.dispatcher.advance(next_action) == "queued"
        controls, source = await command(v, "confirm " + token, 202, capture=not disabled)
        assert "dropped" in await controls.execute(v.binding, source, "en", "confirm " + token)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "skipped"
        assert await v.dispatcher.advance(next_action) == "admitted" and not v.remote.posts
        with pytest.raises(ValueError):
            await controls.execute(v.binding, source, "en", "confirm " + token)


@pytest.mark.parametrize("change", ["user", "expired", "version", "binding"])
async def test_loss_token_is_bound_to_owner_version_expiry_and_current_binding(
    db, tmp_path, change
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        controls, source = await command(v, "skip " + v.action_id)
        reply = await controls.execute(v.binding, source, "en", "skip " + v.action_id)
        token = re.search(r"outputs confirm ([A-Za-z0-9_-]+)", reply).group(1)
        from jt_oz_bridge.storage.control_models import ControlToken

        async with db.sessions.begin() as session:
            if change == "expired":
                await session.execute(update(ControlToken).values(expires_at=0))
            elif change == "version":
                await session.execute(
                    update(GeneratedCaptureJob).values(version=GeneratedCaptureJob.version + 1)
                )
            elif change == "binding":
                await session.execute(update(Binding).values(revision=2))
        controls, source = await command(
            v, "confirm " + token, 202, actor=8 if change == "user" else 7
        )
        with pytest.raises(ValueError):
            await controls.execute(v.binding, source, "en", "confirm " + token)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "held" and not v.remote.posts


async def test_human_retry_keeps_pinned_inventory_and_cannot_replace_bytes(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        body = v.reader.body
        await held(v)
        controls, source = await command(v, "retry " + v.action_id)
        assert "retry" in await controls.execute(v.binding, source, "en", "retry " + v.action_id)
        v.reader.body = body
        assert await v.capture.advance(v.action_id) == "frozen"
        assert len(await all_rows(db, Artifact)) == 1 and v.remote.posts == 0


async def test_default_dispatcher_and_other_original_root_do_not_bypass_or_share_barrier(
    db, tmp_path
):
    async with setup(db, tmp_path, automatic=True) as v:
        restarted = Dispatcher(
            v.store.bindings, v.execution, v.source, v.store.fence.holder, v.store.fence.fencing
        )
        assert await restarted.advance(await second(v)) == "queued"
        other = REF.model_copy(update={"upstream_session_id": "other-original-session"})
        binding = await v.store.bindings.bind("realm", 7, 10, "Other work", other)
        source = message("Other original task", 103, topic="Other work")
        v.source.messages[103] = source
        queued = await QueueService(v.store.bindings).receive(binding.id, source)
        assert await restarted.advance(queued.action_id) == "admitted"


@pytest.mark.parametrize("cutoff", [True, float("nan"), float("inf"), "yesterday", None])
async def test_capture_recovery_rejects_untrusted_cutoffs_before_mutation(db, tmp_path, cutoff):
    async with setup(db, tmp_path, automatic=True) as v:
        with pytest.raises(ValueError, match="cutoff_invalid"):
            await v.capture.recover(before=cutoff)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "pending"
        assert not v.reader.calls and not v.remote.posts


async def test_hold_notice_commits_once_with_failure_without_paths_or_native_resubmit(db, tmp_path):
    from jt_oz_bridge.storage.models import Delivery, DeliveryBatch

    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        batches = [
            b
            for b in await all_rows(db, DeliveryBatch)
            if b.renderer_version == "generated-capture-notice-v1"
        ]
        assert len(batches) == 1
        pages = [p for p in await all_rows(db, Delivery) if p.batch_id == batches[0].id]
        assert len(pages) == 1
        content = pages[0].payload["content"]
        assert v.action_id not in content and "!outputs status" in content
        assert v.reader.filename not in content and "/home/" not in content
        assert await v.capture.advance(v.action_id) == "held"
        assert len(await all_rows(db, DeliveryBatch)) == len(batches)
        assert len(v.execution.submitted) == 1 and v.remote.posts == 0


async def test_revoked_source_holds_without_creating_notice_in_invalid_scope(db, tmp_path):
    from jt_oz_bridge.storage.models import DeliveryBatch

    async with setup(db, tmp_path, automatic=True) as v:
        v.source.messages[101] = v.human.model_copy(update={"deleted": True})
        assert await v.capture.advance(v.action_id) == "held"
        assert not await all_rows(db, DeliveryBatch)
        assert not v.reader.calls and not v.remote.posts


async def test_notice_failure_rolls_back_hold_checkpoint_for_successor_recovery(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path, automatic=True) as v:
        assert await v.capture.advance(v.action_id) == "pending"
        v.reader.body = b"changed original output"

        async def unavailable(*args, **kwargs):
            raise RuntimeError("synthetic own DB notice failure")

        monkeypatch.setattr(v.service.outbox, "queue_batch_in_session", unavailable)
        with pytest.raises(RuntimeError, match="notice failure"):
            await v.capture.advance(v.action_id)
        job = (await all_rows(db, GeneratedCaptureJob))[0]
        assert job.state == "capturing" and not job.status_reason
        assert not v.remote.posts


async def test_corrupted_terminal_inventory_cannot_release_the_native_write_barrier(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        assert await v.capture.advance(v.action_id) == "pending"
        assert await v.capture.advance(v.action_id) == "frozen"
        async with db.sessions.begin() as session:
            job = await session.get(GeneratedCaptureJob, v.action_id)
            payload = {**job.payload, "next_index": 0}
            job.payload, job.payload_hash = payload, digest(payload)
        with pytest.raises(ValueError, match="state_changed"):
            await v.dispatcher.advance(await second(v))
        assert len(v.execution.submitted) == 1 and not v.remote.posts


async def test_partial_capture_stays_unsent_until_atomic_human_loss_ack(db, tmp_path, monkeypatch):
    from jt_oz_bridge.storage.durable import Conflict

    async with setup(db, tmp_path, automatic=True) as v:
        capture = v.reader.capture

        async def two_outputs(correlation):
            outputs = await capture(correlation)
            selections = (*outputs.files, outputs.files[0].model_copy(update={"file_index": 1}))
            sha = digest(
                dict(
                    turn=v.reader.turn.model_dump(mode="json"),
                    outputs=[f.model_dump(mode="json") for f in selections],
                    hidden=0,
                    unsupported=0,
                    semantics=v.reader.metadata.semantics_sha256,
                )
            )
            v.reader.outputs = replace(outputs, files=selections, evidence_sha256=sha)
            return v.reader.outputs

        monkeypatch.setattr(v.reader, "capture", two_outputs)
        assert await v.capture.advance(v.action_id) == "pending"
        assert await v.capture.advance(v.action_id) == "pending"
        transfer = (await all_rows(db, FileTransfer))[0]
        artifact = (await all_rows(db, Artifact))[0]
        assert await v.service.next_pending() is None
        assert await v.service.advance(transfer.id) == "prepared"
        assert await v.service.artifacts.protected(artifact)
        original = v.service.capture_generated

        async def missing(identity, index, **kwargs):
            if index == 1:
                raise Conflict("synthetic missing second output")
            return await original(identity, index, **kwargs)

        monkeypatch.setattr(v.service, "capture_generated", missing)
        assert await v.capture.advance(v.action_id) == "held"
        controls, source = await command(v, "skip " + v.action_id)
        response = await controls.execute(v.binding, source, "en", "skip " + v.action_id)
        token = re.search(r"outputs confirm ([A-Za-z0-9_-]+)", response).group(1)
        controls, source = await command(v, "confirm " + token, 202)
        await controls.execute(v.binding, source, "en", "confirm " + token)
        assert (await all_rows(db, FileTransfer))[0].state == "rejected"
        assert not await v.service.artifacts.protected(artifact)
        assert await v.dispatcher.advance(await second(v)) == "admitted"
        assert not v.remote.posts
