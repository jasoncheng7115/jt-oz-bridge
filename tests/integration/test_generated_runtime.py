"""Whole automatic capture service graph over synthetic peers; not phone acceptance."""

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob
from jt_oz_bridge.storage.models import Action
from tests.integration.test_consumer_runtime import post_containing, rows, setup, until
from tests.integration.test_file_runtime import file_pipeline
from tests.integration.test_generated_file_returns import GeneratedReader


async def capture_failure_metadata(db, pipeline, runtime, native, observed):
    """Failure-only metadata: no payloads, commands, exception bodies or raw IDs."""
    states = {
        "received",
        "validated",
        "queued",
        "held",
        "dispatching",
        "admitted",
        "running",
        "completed",
        "cancelled",
        "rejected",
        "failed",
        "ambiguous",
        "pending",
        "capturing",
        "frozen",
        "skipped",
        "prepared",
        "uploading",
        "uploaded",
        "verified",
    }
    value = {
        "healthy": runtime.healthy is True,
        "failure": runtime.failure_code
        in {
            "runtime_worker_stopped",
            "runtime_start_failed",
            "runtime_cleanup_failed",
            "runtime_start_cancelled",
        },
        "native_submissions": len(native.submitted),
        "upload_posts": observed.posts if type(observed.posts) is int else None,
        "deferrals": sum(x for x in pipeline.deferred.values() if type(x) is int),
    }
    tasks = []
    for task in asyncio.all_tasks():
        if not task.get_name().startswith("jtoz:"):
            continue
        chain, coroutine, seen = [], task.get_coro(), set()
        while coroutine is not None and id(coroutine) not in seen and len(chain) < 16:
            seen.add(id(coroutine))
            frame = getattr(coroutine, "cr_frame", None) or getattr(coroutine, "gi_frame", None)
            if frame is not None:
                chain.append((frame.f_code.co_name, frame.f_lineno))
            coroutine = getattr(coroutine, "cr_await", None) or getattr(
                coroutine, "gi_yieldfrom", None
            )
        tasks.append({"cancelling": task.cancelling(), "stack": chain})
        if len(tasks) == 24:
            break
    value["worker_tasks"] = tasks
    print("generated_runtime_failure_metadata", json.dumps(value), flush=True)
    try:
        # Separate from, and after, the unchanged eight-second result deadline.
        # A diagnostic failure must not suppress the original TimeoutError.
        async with asyncio.timeout(1):
            async with db.sessions() as session:
                groups = {}
                for label, model, identity in (
                    ("actions", Action, Action.id),
                    ("captures", GeneratedCaptureJob, GeneratedCaptureJob.action_id),
                    ("transfers", FileTransfer, FileTransfer.id),
                ):
                    records = (
                        await session.execute(
                            select(identity, model.state, model.version).limit(11)
                        )
                    ).all()
                    groups[label] = {
                        "truncated": len(records) > 10,
                        "records": [
                            {
                                "id_hash": hashlib.sha256(str(key).encode()).hexdigest()[:12],
                                "state": state if state in states else "other",
                                "version": version if type(version) is int else None,
                            }
                            for key, state, version in records[:10]
                        ],
                    }
        print("generated_runtime_failure_database", json.dumps(groups), flush=True)
    except Exception:
        print("generated_runtime_failure_database_unavailable", flush=True)


def factory(results, files, body, descriptor):
    class OriginalReader(GeneratedReader):
        async def capture(self, correlation):
            self.result = SimpleNamespace(evidence=results.evidence)
            if self.block and not self.released.is_set():
                self.entered.set()
                await self.released.wait()
            return await super().capture(correlation)

    reader = OriginalReader(None, body, "inline")
    reader.filename, reader.mime_type = descriptor.filename, descriptor.mime_type
    reader.turns, reader.file_reader = results, files
    reader.entered, reader.released, reader.block = asyncio.Event(), asyncio.Event(), False
    return reader


async def test_automatic_original_task_file_reaches_original_topic_without_file_command(
    db, tmp_path
):
    pipeline, server, native, observed = await file_pipeline(
        db, tmp_path, generated_reader_factory=factory
    )
    runtime = pipeline.runtime()
    assert any(w.name == "generated-capture" for w in runtime.workers)
    await runtime.start()
    try:
        server.input("Create an original report")
        reply = await post_containing(server, "/user_uploads/2/synthetic/report.bin")
        assert reply["subject"] == "Original work" and reply["sender_id"] == 11
        assert observed.posts == observed.downloads == 1 and len(native.submitted) == 1
        jobs = await rows(db, GeneratedCaptureJob)
        assert len(jobs) == 1 and jobs[0].state == "frozen"
        assert len(await rows(db, Action)) == 1 and runtime.healthy
    finally:
        await runtime.close()


async def test_real_loops_do_not_send_second_input_while_original_capture_is_in_progress(
    db, tmp_path
):
    pipeline, server, native, observed = await file_pipeline(
        db, tmp_path, generated_reader_factory=factory
    )
    observed.generated.block = True
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("First original report")
        await asyncio.wait_for(observed.generated.entered.wait(), 8)
        server.input("Next original report", mid=102)

        async def queued():
            items = await rows(db, Action)
            return len(items) == 2 and any(x.state == "queued" for x in items)

        await until(queued)
        await asyncio.sleep(0.1)
        assert len(native.submitted) == 1 and not observed.posts
        observed.generated.released.set()

        async def finished():
            jobs = await rows(db, GeneratedCaptureJob)
            return len(jobs) == 2 and all(x.state == "frozen" for x in jobs) and observed.posts == 2

        await until(finished)
        assert len(native.submitted) == 2 and runtime.healthy
    except TimeoutError:
        await capture_failure_metadata(db, pipeline, runtime, native, observed)
        raise
    finally:
        observed.generated.released.set()
        await runtime.close()


async def test_disabled_automatic_capture_stays_off_and_control_never_becomes_native_prompt(db):
    pipeline, server, native, _, _, _ = await setup(db)
    assert pipeline.generated is None
    runtime = pipeline.runtime()
    assert not any(w.name == "generated-capture" for w in runtime.workers)
    await runtime.start()
    try:
        server.input("!oz outputs status")
        await post_containing(server, "No file capture jobs")
        assert not native.submitted and not await rows(db, Action)
    finally:
        await runtime.close()


async def test_foreign_generated_factory_cannot_replace_original_source_or_journal(db, tmp_path):
    pipeline, _, _, observed = await file_pipeline(db, tmp_path, generated_reader_factory=factory)
    try:
        with pytest.raises(ValueError):
            ConsumerPipeline(
                db,
                pipeline.fence,
                pipeline.scope,
                pipeline.backends,
                generated_factory=lambda _: GeneratedCaptureService(pipeline.files.journal),
            )
    finally:
        await pipeline.close_files()
        await pipeline.scope.client.close()


async def test_running_pipeline_admin_loss_ack_then_new_actor_task_uses_original_root(db, tmp_path):
    import re

    from sqlalchemy import update

    from jt_oz_bridge.services.generated_capture_plans import read_capture
    from jt_oz_bridge.storage.models import Grant

    pipeline, server, native, observed = await file_pipeline(
        db, tmp_path, generated_reader_factory=factory
    )
    observed.generated.block = True
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("Original actor report")
        await asyncio.wait_for(observed.generated.entered.wait(), 8)
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            session.add(Grant(realm_id="realm", project_id="project", user_id=7, role="viewer"))
        observed.generated.released.set()

        async def held_job():
            jobs = await rows(db, GeneratedCaptureJob)
            return jobs and jobs[0].state == "held"

        await until(held_job)
        identity = (await rows(db, GeneratedCaptureJob))[0].action_id
        server.input("!oz outputs skip " + identity, mid=102, author=8)
        reply = await post_containing(server, "as an administrator")
        token = re.search(r"outputs confirm ([A-Za-z0-9_-]+)", reply["content"]).group(1)
        server.input("!oz outputs confirm " + token, mid=103, author=8)
        await post_containing(server, "dropped")
        job = (await rows(db, GeneratedCaptureJob))[0]
        assert job.state == "skipped" and read_capture(job).acknowledgement.author_id == 8
        assert not observed.posts and len(native.submitted) == 1
        server.input("Administrator new report", mid=104, author=8)
        await post_containing(server, "/user_uploads/2/synthetic/report.bin")
        assert len(native.submitted) == 2 and observed.posts == 1 and runtime.healthy
        assert {a.actor_id for a in await rows(db, Action)} == {7, 8}
    finally:
        observed.generated.released.set()
        await runtime.close()


async def test_failure_metadata_never_discloses_payloads_credentials_or_unknown_states(db, capsys):
    secret = "SENSITIVE_DIAGNOSTIC_SENTINEL"
    async with db.sessions.begin() as session:
        session.add(
            Action(
                id="private-action-id",
                dedupe_key="private-action",
                binding_id="private-binding",
                binding_revision=1,
                actor_id=7,
                operation_digest="a" * 64,
                operation="prompt",
                payload={"text": secret, "api_key": secret},
                state=secret,
            )
        )
    pipeline = SimpleNamespace(deferred={secret: 2}, credential=secret)
    runtime = SimpleNamespace(healthy=False, failure_code=secret, failure_detail=secret)
    native = SimpleNamespace(submitted=[{"prompt": secret}])
    observed = SimpleNamespace(posts=1, private_output=secret)
    await capture_failure_metadata(db, pipeline, runtime, native, observed)
    output = capsys.readouterr().out
    assert secret not in output and "private-action-id" not in output
    assert '"native_submissions": 1' in output and '"upload_posts": 1' in output
    assert '"state": "other"' in output and '"version": 1' in output
