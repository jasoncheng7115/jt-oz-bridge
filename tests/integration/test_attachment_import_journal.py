"""Crash/restart/source/fence checks for real encrypted per-file import progress."""

import asyncio
import json
import time

import httpx
import pytest
from sqlalchemy import select

from jt_oz_bridge.services.artifacts import ArtifactService
from jt_oz_bridge.services.attachment_imports import AttachmentImportJournal
from jt_oz_bridge.services.prompt_attachments import ZulipPromptAttachmentImporter
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.storage.artifact_models import Artifact, ArtifactBudget
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, WorkerLease
from tests.integration.test_prompt_attachments import build, close


async def setup_journal(db, tmp_path, *, two=False):
    parts = await build(db, tmp_path)
    holder = "attachment-journal-synthetic"
    number = await DurableStore(db).acquire_lease(holder)
    assert number is not None
    fence = ConsumerFence(holder, number)
    parts[0].fence = fence
    if two:
        source = parts[3].model_copy(
            update={
                "revision": 2,
                "text": "[one](/user_uploads/2/random/one.txt) [two](/user_uploads/2/random/two.txt)",
            }
        )
        parts[4].messages[source.message_id] = source
        await QueueService(parts[0].bindings).receive(parts[1].id, source)
        await parts[6].client.aclose()

        def api(request):
            parts[-1].append(request)
            assert request.headers["authorization"].startswith("Basic ")
            assert request.url.path in (
                "/api/v1/user_uploads/2/random/one.txt",
                "/api/v1/user_uploads/2/random/two.txt",
            )
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "url": "https://files.example/blob?signature=PRIVATE-SIGNED",
                },
            )

        parts[6].client = httpx.AsyncClient(
            base_url="https://chat.example/api/v1/",
            auth=httpx.BasicAuth("synthetic", "synthetic-key"),
            transport=httpx.MockTransport(api),
        )
    return parts, AttachmentImportJournal(parts[8], fence)


async def action(db, identity):
    async with db.sessions() as session:
        return await session.get(Action, identity)


async def test_ready_manifest_is_fenced_encrypted_and_repeat_staging_performs_no_download(
    db, tmp_path
):
    parts, journal = await setup_journal(db, tmp_path, two=True)
    try:
        staged = await journal.stage(parts[5])
        assert staged.state == "queued" and staged.upstream_id is None
        assert (
            "_attachment_import" not in staged.payload
            and len(staged.payload["attachments"]["files"]) == 2
        )
        assert staged.operation_digest == digest(staged.payload)
        assert [f["filename"] for f in staged.payload["attachments"]["files"]] == [
            "one.txt",
            "two.txt",
        ]
        assert "PRIVATE-SIGNED" not in json.dumps(staged.payload)
        count = len(parts[-1])
        restarted = AttachmentImportJournal(parts[8], journal.fence)
        repeated = await restarted.stage(parts[5])
        assert len(parts[-1]) == count and repeated.version == staged.version
        assert all(r.method == "GET" for r in parts[-1])
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 2
    finally:
        await close(parts)


async def test_crash_after_artifact_commit_before_progress_recovers_same_object_without_duplicate_storage(
    db, tmp_path
):
    parts, journal = await setup_journal(db, tmp_path, two=True)
    original = parts[8].import_one

    async def crash(*args, **kwargs):
        receipt = await original(*args, **kwargs)
        if receipt.filename == "two.txt":
            raise RuntimeError("synthetic crash after storage before manifest CAS")
        return receipt

    parts[8].import_one = crash
    try:
        with pytest.raises(RuntimeError, match="after storage"):
            await journal.stage(parts[5])
        partial = await action(db, parts[5])
        assert len(partial.payload["_attachment_import"]["completed"]) == 1
        assert partial.status_reason == "attachment_import_pending" and partial.state == "queued"
        async with db.sessions() as session:
            ids = set((await session.scalars(select(Artifact.id))).all())
            assert len(ids) == 2
        parts[8].import_one = original
        complete = await AttachmentImportJournal(parts[8], journal.fence).stage(parts[5])
        assert {f["artifact_id"] for f in complete.payload["attachments"]["files"]} == ids
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 2
        routes = [r.url.path for r in parts[-1] if r.url.path.startswith("/api/v1/")]
        assert routes.count("/api/v1/user_uploads/2/random/one.txt") == 1
        assert routes.count("/api/v1/user_uploads/2/random/two.txt") == 2
    finally:
        await close(parts)


async def test_same_journal_concurrent_staging_does_not_duplicate_download_or_manifest(
    db, tmp_path
):
    parts, journal = await setup_journal(db, tmp_path)
    try:
        first, second = await asyncio.gather(journal.stage(parts[5]), journal.stage(parts[5]))
        assert first.payload == second.payload and first.version == second.version
        assert len(parts[-1]) == 2
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 1
    finally:
        await close(parts)


@pytest.mark.parametrize("kind", ["initial", "after-storage"])
async def test_expired_consumer_cannot_publish_ready_progress_and_new_fence_recovers_existing_bytes(
    db, tmp_path, kind
):
    parts, journal = await setup_journal(db, tmp_path)
    original = parts[8].import_one

    async def expire():
        async with db.sessions.begin() as session:
            (await session.get(WorkerLease, "consumer")).expires_at = time.time() - 1

    if kind == "initial":
        await expire()
    else:

        async def lost(*args, **kwargs):
            receipt = await original(*args, **kwargs)
            await expire()
            return receipt

        parts[8].import_one = lost
    try:
        with pytest.raises(Conflict, match="lease"):
            await journal.stage(parts[5])
        saved = await action(db, parts[5])
        assert "attachments" not in saved.payload and saved.upstream_id is None
        number = await DurableStore(db).acquire_lease("replacement-consumer")
        assert number is not None
        next_fence = ConsumerFence("replacement-consumer", number)
        store = ArtifactService(
            parts[0].bindings,
            parts[0].files,
            parts[0].cipher,
            maximum_file_bytes=1024,
            reserve_free_bytes=0,
            fence=next_fence,
        )
        importer = ZulipPromptAttachmentImporter(
            store, parts[4], parts[6], parts[7], associations=parts[8].associations
        )
        complete = await AttachmentImportJournal(importer, next_fence).stage(parts[5])
        assert len(complete.payload["attachments"]["files"]) == 1
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 1
        with pytest.raises(Conflict, match="lease"):
            await journal.stage(parts[5])
    finally:
        await close(parts)


async def test_human_edit_after_storage_never_commits_old_source_and_fresh_source_can_reuse_proven_bytes(
    db, tmp_path
):
    parts, journal = await setup_journal(db, tmp_path)
    original = parts[8].import_one

    async def edited(*args, **kwargs):
        receipt = await original(*args, **kwargs)
        latest = parts[3].model_copy(
            update={"revision": 2, "text": parts[3].text + " new instruction"}
        )
        parts[4].messages[latest.message_id] = latest
        await QueueService(parts[0].bindings).receive(parts[1].id, latest)
        return receipt

    parts[8].import_one = edited
    try:
        with pytest.raises(Conflict):
            await journal.stage(parts[5])
        saved = await action(db, parts[5])
        assert saved.payload["source"]["revision"] == 2
        assert "_attachment_import" not in saved.payload and "attachments" not in saved.payload
        parts[8].import_one = original
        ready = await journal.stage(parts[5])
        assert ready.payload["attachments"]["files"][0]["source_sha256"] == digest(
            ready.payload["source"]
        )
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 1
    finally:
        await close(parts)


@pytest.mark.parametrize(
    "kind",
    ["source-hash", "binding-revision", "paths", "artifact-origin", "artifact-bytes", "claimed"],
)
async def test_partial_recovery_revalidates_saved_scope_and_artifacts_before_more_downloads(
    db, tmp_path, kind
):
    parts, journal = await setup_journal(db, tmp_path, two=True)
    original = parts[8].import_one

    async def interrupted(*args, **kwargs):
        if args[2].filename == "two.txt":
            raise RuntimeError("stop before second download")
        return await original(*args, **kwargs)

    parts[8].import_one = interrupted
    try:
        with pytest.raises(RuntimeError):
            await journal.stage(parts[5])
        count = len(parts[-1])
        async with db.sessions.begin() as session:
            saved = await session.get(Action, parts[5])
            payload = dict(saved.payload)
            progress = dict(payload["_attachment_import"])
            if kind == "source-hash":
                progress["source_sha256"] = "f" * 64
            if kind == "binding-revision":
                progress["binding_revision"] += 1
            if kind == "paths":
                progress["uploads"] = list(reversed(progress["uploads"]))
            payload["_attachment_import"] = progress
            saved.payload = payload
            saved.operation_digest = digest(payload)
            if kind == "artifact-origin":
                artifact = await session.get(Artifact, progress["completed"][0]["artifact_id"])
                artifact.action_id = "different-action"
            if kind == "claimed":
                saved.state = "dispatching"
        if kind == "artifact-bytes":
            identity = progress["completed"][0]["artifact_id"]
            path = tmp_path / "private-artifacts" / (identity + ".bin")
            path.write_bytes(b"corrupt ciphertext")
        parts[8].import_one = original
        with pytest.raises((ValueError, Conflict)):
            await journal.stage(parts[5])
        assert len(parts[-1]) == count
        assert (await action(db, parts[5])).upstream_id is None
    finally:
        await close(parts)


async def test_import_journal_never_resumes_a_held_queue(db, tmp_path):
    parts, journal = await setup_journal(db, tmp_path)
    try:
        async with db.sessions.begin() as session:
            (await session.get(Action, parts[5])).state = "held"
        saved = await journal.stage(parts[5])
        assert saved.state == "held" and "attachments" in saved.payload
    finally:
        await close(parts)


async def test_unfenced_storage_is_not_accepted_by_journal(db, tmp_path):
    parts, journal = await setup_journal(db, tmp_path)
    try:
        parts[0].fence = None
        with pytest.raises(ValueError, match="same_consumer_fence"):
            AttachmentImportJournal(parts[8], journal.fence)
    finally:
        await close(parts)


@pytest.mark.parametrize("configured", [False, True])
async def test_dispatcher_stages_all_receipts_before_one_original_native_claim_or_holds_unqualified_files(
    db, tmp_path, configured
):
    from jt_oz_bridge.services.dispatch import Dispatcher
    from tests.integration.test_dispatch import SyntheticExecution

    parts, journal = await setup_journal(db, tmp_path)
    execution = SyntheticExecution()
    worker = Dispatcher(
        parts[0].bindings,
        execution,
        parts[4],
        journal.fence.holder,
        journal.fence.fencing,
        attachment_imports=journal if configured else None,
        attachment_realm_url=parts[6].url,
    )
    try:
        state = await worker.advance(parts[5])
        saved = await action(db, parts[5])
        if configured:
            assert state == "admitted" and len(execution.submitted) == 1
            reference, payload, action_id = execution.submitted[0]
            assert (
                reference.upstream_session_id == parts[0].bindings.control.ref.upstream_session_id
            )
            assert action_id == parts[5] and "_attachment_import" not in payload
            assert len(payload["attachments"]["files"]) == 1
            assert saved.operation_digest == digest(payload)
        else:
            assert state == "rejected" and saved.status_reason == "attachments_not_qualified"
            assert not execution.submitted and not parts[-1]
    finally:
        await close(parts)


async def test_dispatcher_never_forwards_an_incomplete_import_as_text_only_prompt(db):
    from jt_oz_bridge.services.queue import QueueService
    from tests.integration.test_dispatch import dispatcher, message

    worker, binding, execution, reader = await dispatcher(db)
    source = message()
    reader.messages[source.message_id] = source
    queued = await QueueService(worker.bindings).receive(binding.id, source)
    async with db.sessions.begin() as session:
        saved = await session.get(Action, queued.action_id)
        saved.payload = {**saved.payload, "_attachment_import": {"incomplete": "synthetic"}}
        saved.operation_digest = digest(saved.payload)
    assert await worker.advance(queued.action_id) == "held"
    saved = await action(db, queued.action_id)
    assert saved.status_reason == "attachment_import_pending"
    assert not execution.submitted
