"""Real encrypted/fenced workspace imports with synthetic HTTP/source authority.

These checks neither enroll a real Human upload nor submit a Native prompt.
"""

import json
import time
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    PromptAttachmentManifest,
    PromptAttachmentReceipt,
    WorkspaceAttachmentManifest,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.attachment_imports import (
    AttachmentImportJournal,
    AttachmentImportProgress,
    WorkspaceImportProgress,
)
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.storage.artifact_models import Artifact, ArtifactBudget
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_attachment_import_journal import action, setup_journal
from tests.integration.test_dispatch import SyntheticExecution, message
from tests.integration.test_prompt_attachments import close


def receipts(count=10, size=MAX_ATTACHMENT_BYTES):
    source = message()
    return source, tuple(
        PromptAttachmentReceipt(
            artifact_id=str(uuid4()),
            source_upload=f"/user_uploads/2/random/{index}.bin",
            source_message_id=source.message_id,
            source_sha256=digest(source.model_dump(mode="json")),
            filename=f"檔案{index}.bin",
            mime_type="application/octet-stream",
            size=size,
            sha256="a" * 64,
        )
        for index in range(count)
    )


def test_ten_independent_20mib_receipts_have_explicit_transport_and_cannot_be_inline():
    source, files = receipts()
    manifest = WorkspaceAttachmentManifest(files=files)
    manifest.checked(source)
    assert sum(f.size for f in manifest.files) == 200 * 1024**2
    assert manifest.format == "original-workspace-attachments-v1"
    with pytest.raises(ValueError):
        PromptAttachmentManifest.model_validate(manifest.model_dump(mode="json"))
    with pytest.raises(ValueError, match="total_size"):
        PromptAttachmentManifest(files=files)
    with pytest.raises(ValueError):
        WorkspaceAttachmentManifest.model_validate({"files": files, "format": "inline"})


@pytest.mark.parametrize(
    "change",
    [
        "per-file",
        "count",
        "duplicate-path",
        "duplicate-artifact",
        "nested-size",
        "source",
        "bot",
        "deleted",
    ],
)
def test_workspace_manifest_rejects_capacity_aliases_and_changed_source(change):
    source, files = receipts()
    if change in {"per-file", "nested-size"}:
        files = (files[0].model_copy(update={"size": MAX_ATTACHMENT_BYTES + 1}), *files[1:])
    if change == "count":
        files = (*files, *receipts(count=1)[1])
    if change == "duplicate-path":
        files = (*files[:9], files[9].model_copy(update={"source_upload": files[0].source_upload}))
    if change == "duplicate-artifact":
        files = (*files[:9], files[9].model_copy(update={"artifact_id": files[0].artifact_id}))
    if change == "source":
        source = source.model_copy(update={"revision": source.revision + 1})
    if change == "bot":
        source = source.model_copy(update={"is_bot": True})
    if change == "deleted":
        source = source.model_copy(update={"deleted": True})
    with pytest.raises(ValueError):
        if change == "nested-size":
            # Even a caller bypassing construction cannot forge a current receipt.
            manifest = WorkspaceAttachmentManifest.model_construct(files=files)
        else:
            manifest = WorkspaceAttachmentManifest(files=files)
        manifest.checked(source)


@pytest.mark.parametrize("change", ["format", "source", "prefix", "duplicate", "oversize"])
def test_workspace_progress_is_transport_tagged_bounded_ordered_source_prefix(change):
    _, files = receipts()
    data = {
        "source_sha256": files[0].source_sha256,
        "binding_revision": 1,
        "uploads": tuple(f.source_upload for f in files),
        "completed": files,
    }
    good = WorkspaceImportProgress(**data)
    assert len(good.completed) == 10
    with pytest.raises(ValueError):
        AttachmentImportProgress.model_validate(good.model_dump(mode="json"))
    if change == "format":
        data["format"] = "original-prompt-attachment-import-v1"
    if change == "source":
        data["source_sha256"] = "b" * 64
    if change == "prefix":
        data["completed"] = tuple(reversed(files))
    if change == "duplicate":
        data["uploads"] = tuple(files[0].source_upload for _ in files)
    if change == "oversize":
        data["completed"] = (files[0].model_copy(update={"size": MAX_ATTACHMENT_BYTES + 1}),)
    with pytest.raises(ValueError):
        WorkspaceImportProgress(**data)


async def workspace(db, tmp_path, *, count=2, size=22, same_name=False):
    parts, inline = await setup_journal(db, tmp_path)
    # All network operations are the existing synthetic transports; increase only
    # the per-file bound to the production 20 MiB value for this isolated store.
    parts[0].maximum = MAX_ATTACHMENT_BYTES
    parts[7].maximum = MAX_ATTACHMENT_BYTES
    body = b"\x00" * size
    parts[8].associations.size = size
    paths = tuple(
        f"/user_uploads/2/random-{index}/" + ("同名.bin" if same_name else f"{index}.bin")
        for index in range(count)
    )
    # Use encoded URLs as a real Zulip source would; names are not local paths.
    from urllib.parse import quote

    paths = tuple(quote(path, safe="/") for path in paths)
    source = parts[3].model_copy(
        update={"revision": 2, "text": "分析 " + " ".join(f"[檔案]({path})" for path in paths)}
    )
    parts[4].messages[source.message_id] = source
    queued = await QueueService(parts[0].bindings).receive(parts[1].id, source)
    assert queued.action_id == parts[5]
    await parts[6].client.aclose()

    def api(request):
        parts[-1].append(request)
        assert request.method == "GET" and "authorization" in request.headers
        assert str(request.url).partition("/api/v1")[2] in paths
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
    await parts[7].client.aclose()

    def download(request):
        parts[-1].append(request)
        assert request.method == "GET" and "authorization" not in request.headers
        assert "cookie" not in request.headers and request.url.host == "8.8.8.8"
        return httpx.Response(200, content=body)

    parts[7].client = httpx.AsyncClient(transport=httpx.MockTransport(download))
    return parts, AttachmentImportJournal(parts[8], inline.fence, transport="workspace")


async def test_ten_20mib_downloads_are_sequential_encrypted_fenced_and_restartable(db, tmp_path):
    parts, journal = await workspace(db, tmp_path, count=10, size=MAX_ATTACHMENT_BYTES)
    original = parts[8].import_one
    limits = []

    async def import_one(*args, **kwargs):
        limits.append(kwargs["remaining"])
        return await original(*args, **kwargs)

    parts[8].import_one = import_one
    try:
        saved = await journal.stage(parts[5])
        manifest = WorkspaceAttachmentManifest.model_validate(
            saved.payload["workspace_attachments"]
        )
        assert saved.state == "queued" and saved.upstream_id is None
        assert saved.operation_digest == digest(saved.payload)
        assert (
            "attachments" not in saved.payload
            and "_workspace_attachment_import" not in saved.payload
        )
        assert limits == [MAX_ATTACHMENT_BYTES] * 10
        assert sum(f.size for f in manifest.files) == MAX_ATTACHMENTS * MAX_ATTACHMENT_BYTES
        assert len({f.artifact_id for f in manifest.files}) == 10
        assert "PRIVATE-SIGNED" not in json.dumps(saved.payload)
        async with db.sessions() as session:
            budget = await session.get(ArtifactBudget, "global")
            assert budget.object_count == 10 and budget.reserved_bytes > 200 * 1024**2
            assert len((await session.scalars(select(Artifact))).all()) == 10
        count = len(parts[-1])
        restarted = AttachmentImportJournal(parts[8], journal.fence, transport="workspace")
        repeated = await restarted.stage(parts[5])
        assert repeated.version == saved.version and len(parts[-1]) == count
        assert count == 20
    finally:
        await close(parts)


@pytest.mark.parametrize("transport", ["inline", "workspace"])
async def test_independent_same_name_same_bytes_uploads_keep_distinct_objects_after_crash(
    db, tmp_path, transport
):
    parts, journal = await workspace(db, tmp_path, same_name=True)
    journal = AttachmentImportJournal(parts[8], journal.fence, transport=transport)
    original = parts[8].import_one
    calls = 0

    async def crash(*args, **kwargs):
        nonlocal calls
        file = await original(*args, **kwargs)
        calls += 1
        if calls == 2:
            raise RuntimeError("isolated crash after second artifact before CAS")
        return file

    parts[8].import_one = crash
    try:
        with pytest.raises(RuntimeError, match="isolated crash"):
            await journal.stage(parts[5])
        saved = await action(db, parts[5])
        assert len(saved.payload[journal.progress_key]["completed"]) == 1
        async with db.sessions() as session:
            ids = set((await session.scalars(select(Artifact.id))).all())
            assert len(ids) == 2
        parts[8].import_one = original
        complete = await AttachmentImportJournal(
            parts[8], journal.fence, transport=transport
        ).stage(parts[5])
        files = complete.payload[journal.manifest_key]["files"]
        assert {file["artifact_id"] for file in files} == ids
        assert files[0]["filename"] == files[1]["filename"] == "同名.bin"
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 2
    finally:
        await close(parts)


@pytest.mark.parametrize(
    "change", ["source", "grant", "association", "fence", "artifact", "transport", "format"]
)
async def test_workspace_partial_recovery_checks_authority_and_provenance_before_more_network(
    db, tmp_path, change
):
    parts, journal = await workspace(db, tmp_path)
    original = parts[8].import_one

    async def interrupted(*args, **kwargs):
        if args[2].filename == "1.bin":
            raise RuntimeError("isolated stop before second file")
        return await original(*args, **kwargs)

    parts[8].import_one = interrupted
    try:
        with pytest.raises(RuntimeError):
            await journal.stage(parts[5])
        network_count = len(parts[-1])
        if change == "source":
            source = parts[4].messages[parts[3].message_id]
            parts[4].messages[source.message_id] = source.model_copy(update={"revision": 3})
        if change == "association":
            parts[8].associations.active = False
        async with db.sessions.begin() as session:
            saved = await session.get(Action, parts[5])
            if change == "grant":
                grants = (await session.scalars(select(Grant))).all()
                for grant in grants:
                    grant.active = False
                    grant.revision += 1
            if change == "fence":
                (await session.get(WorkerLease, "consumer")).expires_at = time.time() - 1
            if change == "artifact":
                identity = saved.payload[journal.progress_key]["completed"][0]["artifact_id"]
                (await session.get(Artifact, identity)).action_id = "other-action"
            if change in {"transport", "format"}:
                payload = dict(saved.payload)
                progress = dict(payload[journal.progress_key])
                if change == "transport":
                    payload["_attachment_import"] = progress
                else:
                    progress["format"] = "original-prompt-attachment-import-v1"
                    payload[journal.progress_key] = progress
                saved.payload = payload
                saved.operation_digest = digest(payload)
        parts[8].import_one = original
        with pytest.raises((AccessDenied, Conflict, ValueError)):
            await journal.stage(parts[5])
        assert len(parts[-1]) == network_count
        assert (await action(db, parts[5])).upstream_id is None
    finally:
        await close(parts)


@pytest.mark.parametrize("ready", [False, True])
async def test_dispatcher_holds_workspace_receipts_until_original_prompt_projection_is_composed(
    db, tmp_path, ready
):
    parts, journal = await workspace(db, tmp_path)
    execution = SyntheticExecution()
    if ready:
        await journal.stage(parts[5])
    else:
        source = parts[4].messages[parts[3].message_id]
        current = await action(db, parts[5])
        await journal.publish(
            current,
            source,
            WorkspaceImportProgress(
                source_sha256=digest(source.model_dump(mode="json")),
                binding_revision=current.binding_revision,
                uploads=tuple(f"/user_uploads/2/random-{i}/{i}.bin" for i in range(2)),
            ),
        )
    worker = Dispatcher(
        parts[0].bindings,
        execution,
        parts[4],
        journal.fence.holder,
        journal.fence.fencing,
    )
    try:
        assert await worker.advance(parts[5]) == "held"
        saved = await action(db, parts[5])
        assert saved.status_reason == (
            "workspace_attachments_not_qualified"
            if ready
            else "workspace_attachment_import_pending"
        )
        assert not execution.submitted and saved.upstream_id is None
    finally:
        await close(parts)


async def test_inline_and_workspace_journals_cannot_reinterpret_each_others_completed_payload(
    db, tmp_path
):
    parts, journal = await workspace(db, tmp_path)
    try:
        await journal.stage(parts[5])
        network_count = len(parts[-1])
        with pytest.raises(Conflict, match="transport"):
            await AttachmentImportJournal(parts[8], journal.fence).stage(parts[5])
        assert len(parts[-1]) == network_count
    finally:
        await close(parts)


async def test_inline_aggregate_limit_still_stops_second_file_before_url_lookup(db, tmp_path):
    parts, workspace_journal = await workspace(db, tmp_path, size=11 * 1024**2)
    journal = AttachmentImportJournal(parts[8], workspace_journal.fence)
    try:
        with pytest.raises(ValueError, match="total_size"):
            await journal.stage(parts[5])
        saved = await action(db, parts[5])
        assert len(saved.payload["_attachment_import"]["completed"]) == 1
        assert "attachments" not in saved.payload and "workspace_attachments" not in saved.payload
        assert len(parts[-1]) == 2
        assert saved.state == "queued" and saved.upstream_id is None
    finally:
        await close(parts)
