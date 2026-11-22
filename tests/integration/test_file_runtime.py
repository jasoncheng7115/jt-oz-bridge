"""Actual service loops; synthetic Native, Zulip HTTP, source and download peers."""

import asyncio
import hashlib
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.files import FILE_SEMANTICS, NativeFileEvidence, NativeReadFile
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.file_upload import (
    UPLOAD_SEMANTICS,
    FileUploadAttestation,
    ZulipFileUploader,
)
from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader
from jt_oz_bridge.domain.attachments import NativeAttachmentProjection
from jt_oz_bridge.security.downloads import DownloadOrigin, DownloadPolicy
from jt_oz_bridge.services.artifacts import ArtifactService
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.file_returns import FileReturnJournal
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action
from tests.contract.test_safe_download import DNS
from tests.integration.test_consumer_runtime import post_containing, rows, setup, until
from tests.support import REF


async def file_pipeline(
    db, tmp_path, *, mode="success", menu_factory=None, generated_reader_factory=None
):
    previous, server, native, _, _, _ = await setup(db)
    client = previous.scope.client
    client.attestation = replace(
        client.attestation, verified_file_operations=frozenset({"upload", "download"})
    )
    scope = ZulipScopeReader(client, channel_ids=previous.scope.channel_ids)
    body = b"original workspace file\r\n\x00binary"
    descriptor = NativeAttachmentProjection(
        filename="report.bin",
        mime_type="application/octet-stream",
        size=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )
    observed = SimpleNamespace(posts=0, downloads=0, reads=0, file=None)

    class NativeFiles:
        async def read(self, reference, path, *, maximum_bytes):
            assert reference == REF and path == descriptor.filename and maximum_bytes >= len(body)
            observed.reads += 1
            now = time.time()
            observed.file = NativeReadFile(
                NativeFileEvidence(
                    reference=REF,
                    relative_path=path,
                    projection=descriptor,
                    etag='"synthetic"',
                    contract_sha256=INSTALLED_SCHEMA,
                    semantics_sha256=FILE_SEMANTICS,
                    installed_evidence_sha256="a" * 64,
                    native_policy_sha256="b" * 64,
                    owner_epoch="synthetic",
                    connection_epoch="synthetic",
                    resource_fence="synthetic",
                    observed_at=now,
                    expires_at=now + 5,
                ),
                body,
            )
            return observed.file

        def current(self, file):
            return (
                file is observed.file
                and file.evidence.observed_at <= time.time() < file.evidence.expires_at
            )

    files = NativeFiles()
    generated = (
        generated_reader_factory(previous.backends[REF.backend_id].results, files, body, descriptor)
        if generated_reader_factory is not None
        else None
    )
    observed.generated = generated

    def api(request):
        if request.url.path == "/api/v1/user_uploads" and request.method == "POST":
            observed.posts += 1
            assert body in request.content
            if mode == "timeout":
                raise httpx.ReadTimeout("synthetic accepted upload / lost response")
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "url": "/user_uploads/2/synthetic/report.bin",
                    "filename": descriptor.filename,
                },
            )
        if request.url.path.startswith("/api/v1/user_uploads/"):
            assert request.method == "GET"
            return httpx.Response(
                200,
                json={"result": "success", "url": "/user_uploads/temporary/synthetic/report.bin"},
            )
        return server.handle(request)

    def download(request):
        observed.downloads += 1
        assert (
            request.url.host == "8.8.8.8"
            and "authorization" not in request.headers
            and "cookie" not in request.headers
        )
        return httpx.Response(200, headers={"content-type": descriptor.mime_type}, content=body)

    client.client._transport = httpx.MockTransport(api)

    def factory(bindings, source, outbox):
        store = ArtifactService(
            bindings,
            LocalArtifactFiles(tmp_path / "artifacts"),
            db.cipher,
            reserve_free_bytes=0,
            fence=outbox.fence,
        )
        uploader = ZulipFileUploader(
            client,
            attestation=FileUploadAttestation("realm", 2, 11, 500, UPLOAD_SEMANTICS, "c" * 64),
        )
        downloader = SafeDownloader(
            DownloadPolicy((DownloadOrigin(client.url, path_prefixes=("/user_uploads/",)),), DNS()),
            transport=httpx.MockTransport(download),
        )
        journal_type = GeneratedFileReturnJournal if generated is not None else FileReturnJournal
        extra = {"generated_readers": {REF: generated}} if generated is not None else {}
        journal = journal_type(
            store,
            source,
            outbox,
            uploader,
            downloader,
            {REF: files},
            message_limit=1000,
            topic_limit=60,
            **extra,
        )
        return FileCommands(journal, {REF: files})

    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        scope,
        previous.backends,
        interval=0.02,
        delivery_interval=0,
        file_factory=factory,
        file_menu_factory=menu_factory,
        generated_factory=(lambda commands: GeneratedCaptureService(commands.journal))
        if generated is not None
        else None,
    )
    return pipeline, server, native, observed


async def test_eighth_loop_captures_and_delivers_same_topic_file_without_native_mutation(
    db, tmp_path
):
    pipeline, server, native, observed = await file_pipeline(db, tmp_path)
    runtime = pipeline.runtime()
    assert any(worker.name == "file-transfers" for worker in runtime.workers)
    await runtime.start()
    try:
        server.input("!oz file report.bin")
        delivered = await post_containing(server, "/user_uploads/2/synthetic/report.bin")
        assert delivered["subject"] == "Original work" and delivered["sender_id"] == 11
        assert observed.reads == observed.posts == observed.downloads == 1
        assert (await rows(db, FileTransfer))[0].state == "queued"
        assert not await rows(db, Action) and not native.submitted
        assert runtime.healthy and len(server.posts) == 2
        await asyncio.sleep(0.1)
        assert observed.posts == 1 and len(server.posts) == 2
    finally:
        await runtime.close()


async def test_runtime_unknown_upload_is_ambiguous_and_never_automatically_repeated(db, tmp_path):
    pipeline, server, native, observed = await file_pipeline(db, tmp_path, mode="timeout")
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz file report.bin")

        async def ambiguous():
            records = await rows(db, FileTransfer)
            return records and records[0].state == "ambiguous"

        await until(ambiguous)
        await asyncio.sleep(0.15)
        assert observed.posts == 1 and observed.downloads == 0 and observed.reads == 1
        assert not await rows(db, Action) and not native.submitted and runtime.healthy
        assert not any("/user_uploads/" in x["content"] for x in server.posts)
    finally:
        await runtime.close()


async def test_runtime_files_default_off_no_transfer_worker_or_accidental_native_prompt(db):
    pipeline, server, native, _, _, _ = await setup(db)
    assert pipeline.files is None
    runtime = pipeline.runtime()
    assert not any(x.name == "file-transfers" for x in runtime.workers)
    await runtime.start()
    try:
        server.input("!oz file report.bin")
        await post_containing(server, "available yet")
        assert (
            not await rows(db, Action) and not await rows(db, FileTransfer) and not native.submitted
        )
    finally:
        await runtime.close()


async def test_runtime_refuses_a_factory_bound_to_a_different_pipeline_source(db, tmp_path):
    pipeline, _, _, _ = await file_pipeline(db, tmp_path)
    try:
        with pytest.raises(ValueError, match="composition_scope_mismatch"):
            ConsumerPipeline(
                db,
                pipeline.fence,
                pipeline.scope,
                pipeline.backends,
                file_factory=lambda *_: pipeline.files,
            )
    finally:
        await pipeline.close_files()
        await pipeline.scope.client.close()


async def test_runtime_files_menu_token_download_and_diff_share_original_resources(db, tmp_path):
    import re

    from jt_oz_bridge.services.file_menus import FileMenus
    from tests.integration.test_file_menus import Catalog

    catalog = Catalog("report.bin")

    def factory(bindings, source, tokens, files):
        return FileMenus(bindings, source, tokens, {REF: catalog}, message_limit=1000)

    pipeline, server, native, observed = await file_pipeline(db, tmp_path, menu_factory=factory)
    assert pipeline.file_menus.choices is pipeline.files.choices
    assert pipeline.file_menus.tokens is pipeline.tokens
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz files")
        menu = await post_containing(server, "!oz file file:")
        choice = re.search(r"file:[A-Za-z0-9_-]{32}", menu["content"])[0]
        server.input("!oz file " + choice, 102)
        delivered = await post_containing(server, "/user_uploads/2/synthetic/report.bin")
        assert delivered["subject"] == "Original work"
        server.input("!oz diff", 103)
        await post_containing(server, "!oz diff diff:")
        assert runtime.healthy and observed.posts == observed.downloads == observed.reads == 1
        assert not native.submitted and not await rows(db, Action)
    finally:
        await runtime.close()


async def test_runtime_menu_factory_failure_closes_new_artifact_descriptor(db, tmp_path):
    observed = []

    def bad_factory(bindings, source, tokens, files):
        observed.append(files.journal.artifacts.files)
        raise ValueError("synthetic factory failed")

    with pytest.raises(ValueError, match="synthetic factory failed"):
        await file_pipeline(db, tmp_path, menu_factory=bad_factory)
    assert observed
    assert observed[0]._fd == -1


@pytest.mark.parametrize("bad", ["none", "other-tokens", "capacity", "foreign-root"])
async def test_runtime_rejects_unusable_menu_composition_and_closes_artifact_fd(db, tmp_path, bad):
    from jt_oz_bridge.services.file_menus import FileMenus
    from jt_oz_bridge.services.tokens import TokenService
    from tests.integration.test_file_menus import Catalog

    seen = []

    def factory(bindings, source, tokens, files):
        seen.append(files.journal.artifacts.files)
        if bad == "none":
            return None
        catalogs = {REF: Catalog("report.bin")}
        if bad == "foreign-root":
            catalogs[REF.model_copy(update={"upstream_session_id": "ses_foreign"})] = Catalog(
                "report.bin"
            )
        return FileMenus(
            bindings,
            source,
            TokenService(db, fence=tokens.fence) if bad == "other-tokens" else tokens,
            catalogs,
            message_limit=11000 if bad == "capacity" else 1000,
        )

    with pytest.raises(ValueError, match="file_menu_runtime_scope_mismatch"):
        await file_pipeline(db, tmp_path, menu_factory=factory)
    assert seen and seen[0]._fd == -1
