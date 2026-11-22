"""Actual consumer/dispatch/result loops, encrypted SQL/files; synthetic peers only.

The deliberately injected Native batch/source association fixtures do not
qualify any installed server, Human upload, model or official mobile client.
"""

import asyncio
import copy
from dataclasses import asdict, replace
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.files import V2NativeFileReader
from jt_oz_bridge.adapters.opencode.native_workspace import NativeWorkspaceBatch
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.file_upload import (
    UPLOAD_SEMANTICS,
    FileUploadAttestation,
    ZulipFileUploader,
)
from jt_oz_bridge.domain.attachments import WorkspaceAttachmentManifest
from jt_oz_bridge.domain.execution import Admission, HumanMessage
from jt_oz_bridge.security.downloads import DownloadOrigin, DownloadPolicy
from jt_oz_bridge.services import workspace_runtime as module
from jt_oz_bridge.services.artifacts import ArtifactService
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.file_returns import FileReturnJournal
from jt_oz_bridge.services.workspace_journal import WorkspaceJournal
from jt_oz_bridge.services.workspace_routes import WorkspaceProviderRoutes
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.workspace_files import WorkspaceFiles, WorkspaceNamespace
from jt_oz_bridge.storage.workspace_models import WorkspacePublication
from tests.contract.test_safe_download import DNS
from tests.integration.test_consumer_runtime import (
    post_containing,
    rows,
    until,
)
from tests.integration.test_consumer_runtime import (
    setup as base_setup,
)
from tests.integration.test_prompt_attachments import SyntheticUploadAssociations
from tests.support import REF

UPLOAD = "/user_uploads/2/synthetic/input.bin"
BODY = b"original synthetic input\x00\xff\r\n"


class SyntheticV2Files(V2NativeFileReader):
    def __init__(self, client):
        self.client = client

    def require(self, ref):
        assert ref == REF
        return SimpleNamespace(contract_sha256=INSTALLED_SCHEMA)


class SyntheticSharedHost:
    def __init__(self, reader, files):
        self.reader, self.files = reader, files
        data = asdict(files.namespace)
        data["path"] = str(files.namespace.path)
        self.namespace_sha256 = digest(data)
        self.issued = []
        self.active = True

    def qualified(self, ref, schema):
        return self.active and ref == REF and schema == INSTALLED_SCHEMA

    async def prove(self, ref, files):
        assert all(self.files.current(file) for file in files)
        assert all((self.files.namespace.path / f.storage_name).read_bytes() == BODY for f in files)
        result = NativeWorkspaceBatch(ref, files, "b" * 64)
        self.issued.append(result)
        return result

    def current(self, proof):
        return (
            self.active
            and any(proof is p for p in self.issued)
            and all(self.files.unchanged(f) for f in proof.files)
        )


async def setup(db, tmp_path, monkeypatch, *, mode="normal"):
    previous, server, native, result_reader, binding, pulse = await base_setup(db)
    client = previous.scope.client
    client.attestation = replace(
        client.attestation, verified_file_operations=frozenset({"upload", "download"})
    )
    # The scope reader pins the same attestation object used by the client.
    from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader

    scope = ZulipScopeReader(client, channel_ids=previous.scope.channel_ids)
    associations = SyntheticUploadAssociations(len(BODY))
    original = client.client._transport

    def api(request):
        if request.url.path == "/api/v1" + UPLOAD:
            assert request.method == "GET" and "authorization" in request.headers
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "url": UPLOAD.replace("/synthetic/", "/temporary/synthetic/"),
                },
            )
        return original.handler(request)

    client.client._transport = httpx.MockTransport(api)

    def download(request):
        assert request.method == "GET" and request.url.host == "8.8.8.8"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        return httpx.Response(200, content=BODY)

    native.workspace_attachments = None
    native.projected = []

    async def submit(ref, payload, action_id):
        source = HumanMessage.model_validate(payload["source"])
        manifest = WorkspaceAttachmentManifest.model_validate(payload["workspace_attachments"])
        provider = native.workspace_attachments
        assert provider is not None
        prepared = await provider.prepare(ref, action_id, source, manifest, payload["text"])
        text = prepared.checked(ref, action_id, source, manifest, payload["text"])
        assert provider.current(ref, action_id, prepared) and prepared.operation_digest == digest(
            payload
        )
        native.submitted.append((ref, copy.deepcopy(payload), action_id))
        native.projected.append(text)
        if mode == "ambiguous":
            raise TimeoutError("synthetic accepted input/lost response")
        return Admission(
            status="admitted",
            upstream_id="fixture:" + action_id,
            details={
                "workspace_projection": prepared.projection.model_dump(mode="json"),
                "model_visibility": "unverified",
            },
        )

    native.submit = submit
    reader = SyntheticV2Files(native)

    def files_factory(bindings, source, outbox):
        artifacts = ArtifactService(
            bindings,
            LocalArtifactFiles(tmp_path / "encrypted"),
            db.cipher,
            reserve_free_bytes=0,
            fence=outbox.fence,
        )
        downloader = SafeDownloader(
            DownloadPolicy((DownloadOrigin(client.url, path_prefixes=("/user_uploads/",)),), DNS()),
            transport=httpx.MockTransport(download),
        )
        journal = FileReturnJournal(
            artifacts,
            source,
            outbox,
            ZulipFileUploader(
                client,
                attestation=FileUploadAttestation("realm", 2, 11, 500, UPLOAD_SEMANTICS, "c" * 64),
            ),
            downloader,
            {REF: reader},
            message_limit=10000,
            topic_limit=60,
        )
        return FileCommands(journal, {REF: reader})

    path = tmp_path.resolve() / ".jt-oz-incoming-runtime"
    path.mkdir(mode=0o2750)
    path.chmod(0o2750)
    st = path.stat()
    monkeypatch.setattr(module, "V2SharedWorkspaceHost", SyntheticSharedHost)

    def incoming_factory(files):
        namespace = WorkspaceFiles(
            WorkspaceNamespace(path, st.st_dev, st.st_ino, st.st_uid, st.st_gid),
            reserve_free_bytes=0,
        )
        return module.WorkspaceIncoming(
            files, associations, {REF: WorkspaceJournal(files.journal.artifacts, namespace)}
        )

    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        scope,
        previous.backends,
        interval=0.02,
        delivery_interval=0,
        file_factory=files_factory,
        incoming_factory=incoming_factory,
    )
    return pipeline, server, native, associations, path


async def test_workspace_resource_imports_exact_encrypted_bytes_and_delivers_original_topic_result(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    live = pipeline.runtime()
    await live.start()
    try:
        server.input("分析 [input.bin](" + UPLOAD + ")")
        reply = await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
        assert reply["subject"] == "Original work" and reply["sender_id"] == 11
        assert len(native.submitted) == len(native.projected) == 1
        ref, frozen, identity = native.submitted[0]
        assert frozen["text"] == "分析 [input.bin](" + UPLOAD + ")"
        assert native.projected[0].startswith(
            frozen["text"] + "\n\n[jt-oz-bridge workspace inputs v1]"
        )
        assert "attachments" not in frozen and "workspace_attachments" in frozen
        assert "data:" not in native.projected[0]
        action = (await rows(db, Action))[0]
        assert action.id == identity and action.state == "completed"
        assert action.payload == frozen and action.operation_digest == digest(frozen)
        publications = await rows(db, WorkspacePublication)
        assert len(publications) == 1 and publications[0].state == "ready"
        assert len(await rows(db, Artifact)) == 1 and len(list(path.iterdir())) == 1
        assert next(path.iterdir()).read_bytes() == BODY
        assert all(BODY not in blob.read_bytes() for blob in (tmp_path / "encrypted").glob("*.bin"))
        assert len(associations.calls) >= 3 and live.healthy
        await asyncio.sleep(0.1)
        assert len(native.submitted) == 1
    finally:
        await live.close()
    assert all(j.files._fd == -1 for j in pipeline.incoming.journals.values())
    assert pipeline.files.journal.artifacts.files._fd == -1


async def test_revoked_source_association_rejects_without_native_input_or_plaintext(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    live = pipeline.runtime()
    await live.start()
    associations.active = False
    try:
        server.input("分析 [input.bin](" + UPLOAD + ")")

        async def held():
            actions = await rows(db, Action)
            return actions and actions[0].state == "rejected"

        await until(held)
        assert (await rows(db, Action))[0].status_reason == "authorization_revoked"
        assert not native.submitted and not list(path.iterdir())
        assert not await rows(db, Artifact) and not await rows(db, WorkspacePublication)
    finally:
        await live.close()


async def test_replaced_native_route_keeps_encrypted_receipt_held_without_dropping_file_to_text(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    live = pipeline.runtime()
    await live.start()
    native.workspace_attachments = WorkspaceProviderRoutes()
    try:
        server.input("分析 [input.bin](" + UPLOAD + ")")

        async def held():
            actions = await rows(db, Action)
            return actions and actions[0].state == "held"

        await until(held)
        action = (await rows(db, Action))[0]
        assert action.status_reason == "workspace_attachments_not_qualified"
        assert "workspace_attachments" in action.payload
        assert len(await rows(db, Artifact)) == 1
        assert not native.submitted and not list(path.iterdir())
    finally:
        await live.close()


async def test_uncertain_native_admission_is_not_retried_and_plaintext_is_retained_for_reconciliation(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(
        db, tmp_path, monkeypatch, mode="ambiguous"
    )
    live = pipeline.runtime()
    await live.start()
    try:
        server.input("分析 [input.bin](" + UPLOAD + ")")

        async def ambiguous():
            actions = await rows(db, Action)
            return actions and actions[0].state == "ambiguous"

        await until(ambiguous)
        await asyncio.sleep(0.1)
        assert len(native.submitted) == 1 and len(list(path.iterdir())) == 1
        assert await pipeline.incoming.journals[REF].prune_expired() == 0
    finally:
        await live.close()


async def test_input_resource_close_unregisters_only_its_own_realm_and_preserves_other_registration(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    routes = WorkspaceProviderRoutes()
    native.workspace_attachments = routes
    other = routes.register("other-realm", SimpleNamespace(qualified=lambda *_: False))
    await pipeline.incoming.start()
    try:
        assert len(routes._realms) == 2
        await pipeline.incoming.close()
        assert routes._realms == {"other-realm": other}
        assert all(j.files._fd == -1 for j in pipeline.incoming.journals.values())
        assert (
            pipeline.files.journal.artifacts.files._fd >= 0
        )  # shared outgoing store still owned there
    finally:
        await pipeline.close_files()
        await pipeline.scope.client.close()


async def test_bot_attachment_is_not_a_human_input_or_import_authority(db, tmp_path, monkeypatch):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    live = pipeline.runtime()
    await live.start()
    try:
        server.input("分析 [input.bin](" + UPLOAD + ")", author=11)
        await asyncio.sleep(0.15)
        assert not await rows(db, Action) and not associations.calls
        assert not native.submitted and not list(path.iterdir())
    finally:
        await live.close()


async def test_replaced_original_native_reader_client_revokes_runtime_readiness(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    await pipeline.incoming.start()
    reader = pipeline.incoming.readers[REF]
    try:
        assert pipeline.incoming.qualified(REF, INSTALLED_SCHEMA)
        reader.client = SimpleNamespace(workspace_attachments=native.workspace_attachments)
        assert not pipeline.incoming.qualified(REF, INSTALLED_SCHEMA)
    finally:
        await pipeline.close_files()
        await pipeline.scope.client.close()


async def test_registration_cleanup_failure_still_revokes_provider_and_closes_namespaces(
    db, tmp_path, monkeypatch
):
    pipeline, server, native, associations, path = await setup(db, tmp_path, monkeypatch)
    await pipeline.incoming.start()
    client, route, registration = pipeline.incoming._installed[0]
    route.unregister(registration)
    try:
        with pytest.raises(ValueError, match="registration_cleanup_failed"):
            await pipeline.incoming.close()
        assert pipeline.incoming.provider._closed
        assert all(j.files._fd == -1 for j in pipeline.incoming.journals.values())
        assert not pipeline.incoming.qualified(REF, INSTALLED_SCHEMA)
    finally:
        await pipeline.close_files()
        await pipeline.scope.client.close()
