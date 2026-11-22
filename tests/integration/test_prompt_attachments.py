"""Real encrypted artifact/SQL pipeline with synthetic HTTP and original sources."""

import gc
import json
import time
import weakref
from dataclasses import replace

import httpx
import pytest
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.attachments import (
    ATTACHMENT_SCHEMA,
    ATTACHMENT_SEMANTICS,
    InlineAttachmentAttestation,
    inline_files,
)
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.uploads import upload_reference
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, PromptAttachmentManifest
from jt_oz_bridge.security.downloads import DownloadDenied, DownloadOrigin, DownloadPolicy
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.prompt_attachments import (
    ArtifactPromptAttachmentProvider,
    SourceUploadAssociation,
    SourceUploadDescriptor,
    ZulipPromptAttachmentImporter,
    source_uploads,
)
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.storage.artifact_models import Artifact, ArtifactBudget
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Grant
from tests.contract.test_safe_download import DNS
from tests.integration.test_artifacts import service
from tests.integration.test_dispatch import SyntheticReader, message
from tests.support import REF

UPLOAD = "/user_uploads/2/random/original.txt"


class SyntheticUploadAssociations:
    """Local fixture authority only; does not qualify any installed Zulip API."""

    def __init__(self, size=22):
        self.active = True
        self.calls = []
        self.witnesses = []
        self.denied_paths = set()
        self.size = size
        self.metadata = {}

    async def authorize(self, source, uploads):
        self.calls.append((source.message_id, tuple(upload.path_id for upload in uploads)))
        if not self.active or any(upload.path_id in self.denied_paths for upload in uploads):
            raise AccessDenied("synthetic_per_path_association_denied")
        now = time.monotonic()
        witness = SourceUploadAssociation(
            source_sha256=digest(source.model_dump(mode="json")),
            upload_paths=tuple("/user_uploads/" + upload.path_id for upload in uploads),
            files=tuple(
                self.metadata.get(upload.path_id)
                or SourceUploadDescriptor(
                    upload_path="/user_uploads/" + upload.path_id,
                    filename=upload.filename,
                    mime_type="text/plain",
                    size=self.size,
                )
                for upload in uploads
            ),
            observation_sha256="c" * 64,
            observed_at=now,
            expires_at=now + 5,
        )
        self.witnesses.append(witness)
        return witness

    def current(self, witness):
        return self.active and any(witness is original for original in self.witnesses)


@pytest.mark.parametrize(
    "text,count",
    [
        (f"analyze [original.txt]({UPLOAD})", 1),
        (f"![original.txt]({UPLOAD})", 1),
        (f"[a]({UPLOAD}) and ![b]({UPLOAD})", 1),
        (f"[a](https://chat.example{UPLOAD})", 1),
        (f"`[a]({UPLOAD})`", 0),
        (f"```markdown\n[a]({UPLOAD})\n```", 0),
        (f'<a href="{UPLOAD}">not a Markdown upload</a>', 0),
        ("[ordinary](https://example.org/)", 0),
        (f"[a][ref]\n\n[ref]: {UPLOAD}", 1),
    ],
)
def test_only_markdown_upload_links_are_parsed_not_code_or_html(text, count):
    assert len(source_uploads(message(text=text), "https://chat.example")) == count


@pytest.mark.parametrize(
    "value",
    [
        "https://foreign.example" + UPLOAD,
        "/user_uploads/2/random/%2fetc%2fpasswd",
        "/user_uploads/2/random/name?signature=PRIVATE",
        "/user_uploads/2/random/%252e%252e",
        "//foreign.example" + UPLOAD,
    ],
)
def test_foreign_ambiguous_or_signed_original_links_cannot_be_imported(value):
    with pytest.raises((ValueError, DownloadDenied)):
        source_uploads(message(text=f"[file]({value})"), "https://chat.example")


def test_too_many_files_rejected_as_a_whole_not_silently_truncated():
    text = " ".join(f"[a](/user_uploads/2/random/file{i})" for i in range(11))
    with pytest.raises(ValueError, match="count"):
        source_uploads(message(text=text), "https://chat.example")


async def build(db, tmp_path, *, body=b"exact PRIVATE-CONTENT\r\n", declared=None):
    artifacts, binding, audience = await service(db, tmp_path)
    source = message(text=f"analyze [original.txt]({UPLOAD})")
    reader = SyntheticReader()
    reader.messages[source.message_id] = source
    queued = await QueueService(artifacts.bindings).receive(binding.id, source)
    seen = []

    async def identity():
        return True

    def api(request):
        seen.append(request)
        assert request.headers["authorization"].startswith("Basic ")
        assert request.url.path == "/api/v1" + UPLOAD
        return httpx.Response(
            200,
            json={
                "result": "success",
                "url": "https://files.example/blob?signature=PRIVATE-SIGNED",
            },
        )

    def download(request):
        seen.append(request)
        assert "authorization" not in request.headers and "cookie" not in request.headers
        assert request.url.host == "8.8.8.8" and request.headers["host"] == "files.example"
        headers = {"content-type": "text/plain"}
        if declared is not None:
            headers["content-length"] = str(declared)
        response = httpx.Response(200, headers=headers, content=body)
        if declared is None:
            response.headers.pop("content-length", None)
        return response

    zulip = ZulipClient(
        "https://chat.example",
        "synthetic@example",
        "synthetic-key",
        attestation=ZulipAttestation(
            "https://chat.example",
            "realm",
            11,
            500,
            10000,
            60,
            verified_file_operations=frozenset({"download"}),
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(api),
    )
    downloader = SafeDownloader(
        DownloadPolicy((DownloadOrigin("https://files.example"),), DNS()),
        maximum_file_bytes=1024,
        transport=httpx.MockTransport(download),
    )
    associations = SyntheticUploadAssociations(len(body))
    importer = ZulipPromptAttachmentImporter(
        artifacts, reader, zulip, downloader, associations=associations
    )
    attestation = InlineAttachmentAttestation(
        REF,
        ATTACHMENT_SCHEMA,
        ATTACHMENT_SEMANTICS,
        "a" * 64,
        verified_mime_types=frozenset(
            {"text/plain", "application/octet-stream", "application/pdf"}
        ),
    )
    provider = ArtifactPromptAttachmentProvider(
        artifacts, reader, zulip.url, {REF: attestation}, associations=associations
    )
    return (
        artifacts,
        binding,
        audience,
        source,
        reader,
        queued.action_id,
        zulip,
        downloader,
        importer,
        provider,
        seen,
    )


async def close(parts):
    parts[0].files.close()
    await parts[6].close()
    await parts[7].close()


async def imported(parts):
    source, action = parts[3], parts[5]
    receipt = await parts[8].import_one(
        action, source, upload_reference(UPLOAD, parts[6].url), remaining=MAX_ATTACHMENT_BYTES
    )
    manifest = PromptAttachmentManifest(files=(receipt,))
    async with parts[0].db.sessions.begin() as session:
        saved = await session.get(Action, action)
        payload = {**saved.payload, "attachments": manifest.model_dump(mode="json")}
        saved.payload = payload
        saved.operation_digest = digest(payload)
        saved.state = "dispatching"
        saved.version += 1
    return manifest


async def test_authenticated_source_download_encrypted_storage_and_inline_exact_bytes(
    db, tmp_path, caplog
):
    parts = await build(db, tmp_path)
    try:
        manifest = await imported(parts)
        (
            artifacts,
            binding,
            audience,
            source,
            reader,
            action,
            zulip,
            downloader,
            importer,
            provider,
            seen,
        ) = parts
        prepared = await provider.prepare(REF, action, source, manifest)
        assert prepared.files[0].content == b"exact PRIVATE-CONTENT\r\n"
        assert provider.current(REF, action, prepared)
        assert provider.qualified(REF, ATTACHMENT_SCHEMA)
        assert inline_files(manifest, prepared)[0]["uri"].startswith("data:text/plain;base64,")
        assert len(seen) == 2 and all(r.method == "GET" for r in seen)
        blob = next((tmp_path / "private-artifacts").glob("*.bin"))
        assert b"PRIVATE-CONTENT" not in blob.read_bytes()
        assert "PRIVATE-SIGNED" not in caplog.text
        async with db.sessions() as session:
            saved = await session.get(Artifact, manifest.files[0].artifact_id)
            own_action = await session.get(Action, action)
            assert saved.action_id == action and saved.source_message_id == source.message_id
            assert own_action.payload["attachments"] == manifest.model_dump(mode="json")
            assert "PRIVATE-SIGNED" not in json.dumps(own_action.payload)
    finally:
        await close(parts)


@pytest.mark.parametrize(
    "kind", ["source-edit", "wrong-link", "admitted", "revoked-grant", "remaining", "bot"]
)
async def test_untrusted_or_revoked_import_cannot_download_or_create_artifact(db, tmp_path, kind):
    parts = await build(db, tmp_path)
    (
        artifacts,
        binding,
        audience,
        source,
        reader,
        action,
        zulip,
        downloader,
        importer,
        provider,
        seen,
    ) = parts
    upload = upload_reference(UPLOAD, zulip.url)
    remaining = MAX_ATTACHMENT_BYTES
    if kind == "source-edit":
        reader.messages[source.message_id] = source.model_copy(update={"revision": 2})
    if kind == "wrong-link":
        upload = upload_reference("/user_uploads/2/random/other.txt", zulip.url)
    if kind == "admitted":
        async with db.sessions.begin() as session:
            (await session.get(Action, action)).state = "admitted"
    if kind == "revoked-grant":
        async with db.sessions.begin() as session:
            for grant in (await session.scalars(select(Grant))).all():
                grant.active = False
    if kind == "remaining":
        remaining = -1
    if kind == "bot":
        source = source.model_copy(update={"is_bot": True})
    try:
        with pytest.raises((AccessDenied, Conflict, ValueError)):
            await importer.import_one(action, source, upload, remaining=remaining)
        assert not seen
        async with db.sessions() as session:
            assert not (await session.scalars(select(Artifact))).all()
    finally:
        await close(parts)


@pytest.mark.parametrize("declared", [50, None])
async def test_total_size_limit_rejects_declared_or_streamed_overflow_and_releases_quota(
    db, tmp_path, declared
):
    parts = await build(db, tmp_path, body=b"x" * 50, declared=declared)
    # Exercise the HTTP size guard even when the separately attested metadata
    # was stale, rather than rejecting solely on metadata before download.
    parts[8].associations.size = 20
    try:
        with pytest.raises(ValueError):
            await parts[8].import_one(
                parts[5], parts[3], upload_reference(UPLOAD, parts[6].url), remaining=20
            )
        async with db.sessions() as session:
            budget = await session.get(ArtifactBudget, "global")
            assert budget is None or budget.reserved_bytes == budget.object_count == 0
        assert not list((tmp_path / "private-artifacts").iterdir())
    finally:
        await close(parts)


@pytest.mark.parametrize(
    "kind",
    [
        "action-state",
        "action-digest",
        "source-edit",
        "artifact-action",
        "artifact-source",
        "artifact-kind",
        "artifact-checksum",
        "artifact-descriptor",
        "grant-revoked",
        "audience",
        "wrong-ref",
        "missing-qualified",
    ],
)
async def test_resolution_revalidates_claim_source_artifact_and_current_authority(
    db, tmp_path, kind
):
    parts = await build(db, tmp_path)
    (
        artifacts,
        binding,
        audience,
        source,
        reader,
        action,
        zulip,
        downloader,
        importer,
        provider,
        seen,
    ) = parts
    try:
        manifest = await imported(parts)
        selected = REF
        async with db.sessions.begin() as session:
            saved = await session.get(Artifact, manifest.files[0].artifact_id)
            if kind == "action-state":
                (await session.get(Action, action)).state = "cancelled"
            if kind == "action-digest":
                (await session.get(Action, action)).operation_digest = "f" * 64
            if kind == "artifact-action":
                saved.action_id = "another-action"
            if kind == "artifact-source":
                saved.source_message_id += 1
            if kind == "artifact-kind":
                saved.kind = "output"
            if kind == "artifact-checksum":
                saved.checksum = "f" * 64
            if kind == "grant-revoked":
                for grant in (await session.scalars(select(Grant))).all():
                    grant.active = False
        if kind == "source-edit":
            reader.messages[source.message_id] = source.model_copy(update={"revision": 2})
        if kind == "artifact-descriptor":
            file = manifest.files[0].model_copy(update={"filename": "wrong.txt"})
            manifest = manifest.model_copy(update={"files": (file,)})
            async with db.sessions.begin() as session:
                saved = await session.get(Action, action)
                saved.payload = {**saved.payload, "attachments": manifest.model_dump(mode="json")}
                saved.operation_digest = digest(saved.payload)
        if kind == "audience":
            audience.users = frozenset({7, 8, 999})
        if kind == "wrong-ref":
            selected = REF.model_copy(update={"upstream_session_id": "other-session"})
        if kind == "missing-qualified":
            provider = ArtifactPromptAttachmentProvider(artifacts, reader, zulip.url, {})
        with pytest.raises((ValueError, AccessDenied, Conflict)):
            await provider.prepare(selected, action, source, manifest)
        assert all(request.method == "GET" for request in seen)
    finally:
        await close(parts)


async def test_prepared_witness_is_object_bound_expires_and_does_not_retain_plaintext(
    db, tmp_path, monkeypatch
):
    parts = await build(db, tmp_path)
    try:
        manifest = await imported(parts)
        provider = parts[9]
        prepared = await provider.prepare(REF, parts[5], parts[3], manifest)
        assert not provider.current(REF, parts[5], replace(prepared))
        assert not provider.current(REF, "other-action", prepared)
        held = weakref.ref(prepared)
        del prepared
        gc.collect()
        assert held() is None
        prepared = await provider.prepare(REF, parts[5], parts[3], manifest)
        current = time.monotonic()
        monkeypatch.setattr(
            "jt_oz_bridge.services.prompt_attachments.time.monotonic", lambda: current + 6
        )
        assert not provider.current(REF, parts[5], prepared)
    finally:
        await close(parts)


@pytest.mark.parametrize(
    "kind",
    ["missing", "denied", "wrong-source", "wrong-path", "expired", "future", "long-ttl", "copy"],
)
async def test_bot_readable_link_is_not_original_human_per_path_authorization(db, tmp_path, kind):
    parts = await build(db, tmp_path)
    importer = parts[8]
    associations = importer.associations
    if kind == "missing":
        importer.associations = None
    elif kind == "denied":
        associations.denied_paths.add(upload_reference(UPLOAD, parts[6].url).path_id)
    else:
        original = associations.authorize

        async def changed(source, uploads):
            witness = await original(source, uploads)
            now = time.monotonic()
            update = {
                "wrong-source": {"source_sha256": "0" * 64},
                "wrong-path": {"upload_paths": ("/user_uploads/2/private/other.txt",)},
                "expired": {"observed_at": now - 10, "expires_at": now - 5},
                "future": {"observed_at": now + 1, "expires_at": now + 3},
                "long-ttl": {"observed_at": now, "expires_at": now + 500},
                "copy": {},
            }[kind]
            other = witness.model_copy(update=update)
            if kind != "copy":
                associations.witnesses.append(other)
            return other

        associations.authorize = changed
    try:
        with pytest.raises(AccessDenied):
            await importer.import_one(
                parts[5],
                parts[3],
                upload_reference(UPLOAD, parts[6].url),
                remaining=MAX_ATTACHMENT_BYTES,
            )
        assert not parts[
            10
        ]  # No temporary-URL or download request, even though Bot could retrieve it.
        async with db.sessions() as session:
            assert not (await session.scalars(select(Artifact))).all()
    finally:
        await close(parts)


async def test_association_revocation_during_download_prevents_artifact_creation(db, tmp_path):
    parts = await build(db, tmp_path)
    associations = parts[8].associations
    original = parts[7].client._transport

    # The synthetic downloader's response is readable to the Bot, but this
    # original Human/message association disappears while bytes are in flight.
    def download(request):
        response = original.handler(request)
        associations.active = False
        return response

    parts[7].client._transport = httpx.MockTransport(download)
    try:
        with pytest.raises(AccessDenied):
            await parts[8].import_one(
                parts[5],
                parts[3],
                upload_reference(UPLOAD, parts[6].url),
                remaining=MAX_ATTACHMENT_BYTES,
            )
        assert len(parts[10]) == 2
        async with db.sessions() as session:
            assert not (await session.scalars(select(Artifact))).all()
    finally:
        await close(parts)


@pytest.mark.parametrize("kind", ["missing", "revoked", "replaced"])
async def test_dispatch_requires_fresh_file_association_after_import_and_until_native_send(
    db, tmp_path, kind
):
    parts = await build(db, tmp_path)
    try:
        manifest = await imported(parts)
        provider = parts[9]
        if kind == "missing":
            provider.associations = None
            assert not provider.qualified(REF, ATTACHMENT_SCHEMA)
            with pytest.raises(AccessDenied):
                await provider.prepare(REF, parts[5], parts[3], manifest)
        else:
            prepared = await provider.prepare(REF, parts[5], parts[3], manifest)
            assert provider.current(REF, parts[5], prepared)
            if kind == "revoked":
                provider.associations.active = False
            else:
                provider.associations = SyntheticUploadAssociations()
            assert not provider.current(REF, parts[5], prepared)
    finally:
        await close(parts)


async def test_installed_relative_temporary_url_downloads_from_original_realm_without_bot_auth(
    db, tmp_path
):
    parts = await build(db, tmp_path)
    parts[8].associations.size = len(b"actual-style relative URL bytes")
    zulip, downloader = parts[6], parts[7]
    seen = []

    def api(request):
        assert request.url.path == "/api/v1" + UPLOAD and request.headers[
            "authorization"
        ].startswith("Basic ")
        return httpx.Response(
            200,
            json={
                "result": "success",
                "url": "/user_uploads/temporary/PRIVATE-SIGNED/original.txt",
            },
        )

    def download(request):
        seen.append(request)
        assert request.url.host == "8.8.8.8" and request.headers["host"] == "chat.example"
        assert request.url.path == "/user_uploads/temporary/PRIVATE-SIGNED/original.txt"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        return httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"actual-style relative URL bytes"
        )

    zulip.client._transport = httpx.MockTransport(api)
    downloader.policy = DownloadPolicy(
        (DownloadOrigin("https://chat.example", path_prefixes=("/user_uploads/",)),), DNS()
    )
    downloader.client._transport = httpx.MockTransport(download)
    try:
        manifest = await imported(parts)
        prepared = await parts[9].prepare(REF, parts[5], parts[3], manifest)
        assert prepared.files[0].content == b"actual-style relative URL bytes" and len(seen) == 1
        async with db.sessions() as session:
            item = await session.get(Action, parts[5])
            assert "PRIVATE-SIGNED" not in json.dumps(item.payload)
    finally:
        await close(parts)


async def test_original_server_filename_and_mime_are_preserved_instead_of_sanitized_url_name(
    db, tmp_path
):
    parts = await build(db, tmp_path)
    path = upload_reference(UPLOAD, parts[6].url).path_id
    parts[8].associations.metadata[path] = SourceUploadDescriptor(
        upload_path=UPLOAD,
        filename="原始 [附件].txt",
        mime_type="application/octet-stream",
        size=parts[8].associations.size,
    )
    try:
        manifest = await imported(parts)
        assert (
            manifest.files[0].filename == "原始 [附件].txt"
            and manifest.files[0].mime_type == "application/octet-stream"
        )
        prepared = await parts[9].prepare(REF, parts[5], parts[3], manifest)
        assert (
            prepared.files[0].receipt == manifest.files[0]
            and prepared.files[0].content == b"exact PRIVATE-CONTENT\r\n"
        )
    finally:
        await close(parts)


@pytest.mark.parametrize("phase", ["download", "dispatch"])
async def test_metadata_name_or_size_changes_do_not_silently_relabel_imported_bytes(
    db, tmp_path, phase
):
    parts = await build(db, tmp_path)
    authority = parts[8].associations
    try:
        if phase == "download":
            original = authority.authorize

            async def change(source, uploads):
                witness = await original(source, uploads)
                if len(authority.calls) == 2:
                    file = witness.files[0].model_copy(update={"filename": "changed.txt"})
                    witness = witness.model_copy(update={"files": (file,)})
                    authority.witnesses.append(witness)
                return witness

            authority.authorize = change
            with pytest.raises(Conflict, match="metadata_or_size_changed"):
                await parts[8].import_one(
                    parts[5],
                    parts[3],
                    upload_reference(UPLOAD, parts[6].url),
                    remaining=MAX_ATTACHMENT_BYTES,
                )
            async with db.sessions() as session:
                assert not (await session.scalars(select(Artifact))).all()
        else:
            manifest = await imported(parts)
            path = upload_reference(UPLOAD, parts[6].url).path_id
            authority.metadata[path] = SourceUploadDescriptor(
                upload_path=UPLOAD,
                filename="changed.txt",
                mime_type="text/plain",
                size=authority.size,
            )
            with pytest.raises(Conflict, match="manifest_descriptor_changed"):
                await parts[9].prepare(REF, parts[5], parts[3], manifest)
    finally:
        await close(parts)
