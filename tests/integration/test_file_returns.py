"""Synthetic Native/source HTTP + real encrypted DB/outbox; no live Human data."""

import asyncio
import copy
import hashlib
import re
import time
from contextlib import asynccontextmanager
from email import policy
from email.parser import BytesParser
from html import unescape
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import unquote

import httpx
import pytest
from sqlalchemy import event, select, update

from jt_oz_bridge.adapters.opencode.files import FILE_SEMANTICS, NativeFileEvidence, NativeReadFile
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.file_upload import (
    UPLOAD_SEMANTICS,
    FileUploadAttestation,
    ZulipFileUploader,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.security.downloads import DownloadOrigin, DownloadPolicy
from jt_oz_bridge.services.artifacts import ArtifactService, FileDescriptor
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.file_returns import FileReturnJournal, requested_file
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch, Grant, WorkerLease
from tests.contract.test_safe_download import DNS
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_router import Source, message
from tests.support import REF, bound


async def chunks(value):
    for offset in range(0, len(value), 65536):
        yield value[offset : offset + 65536]


def multipart_file(request):
    """Validate one raw multipart file without decoding/copying the whole payload.

    BytesParser.parsebytes decodes a complete wire body into text, and parsing
    and get_payload(decode=True) make further complete copies. Keep the same
    standard parser for bounded headers, then compare the immutable body view.
    This is an independent receiver assertion, not an upload implementation.
    """
    outer = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + request.headers["content-type"].encode() + b"\r\n\r\n"
    )
    assert outer.get_content_type() == "multipart/form-data"
    boundary = outer.get_boundary()
    assert boundary and len(boundary) <= 70 and boundary.isascii()
    delimiter = b"--" + boundary.encode("ascii")
    wire = request.content
    assert wire.startswith(delimiter + b"\r\n")
    start = len(delimiter) + 2
    header_end = wire.find(b"\r\n\r\n", start, start + 16384)
    assert header_end >= start
    tail = b"\r\n" + delimiter + b"--\r\n"
    assert wire.endswith(tail)
    end = len(wire) - len(tail)
    assert wire.find(b"\r\n" + delimiter, header_end + 4, end) == -1
    header = BytesParser(policy=policy.default).parsebytes(wire[start:header_end] + b"\r\n\r\n")
    assert header.get_content_disposition() == "form-data"
    assert header.get_param("name", header="content-disposition") == "filename"
    assert header.get("Content-Transfer-Encoding") in (None, "binary")
    return header, memoryview(wire)[header_end + 4 : end]


class SyntheticFileWitness:
    def __init__(self, file):
        self.file, self.active = file, True

    def current(self, file):
        return self.active and file is self.file and time.time() < file.evidence.expires_at


@asynccontextmanager
async def setup(
    db,
    tmp_path,
    *,
    body=b"exact original file\r\n",
    path="reports/原始 [file].html",
    mime="text/html",
    limit=1000,
    initial_artifact=True,
):
    bindings, binding, control, audience = await bound(db)
    number = await DurableStore(db).acquire_lease("file-worker", ttl=120)
    fence = ConsumerFence("file-worker", number)
    store = ArtifactService(
        bindings,
        LocalArtifactFiles(tmp_path / "files"),
        db.cipher,
        reserve_free_bytes=0,
        fence=fence,
    )
    source = Source()
    human = message("!oz file " + path)
    source.messages[human.message_id] = human
    projection = NativeAttachmentProjection(
        filename=path.rsplit("/", 1)[-1],
        mime_type=mime,
        size=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )
    now = time.time()
    native = NativeReadFile(
        NativeFileEvidence(
            reference=REF,
            relative_path=path,
            projection=projection,
            etag='"synthetic"',
            contract_sha256=control.contract_hash,
            semantics_sha256=FILE_SEMANTICS,
            installed_evidence_sha256="a" * 64,
            native_policy_sha256="b" * 64,
            owner_epoch="owner",
            connection_epoch="connection",
            resource_fence="resource",
            observed_at=now,
            expires_at=now + 5,
        ),
        body,
    )
    witness = SyntheticFileWitness(native)
    artifact = (
        await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename=projection.filename, mime_type=mime),
            chunks(body),
            kind="output",
            expected_size=len(body),
            expected_sha256=projection.sha256,
            source_message_id=human.message_id,
        )
        if initial_artifact
        else None
    )
    remote = SimpleNamespace(
        posts=0,
        gets=0,
        downloads=0,
        mode="success",
        body=body,
        mime=mime,
        hook=None,
        entered=asyncio.Event(),
    )
    slug = re.sub(r"[^\w.-]", "-", projection.filename)
    upload_url = "/user_uploads/2/ab/opaque/" + slug

    async def api(request):
        assert request.headers["authorization"].startswith("Basic ")
        if request.method == "POST":
            remote.posts += 1
            assert request.url.path == "/api/v1/user_uploads"
            async with db.sessions() as session:
                row = (await session.scalars(select(FileTransfer))).one()
                assert row.state == "uploading" and row.attempts == remote.posts
            part, payload = multipart_file(request)
            assert (
                payload == body
                and unquote(unescape(part.get_filename())) == projection.filename
                and part.get_content_type() == mime
            )
            remote.entered.set()
            if remote.hook:
                await remote.hook()
            if remote.mode == "timeout":
                raise httpx.ReadTimeout("accepted, response unknown")
            if remote.mode == "wait":
                await asyncio.Event().wait()
            if remote.mode == "reject":
                return httpx.Response(403, json={"result": "error"})
            if remote.mode == "rate":
                return httpx.Response(
                    429,
                    headers={"retry-after": "1"},
                    json={"result": "error", "code": "RATE_LIMIT_HIT"},
                )
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "url": upload_url,
                    "uri": upload_url,
                    "filename": projection.filename,
                },
            )
        remote.gets += 1
        return httpx.Response(
            200, json={"result": "success", "url": "/user_uploads/temporary/PRIVATE-SIGNED/file"}
        )

    async def download(request):
        remote.downloads += 1
        assert request.url.host == "8.8.8.8" and request.headers["host"] == "chat.example"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        if remote.hook:
            await remote.hook()
        return httpx.Response(200, headers={"content-type": remote.mime}, content=remote.body)

    client = ZulipClient(
        "https://chat.example",
        "bot@example",
        "synthetic-only",
        attestation=ZulipAttestation(
            "https://chat.example",
            "realm",
            11,
            500,
            10000,
            60,
            verified_file_operations=frozenset({"upload", "download"}),
        ),
        verify_identity=AsyncMock(return_value=True),
        transport=httpx.MockTransport(api),
    )
    uploader = ZulipFileUploader(
        client, attestation=FileUploadAttestation("realm", 2, 11, 500, UPLOAD_SEMANTICS, "a" * 64)
    )
    downloader = SafeDownloader(
        DownloadPolicy((DownloadOrigin(client.url, path_prefixes=("/user_uploads/",)),), DNS()),
        transport=httpx.MockTransport(download),
    )
    outbox = Outbox(bindings, 11, fence=fence)
    service = FileReturnJournal(
        store,
        source,
        outbox,
        uploader,
        downloader,
        {REF: witness},
        message_limit=limit,
        topic_limit=60,
    )
    value = SimpleNamespace(
        service=service,
        binding=binding,
        source=source,
        human=human,
        file=native,
        witness=witness,
        artifact=artifact,
        remote=remote,
        client=client,
        uploader=uploader,
        downloader=downloader,
        store=store,
        outbox=outbox,
        audience=audience,
    )
    try:
        yield value
    finally:
        await client.close()
        await downloader.close()
        store.files.close()


async def prepared(value):
    return await value.service.prepare(value.artifact, value.human, value.file, locale="zh-TW")


async def all_rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


@pytest.mark.parametrize("filename", ["plain.bin", "原始 & [檔].html", "x%20.txt"])
@pytest.mark.parametrize("body", [b"", b"\x00\xff\r\nraw binary\x00"])
def test_bounded_multipart_receiver_agrees_with_standard_full_parser(filename, body):
    request = httpx.Request(
        "POST",
        "https://example.test/upload",
        files={"filename": (filename, body, "application/octet-stream")},
    )
    request.read()
    part, payload = multipart_file(request)
    old = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + request.headers["content-type"].encode() + b"\r\n\r\n" + request.content
    )
    expected = tuple(old.iter_parts())[0]
    assert payload == expected.get_payload(decode=True) == body
    assert part.get_filename() == expected.get_filename()
    assert part.get_content_type() == expected.get_content_type()
    assert payload.obj is request.content and payload.readonly


@pytest.mark.parametrize("changed", ["extra-part", "truncated"])
def test_bounded_multipart_receiver_rejects_additional_part_or_truncated_wire(changed):
    request = httpx.Request(
        "POST", "https://example.test/upload", files={"filename": ("a.bin", b"data")}
    )
    request.read()
    raw = request.content
    boundary = request.headers["content-type"].split("boundary=", 1)[1].encode()
    if changed == "extra-part":
        raw = raw.replace(
            b"\r\n--" + boundary + b"--",
            b"\r\n--"
            + boundary
            + b"\r\nContent-Disposition: form-data; name=other\r\n\r\nother\r\n--"
            + boundary
            + b"--",
        )
    else:
        raw = raw[:-1]
    malformed = httpx.Request(
        "POST", request.url, headers={"content-type": request.headers["content-type"]}, content=raw
    )
    with pytest.raises(AssertionError):
        multipart_file(malformed)


async def test_exact_file_upload_readback_and_same_topic_delivery_are_separate_durable_steps(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        assert await prepared(v) == identity
        assert await v.service.advance(identity) == "uploaded" and v.remote.posts == 1
        row, plan = await v.service.load(identity)
        assert (
            plan.upload.bytes_verified is False
            and not plan.bytes_verified
            and not await all_rows(db, Delivery)
        )
        assert await v.service.advance(identity) == "verified" and v.remote.downloads == 1
        assert await v.service.advance(identity) == "queued" and v.remote.posts == 1
        assert await v.service.advance(identity) == "queued"
        deliveries = await all_rows(db, Delivery)
        assert (
            len(deliveries) == 1
            and "原始" in deliveries[0].payload["content"]
            and "SHA-256" in deliveries[0].payload["content"]
        )
        assert "PRIVATE-SIGNED" not in str((await v.service.load(identity))[0].payload)
        chat = SyntheticChat()
        chat.bot_user_id = 11
        worker = DeliveryWorker(
            v.outbox,
            chat,
            "file-worker",
            v.service.fence.fencing,
            minimum_interval=0,
            file_returns=v.service,
        )
        assert await worker.advance(deliveries[0].id) == "delivered"
        actual = next(iter(chat.messages.values()))
        assert (actual.channel_id, actual.topic) == (v.binding.channel_id, v.binding.topic)
        assert actual.sender_id == 11 and len(chat.calls) == v.remote.posts == 1


async def test_restart_keeps_ack_original_filename_limits_and_one_upload(db, tmp_path):
    async with setup(db, tmp_path, limit=512) as v:
        identity = await prepared(v)
        await v.service.advance(identity)
        fresh = FileReturnJournal(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {REF: v.witness},
            message_limit=900,
            topic_limit=80,
        )
        assert await fresh.advance(identity) == "verified"
        assert await fresh.advance(identity) == "queued"
        row, plan = await fresh.load(identity)
        assert plan.message_limit == 512 and plan.locale == "zh-TW"
        before = (await all_rows(db, Delivery))[0].payload
        await fresh.publish(row, plan)
        assert (await all_rows(db, Delivery))[0].payload == before and v.remote.posts == 1


async def test_two_workers_claim_only_one_upload_and_publication_batch(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        results = await asyncio.gather(*(v.service.advance(identity) for _ in range(2)))
        assert v.remote.posts == 1 and set(results) <= {"uploading", "uploaded", "verified"}
        while (await v.service.load(identity))[0].state != "verified":
            await v.service.advance(identity)
        row, plan = await v.service.load(identity)
        batches = await asyncio.gather(*(v.service.publish(row, plan) for _ in range(2)))
        assert batches[0] == batches[1] and len(await all_rows(db, DeliveryBatch)) == 1


@pytest.mark.parametrize(
    "mode,state", [("timeout", "ambiguous"), ("reject", "rejected"), ("rate", "prepared")]
)
async def test_upload_failures_keep_positive_rejection_distinct_from_unknown_post(
    db, tmp_path, mode, state
):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        v.remote.mode = mode
        assert await v.service.advance(identity) == state
        for _ in range(3):
            assert await v.service.advance(identity) == state
        assert v.remote.posts == 1 and not await all_rows(db, Delivery)


async def test_cancel_during_upload_retains_ambiguous_evidence_without_retry(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        v.remote.mode = "wait"
        task = asyncio.create_task(v.service.advance(identity))
        await asyncio.wait_for(v.remote.entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await v.service.load(identity))[0].state == "ambiguous"
        assert await v.service.advance(identity) == "ambiguous" and v.remote.posts == 1


async def test_known_not_sent_is_held_without_an_http_upload(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        v.client.verify_identity = AsyncMock(return_value=False)
        assert await v.service.advance(identity) == "held" and v.remote.posts == 0


@pytest.mark.parametrize(
    "change", ["source", "actor", "revision", "public", "audience", "grant", "artifact"]
)
async def test_source_scope_and_revocation_stop_upload_before_network(db, tmp_path, change):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        if change in {"source", "actor"}:
            v.source.messages[101] = v.human.model_copy(
                update={"text": "!oz file other.txt"} if change == "source" else {"author_id": 8}
            )
        elif change == "public":
            v.audience.private = False
        elif change == "audience":
            v.audience.users = frozenset({7, 8, 999})
        else:
            async with db.sessions.begin() as session:
                if change == "revision":
                    await session.execute(update(Binding).values(revision=2))
                elif change == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                elif change == "artifact":
                    await session.execute(update(Artifact).values(checksum="f" * 64))
        assert await v.service.advance(identity) == "held" and v.remote.posts == 0
        assert not await all_rows(db, Delivery)


async def test_revoke_during_upload_preserves_ack_but_never_posts_link(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)

        async def revoke():
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))

        v.remote.hook = revoke
        assert await v.service.advance(identity) == "uploaded"
        v.remote.hook = None
        assert await v.service.advance(identity) == "held"
        _, plan = await v.service.load(identity)
        assert plan.upload is not None and not plan.bytes_verified and v.remote.posts == 1
        assert not await all_rows(db, Delivery)


@pytest.mark.parametrize("change", ["bytes", "mime", "truncated", "grant-during-download"])
async def test_uploaded_file_must_be_read_back_exactly_before_any_link_is_queued(
    db, tmp_path, change
):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        await v.service.advance(identity)
        if change == "bytes":
            v.remote.body = b"x" * len(v.remote.body)
        elif change == "mime":
            v.remote.mime = "application/octet-stream"
        elif change == "truncated":
            v.remote.body = v.remote.body[:-1]
        else:

            async def revoke():
                async with db.sessions.begin() as session:
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )

            v.remote.hook = revoke
        assert await v.service.advance(identity) == "held"
        assert v.remote.posts == 1 and not await all_rows(db, Delivery)
        assert (await v.service.load(identity))[1].upload is not None


async def test_atomic_outbox_failure_rolls_back_batch_and_recovery_never_reuploads(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        await v.service.advance(identity)
        await v.service.advance(identity)

        def fail(*args):
            raise OSError("synthetic SQL publication failure")

        event.listen(DeliveryBatch, "before_insert", fail)
        # Core INSERT statements do not run ORM insert events; fail the journal
        # update after its in-session batch INSERT to test the atomic boundary.
        event.remove(DeliveryBatch, "before_insert", fail)
        event.listen(FileTransfer, "before_update", fail)
        try:
            with pytest.raises(OSError):
                await v.service.advance(identity)
        finally:
            event.remove(FileTransfer, "before_update", fail)
        assert not await all_rows(db, DeliveryBatch) and not await all_rows(db, Delivery)
        assert (await v.service.load(identity))[0].state == "verified"
        assert await v.service.advance(identity) == "queued" and v.remote.posts == 1


async def test_lost_ack_commit_stays_uploading_and_successor_marks_ambiguous(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        original = v.service.save

        async def failed(*args, **kwargs):
            raise OSError("lost local ACK commit")

        v.service.save = failed
        with pytest.raises(OSError):
            await v.service.advance(identity)
        v.service.save = original
        assert (await v.service.load(identity))[0].state == "uploading"
        assert await v.service.advance(identity) == "uploading" and v.remote.posts == 1
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=0))
        n = await DurableStore(db).acquire_lease("file-successor")
        v.service.fence = ConsumerFence("file-successor", n)
        assert await v.service.recover_uploading(before=time.time()) == 1
        assert await v.service.advance(identity) == "ambiguous" and v.remote.posts == 1


@pytest.mark.parametrize("change", ["index", "hash", "state", "source", "native"])
async def test_encrypted_plan_and_index_corruption_cannot_repeat_or_redirect_upload(
    db, tmp_path, change
):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        async with db.sessions.begin() as session:
            row = await session.get(FileTransfer, identity)
            if change == "index":
                row.actor_id = 8
            elif change == "hash":
                row.payload_hash = "f" * 64
            elif change == "state":
                row.state = "verified"
            else:
                p = copy.deepcopy(row.payload)
                if change == "source":
                    p["source"]["is_bot"] = True
                else:
                    p["native"]["relative_path"] = "other/path.txt"
                row.payload = p
                row.payload_hash = digest(p)
        with pytest.raises(ValueError):
            await v.service.advance(identity)
        assert v.remote.posts == 0 and not await all_rows(db, Delivery)


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "a/.env.local",
        ".ssh/id_ed25519",
        "secrets/config.json",
        "a/credentials/token",
        "key.key",
        "../escape",
        "/absolute",
        "a/../bad",
        "auth.json",
        ".docker/config.json",
        ".git-credentials",
        "terraform.tfstate",
    ],
)
def test_default_sensitive_and_escaping_workspace_paths_are_not_file_commands(path):
    with pytest.raises(ValueError):
        requested_file(message("!oz file " + path))


@pytest.mark.parametrize(
    "body",
    [
        b'password="PRIVATE-value"',
        b'{"token":"PRIVATE-value"}',
        b"x" * 65530 + b" sk-" + b"A" * 24,
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key",
    ],
    ids=("env", "json", "split-token", "private-key"),
)
async def test_recognizable_credentials_are_rejected_without_rewriting_original_bytes(
    db, tmp_path, body
):
    async with setup(db, tmp_path, body=body) as v:
        with pytest.raises(ValueError):
            await prepared(v)
        assert v.remote.posts == 0 and not await all_rows(db, FileTransfer)
        assert (await v.store.read(v.artifact, "realm", 7)).content == body


@pytest.mark.parametrize("kind", ["copy", "expired", "inactive"])
async def test_only_original_enrolled_native_file_witness_can_prepare_transfer(db, tmp_path, kind):
    async with setup(db, tmp_path) as v:
        if kind == "copy":
            v.file = NativeReadFile(v.file.evidence, v.file.content)
        elif kind == "expired":
            v.file = NativeReadFile(
                v.file.evidence.model_copy(update={"expires_at": time.time() - 1}), v.file.content
            )
        else:
            v.witness.active = False
        with pytest.raises(ValueError):
            await prepared(v)
        assert not await all_rows(db, FileTransfer)


async def test_encrypted_metadata_and_incomplete_transfer_retention(db, tmp_path):
    async with setup(db, tmp_path, path="PRIVATE-FILE.txt", mime="text/plain") as v:
        identity = await prepared(v)
        assert b"PRIVATE-FILE" not in (tmp_path / "test.db").read_bytes()
        async with db.sessions.begin() as session:
            await session.execute(
                update(Artifact).where(Artifact.id == v.artifact).values(expires_at=0)
            )
        async with db.sessions() as session:
            saved = await session.get(Artifact, v.artifact)
        assert await v.store.protected(saved)
        await v.service.advance(identity)
        await v.service.advance(identity)
        await v.service.advance(identity)
        assert await v.store.protected(saved)
        async with db.sessions.begin() as session:
            await session.execute(update(Delivery).values(state="delivered", posted_message_id=1))
        assert not await v.store.protected(saved)


@pytest.mark.parametrize("size", [0, MAX_ATTACHMENT_BYTES], ids=("empty", "twenty-mib"))
async def test_empty_and_twenty_mib_files_keep_exact_bytes_through_upload_and_readback(
    db, tmp_path, size
):
    async with setup(
        db, tmp_path, body=b"x" * size, path="data.bin", mime="application/octet-stream"
    ) as v:
        identity = await prepared(v)
        assert await v.service.advance(identity) == "uploaded"
        assert await v.service.advance(identity) == "verified"
        assert await v.service.advance(identity) == "queued"
        assert v.remote.posts == v.remote.downloads == 1
        assert (await v.service.load(identity))[1].projection.size == size


async def test_escaped_long_display_name_uses_short_label_but_keeps_file_name_and_frozen_cap(
    db, tmp_path
):
    name = "[" * 60 + ".txt"
    async with setup(db, tmp_path, path=name, mime="text/plain", limit=512) as v:
        identity = await prepared(v)
        for _ in range(3):
            await v.service.advance(identity)
        row, plan = await v.service.load(identity)
        assert row.state == "queued" and plan.upload.filename_stored == name
        body = (await all_rows(db, Delivery))[0].payload["content"]
        assert len(body) <= 512 and "下載檔案" in body


async def test_old_fence_cannot_start_upload_after_lease_expires(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=0))
        with pytest.raises(Conflict):
            await v.service.advance(identity)
        assert v.remote.posts == 0 and (await v.service.load(identity))[0].state == "prepared"


@pytest.mark.parametrize(
    "change",
    ["missing-guard", "source-edit", "source-delete", "operator-revoked", "artifact", "batch"],
)
async def test_file_delivery_rechecks_original_command_and_scope_even_after_queue(
    db, tmp_path, change
):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        for _ in range(3):
            await v.service.advance(identity)
        delivery = (await all_rows(db, Delivery))[0]
        if change == "source-edit":
            v.source.messages[101] = v.human.model_copy(
                update={"text": "!oz file other.txt", "revision": 1}
            )
        elif change == "source-delete":
            v.source.messages[101] = v.human.model_copy(update={"deleted": True})
        elif change != "missing-guard":
            async with db.sessions.begin() as session:
                if change == "operator-revoked":
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == 7, Grant.role.in_(("operator", "administrator")))
                        .values(active=False)
                    )
                elif change == "artifact":
                    await session.execute(update(Artifact).values(state="quarantined"))
                else:
                    await session.execute(
                        update(DeliveryBatch).values(renderer_version="corrupted")
                    )
        chat = SyntheticChat()
        chat.bot_user_id = 11
        worker = DeliveryWorker(
            v.outbox,
            chat,
            "file-worker",
            v.service.fence.fencing,
            minimum_interval=0,
            file_returns=None if change == "missing-guard" else v.service,
        )
        assert await worker.advance(delivery.id) == "held" and not chat.calls
        assert v.remote.posts == 1


async def test_scheduler_advances_known_receipts_and_skips_queued_held_or_delayed_work(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        assert await v.service.next_pending() is None
        identity = await prepared(v)
        assert await v.service.next_pending() == identity
        await v.service.advance(identity)
        assert await v.service.next_pending() == identity
        await v.service.advance(identity)
        assert await v.service.next_pending() == identity
        await v.service.advance(identity)
        assert await v.service.next_pending() is None


@pytest.mark.parametrize(
    "body",
    [
        b'api_key = os.environ["EXAMPLE_KEY"]\n',
        b"client = Client(api_key=token_variable)\n",
        b'{"password": environment_value}',
    ],
    ids=("environment", "argument", "object-variable"),
)
async def test_code_that_only_references_credentials_remains_an_ordinary_unchanged_file(
    db, tmp_path, body
):
    async with setup(db, tmp_path, body=body, path="example.py", mime="text/x-python") as v:
        identity = await prepared(v)
        for _ in range(3):
            await v.service.advance(identity)
        assert (await v.service.load(identity))[0].state == "queued"
        assert (await v.store.read(v.artifact, "realm", 7)).content == body
        assert v.remote.posts == 1


@pytest.mark.parametrize(
    "body",
    [
        b'api_key = "sk-" + "not-a-token"\npassword="actual-secret"\n',
        b'password = "actual-secret"\n',
        b"client(api_key=sk-AAAAAAAAAAAAAAAAAAAAAAAA)",
    ],
    ids=("literal-key", "literal-password", "token-shape"),
)
async def test_code_reference_exception_does_not_hide_literal_or_formatted_credentials(
    db, tmp_path, body
):
    async with setup(db, tmp_path, body=body, path="example.py", mime="text/x-python") as v:
        with pytest.raises(ValueError):
            await prepared(v)
        assert v.remote.posts == 0


async def test_successor_recovery_never_reads_or_changes_another_realms_upload(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        async with db.sessions.begin() as session:
            await session.execute(
                update(FileTransfer)
                .where(FileTransfer.id == identity)
                .values(
                    realm_id="foreign-realm",
                    state="uploading",
                    holder="previous",
                    fencing=0,
                    updated_at=time.time() - 30,
                )
            )
        # Even a foreign row whose encrypted/header relation cannot be decoded
        # by this realm must not be inspected as part of this realm's recovery.
        assert await v.service.recover_uploading(before=time.time()) == 0
        async with db.sessions() as session:
            row = await session.get(FileTransfer, identity)
            assert row.realm_id == "foreign-realm" and row.state == "uploading"


@pytest.mark.parametrize(
    "cutoff",
    [float("nan"), float("inf"), True, "invalid", time.time() + 3600],
    ids=("not-finite", "infinite", "boolean", "non-numeric", "future"),
)
async def test_file_recovery_refuses_invalid_or_future_cutoffs(db, tmp_path, cutoff):
    async with setup(db, tmp_path) as v:
        with pytest.raises(ValueError, match="cutoff_invalid"):
            await v.service.recover_uploading(before=cutoff)


@pytest.mark.parametrize(
    "state", ["prepared", "uploaded", "verified", "queued", "held", "ambiguous"]
)
async def test_actual_retention_preserves_pending_or_uncertain_file_bytes(db, tmp_path, state):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        if state == "held":
            v.source.messages[v.human.message_id] = v.human.model_copy(update={"deleted": True})
            assert await v.service.advance(identity) == "held"
        elif state == "ambiguous":
            v.remote.mode = "timeout"
            assert await v.service.advance(identity) == "ambiguous"
        else:
            for expected in ("uploaded", "verified", "queued")[
                : ["prepared", "uploaded", "verified", "queued"].index(state)
            ]:
                assert await v.service.advance(identity) == expected
        async with db.sessions.begin() as session:
            await session.execute(
                update(Artifact).where(Artifact.id == v.artifact).values(expires_at=0)
            )
        assert await v.store.prune_expired(v.store.fence.holder, v.store.fence.fencing) == 0
        assert (await all_rows(db, Artifact))[0].state == "ready"
        assert (await v.store.read(v.artifact, "realm", 7)).content == v.file.content


async def test_actual_retention_releases_file_only_after_all_delivery_evidence_is_terminal(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        identity = await prepared(v)
        for _ in range(3):
            await v.service.advance(identity)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Artifact).where(Artifact.id == v.artifact).values(expires_at=0)
            )
            await session.execute(update(Delivery).values(state="delivered", posted_message_id=1))
        assert await v.store.prune_expired(v.store.fence.holder, v.store.fence.fencing) == 1
        assert (await all_rows(db, Artifact))[0].state == "deleted"
        assert (await v.service.load(identity))[0].state == "queued"


async def test_prepare_rechecks_artifact_state_inside_the_shared_fence(db, tmp_path, monkeypatch):
    async with setup(db, tmp_path) as v:
        original = v.service.operator_lock

        async def change(session, binding, actor):
            await original(session, binding, actor)
            await session.execute(
                update(Artifact)
                .where(Artifact.id == v.artifact)
                .values(state="deleting", version=Artifact.version + 1)
            )

        monkeypatch.setattr(v.service, "operator_lock", change)
        with pytest.raises(Conflict, match="artifact_changed_before_prepare"):
            await prepared(v)
        assert not await all_rows(db, FileTransfer) and v.remote.posts == 0
