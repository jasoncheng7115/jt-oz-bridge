"""Synthetic original Human/Native graph and actual encrypted own DB; no live acceptance."""

import asyncio
import base64
import hashlib
import time
from contextlib import asynccontextmanager
from dataclasses import replace

import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import IntegrityError

from jt_oz_bridge.adapters.opencode.files import FILE_SEMANTICS, NativeFileEvidence
from jt_oz_bridge.adapters.opencode.generated_files import (
    BYTE_FEATURES,
    BYTE_SEMANTICS,
    OUTPUT_FEATURES,
    OUTPUT_SEMANTICS,
    GeneratedByteEvidence,
    GeneratedBytesAttestation,
    GeneratedDiscoveryEvidence,
    GeneratedFile,
    GeneratedFileAttestation,
    GeneratedFileBytes,
    GeneratedFiles,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.file_returns import FileReturnJournal
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.services.generated_output_plans import GeneratedFileReturnPlan, read_intent
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.resource_execution_results import ResourceResultCollector
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedOutputRecord
from jt_oz_bridge.storage.models import Action, Delivery, Grant, WorkerLease
from jt_oz_bridge.storage.resource_models import ResourceResultRecord
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_file_returns import all_rows
from tests.integration.test_file_returns import setup as file_setup
from tests.integration.test_resource_execution_results import Reader
from tests.integration.test_router import message
from tests.support import REF


class GeneratedReader:
    """Domain-only witness double. Actual HTTP/object identity is covered by contracts."""

    def __init__(self, result, body, kind, reference=REF):
        self.result, self.body, self.kind = result, body, kind
        self.reference = reference
        self.filename, self.mime_type = "結果.html", "text/html"
        self.alive, self.calls, self.reads = True, 0, 0
        self.metadata = GeneratedFileAttestation(
            reference, INSTALLED_SCHEMA, OUTPUT_SEMANTICS, "1" * 64, OUTPUT_FEATURES
        )
        self.byte_certificate = GeneratedBytesAttestation(
            reference, INSTALLED_SCHEMA, BYTE_SEMANTICS, "2" * 64, BYTE_FEATURES
        )

    def require(self, ref):
        assert ref == self.reference
        return self.metadata

    def require_bytes(self, ref):
        assert ref == self.reference
        return self.byte_certificate

    async def capture(self, correlation):
        self.calls += 1
        now = time.time()
        self.turn = self.result.evidence.model_copy(
            update={"observed_at": now, "expires_at": now + 5}
        )
        assert self.turn.correlation == correlation
        self.projection = NativeAttachmentProjection(
            filename=self.filename,
            mime_type=self.mime_type,
            size=len(self.body),
            sha256=hashlib.sha256(self.body).hexdigest(),
        )
        item = dict(
            origin="snapshot",
            assistant_id="msg_synthetic_final",
            file_index=0,
            kind="workspace",
            path="reports/" + self.filename,
            name=self.filename,
        )
        if self.kind == "inline":
            uri = "data:" + self.mime_type + ";base64," + base64.b64encode(self.body).decode()
            item = dict(
                origin="tool",
                assistant_id="msg_synthetic_final",
                file_index=0,
                content_index=1,
                tool_id="call_fixture",
                kind="inline",
                name=self.filename,
                mime_type=self.mime_type,
                size=len(self.body),
                sha256=self.projection.sha256,
                uri_sha256=hashlib.sha256(uri.encode()).hexdigest(),
            )
        files = (GeneratedFile(**item),)
        evidence = digest(
            {
                "turn": self.turn.model_dump(mode="json"),
                "outputs": [f.model_dump(mode="json") for f in files],
                "hidden": 0,
                "unsupported": 0,
                "semantics": OUTPUT_SEMANTICS,
            }
        )
        self.outputs = GeneratedFiles(
            self.reference,
            correlation.action_id,
            correlation.operation_digest,
            self.turn.owner_epoch,
            "succeeded",
            files,
            0,
            0,
            evidence,
            now,
            now + 5,
        )
        return self.outputs

    async def read(self, outputs, selection):
        self.reads += 1
        assert outputs is self.outputs and selection is outputs.files[0]
        self.value = GeneratedFileBytes(
            outputs, selection, self.projection, self.body, time.time(), outputs.expires_at
        )
        return self.value

    def current_bytes(self, value):
        return (
            self.alive and value is getattr(self, "value", None) and time.time() < value.expires_at
        )

    def current(self, outputs):
        return (
            self.alive
            and outputs is getattr(self, "outputs", None)
            and time.time() < outputs.expires_at
        )

    def discovery_evidence(self, outputs):
        if not self.current(outputs):
            raise Conflict("synthetic_discovery_not_current")
        return GeneratedDiscoveryEvidence(
            turn=self.turn,
            files=outputs.files,
            hidden_count=outputs.hidden_count,
            unsupported_count=outputs.unsupported_count,
            metadata_sha256=outputs.evidence_sha256,
            metadata_attestation_sha256=self.metadata.installed_evidence_sha256,
        )

    def evidence(self, value):
        if not self.current_bytes(value):
            raise Conflict("synthetic_original_byte_witness_expired")
        native = None
        if self.kind == "workspace":
            native = NativeFileEvidence(
                reference=self.reference,
                relative_path=value.selection.path,
                projection=value.projection,
                etag='"synthetic"',
                contract_sha256=INSTALLED_SCHEMA,
                semantics_sha256=FILE_SEMANTICS,
                installed_evidence_sha256="3" * 64,
                native_policy_sha256="4" * 64,
                owner_epoch=self.turn.owner_epoch,
                connection_epoch=self.turn.connection_epoch,
                resource_fence=self.turn.resource_fence,
                observed_at=self.turn.observed_at,
                expires_at=self.turn.expires_at,
            )
        return GeneratedByteEvidence(
            turn=self.turn,
            selection=value.selection,
            files=value.outputs.files,
            hidden_count=0,
            unsupported_count=0,
            metadata_sha256=value.outputs.evidence_sha256,
            metadata_attestation_sha256=self.metadata.installed_evidence_sha256,
            byte_attestation_sha256=self.byte_certificate.installed_evidence_sha256,
            projection=value.projection,
            native=native,
            observed_at=value.observed_at,
            expires_at=value.expires_at,
        )


def journal(v):
    return GeneratedFileReturnJournal(
        v.store,
        v.source,
        v.outbox,
        v.uploader,
        v.downloader,
        {},
        generated_readers={REF: v.reader},
        message_limit=10000,
        topic_limit=60,
    )


@asynccontextmanager
async def setup(
    db,
    tmp_path,
    *,
    body=b"<html>PRIVATE_GENERATED_ORIGINAL</html>\x00\xff",
    kind="inline",
    automatic=False,
):
    async with file_setup(
        db, tmp_path, body=body, path="reports/結果.html", mime="text/html", initial_artifact=False
    ) as v:
        execution = SyntheticExecution()
        execution.contract_hash = INSTALLED_SCHEMA
        v.store.bindings.control = execution
        async with db.sessions.begin() as session:
            await session.execute(update(EnrolledBackend).values(contract_hash=INSTALLED_SCHEMA))
        v.human = message("Create the original dashboard", 101)
        v.source.messages[101] = v.human
        queue = await QueueService(v.store.bindings).receive(v.binding.id, v.human)
        dispatcher = Dispatcher(
            v.store.bindings, execution, v.source, v.store.fence.holder, v.store.fence.fencing
        )
        assert await dispatcher.advance(queue.action_id) == "admitted"
        resource_reader = Reader()
        v.action_id, v.execution, v.dispatcher = queue.action_id, execution, dispatcher
        v.reader = GeneratedReader(None, body, kind)
        v.reader.turns, v.reader.file_reader = resource_reader, v.witness
        v.service = journal(v)
        v.capture = GeneratedCaptureService(v.service) if automatic else None
        collector = ResourceResultCollector(
            v.store.bindings, resource_reader, v.store.fence, capture=v.capture
        )
        result = await collector.collect(queue.action_id, "realm")
        v.reader.result = result
        v.collector = collector
        yield v


@pytest.mark.parametrize("kind", ["workspace", "inline"])
@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("body", [b"", b"<html>PRIVATE_GENERATED_ORIGINAL</html>\x00\xff"])
async def test_original_action_exact_bytes_encrypted_storage_upload_readback_and_same_topic(
    db, tmp_path, kind, locale, body
):
    async with setup(db, tmp_path, kind=kind, body=body) as v:
        identity = await v.service.capture_generated(v.action_id, 0, locale=locale)
        row, plan = await v.service.load(identity)
        assert isinstance(plan, GeneratedFileReturnPlan) and plan.source == v.human
        assert not plan.source.text.startswith("!oz file")
        assert plan.evidence.selection.kind == kind and (plan.evidence.native is None) == (
            kind == "inline"
        )
        assert (await v.service.content(plan)).content == body
        intent_row = (await all_rows(db, GeneratedOutputRecord))[0]
        intent = read_intent(intent_row)
        assert intent_row.transfer_id == identity and intent.artifact_id == plan.artifact_id
        artifact = (await all_rows(db, Artifact))[0]
        assert artifact.action_id == v.action_id and artifact.source_message_id == 101
        async with db.engine.connect() as connection:
            storage_type, encrypted = (
                await connection.execute(
                    text("SELECT typeof(payload),payload FROM generated_output_records")
                )
            ).one()
            assert storage_type == "blob" and b"Create the original dashboard" not in encrypted
        assert b"PRIVATE_GENERATED_ORIGINAL" not in v.store.files.read(
            artifact.id, v.store.maximum + 8192
        )
        for expected in ("uploaded", "verified", "queued", "queued"):
            assert await v.service.advance(identity) == expected
        delivery = (await all_rows(db, Delivery))[0]
        chat = SyntheticChat()
        chat.bot_user_id = 11
        worker = DeliveryWorker(
            v.outbox,
            chat,
            v.store.fence.holder,
            v.store.fence.fencing,
            minimum_interval=0,
            file_returns=v.service,
        )
        assert await worker.advance(delivery.id) == "delivered"
        assert len(chat.calls) == v.remote.posts == v.remote.downloads == 1
        sent = next(iter(chat.messages.values()))
        assert (sent.channel_id, sent.topic) == (v.human.channel_id, v.human.topic)
        assert len(await all_rows(db, Artifact)) == len(await all_rows(db, FileTransfer)) == 1


async def test_restart_reuses_sealed_artifact_without_reading_a_later_native_turn(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        v.reader.alive = False
        v.reader.body = b"later output must not replace captured bytes"
        v.service = journal(v)
        assert await v.service.capture_generated(v.action_id, 0) == identity
        assert v.reader.calls == v.reader.reads == 1
        for expected in ("uploaded", "verified", "queued"):
            assert await v.service.advance(identity) == expected
        assert v.remote.posts == 1


@pytest.mark.parametrize(
    "changed", ["source", "grant", "audience", "revision", "lease", "action-state", "result-index"]
)
async def test_revocation_before_capture_never_creates_artifact_or_posts(db, tmp_path, changed):
    async with setup(db, tmp_path) as v:
        await mutate(db, v, changed)
        with pytest.raises(ValueError):
            await v.service.capture_generated(v.action_id, 0)
        assert not await all_rows(db, Artifact) and not await all_rows(db, FileTransfer)
        assert not v.remote.posts


async def mutate(db, v, changed):
    if changed == "source":
        v.source.messages[101] = v.human.model_copy(update={"text": "changed", "revision": 2})
    elif changed == "audience":
        v.audience.users |= {999}
    elif changed == "certificate":
        v.reader.byte_certificate = replace(
            v.reader.byte_certificate, installed_evidence_sha256="9" * 64
        )
    else:
        async with db.sessions.begin() as session:
            if changed == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            elif changed == "revision":
                await session.execute(update(Binding).values(revision=2))
            elif changed == "lease":
                await session.execute(update(WorkerLease).values(expires_at=0))
            elif changed == "result-index":
                await session.execute(update(ResourceResultRecord).values(source_hash="0" * 64))
            elif changed == "action-state":
                await session.execute(update(Action).values(state="failed"))
            elif changed == "artifact":
                await session.execute(update(Artifact).values(action_id="different-action"))
            elif changed == "intent":
                await session.execute(update(GeneratedOutputRecord).values(payload_hash="0" * 64))
            else:
                await session.execute(update(Action).values(version=Action.version + 1))


@pytest.mark.parametrize(
    "changed",
    [
        "source",
        "grant",
        "audience",
        "revision",
        "action",
        "result-index",
        "artifact",
        "intent",
        "certificate",
    ],
)
async def test_changed_causal_provenance_after_prepare_is_held_before_upload(db, tmp_path, changed):
    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        await mutate(db, v, changed)
        assert await v.service.advance(identity) == "held"
        assert not v.remote.posts


@pytest.mark.parametrize("change", [False, True])
async def test_crash_after_artifact_commit_recovers_same_reserved_identity_and_original_bytes(
    db, tmp_path, monkeypatch, change
):
    async with setup(db, tmp_path) as v:
        original = v.store.create

        async def crash(*args, **kwargs):
            await original(*args, **kwargs)
            raise OSError("synthetic crash after encrypted artifact commit")

        monkeypatch.setattr(v.store, "create", crash)
        with pytest.raises(OSError):
            await v.service.capture_generated(v.action_id, 0)
        before = (await all_rows(db, GeneratedOutputRecord))[0]
        artifact = (await all_rows(db, Artifact))[0]
        assert artifact.id == before.reserved_artifact_id and before.transfer_id is None
        assert await v.store.protected(artifact)
        monkeypatch.setattr(v.store, "create", original)
        v.service = journal(v)
        if change:
            v.reader.body = b"changed original tool output"
            with pytest.raises(Conflict, match="pinned_origin_or_bytes"):
                await v.service.capture_generated(v.action_id, 0)
            assert not await all_rows(db, FileTransfer)
        else:
            identity = await v.service.capture_generated(v.action_id, 0)
            assert (await v.service.load(identity))[1].artifact_id == artifact.id
        assert (
            len(await all_rows(db, Artifact)) == len(await all_rows(db, GeneratedOutputRecord)) == 1
        )
        assert not v.remote.posts


async def test_uncertain_or_failed_staging_is_not_replaced_by_new_artifact(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path) as v:
        original = v.store.files.write

        def crash(identity, content):
            raise OSError("synthetic encrypted file write failure")

        monkeypatch.setattr(v.store.files, "write", crash)
        with pytest.raises(ValueError):
            await v.service.capture_generated(v.action_id, 0)
        monkeypatch.setattr(v.store.files, "write", original)
        with pytest.raises(Conflict, match="requires_reconciliation"):
            await journal(v).capture_generated(v.action_id, 0)
        assert len(await all_rows(db, Artifact)) == 1 and not await all_rows(db, FileTransfer)


async def test_slow_encrypted_storage_requires_one_genuine_same_bytes_reproof(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path) as v:
        clock, original = time.time, v.store.create

        async def slow(*args, **kwargs):
            identity = await original(*args, **kwargs)
            monkeypatch.setattr(time, "time", lambda: clock() + 6)
            return identity

        monkeypatch.setattr(v.store, "create", slow)
        identity = await v.service.capture_generated(v.action_id, 0)
        plan = (await v.service.load(identity))[1]
        first = read_intent((await all_rows(db, GeneratedOutputRecord))[0]).evidence
        assert v.reader.calls == v.reader.reads == 2
        assert first.expires_at <= plan.evidence.observed_at
        assert first.stable_sha256 == plan.evidence.stable_sha256
        assert plan.evidence.expires_at <= plan.evidence.turn.observed_at + 5


async def test_unknown_upload_result_never_reposts_on_restart(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        v.remote.mode = "timeout"
        assert await v.service.advance(identity) == "ambiguous"
        fresh = journal(v)
        assert await fresh.capture_generated(v.action_id, 0) == identity
        assert await fresh.advance(identity) == "ambiguous" and v.remote.posts == 1


async def test_base_manual_journal_cannot_publish_generated_plan_without_its_authorizer(
    db, tmp_path
):
    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        manual = FileReturnJournal(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {},
            message_limit=10000,
            topic_limit=60,
        )
        assert await manual.advance(identity) == "held" and not v.remote.posts


async def test_concurrent_same_action_output_creates_one_intent_artifact_and_transfer(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identities = await asyncio.gather(
            *(v.service.capture_generated(v.action_id, 0) for _ in range(3))
        )
        assert len(set(identities)) == 1 and v.reader.reads == 1
        assert len(await all_rows(db, Artifact)) == len(await all_rows(db, FileTransfer)) == 1


@pytest.mark.parametrize("index", [-1, True, 0.0, 1000, 1])
async def test_invalid_or_missing_output_ordinal_never_pins_or_uploads(db, tmp_path, index):
    async with setup(db, tmp_path) as v:
        with pytest.raises(ValueError):
            await v.service.capture_generated(v.action_id, index)
        assert not await all_rows(db, GeneratedOutputRecord) and not v.remote.posts


@pytest.mark.parametrize("kind", ["workspace", "inline"])
async def test_twenty_mib_original_output_uses_encrypted_bytes_and_single_upload(
    db, tmp_path, kind
):
    async with setup(db, tmp_path, body=b"x" * MAX_ATTACHMENT_BYTES, kind=kind) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        for expected in ("uploaded", "verified", "queued"):
            assert await v.service.advance(identity) == expected
        assert v.remote.posts == v.remote.downloads == 1
        assert (await v.service.load(identity))[1].projection.size == MAX_ATTACHMENT_BYTES


@pytest.mark.parametrize("changed", ["source", "grant", "audience", "action", "result-index"])
async def test_revoked_during_ack_saves_known_upload_but_prevents_publication(
    db, tmp_path, changed
):
    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)

        async def revoke():
            await mutate(db, v, changed)

        v.remote.hook = revoke
        assert await v.service.advance(identity) == "uploaded"
        assert (await v.service.load(identity))[1].upload is not None
        v.remote.hook = None
        assert await v.service.advance(identity) == "held"
        assert not await all_rows(db, Delivery) and v.remote.posts == 1


async def test_action_version_race_at_prepare_commit_cannot_create_a_transfer(
    db, tmp_path, monkeypatch
):
    async with setup(db, tmp_path) as v:
        original, calls = v.service.operator_lock, 0

        async def changed(session, binding, actor):
            nonlocal calls
            calls += 1
            await original(session, binding, actor)
            if calls == 2:
                await session.execute(update(Action).values(version=Action.version + 1))

        monkeypatch.setattr(v.service, "operator_lock", changed)
        with pytest.raises(Conflict, match="original_action_or_turn"):
            await v.service.capture_generated(v.action_id, 0)
        assert len(await all_rows(db, Artifact)) == 1 and not await all_rows(db, FileTransfer)
        assert not (await all_rows(db, GeneratedOutputRecord))[0].transfer_id


async def test_revoked_between_queue_and_chat_send_is_held_without_message(db, tmp_path):
    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        for expected in ("uploaded", "verified", "queued"):
            assert await v.service.advance(identity) == expected
        await mutate(db, v, "action")
        delivery = (await all_rows(db, Delivery))[0]
        chat = SyntheticChat()
        chat.bot_user_id = 11
        worker = DeliveryWorker(
            v.outbox,
            chat,
            v.store.fence.holder,
            v.store.fence.fencing,
            minimum_interval=0,
            file_returns=v.service,
        )
        assert await worker.advance(delivery.id) == "held"
        assert not chat.calls and v.remote.posts == 1


async def test_recognizable_secret_output_is_blocked_before_plaintext_or_upload(db, tmp_path):
    async with setup(
        db, tmp_path, body=b"-----BEGIN PRIVATE KEY-----\nPRIVATE_DATA\n-----END PRIVATE KEY-----"
    ) as v:
        with pytest.raises(ValueError, match="recognizable_secret"):
            await v.service.capture_generated(v.action_id, 0)
        assert not await all_rows(db, Artifact) and not v.remote.posts


async def test_reserved_artifact_identity_collision_rolls_back_quota_and_never_replaces_bytes(
    db, tmp_path
):
    from jt_oz_bridge.services.artifacts import FileDescriptor
    from tests.integration.test_file_returns import chunks

    async with setup(db, tmp_path) as v:
        identity = await v.service.capture_generated(v.action_id, 0)
        plan = (await v.service.load(identity))[1]
        original = await v.service.content(plan)
        with pytest.raises(IntegrityError):
            await v.store.create(
                v.binding.id,
                "realm",
                7,
                FileDescriptor(filename="different.html", mime_type="text/html"),
                chunks(b"replacement"),
                identity=plan.artifact_id,
            )
        assert await v.service.content(plan) == original
        assert len(await all_rows(db, Artifact)) == 1


@pytest.mark.parametrize("changed", ["certificate", "download", "bot"])
async def test_unqualified_destination_fails_before_native_read_or_any_durable_capture(
    db, tmp_path, changed
):
    async with setup(db, tmp_path) as v:
        if changed == "certificate":
            v.uploader.attestation = None
        elif changed == "download":
            v.client.attestation = replace(
                v.client.attestation, verified_file_operations=frozenset({"upload"})
            )
        else:
            v.uploader.attestation = replace(v.uploader.attestation, bot_user_id=99)
        with pytest.raises(ValueError):
            await v.service.capture_generated(v.action_id, 0)
        assert v.reader.calls == v.reader.reads == v.remote.posts == 0
        assert not await all_rows(db, Artifact)
        assert not await all_rows(db, GeneratedOutputRecord)
        assert not await all_rows(db, FileTransfer)


@pytest.mark.parametrize("limit", ["upload", "download", "artifact"])
async def test_lower_real_transfer_capacity_fails_before_pin_or_encrypted_storage(
    db, tmp_path, limit
):
    async with setup(db, tmp_path) as v:
        if limit == "upload":
            v.uploader.attestation = replace(v.uploader.attestation, maximum_file_bytes=1)
        elif limit == "download":
            v.downloader.maximum = 1
        else:
            v.store.maximum = 1
        with pytest.raises(Conflict, match="actual_transfer_limit"):
            await v.service.capture_generated(v.action_id, 0)
        assert v.reader.calls == v.reader.reads == 1 and not v.remote.posts
        assert not await all_rows(db, Artifact)
        assert not await all_rows(db, GeneratedOutputRecord)
        assert not await all_rows(db, FileTransfer)
