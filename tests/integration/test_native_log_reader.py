import json
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
from jt_oz_bridge.domain.native_events import QualifiedLogRecord
from jt_oz_bridge.services.native_log_reader import V2LogReader
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Checkpoint, Grant, InputEvent, WorkerLease
from tests.contract.test_v2_execution import REF
from tests.integration.test_v2_dispatch import worker


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


def event(seq=0, **changes):
    return {
        "id": "evt_" + str(seq),
        "type": "session.renamed",
        "created": 123,
        "durable": {"aggregateID": REF.upstream_session_id, "seq": seq, "version": 1},
        "location": {"directory": REF.canonical_directory},
        "data": {"sessionID": REF.upstream_session_id, "title": "PRIVATE_CAPTURED_TITLE"},
        **changes,
    }


def synced(seq=3):
    return {
        "type": "log.synced",
        "aggregateID": REF.upstream_session_id,
        **({"seq": seq} if seq is not None else {}),
    }


def sse(value):
    return ("data: " + json.dumps(value) + "\n\n").encode()


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks, between=None):
        self.chunks, self.between, self.closed = chunks, between, False

    async def __aiter__(self):
        for index, chunk in enumerate(self.chunks):
            if index and self.between:
                await self.between()
            yield chunk

    async def aclose(self):
        self.closed = True


async def reader(db, profile, chunks, between=None):
    stream = Stream(chunks, between)

    def response(request, data, proof):
        if request.url.path.endswith("/log"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
        return None

    dispatcher, binding, transport, proof, data, seen, source = await worker(db, profile, response)
    attestation = transport.attestation
    transport.attestation = ContractAttestation(
        attestation.schema_sha256,
        attestation.backend_identity,
        attestation.upstream_version,
        attestation.verified_operations | {"session.log"},
    )
    return (
        V2LogReader(dispatcher.bindings, dispatcher.client, dispatcher.holder, dispatcher.fencing),
        binding,
        transport,
        proof,
        seen,
        stream,
    )


async def test_attested_stream_captures_qualified_encrypted_events_and_real_sync_checkpoint(
    db, profile
):
    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(event()), sse(synced())]
    )
    try:
        result = await pump.run(binding.id)
        assert result.captured_records == 2 and result.replay_synced and result.position == 3
        log_requests = [request for request in seen if request.url.path.endswith("/log")]
        assert len(log_requests) == 1 and dict(log_requests[0].url.params) == {"follow": "false"}
        assert all(request.method == "GET" for request in seen) and stream.closed
        async with db.sessions() as session:
            rows = (await session.scalars(select(InputEvent).order_by(InputEvent.source_id))).all()
            assert len(rows) == 2 and all(row.state == "captured" for row in rows)
            envelopes = [QualifiedLogRecord.model_validate(row.payload) for row in rows]
            assert all(
                record.provenance.binding_id == binding.id
                and record.provenance.binding_revision == binding.revision
                and record.provenance.realm_id == binding.realm_id
                and record.provenance.reference == REF
                and record.provenance.execution_epoch == proof.epoch
                and record.provenance.contract_sha256 == profile.sha256
                and record.capture_epoch == result.capture_epoch
                for record in envelopes
            )
            assert (await session.get(Checkpoint, result.source)).event_id == 3
        async with db.engine.connect() as connection:
            from sqlalchemy import text

            raw = (
                (await connection.execute(text("SELECT payload FROM input_events"))).scalars().all()
            )
            assert all(
                isinstance(item, bytes) and b"PRIVATE_CAPTURED_TITLE" not in item for item in raw
            )
    finally:
        await transport.close()


async def test_empty_log_keeps_absent_native_sequence_not_zero(db, profile):
    pump, binding, transport, proof, seen, stream = await reader(db, profile, [sse(synced(None))])
    try:
        result = await pump.run(binding.id)
        assert result.position is None and result.captured_records == 1
        async with db.sessions() as session:
            row = (await session.scalars(select(InputEvent))).one()
            assert "seq" not in QualifiedLogRecord.model_validate(row.payload).native
            assert (await session.get(Checkpoint, result.source)).event_id == -1
    finally:
        await transport.close()


async def test_missing_log_attestation_does_not_open_native_stream(db, profile):
    pump, binding, transport, proof, seen, stream = await reader(db, profile, [sse(synced())])
    attestation = transport.attestation
    transport.attestation = ContractAttestation(
        attestation.schema_sha256,
        attestation.backend_identity,
        attestation.upstream_version,
        attestation.verified_operations - {"session.log"},
    )
    seen.clear()
    try:
        with pytest.raises(ContractError):
            await pump.run(binding.id)
        assert not seen
        async with db.sessions() as session:
            assert await session.scalar(select(Checkpoint.source)) is None
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change", ["epoch", "attestation", "binding", "grant", "lease", "backend", "project"]
)
async def test_midstream_revocation_halts_before_next_cursor_commit(db, profile, change):
    async def revoke():
        if change == "epoch":
            proof.epoch = "revoked"
        elif change == "attestation":
            captured = transport.attestation
            transport.attestation = ContractAttestation(
                captured.schema_sha256,
                captured.backend_identity,
                captured.upstream_version,
                captured.verified_operations - {"session.log"},
            )
        else:
            async with db.sessions.begin() as session:
                if change == "binding":
                    await session.execute(update(Binding).values(revision=2))
                elif change == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 8).values(active=False)
                    )
                elif change == "lease":
                    await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
                elif change == "backend":
                    await session.execute(update(EnrolledBackend).values(identity="replaced"))
                else:
                    await session.execute(update(EnrolledProject).values(enabled=False))

    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(event()), sse(synced())], revoke
    )
    try:
        with pytest.raises((ContractError, Conflict)):
            await pump.run(binding.id)
        assert stream.closed
        async with db.sessions() as session:
            checkpoint = (await session.scalars(select(Checkpoint))).one()
            assert checkpoint.event_id == 0
            assert len((await session.scalars(select(InputEvent))).all()) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("mode", ["incomplete", "follow-eof", "extra-after-sync"])
async def test_incomplete_or_following_eof_never_reports_continuous_connection(db, profile, mode):
    chunks = [sse(event())]
    if mode != "incomplete":
        chunks.append(sse(synced()))
    if mode == "extra-after-sync":
        chunks.append(sse(event(4)))
    pump, binding, transport, proof, seen, stream = await reader(db, profile, chunks)
    try:
        with pytest.raises((ContractError, Conflict)):
            await pump.run(binding.id, follow=mode == "follow-eof")
        assert stream.closed
        async with db.sessions() as session:
            assert (await session.scalars(select(Checkpoint))).one().event_id == (
                0 if mode == "incomplete" else 3
            )
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "bad",
    [
        b'{"type":"log.synced","aggregateID":"ses_original","seq":3,"seq":4}',
        b'{"type":"log.synced","aggregateID":"ses_original","seq":1e400}',
    ],
)
async def test_ambiguous_json_is_rejected_without_advancing_checkpoint(db, profile, bad):
    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(event()), b"data: " + bad + b"\n\n"]
    )
    try:
        with pytest.raises(ContractError):
            await pump.run(binding.id)
        assert stream.closed
        async with db.sessions() as session:
            assert (await session.scalars(select(Checkpoint))).one().event_id == 0
    finally:
        await transport.close()


async def test_restart_uses_committed_watermark_with_new_capture_epoch_without_replaying_events(
    db, profile
):
    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(event()), sse(synced())]
    )
    try:
        first = await pump.run(binding.id)
        stream.chunks, stream.closed = [sse(event(4)), sse(synced(7))], False
        second = await pump.run(binding.id)
        assert first.source == second.source and first.capture_epoch != second.capture_epoch
        assert second.position == 7 and second.captured_records == 2
        log_requests = [request for request in seen if request.url.path.endswith("/log")]
        assert len(log_requests) == 2 and dict(log_requests[1].url.params) == {
            "follow": "false",
            "after": "3",
        }
        async with db.sessions() as session:
            assert len((await session.scalars(select(InputEvent))).all()) == 4
            checkpoint = await session.get(Checkpoint, second.source)
            assert checkpoint.event_id == 7 and checkpoint.queue_id == second.capture_epoch
    finally:
        await transport.close()


async def test_cancellation_closes_stream_and_keeps_only_committed_capture(db, profile):
    import asyncio

    waiting = asyncio.Event()

    async def pause():
        waiting.set()
        await asyncio.Event().wait()

    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(event()), sse(synced())], pause
    )
    try:
        task = asyncio.create_task(pump.run(binding.id, follow=True))
        await asyncio.wait_for(waiting.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.closed
        async with db.sessions() as session:
            assert len((await session.scalars(select(InputEvent))).all()) == 1
            assert (await session.scalars(select(Checkpoint))).one().event_id == 0
        assert len([request for request in seen if request.url.path.endswith("/log")]) == 1
    finally:
        await transport.close()


async def test_lost_stream_response_keeps_capture_and_does_not_reconnect_automatically(db, profile):
    from jt_oz_bridge.adapters.opencode.transport import TransportError

    async def lost():
        raise httpx.ReadTimeout("PRIVATE_STREAM_ERROR")

    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(event()), sse(synced())], lost
    )
    try:
        with pytest.raises(TransportError) as error:
            await pump.run(binding.id, follow=True)
        assert "PRIVATE" not in str(error.value) and stream.closed
        async with db.sessions() as session:
            assert (await session.scalars(select(Checkpoint))).one().event_id == 0
        assert len([request for request in seen if request.url.path.endswith("/log")]) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["binding", "revision", "realm", "reference", "contract"])
async def test_capture_provenance_cannot_be_reused_for_another_binding_scope(db, profile, change):
    from jt_oz_bridge.services.log_ingestion import LogCapture

    pump, binding, transport, proof, seen, stream = await reader(db, profile, [sse(synced())])
    try:
        result = await pump.run(binding.id)
        async with db.sessions() as session:
            saved = (await session.scalars(select(InputEvent))).one()
            provenance = QualifiedLogRecord.model_validate(saved.payload).provenance
        changes = {
            "binding": {"binding_id": "other"},
            "revision": {"binding_revision": 2},
            "realm": {"realm_id": "other"},
            "reference": {"reference": REF.model_copy(update={"upstream_session_id": "ses_other"})},
            "contract": {"contract_sha256": "c" * 64},
        }[change]
        with pytest.raises(Conflict, match="provenance_scope"):
            await LogCapture.open(
                pump.bindings,
                binding.id,
                pump.holder,
                pump.fencing,
                provenance=provenance.model_copy(update=changes),
            )
        async with db.sessions() as session:
            assert (await session.get(Checkpoint, result.source)).queue_id == result.capture_epoch
    finally:
        await transport.close()
