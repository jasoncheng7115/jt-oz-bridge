"""Real event shapes and failure boundaries for the non-replaying public feed."""

import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed, VolatileFeedIndex
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
from tests.contract.test_installed_opencode_evidence import REF

PROFILE = OpenAPIProfile.from_file(Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json"))
ROOT = Path("tests/fixtures/installed/opencode-v2.0.32")
REAL = [
    e
    for name in ["parsed-interactive.json", "parsed-background-stop.json"]
    for e in json.loads((ROOT / name).read_text())["events"]
]
OWNER = "a" * 64
CONNECTED = {"id": "evt_connection", "type": "server.connected", "created": 1.0, "data": {}}


def frame(raw):
    return SSEFrame("message", json.dumps(raw))


def text_delta(event_id="evt_stream_fragment"):
    """Real installed event shape with an explicitly synthetic event identity."""
    raw = copy.deepcopy(
        next(
            e
            for e in json.loads((ROOT / "parsed-feed.json").read_text())["events"]
            if e["type"] == "session.text.delta"
        )
    )
    raw["id"] = event_id
    return raw


def index(**kwargs):
    result = VolatileFeedIndex(PROFILE, (REF,), OWNER, **kwargs)
    result.accept(frame(CONNECTED))
    return result


def test_all_real_interactions_retain_scope_and_ephemeral_positions_without_fabrication():
    i = index()
    for e in REAL:
        result = i.accept(frame(e))
        assert result.reference == REF
        assert result.native_seq == e.get("durable", {}).get("seq")
        assert result.native_id == e["id"]
        assert result.payload() == e
    assert i.observed_position(REF) == max(e["durable"]["seq"] for e in REAL if "durable" in e)
    assert [i.pop().native_id for _ in REAL] == [e["id"] for e in REAL]
    assert i.pop() is None
    assert not hasattr(i, "replayed") and not hasattr(i, "state")


def test_schema_valid_foreign_session_is_discarded_before_retention():
    i = index(max_events=1)
    for e in REAL:
        raw = json.dumps(e).replace(REF.upstream_session_id, "ses_foreign")
        assert i.accept(SSEFrame("message", raw)) is None
    assert i.pop() is None and not i._seen and not i._positions
    assert i.accept(frame(REAL[0])) is not None


@pytest.mark.parametrize(
    "kind", ["permission.asked", "form.created", "form.replied", "permission.replied"]
)
def test_actual_request_shapes_use_explicit_session_identity_not_prefixes(kind):
    i = index()
    event = next(e for e in REAL if e["type"] == kind)
    assert i.accept(frame(event)).reference == REF


def test_payload_mutation_does_not_alter_the_observation():
    item = index().accept(frame(REAL[0]))
    item.payload()["data"]["sessionID"] = "ses_foreign"
    assert item.payload() == REAL[0]


def test_exact_duplicate_is_ignored_but_conflicting_native_id_invalidates_queue():
    i = index()
    i.accept(frame(REAL[0]))
    assert i.accept(frame(REAL[0])) is None
    changed = {**REAL[0], "created": REAL[0]["created"] + 1}
    with pytest.raises(ContractError, match="identity_changed"):
        i.accept(frame(changed))
    assert i.closed and not i._queue


def test_early_cached_identity_conflict_invalidates_before_microbatch_admission():
    i = index()
    i.accept(frame(REAL[0]))
    i.pop()
    changed = {**REAL[0], "created": REAL[0]["created"] + 1}
    with pytest.raises(ContractError, match="identity_changed"):
        i._notice_arrival(changed)
    assert i.closed


def test_installed_ephemeral_text_delta_keeps_state_revision_but_not_output_revision():
    i = index()
    first = i.accept(frame(text_delta()))
    assert first.event_type == "session.text.delta"
    assert i.revision_for(REF) == 1 and i.state_revision_for(REF) == 0
    assert i.accept(frame(text_delta())) is None
    assert i.revision_for(REF) == 1 and i.state_revision_for(REF) == 0
    i.accept(frame(REAL[0]))
    assert i.revision_for(REF) == 2 and i.state_revision_for(REF) == 1
    assert i.pop() is first  # Not lost or promoted to final output.


def test_another_schema_does_not_inherit_state_neutral_fragment_semantics():
    i = index()
    i.profile = SimpleNamespace(sha256="0" * 64, sse_frame=PROFILE.sse_frame)
    i.accept(frame(text_delta()))
    assert i.revision_for(REF) == i.state_revision_for(REF) == 1


def test_state_revision_checks_exact_reference_and_feed_lifetime():
    i = index()
    with pytest.raises(ContractError, match="not_enrolled"):
        i.state_revision_for(REF.model_copy(update={"canonical_directory": "/other"}))
    i.accept(frame(REAL[0]))
    i.invalidate("lost")
    assert not i._state_revisions
    with pytest.raises(ContractError, match="not_live"):
        i.state_revision_for(REF)


def test_state_neutral_delta_semantics_match_the_preserved_installed_tag_source():
    import hashlib

    from jt_oz_bridge.adapters.opencode.live import STATE_NEUTRAL_TEXT_SCHEMA

    manifest = json.loads((ROOT / "manifest.json").read_text())
    source = next(
        row
        for row in manifest["source_tag_comparison"]
        if row["path"] == "packages_schema_src_session-event.ts"
    )
    original = ROOT / source["preserved_identical_file"]
    raw = original.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == source["sha256"]
    assert STATE_NEUTRAL_TEXT_SCHEMA == manifest["installed_openapi_sha256"] == PROFILE.sha256
    text_source = (
        raw.decode()
        .split("export namespace Text {", 1)[1]
        .split("export namespace Reasoning", 1)[0]
    )
    assert "Delta = Event.ephemeral({" in text_source
    assert "Ended = Event.durable({" in text_source
    event = text_delta()
    assert "durable" not in event
    PROFILE.sse_frame("event.subscribe", event="message", data=json.dumps(event), event_id=None)


@pytest.mark.parametrize("change", ["aggregate", "data", "location"])
def test_conflicting_enrolled_scope_invalidates_feed(change):
    i = index()
    e = copy.deepcopy(next(e for e in REAL if "durable" in e))
    if change == "aggregate":
        e["durable"]["aggregateID"] = "ses_foreign"
    elif change == "data":
        e["data"]["sessionID"] = "ses_foreign"
    else:
        e["location"] = {"directory": "/foreign"}
    with pytest.raises(ContractError, match="conflicting"):
        i.accept(frame(e))
    assert i.closed


def test_sequence_gaps_do_not_claim_replay_and_regression_is_rejected():
    i = index()
    events = [e for e in REAL if "durable" in e]
    i.accept(frame(events[0]))
    i.accept(frame(events[-1]))
    with pytest.raises(ContractError, match="position_regressed"):
        i.accept(frame(events[1]))


@pytest.mark.parametrize("limits", [dict(max_events=1), dict(max_bytes=1)])
def test_capacity_failure_clears_data_and_does_not_reopen(limits):
    i = index(**limits)
    with pytest.raises(ContractError, match="capacity"):
        for e in REAL[:2]:
            i.accept(frame(e))
    assert i.closed and not i._queue and not i._seen
    with pytest.raises(ContractError, match="closed"):
        i.accept(frame(CONNECTED))


def test_one_oversized_event_is_dropped_as_its_roots_gap_not_a_generation_failure():
    # See tests/integration/test_oversized_feed_event.py for the streamed path.
    i = index(max_event_bytes=len(json.dumps(REAL[1])) - 1)
    assert i.accept(frame(REAL[1])) is None
    assert not i.closed and not i._queue and not i._seen
    assert i.revision_for(REF) == i.state_revision_for(REF) == 1
    assert i.accept(frame(REAL[0])).native_id == REAL[0]["id"]


def test_draining_does_not_disable_lifetime_deduplication_limit():
    i = index(max_events=1)
    i.accept(frame(REAL[0]))
    i.pop()
    with pytest.raises(ContractError, match="capacity"):
        i.accept(frame(REAL[1]))


def test_connection_generation_is_owner_and_native_marker_bound():
    a = index()
    b = VolatileFeedIndex(PROFILE, (REF,), "b" * 64)
    b.accept(frame(CONNECTED))
    c = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    c.accept(frame({**CONNECTED, "id": "evt_other"}))
    assert len({a.connection_epoch, b.connection_epoch, c.connection_epoch}) == 3
    with pytest.raises(ContractError, match="reconnected"):
        a.accept(frame(CONNECTED))


def test_missing_initial_connection_and_malformed_frame_fail_closed():
    i = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    with pytest.raises(ContractError):
        i.accept(frame(REAL[0]))
    assert i.closed
    i = index()
    with pytest.raises(ContractError):
        i.accept(SSEFrame("message", '{"type":"session.execution.started"}'))
    assert i.closed


@pytest.mark.parametrize(
    "refs,owner,limits",
    [
        ((), OWNER, {}),
        ((REF, REF), OWNER, {}),
        ((REF,), "bad", {}),
        ((REF,), OWNER, {"max_events": True}),
        ((REF,), OWNER, {"max_bytes": 0}),
    ],
)
def test_invalid_enrollment_or_limits_rejected(refs, owner, limits):
    with pytest.raises(ValueError):
        VolatileFeedIndex(PROFILE, refs, owner, **limits)


def test_unenrolled_reference_cannot_read_position_and_invalidation_removes_data():
    i = index()
    i.accept(frame(REAL[0]))
    with pytest.raises(ContractError, match="not_enrolled"):
        i.observed_position(REF.model_copy(update={"project_id": "foreign"}))
    i.invalidate("lost")
    i.invalidate("later")
    assert i.failure == "lost" and not i._queue
    with pytest.raises(ContractError, match="not_live"):
        i.pop()


def runtime(*, eof=False):
    release = asyncio.Event()

    async def events(operation, *, oversized_event_bytes):
        assert operation == "event.subscribe"
        yield frame(CONNECTED)
        yield frame(REAL[0])
        if not eof:
            await release.wait()

    enrollment = SimpleNamespace(
        backend_id=REF.backend_id,
        backend_identity=REF.backend_identity,
        version="2.0.32",
        url="http://127.0.0.1:4096",
    )
    owner = SimpleNamespace(
        enrollment=enrollment, read=AsyncMock(return_value=SimpleNamespace(owner_epoch=OWNER))
    )
    transport = SimpleNamespace(
        profile=PROFILE,
        client=SimpleNamespace(base_url="http://127.0.0.1:4096/"),
        events=events,
        attestation=ContractAttestation(
            PROFILE.sha256, REF.backend_identity, "2.0.32", frozenset({"event.subscribe"})
        ),
    )
    return V2PublicFeed(transport, owner, (REF,)), release


async def test_runtime_lifetime_one_attempt_close_and_fresh_owner_failure():
    r, _ = runtime()
    await r.start()
    assert (await r.current_owner()).owner_epoch == OWNER
    assert r.index.pop().native_id == REAL[0]["id"]
    with pytest.raises(ContractError, match="already_started"):
        await r.start()
    r.owner.read.side_effect = RuntimeError("private payload")
    with pytest.raises(RuntimeError):
        await r.current_owner()
    assert r.index.closed
    await r.close()
    assert r.task.done()


async def test_eof_does_not_leave_queued_evidence_live_or_retry_connection():
    r, _ = runtime(eof=True)
    with pytest.raises(ContractError):
        await r.start()
    assert r.index.closed and not r.index._queue
    assert r.task.done()


@pytest.mark.parametrize("change", ["identity", "schema", "operation", "version", "absent"])
async def test_installed_attestation_loss_prevents_read_authority(change):
    r, _ = runtime()
    await r.start()
    old = r.transport.attestation
    r.transport.attestation = (
        None
        if change == "absent"
        else ContractAttestation(
            "0" * 64 if change == "schema" else old.schema_sha256,
            "other" if change == "identity" else old.backend_identity,
            "other" if change == "version" else old.upstream_version,
            frozenset() if change == "operation" else old.verified_operations,
        )
    )
    with pytest.raises(ContractError, match="unattested"):
        await r.current_owner()
    assert r.index.closed
    await r.close()


async def test_owner_change_and_cancellation_invalidate_generation():
    r, _ = runtime()
    await r.start()
    r.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
    with pytest.raises(ContractError, match="owner_changed"):
        await r.current_owner()
    await r.close()
    r, _ = runtime()
    await r.start()
    r.task.cancel()
    await asyncio.gather(r.task, return_exceptions=True)
    assert r.index.closed
    with pytest.raises(ContractError):
        await r.current_owner()


async def test_start_unattested_and_wrong_owner_are_rejected():
    r, _ = runtime()
    r.transport.attestation = None
    with pytest.raises(ContractError, match="unattested"):
        await r.start()
    assert r.task is None
    r.owner.enrollment.backend_id = "other"
    with pytest.raises(ValueError, match="scope"):
        V2PublicFeed(r.transport, r.owner, (REF,))


async def test_feed_endpoint_must_match_the_root_enrolled_original_owner():
    r, _ = runtime()
    r.transport.client.base_url = "http://127.0.0.1:5555/"
    with pytest.raises(ContractError, match="unattested"):
        await r.start()
    assert r.task is None


def test_reasoning_is_not_retained_or_turned_into_user_visible_output():
    i = index()
    event = {
        "id": "evt_reasoning",
        "created": 1.0,
        "type": "session.reasoning.delta",
        "data": {
            "sessionID": REF.upstream_session_id,
            "messageID": "msg_test",
            "id": "reasoning_test",
            "text": "private internal reasoning",
        },
    }
    # Use the exact installed union to catch drift in these fields.
    i.accept(frame(event))
    assert i.pop() is None and not i._seen


def test_installed_wheel_reader_capture_hash_and_actual_root_events():
    import hashlib

    manifest = json.loads((ROOT / "manifest.json").read_text())["public_reader_capture"]
    path = ROOT / manifest["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["sha256"]
    captured = json.loads(path.read_text())
    i = index()
    actual = [i.accept(frame(e)) for e in captured["events"]]
    assert len(actual) == 12
    assert actual[-1].event_type == "session.execution.succeeded"
    assert actual[-1].native_seq == 63
    assert all(x.reference == REF for x in actual)


def test_live_close_and_new_connection_evidence_does_not_claim_replay_or_state():
    evidence = json.loads((ROOT / "live-public-feed-20261017.json").read_text())
    assert evidence["passed"] and evidence["exact_assistant_marker"]
    assert evidence["old_generation_closed"]
    assert evidence["first_connection_epoch"] != evidence["new_connection_epoch"]
    assert not evidence["automatic_reconnect"] and not evidence["replayed_or_snapshot_certified"]
