"""Synthetic whole-stream invalidation; not lineage/resource qualification."""

import copy
import json
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.live import VolatileFeedIndex
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from tests.contract.test_public_live_feed import (
    CONNECTED,
    OWNER,
    PROFILE,
    REAL,
    REF,
    frame,
    index,
    text_delta,
)


def foreign(event):
    return json.loads(json.dumps(event).replace(REF.upstream_session_id, "ses_unenrolled_child"))


@pytest.mark.parametrize("early", [False, True])
@pytest.mark.parametrize("event_kind", ["control", "text", "unknown"])
def test_unenrolled_arrivals_invalidate_before_id_filtering_without_payload_or_authority(
    early, event_kind
):
    i = index()
    raw = foreign(text_delta() if event_kind == "text" else REAL[0])
    if event_kind == "unknown":
        raw["type"] = "plugin.synthetic.descendant.notice"
    before = i.stream_fence(), i.stream_fence(state_only=True)
    if early:
        i._notice_arrival(raw)
    else:
        assert i.accept(frame(raw)) is None
    assert i.stream_fence() != before[0]
    assert i.stream_fence(state_only=True) != before[1]
    assert i.revision == 0 and i.revision_for(REF) == 0
    assert not i._queue and not i._seen and not i._positions
    assert i.references == {REF.upstream_session_id: REF}
    assert not hasattr(i, "state") and not hasattr(i, "replayed")


def test_arrival_invalidates_graph_even_when_later_receipt_or_dispatch_has_not_run():
    i = index()
    before = i.stream_fence(state_only=True)
    i._notice_arrival(foreign(REAL[0]))
    assert i.stream_fence(state_only=True) != before
    assert not i._queue and not i._seen and i.revision == 0


def test_enrolled_ephemeral_text_only_relaxes_the_exact_installed_state_fence():
    i = index()
    before = i.stream_fence(), i.stream_fence(state_only=True)
    raw = text_delta()
    i._notice_arrival(raw)
    assert i.stream_fence() != before[0]
    assert i.stream_fence(state_only=True) == before[1]
    assert i.accept(frame(raw)).reference == REF
    assert i.stream_fence(state_only=True) == before[1]
    control = next(e for e in REAL if e["type"] == "session.execution.started")
    assert i.accept(frame(control)).reference == REF
    assert i.stream_fence(state_only=True) != before[1]


def test_unqualified_contract_cannot_inherit_ephemeral_text_semantics_by_name():
    i = index()
    i.profile = copy.copy(PROFILE)
    i.profile.sha256 = "0" * 64
    before = i.stream_fence(state_only=True)
    i.accept(frame(text_delta()))
    assert i.stream_fence(state_only=True) != before


def test_durable_text_is_not_classified_as_ephemeral_state_neutral():
    i = index()
    raw = text_delta()
    raw["durable"] = copy.deepcopy(next(e["durable"] for e in REAL if "durable" in e))
    before = i.stream_fence(state_only=True)
    assert i.accept(frame(raw)).reference == REF
    assert i.stream_fence(state_only=True) != before


def test_unknown_plugin_event_without_session_identity_invalidates_without_becoming_a_message():
    i = index()
    before = i.stream_fence(state_only=True)
    raw = {
        "id": "evt_synthetic_plugin",
        "type": "plugin.synthetic.notice",
        "created": 1.0,
        "data": {"opaque": "TEST_NOT_RETAINED"},
    }
    assert i.accept(frame(raw)) is None
    assert i.stream_fence(state_only=True) != before
    assert not i._queue and not i._seen and "TEST_NOT_RETAINED" not in repr(i.__dict__)


def test_duplicate_unknown_arrival_is_conservative_invalidation_not_a_native_progress_assertion():
    i = index()
    raw = foreign(REAL[0])
    i.accept(frame(raw))
    first = i.stream_fence()
    i.accept(frame(raw))
    assert i.stream_fence() != first
    assert i.revision == 0 and not i._seen and i.observed_position(REF) is None


@pytest.mark.parametrize("mode", ["close", "unconnected", "owner", "generation"])
def test_stream_fence_is_bound_to_original_live_owner_and_generation(mode):
    i = index()
    before = i.stream_fence()
    if mode == "close":
        i.invalidate("synthetic_connection_lost")
    elif mode == "unconnected":
        i = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    elif mode == "owner":
        i.owner_epoch = "b" * 64
    else:
        i.connection_epoch = "different"
    if mode in {"close", "unconnected"}:
        with pytest.raises(ContractError):
            i.stream_fence()
    else:
        assert i.stream_fence() != before


def test_initial_connected_marker_does_not_claim_a_topology_change():
    i = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    i._notice_arrival(CONNECTED)
    i.accept(frame(CONNECTED))
    assert i._stream_arrivals == i._stream_state_arrivals == 0
    assert len(i.stream_fence()) == len(i.stream_fence(state_only=True)) == 64
    assert i.stream_fence() != i.stream_fence(state_only=True)


def test_reasoning_never_enters_graph_observation_or_retained_payloads():
    i = index()
    before = i.stream_fence(), i.stream_fence(state_only=True)
    raw = {
        "id": "evt_synthetic_reasoning",
        "type": "session.reasoning.delta",
        "created": 1.0,
        "data": {"sessionID": REF.upstream_session_id, "text": "PRIVATE_SYNTHETIC_REASONING"},
    }
    i._notice_arrival(raw)
    assert i.accept(frame(raw)) is None
    assert (i.stream_fence(), i.stream_fence(state_only=True)) == before
    assert not i._queue and not i._seen
    assert "PRIVATE_SYNTHETIC_REASONING" not in repr(i.__dict__)


async def test_unenrolled_child_event_is_never_promoted_to_a_receipt_or_scoped_event():
    i = index()
    store = AsyncMock()
    before = i.stream_fence(state_only=True)
    assert await i.accept_receipted((frame(foreign(REAL[0])),), store) == ()
    store.record_many.assert_not_awaited()
    assert i.stream_fence(state_only=True) != before and not i._queue


def test_conflicting_enrolled_text_scope_still_invalidates_the_feed():
    i = index()
    raw = text_delta()
    raw["location"] = {"directory": "/foreign"}
    with pytest.raises(ContractError, match="conflicting_directory"):
        i.accept(frame(raw))
    assert i.closed and not i._queue


def test_invalid_event_kind_fails_closed_instead_of_becoming_a_counter_assertion():
    i = index()
    raw = {"id": "evt_synthetic_invalid", "type": None, "data": {}}
    with pytest.raises(ContractError):
        i.accept(SSEFrame("message", json.dumps(raw)))
    assert i.closed


def elsewhere(event, directory="/home/opencode/workspaces/another-project"):
    raw = foreign(event)
    raw["location"] = {"directory": directory}
    return raw


def directory_fences(i, directory=REF.canonical_directory):
    return i.directory_fence(directory), i.directory_fence(directory, state_only=True)


@pytest.mark.parametrize("early", [False, True])
def test_another_projects_activity_leaves_this_directory_fence_but_not_the_whole_stream(early):
    i = index()
    before, whole = directory_fences(i), i.stream_fence(state_only=True)
    other = directory_fences(i, "/home/opencode/workspaces/another-project")
    for event in REAL:
        raw = elsewhere(event)
        if "location" not in event:
            continue  # Unlocated arrivals are covered below.
        if early:
            i._notice_arrival(raw)
        else:
            assert i.accept(frame(raw)) is None
    assert directory_fences(i) == before
    assert i.stream_fence(state_only=True) != whole
    assert directory_fences(i, "/home/opencode/workspaces/another-project") != other
    assert not i._queue and not i._seen and i.revision_for(REF) == 0


@pytest.mark.parametrize("event_kind", ["control", "text", "unknown"])
def test_an_unknown_session_in_this_directory_still_moves_its_fence(event_kind):
    i = index()
    raw = foreign(text_delta() if event_kind == "text" else REAL[0])
    if event_kind == "unknown":
        raw["type"] = "plugin.synthetic.descendant.notice"
    assert raw["location"] == {"directory": REF.canonical_directory}
    before = directory_fences(i)
    i.accept(frame(raw))
    after = directory_fences(i)
    assert after[0] != before[0] and after[1] != before[1]


def test_an_arrival_without_a_provable_directory_moves_every_directory_fence():
    i = index()
    unlocated = next(e for e in REAL if "location" not in e)
    raw = foreign(unlocated)
    before = directory_fences(i), directory_fences(i, "/elsewhere")
    i.accept(frame(raw))
    assert directory_fences(i)[1] != before[0][1]
    assert directory_fences(i, "/elsewhere")[1] != before[1][1]


def test_an_enrolled_sessions_unlocated_arrival_belongs_to_its_own_directory():
    i = index()
    unlocated = next(e for e in REAL if "location" not in e)
    before = directory_fences(i), directory_fences(i, "/elsewhere")
    assert i.accept(frame(unlocated)).reference == REF
    assert directory_fences(i)[1] != before[0][1]
    assert directory_fences(i, "/elsewhere") == before[1]


def test_a_truncated_frame_moves_every_directory_fence_whatever_its_leading_location():
    i = index()
    raw = elsewhere(REAL[0])
    data = json.dumps(raw)
    before = directory_fences(i), directory_fences(i, "/elsewhere")
    i.discard_truncated(SSEFrame("message", data[: data.index('"data"') + 20], truncated=True))
    assert directory_fences(i)[1] != before[0][1]
    assert directory_fences(i, "/elsewhere")[1] != before[1][1]


def test_enrolled_ephemeral_text_relaxes_its_directory_state_fence_only():
    i = index()
    before = directory_fences(i)
    i.accept(frame(text_delta()))
    after = directory_fences(i)
    assert after[0] != before[0] and after[1] == before[1]


@pytest.mark.parametrize("mode", ["owner", "generation"])
def test_directory_fence_is_bound_to_the_original_live_owner_and_generation(mode):
    i = index()
    before = directory_fences(i)
    if mode == "owner":
        i.owner_epoch = "b" * 64
    else:
        i.connection_epoch = "different"
    assert directory_fences(i)[0] != before[0] and directory_fences(i)[1] != before[1]
    i.invalidate("synthetic_connection_lost")
    with pytest.raises(ContractError):
        i.directory_fence(REF.canonical_directory)
