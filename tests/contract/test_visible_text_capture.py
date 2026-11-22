"""Installed wire shapes, bounded fragments and original-index provenance."""

from dataclasses import replace

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.live import ScopedLiveEvent
from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture, VisibleTextSnapshot
from tests.contract.test_public_live_feed import REF, frame, index, text_delta


def event(number=1, *, kind="delta", ordinal=0, text="Visible output", assistant="msg_stream"):
    value = text_delta("evt_visible_" + str(number))
    value["type"] = "session.text." + kind
    value["data"] = {
        "sessionID": REF.upstream_session_id,
        "assistantMessageID": assistant,
        "ordinal": ordinal,
    }
    if kind == "delta":
        value["data"]["delta"] = text
    else:
        # Durable start/end full-value shapes from the matching installed schema.
        value["durable"] = {"aggregateID": REF.upstream_session_id, "seq": number}
        if kind == "ended":
            value["data"]["text"] = text
    return value


def observe(i, capture, raw):
    value = i.accept(frame(raw))
    assert isinstance(value, ScopedLiveEvent)
    capture.observe(value)
    i.pop()


def test_live_capture_is_distinct_from_resource_history_and_uses_original_owned_events():
    i = index()
    capture = VisibleTextCapture(i)
    observe(i, capture, event(1, kind="started"))
    observe(i, capture, event(2, text="Hello "))
    observe(i, capture, event(3, text="世界"))
    partial = capture.snapshots()[0]
    assert partial.text == "Hello 世界" and partial.revision == 3
    assert not partial.parts[0].prefix_missing and not partial.parts[0].ended
    assert partial.format == "original-visible-text-capture-v1"
    assert not hasattr(partial, "state") and not hasattr(partial, "resource_fence")
    assert capture.current(partial)
    assert not capture.current(VisibleTextSnapshot.model_validate(partial.model_dump()))
    observe(i, capture, event(4, kind="ended", text="Hello 世界 complete"))
    assert not capture.current(partial)
    final = capture.snapshots()[0]
    assert final.parts[0].ended and final.text.endswith("complete")
    assert not hasattr(final, "outcome")  # Ended text is not task success.


def test_reobserving_same_original_queue_object_never_appends_its_text_twice():
    i = index()
    capture = VisibleTextCapture(i)
    item = i.accept(frame(event()))
    capture.observe(item)
    capture.observe(item)
    assert capture.snapshots()[0].text == "Visible output"
    assert capture.snapshots()[0].revision == 1


def test_dto_copy_popped_event_and_foreign_index_cannot_supply_capture_authority():
    i, foreign = index(), index()
    capture = VisibleTextCapture(i)
    item = i.accept(frame(event()))
    for fake in (replace(item), foreign.accept(frame(event()))):
        with pytest.raises(ContractError, match="not_index_owned"):
            capture.observe(fake)
    i.pop()
    with pytest.raises(ContractError, match="not_index_owned"):
        capture.observe(item)
    assert not capture.snapshots()


def test_join_mid_stream_marks_missing_prefix_until_real_full_value_boundary():
    i = index()
    capture = VisibleTextCapture(i)
    observe(i, capture, event(text="suffix"))
    assert capture.snapshots()[0].parts[0].prefix_missing
    observe(i, capture, event(2, kind="ended", text="original whole value"))
    value = capture.snapshots()[0]
    assert not value.parts[0].prefix_missing and value.text == "original whole value"


def test_multibyte_preview_and_part_message_windows_stay_bounded_with_explicit_loss_markers():
    i = index()
    capture = VisibleTextCapture(i, max_messages=2, max_parts=2, message_bytes=7)
    observe(i, capture, event(text="中文中文"))
    first = capture.snapshots()[0]
    assert first.text == "中文" and first.parts[0].truncated
    observe(i, capture, event(2, ordinal=1, text="abc"))
    observe(i, capture, event(3, ordinal=2, text="omitted"))
    value = capture.snapshots()[0]
    assert sum(len(p.text.encode()) for p in value.parts) <= 7
    assert len(value.parts) == 2 and value.omitted_parts
    observe(i, capture, event(4, assistant="msg_other"))
    observe(i, capture, event(5, assistant="msg_third"))
    assert len(capture.snapshots()) == 2 and capture.evictions == 1
    assert not capture.current(first)


@pytest.mark.parametrize("boundary", ["double_start", "delta_after_end", "double_end"])
def test_conflicting_part_boundaries_do_not_silently_append(boundary):
    i = index()
    capture = VisibleTextCapture(i)
    observe(i, capture, event(1, kind="started" if boundary == "double_start" else "ended"))
    item = i.accept(
        frame(
            event(
                2,
                kind={"double_start": "started", "delta_after_end": "delta", "double_end": "ended"}[
                    boundary
                ],
            )
        )
    )
    with pytest.raises(ContractError):
        capture.observe(item)
    assert capture.snapshots()[0].revision == 1


def test_closed_generation_and_different_schema_never_inherit_live_source_qualification():
    from types import SimpleNamespace

    i = index()
    capture = VisibleTextCapture(i)
    observe(i, capture, event())
    value = capture.snapshots()[0]
    i.invalidate("EOF")
    with pytest.raises(ContractError):
        capture.current(value)
    with pytest.raises(ContractError):
        capture.snapshots()
    capture.clear()
    i = index()
    i.profile = SimpleNamespace(sha256="0" * 64)
    with pytest.raises(ContractError, match="installed_schema"):
        VisibleTextCapture(i)


@pytest.mark.parametrize(
    "limits", [{"max_messages": 0}, {"max_parts": True}, {"message_bytes": -1}]
)
def test_invalid_capture_limits_rejected(limits):
    with pytest.raises(ValueError):
        VisibleTextCapture(index(), **limits)
