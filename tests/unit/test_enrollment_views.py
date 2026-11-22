"""Trusted live enrollment views stay readonly; ordinary dependencies stay snapshots."""

from types import MappingProxyType, SimpleNamespace

import pytest

from jt_oz_bridge.domain.enrollment_views import (
    EnrollmentKeys,
    EnrollmentView,
    enrollment_projection,
    enrollment_union,
    readonly_enrollment,
    readonly_enrollment_keys,
)


def test_plain_mapping_is_still_a_defensive_snapshot():
    original = {"old": object()}
    frozen = readonly_enrollment(original)
    old = frozen["old"]
    original["old"] = object()
    original["new"] = object()
    assert tuple(frozen) == ("old",) and frozen["old"] is old
    with pytest.raises(TypeError):
        frozen["new"] = object()


def test_trusted_live_view_preserves_new_entries_without_exposing_a_setter():
    owned = {"old": object()}
    view = EnrollmentView(lambda: MappingProxyType(owned))
    assert readonly_enrollment(view) is view
    owned["new"] = object()
    assert tuple(view) == ("old", "new") and view["new"] is owned["new"]
    with pytest.raises(TypeError):
        view["new"] = object()
    with pytest.raises(AttributeError):
        view.clear()


def test_empty_live_views_remain_live_when_selected_as_a_dependency():
    owned = {}
    view = EnrollmentView(lambda: owned)
    selected = readonly_enrollment(view)
    assert not selected and selected is view
    owned["later"] = 7
    assert selected["later"] == 7


@pytest.mark.parametrize("value", [False, 0, "", object()])
def test_projection_omits_only_missing_resources_not_falsy_values(value):
    owned = {"absent": SimpleNamespace(resource=None)}
    view = enrollment_projection(MappingProxyType(owned), lambda row: row.resource)
    assert not view
    owned["new"] = SimpleNamespace(resource=value)
    assert tuple(view) == ("new",) and view["new"] is value


def test_projection_and_union_publish_all_resource_fields_from_one_record_append():
    owned = {}
    transcripts = enrollment_projection(owned, lambda entry: entry.transcript)
    metadata = enrollment_projection(owned, lambda entry: entry.metadata)
    combined = enrollment_union([transcripts, {"fixed": "existing"}])
    entry = SimpleNamespace(transcript=object(), metadata=object())
    owned["new-root"] = entry
    assert transcripts["new-root"] is combined["new-root"] is entry.transcript
    assert metadata["new-root"] is entry.metadata and combined["fixed"] == "existing"


def test_union_refuses_duplicate_reference_even_if_the_values_happen_to_match():
    shared = object()
    view = enrollment_union([{"root": shared}, {"root": shared}])
    with pytest.raises(ValueError, match="ambiguous"):
        dict(view)


def test_later_union_conflict_never_silently_selects_the_first_backend():
    owned = {}
    view = enrollment_union([{"root": object()}, EnrollmentView(lambda: owned)])
    assert len(view) == 1
    owned["root"] = object()
    with pytest.raises(ValueError, match="ambiguous"):
        view["root"]


def test_iterators_snapshot_keys_while_subsequent_reads_observe_appends():
    owned = {"first": 1}
    view = EnrollmentView(lambda: owned)
    iterator = iter(view)
    owned["second"] = 2
    assert tuple(iterator) == ("first",)
    assert tuple(view) == ("first", "second")


def test_live_key_set_tracks_enrollment_but_plain_sets_remain_frozen():
    owned = {"old": 1}
    keys = EnrollmentKeys(EnrollmentView(lambda: owned))
    assert readonly_enrollment_keys(keys) is keys
    owned["new"] = 2
    assert keys == {"old", "new"} and "new" in keys
    with pytest.raises(AttributeError):
        keys.add("other")
    original = {"old"}
    fixed = readonly_enrollment_keys(original)
    original.add("new")
    assert fixed == {"old"}


def test_key_set_operations_return_stable_immutable_snapshots():
    owned = {"old": 1}
    keys = EnrollmentKeys(EnrollmentView(lambda: owned))
    intersection, union = keys & {"old"}, keys | {"other"}
    owned["new"] = 2
    assert intersection == {"old"} and union == {"old", "other"}
    assert keys & {"new"} == {"new"}
    assert isinstance(union, frozenset)
