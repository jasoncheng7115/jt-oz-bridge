"""Git patch review component tests over a synthetic transport only.

They cover the patch reader's contract, not checks against an installed OpenCode
or what a person viewing the review is shown.
"""

import copy
from dataclasses import replace
from types import MappingProxyType

import pytest

from jt_oz_bridge.adapters.opencode.git_review import (
    PATCH_SEMANTICS,
    GitPatchAttestation,
    V2NativeGitReview,
    review_attestation_sha256,
)
from jt_oz_bridge.domain import git_review as models
from tests.contract.test_git_review import prepared as summary_prepared
from tests.contract.test_leaf_resources import REF, finish


async def prepared(hook=None, *, enable_patch=True):
    p, t, d, original, raw, calls, writes, physical = await summary_prepared(hook)
    pins = {}
    if enable_patch:
        pins[REF] = GitPatchAttestation(
            reference=REF,
            review_attestation_sha256=review_attestation_sha256(original.attestations[REF]),
            semantics_sha256=PATCH_SEMANTICS,
            installed_evidence_sha256="c" * 64,
            verified_modes=frozenset({"working", "branch", "committed"}),
        )
    reader = V2NativeGitReview(
        original.client,
        original.attestations,
        directories=physical,
        patch_attestations=pins,
    )
    return p, t, d, reader, raw, calls, writes, physical


@pytest.mark.parametrize("mode,base", [("branch", "main"), ("committed", "main")])
async def test_working_patch_qualification_never_implies_other_comparison_modes(mode, base):
    p, t, _d, reader, raw, calls, writes, physical = await prepared()
    try:
        reader.patch_attestations = MappingProxyType(
            {REF: replace(reader.patch_attestations[REF], verified_modes=frozenset({"working"}))}
        )
        before = len(calls)
        with pytest.raises(ValueError, match="comparison_mode_not_qualified"):
            await reader.read_patch(REF, path="src/a.py", mode=mode, base=base)
        assert len(calls) == before and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "mode,base", [("working", None), ("branch", "main"), ("committed", "main")]
)
async def test_selected_git_patch_preserves_exact_comparison_and_never_mints_mutation(mode, base):
    p, t, _d, reader, raw, calls, writes, _physical = await prepared()
    try:
        method = getattr(reader, "read_patch", None)
        assert callable(method), "Original summary adapter has no patch-read interface"
        assert reader.qualified_patch(REF)
        assert reader.patch_contract_for(REF) == reader.contract_for(REF)
        view = await method(REF, path="src/a.py", mode=mode, base=base)
        assert isinstance(view, models.NativeGitPatch)
        assert view.reference == REF and view.mode == mode and view.requested_base == base
        assert view.file.path == "src/a.py" and view.patch == raw["diff"][0]["patch"]
        assert view.hidden_files == 1 and "private-secret" not in view.patch
        assert reader.current_patch(view) and not reader.current(view)
        assert not reader.current_patch(view.model_copy())
        assert not reader.current_patch(
            models.NativeGitPatch.model_validate_json(view.model_dump_json())
        )
        assert not any(
            (
                view.index_verified,
                view.head_verified,
                view.remote_verified,
                view.clean_verified,
                view.mutation_confirmation_usable,
                view.full_diff_display,
            )
        )
        assert p.certified_epoch(REF, t.profile.sha256) is None
        with pytest.raises(ValueError):
            await p.prove(REF, t.profile.sha256, "0" * 64)
        assert len(calls) == 12 and not writes
        for kind, request in calls:
            assert request.method == "GET"
            if kind == "diff":
                assert dict(request.url.params) == {
                    "location[directory]": REF.canonical_directory,
                    "mode": mode,
                    **({"base": base} if base else {}),
                }
    finally:
        await finish(p, t)


@pytest.mark.parametrize("path", [".env", ".ssh/key", "../x", "/etc/shadow", "a//b", "", None])
async def test_selected_patch_invalid_or_hidden_name_rejects_before_all_review_reads(path):
    p, t, _d, reader, _raw, calls, writes, physical = await prepared()
    try:
        with pytest.raises(ValueError):
            await reader.read_patch(REF, path=path)
        assert not calls and not physical.calls and not writes
        assert not reader._observed
    finally:
        await finish(p, t)


async def test_selected_patch_absent_path_does_not_substitute_first_or_hidden_file():
    p, t, _d, reader, _raw, _calls, writes, _physical = await prepared()
    try:
        with pytest.raises(ValueError, match="git_patch_selected_file_not_available"):
            await reader.read_patch(REF, path="src/absent.py")
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["bytes", "branch", "base", "owner", "policy", "attestation"])
async def test_selected_patch_boundary_drift_between_bundles_is_not_disclosed(fault):
    def hook(kind, count, value, p, t, d, raw):
        if count != 2:
            return
        if fault == "bytes" and kind == "diff":
            value["data"][0]["patch"] += "different"
        elif fault == "branch" and kind == "info":
            value["data"]["branch"]["current"] = "different"
        elif fault == "base" and kind == "base":
            value["data"]["ref"] = "refs/heads/different"
        elif kind == "diff":
            if fault == "owner":
                p.feed.owner.read.side_effect = ValueError("synthetic_owner_lost")
            elif fault == "policy":
                d["session.get"]["data"]["permissions"] = []
            elif fault == "attestation":
                t.attestation = replace(t.attestation)

    p, t, _d, reader, _raw, _calls, writes, _physical = await prepared(hook)
    try:
        with pytest.raises(ValueError):
            await reader.read_patch(REF, path="src/a.py")
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["physical", "deadline", "generation"])
async def test_returned_patch_requires_same_original_scope_after_last_await(fault, monkeypatch):
    p, t, _d, reader, _raw, _calls, writes, physical = await prepared()
    try:
        view = await reader.read_patch(REF, path="src/a.py")
        assert reader.current_patch(view)
        if fault == "physical":
            # current() checks an enrolled snapshot and its lifetime, not a new
            # filesystem observation. Revoke that authority for this check.
            physical.enabled = False
        elif fault == "deadline":
            context = reader._observed[id(view)]
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.git_review.time.time", lambda: context.deadline
            )
        else:
            t.attestation = replace(t.attestation)
        assert not reader.current_patch(view) and not writes
        assert p.certified_epoch(REF, t.profile.sha256) is None
    finally:
        await finish(p, t)


async def test_summary_still_excludes_patch_content_and_patch_provenance_stays_separate():
    p, t, _d, reader, _raw, _calls, writes, _physical = await prepared()
    try:
        summary = await reader.read(REF)
        assert reader.current(summary) and not reader.current_patch(summary)
        assert "unique-private-patch-text" not in summary.model_dump_json()
        view = await reader.read_patch(REF, path="src/a.py")
        assert reader.current_patch(view) and "unique-private-patch-text" in view.patch
        assert not reader.current(view)
        assert not writes
    finally:
        await finish(p, t)


async def test_other_file_secret_bytes_count_toward_patch_capacity_even_for_selected_safe_path():
    p, t, _d, reader, raw, _calls, writes, _physical = await prepared()
    try:
        raw["diff"][1]["patch"] = "x" * (1024**2 + 1)
        with pytest.raises(ValueError):
            await reader.read_patch(REF, path="src/a.py")
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


async def test_duplicate_selected_path_does_not_pick_arbitrary_patch():
    p, t, _d, reader, raw, _calls, writes, _physical = await prepared()
    try:
        raw["diff"].append(copy.deepcopy(raw["diff"][0]))
        with pytest.raises(ValueError):
            await reader.read_patch(REF, path="src/a.py")
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


async def test_summary_qualification_alone_never_enables_raw_patch_or_patch_contract():
    p, t, _d, reader, _raw, calls, writes, physical = await prepared(enable_patch=False)
    try:
        assert reader.qualified(REF) and not reader.qualified_patch(REF)
        for operation in (
            lambda: reader.require_patch(REF),
            lambda: reader.patch_contract_for(REF),
        ):
            with pytest.raises(ValueError, match="git_patch_projection_not_qualified"):
                operation()
        with pytest.raises(ValueError, match="git_patch_projection_not_qualified"):
            await reader.read_patch(REF, path="src/a.py")
        assert not calls and not physical.calls and not writes and not reader._observed
        summary = await reader.read(REF)
        assert reader.current(summary) and not reader.current_patch(summary)
        assert "unique-private-patch-text" not in summary.model_dump_json()
        assert len(calls) == 12 and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    ["root", "summary-digest", "summary-semantics", "evidence", "evidence-type", "other-root-map"],
)
async def test_each_patch_opt_in_fact_is_required_before_any_native_read(fault):
    p, t, _d, reader, _raw, calls, writes, physical = await prepared()
    try:
        original = reader.patch_attestations[REF]
        if fault == "other-root-map":
            pins = {REF.model_copy(update={"upstream_session_id": "ses_other"}): original}
        else:
            changes = {
                "root": {"reference": REF.model_copy(update={"upstream_session_id": "ses_other"})},
                "summary-digest": {"review_attestation_sha256": "0" * 64},
                "summary-semantics": {
                    "semantics_sha256": reader.attestations[REF].semantics_sha256
                },
                "evidence": {"installed_evidence_sha256": "not-a-sha256"},
                "evidence-type": {"installed_evidence_sha256": None},
            }[fault]
            pins = {REF: replace(original, **changes)}
        reader.patch_attestations = MappingProxyType(pins)
        assert reader.qualified(REF) and not reader.qualified_patch(REF)
        with pytest.raises(ValueError, match="git_patch_projection_not_qualified"):
            await reader.read_patch(REF, path="src/a.py")
        assert not calls and not physical.calls and not writes and not reader._observed
    finally:
        await finish(p, t)


async def test_default_constructor_has_no_patch_opt_in_even_with_full_summary_attestation():
    p, t, _d, original, _raw, calls, writes, physical = await summary_prepared()
    try:
        assert original.qualified(REF) and not original.qualified_patch(REF)
        with pytest.raises(ValueError):
            await original.read_patch(REF, path="src/a.py")
        assert not calls and not physical.calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["pin-replaced", "pin-removed", "summary-replaced"])
async def test_patch_current_requires_original_pin_identity_and_current_summary_digest(fault):
    p, t, _d, reader, _raw, _calls, writes, _physical = await prepared()
    try:
        summary = await reader.read(REF)
        view = await reader.read_patch(REF, path="src/a.py")
        assert reader.current_patch(view) and reader.current(summary)
        if fault == "pin-replaced":
            reader.patch_attestations = MappingProxyType(
                {REF: replace(reader.patch_attestations[REF])}
            )
            assert reader.qualified_patch(REF)
        elif fault == "pin-removed":
            reader.patch_attestations = MappingProxyType({})
        else:
            reader.attestations = MappingProxyType(
                {
                    REF: replace(
                        reader.attestations[REF],
                        installed_evidence_sha256="d" * 64,
                    )
                }
            )
            assert reader.qualified(REF) and not reader.qualified_patch(REF)
        assert not reader.current_patch(view) and not writes
        if fault != "summary-replaced":
            assert reader.current(summary)
    finally:
        await finish(p, t)


async def test_patch_pin_replacement_during_original_bundle_refuses_return():
    chosen = {}

    def hook(kind, count, value, p, t, d, raw):
        if kind == "diff" and count == 2:
            reader = chosen["reader"]
            reader.patch_attestations = MappingProxyType(
                {REF: replace(reader.patch_attestations[REF])}
            )

    p, t, _d, reader, _raw, _calls, writes, _physical = await prepared(hook)
    chosen["reader"] = reader
    try:
        with pytest.raises(ValueError, match="git_review_original_read_boundary_changed"):
            await reader.read_patch(REF, path="src/a.py")
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("file_count", [51, 1000])
async def test_selected_patch_after_fiftieth_file_keeps_original_full_diff_capacity(file_count):
    p, t, _d, reader, raw, calls, writes, _physical = await prepared()
    try:
        prototype = raw["diff"][0]
        raw["diff"] = [{**prototype, "file": f"src/file-{i:04}.py"} for i in range(file_count)]
        selected = raw["diff"][-1]
        view = await reader.read_patch(REF, path=selected["file"])
        assert view.file.path == selected["file"] and view.patch == selected["patch"]
        assert reader.current_patch(view) and view.hidden_files == 0
        assert len(calls) == 12 and not writes
        assert not view.mutation_confirmation_usable
    finally:
        await finish(p, t)
