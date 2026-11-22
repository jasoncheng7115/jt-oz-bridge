"""Synthetic reviewed-packet parsing/composition, never installed qualification.

The maximum-size cases below are typed parser fixtures, not 20 MiB byte-read
acceptance. Actual adapter byte/capacity coverage remains in the contract suite.
"""

import asyncio
import copy
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode import generated_files as component
from jt_oz_bridge.adapters.opencode.generated_files import (
    BYTE_FEATURES,
    BYTE_SEMANTICS,
    OUTPUT_FEATURES,
    OUTPUT_SEMANTICS,
    GeneratedByteEvidence,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.services.file_enrollment import component_sha
from jt_oz_bridge.services.generated_enrollment import NEGATIVE_CHECKS, generated_qualification
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.contract.test_generated_bytes import setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_turn_resources import C
from tests.integration.test_catalog_enrollment import catalogs as catalogs
from tests.integration.test_catalog_enrollment import close_pipeline, configure_catalogs
from tests.integration.test_file_enrollment import files as files
from tests.integration.test_runtime_enrollment import add_second_root
from tests.integration.test_runtime_enrollment import enrolled as enrolled


def checksum(value):
    return digest(
        dict(
            turn=value["turn"],
            outputs=value["files"],
            hidden=value["hidden_count"],
            unsupported=value["unsupported_count"],
            semantics=OUTPUT_SEMANTICS,
        )
    )


@pytest.fixture
async def generated(catalogs):
    p, t, _, _, reader, _, _, _ = await setup()
    try:
        raw_cases = []
        for index in (0, 2, 3):
            outputs = await reader.capture(C)
            raw_cases.append(
                reader.evidence(await reader.read(outputs, outputs.files[index])).model_dump(
                    mode="json"
                )
            )
        b = catalogs.manifest["backends"][0]
        owner = json.loads(catalogs.documents[Path(b["owner"]["path"])])
        for value in raw_cases:
            value["turn"]["correlation"]["reference"] = catalogs.ref
            if value["native"]:
                value["native"]["reference"] = catalogs.ref
            value["metadata_sha256"] = checksum(value)
        # Parser-only boundary fixtures: no large original Native I/O is claimed.
        for base in (raw_cases[0], raw_cases[1]):
            large = copy.deepcopy(base)
            large["projection"]["size"] = MAX_ATTACHMENT_BYTES
            if large["native"]:
                large["native"]["projection"]["size"] = MAX_ATTACHMENT_BYTES
            else:
                large["selection"]["size"] = MAX_ATTACHMENT_BYTES
                for selection in large["files"]:
                    if selection["kind"] == "inline":
                        selection["size"] = MAX_ATTACHMENT_BYTES
            large["metadata_sha256"] = checksum(large)
            raw_cases.append(large)
        proofs = [GeneratedByteEvidence.model_validate(value) for value in raw_cases]
        inventories = [p.discovery().model_dump(mode="json") for p in proofs]
        empty = copy.deepcopy(inventories[0])
        empty.update(files=[], hidden_count=0, unsupported_count=0)
        empty["metadata_sha256"] = checksum(empty)
        inventories.append(empty)
        host = dict(
            pid=42,
            nrestarts=0,
            binary_sha256=owner["executable_sha256"],
            owner_epoch=proofs[0].turn.owner_epoch,
        )
        packet = dict(
            format="qualified-generated-outputs-v1",
            operator_review="installed-evidence-reviewed-for-development-runtime",
            actual_original_native_outputs=True,
            human_input_fabricated=False,
            backend_replaced=False,
            native_database_bytes_read=False,
            native_restarted=False,
            reference=catalogs.ref,
            contract_sha256=b["schema_file"]["sha256"],
            metadata_semantics_sha256=OUTPUT_SEMANTICS,
            byte_semantics_sha256=BYTE_SEMANTICS,
            component_sha256=await asyncio.to_thread(component_sha, component),
            metadata_features=sorted(OUTPUT_FEATURES),
            byte_features=sorted(BYTE_FEATURES),
            native_before=host,
            native_after=copy.deepcopy(host),
            negative_checks=dict.fromkeys(NEGATIVE_CHECKS, True),
            inventories=inventories,
            byte_cases=[
                dict(
                    original_object_current=True,
                    exact_native_bytes_verified=True,
                    no_direct_local_read=True,
                    evidence=proof.model_dump(mode="json"),
                )
                for proof in proofs
            ],
        )
        catalogs.packet = packet

        def save():
            catalogs.manifest["format"] = "qualified-consumer-runtime-v6"
            b["generated_outputs"] = catalogs.pin("generated-v6.json", catalogs.packet)
            catalogs.save_catalogs()

        catalogs.save_generated = save
        catalogs.settings.runtime.generated_returns_enabled = True
        save()
        return catalogs
    finally:
        await finish(p, t)


def qualify(g):
    b = g.manifest["backends"][0]
    owner = json.loads(g.documents[Path(b["owner"]["path"])])
    return generated_qualification(
        json.dumps(g.packet).encode(),
        reference=SessionRef.model_validate(g.ref),
        contract_sha256=b["schema_file"]["sha256"],
        executable_sha256=owner["executable_sha256"],
        evidence_sha256="f" * 64,
    )


def test_complete_reviewed_packet_returns_only_pinned_attestations(generated):
    a, b = qualify(generated)
    assert a.reference == b.reference == SessionRef.model_validate(generated.ref)
    assert a.installed_evidence_sha256 == b.installed_evidence_sha256 == "f" * 64
    assert a.verified_features == OUTPUT_FEATURES and b.verified_features == BYTE_FEATURES


@pytest.mark.parametrize(
    "field",
    [
        "format",
        "operator_review",
        "actual_original_native_outputs",
        "human_input_fabricated",
        "backend_replaced",
        "native_database_bytes_read",
        "native_restarted",
        "reference",
        "contract_sha256",
        "component_sha256",
        "metadata_semantics_sha256",
        "byte_semantics_sha256",
        "metadata_features",
        "byte_features",
        "native_after",
        "negative_checks",
    ],
)
def test_rehashed_packet_cannot_self_assert_wrong_scope_or_component(generated, field):
    old = generated.packet[field]
    generated.packet[field] = not old if isinstance(old, bool) else []
    generated.save_generated()
    with pytest.raises(ValueError):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize(
    "change",
    [
        "missing-empty",
        "missing-bytes",
        "missing-workspace-tool",
        "small-only",
        "unmatched-inventory",
        "not-current",
        "direct-local-read",
        "wrong-owner",
        "bad-projection",
    ],
)
def test_incomplete_original_byte_or_inventory_history_fails_even_disabled(generated, change):
    p = generated.packet
    if change == "missing-empty":
        p["inventories"] = p["inventories"][:-1]
    elif change == "missing-bytes":
        p["byte_cases"] = []
    elif change == "missing-workspace-tool":
        p["byte_cases"][2] = copy.deepcopy(p["byte_cases"][0])
    elif change == "small-only":
        p["byte_cases"][3:] = copy.deepcopy(p["byte_cases"][:2])
    elif change == "unmatched-inventory":
        p["inventories"] = [p["inventories"][0], p["inventories"][-1]]
    elif change in ("not-current", "direct-local-read"):
        p["byte_cases"][0][
            "original_object_current" if change == "not-current" else "no_direct_local_read"
        ] = False
    elif change == "wrong-owner":
        p["native_before"]["owner_epoch"] = p["native_after"]["owner_epoch"] = "0" * 64
    else:
        p["byte_cases"][0]["evidence"]["projection"]["size"] += 1
    generated.settings.runtime.generated_returns_enabled = False
    generated.save_generated()
    with pytest.raises(ValueError):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize("change", ["legacy-enabled", "legacy-with-pin", "v6-missing-pin", "hash"])
def test_generated_enrollment_requires_exact_explicit_v6_root_file(generated, change):
    b = generated.manifest["backends"][0]
    if change == "hash":
        b["generated_outputs"]["sha256"] = "0" * 64
    elif change == "v6-missing-pin":
        b.pop("generated_outputs")
    else:
        generated.manifest["format"] = "qualified-consumer-runtime-v5"
        if change == "legacy-enabled":
            b.pop("generated_outputs")
    generated.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize("enabled", [False, True])
async def test_v6_composes_exact_original_reader_source_and_journal_without_io(
    generated, db, monkeypatch, enabled
):
    generated.settings.runtime.generated_returns_enabled = enabled
    resolver = runtime.resolve_secret
    monkeypatch.setattr(
        runtime, "resolve_secret", lambda _: pytest.fail("credentials during inert read")
    )
    value, sha = runtime.read_enrollment(generated.settings)
    monkeypatch.setattr(runtime, "resolve_secret", resolver)
    pipe = runtime.build_pipeline(generated.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert pipe.files is not None and pipe.incoming is None
        if enabled:
            assert pipe.generated is not None and isinstance(
                pipe.files.journal, GeneratedFileReturnJournal
            )
            assert pipe.generated.journal is pipe.files.journal
            assert (
                pipe.generated.journal.source is pipe.source and pipe.generated.fence == pipe.fence
            )
            for ref, reader in pipe.generated.journal.generated_readers.items():
                backend = pipe.backends[ref.backend_id]
                assert reader.turns is backend.results.registry.selected(ref).results
                assert reader.file_reader is pipe.files.readers[ref]
                assert reader.turns.client is reader.file_reader.client
        else:
            assert pipe.generated is None and not isinstance(
                pipe.files.journal, GeneratedFileReturnJournal
            )
    finally:
        await close_pipeline(pipe)


def scoped_originals(generated):
    """Two synthetic original Roots, one explicitly certified for automatic output."""
    second = add_second_root(generated)
    second.pop("generated_outputs", None)
    configure_catalogs(generated)
    generated.manifest["format"] = "qualified-consumer-runtime-v7"
    generated.manifest["generated_roots"] = [copy.deepcopy(generated.ref)]
    generated.save_catalogs()
    return second


@pytest.mark.parametrize("enabled", [False, True])
async def test_v7_same_backend_project_has_exact_generated_scope_and_all_manual_readers(
    generated, db, monkeypatch, enabled
):
    second = scoped_originals(generated)
    generated.settings.runtime.generated_returns_enabled = enabled
    resolver = runtime.resolve_secret
    monkeypatch.setattr(
        runtime, "resolve_secret", lambda _: pytest.fail("inert read used a credential")
    )
    value, sha = runtime.read_enrollment(generated.settings)
    monkeypatch.setattr(runtime, "resolve_secret", resolver)
    selected = SessionRef.model_validate(generated.ref)
    unselected = SessionRef.model_validate(second["reference"])
    assert value.generated_references() == {selected}
    assert (
        selected.backend_id == unselected.backend_id
        and selected.project_id == unselected.project_id
    )
    pipe = runtime.build_pipeline(generated.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert pipe.files is not None and pipe.file_menus is not None
        assert set(pipe.files.readers) == {selected, unselected}
        assert set(pipe.file_menus.catalogs) == {selected, unselected}
        if enabled:
            assert pipe.generated is not None
            assert set(pipe.generated.journal.generated_readers) == {selected}
            reader = pipe.generated.journal.generated_readers[selected]
            assert reader.file_reader is pipe.files.readers[selected]
            assert (
                reader.turns
                is pipe.backends[selected.backend_id].results.registry.selected(selected).results
            )
        else:
            assert pipe.generated is None
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "empty",
        "null",
        "duplicate",
        "foreign-session",
        "foreign-backend",
        "foreign-project",
        "foreign-directory",
        "missing-certificate",
        "extra-certificate",
        "certificate-hash",
        "copied-other-root",
        "missing-physical-catalog",
        "missing-file-reader",
    ],
)
def test_v7_rejects_incomplete_or_retargeted_scope_even_with_capture_disabled(
    generated, enabled, change
):
    second = scoped_originals(generated)
    generated.settings.runtime.generated_returns_enabled = enabled
    roots = generated.manifest["generated_roots"]
    first = generated.manifest["backends"][0]
    if change == "missing":
        generated.manifest.pop("generated_roots")
    elif change == "empty":
        generated.manifest["generated_roots"] = []
    elif change == "null":
        generated.manifest["generated_roots"] = None
    elif change == "duplicate":
        roots.append(copy.deepcopy(roots[0]))
    elif change.startswith("foreign-"):
        key = {
            "foreign-session": "upstream_session_id",
            "foreign-backend": "backend_identity",
            "foreign-project": "project_id",
            "foreign-directory": "canonical_directory",
        }[change]
        roots[0][key] = "/unrelated" if key == "canonical_directory" else "unrelated"
    elif change == "missing-certificate":
        first.pop("generated_outputs")
    elif change == "extra-certificate":
        second["generated_outputs"] = copy.deepcopy(first["generated_outputs"])
    elif change == "certificate-hash":
        first["generated_outputs"]["sha256"] = "0" * 64
    elif change == "copied-other-root":
        second["generated_outputs"] = first.pop("generated_outputs")
        generated.manifest["generated_roots"] = [second["reference"]]
    elif change == "missing-physical-catalog":
        second.pop("workspace_catalog")
        # Preserve the removal instead of letting save_catalogs regenerate it.
        generated.save()
        with pytest.raises(ValueError):
            runtime.read_enrollment(generated.settings)
        return
    else:
        second.pop("file_read")
    generated.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize("version", ["v5", "v6"])
@pytest.mark.parametrize("scope", [None, [], "selected"])
def test_legacy_enrollment_cannot_silently_accept_a_v7_scope_field(generated, version, scope):
    generated.manifest["format"] = "qualified-consumer-runtime-" + version
    generated.manifest["generated_roots"] = [generated.ref] if scope == "selected" else scope
    generated.save_catalogs()
    with pytest.raises(ValueError, match="explicit_generated_roots_require_v7"):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize("version", ["v5", "v6", "v7"])
@pytest.mark.parametrize("mode", ["python", "json"])
def test_scope_serialization_preserves_legacy_packets_and_explicit_v7_selection(
    generated, version, mode
):
    if version == "v7":
        scoped_originals(generated)
    elif version == "v5":
        generated.manifest["format"] = "qualified-consumer-runtime-v5"
        generated.manifest["backends"][0].pop("generated_outputs")
        generated.settings.runtime.generated_returns_enabled = False
        generated.save_catalogs()
    value, _ = runtime.read_enrollment(generated.settings)
    packet = value.model_dump(mode=mode)
    assert ("generated_roots" in packet) == (version == "v7")
    restored = runtime.RuntimeEnrollment.model_validate(packet)
    assert restored == value and restored.generated_references() == value.generated_references()


def test_v6_still_refuses_partial_original_root_certification(generated):
    scoped_originals(generated)
    generated.manifest["format"] = "qualified-consumer-runtime-v6"
    generated.manifest.pop("generated_roots")
    generated.save_catalogs()
    with pytest.raises(ValueError, match="v6_requires_every_original_generated_qualification"):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize(
    "change", ["missing-bytes", "small-only", "wrong-owner", "wrong-component"]
)
def test_v7_keeps_complete_original_generated_packet_requirements_while_disabled(generated, change):
    scoped_originals(generated)
    generated.settings.runtime.generated_returns_enabled = False
    packet = copy.deepcopy(generated.packet)
    if change == "missing-bytes":
        packet["byte_cases"] = []
    elif change == "small-only":
        packet["byte_cases"][3:] = copy.deepcopy(packet["byte_cases"][:2])
    elif change == "wrong-owner":
        packet["native_after"]["owner_epoch"] = "0" * 64
    else:
        packet["component_sha256"] = "0" * 64
    generated.manifest["backends"][0]["generated_outputs"] = generated.pin(
        "bad-v7-generated.json", packet
    )
    generated.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(generated.settings)


@pytest.mark.parametrize("change", ["extra-scope", "missing-scope", "extra-certificate"])
def test_composition_rechecks_v7_scope_after_a_model_copy(generated, db, change):
    scoped_originals(generated)
    value, sha = runtime.read_enrollment(generated.settings)
    if change == "extra-scope":
        modified = value.model_copy(
            update={"generated_roots": tuple(b.reference for b in value.backends)}
        )
    elif change == "missing-scope":
        modified = value.model_copy(update={"generated_roots": ()})
    else:
        second = value.backends[1].model_copy(
            update={"generated_outputs": value.backends[0].generated_outputs}
        )
        modified = value.model_copy(update={"backends": (value.backends[0], second)})
    with pytest.raises(ValueError, match="exact_explicit_generated_roots"):
        runtime.build_pipeline(generated.settings, modified, sha, db, ConsumerFence("synthetic", 1))


def scoped_packet(g):
    """v2: only the workspace cases, plus parser-only distinct smaller copies of the
    snapshot case, so the declared scope is exactly what the cases cover."""
    packet = copy.deepcopy(g.packet)
    cases = [c for c in packet["byte_cases"] if c["evidence"]["selection"]["kind"] == "workspace"]
    cases = [c for c in cases if c["evidence"]["projection"]["size"] < MAX_ATTACHMENT_BYTES]
    snapshot = next(c for c in cases if c["evidence"]["selection"]["origin"] == "snapshot")
    for size in (1, 2, 3):
        extra = copy.deepcopy(snapshot)
        extra["evidence"]["projection"]["size"] = size
        extra["evidence"]["native"]["projection"]["size"] = size
        cases.append(extra)
    packet["byte_cases"] = cases
    sizes = [c["evidence"]["projection"]["size"] for c in cases]
    packet["format"] = "qualified-generated-outputs-v2"
    packet["scope"] = {
        "origins": [
            {"kind": "workspace", "origin": "snapshot"},
            {"kind": "workspace", "origin": "tool"},
        ],
        "max_bytes": max(sizes),
    }
    return packet


def qualify_packet(g, packet):
    b = g.manifest["backends"][0]
    owner = json.loads(g.documents[Path(b["owner"]["path"])])
    return generated_qualification(
        json.dumps(packet).encode(),
        reference=SessionRef.model_validate(g.ref),
        contract_sha256=b["schema_file"]["sha256"],
        executable_sha256=owner["executable_sha256"],
        evidence_sha256="f" * 64,
    )


def test_v1_evidence_keeps_the_full_scope(generated):
    from jt_oz_bridge.adapters.opencode.generated_files import FULL_SCOPE

    a, b = qualify(generated)
    assert a.scope == b.scope == FULL_SCOPE


def test_v2_evidence_declares_exactly_the_observed_origins_and_size(generated):
    packet = scoped_packet(generated)
    a, b = qualify_packet(generated, packet)
    assert a.scope == b.scope
    assert a.scope.origins == {("workspace", "snapshot"), ("workspace", "tool")}
    assert a.scope.max_bytes == packet["scope"]["max_bytes"] < MAX_ATTACHMENT_BYTES


@pytest.mark.parametrize(
    "change",
    [
        "unread-origin",
        "larger-max",
        "smaller-max",
        "duplicate-case",
        "v2-without-scope",
        "v1-with-scope",
        "unknown-origin",
        "repeated-origin",
        "extra-key",
        "zero-max",
        "over-hard-max",
        "bool-max",
        "empty-origins",
        "too-few-cases",
    ],
)
def test_v2_scope_cannot_claim_more_or_less_than_its_cases(generated, change):
    packet = scoped_packet(generated)
    scope = packet["scope"]
    if change == "unread-origin":
        scope["origins"].append({"kind": "inline", "origin": "tool"})
    elif change == "larger-max":
        scope["max_bytes"] += 1
    elif change == "smaller-max":
        scope["max_bytes"] -= 1
    elif change == "duplicate-case":
        packet["byte_cases"][-1] = copy.deepcopy(packet["byte_cases"][-2])
    elif change == "v2-without-scope":
        packet.pop("scope")
    elif change == "v1-with-scope":
        packet["format"] = "qualified-generated-outputs-v1"
    elif change == "unknown-origin":
        scope["origins"][0] = {"kind": "workspace", "origin": "url"}
    elif change == "repeated-origin":
        scope["origins"].append(copy.deepcopy(scope["origins"][0]))
    elif change == "extra-key":
        scope["note"] = "all"
    elif change == "zero-max":
        scope["max_bytes"] = 0
    elif change == "over-hard-max":
        scope["max_bytes"] = MAX_ATTACHMENT_BYTES + 1
    elif change == "bool-max":
        scope["max_bytes"] = True
    elif change == "empty-origins":
        scope["origins"] = []
    else:
        packet["byte_cases"] = packet["byte_cases"][:4]
    with pytest.raises(ValueError):
        qualify_packet(generated, packet)


@pytest.mark.parametrize("enabled", [False, True])
async def test_v2_scope_reaches_the_composed_generated_reader(generated, db, enabled):
    generated.packet = scoped_packet(generated)
    generated.settings.runtime.generated_returns_enabled = enabled
    generated.save_generated()
    value, sha = runtime.read_enrollment(generated.settings)
    pipe = runtime.build_pipeline(generated.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        if enabled:
            assert pipe.generated is not None
            (reader,) = pipe.generated.journal.generated_readers.values()
            assert reader.attestation.scope == reader.byte_attestation.scope
            assert reader.attestation.scope.max_bytes == generated.packet["scope"]["max_bytes"]
            assert ("inline", "tool") not in reader.attestation.scope.origins
        else:
            assert pipe.generated is None
    finally:
        await close_pipeline(pipe)
