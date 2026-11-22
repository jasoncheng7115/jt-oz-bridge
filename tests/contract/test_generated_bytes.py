"""Synthetic original-turn and binary HTTP graph; no Human or publication acceptance."""

import base64
import copy
import gc
import hashlib
import time
import weakref
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode import generated_files as module
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.generated_files import (
    BYTE_FEATURES,
    BYTE_SEMANTICS,
    GeneratedByteEvidence,
    GeneratedBytesAttestation,
    GeneratedScope,
    V2GeneratedFileReader,
)
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    RESOURCE_TYPES,
    ResourceSemanticAttestation,
    V2TurnResourceReader,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from tests.contract.test_generated_files import BODY, attestation, outputs
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_files import setup as binary_setup
from tests.contract.test_turn_resources import C, native_messages
from tests.contract.test_turn_resources import setup as turn_setup


@pytest.mark.parametrize("index", [0, 2])
async def test_fresh_same_owner_reconnection_compares_history_without_renewing_old_objects(index):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        previous = await reader.capture(C)
        old = await reader.read(previous, previous.files[index])
        old_evidence = reader.evidence(old)
        reader.turns.proofs.feed.index.connection_epoch = "9" * 64
        assert not reader.current(previous) and not reader.current_bytes(old)
        with pytest.raises(ContractError):
            reader.evidence(old)
        # A new feed generation needs an explicit fresh resource qualification;
        # reading alone must not silently regain mutation-watch membership.
        await reader.turns.proofs.watch(REF)
        fresh = await reader.capture(C)
        actual = await reader.read(fresh, fresh.files[index])
        evidence = reader.evidence(actual)
        assert actual.content == old.content and reader.current_bytes(actual)
        assert evidence.turn.connection_epoch != old_evidence.turn.connection_epoch
        assert evidence.stable_sha256 == old_evidence.stable_sha256
        assert evidence.discovery().stable_sha256 == old_evidence.discovery().stable_sha256
        assert actual.expires_at <= fresh.observed_at + 5 and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "changed",
    [
        "metadata",
        "contract",
        "semantics",
        "projection",
        "deadline",
        "selection",
        "native-owner",
        "native-contract",
        "native-deadline",
    ],
)
async def test_sealed_evidence_rejects_changed_origin_contract_and_extended_deadline(changed):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        outputs = await reader.capture(C)
        value = await reader.read(outputs, outputs.files[0])
        evidence = reader.evidence(value)
        raw = evidence.model_dump(mode="json")
        if changed == "metadata":
            raw["metadata_sha256"] = "0" * 64
        elif changed == "contract":
            raw["turn"]["contract_sha256"] = "0" * 64
        elif changed == "semantics":
            raw["byte_semantics_sha256"] = "0" * 64
        elif changed == "projection":
            raw["projection"]["sha256"] = "0" * 64
        elif changed == "deadline":
            raw["expires_at"] = raw["turn"]["expires_at"] + 1
        elif changed == "selection":
            raw["selection"]["file_index"] += 1
        elif changed == "native-owner":
            raw["native"]["owner_epoch"] = "0" * 64
        elif changed == "native-contract":
            raw["native"]["contract_sha256"] = "0" * 64
        else:
            raw["native"]["expires_at"] = raw["native"]["observed_at"] + 6
        with pytest.raises(ValueError):
            GeneratedByteEvidence.model_validate(raw)
        assert reader.current_bytes(value) and not writes
    finally:
        await finish(p, t)


def byte_attestation(turns):
    return GeneratedBytesAttestation(
        REF,
        turns.client.transport.profile.sha256,
        BYTE_SEMANTICS,
        "e" * 64,
        BYTE_FEATURES,
    )


async def setup(body=b"exact workspace\x00\xff", hook=None, binary_hook=None):
    p, t, d, files, reads, writes = await binary_setup(body, hook=binary_hook)
    messages = native_messages()
    outputs(messages)
    pages = []
    original = t.client._transport

    def handler(request):
        if request.method == "GET" and request.url.path.endswith("/message"):
            limit = int(request.url.params["limit"])
            if limit == 50:
                pages.append(str(request.url))
                if hook:
                    hook(len(pages), messages, d, p)
            return httpx.Response(200, json={"data": copy.deepcopy(messages[:limit]), "cursor": {}})
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    certificate = ResourceSemanticAttestation(
        REF.backend_id,
        REF.backend_identity,
        t.profile.sha256,
        RESOURCE_SEMANTICS,
        "b" * 64,
        RESOURCE_TYPES,
        frozenset({"succeeded", "failed", "interrupted"}),
    )
    turns = V2TurnResourceReader(files.client, attestation=certificate)
    reader = V2GeneratedFileReader(
        turns,
        attestation=attestation(turns),
        file_reader=files,
        byte_attestation=byte_attestation(turns),
    )
    return p, t, d, messages, reader, pages, reads, writes


@pytest.mark.parametrize("index", [0, 1, 2, 3])
async def test_same_original_turn_selected_snapshot_inline_and_tool_path_return_exact_bytes(index):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        captured = await reader.capture(C)
        result = await reader.read(captured, captured.files[index])
        expected = BODY if index == 2 else b"exact workspace\x00\xff"
        assert result.content == expected and reader.current_bytes(result)
        assert result.projection.size == len(expected)
        assert result.projection.sha256 == hashlib.sha256(expected).hexdigest()
        assert result.outputs is captured and result.selection is captured.files[index]
        assert result.expires_at == captured.expires_at
        assert result.observed_at >= captured.observed_at
        assert not result.publication_authorized and not writes
        evidence = reader.evidence(result)
        assert evidence.turn.correlation == C and evidence.projection == result.projection
        assert evidence.selection == result.selection and evidence.files == captured.files
        assert (evidence.native is None) == (index == 2)
        assert evidence.observed_at == result.observed_at
        assert evidence.expires_at == result.expires_at
        assert evidence.model_validate(evidence.model_dump(mode="json")) == evidence
        with pytest.raises(ContractError, match="original_byte_evidence"):
            reader.evidence(replace(result))
        assert len(reads) == (0 if index == 2 else 2) and len(pages) == 6
        assert "exact generated output" not in repr(result)
        assert "exact workspace" not in repr(result)
        assert not reader.current_bytes(replace(result))
        reference = weakref.ref(result)
        del result
        gc.collect()
        assert reference() is None
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["copy-metadata", "copy-selection", "foreign-selection", "stale"])
async def test_unissued_selection_or_metadata_is_rejected_before_any_additional_native_request(
    kind,
):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        captured = await reader.capture(C)
        selection = captured.files[0]
        if kind == "copy-metadata":
            captured = replace(captured)
        elif kind == "copy-selection":
            selection = selection.model_copy()
        elif kind == "foreign-selection":
            selection = selection.model_copy(update={"path": "another"})
        else:
            await reader.turns.capture(C)
        count = len(pages)
        with pytest.raises(ContractError, match="original_selection"):
            await reader.read(captured, selection)
        assert len(pages) == count and not reads and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "changed", ["snapshot", "uri", "tool-id", "name", "text", "new-user", "info"]
)
async def test_changed_original_candidate_or_turn_during_byte_read_never_issues_bytes(changed):
    def hook(number, messages, d, p):
        if number == 6:
            if changed == "snapshot":
                messages[1]["snapshot"]["files"][0] = "another.html"
            elif changed == "uri":
                messages[1]["content"][-1]["state"]["content"][1]["uri"] = (
                    "data:text/html;base64," + base64.b64encode(b"rewritten").decode()
                )
            elif changed == "tool-id":
                messages[1]["content"][-1]["id"] = "another_call"
            elif changed == "name":
                messages[1]["content"][-1]["state"]["content"][1]["name"] = "another.html"
            elif changed == "text":
                messages[1]["content"][0]["text"] = "another answer"
            elif changed == "new-user":
                user = copy.deepcopy(messages[-1])
                user["id"] = "another_input"
                messages.insert(1, user)
            else:
                d["session.get"]["data"]["title"] = "another info projection"

    p, t, d, messages, reader, pages, reads, writes = await setup(hook=hook)
    try:
        captured = await reader.capture(C)
        with pytest.raises(ContractError):
            await reader.read(captured, captured.files[2])
        assert not reader._bytes and not reads and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("changed", ["content", "policy", "outside"])
async def test_workspace_changes_and_native_outside_scope_response_fail_without_byte_witness(
    changed,
):
    def hook(number, d, p, t, files):
        if number == 2:
            if changed == "content":
                return httpx.Response(
                    200,
                    content=b"different",
                    headers={
                        "content-type": "text/plain",
                        "etag": "changed",
                        "content-length": "9",
                    },
                )
            if changed == "policy":
                d["session.get"]["data"]["permissions"][0]["effect"] = "allow"
            else:
                return httpx.Response(403, content=b"outside symlink")

    p, t, d, messages, reader, pages, reads, writes = await setup(binary_hook=hook)
    try:
        captured = await reader.capture(C)
        with pytest.raises(ValueError):
            await reader.read(captured, captured.files[0])
        assert not reader._bytes and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("index", [0, 2])
async def test_byte_capture_cannot_extend_original_metadata_deadline(monkeypatch, index):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        captured = await reader.capture(C)
        result = await reader.read(captured, captured.files[index])
        monkeypatch.setattr(module, "time", SimpleNamespace(time=lambda: captured.expires_at))
        assert not reader.current_bytes(result)
    finally:
        await finish(p, t)


async def test_expiry_during_inline_read_fails_even_when_same_native_projection_survives(
    monkeypatch,
):
    def hook(number, messages, d, p):
        if number == 6:
            monkeypatch.setattr(module, "time", SimpleNamespace(time=lambda: time.time() + 10))

    p, t, d, messages, reader, pages, reads, writes = await setup(hook=hook)
    try:
        captured = await reader.capture(C)
        with pytest.raises(ContractError):
            await reader.read(captured, captured.files[2])
        assert not reader._bytes
    finally:
        await finish(p, t)


async def test_inline_capture_needs_no_filesystem_reader_and_never_fetches_remote_uri():
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(
            turns, attestation=attestation(turns), byte_attestation=byte_attestation(turns)
        )
        captured = await reader.capture(C)
        result = await reader.read(captured, captured.files[2])
        assert result.content == BODY and reader.current_bytes(result)
        with pytest.raises(ContractError, match="qualified_workspace_reader"):
            await reader.read(captured, captured.files[0])
        assert len(pages) == 6
    finally:
        await finish(p, t)


async def test_maximum_inline_response_retains_exact_original_binary_bytes():
    body = b"\xff" * MAX_ATTACHMENT_BYTES
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        messages[1]["content"][-1]["state"]["content"][1].update(
            uri="data:application/octet-stream;base64," + base64.b64encode(body).decode(),
            mime="application/octet-stream",
            name="output.bin",
        )
        reader = V2GeneratedFileReader(
            turns, attestation=attestation(turns), byte_attestation=byte_attestation(turns)
        )
        captured = await reader.capture(C)
        result = await reader.read(captured, captured.files[2])
        assert result.content == body and reader.current_bytes(result)
        assert result.projection.size == MAX_ATTACHMENT_BYTES
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "field,value",
    [
        ("missing", None),
        ("reference", REF.model_copy(update={"backend_identity": "foreign"})),
        ("contract_sha256", "0" * 64),
        ("semantics_sha256", "0" * 64),
        ("verified_features", frozenset({"inline-exact-bytes"})),
        ("installed_evidence_sha256", "not-evidence"),
    ],
)
async def test_metadata_certificate_never_grants_byte_access(field, value):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        captured = await reader.capture(C)
        reader.byte_attestation = (
            None if field == "missing" else replace(reader.byte_attestation, **{field: value})
        )
        with pytest.raises(ContractError, match="bytes_semantics_unqualified"):
            await reader.read(captured, captured.files[2])
        assert len(pages) == 4 and not reads and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("changed", ["byte-attestation", "reader", "new-turn", "foreign-client"])
async def test_replaced_original_read_dependencies_invalidate_already_captured_bytes(changed):
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        captured = await reader.capture(C)
        result = await reader.read(captured, captured.files[0])
        if changed == "byte-attestation":
            reader.byte_attestation = replace(reader.byte_attestation)
        elif changed == "reader":
            reader.file_reader = copy.copy(reader.file_reader)
        elif changed == "new-turn":
            await reader.turns.capture(C)
        else:
            reader.file_reader.client = copy.copy(reader.turns.client)
        assert not reader.current_bytes(result)
    finally:
        await finish(p, t)


def scoped(reader, origins, max_bytes):
    scope = GeneratedScope(frozenset(origins), max_bytes)
    reader.attestation = replace(reader.attestation, scope=scope)
    reader.byte_attestation = replace(reader.byte_attestation, scope=scope)
    return scope


async def test_out_of_scope_origins_are_counted_unsupported_at_capture_never_issued():
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        full = await reader.capture(C)
        scoped(reader, {("workspace", "snapshot")}, MAX_ATTACHMENT_BYTES)
        snapshot_only = await reader.capture(C)
        assert [f.origin for f in snapshot_only.files] == ["snapshot", "snapshot"]
        assert snapshot_only.hidden_count == full.hidden_count
        assert snapshot_only.unsupported_count == full.unsupported_count + 2
        evidence = reader.discovery_evidence(snapshot_only)
        assert evidence.unsupported_count == snapshot_only.unsupported_count
        # The earlier full-scope object can no longer be read under the narrowed scope.
        with pytest.raises(ContractError, match="original_selection"):
            await reader.read(full, full.files[2])
        result = await reader.read(snapshot_only, snapshot_only.files[0])
        assert reader.current_bytes(result) and not writes
    finally:
        await finish(p, t)


async def test_workspace_output_above_the_qualified_size_is_refused_at_read():
    body = b"exact workspace\x00\xff"
    p, t, d, messages, reader, pages, reads, writes = await setup(body)
    try:
        scoped(reader, {("workspace", "snapshot")}, len(body) - 1)
        captured = await reader.capture(C)
        with pytest.raises(ValueError, match="native_file_too_large"):
            await reader.read(captured, captured.files[0])
        assert not reader._bytes and not writes
        scoped(reader, {("workspace", "snapshot")}, len(body))
        captured = await reader.capture(C)
        result = await reader.read(captured, captured.files[0])
        assert result.projection.size == len(body)
    finally:
        await finish(p, t)


async def test_inline_output_above_the_qualified_size_is_unsupported_at_capture():
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        full = await reader.capture(C)
        scoped(reader, {(f.kind, f.origin) for f in full.files}, len(BODY) - 1)
        smaller = await reader.capture(C)
        assert all(f.kind != "inline" for f in smaller.files)
        assert smaller.unsupported_count == full.unsupported_count + 1
    finally:
        await finish(p, t)


async def test_byte_and_metadata_scopes_must_be_the_same_qualification():
    p, t, d, messages, reader, pages, reads, writes = await setup()
    try:
        captured = await reader.capture(C)
        reader.byte_attestation = replace(
            reader.byte_attestation,
            scope=GeneratedScope(frozenset({("workspace", "snapshot")}), MAX_ATTACHMENT_BYTES),
        )
        with pytest.raises(ContractError, match="bytes_semantics_unqualified"):
            await reader.read(captured, captured.files[0])
        assert not reads and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "origins, max_bytes",
    [
        (set(), 1),
        ({("inline", "snapshot")}, 1),
        ({("workspace", "url")}, 1),
        ({("workspace", "snapshot")}, 0),
        ({("workspace", "snapshot")}, MAX_ATTACHMENT_BYTES + 1),
        ({("workspace", "snapshot")}, True),
    ],
)
def test_scope_accepts_only_known_origins_and_a_bounded_positive_size(origins, max_bytes):
    with pytest.raises(ValueError, match="generated_scope_invalid"):
        GeneratedScope(frozenset(origins), max_bytes)
