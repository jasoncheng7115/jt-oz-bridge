"""Structured output discovery, synthetic Native; no publication authority."""

import base64
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode import generated_files as module
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.generated_files import (
    MAX_OUTPUTS,
    OUTPUT_FEATURES,
    OUTPUT_SEMANTICS,
    GeneratedFile,
    GeneratedFileAttestation,
    V2GeneratedFileReader,
    inline_metadata,
    output_projection,
    workspace_uri,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_turn_resources import C, native_messages
from tests.contract.test_turn_resources import setup as turn_setup

BODY = b"<html>exact generated output</html>"
URI = "data:text/html;base64," + base64.b64encode(BODY).decode()


def outputs(messages):
    assistant = messages[1]
    assistant["snapshot"] = {"files": ["board.html", "nested/report.pdf", ".env", "../escape"]}
    assistant["content"].append(
        {
            "type": "tool",
            "id": "call_output_fixture",
            "name": "render",
            "time": {"created": 2, "ran": 2.1, "completed": 2.4},
            "state": {
                "status": "completed",
                "input": {"PRIVATE_TOOL_INPUT": "NEVER_RETAIN_INPUT"},
                "content": [
                    {"type": "text", "text": "NEVER_TREAT_THIS_PATH_AS_A_COMMAND /etc/passwd"},
                    {"type": "file", "uri": URI, "mime": "text/html", "name": "board.html"},
                    {
                        "type": "file",
                        "uri": "file://" + REF.canonical_directory + "/rendered.pdf",
                        "mime": "application/pdf",
                        "name": "rendered.pdf",
                    },
                    {
                        "type": "file",
                        "uri": "https://169.254.169.254/SECRET_REMOTE_URI",
                        "mime": "text/plain",
                    },
                ],
            },
        }
    )


def attestation(turns):
    return GeneratedFileAttestation(
        REF, turns.client.transport.profile.sha256, OUTPUT_SEMANTICS, "d" * 64, OUTPUT_FEATURES
    )


async def test_correlated_snapshot_and_tool_outputs_are_metadata_only_and_never_fetched():
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        requests = []

        async def get_only(request):
            assert request.method == "GET"
            assert request.url.host != "169.254.169.254"
            requests.append(request)

        t.client.event_hooks["request"].append(get_only)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        result = await reader.capture(C)
        assert reader.current(result) and result.metadata_only is True and len(pages) == 4
        assert len(result.files) == 4 and result.hidden_count == 2 and result.unsupported_count == 1
        assert [f.origin for f in result.files] == ["snapshot", "snapshot", "tool", "tool"]
        inline = result.files[2]
        assert inline.kind == "inline" and inline.path is None and inline.size == len(BODY)
        assert inline.sha256 == hashlib.sha256(BODY).hexdigest()
        assert result.files[3].path == "rendered.pdf" and result.files[3].size is None
        value = json.dumps([f.model_dump() for f in result.files])
        assert not any(
            secret in value
            for secret in (
                URI,
                BODY.decode(),
                "NEVER_RETAIN_INPUT",
                "NEVER_RETAIN_REASONING",
                "NEVER_RETAIN_METADATA",
                "SECRET_REMOTE_URI",
                "/etc/passwd",
            )
        )
        assert requests and not reader.current(replace(result))
        assert result.expires_at - result.observed_at <= 5
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "bad", ["missing", "reference", "contract", "semantics", "features", "hash"]
)
async def test_missing_or_foreign_attestation_blocks_before_native_http(bad):
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        selected = attestation(turns)
        changes = {
            "reference": {"reference": REF.model_copy(update={"backend_identity": "foreign"})},
            "contract": {"contract_sha256": "0" * 64},
            "semantics": {"semantics_sha256": "0" * 64},
            "features": {"verified_features": frozenset({"owned-turn"})},
            "hash": {"installed_evidence_sha256": "not-a-certificate"},
        }
        reader = V2GeneratedFileReader(
            turns, attestation=None if bad == "missing" else replace(selected, **changes[bad])
        )
        with pytest.raises(ContractError, match="unqualified"):
            await reader.capture(C)
        assert not pages
    finally:
        await finish(p, t)


@pytest.mark.parametrize("changed", ["snapshot", "inline", "name", "legacy", "duplicate"])
async def test_changed_structured_or_legacy_projection_never_becomes_a_witness(changed):
    def hook(number, messages, d, p):
        if number == 4:
            if changed == "snapshot":
                messages[1]["snapshot"]["files"][0] = "other.html"
            elif changed == "inline":
                messages[1]["content"][-1]["state"]["content"][1]["uri"] = URI + "QQ=="
            elif changed == "name":
                messages[1]["content"][-1]["state"]["content"][1]["name"] = "changed.html"
            elif changed == "legacy":
                messages[1]["content"][0]["text"] = "changed answer"
            else:
                return {"data": [messages[0], messages[0], *messages[1:]], "cursor": {}}

    p, t, d, messages, turns, pages = await turn_setup(hook)
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        with pytest.raises(ContractError):
            await reader.capture(C)
    finally:
        await finish(p, t)


async def test_private_reasoning_and_input_do_not_become_file_candidates():
    def hook(number, messages, d, p):
        if number == 4:
            messages[1]["content"][1]["text"] = "changed PRIVATE reasoning /elsewhere"
            messages[1]["content"][-1]["state"]["input"] = {"path": "/another/private/path"}

    p, t, d, messages, turns, pages = await turn_setup(hook)
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        assert len((await reader.capture(C)).files) == 4
    finally:
        await finish(p, t)


async def test_final_native_info_change_refuses_even_unchanged_output_metadata():
    def hook(number, messages, d, p):
        if number == 4:
            d["session.get"]["data"]["title"] = "foreign current Native info"

    p, t, d, messages, turns, pages = await turn_setup(hook)
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        with pytest.raises(ContractError):
            await reader.capture(C)
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "field,value", [("action_id", "foreign"), ("operation_digest", "f" * 64), ("text", "foreign")]
)
async def test_foreign_admission_cannot_attribute_files_to_another_request(field, value):
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        with pytest.raises(ContractError):
            await reader.capture(C.model_copy(update={field: value}))
    finally:
        await finish(p, t)


@pytest.mark.parametrize("outcome", ["succeeded", "failed", "interrupted"])
async def test_output_metadata_preserves_original_terminal_outcome(outcome):
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        messages[0]["outcome"] = outcome
        d["session.get"]["data"]["outcome"] = outcome
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        result = await reader.capture(C)
        assert result.outcome == outcome and reader.current(result)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("changed", ["clock", "attestation", "reader", "transport", "turn"])
async def test_expired_replaced_or_new_turn_invalidates_original_object(monkeypatch, changed):
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        result = await reader.capture(C)
        if changed == "clock":
            monkeypatch.setattr(module, "time", SimpleNamespace(time=lambda: result.expires_at))
        elif changed == "attestation":
            reader.attestation = replace(reader.attestation)
        elif changed == "reader":
            reader.turns = copy.copy(turns)
        elif changed == "transport":
            monkeypatch.setattr(turns.client, "transport", copy.copy(turns.client.transport))
        else:
            await turns.capture(C)
        assert not reader.current(result)
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "uri",
    [
        "file:///etc/passwd",
        "file://remote/workspace/result.pdf",
        "file://user:password@remote/result.pdf",
        "file:///workspace/../outside.pdf",
        "file:///workspace/result.pdf?private=secret",
        "file:///workspace/result.pdf#fragment",
        "file:///workspace/a%2Fb.pdf",
        "file:///workspace/%ff.pdf",
    ],
)
def test_file_uri_never_escapes_scope_or_opens_a_local_path(uri):
    with pytest.raises(ValueError):
        workspace_uri(uri, REF)


def test_unicode_file_uri_is_a_relative_candidate_without_byte_or_creation_authority():
    uri = "file://" + REF.canonical_directory + "/%E6%AA%94%E6%A1%88.pdf"
    assert workspace_uri(uri, REF) == "檔案.pdf"
    assert (
        workspace_uri("file://" + REF.canonical_directory + "/100%25%252F.html", REF)
        == "100%%2F.html"
    )
    messages = native_messages()
    outputs(messages)
    messages[1]["snapshot"]["files"] = ["board.html", ".ssh/key", ".jt-oz-incoming-service/input"]
    files, hidden, unsupported = output_projection(REF, list(reversed(messages)))
    assert files[0].size is None and files[0].sha256 is None and hidden == 2
    assert unsupported == 1


async def test_full_correlated_twenty_mib_inline_metadata_never_retains_the_tool_body():
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        body = bytes(range(256)) * (MAX_ATTACHMENT_BYTES // 256)
        uri = "data:application/octet-stream;base64," + base64.b64encode(body).decode()
        part = messages[1]["content"][-1]["state"]["content"][1]
        part.update(uri=uri, mime="application/octet-stream", name="large.bin")
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        evidence = await reader.capture(C)
        assert reader.current(evidence)
        output = evidence.files[2]
        assert (output.size, output.sha256) == (len(body), hashlib.sha256(body).hexdigest())
        assert len(json.dumps(output.model_dump())) < 1000
    finally:
        await finish(p, t)


async def test_fresh_identical_capture_has_stable_projection_but_no_renewed_old_authority():
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        first = await reader.capture(C)
        second = await reader.capture(C)
        assert first.projection_sha256 == second.projection_sha256
        assert not reader.current(first) and reader.current(second)
        assert first.evidence_sha256 != second.evidence_sha256
    finally:
        await finish(p, t)


@pytest.mark.parametrize("name", [".env", ".ssh/id_rsa", "../escape", "private.key"])
def test_protected_or_unsafe_tool_display_name_does_not_become_an_output(name):
    messages = native_messages()
    outputs(messages)
    part = messages[1]["content"][-1]
    part["state"]["content"] = [{"type": "file", "uri": URI, "mime": "text/html", "name": name}]
    messages[1]["snapshot"] = {}
    assert output_projection(REF, list(reversed(messages))) == ((), 1, 0)


@pytest.mark.parametrize(
    "uri,mime",
    [
        ("data:text/plain;base64,@@", "text/plain"),
        ("data:text/plain;base64,Zh==", "text/plain"),
        ("data:text/plain;base64,é", "text/plain"),
        ("data:text/plain,hello", "text/plain"),
        ("data:text/plain;base64,", "text/html"),
        ("data:text/plain;charset=utf8;base64,", "text/plain"),
    ],
)
def test_noncanonical_or_mismatched_inline_content_refuses(uri, mime):
    with pytest.raises(ContractError):
        inline_metadata(uri, mime)


@pytest.mark.parametrize(
    "content",
    [b"", bytes(range(256)), b"a" * MAX_ATTACHMENT_BYTES],
    ids=["empty", "all-byte-values", "20MiB"],
)
def test_inline_metadata_bounds_and_hashes_without_retaining_bytes(content):
    uri = "data:application/octet-stream;base64," + base64.b64encode(content).decode()
    assert inline_metadata(uri, "application/octet-stream") == (
        len(content),
        hashlib.sha256(content).hexdigest(),
    )


def test_over_capacity_inline_and_output_count_fail_before_unbounded_projection():
    with pytest.raises(ContractError):
        inline_metadata(
            "data:text/plain;base64," + "A" * (4 * ((MAX_ATTACHMENT_BYTES + 2) // 3) + 4),
            "text/plain",
        )
    messages = native_messages()
    messages[1]["snapshot"] = {"files": [f"file-{i}.txt" for i in range(MAX_OUTPUTS + 1)]}
    with pytest.raises(ContractError, match="count_capacity"):
        output_projection(REF, list(reversed(messages)))


def test_model_text_user_files_and_noncompleted_tool_content_are_not_output_authority():
    messages = native_messages()
    outputs(messages)
    messages[1]["snapshot"] = {}
    part = messages[1]["content"][-1]
    part["state"]["status"] = "error"
    assert output_projection(REF, list(reversed(messages))) == ((), 0, 0)
    with pytest.raises(ValueError):
        GeneratedFile(
            origin="snapshot",
            assistant_id="a",
            file_index=0,
            kind="workspace",
            path="a.txt",
            name="a.txt",
            size=1,
            sha256="0" * 64,
        )


def test_reviewed_sources_and_installed_schema_do_not_invent_legacy_step_events():
    root = Path("tests/fixtures/installed/opencode-v2.0.32")
    manifest = json.loads((root / "manifest.json").read_text())
    for item in manifest["generated_output_source_files"]:
        assert hashlib.sha256((root / item["path"]).read_bytes()).hexdigest() == item["sha256"]
        assert item["verification"] == "official_source_tag_research_not_live_output"
    schema = json.loads(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").read_text()
    )
    assert "snapshot" in schema["components"]["schemas"]["Session.Message.Assistant"]["properties"]
    assert "session.step.ended" not in json.dumps(schema)


def test_unpaired_uri_unicode_is_a_generic_contract_failure():
    messages = native_messages()
    outputs(messages)
    messages[1]["content"][-1]["state"]["content"][1]["uri"] = "data:text/html;base64," + chr(
        0xD800
    )
    with pytest.raises(ContractError):
        output_projection(REF, list(reversed(messages)))


async def test_escaped_unpaired_native_json_unicode_is_rejected_without_a_witness():
    p, t, d, messages, turns, pages = await turn_setup()
    try:
        outputs(messages)
        original = t.client._transport
        count = 0

        def handler(request):
            nonlocal count
            if request.url.path.endswith("/message") and request.url.params.get("limit") == "50":
                count += 1
                if count >= 3:
                    malformed = copy.deepcopy(messages)
                    malformed[1]["content"][-1]["state"]["content"][1]["uri"] = (
                        "data:text/html;base64," + chr(0xD800)
                    )
                    return httpx.Response(
                        200,
                        content=json.dumps(
                            {"data": malformed, "cursor": {}}, ensure_ascii=True
                        ).encode(),
                    )
            return original.handler(request)

        t.client._transport = httpx.MockTransport(handler)
        reader = V2GeneratedFileReader(turns, attestation=attestation(turns))
        with pytest.raises(ContractError):
            await reader.capture(C)
    finally:
        await finish(p, t)


def test_files_written_after_a_steer_return_with_the_steer_not_the_head():
    from jt_oz_bridge.adapters.opencode.turn_resources import match_isolated_turn, selected_message
    from tests.contract.test_turn_resources import reply, steered_user

    idle, assistant, user = native_messages()
    after = reply("msg_after_steer", "Shorter answer", 2.8)
    descending = [idle, after, steered_user(), assistant, user]
    head = match_isolated_turn(C, [selected_message(m) for m in descending])
    own = module.own_messages(descending, head)
    assert [m["id"] for m in own] == [user["id"], assistant["id"], idle["id"]]
