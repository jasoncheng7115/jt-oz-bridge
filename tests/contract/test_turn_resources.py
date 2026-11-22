"""Projected resource scope failures, not a real-human or replay certificate."""

import copy
import json
from dataclasses import replace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
)
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    RESOURCE_TYPES,
    ResourceSemanticAttestation,
    TurnCorrelation,
    V2TurnResourceReader,
    match_isolated_turn,
    selected_message,
)
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_leaf_resources import setup as leaf_setup
from tests.contract.test_public_live_feed import REAL, ROOT, frame, text_delta

C = TurnCorrelation(
    reference=REF,
    action_id="action_fixture",
    operation_digest="a" * 64,
    upstream_id="msg_user_fixture",
    text="exact fixture text",
)


def native_messages():
    user = {
        "id": C.upstream_id,
        "type": "user",
        "time": {"created": 1},
        "text": C.text,
        "metadata": {
            "jt_oz_bridge": {"action_id": C.action_id, "operation_digest": C.operation_digest},
            "unrelated_private_metadata": "NEVER_RETAIN_METADATA",
        },
    }
    assistant = {
        "id": "msg_assistant_fixture",
        "type": "assistant",
        "time": {"created": 2, "completed": 2.5},
        "agent": "build",
        "model": {"id": "fixture", "providerID": "fixture"},
        "content": [
            {"type": "text", "text": "Exact final answer"},
            {"type": "reasoning", "text": "NEVER_RETAIN_REASONING"},
        ],
    }
    idle = {
        "id": "msg_idle_fixture",
        "type": "idle",
        "time": {"created": 3},
        "outcome": "succeeded",
    }
    return [idle, assistant, user]


async def setup(hook=None):
    p, t, d, calls = await leaf_setup()
    messages = native_messages()
    pages = []
    original = t.client._transport

    def handler(request):
        if request.method == "GET" and request.url.path.endswith("/message"):
            limit = int(request.url.params["limit"])
            if limit == 50:
                pages.append(str(request.url))
                if hook:
                    result = hook(len(pages), messages, d, p)
                    if result is not None:
                        return httpx.Response(200, json=result)
            data = messages[:limit]
            return httpx.Response(200, json={"data": copy.deepcopy(data), "cursor": {}})
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    await p.watch(REF)
    client = V2ExecutionClient(t, p.projects, proofs=p)
    attestation = ResourceSemanticAttestation(
        REF.backend_id,
        REF.backend_identity,
        t.profile.sha256,
        RESOURCE_SEMANTICS,
        "b" * 64,
        RESOURCE_TYPES,
        frozenset({"succeeded", "failed", "interrupted"}),
    )
    reader = V2TurnResourceReader(client, attestation=attestation)
    return p, t, d, messages, reader, pages


async def test_two_native_ordered_resource_pages_prove_only_the_correlated_isolated_turn():
    p, t, d, m, r, pages = await setup()
    try:
        evidence = await r.capture(C)
        assert evidence.format == "v2-native-resource-turn-v1" and r.current(evidence)
        assert evidence.turn.outcome == "succeeded" and evidence.turn.ordered_message_ids == tuple(
            x["id"] for x in reversed(m)
        )
        assert evidence.turn.text[0].text == "Exact final answer" and len(pages) == 2
        body = evidence.model_dump_json()
        assert not any(
            x in body
            for x in ["NEVER_RETAIN_REASONING", "NEVER_RETAIN_METADATA", "native_seq", "log.synced"]
        )
        assert not r.current(evidence.model_copy())
    finally:
        await finish(p, t)


def model_setting():
    return {
        "id": "msg_model_setting",
        "type": "model-switched",
        "time": {"created": 4},
        "model": {"providerID": "fixture", "id": "model", "variant": "none"},
        "previous": {"providerID": "fixture", "id": "previous", "variant": "default"},
    }


def enroll_model_settings(proofs, transport):
    proofs.model_settings = ModelSettingsAttestation(
        REF, transport.profile.sha256, MODEL_SETTING_SEMANTICS, "c" * 64
    )


async def test_qualified_setting_after_idle_preserves_the_original_turn_and_records_provenance():
    p, t, d, m, reader, _pages = await setup()
    try:
        enroll_model_settings(p, t)
        control = model_setting()
        m.insert(0, control)
        d["session.get"]["data"].update(
            model=control["model"], time={"created": 1, "updated": 4, "idle": 3}
        )
        evidence = await reader.capture(C)
        assert evidence.turn.terminal_id == "msg_idle_fixture"
        assert evidence.turn.text[0].text == "Exact final answer"
        assert evidence.turn.ordered_message_ids[-1] == "msg_idle_fixture"
        assert evidence.turn.setting_message_ids == ("msg_model_setting",)
        assert evidence.model_settings_evidence_sha256 == "c" * 64
        assert evidence.model_settings_semantics_sha256 == MODEL_SETTING_SEMANTICS
        assert reader.current(evidence)
        p.model_settings = None
        assert not reader.current(evidence)
    finally:
        await finish(p, t)


async def test_qualified_model_setting_during_turn_is_not_mistaken_for_a_second_execution_input():
    p, t, d, m, reader, _pages = await setup()
    try:
        enroll_model_settings(p, t)
        control = model_setting()
        control["time"]["created"] = 1.5
        m.insert(2, control)
        d["session.get"]["data"]["model"] = control["model"]
        evidence = await reader.capture(C)
        assert evidence.turn.setting_message_ids == ("msg_model_setting",)
        assert evidence.turn.ordered_message_ids == (
            C.upstream_id,
            "msg_model_setting",
            "msg_assistant_fixture",
            "msg_idle_fixture",
        )
        assert len(evidence.turn.text) == 1
    finally:
        await finish(p, t)


async def test_setting_qualification_never_allows_a_new_user_to_close_an_older_turn():
    p, t, d, m, reader, _pages = await setup()
    try:
        enroll_model_settings(p, t)
        later_user = copy.deepcopy(m[-1])
        later_user["id"] = "msg_another_input"
        m.insert(2, later_user)
        with pytest.raises(ContractError, match="intervening"):
            await reader.capture(C)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["text", "action", "digest", "native_id", "attachments"])
async def test_positive_idle_and_old_success_do_not_override_wrong_input_correlation(change):
    p, t, d, m, r, pages = await setup()
    try:
        user = m[-1]
        if change == "text":
            user["text"] = "edited input"
        elif change == "action":
            user["metadata"]["jt_oz_bridge"]["action_id"] = "other"
        elif change == "digest":
            user["metadata"]["jt_oz_bridge"]["operation_digest"] = "c" * 64
        elif change == "native_id":
            user["id"] = "msg_other"
        else:
            user["skills"] = [{"name": "unqualified"}]
        with pytest.raises(ContractError):
            await r.capture(C)
        assert not r._witnesses
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "kind", ["user", "synthetic", "idle", "compaction", "model-switched", "shell"]
)
def test_later_input_or_terminal_cannot_complete_an_older_cancelled_or_unknown_input(kind):
    m = [selected_message(x) for x in native_messages()]
    # Minimal selected lifecycle facts; actual HTTP contract tests are separate.
    m.insert(2, {"id": "msg_intervening", "type": kind, "time": {"created": 2}})
    with pytest.raises(ContractError, match="intervening"):
        match_isolated_turn(C, m)


@pytest.mark.parametrize(
    "record",
    [
        {"type": "system", "description": "Instructions updated: core/codemode"},
        {"type": "compaction", "status": "completed", "reason": "auto"},
    ],
)
def test_opencode_housekeeping_inside_a_turn_is_part_of_that_turn(record):
    """An auto compaction and instruction refreshes inside a stopped turn must not
    keep it from settling, with every later message waiting behind it."""
    m = [selected_message(x) for x in native_messages()]
    m.insert(2, selected_message({"id": "msg_housekeeping", "time": {"created": 1.5}, **record}))
    turn = match_isolated_turn(C, m)
    assert turn.outcome == "succeeded"
    assert [t.text for t in turn.text] == ["Exact final answer"]


@pytest.mark.parametrize("reason", [None, "manual", "user", ["auto"]])
def test_a_compaction_someone_asked_for_still_counts_as_another_input(reason):
    m = [selected_message(x) for x in native_messages()]
    m.insert(
        2,
        selected_message(
            {
                "id": "msg_requested",
                "type": "compaction",
                "time": {"created": 1.5},
                "reason": reason,
            }
        ),
    )
    with pytest.raises(ContractError, match="intervening"):
        match_isolated_turn(C, m)


async def test_resource_page_rewrite_between_reads_is_not_published_as_stable_final_text():
    def hook(n, m, d, p):
        if n == 2:
            m[1]["content"][0]["text"] = "changed after first read"

    p, t, d, m, r, pages = await setup(hook)
    try:
        with pytest.raises(ContractError, match="boundary_changed"):
            await r.capture(C)
        assert not r._witnesses
    finally:
        await finish(p, t)


async def test_a_refused_boundary_names_its_failing_checks_at_most_once_per_window(caplog):
    # A refused turn boundary must not log only "boundary changed" on every retry;
    # the log says which condition holds, rate-limited.
    def hook(n, m, d, p):
        m[1]["content"][0]["text"] = f"changed between reads {n}"

    p, t, d, m, r, pages = await setup(hook)
    try:
        for _ in range(2):
            with pytest.raises(ContractError, match="boundary_changed"):
                await r.capture(C)
        lines = [x for x in caplog.messages if "native_resource_turn_boundary_detail" in x]
        assert len(lines) == 1 and "checks=pages_differ" in lines[0]
        assert "changed between reads" not in caplog.text
    finally:
        await finish(p, t)


async def test_reasoning_only_change_is_not_retained_or_used_as_final_output():
    def hook(n, m, d, p):
        if n == 2:
            m[1]["content"][1]["text"] = "OTHER_PRIVATE_REASONING"

    p, t, d, m, r, pages = await setup(hook)
    try:
        evidence = await r.capture(C)
        assert r.current(evidence) and "PRIVATE_REASONING" not in evidence.model_dump_json()
    finally:
        await finish(p, t)


async def test_other_closed_turns_before_the_target_are_never_retained():
    p, t, d, m, r, pages = await setup()
    try:
        old = copy.deepcopy(m[1])
        old["id"] = "msg_older"
        old["content"][0]["text"] = "NEVER_RETAIN_OLD_HISTORY"
        m.append(old)
        evidence = await r.capture(C)
        assert "NEVER_RETAIN_OLD_HISTORY" not in evidence.model_dump_json()
    finally:
        await finish(p, t)


@pytest.mark.parametrize("which", ["assistant", "tool"])
async def test_nonterminal_assistant_or_tool_is_not_overridden_by_idle(which):
    p, t, d, m, r, pages = await setup()
    try:
        if which == "assistant":
            m[1]["time"].pop("completed")
        else:
            m[1]["content"].append(
                {
                    "type": "tool",
                    "id": "tool_fixture",
                    "name": "shell",
                    "time": {"created": 2},
                    "state": {"status": "running", "input": {}},
                }
            )
        with pytest.raises(ContractError):
            await r.capture(C)
    finally:
        await finish(p, t)


async def test_native_tool_result_summary_keeps_exit_code_without_copying_input_output():
    p, t, d, m, r, pages = await setup()
    try:
        m[1]["content"].append(
            {
                "type": "tool",
                "id": "tool_fixture",
                "name": "shell",
                "time": {"created": 2, "completed": 2.4},
                "state": {
                    "status": "completed",
                    "input": {"command": "PRIVATE_TOOL_INPUT"},
                    "content": [{"type": "text", "text": "PRIVATE_TOOL_OUTPUT"}],
                    "metadata": {"exit": 7},
                },
            }
        )
        e = await r.capture(C)
        assert e.turn.tools[0].exit_code == 7 and e.turn.tools[0].content_index == 2
        assert "PRIVATE_TOOL" not in e.model_dump_json()
        # Native success and a failing shell exit are deliberately separate facts.
        assert e.turn.outcome == "succeeded"
    finally:
        await finish(p, t)


@pytest.mark.parametrize("which", ["feed", "text_delta", "expiration", "attestation"])
async def test_resource_witness_is_not_current_after_its_original_boundary_changes(
    which, monkeypatch
):
    p, t, d, m, r, pages = await setup()
    try:
        e = await r.capture(C)
        if which == "feed":
            p.feed.index.accept(frame(REAL[0]))
        elif which == "text_delta":
            # Content-neutral active-state proofs never weaken an idle/final
            # resource result or turn it into a streaming completion witness.
            p.feed.index.accept(frame(text_delta()))
        elif which == "expiration":
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.turn_resources.time.time", lambda: e.expires_at + 1
            )
        else:
            r.attestation = replace(r.attestation, verified_outcomes=frozenset({"failed"}))
        assert not r.current(e)
    finally:
        await finish(p, t)


async def test_pending_or_active_root_does_not_yield_a_completed_resource_turn():
    p, t, d, m, r, pages = await setup()
    try:
        d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
        with pytest.raises(ContractError, match="not_idle"):
            await r.capture(C)
        assert not pages
    finally:
        await finish(p, t)


async def test_unknown_installed_outcome_and_unattested_semantics_are_explicitly_refused():
    p, t, d, m, r, pages = await setup()
    try:
        r.attestation = replace(r.attestation, verified_outcomes=frozenset({"failed"}))
        with pytest.raises(ContractError):
            await r.capture(C)
        r.attestation = None
        with pytest.raises(ContractError):
            await r.capture(C)
    finally:
        await finish(p, t)


async def test_native_cursor_is_followed_without_reconstructing_from_ids_or_timestamps():
    def hook(n, m, d, p):
        return {
            "data": m[:2] if n % 2 == 1 else m[2:],
            "cursor": {"next": "OPAQUE_NATIVE_CURSOR"} if n % 2 == 1 else {},
        }

    p, t, d, m, r, pages = await setup(hook)
    try:
        e = await r.capture(C)
        assert e.turn.user_id == C.upstream_id
        assert (
            len(pages) == 4
            and "cursor=OPAQUE_NATIVE_CURSOR" in pages[1]
            and "order=" not in pages[1]
        )
    finally:
        await finish(p, t)


async def test_repeating_native_cursor_or_duplicate_messages_fail_closed():
    def hook(n, m, d, p):
        return {"data": m[:2], "cursor": {"next": "repeated"}}

    p, t, d, m, r, pages = await setup(hook)
    try:
        with pytest.raises(ContractError):
            await r.capture(C)
    finally:
        await finish(p, t)


async def test_actual_resource_capture_uses_the_hash_of_the_retained_operator_observation():
    import hashlib
    from pathlib import Path

    from jt_oz_bridge.adapters.opencode.turn_resources import NativeResourceTurn

    root = Path("tests/fixtures/installed/opencode-v2.0.32")
    original = root / "operator-resource-observation.json"
    record = json.loads((root / "parsed-resource-turn.json").read_text())
    observation_sha = hashlib.sha256(original.read_bytes()).hexdigest()
    evidence = NativeResourceTurn.model_validate(record["evidence"])
    assert (
        observation_sha
        == record["actual_observation_file_sha256"]
        == evidence.installed_evidence_sha256
    )
    assert record["native_prompt_repeated"] is False and not record["native_mutations_enabled"]
    assert record["older_cancel_input_not_completed_by_later_success"] is True
    assert (
        evidence.turn.outcome == "succeeded"
        and "".join(x.text for x in evidence.turn.text) == "JT_OZ_RESOURCE_TURN_OK_20261017"
    )
    p, t, _d, _m, reader, _pages = await setup()
    try:
        assert not reader.current(evidence)  # Serialization never issues a current witness.
    finally:
        await finish(p, t)


def test_exact_resource_semantics_sources_are_preserved_and_hashed():
    import hashlib
    from pathlib import Path

    from jt_oz_bridge.adapters.opencode.turn_resources import RESOURCE_SOURCES

    root = Path("tests/fixtures/installed/opencode-v2.0.32")
    manifest = json.loads((root / "manifest.json").read_text())
    for n, sha in RESOURCE_SOURCES.items():
        path = "source/packages_core_src_session_" + n
        entry = next(x for x in manifest["resource_source_files"] if x["path"] == path)
        assert entry["sha256"] == sha == hashlib.sha256((root / path).read_bytes()).hexdigest()


@pytest.mark.parametrize("case_index", [0, 1])
def test_actual_installed_interruption_and_failure_archives_match_exact_projection(case_index):
    from jt_oz_bridge.adapters.opencode.turn_resources import ProjectedTurn

    raw = (ROOT / "parsed-resource-outcomes.json").read_bytes()
    import hashlib

    # The recordings' own manifest pins the exact archive this projection was checked on.
    pinned = json.loads((ROOT / "manifest.json").read_text())["parsed_resource_outcomes_sha256"]
    assert hashlib.sha256(raw).hexdigest() == pinned
    archive = json.loads(raw)
    assert archive["passed"] and archive["native_mutation_attempts"] == 0
    case = archive["cases"][case_index]
    turn = match_isolated_turn(
        TurnCorrelation.model_validate(case["correlation"]),
        case["selected_descending"],
        allow_model_settings=True,
    )
    assert turn == ProjectedTurn.model_validate(case["expected_turn"])
    assert not turn.text
    if case_index == 0:
        assert turn.outcome == "interrupted" and turn.tools[0].status == "error"
        assert turn.terminal_error_sha256 is None
    else:
        assert turn.outcome == "failed" and turn.tools[0].status == "completed"
        assert turn.terminal_error_sha256 and len(turn.setting_message_ids) == 2


@pytest.mark.parametrize("case_index", [0, 1])
def test_installed_archive_never_authorizes_another_action_or_changed_input(case_index):
    archive = json.loads((ROOT / "parsed-resource-outcomes.json").read_text())
    case = archive["cases"][case_index]
    correlation = TurnCorrelation.model_validate(case["correlation"])
    for patch in ({"action_id": "another_action"}, {"text": "changed prompt"}):
        with pytest.raises(ContractError):
            match_isolated_turn(
                correlation.model_copy(update=patch),
                case["selected_descending"],
                allow_model_settings=True,
            )


def attachment_turn():
    import base64
    import hashlib

    from jt_oz_bridge.adapters.opencode.attachments import ATTACHMENT_SEMANTICS
    from jt_oz_bridge.domain.attachments import NativeAttachmentProjection

    raw = native_messages()
    body = b"ONLY_IN_THE_ATTACHMENT\n"
    file = NativeAttachmentProjection(
        filename="original.txt",
        mime_type="text/plain",
        size=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )
    raw[-1]["files"] = [
        {
            "data": base64.b64encode(body).decode(),
            "mime": "text/plain",
            "source": {"type": "inline"},
            "name": file.filename,
        }
    ]
    c = C.model_copy(
        update={"attachments": (file,), "attachment_semantics_sha256": ATTACHMENT_SEMANTICS}
    )
    return c, raw


def test_legacy_text_turn_serialization_preserves_existing_seals_exactly():
    assert C.model_dump(mode="json") == {
        "reference": REF.model_dump(mode="json"),
        "action_id": C.action_id,
        "operation_digest": C.operation_digest,
        "upstream_id": C.upstream_id,
        "text": C.text,
    }
    c, raw = attachment_turn()
    selected = [
        selected_message(row, with_attachment_receipts=row["id"] == c.upstream_id) for row in raw
    ]
    turn = match_isolated_turn(c, selected)
    assert turn.outcome == "succeeded"
    assert "ONLY_IN_THE_ATTACHMENT" not in json.dumps(selected)
    assert "data" not in selected[-1]["attachments"][0]
    with pytest.raises(ContractError, match="correlation_changed"):
        match_isolated_turn(C, selected)
    with pytest.raises(ContractError, match="correlation_changed"):
        match_isolated_turn(c, [selected_message(row) for row in raw])


@pytest.mark.parametrize(
    "change", ["sha256", "size", "filename", "mime_type", "count", "text", "metadata"]
)
def test_file_turn_requires_exact_sealed_native_projection_and_original_input(change):
    c, raw = attachment_turn()
    selected = [
        selected_message(row, with_attachment_receipts=row["id"] == c.upstream_id) for row in raw
    ]
    user = selected[-1]
    if change in {"sha256", "size", "filename", "mime_type"}:
        user["attachments"][0][change] = {
            "sha256": "0" * 64,
            "size": 0,
            "filename": "other.txt",
            "mime_type": "image/png",
        }[change]
    elif change == "count":
        user["attachments"].append(user["attachments"][0].copy())
    elif change == "text":
        user["text"] += " changed"
    else:
        user["metadata"]["jt_oz_bridge"]["action_id"] = "other_action"
    with pytest.raises(ContractError, match="correlation_changed"):
        match_isolated_turn(c, selected)


@pytest.mark.parametrize("kind", ["agents", "skills"])
def test_file_projection_never_promotes_other_native_attachment_categories(kind):
    c, raw = attachment_turn()
    raw[-1][kind] = [{"name": "unqualified"}]
    with pytest.raises(ContractError, match="agent_or_skill"):
        selected_message(raw[-1], with_attachment_receipts=True)


async def test_file_resource_capture_needs_separate_media_qualification_and_revokes_witness():
    from jt_oz_bridge.adapters.opencode.attachments import (
        ATTACHMENT_SEMANTICS,
        InlineAttachmentAttestation,
    )

    p, t, d, messages, reader, pages = await setup()
    c, raw = attachment_turn()
    messages[:] = raw
    try:
        with pytest.raises(ContractError, match="attachment_semantics_unqualified"):
            await reader.capture(c)
        assert not pages
        reader.attachments = InlineAttachmentAttestation(
            REF,
            t.profile.sha256,
            ATTACHMENT_SEMANTICS,
            "e" * 64,
            verified_mime_types=frozenset({"text/plain"}),
        )
        evidence = await reader.capture(c)
        assert reader.current(evidence) and len(pages) == 2
        assert evidence.attachment_evidence_sha256 == "e" * 64
        assert evidence.attachment_semantics_sha256 == ATTACHMENT_SEMANTICS
        assert "ONLY_IN_THE_ATTACHMENT" not in evidence.model_dump_json()
        reader.attachments = None
        assert not reader.current(evidence)
        assert not reader.current(evidence.model_copy())
    finally:
        await finish(p, t)


async def test_file_receipt_change_between_native_resource_reads_is_not_a_terminal_proof():
    import base64

    from jt_oz_bridge.adapters.opencode.attachments import (
        ATTACHMENT_SEMANTICS,
        InlineAttachmentAttestation,
    )

    def change(page, messages, _d, _p):
        if page == 2:
            messages[-1]["files"][0]["data"] = base64.b64encode(b"replaced").decode()

    p, t, d, messages, reader, pages = await setup(change)
    c, raw = attachment_turn()
    messages[:] = raw
    reader.attachments = InlineAttachmentAttestation(
        REF,
        t.profile.sha256,
        ATTACHMENT_SEMANTICS,
        "e" * 64,
        verified_mime_types=frozenset({"text/plain"}),
    )
    try:
        with pytest.raises(ContractError, match="correlation_changed"):
            await reader.capture(c)
    finally:
        await finish(p, t)


def test_turn_attachment_semantics_cannot_be_declared_without_bounded_file_receipts():
    from pydantic import ValidationError

    from jt_oz_bridge.adapters.opencode.attachments import ATTACHMENT_SEMANTICS

    c, _raw = attachment_turn()
    for change in (
        {"attachments": []},
        {"attachment_semantics_sha256": None},
        {"attachment_semantics_sha256": "f" * 64},
    ):
        value = c.model_dump(mode="json")
        value.update(change)
        with pytest.raises(ValidationError):
            TurnCorrelation.model_validate(value)
    with pytest.raises(ValidationError):
        TurnCorrelation.model_validate(
            {**C.model_dump(mode="json"), "attachment_semantics_sha256": ATTACHMENT_SEMANTICS}
        )


STEERED = TurnCorrelation(
    reference=REF,
    action_id="action_steered",
    operation_digest="d" * 64,
    upstream_id="msg_user_steered",
    text="make it shorter",
)


def steered_user(correlation=STEERED, created=2.6):
    return {
        "id": correlation.upstream_id,
        "type": "user",
        "time": {"created": created},
        "text": correlation.text,
        "metadata": {
            "jt_oz_bridge": {
                "action_id": correlation.action_id,
                "operation_digest": correlation.operation_digest,
            }
        },
    }


def reply(identity, text, created):
    return {
        "id": identity,
        "type": "assistant",
        "time": {"created": created, "completed": created + 0.1},
        "content": [{"type": "text", "text": text}],
    }


def test_a_steered_message_splits_one_busy_period_between_both_actions():
    idle, assistant, user = native_messages()
    later = reply("msg_after_steer", "Shorter answer", 2.8)
    descending = [selected_message(m) for m in (idle, later, steered_user(), assistant, user)]
    head = match_isolated_turn(C, descending)
    # The head owns only what was written before the steer arrived.
    assert [part.text for part in head.text] == ["Exact final answer"]
    assert head.ordered_message_ids == (user["id"], assistant["id"], idle["id"])
    assert head.outcome == "succeeded" and head.terminal_id == idle["id"]
    assert head.session_terminal_created is None and head.latest_created == 3
    assert "session_terminal_created" not in head.model_dump(mode="json")
    steered = match_isolated_turn(STEERED, descending[:3])
    assert [part.text for part in steered.text] == ["Shorter answer"]
    assert steered.terminal_id == head.terminal_id  # One busy period, one idle.


def test_a_steer_that_started_its_own_period_leaves_the_head_its_own_idle():
    idle, assistant, user = native_messages()
    later_idle = {
        "id": "msg_idle_later",
        "type": "idle",
        "time": {"created": 9},
        "outcome": "failed",
    }
    descending = [
        selected_message(m)
        for m in (
            later_idle,
            reply("msg_after_steer", "Shorter answer", 8),
            steered_user(created=7),
            idle,
            assistant,
            user,
        )
    ]
    # Strict by default: a later turn refuses the older input, as before.
    with pytest.raises(ContractError, match="intervening"):
        match_isolated_turn(C, descending)
    # A collector that knows a steer was sent after it may accept the split.
    head = match_isolated_turn(C, descending, allow_later_steer=True)
    assert head.terminal_id == idle["id"] and head.outcome == "succeeded"
    assert [part.text for part in head.text] == ["Exact final answer"]
    # A fresh capture still checks the session's own newest idle.
    assert head.latest_created == 9 and head.latest_outcome == "failed"
    assert head.model_dump(mode="json")["session_outcome"] == "failed"


@pytest.mark.parametrize("tag", ["none", "same-action", "extra-key"])
def test_only_another_bridge_prompt_may_follow_or_split_the_heads_period(tag):
    idle, assistant, user = native_messages()
    foreign = steered_user()
    if tag == "none":
        foreign["metadata"] = {}
    elif tag == "same-action":
        foreign["metadata"]["jt_oz_bridge"]["action_id"] = C.action_id
    else:
        foreign["metadata"]["jt_oz_bridge"]["extra"] = "x"
    inside = [idle, reply("msg_after", "x", 2.8), foreign, assistant, user]
    later_idle = dict(idle, id="msg_idle_later", time={"created": 9})
    after = [later_idle, reply("msg_after", "x", 8), foreign, idle, assistant, user]
    for case in (inside, after):
        with pytest.raises(ContractError, match="intervening"):
            match_isolated_turn(C, [selected_message(m) for m in case], allow_later_steer=True)
