"""Pinned-schema fork/compact/revert requests with synthetic Native; not live qualification."""

import copy
import json
import logging
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.execution import OPERATIONS, V2ExecutionClient
from jt_oz_bridge.adapters.opencode.project_policy import GUARDED_OPERATIONS, NativePolicyEnrollment
from jt_oz_bridge.adapters.opencode.transport import (
    MUTATION_OPERATIONS,
    ContractAttestation,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.execution import HumanMessage, MutationNotSent
from jt_oz_bridge.domain.operations import CURRENT_OPERATIONS
from jt_oz_bridge.domain.session_lifecycle import (
    LIFECYCLE_OPERATIONS,
    SessionLifecycleChange,
    SessionLifecycleOutcome,
    SessionLifecycleRequest,
)
from tests.contract.test_v2_execution import SyntheticProofs
from tests.contract.test_v2_model_catalog import REF, SCOPE, info

CONTRACT = Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
ROOT = "/api/session/ses_original"
MESSAGE = "msg_boundary"
READS = {"session.get", "session.message.list"}
ALL = READS | set(LIFECYCLE_OPERATIONS)
INBOX = ALL | {"session.inbox.list"}


def human(text, message_id):
    return HumanMessage(
        realm_id="realm",
        channel_id=4,
        topic="original",
        message_id=message_id,
        revision=0,
        author_id=9,
        text=text,
    )


def change_for(operation, *, files=False, boundary=None):
    return SessionLifecycleChange(
        operation=operation,
        message_id=(MESSAGE if operation == "session.revert.stage" else boundary),
        message_preview="earlier message",
        files=files,
        pending_revert_message_id=(
            MESSAGE if operation in {"session.revert.clear", "session.revert.commit"} else None
        ),
    )


def request_for(operation, change=None, **changes):
    opening = {
        "session.fork": "!fork",
        "session.compact": "!compact",
        "session.revert.stage": "!revert",
        "session.revert.clear": "!revert clear",
        "session.revert.commit": "!revert commit",
    }[operation]
    return {
        "operation": operation,
        "reference": REF.model_dump(mode="json"),
        "source": human("!confirm", 13).model_dump(mode="json"),
        "preview_sources": [human(opening, 12).model_dump(mode="json")],
        "change": (change or change_for(operation)).model_dump(mode="json"),
        "reply_locale": "zh-TW",
        "confirm_expires_at": time.time() + 60,
        "confirmation_token_sha256": "c" * 64,
        **changes,
    }


def setup(mode="success", operations=ALL, proofs=None, scope_guard=None, tagged=(), inbox=()):
    profile = OpenAPIProfile.from_file(CONTRACT)
    provider = proofs or SyntheticProofs()
    data = info(title="Original")
    child = info(id="ses_child", fork={"sessionID": "ses_original", "boundary": None})
    seen = []
    messages = [
        {"id": "msg_two", "type": "user", "text": "second\nline", "time": {"created": 2}},
        {"id": "msg_one", "type": "user", "text": "first", "time": {"created": 1}},
        *tagged,
    ]

    def handler(request):
        path, method = request.url.path, request.method
        if method == "GET" and path == ROOT:
            return httpx.Response(200, json={"data": copy.deepcopy(data)})
        if method == "GET" and path == ROOT + "/message":
            return httpx.Response(200, json={"data": copy.deepcopy(messages), "cursor": {}})
        if method == "GET" and path == ROOT + "/inbox":
            return httpx.Response(200, json={"data": copy.deepcopy(list(inbox))})
        if method == "GET" and path == "/api/session/ses_child":
            if mode == "child-unreadable":
                return httpx.Response(200, json={"data": {**child, "id": "ses_other"}})
            return httpx.Response(200, json={"data": copy.deepcopy(child)})
        body = json.loads(request.content) if request.content else None
        seen.append((method, path, body))
        if mode == "lost-ack":
            raise httpx.ReadTimeout("synthetic lost acknowledgement", request=request)
        if path == ROOT + "/fork":
            boundary = (
                {"type": "before", "messageID": body["before"]}
                if body.get("before")
                else {"type": "through", "messageID": "msg_last"}
            )
            child["fork"] = {"sessionID": "ses_original", "boundary": boundary}
            if mode == "foreign-fork":
                child["fork"] = {"sessionID": "ses_foreign", "boundary": boundary}
            return httpx.Response(200, json={"data": copy.deepcopy(child)})
        if path == ROOT + "/compact":
            value = {
                "id": "msg_compaction",
                "sessionID": "ses_foreign" if mode == "foreign-compact" else "ses_original",
                "time": {"created": 3},
                "type": "compaction",
                "payload": {},
                "delivery": body["delivery"],
            }
            return httpx.Response(200, json={"data": value})
        if path == ROOT + "/revert/stage":
            if mode != "stage-not-applied":
                data["revert"] = {"messageID": body["messageID"]}
            return httpx.Response(200, json={"data": {"messageID": body["messageID"]}})
        if path == ROOT + "/revert" and method == "DELETE":
            if mode != "still-staged":
                data.pop("revert", None)
            return httpx.Response(204)
        if path == ROOT + "/revert/commit":
            if mode != "still-staged":
                data.pop("revert", None)
            return httpx.Response(204)
        raise AssertionError(f"unexpected Native request {method} {path}")

    async def identity():
        return True

    transport = V2HTTPTransport(
        "https://native.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, REF.backend_identity, "2.0.32", frozenset(operations)
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handler),
    )
    client = V2ExecutionClient(
        transport,
        {SCOPE.project_id: V2CatalogProject(SCOPE, "native-project")},
        proofs=provider,
        scope_guard=scope_guard,
    )
    return client, transport, data, seen


def test_pinned_contract_offers_these_routes_and_no_session_archive():
    raw = json.loads(CONTRACT.read_text())
    identifiers = {
        operation["operationId"] for path in raw["paths"].values() for operation in path.values()
    }
    assert LIFECYCLE_OPERATIONS <= identifiers
    assert LIFECYCLE_OPERATIONS <= MUTATION_OPERATIONS
    assert not any("archive" in name.lower() for name in identifiers)
    # time.archived is only read back; nothing in the fixed setter can write it.
    update = raw["paths"]["/api/session/{sessionID}"]["patch"]["requestBody"]
    schema = update["content"]["application/json"]["schema"]
    assert set(schema["properties"]) == {"title", "metadata", "permissions"}
    assert schema["additionalProperties"] is False
    profile = OpenAPIProfile.from_file(CONTRACT)
    with pytest.raises(ContractError):
        profile.prepare(
            "session.update",
            path={"sessionID": "ses_original"},
            body={"time": {"archived": 1}},
        )


def test_new_operations_are_current_guarded_and_policy_enrollable():
    assert LIFECYCLE_OPERATIONS <= CURRENT_OPERATIONS
    assert LIFECYCLE_OPERATIONS <= GUARDED_OPERATIONS
    assert LIFECYCLE_OPERATIONS <= set(OPERATIONS)
    assert all(OPERATIONS[name][-1] == name for name in LIFECYCLE_OPERATIONS)
    NativePolicyEnrollment(
        format="native-project-policy-v1",
        reference=REF,
        native_project_id="native-project",
        contract_sha256="a" * 64,
        permission_source_sha256="b" * 64,
        fingerprint_sha256="c" * 64,
        operations=LIFECYCLE_OPERATIONS,
    )


@pytest.mark.parametrize(
    ("operation", "change", "method", "path", "body"),
    [
        ("session.fork", None, "POST", ROOT + "/fork", {}),
        (
            "session.fork",
            change_for("session.fork", boundary=MESSAGE),
            "POST",
            ROOT + "/fork",
            {"before": MESSAGE},
        ),
        ("session.compact", None, "POST", ROOT + "/compact", {"delivery": "queue"}),
        (
            "session.revert.stage",
            None,
            "POST",
            ROOT + "/revert/stage",
            {"messageID": MESSAGE, "files": False},
        ),
        (
            "session.revert.stage",
            change_for("session.revert.stage", files=True),
            "POST",
            ROOT + "/revert/stage",
            {"messageID": MESSAGE, "files": True},
        ),
        ("session.revert.clear", None, "DELETE", ROOT + "/revert", None),
        ("session.revert.commit", None, "POST", ROOT + "/revert/commit", None),
    ],
)
async def test_exact_single_request_and_readback_keep_the_original_session(
    operation, change, method, path, body
):
    client, transport, data, seen = setup()
    if operation in {"session.revert.clear", "session.revert.commit"}:
        data["revert"] = {"messageID": MESSAGE}
    try:
        admission = await client.submit(REF, request_for(operation, change), "action")
        outcome = SessionLifecycleOutcome.model_validate(admission.details)
        assert seen == [(method, path, body)]
        assert admission.status == "completed" and admission.upstream_id is None
        assert outcome.session_id == REF.upstream_session_id and not outcome.turn_completed
        assert data["id"] == REF.upstream_session_id
        assert outcome.new_session_id == ("ses_child" if operation == "session.fork" else None)
        assert (outcome.native_request_id is not None) == (operation == "session.compact")
        if operation == "session.revert.stage":
            assert data["revert"] == {"messageID": MESSAGE}
        else:
            assert "revert" not in data
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault",
    [
        "preview-edited",
        "preview-bot",
        "confirm-edited",
        "confirm-not-confirm",
        "wrong-command",
        "other-author",
        "other-topic",
        "reused-message",
        "reference",
        "extra",
        "expired",
        "pending-changed",
        "running",
        "unattested",
        "owner-lost",
    ],
)
async def test_preflight_faults_never_reach_native(fault):
    proofs = SyntheticProofs()
    client, transport, data, seen = setup(proofs=proofs)
    payload = request_for("session.compact")
    if fault == "preview-edited":
        payload["preview_sources"][0]["revision"] = 1
    elif fault == "preview-bot":
        payload["preview_sources"][0]["is_bot"] = True
    elif fault == "confirm-edited":
        payload["source"]["revision"] = 1
    elif fault == "confirm-not-confirm":
        payload["source"]["text"] = "!oz status"
    elif fault == "wrong-command":
        payload["preview_sources"][0]["text"] = "!fork"
    elif fault == "other-author":
        payload["preview_sources"][0]["author_id"] = 8
    elif fault == "other-topic":
        payload["preview_sources"][0]["topic"] = "elsewhere"
    elif fault == "reused-message":
        payload["source"]["message_id"] = 12
    elif fault == "reference":
        payload["reference"]["canonical_directory"] = "/foreign"
    elif fault == "extra":
        payload["metadata"] = {"permissions": "never send"}
    elif fault == "expired":
        payload["confirm_expires_at"] = time.time() - 1
    elif fault == "pending-changed":
        data["revert"] = {"messageID": "msg_from_tui"}
    elif fault == "running":
        from jt_oz_bridge.domain.control import ExecutionState

        proofs.state = ExecutionState.RUNNING
    elif fault == "unattested":
        transport.attestation = replace(transport.attestation, verified_operations=frozenset(READS))
    else:
        proofs.epoch = None
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload, "action")
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize(
    ("operation", "mode"),
    [
        ("session.fork", "lost-ack"),
        ("session.fork", "foreign-fork"),
        ("session.fork", "child-unreadable"),
        ("session.compact", "lost-ack"),
        ("session.compact", "foreign-compact"),
        ("session.revert.stage", "lost-ack"),
        ("session.revert.stage", "stage-not-applied"),
        ("session.revert.clear", "lost-ack"),
        ("session.revert.clear", "still-staged"),
        ("session.revert.commit", "lost-ack"),
        ("session.revert.commit", "still-staged"),
    ],
)
async def test_post_send_uncertainty_is_not_unsent_and_sends_only_once(operation, mode):
    client, transport, data, seen = setup(mode)
    if operation in {"session.revert.clear", "session.revert.commit"}:
        data["revert"] = {"messageID": MESSAGE}
    try:
        with pytest.raises(ValueError) as error:
            await client.submit(REF, request_for(operation), "action")
        assert not isinstance(error.value, MutationNotSent)
        assert len(seen) == 1
    finally:
        await transport.close()


class EnrolledGuard:
    def __init__(self, *operations):
        self.operations = set(operations)

    def enrolled(self, reference, operation):
        return operation in self.operations

    async def authorize(self, reference, operation, proof):
        return object()

    def current(self, reference, operation, proof, witness):
        return True


@pytest.mark.parametrize("operation", sorted(LIFECYCLE_OPERATIONS))
async def test_every_operation_needs_both_root_policy_and_installed_attestation(operation):
    current_production = {"session.get", "session.update", "session.message.list"}
    for guard, verified, expected in (
        (EnrolledGuard(), ALL, False),
        (EnrolledGuard(operation), current_production, False),
        (EnrolledGuard("session.rename"), current_production, False),
        (EnrolledGuard(operation), ALL, True),
    ):
        client, transport, _, seen = setup(operations=verified, scope_guard=guard)
        try:
            assert client.capabilities(REF)[operation].supported is expected
            if not expected:
                with pytest.raises(MutationNotSent):
                    await client.submit(REF, request_for(operation), "action")
            assert not seen or expected
        finally:
            await transport.close()


async def test_menu_reads_are_bounded_user_turns_in_one_line_and_get_only():
    client, transport, data, seen = setup()
    try:
        choices = await client.recent_user_messages(REF)
        assert [c.message_id for c in choices] == ["msg_two", "msg_one"]
        assert choices[0].preview == "second line"
        assert await client.pending_revert(REF) is None
        data["revert"] = {"messageID": MESSAGE}
        assert await client.pending_revert(REF) == MESSAGE
        assert not seen
    finally:
        await transport.close()


def tagged_prompt(text="sent once", **extra):
    return {
        "id": "msg_landed",
        "type": "user",
        "text": text,
        "time": {"created": 3},
        "metadata": {"jt_oz_bridge": {"action_id": "action-1", "operation_digest": "d" * 64}},
        **extra,
    }


async def test_an_uncertain_prompt_is_found_by_its_own_tag_with_get_only():
    client, transport, data, seen = setup(tagged=(tagged_prompt(),))
    try:
        assert await client.prompt_readback(REF, "action-1", "d" * 64, "sent once") == (
            "msg_landed"
        )
        assert await client.prompt_readback(REF, "action-2", "d" * 64, "sent once") is None
        assert await client.prompt_readback(REF, "action-1", "e" * 64, "sent once") is None
        assert not seen
    finally:
        await transport.close()


async def test_a_prompt_opencode_holds_no_trace_of_never_arrived():
    client, transport, data, seen = setup(operations=INBOX)
    try:
        assert await client.prompt_never_arrived(REF, "action-1", "d" * 64, 0.0) is True
        assert not seen
    finally:
        await transport.close()


async def test_never_arrived_needs_an_attested_inbox_read(caplog):
    client, transport, data, seen = setup()
    try:
        with caplog.at_level(logging.WARNING):
            assert await client.prompt_never_arrived(REF, "action-1", "d" * 64, 0.0) is False
        assert "check=reads_not_attested" in caplog.text
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "trace",
    [
        {"tagged": (tagged_prompt(),)},
        {
            "inbox": (
                {
                    "id": "msg_waiting",
                    "sessionID": "ses_original",
                    "time": {"created": 4},
                    "type": "user",
                    "payload": {"text": "waiting"},
                    "delivery": "queue",
                },
            )
        },
        # A full page that does not reach back before the prompt proves nothing.
        {
            "tagged": tuple(
                {**tagged_prompt(), "id": f"msg_{i:03d}", "metadata": {}} for i in range(48)
            )
        },
    ],
)
async def test_any_trace_or_an_unread_past_is_not_never_arrived(trace):
    client, transport, data, seen = setup(operations=INBOX, **trace)
    try:
        assert await client.prompt_never_arrived(REF, "action-1", "d" * 64, 0.0) is False
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "tagged",
    [
        (tagged_prompt(text="changed"),),
        (tagged_prompt(), {**tagged_prompt(), "id": "msg_again"}),
    ],
)
async def test_a_tagged_message_that_differs_is_refused_not_admitted(tagged):
    client, transport, data, seen = setup(tagged=tagged)
    try:
        with pytest.raises(ContractError, match="v2_prompt_readback_mismatch"):
            await client.prompt_readback(REF, "action-1", "d" * 64, "sent once")
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fields",
    [
        {"operation": "session.compact", "message_id": MESSAGE},
        {"operation": "session.compact", "pending_revert_message_id": MESSAGE},
        {"operation": "session.revert.stage"},
        {"operation": "session.revert.clear"},
        {"operation": "session.revert.commit", "message_id": MESSAGE},
        {"operation": "session.fork", "files": True},
        {"operation": "session.fork", "message_id": "not-a-message"},
        {"operation": "session.delete"},
    ],
)
def test_change_shape_cannot_describe_anything_else(fields):
    with pytest.raises(ValidationError):
        SessionLifecycleChange(**fields)


def test_menu_choice_source_must_be_a_choice_from_the_same_person():
    payload = request_for("session.revert.stage")
    choice = human("!1", 14).model_dump(mode="json")
    SessionLifecycleRequest.model_validate(
        {**payload, "preview_sources": [*payload["preview_sources"], choice]}
    )
    with pytest.raises(ValidationError):
        SessionLifecycleRequest.model_validate(
            {
                **payload,
                "preview_sources": [
                    *payload["preview_sources"],
                    {**choice, "text": "!status"},
                ],
            }
        )
    with pytest.raises(ValidationError):
        SessionLifecycleRequest.model_validate(
            {
                **payload,
                "preview_sources": [*payload["preview_sources"], {**choice, "author_id": 8}],
            }
        )
