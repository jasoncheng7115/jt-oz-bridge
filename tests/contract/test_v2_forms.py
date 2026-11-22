"""Public-source contract normalization; these are not installed-backend tests."""

from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.forms import normalize_form, normalize_permission
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.domain.control import FieldAnswer, draft_answers, validate_answers, wire_answers
from jt_oz_bridge.domain.execution import AnswerRejected, MutationRejected
from tests.support import REF as BASE_REF

REF = BASE_REF.model_copy(update={"upstream_session_id": "ses_original"})


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


def form(fields):
    return {
        "id": "frm_original",
        "sessionID": REF.upstream_session_id,
        "title": "Original tool questions",
        "fields": fields,
    }


def test_typed_answers_preserve_false_zero_and_exact_choice_values(profile):
    snapshot = normalize_form(
        profile,
        REF,
        form(
            [
                {"key": "enabled", "type": "boolean", "required": True, "default": True},
                {"key": "count", "type": "integer", "required": True, "minimum": 0},
                {"key": "level", "type": "number", "minimum": 0, "maximum": 1},
                {
                    "key": "mode",
                    "type": "string",
                    "options": [{"value": "raw", "label": "Translated label"}],
                },
                {"key": "note", "type": "string", "description": "Keep whitespace"},
            ]
        ),
        "verified-test-epoch",
        pending_catalog=True,
    )
    with pytest.raises(ValueError, match="missing"):
        validate_answers(snapshot.fields, {})  # Defaults are hints, never silent answers.
    answers = {
        "enabled": FieldAnswer(value=False),
        "count": FieldAnswer(value=0),
        "level": FieldAnswer(value=0.25),
        "mode": FieldAnswer(selected=("raw",)),
        "note": FieldAnswer(text="  exact\ntext  "),
    }
    assert wire_answers(snapshot.fields, answers) == {
        "enabled": False,
        "count": 0,
        "level": 0.25,
        "mode": "raw",
        "note": "  exact\ntext  ",
    }
    assert snapshot.fields[-1].description == "Keep whitespace"
    for key, value in [("count", 0.5), ("count", -1), ("level", 2), ("enabled", 1)]:
        with pytest.raises(ValueError):
            validate_answers(snapshot.fields, {**answers, key: FieldAnswer(value=value)})


def test_conditional_wizard_drops_inactive_answers_and_requires_active_only(profile):
    snapshot = normalize_form(
        profile,
        REF,
        form(
            [
                {"key": "enabled", "type": "boolean", "required": True},
                {
                    "key": "details",
                    "type": "string",
                    "required": True,
                    "when": [{"key": "enabled", "op": "eq", "value": True}],
                },
                {
                    "key": "disabled_reason",
                    "type": "string",
                    "required": True,
                    "when": [{"key": "enabled", "op": "neq", "value": True}],
                },
            ]
        ),
        "epoch",
    )
    draft = draft_answers(snapshot.fields, {}, "enabled", FieldAnswer(value=True))
    draft = draft_answers(snapshot.fields, draft, "details", FieldAnswer(text="original"))
    validate_answers(snapshot.fields, draft)
    draft = draft_answers(snapshot.fields, draft, "enabled", FieldAnswer(value=False))
    assert set(draft) == {"enabled"}
    with pytest.raises(ValueError, match="missing"):
        validate_answers(snapshot.fields, draft)
    with pytest.raises(ValueError, match="inactive"):
        draft_answers(snapshot.fields, draft, "details", FieldAnswer(text="stale"))
    draft = draft_answers(snapshot.fields, draft, "disabled_reason", FieldAnswer(text="why"))
    assert wire_answers(snapshot.fields, draft) == {"enabled": False, "disabled_reason": "why"}


def test_multiple_choice_conditions_are_membership_and_bounds_are_enforced(profile):
    snapshot = normalize_form(
        profile,
        REF,
        form(
            [
                {
                    "key": "checks",
                    "type": "multiselect",
                    "required": True,
                    "minItems": 1,
                    "maxItems": 2,
                    "options": [
                        {"value": "unit", "label": "Unit"},
                        {"value": "slow", "label": "Slow"},
                    ],
                },
                {
                    "key": "explain",
                    "type": "string",
                    "required": True,
                    "when": [{"key": "checks", "op": "eq", "value": "slow"}],
                },
            ]
        ),
        "epoch",
    )
    validate_answers(snapshot.fields, {"checks": FieldAnswer(selected=("unit",))})
    with pytest.raises(ValueError, match="missing"):
        validate_answers(snapshot.fields, {"checks": FieldAnswer(selected=("slow",))})
    with pytest.raises(ValueError, match="duplicate"):
        validate_answers(snapshot.fields, {"checks": FieldAnswer(selected=("unit", "unit"))})


def test_form_identity_pending_and_reconnect_generations_are_explicit(profile):
    raw = form([{"key": "note", "type": "string"}])
    a = normalize_form(profile, REF, raw, "connection-A")
    b = normalize_form(profile, REF, raw, "connection-B", pending_catalog=True)
    assert not a.pending and b.pending and a.generation != b.generation
    with pytest.raises(ContractError, match="identity"):
        normalize_form(profile, REF, {**raw, "sessionID": "another-session"}, "epoch")
    with pytest.raises(ContractError, match="epoch"):
        normalize_form(profile, REF, raw, "")
    with pytest.raises(ContractError):
        normalize_form(profile, REF, form([{"key": "unknown", "type": "future-type"}]), "epoch")


def test_external_forms_require_explicit_ack_and_never_fetch_the_url(profile):
    raw = form([{"key": "review", "type": "external", "url": "https://review.example/path"}])
    snapshot = normalize_form(profile, REF, raw, "epoch")
    with pytest.raises(ValueError, match="explicit"):
        validate_answers(snapshot.fields, {"review": FieldAnswer(value=False)})
    assert wire_answers(snapshot.fields, {"review": FieldAnswer(value=True)}) == {"review": True}
    with pytest.raises(ValueError):
        normalize_form(
            profile,
            REF,
            form([{"key": "review", "type": "external", "url": "http://127.0.0.1/admin"}]),
            "epoch",
        )


def test_permission_resource_scope_is_preserved_without_broad_approval(profile):
    raw = {
        "id": "per_original",
        "sessionID": REF.upstream_session_id,
        "action": "write",
        "resources": ["/workspace/file"],
        "save": ["/workspace/**"],
        "message": "Please review",
    }
    snapshot = normalize_permission(profile, REF, raw, "epoch", pending_catalog=True)
    assert snapshot.pending and snapshot.operation == "write"
    assert snapshot.resources == ("/workspace/file",) and snapshot.requested_scope == (
        "/workspace/**",
    )


async def test_only_verified_invalid_answer_response_is_retryable_by_a_new_human_attempt(profile):
    async def identity():
        return True

    for tag, expected in [
        ("FormInvalidAnswerError", AnswerRejected),
        ("InvalidRequestError", MutationRejected),
    ]:

        def handle(request, tag=tag):
            data = {"_tag": tag, "message": "PRIVATE-MARKER"}
            if tag == "FormInvalidAnswerError":
                data["id"] = "frm_original"
            return httpx.Response(400, json=data)

        transport = V2HTTPTransport(
            "http://127.0.0.1:4096",
            profile,
            attestation=ContractAttestation(
                profile.sha256, "synthetic", "synthetic", frozenset({"session.form.reply"})
            ),
            verify_identity=identity,
            transport=httpx.MockTransport(handle),
        )
        try:
            with pytest.raises(expected) as error:
                await transport.request(
                    "session.form.reply",
                    path={"sessionID": "ses_original", "formID": "frm_original"},
                    body={"answer": {"note": "exact answer"}},
                )
            assert "PRIVATE-MARKER" not in str(error.value)
            if tag == "InvalidRequestError":
                assert not isinstance(error.value, AnswerRejected)
        finally:
            await transport.close()


async def test_wrong_form_error_identity_is_uncertain_instead_of_reopening_an_answer(profile):
    async def identity():
        return True

    client = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=ContractAttestation(
            profile.sha256, "synthetic", "synthetic", frozenset({"session.form.reply"})
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                400,
                json={
                    "_tag": "FormInvalidAnswerError",
                    "id": "frm_other",
                    "message": "PRIVATE-MARKER",
                },
            )
        ),
    )
    try:
        with pytest.raises(ContractError, match="identity") as error:
            await client.request(
                "session.form.reply",
                path={"sessionID": "ses_original", "formID": "frm_original"},
                body={"answer": {"note": "original"}},
            )
        assert "PRIVATE-MARKER" not in str(error.value)
    finally:
        await client.close()


def test_permission_metadata_requester_and_redacted_source_fingerprint_are_preserved(profile):
    import copy
    import json

    raw = {
        "id": "per_details",
        "sessionID": REF.upstream_session_id,
        "action": "shell.execute",
        "resources": ["pytest -q"],
        "save": ["exact project command"],
        "metadata": {
            "command": "pytest -q",
            "env": {"API_KEY": "PRIVATE_FIRST_VALUE", "PATH": "/workspace/bin"},
            "enabled": False,
            "count": 0,
        },
        "source": {"type": "tool", "messageID": "msg_source", "id": "call_source"},
    }
    before = copy.deepcopy(raw)
    first = normalize_permission(profile, REF, raw, "epoch", pending_catalog=True)
    assert raw == before
    assert first.permission_details.redactions == 1
    assert "PRIVATE_FIRST_VALUE" not in first.model_dump_json()
    assert json.loads(first.permission_details.metadata_json) == {
        "command": "pytest -q",
        "env": {"API_KEY": "[REDACTED]", "PATH": "/workspace/bin"},
        "enabled": False,
        "count": 0,
    }
    assert json.loads(first.permission_details.requester_json) == raw["source"]
    raw["metadata"]["env"]["API_KEY"] = "PRIVATE_SECOND_VALUE"
    second = normalize_permission(profile, REF, raw, "epoch", pending_catalog=True)
    assert second.permission_details.metadata_json == first.permission_details.metadata_json
    assert second.permission_details.source_digest != first.permission_details.source_digest
    assert second != first  # A hidden value change must invalidate the old approval.


def test_permission_metadata_missing_is_not_invented_and_oversize_is_not_silently_omitted(profile):
    raw = {
        "id": "per_details",
        "sessionID": REF.upstream_session_id,
        "action": "shell.execute",
        "resources": ["pytest -q"],
    }
    first = normalize_permission(profile, REF, raw, "epoch", pending_catalog=True)
    assert (
        first.permission_details.metadata_json is None
        and first.permission_details.requester_json is None
    )
    raw["metadata"] = {"content": "x" * 262145}
    with pytest.raises(ContractError, match="safely_previewable"):
        normalize_permission(profile, REF, raw, "epoch", pending_catalog=True)


def test_permission_normalization_upgrade_gets_a_distinct_bridge_generation(profile):
    from jt_oz_bridge.adapters.opencode.forms import generation

    raw = {
        "id": "per_details",
        "sessionID": REF.upstream_session_id,
        "action": "shell.execute",
        "resources": ["pytest -q"],
    }
    normalized = normalize_permission(
        profile, REF, raw, "same-verified-epoch", pending_catalog=True
    )
    assert normalized.generation != generation(REF, raw["id"], "same-verified-epoch")


async def test_native_cancel_is_exact_bodyless_delete_only_after_separate_attestation(profile):
    seen = []

    async def identity():
        return True

    def handle(request):
        seen.append(request)
        assert request.method == "DELETE"
        assert request.url.path == "/api/session/ses_original/form/frm_original"
        assert not request.content and not request.url.query
        return httpx.Response(204)

    client = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, "synthetic", "synthetic", frozenset({"session.form.cancel"})
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handle),
    )
    try:
        assert (
            await client.request(
                "session.form.cancel", path={"sessionID": "ses_original", "formID": "frm_original"}
            )
            is None
        )
        assert len(seen) == 1
    finally:
        await client.close()


async def test_reply_attestation_does_not_authorize_cancel_or_retry_it(profile):
    from jt_oz_bridge.adapters.opencode.transport import TransportError

    seen = []

    async def identity():
        return True

    def handle(request):
        seen.append(request)
        raise httpx.ReadTimeout("synthetic lost cancel response")

    client = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, "synthetic", "synthetic", frozenset({"session.form.reply"})
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handle),
    )
    try:
        with pytest.raises(TransportError, match="not_attested"):
            await client.request(
                "session.form.cancel", path={"sessionID": "ses_original", "formID": "frm_original"}
            )
        assert not seen
    finally:
        await client.close()
    client = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, "synthetic", "synthetic", frozenset({"session.form.cancel"})
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handle),
    )
    try:
        with pytest.raises(TransportError, match="transport"):
            await client.request(
                "session.form.cancel", path={"sessionID": "ses_original", "formID": "frm_original"}
            )
        assert len(seen) == 1
    finally:
        await client.close()
