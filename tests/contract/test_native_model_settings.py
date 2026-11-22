"""A setting tail cannot turn an unresolved old execution into fresh idle."""

import copy
import hashlib
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    MODEL_SETTING_SOURCES,
    ModelSettingsAttestation,
    reconcile_model_tail,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_leaf_resources import REF, finish, fixture_data, setup

MODEL = {"providerID": "synthetic-provider", "id": "original-model", "variant": "none"}
HIGH = {**MODEL, "variant": "high"}


def page():
    return copy.deepcopy(
        {
            "data": [
                {
                    "id": "msg_model_latest",
                    "type": "model-switched",
                    "model": MODEL,
                    "previous": HIGH,
                    "time": {"created": 5},
                },
                {
                    "id": "msg_model_previous",
                    "type": "model-switched",
                    "model": HIGH,
                    "previous": MODEL,
                    "time": {"created": 4},
                },
                {"id": "msg_idle", "type": "idle", "outcome": "succeeded", "time": {"created": 3}},
            ],
            "cursor": {"next": "older-native-history"},
        }
    )


def info():
    row = fixture_data()["session.get"]["data"]
    row.update(model=dict(MODEL), time={"created": 1, "updated": 5, "idle": 3})
    return row


def attestation(**changes):
    return ModelSettingsAttestation(
        **{
            "reference": REF,
            "contract_sha256": INSTALLED_SCHEMA,
            "semantics_sha256": MODEL_SETTING_SEMANTICS,
            "installed_evidence_sha256": "a" * 64,
            **changes,
        }
    )


def test_exact_native_setting_sources_are_preserved_with_source_semantics():
    root = Path("tests/fixtures/installed/opencode-v2.0.32/source")
    for key, suffix in [
        ("session.ts", "session"),
        ("info.ts", "info"),
        ("projector.ts", "projector"),
        ("message-updater.ts", "message-updater"),
    ]:
        raw = (root / f"packages_core_src_session_{suffix}.ts").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == MODEL_SETTING_SOURCES[key]


def test_native_default_variant_normalization_does_not_conflate_literal_none():
    raw = page()
    raw["data"][0]["model"].pop("variant")
    session = info()
    session["model"] = {**MODEL, "variant": "default"}
    assert reconcile_model_tail(session, raw)["idle"]["id"] == "msg_idle"
    session["model"] = MODEL
    with pytest.raises(ContractError, match="selection_chain"):
        reconcile_model_tail(session, raw)


def test_positive_idle_and_complete_model_chain_are_retained_without_metadata_or_body():
    raw = page()
    raw["data"][0]["metadata"] = {"private": "must-not-be-retained"}
    result = reconcile_model_tail(info(), raw)
    assert result["idle"]["id"] == "msg_idle" and not result["pristine"]
    assert [x["id"] for x in result["controls"]] == ["msg_model_latest", "msg_model_previous"]
    assert "metadata" not in str(result) and "must-not-be-retained" not in str(result)


@pytest.mark.parametrize(
    "change",
    [
        "latest-model",
        "chain",
        "user",
        "assistant",
        "agent",
        "shell",
        "idle-time",
        "outcome",
        "no-idle",
        "duplicate",
        "clock",
        "too-many",
    ],
)
def test_intervening_input_stale_outcome_or_changed_selection_cannot_become_idle(change):
    raw, session = page(), info()
    if change == "latest-model":
        session["model"] = HIGH
    elif change == "chain":
        raw["data"][1]["model"] = MODEL
    elif change in {"user", "assistant", "agent", "shell"}:
        raw["data"][1]["type"] = "agent-switched" if change == "agent" else change
    elif change == "idle-time":
        session["time"]["idle"] = 2
    elif change == "outcome":
        session["outcome"] = "failed"
    elif change == "no-idle":
        raw["data"].pop()
    elif change == "duplicate":
        raw["data"][1]["id"] = raw["data"][0]["id"]
    elif change == "clock":
        raw["data"][1]["time"]["created"] = 6
    else:
        raw["data"] = [copy.deepcopy(raw["data"][0]) for _ in range(52)]
    with pytest.raises(ContractError):
        reconcile_model_tail(session, raw)


def test_pristine_requires_complete_history_no_previous_selection_and_no_old_outcome():
    session = info()
    session.pop("outcome")
    session["time"].pop("idle")
    raw = {"data": [page()["data"][0]], "cursor": {}}
    raw["data"][0].pop("previous")
    assert reconcile_model_tail(session, raw)["pristine"]
    for change in ("old-outcome", "more-history", "previous-selection"):
        altered, altered_info = copy.deepcopy(raw), copy.deepcopy(session)
        if change == "old-outcome":
            altered_info["outcome"] = "succeeded"
        elif change == "more-history":
            altered["cursor"]["next"] = "opaque"
        else:
            altered["data"][0]["previous"] = HIGH
        with pytest.raises(ContractError):
            reconcile_model_tail(altered_info, altered)


@pytest.mark.parametrize("change", ["scope", "contract", "semantics", "evidence"])
def test_settings_qualification_is_explicit_and_exact(change):
    changes = {
        "scope": {"reference": REF.model_copy(update={"upstream_session_id": "ses_foreign"})},
        "contract": {"contract_sha256": "b" * 64},
        "semantics": {"semantics_sha256": "b" * 64},
        "evidence": {"installed_evidence_sha256": "not-an-evidence-hash"},
    }
    with pytest.raises(ContractError):
        attestation(**changes[change]).require(REF, INSTALLED_SCHEMA)


async def test_unqualified_model_change_does_not_enable_leaf_idle():
    data = fixture_data()
    data["session.get"]["data"] = info()
    data["session.message.list"]["data"] = page()["data"][:1]
    proofs, transport, _data, _calls = await setup(data)
    try:
        with pytest.raises(ContractError, match="idle_not_positively"):
            await proofs.watch(REF)
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize("kind", ["running", "permission", "form"])
async def test_setting_during_positive_active_work_never_demands_an_old_idle_or_blocks_pending(
    kind,
):
    from tests.contract.test_public_live_feed import REAL

    data = fixture_data()
    data["session.get"]["data"] = info()
    data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    data["session.message.list"]["data"] = page()["data"][:1]
    if kind in {"permission", "form"}:
        event = next(
            e
            for e in REAL
            if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
        )
        data["session." + kind + ".list"]["data"] = [
            event["data"] if kind == "permission" else event["data"]["form"]
        ]
    proofs, transport, _data, calls = await setup(data)
    proofs.model_settings = attestation()
    try:
        witness = await proofs.watch(REF)
        assert (
            witness.state
            == {
                "running": ExecutionState.RUNNING,
                "permission": ExecutionState.WAITING_PERMISSION,
                "form": ExecutionState.WAITING_INPUT,
            }[kind]
        )
        assert not any("limit=51" in url for _operation, url in calls)
    finally:
        await finish(proofs, transport)


async def test_leaf_doubles_qualified_tail_and_revokes_proof_when_enrollment_changes():
    data = fixture_data()
    data["session.get"]["data"] = info()
    proofs, transport, _data, calls = await setup(data)
    original_request = transport.request

    async def request(operation, **kwargs):
        if operation == "session.message.list":
            limit = kwargs["query"]["limit"]
            return page() if limit == "51" else {"data": page()["data"][:1], "cursor": {}}
        return await original_request(operation, **kwargs)

    transport.request = request
    proofs.model_settings = attestation()
    try:
        witness = await proofs.watch(REF)
        assert witness.state == ExecutionState.IDLE and witness.last_outcome == "succeeded"
        proof = await proofs.prove(REF, INSTALLED_SCHEMA, digest(info()))
        assert proofs.valid_fence(REF, proof.resource_fence)
        proofs.model_settings = None
        assert not proofs.valid_fence(REF, proof.resource_fence)
    finally:
        await finish(proofs, transport)


async def test_latest_change_between_one_message_and_tail_read_is_rejected():
    data = fixture_data()
    data["session.get"]["data"] = info()
    proofs, transport, _data, _calls = await setup(data)
    original_request = transport.request

    async def request(operation, **kwargs):
        if operation == "session.message.list":
            raw = page()
            if kwargs["query"]["limit"] == "1":
                raw["data"] = raw["data"][:1]
                raw["data"][0]["id"] = "msg_stale_latest"
            return raw
        return await original_request(operation, **kwargs)

    transport.request = request
    proofs.model_settings = attestation()
    try:
        with pytest.raises(ContractError, match="tail_changed"):
            await proofs.watch(REF)
    finally:
        await finish(proofs, transport)


def test_explicit_backend_codec_qualification_does_not_masquerade_as_per_session_observation():
    other = REF.model_copy(update={"upstream_session_id": "another-existing-root"})
    bound = attestation()
    with pytest.raises(ContractError):
        bound.require(other, INSTALLED_SCHEMA)
    backend = attestation(qualification_scope="backend")
    backend.require(other, INSTALLED_SCHEMA)
    assert backend.reference == REF  # Preserve the actual observed reference.
    assert backend.enrollment_sha256 != bound.enrollment_sha256
    assert bound.enrollment_sha256 == digest(
        {
            "reference": REF.model_dump(mode="json"),
            "contract_sha256": INSTALLED_SCHEMA,
            "semantics_sha256": MODEL_SETTING_SEMANTICS,
            "installed_evidence_sha256": "a" * 64,
        }
    )  # Existing session-scoped enrollment fingerprints remain compatible.


@pytest.mark.parametrize(
    "patch",
    [
        {"backend_id": "other"},
        {"backend_identity": "other"},
    ],
)
def test_backend_codec_qualification_cannot_cross_instance_identity(patch):
    with pytest.raises(ContractError):
        attestation(qualification_scope="backend").require(
            REF.model_copy(update=patch), INSTALLED_SCHEMA
        )


def test_backend_codec_still_requires_exact_installed_schema_source_and_real_evidence_pin():
    for change in (
        {"contract_sha256": "b" * 64},
        {"semantics_sha256": "b" * 64},
        {"installed_evidence_sha256": "not-a-pin"},
        {"qualification_scope": "unknown"},
    ):
        with pytest.raises(ContractError):
            attestation(**change).require(REF, INSTALLED_SCHEMA)
