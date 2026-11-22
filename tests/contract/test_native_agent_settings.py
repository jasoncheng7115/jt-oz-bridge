"""Synthetic candidate validators, never installed Agent-switch qualification."""

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.agent_settings import (
    AGENT_SETTING_SCHEMA,
    AGENT_SETTING_SEMANTICS,
    AGENT_SETTING_SOURCES,
    AgentSettingsAttestation,
    agent_catalog,
    agent_definition,
    agent_policy_endpoint,
    agent_transition_preview,
    reconcile_agent_settings_tail,
    require_agent_transition,
    root_agent_transition,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    reconcile_model_tail,
)
from jt_oz_bridge.adapters.opencode.project_policy import PERMISSION_SOURCE
from jt_oz_bridge.domain.agent_selection import AgentTransitionEnrollment
from tests.contract.test_leaf_resources import fixture_data
from tests.contract.test_public_live_feed import PROFILE, REF
from tests.unit.test_root_files import synthetic_root_metadata


def agent(identity="build", *, effect="ask", **extra):
    return {
        "id": identity,
        "name": identity.title(),
        "mode": "primary",
        "hidden": False,
        "permissions": [{"action": "*", "resource": "*", "effect": effect}],
        "request": {"settings": {}, "headers": {}, "body": {}},
        **extra,
    }


def info():
    data = fixture_data()["session.get"]["data"]
    data.update(
        agent="review",
        model={"providerID": "synthetic-provider", "id": "synthetic", "variant": "none"},
        time={"created": 1, "updated": 9, "idle": 3},
    )
    return data


def endpoint(identity="build", *, effect="ask"):
    data = info()
    data["agent"] = identity
    return agent_policy_endpoint(
        PROFILE,
        REF,
        "global",
        data,
        {
            "location": {"directory": REF.canonical_directory},
            "data": agent(identity, effect=effect),
        },
        {"location": {"directory": REF.canonical_directory}, "data": []},
        {"data": []},
        {"location": {"directory": REF.canonical_directory}, "data": []},
    )


def transition():
    return AgentTransitionEnrollment(
        format="native-agent-transition-v1",
        contract_sha256=AGENT_SETTING_SCHEMA,
        permission_source_sha256=PERMISSION_SOURCE,
        before=endpoint(),
        after=endpoint("review", effect="allow"),
        installed_evidence_sha256="a" * 64,
    )


def qualification(**updates):
    return AgentSettingsAttestation(
        **{
            "reference": REF,
            "native_project_id": "global",
            "contract_sha256": AGENT_SETTING_SCHEMA,
            "semantics_sha256": AGENT_SETTING_SEMANTICS,
            "switch_evidence_sha256": "a" * 64,
            "mixed_tail_evidence_sha256": "b" * 64,
            "policy_transition_evidence_sha256": "c" * 64,
            **updates,
        }
    )


def page():
    return {
        "data": [
            {
                "id": "msg_agent_review",
                "type": "agent-switched",
                "agent": "review",
                "previous": "build",
                "time": {"created": 8},
            },
            {
                "id": "msg_model_latest",
                "type": "model-switched",
                "model": info()["model"],
                "previous": {"providerID": "synthetic-provider", "id": "older"},
                "time": {"created": 7},
            },
            {
                "id": "msg_agent_build",
                "type": "agent-switched",
                "agent": "build",
                "previous": "plan",
                "time": {"created": 6},
            },
            {"id": "msg_idle", "type": "idle", "outcome": "succeeded", "time": {"created": 3}},
        ],
        "cursor": {"next": "older-history"},
    }


def test_agent_semantics_are_distinct_and_match_exact_preserved_installed_source():
    root = Path("tests/fixtures/installed/opencode-v2.0.32/source")
    for key, expected in AGENT_SETTING_SOURCES.items():
        name = (
            "packages_core_src_permission.ts"
            if key == "permission.ts"
            else "packages_core_src_session_" + key
        )
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
    assert AGENT_SETTING_SEMANTICS != MODEL_SETTING_SEMANTICS


@pytest.mark.parametrize(
    "field",
    [
        "request_settings",
        "request_headers",
        "request_body",
        "system",
        "model",
        "permissions",
        "name",
        "mode",
        "hidden",
        "steps",
        "description",
        "color",
    ],
)
def test_complete_definition_changes_invalidate_even_when_id_is_unchanged(field):
    raw = agent()
    before = agent_definition(PROFILE, raw)
    if field.startswith("request_"):
        raw["request"][field.removeprefix("request_")]["private"] = "PRIVATE-DEFINITION-CANARY"
    else:
        raw[field] = {
            "system": "PRIVATE-DEFINITION-CANARY",
            "model": {"providerID": "private", "id": "PRIVATE-DEFINITION-CANARY"},
            "permissions": [
                {"action": "read", "resource": "PRIVATE-DEFINITION-CANARY", "effect": "allow"}
            ],
            "name": "Changed",
            "mode": "all",
            "hidden": True,
            "steps": 3,
            "description": "PRIVATE-DEFINITION-CANARY",
            "color": "blue",
        }[field]
    after = agent_definition(PROFILE, raw)
    assert before.agent_id == after.agent_id and before.definition_sha256 != after.definition_sha256
    assert "PRIVATE-DEFINITION-CANARY" not in after.model_dump_json()


def test_definition_hash_preserves_rule_order_and_absent_optional_fields():
    raw = agent(
        permissions=[
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*", "effect": "allow"},
        ]
    )
    before = agent_definition(PROFILE, raw)
    raw["permissions"].reverse()
    assert agent_definition(PROFILE, raw).permissions_sha256 != before.permissions_sha256
    raw["system"] = ""
    with_empty = agent_definition(PROFILE, raw)
    raw.pop("system")
    assert with_empty.definition_sha256 != agent_definition(PROFILE, raw).definition_sha256


@pytest.mark.parametrize(
    "invalid",
    ["oversized", "unknown_field", "nonfinite", "invalid_shape", "control_id", "oversized_id"],
)
def test_bad_definitions_fail_generically_without_private_values(invalid):
    raw = agent(system="PRIVATE-DEFINITION-CANARY")
    if invalid == "oversized":
        raw["system"] *= 60000
    elif invalid == "unknown_field":
        raw["credential"] = "PRIVATE-DEFINITION-CANARY"
    elif invalid == "nonfinite":
        raw["request"]["body"]["number"] = float("nan")
    elif invalid == "control_id":
        raw["id"] = "PRIVATE-DEFINITION-CANARY\n"
    elif invalid == "oversized_id":
        raw["id"] = "PRIVATE-DEFINITION-CANARY" * 100
    else:
        raw["permissions"] = [{"effect": "allow"}]
    with pytest.raises(ContractError) as error:
        agent_definition(PROFILE, raw)
    assert "PRIVATE-DEFINITION-CANARY" not in str(error.value)


def test_catalog_hashes_hidden_definitions_but_exposes_only_safe_visible_items():
    raw = {
        "location": {"directory": REF.canonical_directory},
        "data": [agent(), agent("hidden", hidden=True, system="PRIVATE-DEFINITION-CANARY")],
    }
    first = agent_catalog(PROFILE, REF, raw)
    assert [row.agent_id for row in first.items] == ["build"]
    raw["data"][1]["system"] = "changed-private-system"
    second = agent_catalog(PROFILE, REF, raw)
    assert first.items == second.items and first.catalog_sha256 != second.catalog_sha256
    assert "PRIVATE-DEFINITION-CANARY" not in first.model_dump_json()


@pytest.mark.parametrize("change", ["location", "duplicate", "capacity"])
def test_catalog_rejects_foreign_duplicate_and_oversized_responses(change):
    raw = {"location": {"directory": REF.canonical_directory}, "data": [agent()]}
    if change == "location":
        raw["location"]["directory"] = "/foreign"
    elif change == "duplicate":
        raw["data"].append(agent())
    else:
        raw["data"] = [agent(str(n)) for n in range(4097)]
    with pytest.raises(ContractError):
        agent_catalog(PROFILE, REF, raw)


def test_approved_transition_can_include_different_permissions_without_equivalence_claim():
    enrollment = transition()
    require_agent_transition(enrollment, enrollment.before, enrollment.after, AGENT_SETTING_SCHEMA)
    preview = agent_transition_preview(enrollment)
    assert preview.permissions_differ and preview.may_change_tools_system_or_provider
    assert not preview.mutation_authorized and not preview.starts_execution


@pytest.mark.parametrize(
    "change",
    [
        "reverse",
        "new_definition",
        "new_permissions",
        "foreign_root",
        "schema",
        "permission_semantics",
    ],
)
def test_transition_never_wildcards_or_accepts_catalog_or_policy_drift(change):
    e = transition()
    before, after, schema = e.before, e.after, AGENT_SETTING_SCHEMA
    if change == "reverse":
        before, after = after, before
    elif change == "new_definition":
        after = after.model_copy(
            update={
                "definition": after.definition.model_copy(update={"definition_sha256": "d" * 64})
            }
        )
    elif change == "new_permissions":
        after = endpoint("review", effect="deny")
    elif change == "foreign_root":
        after = after.model_copy(
            update={"reference": REF.model_copy(update={"upstream_session_id": "ses_foreign"})}
        )
    elif change == "schema":
        schema = "0" * 64
    else:
        e = e.model_copy(update={"permission_source_sha256": "0" * 64})
    with pytest.raises(ContractError):
        require_agent_transition(e, before, after, schema)


@pytest.mark.parametrize("change", ["same_agent", "foreign_root", "hidden", "subagent"])
def test_transition_enrollment_requires_directed_original_root_and_explicit_root_target(change):
    raw = transition().model_dump(mode="json")
    if change == "same_agent":
        raw["after"]["definition"]["agent_id"] = raw["before"]["definition"]["agent_id"]
    elif change == "foreign_root":
        raw["after"]["reference"]["upstream_session_id"] = "ses_foreign"
    elif change == "hidden":
        raw["after"]["definition"]["hidden"] = True
    else:
        raw["after"]["definition"]["mode"] = "subagent"
    with pytest.raises(ValidationError):
        AgentTransitionEnrollment.model_validate(raw)


def test_root_loader_uses_root_file_identity_and_never_accepts_user_managed_input(
    tmp_path, monkeypatch
):
    path = tmp_path / "candidate.json"
    path.write_text(transition().model_dump_json())
    path.chmod(0o600)
    with pytest.raises(ContractError):
        root_agent_transition(path)
    synthetic_root_metadata(monkeypatch)
    loaded = root_agent_transition(path)
    assert loaded == transition() and loaded.enrollment_sha256 == transition().enrollment_sha256
    path.chmod(0o660)
    with pytest.raises(ContractError):
        root_agent_transition(path)


def test_mixed_chain_validates_both_axes_and_removes_all_metadata_without_input_aliases():
    raw = page()
    raw["data"][0]["metadata"] = {"private": "PRIVATE-DEFINITION-CANARY"}
    result = reconcile_agent_settings_tail(PROFILE, REF, info(), raw, qualification())
    assert (
        len(result["controls"]) == 3
        and result["idle"]["id"] == "msg_idle"
        and not result["pristine"]
    )
    assert "metadata" not in str(result) and "PRIVATE-DEFINITION-CANARY" not in str(result)
    raw["data"][0]["time"]["created"] = 100
    assert result["controls"][0]["time"]["created"] == 8


def test_same_agent_control_is_not_silently_dropped():
    raw = page()
    raw["data"].insert(
        0,
        {
            "id": "msg_same_agent",
            "type": "agent-switched",
            "agent": "review",
            "previous": "review",
            "time": {"created": 9},
        },
    )
    result = reconcile_agent_settings_tail(PROFILE, REF, info(), raw, qualification())
    assert result["controls"][0]["id"] == "msg_same_agent" and len(result["controls"]) == 4


@pytest.mark.parametrize(
    "change",
    [
        "agent_head",
        "agent_previous",
        "model_head",
        "model_previous",
        "duplicate",
        "time",
        "idle_time",
        "idle_outcome",
        "no_idle",
        "user",
        "unknown",
        "foreign",
        "foreign_project",
        "foreign_location",
        "archived",
        "reverted",
        "too_many",
        "model_only",
    ],
)
def test_invalid_or_incomplete_chain_cannot_become_fresh_idle(change):
    current, raw = info(), page()
    if change == "agent_head":
        current["agent"] = "other"
    elif change == "agent_previous":
        raw["data"][0]["previous"] = "other"
    elif change == "model_head":
        current["model"]["id"] = "other"
    elif change == "model_previous":
        raw["data"].insert(
            2,
            {
                "id": "msg_model_older",
                "type": "model-switched",
                "model": {"providerID": "synthetic-provider", "id": "different"},
                "time": {"created": 6.5},
            },
        )
    elif change == "duplicate":
        raw["data"][1]["id"] = raw["data"][0]["id"]
    elif change == "time":
        raw["data"][1]["time"]["created"] = 10
    elif change == "idle_time":
        current["time"]["idle"] = 4
    elif change == "idle_outcome":
        raw["data"][-1]["outcome"] = "failed"
    elif change == "no_idle":
        raw["data"].pop()
    elif change == "user":
        raw["data"].insert(
            2,
            {
                "id": "msg_user",
                "type": "user",
                "text": "PRIVATE-DEFINITION-CANARY",
                "time": {"created": 6.5},
            },
        )
    elif change == "unknown":
        raw["data"][1]["type"] = "future-control"
    elif change == "foreign":
        current["id"] = "ses_foreign"
    elif change == "foreign_project":
        current["projectID"] = "different-native-project"
    elif change == "foreign_location":
        current["location"] = {"directory": "/foreign-workspace"}
    elif change == "archived":
        current["time"]["archived"] = 9
    elif change == "reverted":
        current["revert"] = {}
    elif change == "too_many":
        raw["data"] *= 14
    else:
        raw["data"] = [raw["data"][1], raw["data"][-1]]
    with pytest.raises(ContractError) as error:
        reconcile_agent_settings_tail(PROFILE, REF, current, raw, qualification())
    assert "PRIVATE-DEFINITION-CANARY" not in str(error.value)


@pytest.mark.parametrize("cursor", [{}, {"next": None}, {"next": "more"}])
def test_pristine_chain_needs_independently_qualified_creation_baseline(cursor):
    current, raw = info(), page()
    current.pop("outcome")
    current["time"].pop("idle")
    raw["data"].pop()
    raw["cursor"] = cursor
    with pytest.raises(ContractError, match="positive_idle_not_found"):
        reconcile_agent_settings_tail(PROFILE, REF, current, raw, qualification())


@pytest.mark.parametrize("change", ["missing", "model_semantics", "foreign_root", "schema"])
def test_agent_tail_has_no_default_or_model_only_qualification(change):
    q = qualification()
    if change == "missing":
        q = None
    elif change == "model_semantics":
        q = qualification(semantics_sha256=MODEL_SETTING_SEMANTICS)
    elif change == "foreign_root":
        q = qualification(reference=REF.model_copy(update={"upstream_session_id": "ses_foreign"}))
    else:
        q = qualification(contract_sha256="0" * 64)
    with pytest.raises(ContractError):
        reconcile_agent_settings_tail(PROFILE, REF, info(), page(), q)
    with pytest.raises(ContractError):
        reconcile_model_tail(info(), page())


def test_safe_preview_has_no_private_definitions_and_no_unqualified_authority():
    raw = agent(name="@**everyone**\n```arbitrary```", system="PRIVATE-DEFINITION-CANARY")
    definition = agent_definition(PROFILE, raw)
    assert "\n" not in definition.label
    e = transition()
    e = e.model_copy(update={"after": e.after.model_copy(update={"definition": definition})})
    preview = agent_transition_preview(e).model_dump_json()
    assert "PRIVATE-DEFINITION-CANARY" not in preview and '"mutation_authorized":false' in preview


def test_label_limits_apply_after_serialization_and_root_labels_are_sanitized_again():
    raw = agent(name="*" * 120)
    value = agent_definition(PROFILE, raw)
    assert len(value.label) <= 512 and value.label.endswith("…")
    e = transition()
    e = e.model_copy(
        update={
            "after": e.after.model_copy(
                update={
                    "definition": e.after.definition.model_copy(
                        update={"label": "@**all**\n\x1b[31m&#10;"}
                    )
                }
            )
        }
    )
    label = agent_transition_preview(e).after_label
    assert "\n" not in label and "\x1b" not in label and "@**all**" not in label
    encoded = value.model_copy(update={"agent_id": "review"})
    e = e.model_copy(update={"after": e.after.model_copy(update={"definition": encoded})})
    assert agent_transition_preview(e).after_label == encoded.label


def test_largest_candidate_tail_is_complete_and_unique_before_capacity_rejection():
    current = info()
    raw = page()
    raw["data"] = [
        {
            "id": "msg_setting_" + str(i),
            "type": "agent-switched",
            "agent": "review",
            "previous": "review",
            "time": {"created": 9 - i / 10},
        }
        for i in range(50)
    ] + [raw["data"][-1]]
    result = reconcile_agent_settings_tail(PROFILE, REF, current, raw, qualification())
    assert len(result["controls"]) == 50
    raw["data"].insert(
        50,
        {
            "id": "msg_over_capacity",
            "type": "agent-switched",
            "agent": "review",
            "previous": "review",
            "time": {"created": 4},
        },
    )
    with pytest.raises(ContractError, match="boundary_or_duplicate"):
        reconcile_agent_settings_tail(PROFILE, REF, current, raw, qualification())


@pytest.mark.parametrize(
    "invalid", ["plugin_extra", "saved_extra", "mcp_unknown", "nonfinite", "oversized"]
)
def test_policy_endpoint_requires_complete_dependency_contracts_and_bounded_json(invalid):
    current = info()
    current["agent"] = "build"
    location = {"directory": REF.canonical_directory}
    plugins = {"location": location, "data": []}
    saved = {"data": []}
    mcp = {"location": location, "data": [{"name": "fixture", "status": {"status": "disabled"}}]}
    if invalid == "plugin_extra":
        plugins["private_unknown"] = "PRIVATE-DEFINITION-CANARY"
    elif invalid == "saved_extra":
        saved["private_unknown"] = "PRIVATE-DEFINITION-CANARY"
    elif invalid == "mcp_unknown":
        mcp["data"][0]["status"] = {"status": "PRIVATE-DEFINITION-CANARY"}
    elif invalid == "nonfinite":
        mcp["data"][0]["value"] = float("inf")
    else:
        mcp["data"][0]["name"] = "PRIVATE-DEFINITION-CANARY" * 200000
    with pytest.raises(ContractError) as error:
        agent_policy_endpoint(
            PROFILE,
            REF,
            "global",
            current,
            {"location": location, "data": agent()},
            plugins,
            saved,
            mcp,
        )
    assert "PRIVATE-DEFINITION-CANARY" not in str(error.value)


@pytest.mark.parametrize("name", ["a&b", "a&amp;b", "<Agent>", "@**all**", "a`b_*-"])
def test_native_label_preview_roundtrip_is_idempotent_without_entity_doubling(name):
    definition = agent_definition(PROFILE, agent("review", name=name))
    e = transition()
    e = e.model_copy(update={"after": e.after.model_copy(update={"definition": definition})})
    assert agent_transition_preview(e).after_label == definition.label
    e = e.model_copy(
        update={
            "after": e.after.model_copy(
                update={
                    "definition": definition.model_copy(
                        update={"label": agent_transition_preview(e).after_label}
                    )
                }
            )
        }
    )
    assert agent_transition_preview(e).after_label == definition.label
