"""Synthetic Native setter/readback/reader cases; never installed Agent qualification."""

import json

import pytest

from jt_oz_bridge.adapters.opencode.agent_configuration import ConfigurationReadiness
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.resources import root_state
from jt_oz_bridge.adapters.opencode.transport import TransportError
from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation, match_isolated_turn
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent, MutationRejected
from tests.agent_switch_support import ACTIVE, native_root
from tests.contract.test_leaf_resources import finish
from tests.contract.test_native_project_policy import prompt_payload

ACTION = "action_fixture"


def ready(root, identity, *, mode="mutation_ready", reason=None, revision=2):
    endpoint = root.endpoint(identity)
    return root.cell.set(
        ConfigurationReadiness(
            reference=root.reference,
            root_key="k" * 64,
            revision=revision,
            effective_sha256="f" * 64,
            agent_id=identity,
            policy_sha256=endpoint.policy_sha256,
            mode=mode,
            reason=reason,
        )
    )


async def test_observation_is_get_only_and_lists_only_exact_enrolled_targets():
    root = await native_root(transitions=(("build", "plan"), ("plan", "review")))
    try:
        seen = await root.settings.observe(root.reference)
        assert seen.agent_id == "build" and seen.state == ExecutionState.IDLE
        assert [c.endpoint.definition.agent_id for c in seen.candidates] == ["plan"]
        assert seen.settings_tail_ready is True and not root.writes
        visible = {item.agent_id for item in seen.catalog.items}
        assert "secret" not in visible and {"build", "plan", "helper"} <= visible
    finally:
        await finish(root.proofs, root.transport)


async def test_no_enrollment_gives_no_candidate_and_setter_never_posts():
    root = await native_root(transitions=())
    try:
        seen = await root.settings.observe(root.reference)
        assert seen.candidates == ()
        with pytest.raises(MutationNotSent):
            await root.settings.switch(
                root.reference, ACTION, root.endpoint("build"), root.endpoint("plan")
            )
        assert not root.writes
    finally:
        await finish(root.proofs, root.transport)


async def test_setter_sends_one_fixed_body_and_nothing_can_widen_session_rules():
    root = await native_root()
    rules = list(root.data["session.get"]["data"]["permissions"])
    before, after = root.endpoint("build"), root.endpoint("plan")
    try:
        ack = await root.settings.switch(root.reference, ACTION, before, after)
        assert ack.agent_id == "plan" and len(root.writes) == 1
        write = root.writes[0]
        assert write.url.path.endswith("/agent") and json.loads(write.content) == {"agent": "plan"}
        # Root deny-all session rules remain the stored rules after the only write.
        assert root.data["session.get"]["data"]["permissions"] == rules
        back = await root.settings.readback(root.reference, ack, before, after)
        assert back.observation.endpoint == after and len(root.writes) == 1
    finally:
        await finish(root.proofs, root.transport)


@pytest.mark.parametrize("change", ["running", "definition", "permissions", "catalog", "tail"])
async def test_changed_preflight_is_known_unsent_and_posts_nothing(change):
    root = await native_root()
    before, after = root.endpoint("build"), root.endpoint("plan")
    if change == "running":
        root.data["session.active"]["data"] = {root.reference.upstream_session_id: ACTIVE}
    elif change == "definition":
        root.agents["plan"]["description"] = "changed"
    elif change == "permissions":
        root.agents["plan"]["permissions"].append(
            {"action": "bash", "resource": "*", "effect": "allow"}
        )
    elif change == "catalog":
        del root.agents["plan"]
    else:
        root.rows.clear()
    try:
        with pytest.raises(MutationNotSent):
            await root.settings.switch(root.reference, ACTION, before, after)
        assert not root.writes
    finally:
        await finish(root.proofs, root.transport)


async def test_lost_ack_is_uncertain_exactly_one_post_and_no_retry():
    root = await native_root()
    root.post_mode[0] = "lost_ack"
    try:
        with pytest.raises(TransportError) as raised:
            await root.settings.switch(
                root.reference, ACTION, root.endpoint("build"), root.endpoint("plan")
            )
        assert not isinstance(raised.value, MutationNotSent)
        assert len(root.agent_posts()) == 1
    finally:
        await finish(root.proofs, root.transport)


async def test_upstream_rejection_is_not_reported_as_known_unsent():
    root = await native_root()
    root.post_mode[0] = "reject"
    try:
        with pytest.raises(MutationRejected) as raised:
            await root.settings.switch(
                root.reference, ACTION, root.endpoint("build"), root.endpoint("plan")
            )
        assert not isinstance(raised.value, MutationNotSent)
    finally:
        await finish(root.proofs, root.transport)


@pytest.mark.parametrize("mode", ["wrong_readback", "foreign_previous", "no_record"])
async def test_target_field_equality_alone_never_verifies_readback(mode):
    """Native showing the target Agent cannot prove this exact setter result."""
    root = await native_root()
    root.post_mode[0] = mode
    before, after = root.endpoint("build"), root.endpoint("plan")
    try:
        ack = await root.settings.switch(root.reference, ACTION, before, after)
        with pytest.raises(ContractError):
            await root.settings.readback(root.reference, ack, before, after)
        assert len(root.agent_posts()) == 1
    finally:
        await finish(root.proofs, root.transport)


async def test_same_id_definition_drift_never_matches_the_enrolled_endpoint():
    root = await native_root()
    before, after = root.endpoint("build"), root.endpoint("plan")
    try:
        ack = await root.settings.switch(root.reference, ACTION, before, after)
        root.agents["plan"]["system"] = "a different system prompt, same Agent and permissions"
        with pytest.raises(ContractError):
            await root.settings.readback(root.reference, ack, before, after)
    finally:
        await finish(root.proofs, root.transport)


async def test_generic_submit_can_never_send_the_agent_setter():
    root = await native_root()
    try:
        payload = {**prompt_payload(), "operation": "agent.switch"}
        with pytest.raises(MutationNotSent):
            await root.client.submit(root.reference, payload, ACTION)
        assert not root.writes
    finally:
        await finish(root.proofs, root.transport)


async def test_capability_needs_exact_root_attestation_and_installed_setter():
    unqualified = await native_root(qualified=False)
    try:
        assert not unqualified.client.capabilities(unqualified.reference)["agent.switch"].supported
    finally:
        await finish(unqualified.proofs, unqualified.transport)
    root = await native_root()
    try:
        assert root.client.capabilities(root.reference)["agent.switch"].supported
        operations = root.transport.attestation.verified_operations - {"session.switchAgent"}
        from dataclasses import replace

        root.transport.attestation = replace(
            root.transport.attestation, verified_operations=operations
        )
        assert not root.client.capabilities(root.reference)["agent.switch"].supported
    finally:
        await finish(root.proofs, root.transport)


async def test_next_prompt_requires_the_published_activation_not_just_native_state():
    root = await native_root()
    before, after = root.endpoint("build"), root.endpoint("plan")
    try:
        ack = await root.settings.switch(root.reference, ACTION, before, after)
        await root.settings.readback(root.reference, ack, before, after)
        # Native already reports the target. Without activation the old pin refuses.
        with pytest.raises(MutationNotSent):
            await root.client.submit(root.reference, prompt_payload(), ACTION)
        assert not root.prompt_posts()
        ready(root, "plan")
        result = await root.client.submit(root.reference, prompt_payload(), ACTION)
        assert result.status == "admitted" and len(root.prompt_posts()) == 1
    finally:
        await finish(root.proofs, root.transport)


async def test_read_only_configuration_blocks_mutation_but_keeps_interrupt_and_reads():
    root = await native_root()
    try:
        ready(root, "build", mode="read_only", reason="external_change")
        with pytest.raises(MutationNotSent):
            await root.client.submit(root.reference, prompt_payload(), ACTION)
        assert not root.writes
        snapshot = await root.client.snapshot(root.reference)
        assert snapshot.reference == root.reference
        stop = await root.client.submit(
            root.reference,
            {
                "operation": "interrupt",
                "reference": root.reference.model_dump(),
                "source": _stop_source(),
            },
            ACTION,
        )
        assert stop.status == "completed"
    finally:
        await finish(root.proofs, root.transport)


def _stop_source():
    from tests.integration.test_dispatch import message

    return message(text="!oz stop", revision=0).model_dump(mode="json")


async def test_external_change_invalidates_guard_until_it_is_explicitly_adopted():
    root = await native_root()
    try:
        ready(root, "build", revision=1)
        root.external_switch("plan")
        with pytest.raises(MutationNotSent):
            await root.client.submit(root.reference, prompt_payload(), ACTION)
        assert not root.writes
    finally:
        await finish(root.proofs, root.transport)


async def test_published_configuration_invalidates_witness_crossing_it():
    root = await native_root()
    try:
        _snapshot, proof = await root.client.qualified_snapshot(root.reference)
        witness = await root.guard.authorize(root.reference, "prompt", proof)
        assert root.guard.current(root.reference, "prompt", proof, witness)
        ready(root, "build", revision=1)
        assert not root.guard.current(root.reference, "prompt", proof, witness)
    finally:
        await finish(root.proofs, root.transport)


@pytest.mark.parametrize(
    "rows",
    [
        [("agent-switched", "plan", "build")],
        [("model-switched", None, None), ("agent-switched", "plan", "build")],
        [("agent-switched", "plan", "review"), ("agent-switched", "review", "build")],
    ],
)
async def test_mixed_setting_tail_reaches_positive_idle_only_with_attestation(rows):
    root = await native_root()
    info = root.data["session.get"]["data"]
    created = info["time"]["updated"]
    for index, (kind, agent, previous) in enumerate(reversed(rows)):
        created += 1
        row = {"id": f"msg_tail_{index}", "type": kind, "time": {"created": created}}
        if kind == "agent-switched":
            row |= {"agent": agent, "previous": previous}
            info["agent"] = agent
        else:
            row |= {
                "model": {"providerID": "synthetic-provider", "id": "m"},
            }
            info["model"] = {"providerID": "synthetic-provider", "id": "m"}
        root.rows.insert(0, row)
    info["time"]["updated"] = created
    try:
        bundle = await root.proofs.bundle(root.reference)
        assert root_state(bundle) == ExecutionState.IDLE
        assert bundle["agent_settings"]["idle"]["type"] == "idle"
    finally:
        await finish(root.proofs, root.transport)


async def test_agent_tail_without_exact_attestation_is_never_idle():
    root = await native_root(qualified=False)
    root.external_switch("plan")
    try:
        bundle = await root.proofs.bundle(root.reference)
        with pytest.raises(ContractError):
            root_state(bundle)
    finally:
        await finish(root.proofs, root.transport)


async def test_broken_previous_chain_is_rejected_by_qualified_reader():
    root = await native_root()
    root.external_switch("plan")
    root.external_switch("review")
    root.rows[0]["previous"] = "build"
    try:
        with pytest.raises(ContractError):
            await root.proofs.bundle(root.reference)
    finally:
        await finish(root.proofs, root.transport)


def turn_rows(*settings):
    user = {
        "id": "msg_user",
        "type": "user",
        "time": {"created": 1},
        "text": "exact",
        "metadata": {"jt_oz_bridge": {"action_id": "a", "operation_digest": "b" * 64}},
        "attachments_present": False,
    }
    idle = {"id": "msg_end", "type": "idle", "time": {"created": 3}, "outcome": "succeeded"}
    return [*settings, idle, user]


def test_turn_result_tolerates_following_agent_setting_only_when_qualified():
    from tests.contract.test_leaf_resources import REF

    correlation = TurnCorrelation(
        reference=REF,
        action_id="a",
        operation_digest="b" * 64,
        upstream_id="msg_user",
        text="exact",
    )
    setting = {"id": "msg_set", "type": "agent-switched", "time": {"created": 4}}
    with pytest.raises(ContractError):
        match_isolated_turn(correlation, turn_rows(setting))
    turn = match_isolated_turn(correlation, turn_rows(setting), allow_agent_settings=True)
    assert turn.setting_message_ids == ("msg_set",) and turn.outcome == "succeeded"


async def test_cell_refuses_revision_regression_and_unissued_candidates():
    root = await native_root()
    try:
        saved = ready(root, "plan", revision=5)
        assert saved.mode == "mutation_ready"
        with pytest.raises(Exception, match="agent_configuration_revision_regressed"):
            ready(root, "build", revision=4)
        first = root.cell.prepare(saved)
        second = root.cell.prepare(saved)
        root.cell.publish(first)
        with pytest.raises(Exception, match="agent_configuration_predecessor_changed"):
            root.cell.publish(second)
    finally:
        await finish(root.proofs, root.transport)


async def _check_tail(root, *, agent_settings):
    from jt_oz_bridge.adapters.opencode.checks import (
        CHECK_SEMANTICS,
        CheckExecutionAttestation,
        KnownCheck,
        V2CheckTailReader,
    )
    from jt_oz_bridge.domain.checks import CheckCatalog, check_message_id
    from tests.contract.test_native_checks import CHECK

    catalog = CheckCatalog(
        reference=root.reference, contract_sha256=root.transport.profile.sha256, checks=(CHECK,)
    )
    qualification = CheckExecutionAttestation(catalog, CHECK_SEMANTICS, "a" * 64)

    async def known(_reference, _identity):
        return KnownCheck("a", "b" * 64, CHECK, qualification.enrollment_sha256)

    info = root.data["session.get"]["data"]
    info["agent"] = "plan"
    info["time"]["updated"] = 30
    root.rows[:0] = [
        {
            "id": check_message_id("a"),
            "type": "shell",
            "command": CHECK.command,
            "shellID": "sh_owned",
            "status": "exited",
            "exit": 0,
            "time": {"created": 10, "completed": 20},
            "output": {"output": "ok", "cursor": 2, "size": 2, "truncated": False},
        },
        {
            "id": "msg_agent_switch",
            "type": "agent-switched",
            "time": {"created": 5},
            "agent": "plan",
            "previous": "build",
        },
    ]
    transport = root.transport
    reader = V2CheckTailReader(
        transport,
        qualification,
        known,
        model_settings=root.proofs.model_settings,
        agent_settings=agent_settings,
    )
    page = root.rows[0]
    return await reader.read(root.reference, info, page)


async def test_owned_check_tail_reads_agent_setting_only_with_exact_attestation():
    root = await native_root()
    try:
        tail = await _check_tail(root, agent_settings=root.proofs.agent_settings_for)
        assert tail["idle"]["type"] == "idle" and len(tail["checks"]) == 1
        assert [item["id"] for item in tail["model_controls"]] == ["msg_agent_switch"]
    finally:
        await finish(root.proofs, root.transport)
    root = await native_root()
    try:
        with pytest.raises(ContractError, match="agent_qualification_required"):
            await _check_tail(root, agent_settings=None)
    finally:
        await finish(root.proofs, root.transport)
