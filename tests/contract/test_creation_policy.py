"""Synthetic policy-template derivation; never an installed creation certificate."""

import copy
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate, V2CreationPolicy
from jt_oz_bridge.adapters.opencode.project_policy import _policy_facts, policy_fingerprint
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.session_creation import (
    NativePermissionRule,
    RootCreationTemplate,
    SessionCreationIntent,
)
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import fingerprint, setup


async def creation(hook=None, *, mcp_status=None):
    proofs, transport, data, guard, execution, calls, writes = await setup(
        hook, mcp_status=mcp_status
    )
    epoch = (await proofs.feed.current_owner()).owner_epoch
    proofs.feed.owner.read.side_effect = lambda: SimpleNamespace(
        owner_epoch=epoch,
        backend_id=REF.backend_id,
        backend_identity=REF.backend_identity,
        observed_at=time.time(),
    )
    source = guard.enrollments[REF]
    template = CreationPolicyTemplate(
        format="native-root-creation-policy-v1",
        source=source,
        creation=RootCreationTemplate(
            scope=ProjectScope(**REF.model_dump(exclude={"upstream_session_id"})),
            native_project_id="global",
            agent_id="build",
            permissions=(),
        ),
        operations=frozenset({"prompt", "model.switch"}),
    )
    intent = SessionCreationIntent(
        intent_id="a" * 32,
        scope=template.creation.scope,
        native_session_id="ses_jtoz_" + "b" * 32,
        source_sha256="c" * 64,
        owner_epoch=(await proofs.feed.current_owner()).owner_epoch,
    )
    return V2CreationPolicy(guard, template), intent, proofs, transport, data, calls, writes


async def test_original_fingerprint_bytes_unchanged_and_new_ref_uses_approved_template_rules():
    policy, intent, proofs, transport, data, calls, writes = await creation()
    try:
        facts = _policy_facts(
            REF,
            "global",
            data["session.get"]["data"],
            data["agent.get"],
            data["plugin.list"],
            data["permission.saved.list"],
            data["mcp.list"],
        )
        assert facts["format"] == "native-project-policy-fingerprint-v2"
        legacy = copy.deepcopy(facts)
        legacy["format"] = "native-project-policy-fingerprint-v1"
        legacy["mcp"] = copy.deepcopy(data["mcp.list"]["data"])
        # Preserve the historical fixture bytes, while explicitly migrating its
        # policy projection. Deriving a new Root must not rewrite the source pin.
        assert digest(legacy) == "0eed3f6aa94e4f449ddcb64fc5902c694176ebedc63c42f60859d90cffbb9827"
        original = fingerprint(data)
        assert original == policy.template.source.fingerprint_sha256 != digest(legacy)
        result = await policy.derive(intent)
        assert fingerprint(data) == original == policy.template.source.fingerprint_sha256
        assert result.enrollment.reference.upstream_session_id == intent.native_session_id
        assert result.enrollment.operations == {"prompt", "model.switch"}
        # New projects may use administrator-approved Native defaults; do not
        # silently copy the integration fixture's deny-all session rules.
        info = copy.deepcopy(data["session.get"]["data"])
        info.update(id=intent.native_session_id, permissions=[])
        assert result.enrollment.fingerprint_sha256 == policy_fingerprint(
            result.enrollment.reference,
            "global",
            info,
            data["agent.get"],
            data["plugin.list"],
            data["permission.saved.list"],
            data["mcp.list"],
        )
        assert result.enrollment.fingerprint_sha256 != policy.template.source.fingerprint_sha256
        assert data["session.get"]["data"]["permissions"] == [
            {"action": "*", "resource": "*", "effect": "deny"}
        ]
        assert await policy.current(intent, result)
        assert not await policy.current(intent, result.model_copy())
        assert len(calls) == 12 and not writes
        serialized = result.model_dump_json()
        assert "permissions" not in serialized and "request" not in serialized
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize(
    "fault",
    [
        "rules",
        "agent-rules",
        "mcp",
        "saved",
        "plugin",
        "source-scope",
        "agent",
        "scope",
        "operation",
    ],
)
async def test_drift_or_unapproved_source_never_derives_new_execution_policy(fault):
    policy, intent, proofs, transport, data, calls, writes = await creation()
    try:
        if fault == "rules":
            data["session.get"]["data"]["permissions"][0]["effect"] = "allow"
        elif fault == "agent-rules":
            data["agent.get"]["data"]["permissions"][0]["effect"] = "deny"
        elif fault == "mcp":
            data["mcp.list"]["data"] = []
        elif fault == "saved":
            data["permission.saved.list"]["data"] = [
                {
                    "id": "new-grant",
                    "projectID": "global",
                    "rules": [{"action": "*", "resource": "*", "effect": "allow"}],
                }
            ]
        elif fault == "plugin":
            data["plugin.list"]["data"][0]["features"]["server"] = False
        elif fault == "source-scope":
            data["session.get"]["data"]["projectID"] = "other"
        elif fault == "agent":
            policy.template = policy.template.model_copy(
                update={
                    "creation": policy.template.creation.model_copy(
                        update={"agent_id": "other-agent"}
                    )
                }
            )
        elif fault == "scope":
            intent = intent.model_copy(
                update={"scope": intent.scope.model_copy(update={"canonical_directory": "/other"})}
            )
        else:
            transport.attestation = replace(
                transport.attestation, verified_operations=frozenset({"session.get"})
            )
        with pytest.raises(ContractError):
            await policy.derive(intent)
        assert not writes
    finally:
        await finish(proofs, transport)


async def test_a_native_restart_after_creation_still_derives_under_the_current_process():
    policy, intent, proofs, transport, _data, _calls, writes = await creation()
    try:
        live = (await policy.anchor.proofs.feed.current_owner()).owner_epoch
        derived = await policy.derive(intent.model_copy(update={"owner_epoch": "f" * 64}))
        assert derived.owner_epoch == live and not writes
    finally:
        await finish(proofs, transport)


async def test_an_owner_change_during_one_derivation_is_rejected():
    policy, intent, proofs, transport, _data, _calls, writes = await creation()
    try:
        feed = policy.anchor.proofs.feed
        read = feed.current_owner
        seen = 0

        async def restarted():
            nonlocal seen
            seen += 1
            owner = await read()
            return (
                owner if seen == 1 else SimpleNamespace(**{**vars(owner), "owner_epoch": "f" * 64})
            )

        feed.current_owner = restarted
        with pytest.raises(ContractError):
            await policy.derive(intent)
        assert not writes
    finally:
        await finish(proofs, transport)


async def test_source_global_change_between_double_reads_is_rejected():
    def hook(op, count, data, proofs):
        if count == 5:
            data["mcp.list"]["data"] = []

    policy, intent, proofs, transport, data, calls, writes = await creation(hook)
    try:
        with pytest.raises(ContractError):
            await policy.derive(intent)
        assert not writes
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize("initial", ["connected", "failed"])
async def test_creation_derivation_and_current_check_share_transport_health_projection(initial):
    reads = []

    def hook(op, count, data, proofs):
        if op == "mcp.list":
            status = (
                {"status": "connected"}
                if len(reads) % 2
                else {"status": "failed", "error": f"fixture transport error {len(reads)}"}
            )
            data[op]["data"][0]["status"] = status
            reads.append(copy.deepcopy(status))

    status = {"status": initial}
    if initial == "failed":
        status["error"] = "initial fixture transport error"
    policy, intent, proofs, transport, data, calls, writes = await creation(hook, mcp_status=status)
    try:
        source = policy.template.source
        original_rules = copy.deepcopy(data["session.get"]["data"]["permissions"])
        result = await policy.derive(intent)
        assert await policy.current(intent, result)
        assert len(reads) == 3 and reads[0] != reads[1]
        assert fingerprint(data) == source.fingerprint_sha256
        assert data["mcp.list"]["data"][0]["status"] == reads[-1]
        assert data["session.get"]["data"]["permissions"] == original_rules
        assert policy.template.source is source and not writes
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize(
    "fault", ["changed-policy", "attestation", "expired", "intent", "template"]
)
async def test_handoff_checks_issued_object_owner_contract_age_and_original_global_policy(fault):
    policy, intent, proofs, transport, data, calls, writes = await creation()
    try:
        result = await policy.derive(intent)
        if fault == "changed-policy":
            data["mcp.list"]["data"] = []
        elif fault == "attestation":
            transport.attestation = replace(transport.attestation)
        elif fault == "expired":
            result = result.model_copy(update={"observed_at": time.time() - 6})
        elif fault == "intent":
            intent = intent.model_copy(update={"source_sha256": "f" * 64})
        else:
            policy.template = policy.template.model_copy(
                update={
                    "creation": policy.template.creation.model_copy(
                        update={
                            "permissions": (
                                NativePermissionRule(action="*", resource="*", effect="ask"),
                            )
                        }
                    )
                }
            )
        assert not await policy.current(intent, result) and not writes
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize("fault", ["scope", "project", "operations", "contract"])
async def test_creation_template_cannot_expand_operator_approved_scope_or_operations(fault):
    policy, intent, proofs, transport, data, calls, writes = await creation()
    try:
        value = policy.template.model_dump(mode="json")
        if fault == "scope":
            value["creation"]["scope"]["canonical_directory"] = "/other"
        elif fault == "project":
            value["creation"]["native_project_id"] = "other"
        elif fault == "operations":
            value["operations"] = ["session.create", "arbitrary.tool"]
        else:
            value["source"]["contract_sha256"] = "f" * 64
        with pytest.raises(ValidationError):
            CreationPolicyTemplate.model_validate(value)
        assert not writes
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize("seed", ["1", "2", "17", "91"])
async def test_template_checksum_survives_independent_hash_seeds_and_json_order(seed):
    import asyncio
    import json
    import os
    import sys

    from jt_oz_bridge.storage.durable import digest

    policy, _, proofs, transport, _, _, _ = await creation()
    try:
        value = policy.template.model_dump(mode="json")
        value["operations"] = sorted(value["operations"])
        value["source"]["operations"] = sorted(value["source"]["operations"])
        expected = digest(value)
        value["operations"].reverse()
        value["source"]["operations"].reverse()
        script = (
            "import json,sys;"
            "from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate;"
            "v=CreationPolicyTemplate.model_validate(json.load(sys.stdin));print(v.checksum())"
        )
        env = dict(os.environ, PYTHONHASHSEED=seed)
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(15):
                output, errors = await child.communicate(json.dumps(value).encode())
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()
        assert child.returncode == 0 and errors == b""
        assert output.decode().strip() == expected
        assert policy.template.checksum() == expected
        # Ordered Native permission rules must remain part of the identity.
        value["creation"]["permissions"] = [
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*", "effect": "ask"},
        ]
        first = CreationPolicyTemplate.model_validate(value).checksum()
        value["creation"]["permissions"].reverse()
        assert CreationPolicyTemplate.model_validate(value).checksum() != first
    finally:
        await finish(proofs, transport)
