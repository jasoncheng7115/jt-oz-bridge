"""Original installed schema + real resource/policy gates; HTTP and directories synthetic."""

import copy
import json
import time
from dataclasses import replace
from types import MappingProxyType

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.git_review import GitReviewAttestation
from jt_oz_bridge.adapters.opencode.transport import TransportNotSent
from jt_oz_bridge.adapters.opencode.worktrees import WORKTREE_OPERATIONS, V2WorktreeCreation
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.worktrees import WorktreeIntent, WorktreeTemplate, native_setup_command
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_git_review import prepared
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import fingerprint


async def fixture(
    *,
    setup_allowed=True,
    opted_in=True,
    lost=False,
    suffix=False,
    readback_wrong=False,
    running=False,
):
    p, t, d, review, raw, calls, writes, physical = await prepared()
    command = "echo setup"
    d["session.get"]["data"]["permissions"] = [
        {"action": "shell", "resource": command, "effect": "allow" if setup_allowed else "deny"}
    ]
    e = review.guard.enrollments[REF].model_copy(
        update={
            "fingerprint_sha256": fingerprint(d),
            "operations": review.guard.enrollments[REF].operations
            | ({"worktree.create"} if opted_in else set()),
        }
    )
    review.guard.enrollments = MappingProxyType({REF: e})
    a = review.attestations[REF]
    review.attestations = MappingProxyType(
        {
            REF: GitReviewAttestation(
                REF,
                a.schema_sha256,
                e.fingerprint_sha256,
                a.semantics_sha256,
                a.installed_evidence_sha256,
                a.operations,
            )
        }
    )
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | WORKTREE_OPERATIONS
    )
    project = {
        "id": "global",
        "canonical": REF.canonical_directory,
        "vcs": "git",
        "commands": {"start": command},
        "time": {"created": 1, "updated": 2, "active": 3},
        "sandboxes": [],
    }
    template = WorktreeTemplate(
        reference=REF,
        native_project_id="global",
        destination_parent=REF.canonical_directory + "/worktrees",
        contract_sha256=t.profile.sha256,
        native_policy_sha256=e.fingerprint_sha256,
        project_facts_sha256=digest(
            {k: project.get(k) for k in ("id", "canonical", "vcs", "commands")}
        ),
        strategy_evidence_sha256="c" * 64,
        setup_command=command,
    )
    producer = V2WorktreeCreation(review, template)
    intent = WorktreeIntent(intent_id="1" * 32, template=template, source_sha256="d" * 64)
    original = t.client._transport
    sent = []

    def handler(request):
        if request.url.path == "/api/project":
            assert request.method == "GET"
            return httpx.Response(200, json=[copy.deepcopy(project)])
        if request.url.path == "/api/worktree" and request.method == "POST":
            body = json.loads(request.content)
            assert body == {
                "projectID": "global",
                "from": REF.canonical_directory,
                "directory": template.destination_parent,
                "name": intent.name,
                "branch": intent.branch,
            }
            sent.append(body)
            directory = intent.directory + ("-2" if suffix else "")
            raw["worktrees"].append({"directory": directory, "strategy": "git"})
            if lost:
                raise httpx.ReadTimeout("synthetic_response_lost")
            return httpx.Response(200, json={"directory": directory})
        if (
            request.url.path == "/api/location"
            and request.url.params.get("location[directory]") == intent.directory
        ):
            return httpx.Response(
                200,
                json={
                    "directory": intent.directory,
                    "project": {
                        "id": "foreign" if readback_wrong else "global",
                        "directory": intent.directory,
                        "canonical": REF.canonical_directory,
                    },
                },
            )
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    if running:
        d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    await p.watch(REF)
    return p, t, producer, intent, sent, project, physical


async def test_true_native_worktree_create_request_then_double_get_and_physical_readback():
    p, t, producer, intent, sent, _, physical = await fixture()
    authorities = []

    async def authority():
        authorities.append(True)

    try:
        proof = await producer.prepare(intent)
        assert producer.current(intent, proof)
        observed = await producer.create(intent, proof, authorize=authority)
        assert len(sent) == 1 and authorities
        assert observed.status == "completed" and producer.observation_current(intent, observed)
        assert not observed.changes_original_session and not observed.grants_execution
        assert (
            sum(
                intent.directory.removeprefix(REF.canonical_directory + "/") in paths
                for paths in physical.calls
            )
            == 2
        )
        recovered = await producer.reconcile(intent)
        assert recovered.status == "registered_setup_unknown" and len(sent) == 1
    finally:
        await finish(p, t)


@pytest.mark.parametrize("setup_allowed,opted_in", [(False, True), (True, False)])
async def test_native_worktree_denied_original_setup_or_absent_independent_optin_never_sends(
    setup_allowed, opted_in
):
    p, t, producer, intent, sent, _, _ = await fixture(
        setup_allowed=setup_allowed, opted_in=opted_in
    )
    try:
        with pytest.raises(ValueError):
            await producer.prepare(intent)
        assert sent == []
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "lost,suffix,readback_wrong", [(True, False, False), (False, True, False), (False, False, True)]
)
async def test_native_worktree_uncertain_or_mismatched_response_never_retries_or_claims_completion(
    lost, suffix, readback_wrong
):
    p, t, producer, intent, sent, _, _ = await fixture(
        lost=lost, suffix=suffix, readback_wrong=readback_wrong
    )

    async def authority():
        pass

    try:
        proof = await producer.prepare(intent)
        with pytest.raises(ValueError):
            await producer.create(intent, proof, authorize=authority)
        assert len(sent) == 1
        if lost:
            observed = await producer.reconcile(intent)
            assert observed.status == "registered_setup_unknown"
        assert len(sent) == 1
    finally:
        await finish(p, t)


async def test_native_worktree_setup_edit_or_expired_issuer_proof_cannot_send():
    p, t, producer, intent, sent, project, _ = await fixture()

    async def authority():
        pass

    try:
        proof = await producer.prepare(intent)
        forged = proof.model_copy(update={"expires_at": time.time() + 5})
        with pytest.raises(ValueError):
            await producer.create(intent, forged, authorize=authority)
        assert sent == []
        project["commands"]["start"] = "different command"
        with pytest.raises(ValueError):
            await producer.prepare(intent)
        assert sent == []
    finally:
        await finish(p, t)


async def test_worktree_transport_requires_live_original_authority_even_with_attestation():
    p, t, producer, intent, sent, _, _ = await fixture()
    try:
        with pytest.raises(TransportNotSent, match="authority_required"):
            await t.request("worktree.create", body={"projectID": "global"})
        proof = await producer.prepare(intent)

        async def deny():
            raise ValueError("source revoked")

        with pytest.raises(MutationNotSent):
            await producer.create(intent, proof, authorize=deny)
        assert sent == []
    finally:
        await finish(p, t)


async def test_native_worktree_project_setup_changed_during_human_authority_recheck_never_sends():
    p, t, producer, intent, sent, project, _ = await fixture()

    async def authority():
        project["commands"]["start"] = "unreviewed script"

    try:
        proof = await producer.prepare(intent)
        with pytest.raises(MutationNotSent):
            await producer.create(intent, proof, authorize=authority)
        assert sent == []
    finally:
        await finish(p, t)


async def test_worktree_running_original_root_remains_in_place_with_full_qualified_proof():
    p, t, producer, intent, sent, _, _ = await fixture(running=True)

    async def authority():
        pass

    try:
        proof = await producer.prepare(intent)
        observed = await producer.create(intent, proof, authorize=authority)
        assert len(sent) == 1 and observed.status == "completed"
        assert not observed.changes_original_session
    finally:
        await finish(p, t)


def test_native_setup_rule_evaluates_exact_ecmascript_trim_not_python_whitespace():
    assert native_setup_command("\ufeff echo setup \ufeff") == "echo setup"
    assert native_setup_command("\x85echo setup\x85") == "\x85echo setup\x85"
