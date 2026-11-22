"""A Root created from chat reads files only when its rules match its source Root.

Synthetic Native GET peers and attestations; not live or Human evidence.
"""

from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode.creation_policy import effective_rules, same_rules
from jt_oz_bridge.adapters.opencode.files import (
    FILE_FEATURES,
    FILE_SEMANTICS,
    BinaryReadAttestation,
    V2NativeFileReader,
)
from jt_oz_bridge.domain.session_creation import NativePermissionRule
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from tests.contract.test_created_root_factory import setup, staged_graph
from tests.contract.test_leaf_resources import REF, finish

DENY_ALL = (NativePermissionRule(action="*", resource="*", effect="deny"),)


def source_reads(execution, transport, guard):
    transport.attestation = replace(
        transport.attestation,
        verified_operations=transport.attestation.verified_operations | {"fs.read"},
    )
    attestation = BinaryReadAttestation(
        REF,
        transport.profile.sha256,
        FILE_SEMANTICS,
        "f" * 64,
        guard.enrollments[REF].fingerprint_sha256,
        FILE_FEATURES,
    )
    return {"files": V2NativeFileReader(execution, attestation=attestation)}


def test_effective_rules_drop_only_copies_that_can_never_decide():
    allow, deny = (
        {"action": "*", "resource": "*", "effect": "allow"},
        {
            "action": "*",
            "resource": "*",
            "effect": "deny",
        },
    )
    env = {"action": "read", "resource": "*.env", "effect": "ask"}
    # The agent's rules repeated as the session's: every decision is the same.
    assert effective_rules([allow, env], []) == effective_rules([allow, env], [allow, env])
    # Order decides (the last match wins), so a reordering is a different policy.
    assert effective_rules([allow, deny], []) != effective_rules([allow, deny], [allow])
    assert effective_rules([allow], [deny]) != effective_rules([allow], [])
    facts = {"agent": {"permissions": [allow, env]}, "session_permissions": [allow, env]}
    assert same_rules({**facts, "saved_permissions": []}, [])
    # A saved approval may be evaluated between the two lists: never equal then.
    assert not same_rules({**facts, "saved_permissions": [{"id": "per_1"}]}, [])


async def test_a_root_with_its_sources_rules_gets_its_own_file_reader():
    p, t, _d, f, intent, candidate, _state, calls, writes, anchor = await setup(
        permissions=DENY_ALL, reads=source_reads
    )
    try:
        entry = await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        ref = entry.reference
        policy = entry.execution.scope_guard.enrollments[ref]
        assert entry.files is not None and entry.files.client is entry.execution
        assert entry.files.attestation.reference == ref
        assert entry.files.attestation.native_policy_sha256 == policy.fingerprint_sha256
        assert entry.files.require(ref) is entry.files.attestation
        assert f.registry.files[ref] is entry.files and REF not in f.registry.files
        assert anchor.files is None and entry.catalog is None
        assert not writes and all(c.method == "GET" for c in calls)
    finally:
        await finish(p, t)


async def test_a_root_whose_rules_differ_from_the_source_reads_nothing():
    # The source session denies everything; a Root without that rule would allow more.
    p, t, _d, f, intent, candidate, *_ = await setup(reads=source_reads)
    try:
        entry = await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        assert entry.files is None and entry.reference not in f.registry.files
    finally:
        await finish(p, t)


async def test_only_the_source_roots_own_reader_can_be_reused():
    p, t, _d, f, *_ = await setup(permissions=DENY_ALL, reads=source_reads)
    try:
        foreign = replace(
            f._files.attestation, reference=REF.model_copy(update={"project_id": "x"})
        )
        for files in (
            V2NativeFileReader(f.anchor.execution, attestation=foreign),
            V2NativeFileReader(f.anchor.execution, attestation=None),
        ):
            with pytest.raises(ValueError, match="source_roots"):
                V2CreatedRootFactory(f.creator, f.policies, f.registry, files=files)
    finally:
        await finish(p, t)


async def test_a_restored_root_gets_the_same_reader_sealed_in_its_assembly(db):
    graph, stage, candidate, _context, _journal = await staged_graph(
        db, permissions=DENY_ALL, reads=source_reads
    )
    p, t, _d, f, *_ = graph
    try:
        staged = stage.entry
        assert staged.files is not None and staged.files.client is staged.execution
        assert staged.files in f._restore_assembly(staged)
        entry = f.publish_restore(stage, candidate)
        assert entry is staged and f.registry.files[entry.reference] is entry.files
    finally:
        await finish(p, t)
