"""Tree identity outlives runtime manifest edits; synthetic peers, no Native/Human run.

An older release digested the whole runtime manifest into every adoption
qualification, so any manifest edit after a tree baseline stopped startup with
original_graph_update_historical_scope_changed. These tests use real adapters,
the real composed pipeline and an encrypted own DB only.
"""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from jt_oz_bridge.domain.session_adoption import (
    LEGACY_RECORD_FORMAT,
    RECORD_FORMAT,
    SessionAdoptionRecord,
)
from jt_oz_bridge.services import runtime_enrollment as module
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.existing_session_factory import V2ExistingSessionFactory
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.services.session_registration_journal import (
    SessionRegistrationJournal,
    registration_identity,
)
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.session_registration_models import (
    REGISTRATION_SEAL_FIELDS,
    SessionRegistration,
    registration_history_seal,
)
from tests.contract.test_existing_session_factory import setup as factory_setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import TARGET
from tests.contract.test_public_live_feed import REF
from tests.integration.test_existing_session_updates import commit, environment, grow, recover
from tests.integration.test_router import Source
from tests.integration.test_runtime_enrollment import configured_anchor_startup_peer
from tests.integration.test_runtime_enrollment import enrolled as enrolled
from tests.integration.test_session_adoption import setup as adoption_setup
from tests.integration.test_session_registration_extension import (
    graph,
    initialize,
    raw_state,
)
from tests.integration.test_session_registration_extension import grow as grown_record
from tests.support import SyntheticAudience


def old_rule(factory):
    """The older release's qualification: these pins plus the whole manifest digest."""
    return digest(factory._qualification())


def another_manifest(factory, value="f" * 64):
    # A rebuilt pipeline gives every reader of the backend one new attestation.
    object.__setattr__(factory._semantics, "installed_evidence_sha256", value)


async def write_legacy_head(db, qualification):
    """Trusted fixture writer for the row shape that older release left in the field."""
    async with db.sessions.begin() as session:
        for row in (await session.scalars(select(SessionRegistration))).all():
            record = SessionAdoptionRecord.model_validate(row.payload)
            legacy = SessionAdoptionRecord.model_validate(
                record.model_dump(mode="python")
                | {"format": LEGACY_RECORD_FORMAT, "qualification_sha256": qualification}
            )
            row.payload = legacy.model_dump(mode="json")
            row.payload_hash = digest(row.payload)
            row.identity_hash = registration_identity(legacy)
            row.history_seal = registration_history_seal(
                {field: getattr(row, field) for field in REGISTRATION_SEAL_FIELDS}
            )


async def heads(pipeline, root):
    return await pipeline.adoption.journal.recovery_records(
        "2",
        root.project_id,
        lock_authority=pipeline.graph_authority(root.project_id)[1],
        current=lambda: True,
    )


def edited_manifest(enrolled):
    """The same pins in other bytes: the smallest edit that changes the manifest digest."""
    path = Path(enrolled.settings.runtime.enrollment_file)
    enrolled.documents[path] = json.dumps(enrolled.manifest, indent=2).encode()
    return module.read_enrollment(enrolled.settings)


def rebuilt(enrolled, db, graph, value, sha):
    return module.build_pipeline(
        enrolled.settings, value, sha, db, module.ConsumerFence(graph.holder, graph.epoch)
    )


async def baseline(enrolled, db, monkeypatch):
    peer = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    first = peer.build()
    await peer.start(first)
    factory = first.adoption.factory(peer.root)
    pins = factory.qualification_sha256(), old_rule(factory)
    (head,) = await heads(first, peer.root)
    await peer.close(first)
    return peer, head, pins


async def test_manifest_edit_after_a_tree_baseline_still_restores_the_configured_root(
    enrolled, db, monkeypatch
):
    peer, head, (identity, legacy) = await baseline(enrolled, db, monkeypatch)
    second = None
    try:
        assert head.record.format == RECORD_FORMAT and head.record.qualification_sha256 == identity
        second = rebuilt(enrolled, db, peer, *edited_manifest(enrolled))
        names = await peer.start(second)
        assert names.index("original-session-restoration") < names.index("zulip-consumer")
        factory = second.adoption.factory(peer.root)
        # The old rule would have refused this very head at startup.
        assert old_rule(factory) != legacy
        assert factory.qualification_sha256() == identity
        (after,) = await heads(second, peer.root)
        assert after.state == "active" and after.receipt.identity_hash == head.receipt.identity_hash
        assert not peer.writes and all(r.method == "GET" for r in peer.state["calls"])
    finally:
        if second is not None:
            await peer.close(second)
        await peer.store.release_lease(peer.holder, peer.epoch)


async def test_legacy_single_root_head_is_resealed_once_after_the_manifest_changed(
    enrolled, db, monkeypatch
):
    peer, head, (identity, legacy) = await baseline(enrolled, db, monkeypatch)
    await write_legacy_head(db, legacy)
    calls = []
    requalify = SessionRegistrationJournal.requalify

    async def counted(self, *args, **kwargs):
        calls.append(args[0].receipt.revision)
        return await requalify(self, *args, **kwargs)

    monkeypatch.setattr(SessionRegistrationJournal, "requalify", counted)
    value, sha = edited_manifest(enrolled)
    second = third = None
    try:
        second = rebuilt(enrolled, db, peer, value, sha)
        await peer.start(second)
        factory = second.adoption.factory(peer.root)
        assert old_rule(factory) != legacy  # The exact v1 digest no longer matches.
        (resealed,) = await heads(second, peer.root)
        assert calls == [head.receipt.revision]
        assert resealed.state == "active" and resealed.extension_count == 0
        assert resealed.record.format == RECORD_FORMAT
        assert resealed.record.qualification_sha256 == identity
        assert resealed.receipt.identity_hash == head.receipt.identity_hash
        assert resealed.receipt.revision > head.receipt.revision
        assert resealed.record.nodes == head.record.nodes
        generation = factory.registry.publication.generation(peer.root)
        assert generation.record is not None and generation.receipt.revision >= 1
        await peer.close(second)
        second = None
        third = rebuilt(enrolled, db, peer, value, sha)
        await peer.start(third)
        (again,) = await heads(third, peer.root)
        assert calls == [head.receipt.revision]
        assert again.state == "active" and again.receipt.identity_hash == head.receipt.identity_hash
        assert not peer.writes and all(r.method == "GET" for r in peer.state["calls"])
    finally:
        for pipeline in (second, third):
            if pipeline is not None:
                await peer.close(pipeline)
        await peer.store.release_lease(peer.holder, peer.epoch)


async def test_legacy_single_root_head_whose_root_grew_a_child_still_stops_startup(
    enrolled, db, monkeypatch
):
    peer, _, (_, legacy) = await baseline(enrolled, db, monkeypatch)
    await write_legacy_head(db, legacy)
    before = await raw_state(db)
    peer.state["child"] = True
    second = rebuilt(enrolled, db, peer, *edited_manifest(enrolled))
    seen = []

    async def before_start(name, pipeline):
        seen.append(name)

    try:
        with pytest.raises(Conflict, match="legacy_identity_changed"):
            await peer.start(second, before=before_start)
        assert "zulip-consumer" not in seen
        generation = second.adoption.factory(peer.root).registry.publication.generation(peer.root)
        assert generation.record is None and set(generation.entries) == {peer.root}
        assert await raw_state(db) == before and not peer.writes
    finally:
        await peer.close(second)
        await peer.store.release_lease(peer.holder, peer.epoch)


@pytest.mark.parametrize("child", [False, True])
async def test_genuinely_changed_lineage_pin_reseals_only_a_childless_root(
    enrolled, db, monkeypatch, child
):
    """A re-certified project (a new lineage observation) keeps a Root without
    subagents; a Root that grew one since its baseline still stops startup."""
    peer, head, (identity, _) = await baseline(enrolled, db, monkeypatch)
    before = await raw_state(db)
    if child:
        peer.state["child"] = True
    entry = enrolled.manifest["adoption_projects"][0]
    envelope = json.loads(enrolled.documents[Path(entry["lineage"]["path"])])
    observed = json.loads(enrolled.documents[Path(envelope["observation"]["path"])])
    observed["requests"][0]["response_sha256"] = "e" * 64
    envelope["observation"] = enrolled.pin("lineage-observation-reviewed.json", observed)
    entry["lineage"] = enrolled.pin("lineage-pin-reviewed.json", envelope)
    enrolled.save()
    second = rebuilt(enrolled, db, peer, *module.read_enrollment(enrolled.settings))
    try:
        if child:
            with pytest.raises(Conflict):
                await peer.start(second)
            assert await raw_state(db) == before and not peer.writes
            return
        await peer.start(second)
        factory = second.adoption.factory(peer.root)
        assert factory.qualification_sha256() != identity
        (resealed,) = await heads(second, peer.root)
        assert resealed.state == "active" and resealed.extension_count == 0
        assert resealed.record.qualification_sha256 == factory.qualification_sha256()
        assert resealed.receipt.key == head.receipt.key
        assert resealed.record.graph_sha256 == head.record.graph_sha256
        assert resealed.receipt.revision > head.receipt.revision
        assert resealed.record.nodes == head.record.nodes
        assert not peer.writes and all(r.method == "GET" for r in peer.state["calls"])
    finally:
        await peer.close(second)
        await peer.store.release_lease(peer.holder, peer.epoch)


async def test_extended_tree_keeps_growing_across_another_manifest_digest(db):
    env = await environment(db)
    try:
        grow(env)
        await commit(
            env,
            await env["updates"].prepare(TARGET, await recover(env), authorize=env["authority"]),
        )
        extended = await recover(env)
        assert extended.extension_count == 1
        identity = env["factory"].qualification_sha256()
        another_manifest(env["factory"])
        assert env["factory"].qualification_sha256() == identity
        grow(env, grandchild=True)
        candidate = await env["updates"].prepare(TARGET, extended, authorize=env["authority"])
        await commit(env, candidate)
        head = await recover(env)
        assert head.state == "active" and head.extension_count == 2
        assert len(head.record.nodes) == 3 and not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize("change", ["lineage", "policy"])
@pytest.mark.parametrize("shape", ["root", "tree"])
async def test_changed_policy_or_lineage_still_refuses_the_saved_graph(db, change, shape):
    env = await environment(db)
    try:
        if shape == "tree":
            grow(env)
            await commit(
                env,
                await env["updates"].prepare(
                    TARGET, await recover(env), authorize=env["authority"]
                ),
            )
        previous = await recover(env)
        if change == "lineage":
            object.__setattr__(env["factory"].lineage, "installed_evidence_sha256", "f" * 64)
        else:
            object.__setattr__(env["factory"].policy, "operations", frozenset({"prompt"}))
        assert env["factory"].qualification_sha256() != previous.record.qualification_sha256
        before = await raw_state(db)
        if shape == "root":
            # A childless root re-proves the identical live graph under the new pins.
            candidate = await env["updates"].prepare(TARGET, previous, authorize=env["authority"])
            assert candidate.record.qualification_sha256 == env["factory"].qualification_sha256()
            assert candidate.record.graph_sha256 == previous.record.graph_sha256
        else:
            with pytest.raises(Conflict, match="historical_scope_changed"):
                await env["updates"].prepare(TARGET, previous, authorize=env["authority"])
        assert await raw_state(db) == before and not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


def restarted(factory, original, **changes):
    policy = changes.get("policy", factory.policy)
    lineage = changes.get("lineage", factory.lineage)
    return V2ExistingSessionFactory(
        factory.observer, SessionRegistry({REF: original}), policy, lineage=lineage
    )


@pytest.mark.parametrize("legacy", [False, True])
async def test_adopted_tree_record_restores_under_another_manifest_digest(legacy):
    anchor, t, f, tree, state, writes, original = await factory_setup()
    try:
        first = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        await f.commit(first, authorize=AsyncMock(return_value=True))
        historical = first.record
        if legacy:
            # An unextended v1 tree is admitted only by its exact v1 digest.
            historical = SessionAdoptionRecord.model_validate(
                historical.model_dump(mode="python")
                | {"format": LEGACY_RECORD_FORMAT, "qualification_sha256": old_rule(f)}
            )
            ready = await restarted(f, original).prepare_record(
                historical, authorize=AsyncMock(return_value=True)
            )
            assert ready.record.format == RECORD_FORMAT
            assert ready.record.graph_sha256 == historical.graph_sha256
        another_manifest(f)
        factory = restarted(f, original)
        if legacy:
            with pytest.raises(Conflict, match="historical_qualification_changed"):
                await factory.prepare_record(historical, authorize=AsyncMock(return_value=True))
        else:
            ready = await factory.prepare_record(historical, authorize=AsyncMock(return_value=True))
            assert ready.record.qualification_sha256 == historical.qualification_sha256
        assert not writes and all(r.method == "GET" for r in state["resource_calls"])
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("change", ["lineage", "policy"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_adopted_tree_record_with_changed_pins_is_not_restored(change, legacy):
    anchor, t, f, tree, state, writes, original = await factory_setup()
    try:
        first = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        historical = first.record
        if legacy:
            historical = SessionAdoptionRecord.model_validate(
                historical.model_dump(mode="python")
                | {"format": LEGACY_RECORD_FORMAT, "qualification_sha256": old_rule(f)}
            )
        if change == "lineage":
            factory = restarted(
                f, original, lineage=replace(f.lineage, installed_evidence_sha256="f" * 64)
            )
        else:
            factory = restarted(
                f,
                original,
                policy=f.policy.model_copy(update={"operations": frozenset({"prompt"})}),
            )
        with pytest.raises(Conflict, match="historical_qualification_changed"):
            await factory.prepare_record(historical, authorize=AsyncMock(return_value=True))
        assert tuple(factory.registry.sessions) == (REF,) and not writes
    finally:
        await finish(anchor, t)


async def test_adopted_legacy_root_is_resealed_by_fresh_startup_recovery(db):
    controller, item, _, _, factory, _, writes, anchor, t = await adoption_setup(db, leaf=True)
    fresh_anchor = fresh_t = None
    try:
        await controller.adopt(item, TARGET)
        (head,) = await controller.journal.recovery_records(
            "realm", TARGET.project_id, lock_authority=AsyncMock(), current=lambda: True
        )
        await write_legacy_head(db, old_rule(factory))
        fresh_anchor, fresh_t, fresh_factory, _, fresh_state, fresh_writes, _ = await factory_setup(
            leaf=True
        )
        another_manifest(fresh_factory)
        fresh = SessionAdoptionService(
            BindingService(db, fresh_factory.registry, SyntheticAudience()),
            Source(),
            controller.journal.fence,
            {TARGET.project_id: fresh_factory},
        )
        assert await fresh.recover_project(
            "realm",
            TARGET.project_id,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        ) == (TARGET,)
        (after,) = await fresh.journal.recovery_records(
            "realm", TARGET.project_id, lock_authority=AsyncMock(), current=lambda: True
        )
        assert after.state == "active" and after.record.format == RECORD_FORMAT
        assert after.receipt.identity_hash == head.receipt.identity_hash
        assert after.receipt.revision == head.receipt.revision + 1
        assert TARGET in fresh_factory.registry.sessions
        assert not writes and not fresh_writes
        assert all(r.method == "GET" for r in fresh_state["resource_calls"])
    finally:
        if fresh_anchor is not None:
            await finish(fresh_anchor, fresh_t)
        await finish(anchor, t)


def legacy(value, qualification="9" * 64):
    return SessionAdoptionRecord.model_validate(
        value.model_dump(mode="python")
        | {"format": LEGACY_RECORD_FORMAT, "qualification_sha256": qualification}
    )


def resealed(value, qualification="8" * 64):
    return SessionAdoptionRecord.model_validate(
        value.model_dump(mode="python")
        | {"format": RECORD_FORMAT, "qualification_sha256": qualification}
    )


async def test_requalification_rewrites_only_an_unextended_head(db):
    journal, authority, saved = await initialize(db, legacy(graph()))
    current = resealed(saved.record)
    for refused in (
        resealed(saved.record, saved.record.qualification_sha256),
        legacy(saved.record, "8" * 64),
        resealed(grown_record(saved.record)),
    ):
        with pytest.raises(Conflict, match="requalification_identity_changed"):
            await journal.requalify(saved, refused, lock_authority=authority, current=lambda: True)
    before = await raw_state(db)
    with pytest.raises(Conflict, match="requalification_predecessor_changed"):
        await journal.requalify(
            replace(saved, state="prepared"),
            current,
            lock_authority=authority,
            current=lambda: True,
        )
    assert await raw_state(db) == before
    receipt = await journal.requalify(
        saved, current, lock_authority=authority, current=lambda: True
    )
    (head,) = await journal.recovery_records(
        "realm", saved.record.root.project_id, lock_authority=authority, current=lambda: True
    )
    assert head.state == "prepared" and head.receipt == receipt
    assert receipt.revision == saved.receipt.revision + 1 and head.record == current
    await journal.activate(receipt, lock_authority=authority, current=lambda: True)
    (head,) = await journal.recovery_records(
        "realm", saved.record.root.project_id, lock_authority=authority, current=lambda: True
    )
    with pytest.raises(Conflict, match="requalification_identity_changed"):
        await journal.requalify(
            head, legacy(head.record), lock_authority=authority, current=lambda: True
        )
    # A current childless head may be re-pinned again, as a fresh baseline would be.
    again = await journal.requalify(
        head, resealed(saved.record, "7" * 64), lock_authority=authority, current=lambda: True
    )
    assert again.revision == head.receipt.revision + 1


async def test_requalification_never_rewrites_a_current_tree_head(db):
    journal, authority, saved = await initialize(db, resealed(grown_record(graph())))
    assert len(saved.record.nodes) > 1 and saved.extension_count == 0
    before = await raw_state(db)
    with pytest.raises(Conflict, match="requalification_identity_changed"):
        await journal.requalify(
            saved, resealed(saved.record, "7" * 64), lock_authority=authority, current=lambda: True
        )
    assert await raw_state(db) == before


async def test_requalification_never_rewrites_an_extended_history(db):
    journal, authority, saved = await initialize(db, legacy(graph()))
    extended = await journal.extend(
        saved,
        legacy(grown_record(saved.record)),
        lock_authority=authority,
        current=lambda: True,
    )
    (head,) = await journal.recovery_records(
        "realm", saved.record.root.project_id, lock_authority=authority, current=lambda: True
    )
    assert head.receipt == extended and head.extension_count == 1
    before = await raw_state(db)
    with pytest.raises(Conflict, match="requalification_identity_changed"):
        await journal.requalify(
            head, resealed(head.record), lock_authority=authority, current=lambda: True
        )
    assert await raw_state(db) == before
