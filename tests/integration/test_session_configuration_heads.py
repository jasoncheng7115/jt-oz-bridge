"""Isolated persistence evidence only; no Native, Source or Human qualification."""

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import delete, func, inspect, select, text, update

from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, WorkerLease
from jt_oz_bridge.storage.schema import Base
from jt_oz_bridge.storage.session_configuration_heads import (
    AgentSettingEvidence,
    AgentSwitchIntent,
    ConfigurationCommitExpectation,
    ConfigurationNode,
    ConfigurationOrigin,
    EffectiveConfiguration,
    GuardedAgent,
    InitializationProof,
    KnownUnsentEvidence,
    SessionConfigurationHeads,
    configuration_root_key,
)
from jt_oz_bridge.storage.session_configuration_models import SessionConfigurationHead
from tests.support import REF


async def authority(_session):
    """Only a synthetic fixture callback; never a live grant or Source."""


def effective(agent="build"):
    nodes = (
        ConfigurationNode(
            node_key="1" * 64, policy_sha256="2" * 64, reader_qualification_sha256="3" * 64
        ),
    )
    return EffectiveConfiguration(
        agent_id=agent,
        configured_model_sha256="4" * 64,
        context_qualification_sha256=("5" if agent == "build" else "6") * 64,
        node_scope_sha256=digest({"nodes": [n.model_dump(mode="json") for n in nodes]}),
        nodes=nodes,
        guarded_agents=(
            GuardedAgent(
                agent_id="build", definition_sha256="7" * 64, policy_inputs_sha256="8" * 64
            ),
            GuardedAgent(
                agent_id="plan", definition_sha256="9" * 64, policy_inputs_sha256="a" * 64
            ),
        ),
    )


def origin(reference=REF):
    return ConfigurationOrigin(
        root=reference,
        native_created_at=123,
        original_registration_identity_sha256="b" * 64,
        original_registration_payload_sha256="c" * 64,
        qualification_sha256="d" * 64,
    )


async def setup(db):
    holder = "synthetic-configuration-consumer"
    epoch = await DurableStore(db).acquire_lease(holder, ttl=120)
    assert epoch is not None
    return SessionConfigurationHeads(db, ConsumerFence(holder, epoch), enabled=True)


async def initialize(store, value=None, configuration=None):
    value = value or origin()
    configuration = configuration or effective()
    proof = InitializationProof(
        kind="qualified_original_root",
        origin_sha256=digest(value.model_dump(mode="json")),
        effective_sha256=digest(configuration.model_dump(mode="json")),
        qualification_sha256=value.qualification_sha256,
        observed_at=time.time(),
    )
    return await store.initialize(
        value, configuration, proof, lock_authority=authority, current=lambda: True
    )


async def action(db, saved, *, realm="realm-a", binding=None, agent="plan"):
    identity = str(uuid.uuid4())
    payload = AgentSwitchIntent(
        action_id=identity,
        realm_id=realm,
        binding_id=binding or str(uuid.uuid4()),
        binding_revision=1,
        actor_id=7,
        queued_action_version=1,
        reference=saved.origin.root,
        root_key=saved.token.root_key,
        origin_sha256=digest(saved.origin.model_dump(mode="json")),
        expected_revision=saved.token.revision,
        before_configuration_sha256=saved.token.effective_sha256,
        after=effective(agent),
        source_sha256="e" * 64,
        preview_sha256="f" * 64,
        confirmation_sha256="f" * 64,
        transition_certificate_sha256="d" * 64,
        affected_scope_sha256="0" * 64,
        owner_epoch_sha256="1" * 64,
    ).model_dump(mode="json")
    async with db.sessions.begin() as session:
        session.add(
            Action(
                id=identity,
                dedupe_key=identity,
                binding_id=payload["binding_id"],
                binding_revision=1,
                actor_id=7,
                operation="agent.switch",
                operation_digest=digest(payload),
                payload=payload,
                state="queued",
                version=1,
                owner="bridge",
                admission={},
                native_result={},
            )
        )
    return identity, payload


async def reserve(store, saved, identity):
    return await store.reserve(
        saved.token, identity, 1, lock_authority=authority, current=lambda: True
    )


async def settle(store, saved, outcome, **kwargs):
    checksum = "a" * 64
    if outcome == "not_sent" and saved.pending is not None:
        proof = KnownUnsentEvidence(
            kind="native_request_not_opened",
            action_id=saved.token.active_action_id,
            intent_sha256=digest(saved.pending.model_dump(mode="json")),
            reserved_revision=saved.token.revision,
            proof_sha256="1" * 64,
        )
        kwargs.setdefault("not_sent_evidence", proof)
        checksum = digest(proof.model_dump(mode="json"))
    if outcome == "activated":
        kwargs.setdefault("staged_context_observed_at", time.time())
    return await store.settle(
        saved.token, outcome, checksum, lock_authority=authority, current=lambda: True, **kwargs
    )


async def prepare(store, saved, payload):
    evidence = AgentSettingEvidence(
        native_ack_sha256="2" * 64,
        readback_sha256="3" * 64,
        after_configuration_sha256=digest(payload["after"]),
        supported_context_sha256=payload["after"]["context_qualification_sha256"],
        observed_at=time.time(),
    )
    receipt = ExecutionReceipt(
        action_id=payload["action_id"],
        operation_digest=digest(payload),
        reference=saved.origin.root,
        contract_sha256="4" * 64,
        admission=Admission(
            status="admitted",
            owner="opencode",
            details={
                "operation": "agent.switch",
                "agent_setting": evidence.model_dump(mode="json"),
            },
        ),
    )
    return await store.settle(
        saved.token,
        "prepared",
        digest(evidence.model_dump(mode="json")),
        receipt=receipt,
        evidence=evidence,
        lock_authority=authority,
        current=lambda: True,
    )


async def inspect_head(store, key):
    return await store.inspect_locked(key, lock_authority=authority, current=lambda: True)


async def test_explicit_enrollment_encrypted_and_default_feature_disabled(db):
    enabled = await setup(db)
    disabled = SessionConfigurationHeads(db, enabled.fence)
    with pytest.raises(Conflict, match="feature_disabled"):
        await initialize(disabled)
    saved = await initialize(enabled)
    assert saved.token.revision == 1 and saved.token.phase == "stable"
    assert saved.token.root_key == configuration_root_key(saved.origin)
    async with db.engine.connect() as connection:
        blob = await connection.scalar(text("SELECT payload FROM session_configuration_heads"))
        assert isinstance(blob, bytes) and b"session-effective" not in blob
        assert await connection.scalar(text("SELECT COUNT(*) FROM actions")) == 0
        assert await connection.scalar(text("SELECT COUNT(*) FROM input_events")) == 0
    with pytest.raises(Conflict, match="already_enrolled"):
        await initialize(enabled, origin().model_copy(update={"native_created_at": 456}))


async def test_single_attempt_atomic_prepared_then_configured_not_inflight_ready(db):
    store = await setup(db)
    initial = await initialize(store)
    identity, payload = await action(db, initial)
    reserved = await reserve(store, initial, identity)
    assert reserved.token.revision == 2 and reserved.token.phase == "dispatching"
    assert reserved.effective == initial.effective and reserved.pending.after.agent_id == "plan"
    with pytest.raises(Conflict):
        await reserve(store, initial, identity)
    prepared = await prepare(store, reserved, payload)
    assert prepared.token.revision == 3 and prepared.token.phase == "activation_prepared"
    assert prepared.effective == initial.effective
    ready = await settle(
        store,
        prepared,
        "activated",
        staged_context_sha256=effective("plan").context_qualification_sha256,
    )
    assert ready.token.revision == 4 and ready.token.phase == "stable"
    assert ready.origin == initial.origin and ready.effective.agent_id == "plan"
    assert (
        ready.token.active_action_id is None and ready.token.last_activation_action_id == identity
    )
    assert await inspect_head(store, ready.token.root_key) == ready
    async with db.sessions() as session:
        native = await session.get(Action, identity)
        assert native.state == "completed"
        assert native.native_result["format"] == "session-agent-activation-result-v1"
        assert native.native_result["phase"] == "activated"
    # No registry readiness value or observed provider-attempt identity is fabricated.
    assert not hasattr(ready, "mutation_ready") and not hasattr(ready, "observed_attempt")


async def test_cross_realm_same_Root_barrier_and_stale_work_never_retagged(db):
    store = await setup(db)
    saved = await initialize(store)
    one, _ = await action(db, saved, realm="one")
    two, before = await action(db, saved, realm="two")
    reserved = await reserve(store, saved, one)
    with pytest.raises(Conflict):
        await reserve(store, reserved, two)
    rejected = await settle(store, reserved, "not_sent")
    assert rejected.token.revision == 3 and rejected.effective == saved.effective
    assert rejected.token.active_action_id is None
    with pytest.raises(Conflict):
        await reserve(store, rejected, two)
    async with db.sessions() as session:
        unchanged = await session.get(Action, two)
        assert (
            unchanged.payload == before and unchanged.version == 1 and unchanged.state == "queued"
        )


async def test_quarantined_attempt_cannot_resume_or_become_not_sent(db):
    store = await setup(db)
    initial = await initialize(store)
    identity, _ = await action(db, initial)
    reserved = await reserve(store, initial, identity)
    held = await settle(store, reserved, "quarantined")
    assert held.token.phase == "quarantined" and held.token.active_action_id == identity
    for outcome in ("not_sent", "prepared", "activated"):
        with pytest.raises(Conflict):
            await settle(store, held, outcome)
    assert await inspect_head(store, held.token.root_key) == held


@pytest.mark.parametrize(
    "column,value",
    [
        ("phase", "external_unqualified"),
        ("revision", 22),
        ("payload_hash", "0" * 64),
        ("root_reference_hash", "1" * 64),
        ("last_activation_action_id", "action-placeholder"),
    ],
)
async def test_plain_head_projection_tamper_never_unlocks(db, column, value):
    store = await setup(db)
    saved = await initialize(store)
    if column.endswith("action_id"):
        value, _ = await action(db, saved)
    async with db.sessions.begin() as session:
        await session.execute(update(SessionConfigurationHead).values(**{column: value}))
    with pytest.raises(Conflict, match="head_invalid"):
        await inspect_head(store, saved.token.root_key)


async def test_ciphertext_row_swap_refused(db):
    store = await setup(db)
    one = await initialize(store)
    other_ref = REF.model_copy(update={"upstream_session_id": "different-original-root"})
    two = await initialize(store, origin(other_ref))
    async with db.engine.begin() as connection:
        rows = (
            await connection.execute(
                text("SELECT root_key,payload FROM session_configuration_heads")
            )
        ).all()
        by_key = dict(rows)
        await connection.execute(
            text("UPDATE session_configuration_heads SET payload=:payload WHERE root_key=:key"),
            {"payload": by_key[two.token.root_key], "key": one.token.root_key},
        )
    with pytest.raises(Conflict, match="head_invalid"):
        await inspect_head(store, one.token.root_key)


@pytest.mark.parametrize(
    "column,value",
    [
        ("state", "queued"),
        ("version", 99),
        ("binding_revision", 9),
        ("actor_id", 99),
        ("owner", "opencode"),
    ],
)
async def test_active_action_plaintext_tamper_keeps_barrier(db, column, value):
    store = await setup(db)
    saved = await initialize(store)
    identity, _ = await action(db, saved)
    reserved = await reserve(store, saved, identity)
    async with db.sessions.begin() as session:
        await session.execute(update(Action).where(Action.id == identity).values(**{column: value}))
    with pytest.raises(Conflict):
        await inspect_head(store, reserved.token.root_key)
    async with db.engine.connect() as connection:
        assert (
            await connection.scalar(text("SELECT phase FROM session_configuration_heads"))
            == "dispatching"
        )


async def test_plain_active_FK_swap_to_other_Action_is_invalid(db):
    store = await setup(db)
    saved = await initialize(store)
    one, _ = await action(db, saved)
    two, _ = await action(db, saved)
    reserved = await reserve(store, saved, one)
    async with db.sessions.begin() as session:
        await session.execute(update(SessionConfigurationHead).values(active_action_id=two))
    with pytest.raises(Conflict):
        await inspect_head(store, reserved.token.root_key)


async def test_consumer_fence_lost_and_current_proof_false_prevent_updates(db):
    store = await setup(db)
    saved = await initialize(store)
    identity, _ = await action(db, saved)
    with pytest.raises(Conflict, match="authority_changed"):
        await store.reserve(
            saved.token, identity, 1, lock_authority=authority, current=lambda: False
        )
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(fencing=store.fence.fencing + 1))
    with pytest.raises(Conflict, match="consumer_lease"):
        await reserve(store, saved, identity)
    async with db.sessions() as session:
        row = await session.get(Action, identity)
        assert row.state == "queued" and row.version == 1


async def test_active_and_last_activation_FKs_protect_original_Actions(db):
    from sqlalchemy.exc import IntegrityError

    store = await setup(db)
    saved = await initialize(store)
    identity, payload = await action(db, saved)
    reserved = await reserve(store, saved, identity)
    with pytest.raises(IntegrityError):
        async with db.sessions.begin() as session:
            await session.execute(delete(Action).where(Action.id == identity))
    prepared = await prepare(store, reserved, payload)
    ready = await settle(
        store,
        prepared,
        "activated",
        staged_context_sha256=effective("plan").context_qualification_sha256,
    )
    with pytest.raises(IntegrityError):
        async with db.sessions.begin() as session:
            await session.execute(delete(Action).where(Action.id == identity))
    assert await inspect_head(store, ready.token.root_key) == ready


async def test_head_has_bounded_current_nodes_and_bytes_not_history(db):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        effective().model_validate(effective().model_dump() | {"nodes": effective().nodes * 1001})
    with pytest.raises(ValidationError):
        effective().model_validate(effective().model_dump() | {"history": []})


async def test_wrong_key_never_changes_or_unlocks_head(db):
    from jt_oz_bridge.security.cipher import EnvelopeCipher

    store = await setup(db)
    saved = await initialize(store)
    identity, _ = await action(db, saved)
    await reserve(store, saved, identity)
    wrong = Database(str(db.engine.url), cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"))
    try:
        denied = SessionConfigurationHeads(wrong, store.fence, enabled=True)
        with pytest.raises(Conflict, match="database_not_ready"):
            await inspect_head(denied, saved.token.root_key)
    finally:
        await wrong.close()
    async with db.engine.connect() as connection:
        assert (
            await connection.scalar(text("SELECT phase FROM session_configuration_heads"))
            == "dispatching"
        )


async def test_unknown_after_commit_resolves_by_locked_intent_without_replay(db):
    store = await setup(db)
    saved = await initialize(store)
    identity, payload = await action(db, saved)
    original = db.sessions

    class LostCommit:
        @asynccontextmanager
        async def begin(self):
            async with original.begin() as session:
                yield session
            raise ConnectionError("synthetic_response_lost_after_real_commit")

    db.sessions = LostCommit()
    try:
        with pytest.raises(ConnectionError):
            await reserve(store, saved, identity)
    finally:
        db.sessions = original
    expected = ConfigurationCommitExpectation(
        root_key=saved.token.root_key,
        revision=2,
        phase="dispatching",
        effective_sha256=saved.token.effective_sha256,
        active_action_id=identity,
        last_activation_action_id=None,
        transition_action_id=identity,
        transition_intent_sha256=digest(payload),
    )
    resolved = await store.reconcile_attempt(
        saved.token, expected, lock_authority=authority, current=lambda: True
    )
    assert resolved.status == "exact_committed" and resolved.native_send_authorized is False
    assert resolved.snapshot.token.phase == "dispatching"
    with pytest.raises(Conflict):
        await reserve(store, saved, identity)


async def test_still_pending_writer_blocks_locked_reconciliation_until_real_rollback(db):
    store = await setup(db)
    saved = await initialize(store)
    identity, payload = await action(db, saved)
    entered, release = asyncio.Event(), asyncio.Event()

    async def writer():
        async with db.sessions.begin() as session:
            await store.fence.lock(session)
            entered.set()
            await release.wait()
            raise RuntimeError("synthetic_real_rollback")

    writer_task = asyncio.create_task(writer())
    await entered.wait()
    expected = ConfigurationCommitExpectation(
        root_key=saved.token.root_key,
        revision=2,
        phase="dispatching",
        effective_sha256=saved.token.effective_sha256,
        active_action_id=identity,
        last_activation_action_id=None,
        transition_action_id=identity,
        transition_intent_sha256=digest(payload),
    )
    read_task = asyncio.create_task(
        store.reconcile_attempt(
            saved.token, expected, lock_authority=authority, current=lambda: True
        )
    )
    try:
        await asyncio.sleep(0.04)
        assert not read_task.done()
    finally:
        release.set()
        with pytest.raises(RuntimeError, match="real_rollback"):
            await writer_task
    resolved = await read_task
    assert resolved.status == "predecessor_locked" and resolved.native_send_authorized is False


async def test_new_schema_metadata_create_all_and_current_revision(db, tmp_path):
    assert CURRENT_REVISION == "0038_prompt_schedules"
    async with db.engine.connect() as connection:
        names = await connection.run_sync(lambda c: set(inspect(c).get_table_names()))
        assert names == set(Base.metadata.tables) | {"alembic_version"}
        assert (
            await connection.scalar(select(func.count()).select_from(SessionConfigurationHead)) == 0
        )
    # An independent empty metadata database uses genuine FKs/EncryptedJSON.
    empty = Database("sqlite+aiosqlite:///" + str(tmp_path / "metadata-only.db"))
    try:
        async with empty.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            foreign = await connection.run_sync(
                lambda c: inspect(c).get_foreign_keys("session_configuration_heads")
            )
            assert len(foreign) == 2 and {r["referred_table"] for r in foreign} == {"actions"}
    finally:
        await empty.close()


@pytest.mark.parametrize("operation", ["initialize", "prepared", "activated"])
async def test_original_five_second_proof_expires_during_real_locked_authority_wait(db, operation):
    store = await setup(db)
    entered = False

    async def slow_authority(_session):
        nonlocal entered
        entered = True
        await asyncio.sleep(5.02)

    if operation == "initialize":
        value, config = origin(), effective()
        proof = InitializationProof(
            kind="qualified_original_root",
            origin_sha256=digest(value.model_dump(mode="json")),
            effective_sha256=digest(config.model_dump(mode="json")),
            qualification_sha256=value.qualification_sha256,
            observed_at=time.time(),
        )
        with pytest.raises(Conflict, match="qualification_expired"):
            await store.initialize(
                value, config, proof, lock_authority=slow_authority, current=lambda: True
            )
        async with db.sessions() as session:
            assert (
                await session.scalar(select(func.count()).select_from(SessionConfigurationHead))
                == 0
            )
    else:
        initial = await initialize(store)
        identity, payload = await action(db, initial)
        reserved = await reserve(store, initial, identity)
        if operation == "prepared":
            evidence = AgentSettingEvidence(
                native_ack_sha256="2" * 64,
                readback_sha256="3" * 64,
                after_configuration_sha256=digest(payload["after"]),
                supported_context_sha256=effective("plan").context_qualification_sha256,
                observed_at=time.time(),
            )
            receipt = ExecutionReceipt(
                action_id=identity,
                operation_digest=digest(payload),
                reference=initial.origin.root,
                contract_sha256="4" * 64,
                admission=Admission(
                    status="admitted",
                    owner="opencode",
                    details={
                        "operation": "agent.switch",
                        "agent_setting": evidence.model_dump(mode="json"),
                    },
                ),
            )
            with pytest.raises(Conflict, match="qualification_expired"):
                await store.settle(
                    reserved.token,
                    "prepared",
                    digest(evidence.model_dump(mode="json")),
                    receipt=receipt,
                    evidence=evidence,
                    lock_authority=slow_authority,
                    current=lambda: True,
                )
            assert await inspect_head(store, reserved.token.root_key) == reserved
        else:
            prepared = await prepare(store, reserved, payload)
            with pytest.raises(Conflict, match="qualification_expired"):
                await store.settle(
                    prepared.token,
                    "activated",
                    "a" * 64,
                    staged_context_sha256=effective("plan").context_qualification_sha256,
                    staged_context_observed_at=time.time(),
                    lock_authority=slow_authority,
                    current=lambda: True,
                )
            assert await inspect_head(store, prepared.token.root_key) == prepared
    assert entered is True


async def test_absence_is_not_legacy_configuration_zero_and_missing_unsent_proof_is_not_ACK_absence(
    db,
):
    store = await setup(db)
    with pytest.raises(Conflict, match="head_absent_not_legacy_authority"):
        await inspect_head(store, configuration_root_key(origin()))
    initial = await initialize(store)
    identity, _ = await action(db, initial)
    reserved = await reserve(store, initial, identity)
    with pytest.raises(Conflict, match="explicit_not_opened_proof_required"):
        await store.settle(
            reserved.token, "not_sent", "a" * 64, lock_authority=authority, current=lambda: True
        )
    assert await inspect_head(store, reserved.token.root_key) == reserved


async def test_upgrade35_only_adds_empty_head_and_preserves_original_ciphertext(tmp_path):
    from alembic import command
    from alembic.config import Config

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.storage.cipher_types import checked_json, key_state, payload_scope
    from jt_oz_bridge.storage.database import migrate

    value = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "previous35.db"),
        cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"),
    )
    try:

        def old_schema(connection):
            cfg = Config()
            cfg.set_main_option("script_location", "src/jt_oz_bridge/storage/migrations")
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "0035_projection_ordinal_width")

        async with value.engine.begin() as connection:
            await connection.run_sync(old_schema)
            sealed = key_state(value.engine.dialect).cipher.seal(
                checked_json({"preserve": "original-secret-fixture"}),
                payload_scope("input_events", "payload"),
            )
            await connection.execute(
                text(
                    "INSERT INTO input_events (id,source,source_id,revision,payload_hash,payload,state,created_at) "
                    "VALUES ('old','synthetic','original',1,:hash,:payload,'received',1)"
                ),
                {"hash": digest({"preserve": "original-secret-fixture"}), "payload": sealed},
            )
            before = await connection.run_sync(lambda c: set(inspect(c).get_table_names()))
        await migrate(value.engine)
        assert await value.ready()
        async with value.engine.begin() as connection:
            after = await connection.run_sync(lambda c: set(inspect(c).get_table_names()))
            # Schema38 adds its own empty table on the way to the head.
            assert after - before == {"session_configuration_heads", "prompt_schedules"}
            assert (
                await connection.scalar(text("SELECT payload FROM input_events WHERE id='old'"))
                == sealed
            )
            assert (
                await connection.scalar(text("SELECT COUNT(*) FROM session_configuration_heads"))
                == 0
            )
            assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()

        def refuse_downgrade(connection):
            cfg = Config()
            cfg.set_main_option("script_location", "src/jt_oz_bridge/storage/migrations")
            cfg.attributes["connection"] = connection
            command.downgrade(cfg, "0035_projection_ordinal_width")

        # Schema38 is now the head and refuses first; it never reaches 0036's barrier.
        with pytest.raises(ValueError, match="prompt_schedules_must_be_preserved"):
            async with value.engine.begin() as connection:
                await connection.run_sync(refuse_downgrade)
        assert await value.ready()
    finally:
        await value.close()


async def test_actual_head_byte_limit_rolls_back_Action_and_head_atomically(db):
    agents = tuple(
        GuardedAgent(
            agent_id=f"{i:04d}" + "界" * 124,
            definition_sha256="7" * 64,
            policy_inputs_sha256="8" * 64,
        )
        for i in range(1000)
    )
    nodes = tuple(
        ConfigurationNode(
            node_key=f"{i:064x}", policy_sha256="2" * 64, reader_qualification_sha256="3" * 64
        )
        for i in range(1000)
    )
    config = EffectiveConfiguration(
        agent_id=agents[0].agent_id,
        configured_model_sha256="4" * 64,
        context_qualification_sha256="5" * 64,
        node_scope_sha256=digest({"nodes": [n.model_dump(mode="json") for n in nodes]}),
        nodes=nodes,
        guarded_agents=agents,
    )
    store = await setup(db)
    saved = await initialize(store, configuration=config)
    identity = str(uuid.uuid4())
    payload = AgentSwitchIntent(
        action_id=identity,
        realm_id="synthetic",
        binding_id=str(uuid.uuid4()),
        binding_revision=1,
        actor_id=7,
        queued_action_version=1,
        reference=saved.origin.root,
        root_key=saved.token.root_key,
        origin_sha256=digest(saved.origin.model_dump(mode="json")),
        expected_revision=1,
        before_configuration_sha256=saved.token.effective_sha256,
        after=config.model_copy(update={"agent_id": agents[1].agent_id}),
        source_sha256="e" * 64,
        preview_sha256="f" * 64,
        confirmation_sha256="f" * 64,
        transition_certificate_sha256="d" * 64,
        affected_scope_sha256="0" * 64,
        owner_epoch_sha256="1" * 64,
    ).model_dump(mode="json")
    async with db.sessions.begin() as session:
        session.add(
            Action(
                id=identity,
                dedupe_key=identity,
                binding_id=payload["binding_id"],
                binding_revision=1,
                actor_id=7,
                operation="agent.switch",
                operation_digest=digest(payload),
                payload=payload,
                state="queued",
                version=1,
                owner="bridge",
                admission={},
                native_result={},
            )
        )
    with pytest.raises(Conflict, match="capacity_exceeded"):
        await reserve(store, saved, identity)
    assert await inspect_head(store, saved.token.root_key) == saved
    async with db.sessions() as session:
        value = await session.get(Action, identity)
        assert value.state == "queued" and value.version == 1


@pytest.mark.parametrize("stage", ["reserve", "not_sent", "quarantined", "prepared", "activated"])
@pytest.mark.parametrize("committed", [False, True])
async def test_every_Action_head_transaction_resolves_lost_outcome_under_lock_without_retry(
    db, stage, committed
):
    store = await setup(db)
    predecessor = await initialize(store)
    identity, payload = await action(db, predecessor)
    if stage != "reserve":
        predecessor = await reserve(store, predecessor, identity)
    if stage == "activated":
        predecessor = await prepare(store, predecessor, payload)
    evidence = AgentSettingEvidence(
        native_ack_sha256="2" * 64,
        readback_sha256="3" * 64,
        after_configuration_sha256=digest(payload["after"]),
        supported_context_sha256=effective("plan").context_qualification_sha256,
        observed_at=time.time(),
    )
    receipt = ExecutionReceipt(
        action_id=identity,
        operation_digest=digest(payload),
        reference=predecessor.origin.root,
        contract_sha256="4" * 64,
        admission=Admission(
            status="admitted",
            owner="opencode",
            details={
                "operation": "agent.switch",
                "agent_setting": evidence.model_dump(mode="json"),
            },
        ),
    )
    checksum = None if stage == "reserve" else "a" * 64
    if stage == "not_sent":
        proof = KnownUnsentEvidence(
            kind="native_request_not_opened",
            action_id=identity,
            intent_sha256=digest(payload),
            reserved_revision=predecessor.token.revision,
            proof_sha256="1" * 64,
        )
        checksum = digest(proof.model_dump(mode="json"))
    if stage == "prepared":
        checksum = digest(evidence.model_dump(mode="json"))
    expected = ConfigurationCommitExpectation(
        root_key=predecessor.token.root_key,
        revision=predecessor.token.revision + 1,
        phase={
            "reserve": "dispatching",
            "prepared": "activation_prepared",
            "quarantined": "quarantined",
            "not_sent": "stable",
            "activated": "stable",
        }[stage],
        effective_sha256=digest(payload["after"])
        if stage == "activated"
        else predecessor.token.effective_sha256,
        active_action_id=identity if stage in {"reserve", "prepared", "quarantined"} else None,
        last_activation_action_id=identity
        if stage == "activated"
        else predecessor.token.last_activation_action_id,
        transition_action_id=identity,
        transition_intent_sha256=digest(payload),
        transition_evidence_sha256=checksum,
    )
    original = db.sessions

    class UnknownOutcome:
        @asynccontextmanager
        async def begin(self):
            async with original.begin() as session:
                yield session
                if not committed:
                    raise ConnectionError("synthetic_failure_before_real_commit")
            raise ConnectionError("synthetic_response_lost_after_real_commit")

    db.sessions = UnknownOutcome()
    try:
        with pytest.raises(ConnectionError):
            if stage == "reserve":
                await reserve(store, predecessor, identity)
            elif stage == "prepared":
                await store.settle(
                    predecessor.token,
                    "prepared",
                    checksum,
                    receipt=receipt,
                    evidence=evidence,
                    lock_authority=authority,
                    current=lambda: True,
                )
            else:
                await settle(
                    store,
                    predecessor,
                    stage,
                    **(
                        {"staged_context_sha256": effective("plan").context_qualification_sha256}
                        if stage == "activated"
                        else {}
                    ),
                )
    finally:
        db.sessions = original
    result = await store.reconcile_attempt(
        predecessor.token,
        expected,
        lock_authority=authority,
        current=lambda: True,
    )
    assert result.status == ("exact_committed" if committed else "predecessor_locked")
    assert result.native_send_authorized is False
    assert (
        result.snapshot.token.revision == expected.revision
        if committed
        else result.snapshot == predecessor
    )
    # No retry, queue resume, settings setter, Source creation or Native I/O occurs.


async def test_external_mark_and_release_keep_effective_and_only_move_forward(db):
    store = await setup(db)
    saved = await initialize(store)
    marked = await store.mark_external(saved.token, lock_authority=authority, current=lambda: True)
    assert marked.token.phase == "external_unqualified"
    assert marked.effective == saved.effective and marked.token.revision == saved.token.revision + 1
    with pytest.raises(Conflict):
        await store.mark_external(marked.token, lock_authority=authority, current=lambda: True)
    with pytest.raises(Conflict):
        await store.mark_external(saved.token, lock_authority=authority, current=lambda: True)
    released = await store.release_external(
        marked.token, lock_authority=authority, current=lambda: True
    )
    assert released.token.phase == "stable" and released.token.revision == marked.token.revision + 1


def adoption_intent(saved, *, operation="agent.adopt", resolves=None, agent="plan"):
    return AgentSwitchIntent(
        operation=operation,
        action_id=str(uuid.uuid4()),
        realm_id="realm-a",
        binding_id=str(uuid.uuid4()),
        binding_revision=1,
        actor_id=7,
        queued_action_version=1,
        reference=saved.origin.root,
        root_key=saved.token.root_key,
        origin_sha256=digest(saved.origin.model_dump(mode="json")),
        expected_revision=saved.token.revision,
        before_configuration_sha256=saved.token.effective_sha256,
        after=effective(agent),
        source_sha256="e" * 64,
        preview_sha256="f" * 64,
        confirmation_sha256="f" * 64,
        transition_certificate_sha256="d" * 64,
        affected_scope_sha256="0" * 64,
        owner_epoch_sha256="1" * 64,
        resolves_action_id=resolves,
    )


async def adopt(store, saved, intent, **options):
    return await store.adopt_observed(
        saved.token,
        intent,
        "a" * 64,
        dedupe_key=intent.action_id,
        lock_authority=options.pop("lock_authority", authority),
        current=lambda: True,
        observed_at=time.time(),
        **options,
    )


async def test_adoption_is_local_only_and_leaves_ambiguous_action_unchanged(db):
    store = await setup(db)
    saved = await initialize(store)
    with pytest.raises(Conflict, match="adoption_stale"):
        await adopt(store, saved, adoption_intent(saved))
    identity, _payload = await action(db, saved)
    reserved = await reserve(store, saved, identity)
    quarantined = await settle(store, reserved, "quarantined")
    intent = adoption_intent(quarantined, resolves=identity)
    wrong = adoption_intent(quarantined, resolves=str(uuid.uuid4()))
    with pytest.raises(Conflict, match="adoption_stale"):
        await adopt(store, quarantined, wrong)
    with pytest.raises(Conflict, match="adoption_intent_required"):
        await adopt(store, quarantined, adoption_intent(quarantined, operation="agent.switch"))
    result, record = await adopt(store, quarantined, intent)
    assert result.token.phase == "stable" and result.effective.agent_id == "plan"
    assert result.token.last_activation_action_id == record.id and record.state == "completed"
    async with db.sessions() as session:
        old = await session.get(Action, identity)
    assert old.state == "ambiguous" and old.native_result["phase"] == "quarantined"
    assert (await inspect_head(store, result.token.root_key)).token == result.token


async def test_failed_activation_hook_rolls_back_action_and_head_together(db):
    store = await setup(db)
    saved = await initialize(store)
    identity, _payload = await action(db, saved)
    reserved = await reserve(store, saved, identity)
    quarantined = await settle(store, reserved, "quarantined")

    async def failing(_session):
        raise OSError("synthetic hold failure")

    intent = adoption_intent(quarantined, resolves=identity)
    with pytest.raises(OSError):
        await adopt(store, quarantined, intent, on_activated=failing)
    after = await inspect_head(store, quarantined.token.root_key)
    assert after.token == quarantined.token
    async with db.sessions() as session:
        assert await session.get(Action, intent.action_id) is None
