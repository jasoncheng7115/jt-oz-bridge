import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text, update

from jt_oz_bridge.domain.control import InteractionSnapshot
from jt_oz_bridge.domain.execution import Admission, MutationNotSent
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.execution_receipts import native_receipt, read_receipt
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
from jt_oz_bridge.storage.control_models import Binding, PendingInteraction
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_dispatch import dispatcher, message
from tests.support import REF


async def admitted_prompt(db, details=None):
    worker, binding, client, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await worker.queue.receive(binding.id, message())

    async def submit(reference, payload, identity):
        return Admission(status="admitted", upstream_id="msg_original", details=details or {})

    client.submit = submit
    assert await worker.advance(queued.action_id) == "admitted"
    return worker, binding, queued.action_id


async def test_receipt_encrypted_separately_and_request_digest_unchanged(db):
    evidence = {"interrupted": False, "accepted": 0, "native": {"message": "PRIVATE_RECEIPT"}}
    worker, binding, identity = await admitted_prompt(db, evidence)
    saved = await worker.load(identity)
    receipt = await read_receipt(worker.bindings, identity, "realm", 7)
    assert receipt.reference == REF
    assert receipt.admission.status == "admitted"  # Not the end of the native turn.
    assert receipt.admission.details == evidence
    assert receipt.contract_sha256 == "a" * 64
    assert saved.operation_digest == digest(saved.payload)
    async with db.engine.connect() as connection:
        raw = await connection.scalar(
            text("SELECT admission FROM actions WHERE id=:id"), {"id": identity}
        )
    assert isinstance(raw, bytes) and b"PRIVATE_RECEIPT" not in raw
    assert await worker.advance(identity) == "admitted"


@pytest.mark.parametrize("change", ["actor", "realm", "binding", "grant"])
async def test_receipt_requires_current_view_and_binding_revision(db, change):
    worker, binding, identity = await admitted_prompt(db)
    if change == "binding":
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(revision=2))
    if change == "grant":
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
    with pytest.raises((AccessDenied, Conflict)):
        await read_receipt(
            worker.bindings,
            identity,
            "other" if change == "realm" else "realm",
            99 if change == "actor" else 7,
        )


@pytest.mark.parametrize("change", ["id", "digest", "owner", "upstream", "scope", "session"])
async def test_receipt_cannot_be_substituted_for_another_action_or_target(db, change):
    worker, binding, identity = await admitted_prompt(db)
    saved = await worker.load(identity)
    document = saved.admission
    if change in {"scope", "session"}:
        document["reference"]["project_id" if change == "scope" else "upstream_session_id"] = (
            "other"
        )
    elif change == "id":
        document["action_id"] = "other"
    elif change == "digest":
        document["operation_digest"] = "b" * 64
    elif change == "owner":
        document["admission"]["owner"] = "bridge"
    else:
        document["admission"]["upstream_id"] = "other"
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == identity).values(admission=document)
        )
    with pytest.raises(Conflict):
        await read_receipt(worker.bindings, identity, "realm", 7)


@pytest.mark.parametrize("bad", [{"x": float("nan")}, {"x": "x" * 32769}, {"x": object()}])
async def test_malformed_native_success_is_ambiguous_and_never_replayed(db, bad):
    worker, binding, client, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await worker.queue.receive(binding.id, message())
    attempts = []

    async def submit(reference, payload, identity):
        attempts.append(identity)
        return Admission.model_construct(
            status="admitted", owner="opencode", upstream_id="msg_sent", details=bad
        )

    client.submit = submit
    assert await worker.advance(queued.action_id) == "ambiguous"
    assert await worker.advance(queued.action_id) == "ambiguous"
    assert attempts == [queued.action_id]
    assert native_receipt(await worker.load(queued.action_id)) is None


@pytest.mark.parametrize("kind", ["permission", "form"])
async def test_proven_no_mutation_attempt_reopens_only_for_new_human_action(db, kind):
    worker, binding, client, reader = await dispatcher(db)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="original-request",
        generation="g1",
        kind=kind,
        pending=True,
        description="Original request",
    )
    client.requests[snapshot.upstream_request_id] = snapshot
    interactions = InteractionService(worker.bindings)
    pending = await interactions.observe(binding, snapshot)
    token = await interactions.issue(pending, "realm", 7)
    arguments = {"decision": "once"} if kind == "permission" else {"answers": {}}
    identity = await interactions.reply(token, "realm", 7, **arguments)

    async def no_post(reference, payload, identity):
        raise MutationNotSent("fixture pre-HTTP rejection")

    client.submit = no_post
    assert await worker.advance(identity) == "rejected"
    async with db.sessions() as session:
        row = await session.get(PendingInteraction, pending)
        assert row.state == "pending" and row.action_id is None and row.winner_user_id is None
    assert await worker.advance(identity) == "rejected"
    with pytest.raises(Conflict):
        await interactions.reply(token, "realm", 7, **arguments)
    fresh = await interactions.issue(pending, "realm", 7)
    assert await interactions.reply(fresh, "realm", 7, **arguments) != identity


async def test_upgrade_preserves_legacy_request_bytes_and_ambiguous_state(tmp_path):
    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'old.db'}", cipher=cipher)
    payload = {"operation": "prompt", "text": "ORIGINAL_PRIVATE_INPUT"}
    encoded = cipher.seal(checked_json(payload), payload_scope("actions", "payload"))

    def legacy(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, "0011_delivery_destinations")

    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(legacy)
            await connection.execute(
                text(
                    "INSERT INTO actions (id,dedupe_key,binding_id,binding_revision,actor_id,operation_digest,payload,state,version,created_at,owner,operation,upstream_id) VALUES ('old','old','binding',3,7,:digest,:payload,'ambiguous',9,123,'opencode','prompt','msg_original')"
                ),
                {"digest": digest(payload), "payload": encoded},
            )
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(text("SELECT payload FROM actions WHERE id='old'"))
                == encoded
            )
            assert isinstance(
                await connection.scalar(text("SELECT admission FROM actions WHERE id='old'")), bytes
            )
        async with db.sessions() as session:
            row = await session.get(Action, "old")
            assert (row.state, row.version, row.upstream_id, row.operation_digest, row.payload) == (
                "ambiguous",
                9,
                "msg_original",
                digest(payload),
                payload,
            )
            assert row.admission == {} and native_receipt(row) is None
    finally:
        await db.close()
