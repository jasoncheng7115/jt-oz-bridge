"""Actual isolated encrypted ownDB journal; all owners/Native evidence synthetic."""

import os
import time
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError

from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.checks import ApprovedCheck, CheckSelection, check_message_id
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords
from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord
from jt_oz_bridge.storage.cipher_types import EncryptedJSON, checked_json, payload_scope
from jt_oz_bridge.storage.control_models import (
    Binding,
    ControlToken,
    EnrolledBackend,
    EnrolledProject,
)
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database, migrate
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_migration_upgrade import (
    retention_preimage,
    verify_retention_additions,
)
from tests.integration.test_router import message
from tests.support import REF, bound


async def setup(db):
    bindings, binding, _, _ = await bound(db)
    holder = "synthetic-check-dispatch"
    epoch = await DurableStore(db).acquire_lease(holder, ttl=120)
    assert epoch is not None
    service = CheckDispatchRecords(bindings, ConsumerFence(holder, epoch))
    selection = CheckSelection(
        reference=REF,
        check=ApprovedCheck(id="unit", title="approved unit", command="python -m pytest tests"),
        catalog_sha256="a" * 64,
        qualification_sha256="d" * 64,
    )
    now = time.time()
    payload = {
        "operation": "check.run",
        "reference": REF.model_dump(mode="json"),
        "binding_id": binding.id,
        "binding_revision": binding.revision,
        "source": message("!oz check " + "x" * 32).model_dump(mode="json"),
        "selection": selection.model_dump(mode="json"),
        "selection_token_sha256": "e" * 64,
        "choice_expires_at": now + 60,
        "reply_locale": "en",
    }
    async with db.sessions.begin() as session:
        session.add(
            ControlToken(
                token_hash="e" * 64,
                kind="native-check-choice",
                realm_id="realm",
                user_id=7,
                binding_id=binding.id,
                binding_revision=binding.revision,
                context=selection.model_dump(mode="json"),
                context_hash=digest(selection.model_dump(mode="json")),
                expires_at=now + 60,
                used=True,
            )
        )
        action = Action(
            dedupe_key="synthetic-check",
            binding_id=binding.id,
            binding_revision=binding.revision,
            actor_id=7,
            operation="check.run",
            operation_digest=digest(payload),
            payload=payload,
            state="dispatching",
            version=2,
        )
        session.add(action)
        await session.flush()
    proof = CheckDispatchPreflight(
        action_id=action.id,
        operation_digest=action.operation_digest,
        reference=REF,
        binding_id=binding.id,
        binding_revision=binding.revision,
        contract_sha256="a" * 64,
        qualification_sha256="d" * 64,
        message_id=check_message_id(action.id),
        owner_epoch="b" * 64,
        connection_epoch="original-connection",
        ownership_evidence_sha256="c" * 64,
        issued_at=now - 0.01,
        expires_at=now + 5,
    )
    return service, action, binding, proof


async def save(service, proof):
    async with service.db.sessions.begin() as session:
        return await service.record_in_session(session, proof, expected_action_version=2)


async def read(service, proof):
    return await service.owner_for(
        proof.action_id, proof.operation_digest, proof.reference, proof.qualification_sha256
    )


async def count(db):
    async with db.sessions() as session:
        return len(list((await session.scalars(select(CheckDispatchRecord))).all()))


async def test_preflight_is_immutable_encrypted_and_not_admission(db):
    service, action, _, proof = await setup(db)
    assert await save(service, proof) == proof
    assert await save(service, proof) == proof
    assert await read(service, proof) == proof
    assert await count(db) == 1
    async with db.sessions() as session:
        saved = await session.get(Action, action.id)
        assert (
            saved.state,
            saved.version,
            saved.owner,
            saved.admission,
            saved.native_result,
            saved.upstream_id,
        ) == ("dispatching", 2, "bridge", {}, {}, None)
    async with db.engine.connect() as connection:
        raw = (
            await connection.execute(
                text("SELECT payload,payload_hash FROM check_dispatch_records")
            )
        ).one()
        assert isinstance(raw[0], bytes) and proof.owner_epoch.encode() not in raw[0]
        assert raw[1] == digest(proof.model_dump(mode="json"))
        assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()


async def test_caller_rollback_removes_preflight_without_touching_action(db):
    service, action, _, proof = await setup(db)
    with pytest.raises(RuntimeError):
        async with db.sessions.begin() as session:
            await service.record_in_session(session, proof, expected_action_version=2)
            raise RuntimeError("synthetic abort before any send")
    assert await count(db) == 0
    async with db.sessions() as session:
        assert (await session.get(Action, action.id)).state == "dispatching"


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "running"),
        ("message_id", "msg_" + "f" * 64),
        ("owner_epoch", ""),
        ("owner_epoch", "not-owner-evidence"),
        ("ownership_evidence_sha256", ""),
        ("connection_epoch", "bad\nvalue"),
        ("issued_at", True),
        ("expires_at", float("nan")),
        ("expires_at", float("inf")),
        ("binding_revision", True),
    ],
)
async def test_dto_rejects_missing_or_forged_proof_fields(db, field, value):
    _, _, _, proof = await setup(db)
    raw = proof.model_dump(mode="python") | {field: value}
    with pytest.raises(ValidationError):
        CheckDispatchPreflight.model_validate(raw)


@pytest.mark.parametrize("issued,expires", [(100, 100), (100, 99), (100, 131)])
async def test_dto_rejects_unbounded_or_reversed_proof_window(db, issued, expires):
    _, _, _, proof = await setup(db)
    with pytest.raises(ValidationError):
        CheckDispatchPreflight.model_validate(
            proof.model_dump() | {"issued_at": float(issued), "expires_at": float(expires)}
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner_epoch", "f" * 64),
        ("connection_epoch", "foreign-connection"),
        ("ownership_evidence_sha256", "f" * 64),
    ],
)
async def test_original_owner_cannot_be_overwritten(db, field, value):
    service, _, _, proof = await setup(db)
    await save(service, proof)
    changed = CheckDispatchPreflight.model_validate(proof.model_dump() | {field: value})
    with pytest.raises(Conflict):
        await save(service, changed)
    assert await read(service, proof) == proof and await count(db) == 1


@pytest.mark.parametrize(
    "drift",
    [
        "missing_action",
        "wrong_operation",
        "queued",
        "version",
        "payload_digest",
        "binding_payload",
        "pause",
        "revision",
        "session",
        "project_disabled",
        "backend_contract",
        "operate_revoked",
        "audience_revoked",
        "lease",
        "token_unused",
        "token_hash",
        "token_qualification",
        "source_actor",
        "admission",
        "native_result",
        "upstream",
    ],
)
async def test_fenced_record_rejects_current_identity_authority_and_state_drift(db, drift):
    service, action, binding, proof = await setup(db)
    async with db.sessions.begin() as session:
        saved = await session.get(Action, action.id)
        if drift == "missing_action":
            await session.delete(saved)
        elif drift in {
            "wrong_operation",
            "queued",
            "version",
            "admission",
            "native_result",
            "upstream",
        }:
            key, value = {
                "wrong_operation": ("operation", "prompt"),
                "queued": ("state", "queued"),
                "version": ("version", 3),
                "admission": ("admission", {"not": "preflight"}),
                "native_result": ("native_result", {"not": "preflight"}),
                "upstream": ("upstream_id", proof.message_id),
            }[drift]
            setattr(saved, key, value)
        elif drift in {"payload_digest", "binding_payload", "source_actor"}:
            payload = dict(saved.payload)
            if drift == "binding_payload":
                payload["binding_id"] = "foreign"
            elif drift == "source_actor":
                payload["source"] = dict(payload["source"]) | {"author_id": 8}
            else:
                payload["reply_locale"] = "zh-TW"
            saved.payload = payload
            if drift != "payload_digest":
                saved.operation_digest = digest(payload)
                proof = CheckDispatchPreflight.model_validate(
                    proof.model_dump() | {"operation_digest": saved.operation_digest}
                )
        elif drift in {"pause", "revision", "session"}:
            row = await session.get(Binding, binding.id)
            setattr(
                row,
                {"pause": "dispatch_paused", "revision": "revision", "session": "session_id"}[
                    drift
                ],
                {"pause": True, "revision": 2, "session": "foreign"}[drift],
            )
        elif drift == "project_disabled":
            (await session.get(EnrolledProject, "project")).enabled = False
        elif drift == "backend_contract":
            (await session.get(EnrolledBackend, "backend")).contract_hash = "f" * 64
        elif drift in {"operate_revoked", "audience_revoked"}:
            user = 7 if drift == "operate_revoked" else 8
            await session.execute(update(Grant).where(Grant.user_id == user).values(active=False))
        elif drift == "lease":
            await session.execute(update(WorkerLease).values(fencing=999))
        else:
            token = await session.get(ControlToken, "e" * 64)
            if drift == "token_unused":
                token.used = False
            elif drift == "token_hash":
                token.context_hash = "f" * 64
            else:
                token.context = dict(token.context) | {"qualification_sha256": "f" * 64}
                token.context_hash = digest(token.context)
    with pytest.raises(ValueError):
        await save(service, proof)
    assert await count(db) == 0


@pytest.mark.parametrize("deadline", ["proof", "lease", "choice"])
async def test_sql_clock_rejects_expiry_during_actual_encrypted_parameter_encoding(
    db, monkeypatch, deadline
):
    service, _, _, proof = await setup(db)
    now = time.time()
    if deadline == "proof":
        proof = CheckDispatchPreflight.model_validate(
            proof.model_dump() | {"issued_at": now - 1, "expires_at": now + 0.08}
        )
    else:
        async with db.sessions.begin() as session:
            if deadline == "lease":
                await session.execute(update(WorkerLease).values(expires_at=now + 0.08))
            else:
                action = await session.get(Action, proof.action_id)
                payload = dict(action.payload) | {"choice_expires_at": now + 0.08}
                action.payload, action.operation_digest = payload, digest(payload)
                (await session.get(ControlToken, "e" * 64)).expires_at = now + 0.08
                proof = CheckDispatchPreflight.model_validate(
                    proof.model_dump() | {"operation_digest": digest(payload)}
                )
    original = EncryptedJSON.process_bind_param

    def delayed(self, value, dialect):
        if self.table == "check_dispatch_records":
            time.sleep(0.12)
        return original(self, value, dialect)

    monkeypatch.setattr(EncryptedJSON, "process_bind_param", delayed)
    with pytest.raises(Conflict):
        await save(service, proof)
    assert await count(db) == 0


async def test_expired_historical_proof_remains_original_without_renewing_or_current_owner_lookup(
    db,
):
    service, action, _, proof = await setup(db)
    await save(service, proof)
    old = CheckDispatchPreflight.model_validate(
        proof.model_dump() | {"issued_at": 100.0, "expires_at": 105.0}
    )
    # Simulate an actually retained historical sealed record, not new admission.
    async with db.sessions.begin() as session:
        record = await session.get(CheckDispatchRecord, action.id)
        record.payload = old.model_dump(mode="json")
        record.payload_hash = digest(record.payload)
        (await session.get(Action, action.id)).state = "ambiguous"
    service.bindings.control.ref = REF.model_copy(update={"backend_identity": "new-owner-metadata"})
    result = await read(service, proof)
    assert result == old and result.expires_at == 105 and result.owner_epoch == proof.owner_epoch
    async with db.sessions() as session:
        saved = await session.get(Action, action.id)
        assert saved.state == "ambiguous" and not saved.admission and saved.upstream_id is None


@pytest.mark.parametrize(
    "drift",
    [
        "missing",
        "digest",
        "reference",
        "qualification",
        "stored_hash",
        "stored_action",
        "stored_evidence",
    ],
)
async def test_owner_for_rejects_missing_or_corrupt_original_evidence(db, drift):
    service, action, _, proof = await setup(db)
    if drift != "missing":
        await save(service, proof)
    if drift.startswith("stored_"):
        async with db.sessions.begin() as session:
            row = await session.get(CheckDispatchRecord, action.id)
            if drift == "stored_hash":
                row.payload_hash = "f" * 64
            elif drift == "stored_action":
                (await session.get(Action, action.id)).operation_digest = "f" * 64
            else:
                row.payload = dict(row.payload) | {"ownership_evidence_sha256": ""}
                row.payload_hash = digest(row.payload)
    with pytest.raises(Conflict):
        await service.owner_for(
            action.id,
            "f" * 64 if drift == "digest" else proof.operation_digest,
            REF.model_copy(update={"upstream_session_id": "foreign"})
            if drift == "reference"
            else REF,
            "f" * 64 if drift == "qualification" else proof.qualification_sha256,
        )


async def test_record_requires_caller_transaction_and_exact_version(db):
    service, _, _, proof = await setup(db)
    async with db.sessions() as session:
        with pytest.raises(Conflict):
            await service.record_in_session(session, proof, expected_action_version=2)
    for version in (1, 3, True):
        with pytest.raises(Conflict):
            async with db.sessions.begin() as session:
                await service.record_in_session(session, proof, expected_action_version=version)
    assert await count(db) == 0


async def test_action_foreign_key_and_unique_primary_key_are_real_constraints(db):
    service, _, _, proof = await setup(db)
    await save(service, proof)
    with pytest.raises(IntegrityError):
        async with db.sessions.begin() as session:
            session.add(
                CheckDispatchRecord(
                    action_id=proof.action_id,
                    payload=proof.model_dump(mode="json"),
                    payload_hash=digest(proof.model_dump(mode="json")),
                )
            )
    with pytest.raises(IntegrityError):
        async with db.sessions.begin() as session:
            session.add(
                CheckDispatchRecord(
                    action_id="missing-action",
                    payload=proof.model_dump(mode="json"),
                    payload_hash=digest(proof.model_dump(mode="json")),
                )
            )


async def test_upgrade29_to30_preserves_original_encrypted_action_and_state(tmp_path):
    db = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "schema29.db"),
        cipher=EnvelopeCipher({"fixture": os.urandom(32)}, "fixture"),
    )

    def install(connection):
        cfg = Config()
        cfg.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "0029_rendering_runtime")

    try:
        captured = db.cipher.seal(
            checked_json({"old": "private original Action"}), payload_scope("actions", "payload")
        )
        async with db.engine.begin() as connection:
            await connection.run_sync(install)
            await connection.execute(
                text(
                    "INSERT INTO actions(id,dedupe_key,binding_id,binding_revision,actor_id,operation_digest,payload,admission,native_result,operation,state,version,owner,created_at) VALUES ('old','old','binding',1,7,'hash',:payload,:admission,:native_result,'check.run','ambiguous',8,'bridge',1)"
                ),
                {
                    "payload": captured,
                    "admission": db.cipher.seal(
                        checked_json({}), payload_scope("actions", "admission")
                    ),
                    "native_result": db.cipher.seal(
                        checked_json({}), payload_scope("actions", "native_result")
                    ),
                },
            )
            before = (await connection.execute(text("SELECT * FROM actions WHERE id='old'"))).one()
            before_columns = list(
                (await connection.execute(text("PRAGMA table_info(actions)"))).all()
            )
            schema = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            prior_retention_columns = await retention_preimage(connection, schema)
            assert (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one() == "0029_rendering_runtime"
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            current_schema = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            normalized = await verify_retention_additions(
                connection, prior_retention_columns, current_schema
            )
            assert all(normalized[name] == value for name, value in schema.items())
            assert set(current_schema) - set(schema) == {
                "check_dispatch_records",
                "session_registrations",
                "session_registration_extensions",
                "zulip_recovery_checkpoints",
                "zulip_recovery_items",
                "session_configuration_heads",
                "prompt_schedules",
            }
            assert (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one() == CURRENT_REVISION
            assert (
                await connection.execute(
                    text(
                        "SELECT "
                        + ",".join('"' + row[1] + '"' for row in before_columns)
                        + " FROM actions WHERE id='old'"
                    )
                )
            ).one() == before
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM check_dispatch_records"))
            ).scalar_one() == 0
            assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()
    finally:
        await db.close()
