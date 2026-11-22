"""Real isolated encrypted ownDB; synthetic identities are not Native qualification."""

import asyncio
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text, update

from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord
from jt_oz_bridge.services.session_registration_journal import (
    SessionRegistrationJournal,
    registration_key,
)
from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database, migrate
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from jt_oz_bridge.storage.session_registration_models import SessionRegistration
from tests.integration.test_migration_upgrade import (
    retention_preimage,
    verify_retention_additions,
)
from tests.support import REF, service


def record(*, created=123, owner="c" * 64, observed=None, reference=REF):
    origin = {
        "reference": reference.model_dump(mode="json"),
        "native_project_id": "native-project",
        "created_at": created,
        "parent_id": None,
    }
    return SessionAdoptionRecord(
        root=reference,
        native_project_id="native-project",
        contract_sha256="a" * 64,
        qualification_sha256="d" * 64,
        graph_sha256=digest(
            {
                "nodes": [
                    {
                        "reference": reference.model_dump(mode="json"),
                        "origin_sha256": digest(origin),
                        "policy_sha256": "b" * 64,
                    }
                ]
            }
        ),
        nodes=(
            OriginalSessionNode(
                reference=reference, native_created_at=created, policy_sha256="b" * 64
            ),
        ),
        observed_owner_epoch=owner,
        observed_at=time.time() if observed is None else observed,
    )


async def setup(db):
    await service(db)  # Enroll only synthetic project/grants, no Binding/Action.
    holder = "synthetic-registration-consumer"
    fencing = await DurableStore(db).acquire_lease(holder, ttl=120)
    assert fencing is not None
    journal = SessionRegistrationJournal(db, ConsumerFence(holder, fencing))

    async def authority(session):
        grant = await session.scalar(
            select(Grant)
            .where(
                Grant.realm_id == "realm",
                Grant.user_id == 7,
                Grant.project_id == REF.project_id,
                Grant.role == "operator",
                Grant.active.is_(True),
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if grant is None:
            raise Conflict("synthetic_current_grant_revoked")

    return journal, authority


async def prepare(journal, authority, value=None, current=lambda: True):
    return await journal.prepare(
        "realm", value or record(), lock_authority=authority, current=current
    )


async def recovery(journal, authority, realm="realm", project=REF.project_id):
    return await journal.recovery_records(
        realm, project, lock_authority=authority, current=lambda: True
    )


async def counts(db):
    async with db.sessions() as session:
        return tuple(
            [
                await session.scalar(select(func.count()).select_from(model))
                for model in (SessionRegistration, Binding, Action)
            ]
        )


async def test_prepared_and_active_rows_are_encrypted_identities_not_binding_or_dispatch(db):
    journal, authority = await setup(db)
    original = record()
    receipt = await prepare(journal, authority, original)
    assert await prepare(journal, authority, original) == receipt
    saved = await recovery(journal, authority)
    assert len(saved) == 1 and saved[0].record == original and saved[0].state == "prepared"
    assert saved[0].receipt == receipt and receipt.key == registration_key("realm", REF)
    async with db.engine.connect() as connection:
        raw = (
            await connection.execute(text("SELECT payload FROM session_registrations"))
        ).scalar_one()
        assert isinstance(raw, bytes)
        assert REF.upstream_session_id.encode() not in raw and b"native-project" not in raw
    await journal.activate(receipt, lock_authority=authority, current=lambda: True)
    await journal.activate(receipt, lock_authority=authority, current=lambda: True)
    assert (await recovery(journal, authority))[0].state == "active"
    assert await counts(db) == (1, 0, 0)


async def test_crash_prepared_record_survives_new_consumer_but_old_receipt_cannot_activate(db):
    journal, authority = await setup(db)
    old = record()
    receipt = await prepare(journal, authority, old)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
    next_epoch = await DurableStore(db).acquire_lease("replacement-consumer", ttl=120)
    fresh = SessionRegistrationJournal(db, ConsumerFence("replacement-consumer", next_epoch))
    saved = await recovery(fresh, authority)
    assert saved[0].record == old and saved[0].state == "prepared"
    with pytest.raises(Conflict, match="superseded"):
        await fresh.activate(receipt, lock_authority=authority, current=lambda: True)
    # New owner is not taken from the old row; a new GET preparation supplies it.
    observation = record(owner="e" * 64)
    new = await prepare(fresh, authority, observation)
    assert new.revision == receipt.revision + 1 and new.identity_hash == receipt.identity_hash
    await fresh.activate(new, lock_authority=authority, current=lambda: True)
    assert (await recovery(fresh, authority))[0].record == observation
    with pytest.raises(Conflict, match="consumer_lease"):
        await journal.activate(receipt, lock_authority=authority, current=lambda: True)
    assert await counts(db) == (1, 0, 0)


async def test_historic_identity_is_readable_but_never_renewed_as_live_proof(db, monkeypatch):
    journal, authority = await setup(db)
    value = record()
    await prepare(journal, authority, value)
    # Age the genuine authenticated row; editing only its encrypted payload/hash
    # would now be tampering against the separate head history seal.
    historic = value
    later = time.time() + 100
    monkeypatch.setattr(
        "jt_oz_bridge.services.session_registration_journal.time.time", lambda: later
    )
    saved = await recovery(journal, authority)
    assert saved[0].record == historic
    with pytest.raises(Conflict, match="proof_expired"):
        await prepare(journal, authority, historic)
    with pytest.raises(Conflict, match="proof_expired"):
        await journal.activate(saved[0].receipt, lock_authority=authority, current=lambda: True)
    assert (await recovery(journal, authority))[0].state == "prepared"


@pytest.mark.parametrize("fault", ["create_time", "policy", "qualification", "native_project"])
async def test_same_native_id_with_changed_original_identity_is_never_overwritten(db, fault):
    journal, authority = await setup(db)
    original = record()
    await prepare(journal, authority, original)
    changed = record(created=124) if fault == "create_time" else original
    if fault in {"qualification", "native_project"}:
        # These must also carry a self-consistent graph; build it with the normal validator.
        data = changed.model_dump(mode="json")
        if fault == "qualification":
            data["qualification_sha256"] = "f" * 64
        else:
            data["native_project_id"] = "foreign-project"
            origin = {
                "reference": REF.model_dump(mode="json"),
                "native_project_id": "foreign-project",
                "created_at": 123,
                "parent_id": None,
            }
            data["graph_sha256"] = digest(
                {
                    "nodes": [
                        {
                            "reference": REF.model_dump(mode="json"),
                            "origin_sha256": digest(origin),
                            "policy_sha256": "b" * 64,
                        }
                    ]
                }
            )
        changed = SessionAdoptionRecord.model_validate(data)
    if fault == "policy":
        data = original.model_dump(mode="json")
        data["nodes"][0]["policy_sha256"] = "f" * 64
        origin = {
            "reference": REF.model_dump(mode="json"),
            "native_project_id": "native-project",
            "created_at": 123,
            "parent_id": None,
        }
        data["graph_sha256"] = digest(
            {
                "nodes": [
                    {
                        "reference": REF.model_dump(mode="json"),
                        "origin_sha256": digest(origin),
                        "policy_sha256": "f" * 64,
                    }
                ]
            }
        )
        changed = SessionAdoptionRecord.model_validate(data)
    with pytest.raises(Conflict, match="identity_changed"):
        await prepare(journal, authority, changed)
    assert (await recovery(journal, authority))[0].record == original


@pytest.mark.parametrize("when", ["first", "after_flush", "activate", "recover"])
async def test_revoked_current_authority_rolls_back_without_partial_activation(db, when):
    journal, authority = await setup(db)
    receipt = None
    if when in {"activate", "recover"}:
        receipt = await prepare(journal, authority)
    calls = 0

    async def revoked(session):
        nonlocal calls
        calls += 1
        if when != "after_flush" or calls == 2:
            raise Conflict("synthetic_source_or_grant_revoked")
        await authority(session)

    with pytest.raises(Conflict, match="revoked"):
        if when == "activate":
            await journal.activate(receipt, lock_authority=revoked, current=lambda: True)
        elif when == "recover":
            await journal.recovery_records(
                "realm", REF.project_id, lock_authority=revoked, current=lambda: True
            )
        else:
            await prepare(journal, revoked)
    assert await counts(db) == ((1, 0, 0) if receipt else (0, 0, 0))
    if receipt:
        assert (await recovery(journal, authority))[0].state == "prepared"


@pytest.mark.parametrize("kind", ["cancelled", "expired", "lease_lost"])
async def test_post_flush_cancel_expiry_and_fence_change_are_rolled_back(db, kind):
    journal, authority = await setup(db)
    calls = 0
    live = True

    async def interrupt(session):
        nonlocal calls, live
        calls += 1
        await authority(session)
        if calls == 2:
            if kind == "cancelled":
                raise asyncio.CancelledError()
            if kind == "expired":
                live = False
            else:
                await session.execute(update(WorkerLease).values(fencing=999))

    with pytest.raises(asyncio.CancelledError if kind == "cancelled" else Conflict):
        await prepare(journal, interrupt, current=lambda: live)
    assert await counts(db) == (0, 0, 0)
    # The injected lease mutation was in the same rolled-back transaction.
    assert await prepare(journal, authority)


@pytest.mark.parametrize(
    "model,field,value",
    [
        (EnrolledBackend, "enabled", False),
        (EnrolledBackend, "verified", False),
        (EnrolledBackend, "identity", "replacement"),
        (EnrolledBackend, "contract_hash", "f" * 64),
        (EnrolledProject, "enabled", False),
        (EnrolledProject, "realm_id", "foreign"),
        (EnrolledProject, "backend_id", "foreign"),
        (EnrolledProject, "canonical_directory", "/foreign"),
    ],
)
async def test_current_enrollment_is_required_for_prepare_activate_and_recovery(
    db, model, field, value
):
    journal, authority = await setup(db)
    receipt = await prepare(journal, authority)
    async with db.sessions.begin() as session:
        await session.execute(update(model).values({field: value}))
    for attempt in (
        lambda: prepare(journal, authority),
        lambda: journal.activate(receipt, lock_authority=authority, current=lambda: True),
        lambda: recovery(journal, authority),
    ):
        with pytest.raises(Conflict, match="enrollment_changed"):
            await attempt()
    assert await counts(db) == (1, 0, 0)


@pytest.mark.parametrize(
    "changes",
    [
        {"key": "f" * 64},
        {"realm_id": "foreign"},
        {"project_id": "foreign"},
        {"payload_hash": "f" * 64},
        {"identity_hash": "f" * 64},
        {"state": "dispatching"},
        {"state": "active"},
        {"revision": 0},
        {"prepared_holder": ""},
        {"prepared_fencing": 0},
        {"activated_fencing": 1},
        {"updated_at": 0},
        {"payload": {"format": "foreign"}},
    ],
)
async def test_corrupt_projection_cannot_be_recovered_as_valid_identity(db, changes):
    journal, authority = await setup(db)
    await prepare(journal, authority)
    async with db.sessions.begin() as session:
        await session.execute(update(SessionRegistration).values(**changes))
    with pytest.raises(Conflict, match="registration_invalid"):
        await recovery(
            journal,
            authority,
            realm=changes.get("realm_id", "realm"),
            project=changes.get("project_id", REF.project_id),
        )


async def test_concurrent_same_preparation_is_one_record_and_stale_revision_cannot_activate(db):
    journal, authority = await setup(db)
    original = record()
    first, second = await asyncio.gather(
        prepare(journal, authority, original), prepare(journal, authority, original)
    )
    assert first == second
    current = await prepare(journal, authority, record(owner="e" * 64))
    with pytest.raises(Conflict, match="superseded"):
        await journal.activate(first, lock_authority=authority, current=lambda: True)
    with pytest.raises(Conflict, match="superseded"):
        await journal.activate(
            replace(current, realm_id="other"), lock_authority=authority, current=lambda: True
        )
    await journal.activate(current, lock_authority=authority, current=lambda: True)
    assert await counts(db) == (1, 0, 0)


async def test_recovery_is_scoped_and_capacity_failure_is_not_a_partial_catalog(db, monkeypatch):
    journal, authority = await setup(db)
    await prepare(journal, authority)
    assert not await recovery(journal, authority, realm="other")
    assert not await recovery(journal, authority, project="other")
    monkeypatch.setattr("jt_oz_bridge.services.session_registration_journal.MAX_REGISTRATIONS", 0)
    with pytest.raises(Conflict, match="capacity"):
        await prepare(
            journal,
            authority,
            record(reference=REF.model_copy(update={"upstream_session_id": "other-original"})),
        )
    with pytest.raises(Conflict, match="capacity"):
        await recovery(journal, authority)


@pytest.mark.parametrize("proof", [False, None, 1, "yes"])
async def test_only_an_exact_current_proof_can_prepare_activate_or_read_recovery(db, proof):
    journal, authority = await setup(db)
    receipt = await prepare(journal, authority)
    for attempt in (
        lambda: prepare(journal, authority, current=lambda: proof),
        lambda: journal.activate(receipt, lock_authority=authority, current=lambda: proof),
        lambda: journal.recovery_records(
            "realm", REF.project_id, lock_authority=authority, current=lambda: proof
        ),
    ):
        with pytest.raises(Conflict, match="proof_expired"):
            await attempt()
    assert await counts(db) == (1, 0, 0)


async def test_plaintext_or_another_table_ciphertext_is_never_a_registration_payload(db):
    journal, authority = await setup(db)
    await prepare(journal, authority)
    for blob in (
        checked_json(record().model_dump(mode="json")),
        db.cipher.seal(
            checked_json(record().model_dump(mode="json")), payload_scope("actions", "payload")
        ),
    ):
        async with db.engine.begin() as connection:
            await connection.execute(
                text("UPDATE session_registrations SET payload=:payload"), {"payload": blob}
            )
        with pytest.raises(ValueError):
            await recovery(journal, authority)


async def test_future_or_expired_observation_cannot_be_prepared_even_with_current_callback(db):
    journal, authority = await setup(db)
    for observed in (time.time() + 100, time.time() - 100):
        with pytest.raises(Conflict, match="proof_expired"):
            await prepare(journal, authority, record(observed=observed))
    assert await counts(db) == (0, 0, 0)


async def test_upgrade30_adds_only_identity_table_and_preserves_all_old_bytes(tmp_path):
    from jt_oz_bridge.security.cipher import EnvelopeCipher

    db = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "schema30.db"),
        cipher=EnvelopeCipher({"fixture": os.urandom(32)}, "fixture"),
    )

    def install(connection):
        cfg = Config()
        cfg.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "0030_check_dispatch_records")

    try:
        captured = db.cipher.seal(
            checked_json({"private": "old ambiguous receipt"}),
            payload_scope("input_events", "payload"),
        )
        async with db.engine.begin() as connection:
            await connection.run_sync(install)
            await connection.execute(
                text(
                    "INSERT INTO input_events(id,source,source_id,revision,payload_hash,payload,state,created_at) VALUES ('old','original','event',1,'hash',:payload,'ambiguous',123)"
                ),
                {"payload": captured},
            )
            before = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            rows = (await connection.execute(text("SELECT * FROM input_events"))).all()
            old_columns = list(
                (await connection.execute(text("PRAGMA table_info(input_events)"))).all()
            )
            prior_retention_columns = await retention_preimage(connection, before)
        assert not await db.ready()
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            after = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            assert set(after) - set(before) == {
                "session_registrations",
                "session_registration_extensions",
                "zulip_recovery_checkpoints",
                "zulip_recovery_items",
                "session_configuration_heads",
                "prompt_schedules",
            }
            normalized = await verify_retention_additions(
                connection, prior_retention_columns, after
            )
            assert all(normalized[name] == value for name, value in before.items())
            assert (
                await connection.execute(
                    text(
                        "SELECT "
                        + ",".join('"' + column[1] + '"' for column in old_columns)
                        + " FROM input_events"
                    )
                )
            ).all() == rows
            assert (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one() == CURRENT_REVISION
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM session_registrations"))
            ).scalar_one() == 0
            assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()
    finally:
        await db.close()
