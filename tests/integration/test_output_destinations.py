import asyncio
import time
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import update

from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.output_destinations import OutputDestinations
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant, WorkerLease
from jt_oz_bridge.storage.output_models import OutputDestination
from tests.integration.test_discovery import discovery
from tests.integration.test_router import Source, count, message
from tests.support import REF


async def prepared(db, project_ids=("project",), text="!oz sessions PRIVATE_DESTINATION_MARKER"):
    catalog, _clients = await discovery(db)
    fencing = await DurableStore(db).acquire_lease("output-target-test")
    reader = Source()
    source = message(text, 201)
    reader.messages[201] = source
    service = OutputDestinations(catalog, reader, ConsumerFence("output-target-test", fencing))
    target = await service.prepare(source, project_ids)
    return service, reader, target


async def test_destination_is_encrypted_scoped_and_never_creates_a_session_binding(db, tmp_path):
    service, reader, target = await prepared(db, ("project", "second-project"))
    identity = await service.save("source:201", target)
    assert await service.load(identity) == target
    assert target.purpose == "catalog" and len(target.projects) == 2
    assert await count(db, Binding) == 0
    async with db.engine.connect() as connection:
        from sqlalchemy import text

        raw = await connection.scalar(text("SELECT authorization FROM output_destinations"))
    assert isinstance(raw, bytes) and b"PRIVATE_DESTINATION_MARKER" not in raw
    for path in tmp_path.glob("test.db*"):
        assert b"PRIVATE_DESTINATION_MARKER" not in path.read_bytes()


async def test_static_local_help_requires_no_project_grants_but_still_requires_private_audience(db):
    service, reader, target = await prepared(db, (), "!oz help")
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).values(active=False))
    identity = await service.save("static-help", target)
    assert (await service.load(identity)).purpose == "static"
    service.discovery.bindings.audience.private = False
    with pytest.raises(AccessDenied):
        await service.load(identity)


@pytest.mark.parametrize("kind", ["plain", "unknown", "invalid"])
async def test_unbound_plain_text_and_unknown_controls_only_authorize_static_help(db, kind):
    text = {
        "plain": "ordinary conversation",
        "unknown": "!oz nonexistent",
        "invalid": "!oz send missing-literal-separator",
    }[kind]
    service, reader, target = await prepared(db, (), text)
    assert target.purpose == "static" and target.projects == ()
    assert await service.save(kind, target)
    if kind == "plain":
        # Plain unbound text opens the `!go` chooser, so it may name authorized projects.
        return
    with pytest.raises(AccessDenied):
        await service.prepare(target.source, ("project",))


async def test_same_immutable_target_deduplicates_concurrent_saves_without_reauthorizing_another_plan(
    db,
):
    service, reader, target = await prepared(db)
    ids = await asyncio.gather(*(service.save("same-source", target) for _ in range(4)))
    assert len(set(ids)) == 1 and await count(db, OutputDestination) == 1
    different = target.model_copy(update={"id": uuid4()})
    with pytest.raises(Conflict, match="key_reused"):
        await service.save("same-source", different)


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": 1, "text": "edited"},
        {"deleted": True},
        {"author_id": 8},
        {"topic": "different"},
    ],
)
async def test_changed_source_cannot_load_or_save_a_previous_target(db, changes):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    reader.messages[201] = target.source.model_copy(update=changes)
    with pytest.raises(AccessDenied):
        await service.load(identity)
    with pytest.raises(AccessDenied):
        await service.save("other", target)


@pytest.mark.parametrize("change", ["role", "project", "backend", "identity", "version"])
async def test_changed_local_enrollment_or_grants_refuse_previously_saved_output(db, change):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    async with db.sessions.begin() as session:
        if change == "role":
            await session.execute(
                update(Grant)
                .where(Grant.user_id == 8, Grant.project_id == "project")
                .values(active=False)
            )
        elif change == "project":
            await session.execute(
                update(EnrolledProject).where(EnrolledProject.id == "project").values(enabled=False)
            )
        else:
            await session.execute(
                update(EnrolledBackend)
                .where(EnrolledBackend.id == "backend")
                .values(
                    **(
                        {"enabled": False}
                        if change == "backend"
                        else {"identity": "changed"}
                        if change == "identity"
                        else {"version": "changed"}
                    )
                )
            )
    with pytest.raises((Conflict, AccessDenied)):
        await service.load(identity)


@pytest.mark.parametrize("change", ["revision", "members", "public", "bot"])
async def test_exact_audience_is_pinned_for_static_and_catalog_outputs(db, change):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    provider = service.discovery.bindings.audience
    if change == "revision":
        provider.revision = "audience:changed"
    elif change == "members":
        provider.users = frozenset({7, 8, 999})
    elif change == "public":
        provider.private = False
    else:
        original = provider.inspect

        async def injected(realm, channel, topic):
            return (await original(realm, channel, topic)).model_copy(
                update={"untrusted_bot_ids": frozenset({999})}
            )

        provider.inspect = injected
    with pytest.raises((Conflict, AccessDenied)):
        await service.load(identity)


async def test_topic_becoming_bound_holds_old_discovery_authority(db):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    await service.discovery.bindings.bind("realm", 7, 10, "Original work", REF)
    with pytest.raises(Conflict, match="became_bound"):
        await service.load(identity)
    with pytest.raises(Conflict, match="became_bound"):
        await service.save("other", target)


@pytest.mark.parametrize(
    "field,value",
    [
        ("realm_id", "foreign"),
        ("authorization_hash", "b" * 64),
        ("state", "revoked"),
        ("expires_at", 1),
    ],
)
async def test_target_metadata_must_match_encrypted_authorization(db, field, value):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    async with db.sessions.begin() as session:
        await session.execute(
            update(OutputDestination)
            .where(OutputDestination.id == identity)
            .values(**{field: value})
        )
    with pytest.raises(Conflict, match="destination_changed"):
        await service.load(identity)


async def test_revoked_destination_is_never_reactivated_by_duplicate_save(db):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    await service.revoke(identity)
    with pytest.raises(Conflict):
        await service.load(identity)
    with pytest.raises(Conflict):
        await service.save("source", target)


async def test_local_role_change_after_network_preflight_is_checked_in_write_transaction(db):
    service, reader, target = await prepared(db)
    original = service.authorize

    async def revoked_after_preflight(candidate):
        await original(candidate)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant)
                .where(Grant.user_id == 8, Grant.project_id == "project")
                .values(active=False)
            )

    service.authorize = revoked_after_preflight
    with pytest.raises(AccessDenied, match="local_authorization"):
        await service.save("source", target)
    assert await count(db, OutputDestination) == 0


async def test_fenced_target_creation_can_join_a_larger_transaction_and_roll_back(db):
    service, reader, target = await prepared(db)
    with pytest.raises(RuntimeError, match="injected"):
        async with db.sessions.begin() as session:
            await service.persist_in_session(session, "source", target)
            raise RuntimeError("injected after target before batch")
    assert await count(db, OutputDestination) == 0
    assert await service.save("source", target) == str(target.id)


async def test_expired_owner_cannot_create_or_revoke_authorization(db):
    service, reader, target = await prepared(db)
    identity = await service.save("source", target)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
    with pytest.raises(Conflict, match="lease"):
        await service.save("other", target.model_copy(update={"id": uuid4()}))
    with pytest.raises(Conflict, match="lease"):
        await service.revoke(identity)


async def test_expired_or_future_authorization_never_loads_for_delivery(db):
    service, reader, target = await prepared(db)
    stamp = time.time()
    expired = target.model_copy(update={"issued_at": stamp - 1000, "expires_at": stamp - 100})
    with pytest.raises(Conflict, match="expired"):
        await service.save("expired", expired)
    future = target.model_copy(update={"issued_at": stamp + 100, "expires_at": stamp + 200})
    with pytest.raises(Conflict, match="expired"):
        await service.save("future", future)


@pytest.mark.parametrize("change", ["duration", "purpose", "duplicate", "actor"])
async def test_structural_target_model_refuses_invalid_scope_even_before_storage(db, change):
    service, reader, target = await prepared(db)
    data = target.model_dump(mode="json")
    if change == "duration":
        data["expires_at"] = target.issued_at + 901
    elif change == "purpose":
        data["purpose"] = "static"
    elif change == "duplicate":
        data["projects"] *= 2
    else:
        data["source"]["author_id"] = 999
    with pytest.raises(ValidationError):
        DiscoveryTarget.model_validate(data)
