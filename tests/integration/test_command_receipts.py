import asyncio
import time
from contextlib import closing

import pytest
from sqlalchemy import text, update

from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from tests.support import bound


def message(**changes):
    return HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic="Original work",
        message_id=101,
        revision=0,
        author_id=7,
        text="!oz menu",
    ).model_copy(update=changes)


async def inbox(db):
    fencing = await DurableStore(db).acquire_lease("test")
    assert fencing
    return CommandInbox(db, "test", fencing)


async def test_deferred_catalog_preserves_its_identity_and_rechecks_the_original_source(db):
    service = await inbox(db)
    source = message(text="!oz projects")
    claim = await service.claim(source, "projects")
    await service.defer_catalog(claim)
    with pytest.raises(Conflict):
        await service.finish(claim, {"old_attempt": True})
    edited = await service.claim(source.model_copy(update={"revision": 1}), "projects")
    assert edited.status == "changed"
    again = await service.claim(source, "projects")
    assert again.id == claim.id and again.version == claim.version + 2
    assert again.status == "claimed"
    await service.finish(again, {"complete": True})
    assert (await service.claim(source, "projects")).status == "replay"


async def test_discarded_catalog_plan_can_resume_after_a_fenced_restart(db):
    old = await inbox(db)
    source = message(text="!oz projects")
    claim = await old.claim(source, "projects")
    await old.defer_catalog(claim)
    store = DurableStore(db)
    await store.release_lease(old.holder, old.fencing)
    fence = await store.acquire_lease("replacement")
    current = CommandInbox(db, "replacement", fence)
    resumed = await current.claim(source, "projects", recovered=True)
    assert resumed.status == "claimed" and resumed.id == claim.id
    with pytest.raises(Conflict):
        await old.defer_catalog(claim)


@pytest.mark.parametrize("command", ["stop", "new", "confirm", "lang"])
async def test_mutating_commands_never_get_the_catalog_retry_barrier(db, command):
    service = await inbox(db)
    claim = await service.claim(message(text="!oz " + command), command)
    with pytest.raises(Conflict):
        await service.defer_catalog(claim)


async def test_token_plan_and_receipt_commit_or_rollback_together(db):
    from jt_oz_bridge.services.tokens import TokenService
    from jt_oz_bridge.storage.control_models import ControlToken

    service = await inbox(db)
    tokens = TokenService(db, fence=service.fence)
    source = message(text="!oz projects")
    claim = await service.claim(source, "projects")
    with tokens.planning() as plan:
        opaque = await tokens.issue("discover-menu", "realm", 7, {"items": ["original"]})
        async with db.sessions() as session:
            assert (
                await session.get(
                    ControlToken,
                    __import__("jt_oz_bridge.security.admin", fromlist=["token_hash"]).token_hash(
                        opaque
                    ),
                )
                is None
            )

        async def fail_after_token_write(session):
            await plan.commit(session)
            raise Conflict("synthetic_commit_failure")

        with pytest.raises(Conflict, match="synthetic_commit_failure"):
            await service.finish(claim, {"text": opaque}, commit=fail_after_token_write)
    assert (await service.find("realm", 101)).state == "processing"
    with pytest.raises(Conflict):
        await tokens.inspect(opaque, "discover-menu", "realm", 7)
    await service.defer_catalog(claim)


async def test_consumed_menu_stays_usable_until_its_successor_reply_commits(db):
    from jt_oz_bridge.services.tokens import TokenService

    service = await inbox(db)
    tokens = TokenService(db, fence=service.fence)
    opaque = await tokens.issue("discover-menu", "realm", 7, {"items": ["original"]})
    with tokens.planning():
        await tokens.consume(opaque, "discover-menu", "realm", 7)
    # A discarded read-only plan neither consumes the old menu nor emits a new one.
    await tokens.inspect(opaque, "discover-menu", "realm", 7)
    claim = await service.claim(message(text="!oz choose " + opaque + " 1"), "choose")
    with tokens.planning() as plan:
        await tokens.consume(opaque, "discover-menu", "realm", 7)
        await service.finish(claim, {"complete": True}, commit=plan.commit)
    with pytest.raises(Conflict):
        await tokens.inspect(opaque, "discover-menu", "realm", 7)


async def test_restoring_a_snapshot_holds_even_provably_unpublished_catalog_retries(db):
    import sqlite3
    from uuid import uuid4

    from jt_oz_bridge.services.backups import _recover_copy

    service = await inbox(db)
    claim = await service.claim(message(text="!oz projects"), "projects")
    await service.defer_catalog(claim)
    with (
        closing(sqlite3.connect(str(db.engine.url.database))) as original,
        closing(sqlite3.connect(":memory:")) as copy,
    ):
        original.backup(copy)
        result = _recover_copy(copy, str(uuid4()))
        assert result["commands_held"] == 1
        assert copy.execute("SELECT state FROM command_receipts").fetchone()[0] == "held"
        assert original.execute("SELECT state FROM command_receipts").fetchone()[0] == "deferred"


async def test_concurrent_receipts_have_one_owner_and_one_cached_encrypted_response(db):
    first = await inbox(db)
    second = CommandInbox(db, first.holder, first.fencing)
    claims = await asyncio.gather(
        *[service.claim(message(), "menu") for service in [first, second] * 4]
    )
    assert sum(claim.status == "claimed" for claim in claims) == 1
    assert sum(claim.status == "busy" for claim in claims) == 7
    winner = next(claim for claim in claims if claim.status == "claimed")
    response = {"text": "PRIVATE_RETURNED_TOKEN_8a3a319e"}
    await first.finish(winner, response)
    replay = await second.claim(message(), "menu")
    assert replay.status == "replay" and replay.response == response
    assert replay.id == winner.id and replay.version == winner.version + 1
    with pytest.raises(Conflict):
        await first.finish(winner, response)
    async with db.engine.connect() as connection:
        blob = await connection.scalar(text("SELECT response FROM command_receipts"))
        assert isinstance(blob, bytes) and response["text"].encode() not in blob


async def test_edited_control_message_never_claims_another_attempt(db):
    service = await inbox(db)
    claim = await service.claim(message(), "menu")
    await service.finish(claim, {"text": "original"})
    edited = await service.claim(message(revision=1, text="!oz stop"), "stop")
    assert edited.status == "changed" and edited.response == {} and edited.id == claim.id
    assert (await service.claim(message(), "menu")).response == {"text": "original"}


async def test_recovered_historical_commands_are_held_and_not_auto_claimed(db):
    service = await inbox(db)
    held = await service.claim(message(text="!oz stop"), "stop", recovered=True)
    assert held.status == "held"
    assert (await service.claim(message(text="!oz stop"), "stop")).status == "held"
    with pytest.raises(Conflict):
        await service.finish(held, {"unsafe": "not-executed"})


async def test_crash_between_claim_and_finish_is_ambiguous_never_replayed(db):
    old = await inbox(db)
    claim = await old.claim(message(), "menu")
    store = DurableStore(db)
    await store.release_lease(old.holder, old.fencing)
    fencing = await store.acquire_lease("replacement")
    current = CommandInbox(db, "replacement", fencing)
    assert (await current.claim(message(), "menu")).status == "ambiguous"
    assert await current.recover(cutoff=time.time()) == 1
    assert (await current.claim(message(), "menu")).status == "ambiguous"
    with pytest.raises(Conflict, match="lease"):
        await old.finish(claim, {"text": "stale-owner"})
    current_claim = await current.claim(message(message_id=102), "menu")
    assert await current.recover(cutoff=time.time()) == 0
    await current.finish(current_claim, {"text": "current"})


async def test_scope_and_actor_replay_are_rejected(db):
    service = await inbox(db)
    await service.claim(message(), "menu")
    for changed in [dict(author_id=8), dict(channel_id=11), dict(topic="moved")]:
        with pytest.raises(Conflict, match="scope"):
            await service.claim(message(**changed), "menu")
    another = await service.claim(message(realm_id="another"), "menu")
    assert another.status == "claimed"


async def test_binding_move_invalidates_claim_and_finish(db):
    _bindings, binding, _control, _audience = await bound(db)
    service = await inbox(db)
    claim = await service.claim(message(), "menu", binding_id=binding.id, binding_revision=1)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).where(Binding.id == binding.id).values(revision=2))
    with pytest.raises(Conflict, match="binding"):
        await service.finish(claim, {"text": "must-not-send"})
    with pytest.raises(Conflict, match="binding"):
        await service.claim(message(), "menu", binding_id=binding.id, binding_revision=1)


async def test_database_failure_does_not_create_command_ownership(db):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    service = await inbox(db)

    def fail(_session):
        raise RuntimeError("synthetic commit failure")

    event.listen(Session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="commit failure"):
            await service.claim(message(), "menu")
    finally:
        event.remove(Session, "before_commit", fail)
    assert await service.find("realm", 101) is None
    assert (await service.claim(message(), "menu")).status == "claimed"


async def test_invalid_bot_deleted_or_unfenced_claims_cannot_own_commands(db):
    service = await inbox(db)
    for changes in [dict(is_bot=True), dict(deleted=True)]:
        with pytest.raises(AccessDenied):
            await service.claim(message(**changes), "menu")
    with pytest.raises(Conflict):
        await CommandInbox(db, service.holder, service.fencing + 1).claim(message(), "menu")
    with pytest.raises(ValueError):
        await service.claim(message(), "arbitrary_secret_string")
    with pytest.raises(ValueError):
        await service.claim(message(), "menu", binding_id="missing")
    with pytest.raises(ValueError):
        await service.recover(cutoff=float("inf"))
    async with db.sessions() as session:
        assert await session.get(CommandReceipt, "missing") is None


async def test_failure_after_local_effect_remains_ambiguous_on_same_run(db):
    service = await inbox(db)
    claim = await service.claim(message(), "menu")
    await service.abandon(claim)
    assert (await service.claim(message(), "menu")).status == "ambiguous"
    with pytest.raises(Conflict):
        await service.finish(claim, {"text": "cannot-claim-success-after-uncertainty"})
    with pytest.raises(Conflict):
        await service.abandon(claim)


async def test_claim_command_must_match_literal_source_position(db):
    service = await inbox(db)
    for source, command in [
        ("plain prompt", "menu"),
        ("```\n!oz stop\n```", "stop"),
        ("!oz menu", "stop"),
        ("!oz send -- text", "send"),
    ]:
        with pytest.raises(ValueError, match="match_source"):
            await service.claim(message(text=source), command)
    unknown = await service.claim(message(text="!oz not-a-command"), "unknown")
    assert unknown.status == "claimed"
