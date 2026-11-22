import asyncio

import pytest
from sqlalchemy import select, text

from jt_oz_bridge.domain.models import ActionState as S
from jt_oz_bridge.i18n import Translator, get_locale, save_locale
from jt_oz_bridge.security.policy import AccessDenied, Permission, Policy
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Action, Checkpoint, Delivery, Grant, InputEvent


@pytest.mark.parametrize(
    "language, expected",
    [
        ("zh-tw", "zh-TW"),
        ("zh_Hant", "zh-TW"),
        ("zh-HK", "zh-TW"),
        ("en-US", "en"),
        ("ja", None),
        ("zh-cn", None),
    ],
)
def test_platform_language_uses_only_supported_explicit_locale_codes(
    monkeypatch, language, expected
):
    import json
    from pathlib import Path

    import jt_oz_bridge.i18n as module

    raw = {
        "format": "jt-oz-user-languages-v1",
        "realm_id": "realm",
        "generated_at": 100.0,
        "users": {"7": language},
    }
    monkeypatch.setattr(module, "root_bytes", lambda *a, **kw: json.dumps(raw).encode())
    assert (
        module.platform_locale(Path("/synthetic/root-managed.json"), "realm", 7, now=101)
        == expected
    )


@pytest.mark.parametrize(
    "change",
    ["stale", "future", "realm", "format", "extra", "invalid-time", "malformed", "duplicate"],
)
def test_untrusted_or_stale_platform_language_never_overrides_fallback(monkeypatch, change):
    import json
    from pathlib import Path

    import jt_oz_bridge.i18n as module

    raw = {
        "format": "jt-oz-user-languages-v1",
        "realm_id": "realm",
        "generated_at": 100.0,
        "users": {"7": "zh-tw"},
    }
    if change == "stale":
        raw["generated_at"] = -500
    elif change == "future":
        raw["generated_at"] = 200
    elif change == "realm":
        raw["realm_id"] = "another"
    elif change == "format":
        raw["format"] = "untrusted"
    elif change == "extra":
        raw["unapproved"] = True
    elif change == "invalid-time":
        raw["generated_at"] = True
    data = json.dumps(raw).encode()
    if change == "malformed":
        data = b"not-json"
    elif change == "duplicate":
        data = b'{"format":"first","format":"second"}'
    monkeypatch.setattr(module, "root_bytes", lambda *a, **kw: data)
    assert module.platform_locale(Path("/synthetic/root-managed.json"), "realm", 7, now=101) is None


async def test_explicit_personal_language_wins_over_platform_and_topic(db):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from jt_oz_bridge.domain.execution import HumanMessage
    from jt_oz_bridge.i18n import message_locale

    message = HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic="Original work",
        message_id=101,
        revision=0,
        author_id=7,
        text="!help",
    )
    reader = SimpleNamespace(preferred_locale=AsyncMock(return_value="zh-TW"))
    assert await message_locale(db, reader, message, "en") == "zh-TW"
    await save_locale(db, "user:realm:7", "en")
    reader.preferred_locale.reset_mock()
    assert await message_locale(db, reader, message, "zh-TW") == "en"
    reader.preferred_locale.assert_not_called()


async def test_concurrent_duplicate_events_actions_and_deliveries(db):
    store = DurableStore(db)
    await store.enroll_queue("r", "q", -1)
    receipts = await asyncio.gather(
        *[store.ingest("r", "q", i, "same", 0, {"x": 1}) for i in range(8)]
    )
    assert len({r[0] for r in receipts}) == 1
    assert sum(r[1] for r in receipts) == 1
    actions = await asyncio.gather(*[store.enqueue("same", "b", 1, 7, {"x": 1}) for _ in range(8)])
    deliveries = await asyncio.gather(
        *[store.queue_delivery("same", "b", 1, {"x": 1}) for _ in range(8)]
    )
    assert len(set(actions)) == len(set(deliveries)) == 1


async def test_failed_inbox_commit_cannot_advance_checkpoint(db):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    store = DurableStore(db)
    await store.enroll_queue("r", "q", -1)

    def fail(_):
        raise RuntimeError("injected crash before commit")

    event.listen(Session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="injected crash"):
            await store.ingest("r", "q", 100, "message", 0, {"text": "never acknowledged"})
    finally:
        event.remove(Session, "before_commit", fail)
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, "r")).event_id == -1
        assert (await session.scalar(select(InputEvent.id))) is None


async def test_two_action_dispatch_claims_only_one_wins(db):
    store = DurableStore(db)
    action = await store.enqueue("same", "b", 1, 7, {})
    results = await asyncio.gather(
        *[store.transition(action, S.QUEUED, S.DISPATCHING, 1) for _ in range(8)]
    )
    assert sum(results) == 1


async def test_real_migration_idempotent_and_wal(db):
    await migrate(db.engine)
    assert await db.ready()
    async with db.engine.connect() as conn:
        assert (await conn.execute(text("PRAGMA journal_mode"))).scalar() == "wal"
        assert (await conn.execute(text("PRAGMA synchronous"))).scalar() == 2


async def test_dedupe_and_checkpoint_atomicity(db):
    store = DurableStore(db)
    await store.enroll_queue("realm", "q1", -1)
    first = await store.ingest("realm", "q1", 1, "m1", 0, {"text": "hello"})
    second = await store.ingest("realm", "q1", 2, "m1", 0, {"text": "hello"})
    assert first[0] == second[0] and first[1] and not second[1]
    with pytest.raises(Conflict):
        await store.ingest("realm", "q1", 3, "m1", 0, {"text": "different"})
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, "realm")).event_id == 2
        assert len((await session.scalars(select(InputEvent))).all()) == 1
    await store.enroll_queue("realm", "q2", -1)
    with pytest.raises(Conflict):
        await store.ingest("realm", "q1", 100, "m2", 0, {})


async def test_action_recovery_after_new_connection_and_no_blind_replay(db):
    store = DurableStore(db)
    a = await store.enqueue("key1", "binding", 1, 7, {"text": "edit"})
    b = await store.enqueue("key2", "binding", 1, 7, {"text": "second"})
    assert await store.transition(a, S.QUEUED, S.DISPATCHING, 1)
    assert not await store.transition(a, S.QUEUED, S.DISPATCHING, 1)
    other = Database(str(db.engine.url), cipher=db.cipher)
    try:
        assert await other.ready()
        await DurableStore(other).recover()
        async with other.sessions() as session:
            assert (await session.get(Action, a)).state == S.AMBIGUOUS
            assert (await session.get(Action, b)).state == S.HELD
        with pytest.raises(Conflict):
            await store.transition(a, S.AMBIGUOUS, S.QUEUED, 3)
    finally:
        await other.close()


async def test_client_action_digest_and_recovered_hold(db):
    store = DurableStore(db)
    key = await store.enqueue("once", "bind", 1, 7, {"x": 1}, recovered=True)
    assert await store.enqueue("once", "bind", 1, 7, {"x": 1}) == key
    with pytest.raises(Conflict):
        await store.enqueue("once", "bind", 2, 7, {"x": 1})
    async with db.sessions() as session:
        assert (await session.get(Action, key)).state == S.HELD


async def test_outbox_uncertainty_survives_recovery(db):
    store = DurableStore(db)
    key = await store.queue_delivery("once", "bind", 1, {"text": "output"})
    async with db.sessions.begin() as session:
        delivery = await session.get(Delivery, key)
        delivery.state = "sending"
    await store.recover()
    assert await store.queue_delivery("once", "bind", 1, {"text": "output"}) == key
    async with db.sessions() as session:
        assert (await session.get(Delivery, key)).state == "ambiguous"
    with pytest.raises(Conflict):
        await store.queue_delivery("once", "bind", 2, {"text": "output"})


async def test_lease_second_consumer_rejected_and_fenced(db):
    store = DurableStore(db)
    results = await asyncio.gather(store.acquire_lease("a"), store.acquire_lease("b"))
    assert sum(value is not None for value in results) == 1
    winner = "a" if results[0] else "b"
    fencing = results[0] or results[1]
    assert await store.renew_lease(winner, fencing)
    await store.release_lease(winner, fencing)
    next_fence = await store.acquire_lease("new")
    assert next_fence > fencing
    assert not await store.renew_lease(winner, fencing)


async def test_role_scopes_bot_rejection_and_output_audience(db):
    policy = Policy(db)
    async with db.sessions.begin() as session:
        session.add_all(
            [
                Grant(realm_id="r", user_id=7, project_id="p", role="operator"),
                Grant(realm_id="r", user_id=8, project_id="p", role="approver"),
            ]
        )
    await policy.require("r", 7, "p", Permission.OPERATE)
    await policy.require("r", 8, "p", Permission.APPROVE)
    for realm, user, project, permission, bot in [
        ("r", 7, "p", Permission.APPROVE, False),
        ("another", 7, "p", Permission.VIEW, False),
        ("r", 7, "secret", Permission.VIEW, False),
        ("r", 7, "p", Permission.OPERATE, True),
    ]:
        with pytest.raises(AccessDenied):
            await policy.require(realm, user, project, permission, is_bot=bot)
    await policy.require_audience("r", {7, 8}, "p", private=True)
    with pytest.raises(AccessDenied):
        await policy.require_audience("r", {7, 9}, "p", private=True)
    with pytest.raises(AccessDenied):
        await policy.require_audience("r", {7}, "p", private=False)


async def test_locale_persists_and_shared_scope_independent(db):
    await save_locale(db, "user:r:7", "zh-TW")
    await save_locale(db, "binding:one", "en")
    assert await get_locale(db, "user:r:7") == "zh-TW"
    assert await get_locale(db, "binding:one") == "en"
    assert await get_locale(db, "unknown") == "en"
    t = Translator()
    assert "No new one" in t.render("binding.missing")
    assert "沒有另外建立" in t.render("binding.missing", "zh-TW")
    assert t.render("missing.key") == "The request could not be completed."
    with pytest.raises(ValueError):
        t.render("binding.confirm", backend="one")
