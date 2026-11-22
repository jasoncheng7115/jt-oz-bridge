"""Stored resource parts use own cursors and current authorization, never Native RPC."""

import copy

import pytest
from sqlalchemy import event, update

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.services.resource_history import ResourceHistory
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Grant
from jt_oz_bridge.storage.resource_models import ResourceResultRecord, ResourceTextRecord
from tests.integration.test_native_history import menu_token
from tests.integration.test_resource_execution_results import setup as resource_setup
from tests.integration.test_resource_publisher import rows, setup
from tests.integration.test_router import Source, message, send


async def test_history_keyset_does_not_skip_parts_from_the_same_native_turn(db):
    _publisher, collector, binding, _identity, execution, _audience = await setup(
        db, text=["resource part " + str(i) for i in range(13)]
    )
    history = ResourceHistory(collector.bindings)
    first = await history.page(binding.id, "realm", 7)
    assert len(first.items) == 10 and first.next_before is not None
    second = await history.page(binding.id, "realm", 7, before=first.next_before)
    assert len(second.items) == 3 and second.next_before is None
    assert [p.text for p in (*first.items, *second.items)] == [
        "resource part " + str(i) for i in range(12, -1, -1)
    ]
    assert len({p.record_id for p in (*first.items, *second.items)}) == 13
    assert len({p.native_message_id for p in first.items}) == 1
    selected = first.items[0]
    assert (
        await history.part(binding.id, "realm", 7, selected.record_id, selected.record_hash)
        == selected
    )
    assert collector.reader.calls == len(execution.submitted) == 1


async def test_existing_opaque_history_commands_work_with_resource_results_without_native_calls(db):
    _publisher, collector, binding, _identity, execution, _audience = await setup(
        db, text=["Native resource response"]
    )
    history = ResourceHistory(collector.bindings)
    source = Source()
    commands = HistoryCommands(
        history, TokenService(db, fence=collector.fence), source, message_limit=1000
    )
    router = CommandRouter(
        collector.bindings,
        source,
        CommandInbox(db, collector.fence.holder, collector.fence.fencing),
        history=commands,
    )
    menu = await send(router, source, message("!oz history", 201))
    token = menu_token(menu.text)
    choice = await send(router, source, message("!oz history " + token + " 1", 202))
    assert "Native resource response" in choice.text
    assert await router.route(source.messages[202]) == choice
    replay = await send(router, source, message("!oz history " + token + " 1", 203))
    assert "expired" in replay.text or "expired" in replay.text
    assert len(execution.submitted) == collector.reader.calls == 1


@pytest.mark.parametrize(
    "outcome,status",
    [
        ("succeeded", ExecutionState.IDLE),
        ("failed", ExecutionState.FAILED),
        ("interrupted", ExecutionState.IDLE),
    ],
)
async def test_terminal_history_is_explicitly_stored_state_not_fresh_execution_authority(
    db, outcome, status
):
    _publisher, collector, binding, identity, _execution, _audience = await setup(
        db, outcome=outcome
    )
    state = await ResourceHistory(collector.bindings).latest_state(binding.id, "realm", 7)
    assert (
        state.source == "stored-resource-result"
        and state.status == status
        and state.action_id == identity
    )
    collector.reader.alive = False
    assert await ResourceHistory(collector.bindings).latest_state(binding.id, "realm", 7) == state


@pytest.mark.parametrize("change", ["index", "part", "result", "foreign-selection"])
async def test_history_checks_archived_result_and_both_own_indices(db, change):
    _publisher, collector, binding, identity, _execution, _audience = await setup(db)
    history = ResourceHistory(collector.bindings)
    selected = (await history.page(binding.id, "realm", 7)).items[0]
    async with db.sessions.begin() as session:
        if change == "index":
            await session.execute(update(ResourceResultRecord).values(ordinal=2))
        elif change == "part":
            await session.execute(update(ResourceTextRecord).values(part_index=10))
        elif change == "result":
            saved = await session.get(Action, identity)
            value = copy.deepcopy(saved.native_result)
            value["evidence"]["turn"]["text"][0]["text"] = "substituted"
            saved.native_result = value
    with pytest.raises(ValueError):
        await history.part(
            binding.id,
            "realm",
            7,
            selected.record_id,
            "e" * 64 if change == "foreign-selection" else selected.record_hash,
        )


@pytest.mark.parametrize("change", ["view", "audience", "public", "revision"])
async def test_current_scope_and_grants_are_required_for_stored_history(db, change):
    _publisher, collector, binding, _identity, _execution, audience = await setup(db)
    history = ResourceHistory(collector.bindings)
    selected = (await history.page(binding.id, "realm", 7)).items[0]
    if change == "audience":
        audience.users = frozenset({7, 8, 999})
    elif change == "public":
        audience.private = False
    else:
        async with db.sessions.begin() as session:
            if change == "view":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            else:
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(revision=2)
                )
    with pytest.raises((AccessDenied, Conflict)):
        await history.part(binding.id, "realm", 7, selected.record_id, selected.record_hash)


async def test_text_index_write_failure_rolls_back_result_and_state_and_parent_index(db):
    collector, _binding, identity, _reader, execution, _audience = await resource_setup(db)

    def fail(*args):
        raise OSError("synthetic text-index write failure")

    event.listen(ResourceTextRecord, "before_insert", fail)
    try:
        with pytest.raises(OSError):
            await collector.collect(identity, "realm")
    finally:
        event.remove(ResourceTextRecord, "before_insert", fail)
    assert not await rows(db, ResourceResultRecord) and not await rows(db, ResourceTextRecord)
    async with db.sessions() as session:
        action = await session.get(Action, identity)
    assert action.state == "admitted" and not action.native_result
    await collector.collect(identity, "realm")
    assert len(await rows(db, ResourceTextRecord)) == len(execution.submitted) == 1
