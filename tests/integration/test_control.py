import asyncio
import time

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.control import (
    Choice,
    FieldAnswer,
    InteractionSnapshot,
    QuestionField,
    validate_answers,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.services.tokens import MenuService, TokenService
from jt_oz_bridge.storage.control_models import (
    Binding,
    ControlToken,
    PendingInteraction,
)
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action
from tests.support import REF, bound, service


async def test_bind_original_running_session_only_inspects_and_never_replaces(db):
    bindings, binding, control, audience = await bound(db)
    assert binding.session_id == REF.upstream_session_id
    assert control.calls == [("snapshot", REF)]
    with pytest.raises(Conflict, match="writable"):
        await bindings.bind("realm", 7, 10, "Another topic", REF)
    await bindings.unbind(binding.id, "realm", 7, 1)
    assert all(call[0] == "snapshot" for call in control.calls)
    rebound = await bindings.bind("realm", 7, 10, "Original work", REF)
    assert rebound.id != binding.id and rebound.session_id == binding.session_id


async def test_identity_change_and_cross_project_scope_fail_before_binding(db):
    bindings, control, audience = await service(db)
    with pytest.raises(AccessDenied):
        await bindings.bind(
            "realm", 7, 10, "work", REF.model_copy(update={"backend_identity": "replacement"})
        )
    assert control.calls == []
    control.ref = REF.model_copy(update={"upstream_session_id": "replacement"})
    with pytest.raises(Conflict, match="identity"):
        await bindings.bind("realm", 7, 10, "work", REF)


async def test_broader_audience_cannot_bind_or_receive_pending_output(db):
    bindings, control, audience = await service(db)
    audience.users = frozenset({7, 8, 99})
    with pytest.raises(AccessDenied):
        await bindings.bind("realm", 7, 10, "work", REF)
    audience.users = frozenset({7, 8})
    binding = await bindings.bind("realm", 7, 10, "work", REF)
    audience.revision = "audience:2"
    with pytest.raises(Conflict, match="output held"):
        await bindings.audience_for_output(binding)


async def test_move_is_whole_topic_authorized_and_invalidates_tokens(db):
    bindings, binding, control, audience = await bound(db)
    tokens = TokenService(db)
    token = await tokens.issue(
        "confirm", "realm", 7, {"operation": "preview"}, binding_id=binding.id, binding_revision=1
    )
    with pytest.raises(Conflict, match="single-message"):
        await bindings.move(binding.id, "realm", 7, 1, 11, "moved", whole_topic=False)
    await bindings.move(binding.id, "realm", 7, 1, 11, "moved", whole_topic=True)
    with pytest.raises(Conflict, match="binding changed"):
        await tokens.consume(token, "confirm", "realm", 7)
    async with db.sessions() as session:
        moved = await session.get(Binding, binding.id)
        assert moved.revision == 2 and moved.dispatch_paused


async def test_menu_actor_scope_expiry_and_single_use(db):
    tokens = TokenService(db)
    menus = MenuService(tokens)
    token, entries, more = await menus.page("r", 7, [{"id": str(i)} for i in range(13)])
    assert len(entries) == 10 and more == 10
    with pytest.raises(Conflict):
        await menus.choose(token, "r", 8, 1)
    with pytest.raises(Conflict):
        await menus.choose(token, "r", 7, 11)
    assert (await menus.choose(token, "r", 7, 2))["id"] == "1"
    with pytest.raises(Conflict):
        await menus.choose(token, "r", 7, 2)
    expired = await tokens.issue("confirm", "r", 7, {})
    async with db.sessions.begin() as session:
        await session.execute(update(ControlToken).values(expires_at=time.time() - 1))
    with pytest.raises(Conflict):
        await tokens.consume(expired, "confirm", "r", 7)


async def test_two_approvers_only_queue_one_decision(db):
    bindings, binding, control, audience = await bound(db)
    interactions = InteractionService(bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="permission-1",
        generation="g1",
        kind="permission",
        pending=True,
        description="write file",
    )
    control.requests["permission-1"] = snapshot
    interaction = await interactions.observe(binding, snapshot)
    tokens = [await interactions.issue(interaction, "realm", user) for user in (7, 8)]
    results = await asyncio.gather(
        *[
            interactions.reply(token, "realm", user, decision="once")
            for token, user in zip(tokens, (7, 8), strict=True)
        ],
        return_exceptions=True,
    )
    assert sum(isinstance(result, str) for result in results) == 1
    async with db.sessions() as session:
        actions = (await session.scalars(select(Action))).all()
        assert len(actions) == 1 and actions[0].state == "queued"
        saved = await session.get(PendingInteraction, interaction)
        assert saved.state == "reply_queued" and saved.winner_user_id in {7, 8}
    assert all(call[0] in {"snapshot", "interaction"} for call in control.calls)


async def test_tui_resolution_and_broad_permission_never_auto_allow(db):
    bindings, binding, control, audience = await bound(db)
    interactions = InteractionService(bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="p",
        generation="g1",
        kind="permission",
        pending=True,
        description="run tool",
    )
    control.requests["p"] = snapshot
    interaction = await interactions.observe(binding, snapshot)
    token = await interactions.issue(interaction, "realm", 7)
    with pytest.raises(AccessDenied, match="broad"):
        await interactions.reply(token, "realm", 7, decision="always")
    control.resolved = True
    with pytest.raises(Conflict, match="resolved upstream"):
        await interactions.reply(token, "realm", 7, decision="once")
    await interactions.observe(binding, snapshot)
    with pytest.raises(Conflict, match="resolved"):
        await interactions.issue(interaction, "realm", 7)
    async with db.sessions() as session:
        assert await session.scalar(select(Action.id)) is None


async def test_grandchild_form_drafts_validate_before_one_complete_reply(db):
    bindings, binding, control, audience = await bound(db)
    interactions = InteractionService(bindings)
    child = REF.model_copy(update={"upstream_session_id": "grandchild"})
    control.descendants = (REF.model_copy(update={"upstream_session_id": "child"}), child)
    fields = (
        QuestionField(
            id="mode", label="Mode", kind="single", choices=(Choice(id="plan", label="Plan"),)
        ),
        QuestionField(
            id="checks",
            label="Checks",
            kind="multi",
            choices=(
                Choice(id="unit", label="Unit"),
                Choice(id="integration", label="Integration"),
            ),
        ),
        QuestionField(id="note", label="Note", kind="text", min_length=3),
    )
    snapshot = InteractionSnapshot(
        reference=child,
        upstream_request_id="f",
        generation="g1",
        kind="form",
        pending=True,
        description="questions",
        fields=fields,
    )
    control.requests["f"] = snapshot
    interaction = await interactions.observe(binding, snapshot)
    token = await interactions.issue(interaction, "realm", 7)
    revision = await interactions.save_answer(
        token, "realm", 7, "mode", FieldAnswer(selected=("plan",))
    )
    with pytest.raises(ValueError, match="missing"):
        await interactions.reply(token, "realm", 7)
    revision = await interactions.save_answer(
        token, "realm", 7, "checks", FieldAnswer(selected=("unit", "integration")), revision
    )
    revision = await interactions.save_answer(
        token, "realm", 7, "note", FieldAnswer(text="original text"), revision
    )
    action = await interactions.reply(token, "realm", 7)
    async with db.sessions() as session:
        queued = await session.get(Action, action)
        assert queued.payload["reference"]["upstream_session_id"] == "grandchild"
        assert queued.payload["answers"]["note"]["text"] == "original text"
    with pytest.raises(Conflict):
        await interactions.reply(token, "realm", 7)


@pytest.mark.parametrize(
    "field,answer",
    [
        (
            QuestionField(id="s", label="s", kind="single", choices=(Choice(id="a", label="a"),)),
            FieldAnswer(selected=("a", "a")),
        ),
        (
            QuestionField(id="s", label="s", kind="single", choices=(Choice(id="a", label="a"),)),
            FieldAnswer(text="unsupported"),
        ),
        (QuestionField(id="t", label="t", kind="text", min_length=3), FieldAnswer(text="x")),
    ],
)
def test_invalid_answers_never_silently_default(field, answer):
    with pytest.raises(ValueError):
        validate_answers((field,), {field.id: answer})


async def test_new_optional_permission_details_do_not_invalidate_original_form_snapshot_hash(db):
    from jt_oz_bridge.storage.durable import digest

    bindings, binding, control, _audience = await bound(db)
    interactions = InteractionService(bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="legacy-form",
        generation="g1",
        kind="form",
        pending=True,
        description="legacy shape",
        fields=(QuestionField(id="note", label="Note", kind="text"),),
    )
    control.requests["legacy-form"] = snapshot
    old = snapshot.model_dump(mode="json")
    old.pop("permission_details")
    identity = digest(
        {
            "reference": snapshot.reference.model_dump(),
            "request": snapshot.upstream_request_id,
            "generation": snapshot.generation,
        }
    )
    async with db.sessions.begin() as session:
        session.add(
            PendingInteraction(
                id="legacy-form-row",
                identity_key=identity,
                binding_id=binding.id,
                binding_revision=1,
                snapshot=old,
                snapshot_hash=digest(old),
                state="pending",
                expires_at=__import__("time").time() + 900,
            )
        )
    assert await interactions.observe(binding, snapshot) == "legacy-form-row"
    token = await interactions.issue("legacy-form-row", "realm", 7)
    assert token
