"""One-message permission replies: the notice shows the request and its four-digit code.

Real ownDB, synthetic Native and Zulip only. No Human, mobile or Native approval is produced.
"""

import json
from html import unescape
from pathlib import Path

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.domain.control import InteractionSnapshot, QuestionField
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import ParsedInput, parse_input
from jt_oz_bridge.services import interactions as interaction_module
from jt_oz_bridge.services import permission_commands
from jt_oz_bridge.services.interactions import InteractionService, short_code
from jt_oz_bridge.services.permission_commands import permission_notice, permission_widget
from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from tests.contract.test_v2_execution import REF as V2_REF
from tests.integration.test_consumer_runtime import rows, visible
from tests.integration.test_descendant_pending_notices import deliver_all, tree_pipeline
from tests.integration.test_dispatch import dispatcher
from tests.integration.test_dispatch import message as dispatch_message
from tests.integration.test_permission_commands import pending
from tests.integration.test_router import count, message, router, send
from tests.integration.test_v2_dispatch import worker
from tests.support import REF


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


def permission(reference=REF, identity="request", **changes):
    return InteractionSnapshot(
        reference=reference,
        upstream_request_id=identity,
        generation="source:1",
        kind="permission",
        pending=True,
        description="Run approved project checks",
        operation="shell.execute",
        resources=("pytest -q",),
    ).model_copy(update=changes)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("!ok 1234", ParsedInput("command", "approve", "1234 once")),
        ("!ok 1234 once", ParsedInput("command", "approve", "1234 once")),
        ("!ok 1234 always", ParsedInput("command", "approve", "1234 always")),
        ("!ok", ParsedInput("command", "confirm", "")),
        ("!no 1234", ParsedInput("command", "deny", "1234")),
        ("!no 1234 not on production", ParsedInput("command", "deny", "1234 not on production")),
        ("!okay", ParsedInput("prompt", arguments="!okay")),
    ],
)
def test_quick_replies_are_approve_and_deny_only_in_a_connected_topic(text, expected):
    assert parse_input(text, bound=True) == expected
    unbound = parse_input(text)
    # Before a topic is connected `!ok` can only answer Bridge's own question.
    assert unbound.kind == "ignore" or (unbound.command == "confirm" and text.startswith("!ok"))


def test_code_is_four_digits_and_stable():
    assert short_code("a") == short_code("a")
    assert all(len(short_code(str(n))) == 4 for n in range(200))


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_notice_and_buttons_carry_the_request_and_the_same_reply(locale):
    tr = Translator()
    snapshot = permission()
    code = short_code("interaction")
    text = unescape(permission_notice(tr, snapshot, "interaction", locale))
    assert "shell.execute" in text and "Run approved project checks" in text
    assert "pytest -q" in text and f"!ok {code}" in text and f"!no {code}" in text
    widget = json.loads(permission_widget(tr, snapshot, "interaction", locale))
    assert widget["widget_type"] == "zform"
    heading = widget["extra_data"]["heading"]
    assert "shell.execute" in heading and "pytest -q" in heading
    assert [choice["reply"] for choice in widget["extra_data"]["choices"]] == [
        f"!ok {code}",
        f"!no {code}",
    ]


def test_forms_and_oversized_requests_get_no_quick_reply():
    tr = Translator()
    form = permission(
        kind="form",
        operation=None,
        resources=(),
        fields=(QuestionField(id="a", label="A", kind="text"),),
    )
    assert permission_notice(tr, form, "interaction", "en") is None
    large = permission(resources=("x" * 4000,))
    assert permission_notice(tr, large, "interaction", "en") is None
    assert permission_widget(tr, large, "interaction", "en") is None


async def test_runtime_notice_posts_the_request_with_buttons_once(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, binding, _calls = env
        nodes[REF].add_request(permission())
        await pipeline.pending_notices_once()
        await pipeline.pending_notices_once()
        (saved,) = await rows(db, PendingInteraction)
        code = short_code(saved.id)
        deliveries = await deliver_all(pipeline, db)
        assert len(deliveries) == len(server.posts) == 1
        body = visible(server.posts[0]["content"])
        assert "shell.execute" in body and "pytest -q" in body and f"!ok {code}" in body
        widget = json.loads(deliveries[0].payload["widget"])
        assert widget["extra_data"]["choices"][0]["reply"] == f"!ok {code}"
        assert deliveries[0].payload["topic"] == binding.topic
        assert not await rows(db, Action)
        # Restart: the same request is never announced twice.
        pipeline._announced.clear()
        await pipeline.pending_notices_once()
        assert len(await rows(db, Delivery)) == 1


async def test_ok_with_the_code_queues_one_once_decision_from_that_message(db):
    service, binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    reply = await send(service, source, message(f"!ok {short_code(identity)}", 103))
    assert "Received" in reply.text
    assert await service.route(source.messages[103]) == reply
    async with db.sessions() as session:
        (action,) = (await session.scalars(select(Action))).all()
    assert action.payload["decision"] == "once" and action.binding_id == binding.id
    assert action.payload["source"]["text"] == f"!ok {short_code(identity)}"
    again = await send(service, source, message(f"!ok {short_code(identity)}", 104))
    assert "already answered" in again.text and await count(db, Action) == 1


async def test_no_with_the_code_rejects_with_the_reason(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    await send(service, source, message(f"!no {short_code(identity)} Not on production", 103))
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
    assert action.payload["decision"] == "reject"
    assert action.payload["reason"] == "Not on production"


async def test_wrong_code_broad_approval_and_bare_ok_send_nothing(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    code = short_code(identity)
    wrong = "1000" if code != "1000" else "1001"
    assert "already answered" in (await send(service, source, message(f"!ok {wrong}"))).text
    broad = await send(service, source, message(f"!ok {code} always", 102))
    assert "permission" in broad.text
    bare = await send(service, source, message("!ok", 103))
    assert "Permission" in bare.text and "!oz choose" in unescape(bare.text)
    assert await count(db, Action) == 0


async def test_a_form_code_cannot_be_answered_as_a_permission(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(
        service,
        control,
        kind="form",
        operation=None,
        resources=(),
        requested_scope=(),
        fields=(QuestionField(id="a", label="A", kind="text"),),
    )
    result = await send(service, source, message(f"!ok {short_code(identity)}", 103))
    assert "Received" not in result.text and await count(db, Action) == 0


async def test_unpreviewable_request_must_be_decided_in_opencode(db, monkeypatch):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    monkeypatch.setattr(permission_commands, "permission_notice", lambda *_: None)
    result = await send(service, source, message(f"!ok {short_code(identity)}", 103))
    assert "OpenCode" in result.text and await count(db, Action) == 0


async def test_an_expired_but_still_waiting_request_can_still_be_answered(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    async with db.sessions.begin() as session:
        await session.execute(update(PendingInteraction).values(expires_at=0))
    result = await send(service, source, message(f"!ok {short_code(identity)}", 103))
    assert "Received" in result.text and await count(db, Action) == 1


async def test_resolved_in_opencode_first_sends_nothing(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    control.resolved = True
    result = await send(service, source, message(f"!ok {short_code(identity)}", 103))
    assert "Received" not in result.text and await count(db, Action) == 0


async def test_a_viewer_without_approval_cannot_answer(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    result = await send(service, source, message(f"!ok {short_code(identity)}", 103))
    assert "Received" not in result.text and await count(db, Action) == 0


async def test_two_waiting_requests_with_one_code_are_refused_not_guessed(db, monkeypatch):
    service, _binding, source, control, _audience = await router(db)
    await pending(service, control, request="first")
    await pending(service, control, request="second")
    monkeypatch.setattr(permission_commands, "short_code", lambda _: "1234")
    monkeypatch.setattr(interaction_module, "short_code", lambda _: "1234")
    result = await send(service, source, message("!ok 1234", 103))
    assert "Received" not in result.text and await count(db, Action) == 0


async def test_reply_rejects_a_source_naming_another_code(db):
    worker_, binding, execution, _reader = await dispatcher(db, require_control_source=True)
    interactions = InteractionService(worker_.bindings)
    snapshot = permission(identity="source-permission")
    execution.requests[snapshot.upstream_request_id] = snapshot
    identity = await interactions.observe(binding, snapshot)
    token = await interactions.issue(identity, "realm", 7)
    code = short_code(identity)
    other = "1000" if code != "1000" else "1001"
    with pytest.raises(Exception, match="mismatch"):
        await interactions.reply(
            token,
            "realm",
            7,
            decision="once",
            source=dispatch_message(text=f"!ok {other}", revision=0),
            code=code,
        )
    assert await count(db, Action) == 0


async def test_strict_dispatch_accepts_the_quick_reply_source(db):
    worker_, binding, execution, reader = await dispatcher(db, require_control_source=True)
    interactions = InteractionService(worker_.bindings)
    snapshot = permission(identity="source-permission")
    execution.requests[snapshot.upstream_request_id] = snapshot
    identity = await interactions.observe(binding, snapshot)
    token = await interactions.issue(identity, "realm", 7)
    source = dispatch_message(text=f"!ok {short_code(identity)}", revision=0)
    reader.messages[source.message_id] = source
    action = await interactions.reply(
        token, "realm", 7, decision="once", source=source, code=short_code(identity)
    )
    assert await worker_.advance(action) == "completed"
    assert len(execution.submitted) == 1


async def test_native_v2_reply_accepts_the_quick_reply_source(db, profile):
    dispatcher_, binding, transport, proof, _data, seen, reader = await worker(db, profile)
    proof.kind = "permission"
    try:
        snapshot = await dispatcher_.client.interaction(V2_REF, "per_original")
        interactions = InteractionService(dispatcher_.bindings)
        identity = await interactions.observe(binding, snapshot)
        token = await interactions.issue(identity, "realm", 7)
        source = dispatch_message(text=f"!no {short_code(identity)}", revision=0)
        reader.messages[source.message_id] = source
        action = await interactions.reply(
            token, "realm", 7, decision="reject", source=source, code=short_code(identity)
        )
        assert await dispatcher_.advance(action) == "completed"
        assert len([request for request in seen if request.method == "POST"]) == 1
    finally:
        await transport.close()


async def test_a_notice_sent_in_an_earlier_wording_does_not_block_later_ones(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, binding, _calls = env
        nodes[REF].add_request(permission())
        await pipeline.pending_notices_once()
        await deliver_all(pipeline, db)
        async with db.sessions.begin() as session:
            from jt_oz_bridge.storage.control_models import Binding

            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(locale="zh-TW")
            )
        pipeline._announced.clear()
        nodes[REF].add_request(permission(identity="later"))
        await pipeline.pending_notices_once()
        assert len(await rows(db, Delivery)) == 2


async def test_the_pending_list_shows_each_rows_one_message_reply(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    listed = await send(service, source, message("!oz pending"))
    code = short_code(identity)
    assert f"!ok {code}" in unescape(listed.text) and f"!no {code}" in unescape(listed.text)


async def test_a_channel_button_click_with_its_bot_mention_decides_once(db):
    service, binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    clicked = f"@**jt-oz-bridge** !ok {short_code(identity)}"
    reply = await send(service, source, message(clicked, 103))
    assert "Received" in reply.text
    async with db.sessions() as session:
        (action,) = (await session.scalars(select(Action))).all()
    assert action.payload["decision"] == "once" and action.payload["source"]["text"] == clicked
