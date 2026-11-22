"""One-message answers to a one-question OpenCode form, from the notice's four-digit code.

Real ownDB, synthetic Native and Zulip only. No Human, mobile or Native answer is produced.
"""

import json
from html import unescape

import pytest
from sqlalchemy import select

from jt_oz_bridge.domain.control import Choice, InteractionSnapshot, QuestionField
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import ParsedInput, parse_input
from jt_oz_bridge.services.interactions import InteractionService, short_code
from jt_oz_bridge.services.permission_commands import form_notice, form_widget, quick_field
from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.models import Action, Delivery
from tests.integration.test_consumer_runtime import rows, visible
from tests.integration.test_descendant_pending_notices import deliver_all, tree_pipeline
from tests.integration.test_dispatch import dispatcher
from tests.integration.test_dispatch import message as dispatch_message
from tests.integration.test_permission_commands import pending
from tests.integration.test_router import count, message, router, send
from tests.support import REF

CHOICES = (Choice(id="red", label="Red"), Choice(id="blue", label="Blue"))


def field(kind="single", **changes):
    return QuestionField(
        id="colour",
        label="Which colour?",
        kind=kind,
        choices=CHOICES if kind in {"single", "multi"} else (),
    ).model_copy(update=changes)


def question(*fields, identity="question"):
    return InteractionSnapshot(
        reference=REF,
        upstream_request_id=identity,
        generation="source:1",
        kind="form",
        pending=True,
        description="Pick a colour for the chart",
        fields=fields or (field(),),
    )


async def ask(service, control, *fields, identity="question"):
    form = question(*fields, identity=identity)
    return await pending(
        service,
        control,
        request=identity,
        kind="form",
        operation=None,
        resources=(),
        requested_scope=(),
        description=form.description,
        fields=form.fields,
    )


async def answers(db):
    async with db.sessions() as session:
        return [
            action.payload["answers"] for action in (await session.scalars(select(Action))).all()
        ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("!a 1234 2", ParsedInput("command", "answer", "1234 2")),
        ("!a 1234 a longer answer", ParsedInput("command", "answer", "1234 a longer answer")),
        ("!a", ParsedInput("command", "answer", "")),
        ("!about this", ParsedInput("prompt", arguments="!about this")),
    ],
)
def test_quick_answer_parses_only_in_a_connected_topic(text, expected):
    assert parse_input(text, bound=True) == expected
    assert parse_input(text).kind == "ignore"


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_single_choice_notice_lists_options_and_buttons_send_the_number(locale):
    tr, snapshot = Translator(), question()
    code = short_code("interaction")
    text = unescape(form_notice(tr, snapshot, "interaction", locale))
    assert "Pick a colour for the chart" in text and "Which colour?" in text
    assert "1. Red" in text and "2. Blue" in text and f"!a {code}" in text
    widget = json.loads(form_widget(tr, snapshot, "interaction", locale))
    assert widget["widget_type"] == "zform"
    assert [c["reply"] for c in widget["extra_data"]["choices"]] == [f"!a {code} 1", f"!a {code} 2"]
    assert [c["long_name"] for c in widget["extra_data"]["choices"]] == ["Red", "Blue"]


def test_yes_no_has_two_buttons_and_typed_answers_have_none():
    tr = Translator()
    yes_no = json.loads(form_widget(tr, question(field("boolean")), "i", "en"))
    assert [c["reply"].split()[-1] for c in yes_no["extra_data"]["choices"]] == ["yes", "no"]
    for kind in ("text", "multi", "integer", "number"):
        assert form_notice(tr, question(field(kind)), "i", "en") is not None
        assert form_widget(tr, question(field(kind)), "i", "en") is None


@pytest.mark.parametrize(
    "fields",
    [
        (field(), field(id="second")),
        (field(choices=tuple(Choice(id=str(n), label=str(n)) for n in range(11))),),
        (field(hidden=True),),
        (field("text", format="password"),),
        (field("external", external_url="https://example.com/x"),),
    ],
)
def test_forms_a_single_message_cannot_answer_get_no_quick_reply(fields):
    snapshot = question(*fields)
    assert quick_field(snapshot) is None
    assert form_notice(Translator(), snapshot, "i", "en") is None
    assert form_widget(Translator(), snapshot, "i", "en") is None


async def test_number_answers_the_choice_once_from_that_message(db):
    service, binding, source, control, _audience = await router(db)
    identity = await ask(service, control)
    reply = await send(service, source, message(f"!a {short_code(identity)} 2", 103))
    assert "waiting to be sent" in reply.text
    assert await service.route(source.messages[103]) == reply
    async with db.sessions() as session:
        (action,) = (await session.scalars(select(Action))).all()
    assert action.payload["operation"] == "form.reply" and action.binding_id == binding.id
    assert action.payload["answers"] == {
        "colour": {"selected": ["blue"], "text": None, "value": None}
    }
    assert action.payload["source"]["text"] == f"!a {short_code(identity)} 2"
    again = await send(service, source, message(f"!a {short_code(identity)} 1", 104))
    assert "already answered" in again.text and await count(db, Action) == 1


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        (
            "text",
            "light blue, please",
            {"selected": [], "text": "light blue, please", "value": None},
        ),
        ("boolean", "yes", {"selected": [], "text": None, "value": True}),
        ("integer", "42", {"selected": [], "text": None, "value": 42}),
        ("multi", "1,2", {"selected": ["red", "blue"], "text": None, "value": None}),
    ],
)
async def test_typed_answers_are_decoded_like_the_step_form(db, kind, raw, expected):
    service, _binding, source, control, _audience = await router(db)
    identity = await ask(service, control, field(kind))
    await send(service, source, message(f"!a {short_code(identity)} {raw}", 103))
    assert await answers(db) == [{"colour": expected}]


async def test_an_invalid_answer_explains_and_sends_nothing(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await ask(service, control)
    result = await send(service, source, message(f"!a {short_code(identity)} 9", 103))
    assert "option number" in result.text and await count(db, Action) == 0


async def test_a_multi_question_form_points_to_the_step_form(db):
    service, _binding, source, control, _audience = await router(db)
    identity = await ask(service, control, field(), field(id="second"))
    result = await send(service, source, message(f"!a {short_code(identity)} 1", 103))
    assert "!pending" in result.text and await count(db, Action) == 0


async def test_codes_do_not_cross_permission_and_question(db):
    service, _binding, source, control, _audience = await router(db)
    question_id = await ask(service, control)
    permission_id = await pending(service, control, request="permission")
    ok_on_question = await send(service, source, message(f"!ok {short_code(question_id)}", 103))
    a_on_permission = await send(service, source, message(f"!a {short_code(permission_id)} 1", 104))
    assert "Received" not in ok_on_question.text and "Received" not in a_on_permission.text
    assert await count(db, Action) == 0


async def test_strict_dispatch_accepts_the_quick_answer_source(db):
    worker, binding, execution, reader = await dispatcher(db, require_control_source=True)
    interactions = InteractionService(worker.bindings)
    snapshot = question(identity="source-question")
    execution.requests[snapshot.upstream_request_id] = snapshot
    identity = await interactions.observe(binding, snapshot)
    token = await interactions.issue(identity, "realm", 7)
    source = dispatch_message(text=f"!a {short_code(identity)} 1", revision=0)
    reader.messages[source.message_id] = source
    from jt_oz_bridge.domain.control import FieldAnswer

    action = await interactions.reply(
        token,
        "realm",
        7,
        answers={"colour": FieldAnswer(selected=("red",))},
        source=source,
        code=short_code(identity),
    )
    assert await worker.advance(action) == "completed"
    assert len(execution.submitted) == 1


async def test_runtime_posts_the_question_with_buttons_once(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        nodes[REF].add_request(question())
        await pipeline.pending_notices_once()
        await pipeline.pending_notices_once()
        (saved,) = await rows(db, PendingInteraction)
        code = short_code(saved.id)
        deliveries = await deliver_all(pipeline, db)
        assert len(deliveries) == len(server.posts) == 1
        body = visible(server.posts[0]["content"])
        assert "Which colour?" in body and "2. Blue" in body and f"!a {code}" in body
        widget = json.loads(deliveries[0].payload["widget"])
        assert widget["extra_data"]["choices"][1]["reply"] == f"!a {code} 2"
        pipeline._announced.clear()
        await pipeline.pending_notices_once()
        assert len(await rows(db, Delivery)) == 1
