import asyncio
import re
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.control import Choice, FieldCondition, QuestionField, wire_answers
from jt_oz_bridge.storage.control_models import ControlToken, FormDraft, PendingInteraction
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_permission_commands import menu_token, pending
from tests.integration.test_router import count, message, router, send


def answer_token(text):
    text = unescape(text)
    return re.search(r"!(?:oz answer|a) ([A-Za-z0-9_-]{32})", text)[1]


async def opened(db, fields):
    service, binding, source, control, audience = await router(db)
    identity = await pending(
        service,
        control,
        kind="form",
        operation=None,
        resources=(),
        requested_scope=(),
        fields=tuple(fields),
    )
    shown = await service.permissions.open(binding, message(), "en", identity)
    return service, binding, source, control, identity, shown


async def answer(service, source, shown, raw, number):
    return await send(service, source, message(f"!oz answer {answer_token(shown)} {raw}", number))


@pytest.mark.parametrize("token_edges", [False, True])
async def test_typed_phone_flow_false_zero_optional_and_exact_literal_requires_final_confirmation(
    db, monkeypatch, token_edges
):
    if token_edges:
        counter = 0

        def opaque(size):
            nonlocal counter
            counter += 1
            return "_" + f"{counter:030x}" + "_"

        monkeypatch.setattr("jt_oz_bridge.services.tokens.secrets.token_urlsafe", opaque)
    fields = [
        QuestionField(id="bool", label="Enable?", kind="boolean"),
        QuestionField(id="number", label="Count", kind="integer"),
        QuestionField(id="text", label="Literal", kind="text"),
        QuestionField(id="optional", label="Optional", kind="text", required=False),
    ]
    service, _binding, source, control, _id, shown = await opened(db, fields)
    assert "Question 1/4" in shown
    one = await answer(service, source, shown, "no", 201)
    two = await answer(service, source, one.text, "0", 202)
    three = await answer(service, source, two.text, "--  leading\n!oz stop  ", 203)
    review = await answer(service, source, three.text, "/skip", 204)
    assert "Review your draft" in review.text and '"omitted": true' in review.text
    assert await count(db, Action) == 0
    async with db.sessions() as session:
        draft = await session.scalar(select(FormDraft))
        assert draft.answers["bool"]["value"] is False
        assert draft.answers["number"]["value"] == 0
        assert draft.answers["text"]["text"] == " leading\n!oz stop  "
        assert draft.progress == {"skipped": ["optional"]}
    done = await answer(service, source, review.text, "submit", 205)
    assert "not confirmed yet" in done.text
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
        assert action.operation == "form.reply"
        assert action.payload["source"]["message_id"] == 205
        snapshot = control.requests["request"]
        from jt_oz_bridge.domain.control import FieldAnswer

        values = wire_answers(
            snapshot.fields,
            {k: FieldAnswer.model_validate(v) for k, v in action.payload["answers"].items()},
        )
        assert values == {"bool": False, "number": 0, "text": " leading\n!oz stop  "}
    assert await service.route(source.messages[205]) == done
    assert await count(db, Action) == 1


async def test_review_edit_prunes_conditional_answer_and_skip_then_reasks_when_reactivated(db):
    condition = (FieldCondition(key="enabled", op="eq", value=True),)
    fields = [
        QuestionField(id="enabled", label="Enabled", kind="boolean"),
        QuestionField(id="detail", label="Detail", kind="text", when=condition),
        QuestionField(id="optional", label="Optional", kind="text", required=False, when=condition),
    ]
    service, _binding, source, _control, _id, shown = await opened(db, fields)
    one = await answer(service, source, shown, "yes", 201)
    two = await answer(service, source, one.text, "first detail", 202)
    review = await answer(service, source, two.text, "/skip", 203)
    edit = await answer(service, source, review.text, "edit 1", 204)
    changed = await answer(service, source, edit.text, "no", 205)
    assert '"Detail"' not in changed.text and '"Optional"' not in changed.text
    async with db.sessions() as session:
        draft = await session.scalar(select(FormDraft))
        assert set(draft.answers) == {"enabled"} and draft.progress == {"skipped": []}
    edit = await answer(service, source, changed.text, "edit 1", 206)
    again = await answer(service, source, edit.text, "yes", 207)
    assert "Question 2/3" in again.text
    assert await count(db, Action) == 0


async def test_choice_pages_bind_global_numbers_original_ids_and_literal_custom(db):
    choices = tuple(Choice(id=f"id:{index}", label=f"Label {index}") for index in range(1, 26))
    service, _binding, source, _control, _id, shown = await opened(
        db,
        [
            QuestionField(
                id="multi", label="Pick", kind="multi", choices=choices, allow_custom_text=True
            )
        ],
    )
    assert "Label 10" in shown and "Label 11" not in shown
    page = await answer(service, source, shown, "/page 3", 201)
    assert "Label 25" in page.text and "Label 20" not in page.text
    stale = await answer(service, source, shown, "1", 202)
    assert "expired" in stale.text
    review = await answer(service, source, page.text, "1,25 --  custom  ", 203)
    assert "Label 1" in review.text and "Label 25" in review.text
    async with db.sessions() as session:
        draft = await session.scalar(select(FormDraft))
        assert draft.answers["multi"]["selected"] == ["id:1", "id:25"]
        assert draft.answers["multi"]["text"] == " custom  "
    assert await count(db, Action) == 0


async def test_invalid_answer_and_required_skip_preserve_step_for_fresh_correct_message(db):
    service, _binding, source, _control, _id, shown = await opened(
        db, [QuestionField(id="n", label="Number", kind="integer", minimum=2)]
    )
    invalid = await answer(service, source, shown, "not a number", 201)
    assert "whole number" in invalid.text
    skipped = await answer(service, source, shown, "/skip", 202)
    assert "required" in skipped.text and await count(db, FormDraft) == 0
    invalid = await answer(service, source, shown, "1", 203)
    assert "range" in invalid.text
    review = await answer(service, source, shown, "2", 204)
    assert "Review" in review.text and await count(db, FormDraft) == 1


async def test_wrong_actor_or_other_topic_cannot_use_step(db):
    service, binding, source, control, _id, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    result = await send(
        service, source, message(f"!oz answer {answer_token(shown)} text", 201, author_id=8)
    )
    assert "expired" in result.text
    control.ref = control.ref.model_copy(update={"upstream_session_id": "other-session"})
    await service.bindings.bind("realm", 7, 10, "Other work", control.ref)
    result = await send(
        service, source, message(f"!oz answer {answer_token(shown)} text", 202, topic="Other work")
    )
    assert "permission" in result.text and await count(db, FormDraft) == 0


async def test_concurrent_step_answers_have_one_winner_and_consumption_is_atomic(db):
    service, _binding, source, _control, _id, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    items = [
        message(f"!oz answer {answer_token(shown)} {value}", n)
        for n, value in [(201, "first"), (202, "second")]
    ]
    source.messages = {item.message_id: item for item in items}
    replies = await asyncio.gather(*(service.route(item) for item in items))
    assert sum("Review your draft" in reply.text for reply in replies) == 1
    assert await count(db, FormDraft) == 1 and await count(db, Action) == 0
    async with db.sessions() as session:
        assert (await session.scalar(select(FormDraft))).revision == 1


async def test_explicit_refresh_resumes_saved_draft_without_reviving_old_step(db):
    fields = [
        QuestionField(id="first", label="First", kind="text"),
        QuestionField(id="second", label="Second", kind="boolean"),
    ]
    service, binding, source, _control, identity, shown = await opened(db, fields)
    one = await answer(service, source, shown, "saved", 201)
    async with db.sessions.begin() as session:
        await session.execute(update(PendingInteraction).values(expires_at=0))
        await session.execute(update(ControlToken).values(expires_at=0))
    resumed = await service.permissions.open(binding, message(), "en", identity)
    assert "Question 2/2" in resumed
    stale = await answer(service, source, one.text, "no", 202)
    assert "expired" in stale.text
    review = await answer(service, source, resumed, "no", 203)
    assert "saved" in review.text
    assert await count(db, Action) == 0


@pytest.mark.parametrize("change", ["resolved", "schema", "revoke"])
async def test_source_change_or_revoked_role_cannot_submit_review(db, change):
    service, _binding, source, control, _id, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    review = await answer(service, source, shown, "saved", 201)
    if change == "resolved":
        control.resolved = True
    elif change == "schema":
        control.requests["request"] = control.requests["request"].model_copy(
            update={"description": "changed request"}
        )
    else:
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    rejected = await answer(service, source, review.text, "submit", 202)
    assert "expired" in rejected.text or "permission" in rejected.text
    assert await count(db, Action) == 0


async def test_new_draft_revision_invalidates_previous_full_review(db):
    service, binding, source, _control, identity, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    old = await answer(service, source, shown, "old", 201)
    another = await service.permissions.open(binding, message(), "en", identity)
    edit = await answer(service, source, another, "edit 1", 202)
    current = await answer(service, source, edit.text, "new", 203)
    rejected = await answer(service, source, old.text, "submit", 204)
    assert "expired" in rejected.text and await count(db, Action) == 0
    assert "not confirmed yet" in (await answer(service, source, current.text, "submit", 205)).text
    async with db.sessions() as session:
        assert (await session.scalar(select(Action))).payload["answers"]["text"]["text"] == "new"


@pytest.mark.parametrize(
    "fields",
    [
        [],
        [
            QuestionField(
                id="ack",
                label="External",
                kind="external",
                external_url="https://example.test/private?token=PRIVATE",
            )
        ],
    ],
)
async def test_empty_or_external_form_never_submits_automatically_or_fetches_url(db, fields):
    service, _binding, source, _control, _id, shown = await opened(db, fields)
    assert "PRIVATE" not in shown
    if fields:
        shown = (await answer(service, source, shown, "ack", 201)).text
    assert "Review" in shown and await count(db, Action) == 0
    result = await answer(service, source, shown, "submit", 202)
    assert "not confirmed yet" in result.text


@pytest.mark.parametrize("changes", [{"hidden": True}, {"format": "password"}])
async def test_sensitive_or_hidden_active_fields_require_original_tui(db, changes):
    service, _binding, _source, _control, _id, shown = await opened(
        db, [QuestionField(id="private", label="Private", kind="text", **changes)]
    )
    assert "in OpenCode" in shown and "!oz answer" not in shown
    assert await count(db, Action) == 0
    async with db.sessions() as session:
        assert (
            await session.scalar(select(ControlToken).where(ControlToken.kind == "form-step"))
            is None
        )


async def test_phone_pending_menu_opens_form_and_chinese_flow_is_localized(db):
    service, binding, source, _control, _id, _shown = await opened(
        db, [QuestionField(id="bool", label="開啟", kind="boolean")]
    )
    await send(service, source, message("!oz lang zh-TW", 201))
    listed = await send(service, source, message("!oz pending", 202))
    shown = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 203)
    )
    assert "第 1/1 題" in shown.text
    review = await answer(service, source, shown.text, "否", 204)
    assert "請確認草稿" in review.text and "false" in review.text
    assert await count(db, Action) == 0


async def test_failed_transaction_rolls_back_both_answer_and_step_consumption(db):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    service, binding, _source, _control, _id, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    token = answer_token(shown)

    def fail_flush(session, context, instances):
        if any(isinstance(item, FormDraft) for item in session.new):
            raise RuntimeError("injected storage failure")

    event.listen(Session, "before_flush", fail_flush)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            await service.permissions.forms.answer(binding, message(), "en", token + " saved")
    finally:
        event.remove(Session, "before_flush", fail_flush)
    assert await count(db, FormDraft) == 0
    saved = await service.tokens.inspect(token, "form-step", "realm", 7)
    assert not saved.used
    resumed = await service.permissions.forms.answer(binding, message(), "en", token + " saved")
    assert "Review your draft" in resumed


async def test_draft_change_during_final_native_recheck_cannot_submit_old_answers(db):
    service, _binding, source, control, _id, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    review = await answer(service, source, shown, "old", 201)
    original = control.interaction
    calls = 0

    async def changing(reference, request):
        nonlocal calls
        calls += 1
        if calls == 2:
            async with db.sessions.begin() as session:
                draft = await session.scalar(select(FormDraft))
                draft.answers = {"text": {"selected": [], "text": "new", "value": None}}
                draft.revision += 1
        return await original(reference, request)

    control.interaction = changing
    rejected = await answer(service, source, review.text, "submit", 202)
    assert "expired" in rejected.text and await count(db, Action) == 0
    assert not (
        await service.tokens.inspect(answer_token(review.text), "form-submit", "realm", 7)
    ).used


async def test_other_actor_has_separate_draft_and_cannot_submit_after_first_winner(db):
    service, binding, source, _control, identity, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    own = await answer(service, source, shown, "actor seven", 201)
    other = await service.permissions.open(binding, message(author_id=8), "en", identity)
    other_review = await send(
        service,
        source,
        message("!oz answer " + answer_token(other) + " actor eight", 202, author_id=8),
    )
    assert await count(db, FormDraft) == 2
    assert "not confirmed yet" in (await answer(service, source, own.text, "submit", 203)).text
    rejected = await send(
        service,
        source,
        message("!oz answer " + answer_token(other_review.text) + " submit", 204, author_id=8),
    )
    assert "expired" in rejected.text and await count(db, Action) == 1


async def test_recovered_or_edited_answer_command_cannot_modify_draft(db):
    service, _binding, source, _control, _id, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    held = await send(
        service,
        source,
        message("!oz answer " + answer_token(shown) + " saved", 201),
        recovered=True,
    )
    assert held.state == "held" and await count(db, FormDraft) == 0
    held = await send(
        service, source, message("!oz answer " + answer_token(shown) + " edited", 202, revision=1)
    )
    assert held.state == "held" and await count(db, FormDraft) == 0
    assert "Review" in (await answer(service, source, shown, "fresh", 203)).text


@pytest.mark.parametrize("raw", ["edit 1", "submit extra", "submit "])
async def test_service_rejects_forged_final_confirmation_source_without_consuming_review(db, raw):
    from jt_oz_bridge.security.policy import AccessDenied

    service, _binding, _source, _control, _id, shown = await opened(db, [])
    opaque = answer_token(shown)
    step = await service.tokens.inspect(opaque, "form-submit", "realm", 7)
    with pytest.raises(AccessDenied, match="explicit_review"):
        await service.permissions.interactions.reply(
            step.context["root"],
            "realm",
            7,
            answers={},
            confirmation=step,
            draft_revision=0,
            source=message("!oz answer " + opaque + " " + raw),
        )
    assert not (await service.tokens.inspect(opaque, "form-submit", "realm", 7)).used
    assert await count(db, Action) == 0


async def test_final_submit_after_token_newline_is_an_explicit_confirmation(db):
    service, _binding, source, _control, _id, shown = await opened(db, [])
    result = await send(
        service, source, message("!oz answer " + answer_token(shown) + "\nsubmit", 201)
    )
    assert "not confirmed yet" in result.text and await count(db, Action) == 1
