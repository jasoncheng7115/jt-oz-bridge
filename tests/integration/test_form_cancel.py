import asyncio
import re
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.control import QuestionField
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.domain.operations import current_operation
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.storage.control_models import ControlToken, FormDraft, PendingInteraction
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.operations import operation_kind
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_form_wizard import answer, answer_token, opened
from tests.integration.test_router import count, message, send


def cancellation_capability(reference=None, *, supported=True):
    return {
        "form.cancel": Capability(
            supported=supported,
            scope="session.form",
            reason="synthetic test",
            verification="synthetic_test",
        )
    }


def confirm_token(text):
    text = unescape(text)
    return re.search(r"!(?:oz confirm|ok) ([A-Za-z0-9_-]{32})", text)[1]


async def previewed(db, *, fields=None):
    service, binding, source, control, identity, shown = await opened(
        db,
        fields
        if fields is not None
        else [QuestionField(id="required", label="Required", kind="text")],
    )
    service.permissions.forms.native_capabilities = cancellation_capability
    preview = await send(service, source, message("!oz skip " + answer_token(shown), 201))
    return service, binding, source, control, identity, shown, preview


async def queued(db, **options):
    service, binding, source, control, identity, shown, preview = await previewed(db, **options)
    result = await send(service, source, message("!oz confirm " + confirm_token(preview.text), 202))
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
    assert "not confirmed yet" in result.text and action.operation == "form.cancel"
    return service, binding, source, control, identity, action, result


class CancelExecution(SyntheticExecution):
    def capabilities(self, reference):
        return super().capabilities(reference) | cancellation_capability(reference)


def worker_for(service, source, control, *, mode="success"):
    execution = CancelExecution()
    execution.requests = control.requests.copy()
    execution.mode = mode
    worker = Dispatcher(
        service.bindings, execution, source, service.inbox.holder, service.inbox.fencing
    )
    return worker, execution


async def test_default_disabled_cancellation_has_no_confirmation_or_action(db):
    service, binding, source, _control, _identity, shown = await opened(
        db, [QuestionField(id="text", label="Text", kind="text")]
    )
    assert "!oz skip" not in shown
    result = await send(service, source, message("!oz skip " + answer_token(shown), 201))
    assert "Cancelling forms" in result.text and "!oz confirm" not in result.text
    assert await count(db, Action) == 0
    async with db.sessions() as session:
        assert (
            await session.scalar(select(ControlToken).where(ControlToken.kind == "form-cancel"))
            is None
        )


async def test_native_cancel_previews_incomplete_required_form_and_queues_no_answers(db):
    service, binding, source, control, identity, shown, preview = await previewed(db)
    assert "whole form" in preview.text and "not undone" in preview.text
    assert "original-session" in preview.text and "request" in preview.text
    assert await count(db, Action) == 0 and await count(db, FormDraft) == 0
    result = await send(service, source, message("!oz confirm " + confirm_token(preview.text), 202))
    assert "not confirmed yet" in result.text
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
        assert action.payload["operation"] == "form.cancel"
        assert "answers" not in action.payload and "decision" not in action.payload
        assert action.payload["source"] == source.messages[202].model_dump(mode="json")
        assert (await session.get(PendingInteraction, identity)).state == "reply_queued"
    assert await service.route(source.messages[202]) == result
    assert await count(db, Action) == 1


async def test_confirmed_cancel_dispatches_once_and_resolves_only_on_completion(db):
    service, _binding, source, control, identity, action, _result = await queued(db)
    worker, execution = worker_for(service, source, control)
    assert await worker.advance(action.id) == "completed"
    assert await worker.advance(action.id) == "completed" and len(execution.submitted) == 1
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).state == "resolved"


@pytest.mark.parametrize(
    "change", [{"deleted": True}, {"revision": 1, "text": "changed"}, {"author_id": 8}]
)
async def test_changed_final_cancel_source_never_posts_and_requires_new_human_decision(db, change):
    service, _binding, source, control, identity, action, _result = await queued(db)
    source.messages[202] = source.messages[202].model_copy(update=change)
    worker, execution = worker_for(service, source, control)
    assert await worker.advance(action.id) == "held" and not execution.submitted
    async with db.sessions() as session:
        pending = await session.get(PendingInteraction, identity)
        assert pending.state == "pending" and pending.action_id is None


async def test_timeout_after_cancel_is_ambiguous_and_never_replayed_or_reopened(db):
    service, _binding, source, control, identity, action, _result = await queued(db)
    worker, execution = worker_for(service, source, control, mode="timeout")
    assert await worker.advance(action.id) == "ambiguous"
    assert await worker.advance(action.id) == "ambiguous" and len(execution.submitted) == 1
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).state == "reply_queued"


async def test_cancel_capability_removed_after_preview_or_before_dispatch_stays_unexecuted(db):
    service, binding, source, control, identity, shown, preview = await previewed(db)
    service.permissions.forms.native_capabilities = lambda reference: cancellation_capability(
        reference, supported=False
    )
    refused = await send(
        service, source, message("!oz confirm " + confirm_token(preview.text), 202)
    )
    assert "Cancelling forms" in refused.text and await count(db, Action) == 0
    service.permissions.forms.native_capabilities = cancellation_capability
    result = await send(service, source, message("!oz confirm " + confirm_token(preview.text), 203))
    assert "not confirmed yet" in result.text
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
    worker, execution = worker_for(service, source, control)
    execution.capabilities = lambda reference: cancellation_capability(reference, supported=False)
    assert await worker.advance(action.id) == "held" and not execution.submitted


async def test_draft_revision_change_invalidates_cancel_preview(db):
    service, _binding, source, _control, _identity, shown, preview = await previewed(db)
    review = await answer(service, source, shown, "new answer", 202)
    rejected = await send(
        service, source, message("!oz confirm " + confirm_token(preview.text), 203)
    )
    assert "expired" in rejected.text and await count(db, Action) == 0
    assert "Review" in review.text


@pytest.mark.parametrize("changed", ["resolved", "schema", "expiry"])
async def test_native_change_or_expired_confirmation_never_cancels(db, changed):
    service, _binding, source, control, _identity, _shown, preview = await previewed(db)
    if changed == "resolved":
        control.resolved = True
    elif changed == "schema":
        control.requests["request"] = control.requests["request"].model_copy(
            update={"generation": "different"}
        )
    else:
        async with db.sessions.begin() as session:
            await session.execute(
                update(ControlToken).where(ControlToken.kind == "form-cancel").values(expires_at=0)
            )
    rejected = await send(
        service, source, message("!oz confirm " + confirm_token(preview.text), 202)
    )
    assert "expired" in rejected.text and await count(db, Action) == 0


async def test_cancel_confirmation_is_not_an_answer_token_or_other_actors_capability(db):
    service, _binding, source, _control, _identity, shown, preview = await previewed(db)
    token = confirm_token(preview.text)
    refused = await send(service, source, message("!oz answer " + token + " submit", 202))
    assert "expired" in refused.text
    refused = await send(service, source, message("!oz confirm " + token, 203, author_id=8))
    assert "expired" in refused.text
    refused = await send(service, source, message("!oz confirm " + answer_token(shown), 204))
    assert "expired" in refused.text and await count(db, Action) == 0


async def test_form_answer_and_cancel_race_choose_only_one_request_winner(db):
    service, _binding, source, _control, _identity, shown, preview = await previewed(db, fields=[])
    items = [
        message("!oz answer " + answer_token(shown) + " submit", 202),
        message("!oz confirm " + confirm_token(preview.text), 203),
    ]
    source.messages.update({item.message_id: item for item in items})
    replies = await asyncio.gather(*(service.route(item) for item in items))
    assert sum("not confirmed yet" in item.text for item in replies) == 1
    assert await count(db, Action) == 1


def test_current_cancel_index_does_not_change_frozen_migration_operation_semantics():
    assert current_operation({"operation": "form.cancel"}) == "form.cancel"
    assert operation_kind({"operation": "form.cancel"}) == "unknown"
    assert current_operation({"operation": "unsafe.operation"}) == "unknown"


@pytest.mark.parametrize("mode", ["reject", "invalid-answer"])
async def test_cancel_rejection_is_not_reopened_as_an_invalid_answer_or_retried(db, mode):
    service, _binding, source, control, identity, action, _result = await queued(db)
    worker, execution = worker_for(service, source, control, mode=mode)
    assert await worker.advance(action.id) == "rejected"
    assert await worker.advance(action.id) == "rejected" and len(execution.submitted) == 1
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).state == "reply_queued"


async def test_sensitive_form_can_offer_separate_cancel_entry_without_answer_capability(db):
    service, binding, source, _control, identity, _shown = await opened(
        db, [QuestionField(id="private", label="Private", kind="text", format="password")]
    )
    service.permissions.forms.native_capabilities = cancellation_capability
    shown = await service.permissions.open(binding, message(), "en", identity)
    assert "!oz answer" not in shown and "in OpenCode" in shown
    entry = re.search(r"!(?:oz )?skip ([A-Za-z0-9_-]{32})", unescape(shown))[1]
    refused = await send(service, source, message("!oz answer " + entry + " private", 201))
    assert "expired" in refused.text and await count(db, FormDraft) == 0
    preview = await send(service, source, message("!oz skip " + entry, 202))
    result = await send(service, source, message("!oz confirm " + confirm_token(preview.text), 203))
    assert "not confirmed yet" in result.text
    async with db.sessions() as session:
        assert (await session.scalar(select(Action))).operation == "form.cancel"
