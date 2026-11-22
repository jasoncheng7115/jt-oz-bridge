"""Original ownDB check chain and router; all Human/Native sources are synthetic."""

import re
from html import unescape

import pytest
from sqlalchemy import delete, select, update

from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.git_evidence import GitEvidenceResults
from jt_oz_bridge.services.git_evidence_commands import GitEvidenceCommands
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration import test_git_evidence_results as history
from tests.integration.test_router import send
from tests.unit.test_git_evidence import document


async def configured(db, monkeypatch, *, limit=10000, enabled=True, long=False):
    if long:
        monkeypatch.setattr(
            history,
            "document",
            lambda: document(
                staged_paths=[
                    dict(
                        safe_relative_path="src/" + str(i) + "-" + ("long_name-" * 12) + ".txt",
                        change="modified",
                        mode="100644",
                    )
                    for i in range(3)
                ]
            ),
        )
    results, binding, message, action, values, pin = await history.setup(db, monkeypatch)
    if not enabled:
        results = GitEvidenceResults(
            results.bindings, results.source, results.readers, fence=results.fence
        )
    commands = GitEvidenceCommands(results, values[4].tokens, message_limit=limit)
    router = CommandRouter(
        results.bindings, results.source, values[0].inbox, checks=values[4], git_evidence=commands
    )
    request = history.view_request(message, action.id, values[2])
    return commands, router, binding, request, action, values


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


def next_token(text):
    found = re.search(r"!oz git evidence [0-9a-f-]{36} ([A-Za-z0-9_-]{32})", unescape(text))
    return found[1] if found else None


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_router_saved_original_result_and_receipt_without_new_native_or_actions(
    db, monkeypatch, locale
):
    from jt_oz_bridge.storage.models import Preference

    commands, router, binding, request, action, values = await configured(db, monkeypatch)
    async with db.sessions.begin() as session:
        session.add(Preference(principal="user:realm:7", locale=locale))
    before = await rows(db, ControlToken)
    reply = await send(router, values[2], request)
    assert reply.state == "reply" and reply.binding_id == binding.id
    assert ("歷史檢查" if locale == "zh-TW" else "Historical Git check") in reply.text
    assert "src/app.py" in unescape(reply.text) and action.id in unescape(reply.text)
    assert await router.route(request) == reply
    assert len(values[3].submitted) == 1 and len(await rows(db, Action)) == 1
    assert len(await rows(db, ControlToken)) == len(before)


async def test_view_only_actor_can_read_another_original_check_result(db, monkeypatch):
    commands, router, binding, request, action, values = await configured(db, monkeypatch)
    request = await history.viewer_request(db, values, request, action.id)
    body = await commands.route(binding, request, "en", "evidence " + action.id)
    assert action.id in unescape(body) and len(values[3].submitted) == 1


async def test_disabled_session_is_explicit_and_does_not_create_token_or_action(db, monkeypatch):
    commands, router, binding, request, action, values = await configured(
        db, monkeypatch, enabled=False
    )
    before = len(await rows(db, ControlToken))
    body = await commands.route(binding, request, "en", "evidence " + action.id)
    assert "available for this conversation" in body
    assert len(await rows(db, ControlToken)) == before and len(await rows(db, Action)) == 1
    assert len(values[3].submitted) == 1


async def test_router_help_describes_original_action_without_running_check(db, monkeypatch):
    commands, router, binding, request, action, values = await configured(db, monkeypatch)
    request = request.model_copy(update={"message_id": 202, "text": "!oz help git"})
    reply = await send(router, values[2], request)
    assert "!git evidence" in unescape(reply.text)
    assert len(await rows(db, Action)) == 1 and len(values[3].submitted) == 1


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_minimum_budget_pages_reauthenticate_initial_source_and_never_resubmit(
    db, monkeypatch, locale
):
    commands, router, binding, request, action, values = await configured(
        db, monkeypatch, limit=512, long=True
    )
    initial = request
    bodies = []
    for n in range(60):
        args = request.text.removeprefix("!oz git ")
        body = await commands.route(binding, request, locale, args)
        assert len(body) <= 412
        bodies.append(body)
        token = next_token(body)
        if token is None:
            break
        request = initial.model_copy(
            update={"message_id": 202 + n, "text": f"!oz git evidence {action.id} {token}"}
        )
        values[2].messages[request.message_id] = request
    else:
        pytest.fail("bounded projection did not terminate")
    assert len(bodies) > 1 and len(values[3].submitted) == 1 and len(await rows(db, Action)) == 1
    assert ("realm", initial.message_id) in values[2].calls
    all_text = unescape("\n".join(bodies))
    assert "src/0-" in all_text and "src/1-" in all_text and "src/2-" in all_text


@pytest.mark.parametrize(
    "fault",
    [
        "actor",
        "topic",
        "issuer_deleted",
        "issuer_edited",
        "expired",
        "snapshot",
        "limit",
        "binding_revision",
    ],
)
async def test_page_capability_is_bound_to_current_request_and_original_issuer(
    db, monkeypatch, fault
):
    commands, router, binding, initial, action, values = await configured(
        db, monkeypatch, limit=512, long=True
    )
    body = await commands.route(binding, initial, "en", "evidence " + action.id)
    token = next_token(body)
    assert token
    request = initial.model_copy(
        update={"message_id": 202, "text": f"!oz git evidence {action.id} {token}"}
    )
    if fault == "actor":
        request = request.model_copy(update={"author_id": 8})
    elif fault == "topic":
        request = request.model_copy(update={"topic": "other"})
    elif fault in {"issuer_deleted", "issuer_edited"}:
        values[2].messages[initial.message_id] = initial.model_copy(
            update={
                "deleted": fault == "issuer_deleted",
                "revision": 1 if fault == "issuer_edited" else 0,
            }
        )
    elif fault == "limit":
        commands.message_limit = 1000
    else:
        async with db.sessions.begin() as session:
            stored = (
                await session.scalars(
                    select(ControlToken).where(ControlToken.kind == "git-evidence-page")
                )
            ).one()
            if fault == "expired":
                stored.expires_at = 0
            elif fault == "binding_revision":
                stored.binding_revision += 1
            else:
                stored.context = stored.context | {"snapshot_sha256": "0" * 64}
    values[2].messages[202] = request
    with pytest.raises((ValueError, Conflict, AccessDenied)):
        await commands.route(binding, request, "en", request.text.removeprefix("!oz git "))
    assert len(values[3].submitted) == 1


@pytest.mark.parametrize("fault", ["revoke", "source", "journal", "lease"])
async def test_late_publication_changes_reject_output(db, monkeypatch, fault):
    commands, router, binding, initial, action, values = await configured(
        db, monkeypatch, limit=512, long=True
    )
    issue = commands.tokens.issue

    async def changed(*args, **kwargs):
        result = await issue(*args, **kwargs)
        if fault == "source":
            values[2].messages[initial.message_id] = initial.model_copy(update={"deleted": True})
        else:
            async with db.sessions.begin() as session:
                if fault == "revoke":
                    await session.execute(delete(Grant).where(Grant.user_id == initial.author_id))
                elif fault == "lease":
                    await session.execute(update(WorkerLease).values(expires_at=0))
                else:
                    saved = await session.get(Action, action.id)
                    saved.native_result = saved.native_result | {"channel_id": 99}
        return result

    monkeypatch.setattr(commands.tokens, "issue", changed)
    with pytest.raises((Conflict, ValueError, AccessDenied)):
        await commands.route(binding, initial, "en", "evidence " + action.id)
    assert len(values[3].submitted) == 1


@pytest.mark.parametrize(
    "arguments",
    [
        "evidence",
        "evidence bad",
        "evidence 00000000-0000-4000-8000-000000000001 bad",
        "evidence x y z",
    ],
)
async def test_malformed_arguments_are_not_prompted_or_executed(db, monkeypatch, arguments):
    commands, router, binding, request, action, values = await configured(db, monkeypatch)
    request = request.model_copy(update={"text": "!oz git " + arguments})
    values[2].messages[request.message_id] = request
    with pytest.raises(ValueError):
        await commands.route(binding, request, "en", arguments)
    assert len(values[3].submitted) == 1


@pytest.mark.parametrize("fault", ["original_deleted", "original_edited", "journal", "page_issuer"])
async def test_router_replay_revalidates_original_chain_without_new_page_tokens(
    db, monkeypatch, fault
):
    commands, router, binding, request, action, values = await configured(
        db, monkeypatch, limit=512 if fault == "page_issuer" else 10000, long=fault == "page_issuer"
    )
    initial = request
    reply = await send(router, values[2], request)
    if fault == "page_issuer":
        token = next_token(reply.text)
        assert token
        request = request.model_copy(
            update={"message_id": 202, "text": f"!oz git evidence {action.id} {token}"}
        )
        await send(router, values[2], request)
        values[2].messages[initial.message_id] = initial.model_copy(update={"deleted": True})
    elif fault.startswith("original_"):
        original = values[2].messages[102]
        values[2].messages[102] = original.model_copy(
            update={
                "deleted": fault == "original_deleted",
                "revision": 1 if fault == "original_edited" else 0,
            }
        )
    else:
        async with db.sessions.begin() as session:
            saved = await session.get(Action, action.id)
            saved.native_result = saved.native_result | {"channel_id": 99}
    before = len(await rows(db, ControlToken))
    with pytest.raises((Conflict, ValueError, AccessDenied)):
        await router.route(request)
    assert len(await rows(db, ControlToken)) == before
    assert len(values[3].submitted) == 1


async def test_router_page_replay_does_not_mint_replacement_navigation(db, monkeypatch):
    commands, router, binding, request, action, values = await configured(
        db, monkeypatch, limit=512, long=True
    )
    first = await send(router, values[2], request)
    before = len(await rows(db, ControlToken))
    assert await router.route(request) == first
    assert len(await rows(db, ControlToken)) == before and len(values[3].submitted) == 1


@pytest.mark.parametrize("fault", ["pin", "reader", "handler"])
async def test_router_replay_never_returns_old_evidence_after_qualification_removed(
    db, monkeypatch, fault
):
    commands, router, binding, request, action, values = await configured(db, monkeypatch)
    await send(router, values[2], request)
    if fault == "pin":
        commands.results.pins = {}
    elif fault == "reader":
        commands.results.readers = {}
    else:
        router.git_evidence = None
    before = len(await rows(db, ControlToken))
    with pytest.raises(Conflict):
        await router.route(request)
    assert len(await rows(db, ControlToken)) == before and len(values[3].submitted) == 1
