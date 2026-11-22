import asyncio
import re
from html import unescape

from sqlalchemy import select, update

from jt_oz_bridge.domain.control import InteractionSnapshot
from jt_oz_bridge.storage.control_models import ControlToken, PendingInteraction
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_router import count, message, router, send
from tests.support import REF


async def pending(service, control, request="request", **changes):
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id=request,
        generation="source:1",
        kind="permission",
        pending=True,
        description="Run approved project checks",
        operation="shell.execute",
        resources=("pytest -q", "/workspace/project"),
        requested_scope=("exact command", "project directory"),
    ).model_copy(update=changes)
    control.requests[request] = snapshot
    return await service.permissions.interactions.observe(
        await service.bindings.get((await service.binding_for(message())).id, "realm", 7), snapshot
    )


def menu_token(text):
    text = unescape(text)
    return re.search(r"!oz choose ([A-Za-z0-9_-]{32}) 1", text)[1]


def decision_token(text):
    text = unescape(text)
    return re.search(r"!oz approve ([A-Za-z0-9_-]{32}) once", text)[1]


async def preview(service, source, control):
    await pending(service, control)
    menu = await send(service, source, message("!oz pending"))
    assert "Permission" in menu.text
    return await send(service, source, message("!oz choose " + menu_token(menu.text) + " 1", 102))


async def test_permission_preview_scope_and_once_decision_are_saved_not_claimed_approved(db):
    service, binding, source, control, _audience = await router(db)
    shown = await preview(service, source, control)
    assert (
        "shell" in shown.text
        and "exact command" in shown.text
        and "project directory" in shown.text
    )
    token = decision_token(shown.text)
    approved = await send(service, source, message("!oz approve " + token + " once", 103))
    assert "Received" in approved.text and "queued" in approved.text
    assert await service.route(source.messages[103]) == approved
    async with db.sessions() as session:
        actions = (await session.scalars(select(Action))).all()
        assert len(actions) == 1 and actions[0].state == "queued"
        assert actions[0].payload["decision"] == "once"
        assert actions[0].payload["source"]["text"] == source.messages[103].text
        assert actions[0].binding_id == binding.id
    assert "No pending requests" in (await send(service, source, message("!oz pending", 104))).text


async def test_denial_preserves_reason_and_original_source(db):
    service, _binding, source, control, _audience = await router(db)
    shown = await preview(service, source, control)
    item = message(
        "!oz deny " + decision_token(shown.text) + " Production changes are not approved", 103
    )
    await send(service, source, item)
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
        assert action.payload["decision"] == "reject"
        assert action.payload["reason"] == "Production changes are not approved"
        assert action.payload["source"] == item.model_dump(mode="json")


async def test_broad_approval_wrong_actor_and_expiry_never_create_action(db):
    service, _binding, source, control, _audience = await router(db)
    shown = await preview(service, source, control)
    token = decision_token(shown.text)
    assert (
        "permission"
        in (await send(service, source, message("!oz approve " + token + " always", 103))).text
    )
    assert (
        "expired"
        in (
            await send(service, source, message("!oz approve " + token + " once", 104, author_id=8))
        ).text
    )
    async with db.sessions.begin() as session:
        await session.execute(
            update(ControlToken).where(ControlToken.kind == "interaction").values(expires_at=0)
        )
    assert (
        "expired"
        in (await send(service, source, message("!oz approve " + token + " once", 105))).text
    )
    assert await count(db, Action) == 0


async def test_tui_resolution_invalidates_mobile_decision_without_reexecution(db):
    service, _binding, source, control, _audience = await router(db)
    shown = await preview(service, source, control)
    control.resolved = True
    result = await send(
        service, source, message("!oz approve " + decision_token(shown.text) + " once", 103)
    )
    assert "expired" in result.text and await count(db, Action) == 0
    async with db.sessions() as session:
        assert (await session.scalar(select(PendingInteraction))).state == "resolved"


async def test_pending_menu_has_nine_requests_and_explicit_next_choice(db):
    service, _binding, source, control, _audience = await router(db)
    for index in range(11):
        await pending(
            service, control, request=f"request:{index}", description=f"pending item {index}"
        )
    first = await send(service, source, message("!oz pending"))
    assert "10. Next page" in first.text and "11." not in first.text
    next_page = await send(
        service, source, message("!oz choose " + menu_token(first.text) + " 10", 102)
    )
    assert "Next page" not in next_page.text
    assert len(re.findall(r"^\d+\. Permission", next_page.text, re.MULTILINE)) == 2
    assert await count(db, Action) == 0


async def test_viewer_cannot_obtain_permission_token_from_pending_menu(db):
    service, _binding, source, control, _audience = await router(db)
    await pending(service, control)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    listed = await send(service, source, message("!oz pending"))
    result = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 102)
    )
    assert "have permission" in result.text
    async with db.sessions() as session:
        assert (
            await session.scalar(
                select(ControlToken.token_hash).where(ControlToken.kind == "interaction")
            )
            is None
        )
    assert await count(db, Action) == 0


async def test_two_real_human_commands_only_queue_one_permission_decision(db):
    service, binding, source, control, _audience = await router(db)
    identity = await pending(service, control)
    tokens = []
    for user in (7, 8):
        tokens.append(
            decision_token(
                await service.permissions.open(binding, message(author_id=user), "en", identity)
            )
        )
    items = [
        message("!oz approve " + tokens[0] + " once", 101),
        message("!oz deny " + tokens[1] + " Not now", 102, author_id=8),
    ]
    source.messages = {item.message_id: item for item in items}
    replies = await asyncio.gather(*[service.route(item) for item in items])
    assert sum("Received" in reply.text for reply in replies) == 1
    assert await count(db, Action) == 1


async def test_other_topic_cannot_use_permission_token_even_with_same_admin(db):
    service, _binding, source, control, _audience = await router(db)
    shown = await preview(service, source, control)
    other = REF.model_copy(update={"upstream_session_id": "different-original"})
    control.ref = other
    await service.bindings.bind("realm", 7, 10, "Other work", other)
    response = await send(
        service,
        source,
        message("!oz approve " + decision_token(shown.text) + " once", 103, topic="Other work"),
    )
    assert "have permission" in response.text
    assert await count(db, Action) == 0


async def test_expired_request_remains_visible_and_only_explicit_inspection_renews(db):
    service, _binding, source, control, _audience = await router(db)
    shown = await preview(service, source, control)
    old = decision_token(shown.text)
    async with db.sessions.begin() as session:
        await session.execute(update(PendingInteraction).values(expires_at=0))
        await session.execute(
            update(ControlToken).where(ControlToken.kind == "interaction").values(expires_at=0)
        )
    listed = await send(service, source, message("!oz pending", 103))
    assert "Timed out" in listed.text
    assert await count(db, Action) == 0
    refreshed = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 104)
    )
    assert "no decision has been sent" in refreshed.text
    new = decision_token(refreshed.text)
    assert new != old and await count(db, Action) == 0
    stale = await send(service, source, message("!oz approve " + old + " once", 105))
    assert "expired" in stale.text and await count(db, Action) == 0
    assert (
        "Received"
        in (await send(service, source, message("!oz approve " + new + " once", 106))).text
    )
    assert await count(db, Action) == 1


async def test_expired_request_resolved_in_tui_does_not_issue_a_new_token(db):
    service, _binding, source, control, _audience = await router(db)
    await pending(service, control)
    async with db.sessions.begin() as session:
        await session.execute(update(PendingInteraction).values(expires_at=0))
    control.resolved = True
    listed = await send(service, source, message("!oz pending"))
    result = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 102)
    )
    assert "expired" in result.text
    async with db.sessions() as session:
        assert (await session.scalar(select(PendingInteraction))).state == "resolved"
        assert (
            await session.scalar(select(ControlToken).where(ControlToken.kind == "interaction"))
            is None
        )
    assert await count(db, Action) == 0


async def test_native_requester_and_metadata_are_visible_but_sensitive_values_are_not(db):
    import json

    from jt_oz_bridge.domain.control import PermissionDetails

    service, _binding, source, control, _audience = await router(db)
    details = PermissionDetails(
        source_digest="b" * 64,
        metadata_json=json.dumps(
            {
                "command": "pytest -q",
                "env": {"PASSWORD": "PRIVATE_PREVIEW_PASSWORD", "PATH": "/workspace/bin"},
            }
        ),
        requester_json=json.dumps({"type": "tool", "messageID": "msg_source", "id": "call_source"}),
    )
    await pending(service, control, permission_details=details)
    listed = await send(service, source, message("!oz pending"))
    shown = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 102)
    )
    assert (
        "Tool call source" in shown.text
        and "msg_source" in shown.text
        and "call_source" in shown.text
    )
    assert (
        "Permission details" in shown.text
        and "pytest -q" in shown.text
        and "/workspace/bin" in shown.text
    )
    assert "PRIVATE_PREVIEW_PASSWORD" not in shown.text and "[REDACTED]" in shown.text
    assert "hidden" in shown.text
    assert decision_token(shown.text)


async def test_hidden_metadata_change_invalidates_old_preview_even_if_redacted_display_is_equal(db):
    from jt_oz_bridge.domain.control import PermissionDetails

    service, _binding, source, control, _audience = await router(db)
    details = PermissionDetails(
        source_digest="b" * 64, metadata_json='{"password":"[REDACTED]"}', redactions=1
    )
    await pending(service, control, permission_details=details)
    listed = await send(service, source, message("!oz pending"))
    shown = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 102)
    )
    token = decision_token(shown.text)
    control.requests["request"] = control.requests["request"].model_copy(
        update={"permission_details": details.model_copy(update={"source_digest": "c" * 64})}
    )
    result = await send(service, source, message("!oz approve " + token + " once", 103))
    assert "expired" in result.text and await count(db, Action) == 0


async def test_complete_preview_too_large_never_issues_decision_token(db):
    service, _binding, source, control, _audience = await router(db)
    await pending(service, control, description="x" * 1000000)
    listed = await send(service, source, message("!oz pending"))
    shown = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 102)
    )
    assert "too long to show in chat" in shown.text
    async with db.sessions() as session:
        assert (
            await session.scalar(
                select(ControlToken.token_hash).where(ControlToken.kind == "interaction")
            )
            is None
        )
    assert await count(db, Action) == 0


async def test_unpreviewable_description_is_not_leaked_in_pending_menu_or_given_token(db):
    service, _binding, source, control, _audience = await router(db)
    await pending(
        service, control, description="-----BEGIN PRIVATE KEY-----\nPRIVATE_INCOMPLETE_BODY"
    )
    listed = await send(service, source, message("!oz pending"))
    assert "PRIVATE_INCOMPLETE_BODY" not in listed.text and "No preview" in listed.text
    shown = await send(
        service, source, message("!oz choose " + menu_token(listed.text) + " 1", 102)
    )
    assert "decided here" in shown.text
    async with db.sessions() as session:
        assert (
            await session.scalar(
                select(ControlToken.token_hash).where(ControlToken.kind == "interaction")
            )
            is None
        )
    assert await count(db, Action) == 0
