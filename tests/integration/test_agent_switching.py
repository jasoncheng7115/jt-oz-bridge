"""Local DB and synthetic Native; these cases are not live or Human/mobile acceptance."""

import asyncio
import time
import uuid
from html import unescape
from types import MappingProxyType, SimpleNamespace

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.agent_configuration import (
    AgentConfigurationCell,
    ConfigurationReadiness,
)
from jt_oz_bridge.adapters.opencode.agent_settings import (
    AGENT_SETTING_SEMANTICS,
    AgentSettingsAttestation,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.services.agent_commands import AgentCommands
from jt_oz_bridge.services.agent_setting_publisher import AgentSettingPublisher
from jt_oz_bridge.services.agent_switch_coordinator import CONFIGURATION_HELD, EXPIRED
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from jt_oz_bridge.storage.session_configuration_heads import (
    AgentSwitchIntent,
    configuration_barrier,
)
from tests.agent_switch_support import ACTIVE, PLAN_RULES, Topic, bound_topic, native_root
from tests.contract.test_leaf_resources import finish
from tests.contract.test_native_project_policy import prompt_payload
from tests.integration.test_router import message, send


async def topic(db, **options) -> Topic:
    return await bound_topic(db, await native_root(**options))


async def close(item: Topic) -> None:
    await finish(item.root.proofs, item.root.transport)


async def actions(db, operation="agent.switch"):
    async with db.sessions() as session:
        return list(
            (
                await session.scalars(
                    select(Action).where(Action.operation == operation).order_by(Action.created_at)
                )
            ).all()
        )


async def head(item: Topic):
    return await item.registry.snapshot(item.root.reference)


async def preview(item: Topic, start=200):
    menu = await send(item.router, item.source, message("!agent", start))
    assert "**Plan**" in menu.text and "`!1`" in menu.text, menu.text
    return await send(item.router, item.source, message("!1", start + 1))


async def confirmed(item: Topic, start=200):
    await preview(item, start)
    return await send(item.router, item.source, message("!confirm", start + 2))


async def switched(item: Topic, start=200):
    await confirmed(item, start)
    action = (await actions(item.db))[-1]
    assert await item.coordinator.advance(action.id) == "completed"
    return action


async def prompt(item: Topic, identity: int, text="hello after the switch"):
    reply = await send(item.router, item.source, message(text, identity))
    async with item.db.sessions() as session:
        action = await session.scalar(
            select(Action).where(Action.dedupe_key == f"human:realm:{identity}")
        )
    return reply, action


def test_short_command_is_explicit_and_bound_plain_text_stays_a_prompt():
    assert parse_input("!agent", bound=True).command == "agent"
    assert parse_input("!oz agent", bound=True).command == "agent"
    assert parse_input("!agentplease", bound=True).kind == "prompt"
    assert parse_input("agent", bound=True).kind == "prompt"


async def test_menu_preview_and_confirmation_are_short_and_send_nothing_until_confirmed(db):
    item = await topic(db)
    try:
        menu = await send(item.router, item.source, message("!agent", 200))
        assert "Current Agent: **Build**" in menu.text and "1. **Plan** · primary" in menu.text
        assert "Not approved here: Review" in menu.text
        assert "Helper" not in menu.text and "Secret" not in menu.text
        shown = await send(item.router, item.source, message("!1", 201))
        assert unescape(shown.text).startswith("Switch Agent: **Build** → **Plan**")
        assert "permissions differ" in shown.text and "`!ok`" in shown.text
        assert not item.root.writes and not await actions(db)
        sent = await send(item.router, item.source, message("!confirm", 202))
        assert sent.text == "Sending the switch to OpenCode."
        saved = await actions(db)
        assert len(saved) == 1 and saved[0].state == "queued" and not item.root.writes
        assert saved[0].dedupe_key.startswith("agent-choice:")
    finally:
        await close(item)


async def test_traditional_chinese_flow_is_complete(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!oz lang zh-TW", 199))
        menu = await send(item.router, item.source, message("!agent", 200))
        assert "目前 Agent：**Build**" in menu.text and "回覆 `!1` 選擇" in menu.text
        shown = await send(item.router, item.source, message("!1", 201))
        assert "切換 Agent" in unescape(shown.text) and "`!ok`" in shown.text
        sent = await send(item.router, item.source, message("!confirm", 202))
        assert "OpenCode" in sent.text and "正在" in sent.text
    finally:
        await close(item)


async def test_successful_switch_one_post_atomic_stable_then_next_message_is_sent(db):
    item = await topic(db)
    try:
        action = await switched(item)
        posts = item.root.agent_posts()
        assert len(posts) == 1 and posts[0].read() == b'{"agent": "plan"}'
        saved = await head(item)
        assert saved.token.phase == "stable" and saved.effective.agent_id == "plan"
        assert saved.token.last_activation_action_id == action.id
        assert item.root.cell.readiness(item.root.reference).mode == "mutation_ready"
        assert await item.coordinator.advance(action.id) == "completed"
        assert len(item.root.agent_posts()) == 1
        # Stored admission records only a setting: it is never a finished turn.
        assert action.id == saved.token.last_activation_action_id
        current = (await actions(db))[-1]
        details = current.admission["admission"]["details"]
        assert details["turn_completed"] is False and details["starts_execution"] is False
        _reply, queued = await prompt(item, 300)
        assert queued.state == "queued"
        assert await item.worker.advance(queued.id) == "admitted"
        assert len(item.root.prompt_posts()) == 1
    finally:
        await close(item)


async def test_second_switch_to_another_approved_agent_starts_from_the_new_policy(db):
    item = await topic(db, transitions=(("build", "plan"), ("plan", "build")))
    try:
        await switched(item)
        await send(item.router, item.source, message("!agent", 400))
        await send(item.router, item.source, message("!1", 401))
        await send(item.router, item.source, message("!confirm", 402))
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "completed"
        assert len(item.root.agent_posts()) == 2
        saved = await head(item)
        assert saved.effective.agent_id == "build" and saved.token.phase == "stable"
        assert saved.token.revision >= 6
    finally:
        await close(item)


async def test_reverse_transition_is_not_implied_and_needs_its_own_enrollment(db):
    item = await topic(db)
    try:
        await switched(item)
        menu = await send(item.router, item.source, message("!agent", 400))
        assert "No other Agent is approved" in menu.text and "`!1`" not in menu.text
    finally:
        await close(item)


async def test_confirmation_is_one_use_and_duplicate_event_replays_without_second_action(db):
    item = await topic(db)
    try:
        first = await confirmed(item)
        replay = await item.router.route(item.source.messages[202])
        assert replay == first and len(await actions(db)) == 1
        again = await send(item.router, item.source, message("!confirm", 203))
        assert "expired" in again.text and len(await actions(db)) == 1
        old_menu = await send(item.router, item.source, message("!1", 204))
        assert "expired" in old_menu.text or "no menu" in old_menu.text
    finally:
        await close(item)


async def test_new_menu_retires_older_controls_so_they_cannot_resurface(db):
    item = await topic(db)
    try:
        await preview(item, 200)
        await send(item.router, item.source, message("!agent", 210))
        confirm = await send(item.router, item.source, message("!confirm", 211))
        assert "expired" in confirm.text and not await actions(db)
    finally:
        await close(item)


async def test_other_actor_viewer_and_expired_controls_cannot_use_the_menu(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        other = await send(item.router, item.source, message("!1", 201, author_id=8))
        assert (
            "expired" in other.text or "no menu" in other.text or "permission" in other.text.lower()
        )
        viewer_menu = await send(item.router, item.source, message("!agent", 202, author_id=8))
        assert "operator role" in viewer_menu.text and "`!1`" not in viewer_menu.text
        async with db.sessions.begin() as session:
            await session.execute(update(ControlToken).values(expires_at=time.time() - 1))
        expired = await send(item.router, item.source, message("!1", 203))
        assert ("expired" in expired.text or "no menu" in expired.text) and not await actions(db)
    finally:
        await close(item)


async def revoke(db):
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))


async def test_revoked_grant_stops_confirmation_without_any_action_or_post(db):
    item = await topic(db)
    try:
        await preview(item)
        await revoke(db)
        with pytest.raises(AccessDenied):
            await send(item.router, item.source, message("!confirm", 202))
        assert not await actions(db) and not item.root.writes
    finally:
        await close(item)


async def test_grant_revoked_after_confirmation_is_rejected_before_any_post(db):
    item = await topic(db)
    try:
        await confirmed(item)
        await revoke(db)
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "rejected"
        assert not item.root.writes and (await actions(db))[-1].status_reason == (
            "authorization_revoked"
        )
    finally:
        await close(item)


async def test_edited_menu_source_blocks_the_choice(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        item.source.messages[200] = message("!agent", 200, revision=1)
        reply = await send(item.router, item.source, message("!1", 201))
        assert "expired" in reply.text and await head(item) is None
    finally:
        await close(item)


async def test_edited_preview_source_blocks_confirmation(db):
    item = await topic(db)
    try:
        await preview(item)
        item.source.messages[201] = message("!1", 201, revision=1)
        reply = await send(item.router, item.source, message("!confirm", 202))
        assert "expired" in reply.text and not await actions(db)
    finally:
        await close(item)


@pytest.mark.parametrize("edited", [201, 202])
async def test_source_edited_before_attempt_is_rejected_and_never_sent(db, edited):
    item = await topic(db)
    try:
        await confirmed(item)
        item.source.messages[edited] = item.source.messages[edited].model_copy(
            update={"revision": 1}
        )
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "rejected"
        assert not item.root.writes and (await head(item)).token.phase == "stable"
    finally:
        await close(item)


async def test_expired_confirmation_is_rejected_without_post(db, monkeypatch):
    item = await topic(db)
    try:
        await preview(item)
        monkeypatch.setattr("jt_oz_bridge.services.agent_commands.CONFIRM_TTL", -1)
        await send(item.router, item.source, message("!confirm", 202))
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "rejected"
        current = (await actions(db))[-1]
        assert current.status_reason == EXPIRED and not item.root.writes
    finally:
        await close(item)


async def test_not_idle_blocks_preview_and_pending_interaction_is_untouched(db):
    item = await topic(db)
    data = item.root.data
    try:
        await send(item.router, item.source, message("!agent", 200))
        data["session.active"]["data"] = {item.root.reference.upstream_session_id: ACTIVE}
        data["session.permission.list"]["data"] = [
            {
                "id": "per_original",
                "sessionID": item.root.reference.upstream_session_id,
                "action": "write",
                "resources": ["file.txt"],
                "message": "Write original",
            }
        ]
        await item.root.proofs.watch(item.root.reference)
        busy = await send(item.router, item.source, message("!1", 201))
        assert "busy" in busy.text and not item.root.writes
        pending = await item.root.client.snapshot(item.root.reference)
        assert pending.state == ExecutionState.WAITING_PERMISSION
        assert data["session.permission.list"]["data"][0]["id"] == "per_original"
    finally:
        await close(item)


async def test_root_going_busy_after_reservation_is_known_unsent_then_stable(db):
    item = await topic(db)
    try:
        await confirmed(item)
        item.root.data["session.active"]["data"] = {item.root.reference.upstream_session_id: ACTIVE}
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "rejected"
        assert not item.root.writes
        saved = await head(item)
        assert saved.token.phase == "stable" and saved.effective.agent_id == "build"
        assert saved.token.revision == 3  # Reservation and rejection each consumed a revision.
        assert (await actions(db))[-1].native_result["phase"] == "not_sent"
    finally:
        await close(item)


async def test_lost_ack_is_quarantined_never_resent_even_when_target_is_observed(db):
    item = await topic(db, transitions=(("build", "plan"),))
    item.root.post_mode[0] = "lost_ack"
    try:
        await confirmed(item)
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "ambiguous"
        assert len(item.root.agent_posts()) == 1
        # Native shows the target, but equality cannot attribute this uncertain write.
        assert item.root.data["session.get"]["data"]["agent"] == "plan"
        saved = await head(item)
        assert saved.token.phase == "quarantined" and saved.effective.agent_id == "build"
        assert await item.coordinator.advance(action.id) == "ambiguous"
        assert await item.registry.restore(item.root.reference) is not None
        assert len(item.root.agent_posts()) == 1
        assert (await head(item)).token.phase == "quarantined"
        assert (await actions(db))[-1].state == "ambiguous"
    finally:
        await close(item)


async def test_quarantine_blocks_every_same_root_mutation_except_interrupt(db):
    item = await topic(db)
    item.root.post_mode[0] = "lost_ack"
    try:
        await confirmed(item)
        await item.coordinator.advance((await actions(db))[-1].id)
        async with db.sessions() as session:
            assert await configuration_barrier(session, item.root.reference) == "quarantined"
        reply, queued = await prompt(item, 300)
        assert "Agent review" in reply.text
        assert await item.worker.advance(queued.id) != "admitted"
        assert not item.root.prompt_posts()
        stop = await send(item.router, item.source, message("!oz stop", 301))
        assert stop.state == "reply"
    finally:
        await close(item)


async def test_observed_target_adoption_is_local_only_and_old_uncertainty_stays_visible(db):
    item = await topic(db)
    item.root.post_mode[0] = "lost_ack"
    try:
        await confirmed(item)
        old = (await actions(db))[-1]
        await item.coordinator.advance(old.id)
        review = await send(item.router, item.source, message("!agent", 300))
        text = unescape(review.text)
        assert "unknown result" in text and "**Plan**" in text and "`!ok`" in text
        adopted = await send(item.router, item.source, message("!confirm", 301))
        assert "Nothing was sent to OpenCode" in adopted.text
        assert len(item.root.agent_posts()) == 1
        assert (await actions(db))[0].state == "ambiguous"
        record = (await actions(db, "agent.adopt"))[0]
        assert record.state == "completed" and not record.admission
        assert record.payload["resolves_action_id"] == old.id
        saved = await head(item)
        assert saved.token.phase == "stable" and saved.effective.agent_id == "plan"
        _reply, queued = await prompt(item, 302)
        assert await item.worker.advance(queued.id) == "admitted"
    finally:
        await close(item)


async def test_observed_old_agent_can_release_quarantine_without_any_native_write(db):
    item = await topic(db)
    item.root.post_mode[0] = "reject"
    try:
        await confirmed(item)
        await item.coordinator.advance((await actions(db))[-1].id)
        assert item.root.data["session.get"]["data"]["agent"] == "build"
        review = await send(item.router, item.source, message("!agent", 300))
        assert "`!ok`" in review.text
        await send(item.router, item.source, message("!confirm", 301))
        saved = await head(item)
        assert saved.token.phase == "stable" and saved.effective.agent_id == "build"
        assert len(item.root.agent_posts()) == 1
    finally:
        await close(item)


async def test_external_tui_change_stays_read_only_then_exact_approved_adoption(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))  # Mints the first head.
        item.root.external_switch("plan")
        await item.registry.restore(item.root.reference)
        assert (await head(item)).token.phase == "external_unqualified"
        assert not item.root.client.capabilities(item.root.reference)["agent.switch"].supported or (
            item.root.cell.readiness(item.root.reference).reason == "external_change"
        )
        _reply, queued = await prompt(item, 300)
        assert await item.worker.advance(queued.id) != "admitted"
        assert not item.root.prompt_posts()
        # History and read scope remain available while mutations wait for review.
        read = await item.root.client.snapshot(item.root.reference)
        assert read.reference == item.root.reference
        review = await send(item.router, item.source, message("!agent", 301))
        assert "outside Zulip" in review.text and "`!ok`" in review.text
        done = await send(item.router, item.source, message("!confirm", 302))
        assert "Nothing was sent" in done.text and not item.root.agent_posts()
        assert (await head(item)).effective.agent_id == "plan"
        async with db.sessions() as session:
            held = await session.get(Action, queued.id)
        assert held.state in {"held", "rejected"}
    finally:
        await close(item)


async def test_unapproved_external_agent_remains_read_only_with_no_confirm_offered(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))
        item.root.external_switch("review")
        review = await send(item.router, item.source, message("!agent", 300))
        assert "isn&#x27;t approved" in review.text or "isn't approved" in review.text
        assert "`!ok`" not in review.text
        again = await send(item.router, item.source, message("!confirm", 301))
        assert "expired" in again.text or "invalid" in again.text
        assert (await head(item)).token.phase == "external_unqualified"
    finally:
        await close(item)


async def test_external_change_back_to_exact_approved_state_restores_readiness(db):
    item = await topic(db, transitions=(("build", "plan"),))
    try:
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))
        item.root.external_switch("plan")
        await item.registry.restore(item.root.reference)
        item.root.external_switch("build")
        restored = await item.registry.restore(item.root.reference)
        assert restored.mode == "mutation_ready" and (await head(item)).token.phase == "stable"
        assert not item.root.writes
    finally:
        await close(item)


async def test_same_agent_id_definition_drift_is_an_external_change(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))
        item.root.agents["build"]["system"] = "same id, same permissions, new instructions"
        restored = await item.registry.restore(item.root.reference)
        assert restored.mode == "read_only" and restored.reason == "external_change"
    finally:
        await close(item)


async def test_restart_with_reservation_open_quarantines_without_any_post(db):
    item = await topic(db)
    try:
        await confirmed(item)
        saved = await head(item)
        action = (await actions(db))[-1]
        await item.registry.heads.reserve(
            saved.token,
            action.id,
            action.version,
            lock_authority=_authority,
            current=lambda: True,
        )
        restored = await item.registry.restore(item.root.reference)
        assert restored.mode == "read_only" and restored.reason == "review_required"
        assert not item.root.writes and (await actions(db))[-1].state == "ambiguous"
    finally:
        await close(item)


async def _authority(_session):
    return None


async def _prepared(item: Topic):
    """Commit activation_prepared, then lose the process before the final commit."""
    settle = item.registry.heads.settle

    async def crash(token, outcome, evidence_sha256, **kwargs):
        if outcome == "activated":
            raise asyncio.CancelledError
        return await settle(token, outcome, evidence_sha256, **kwargs)

    item.registry.heads.settle = crash
    action = (await actions(item.db))[-1]
    with pytest.raises(asyncio.CancelledError):
        await item.coordinator.advance(action.id)
    item.registry.heads.settle = settle
    return action


async def test_restart_after_prepared_activates_by_get_only_with_no_second_setter(db):
    item = await topic(db)
    try:
        await confirmed(item)
        await _prepared(item)
        assert (await head(item)).token.phase == "activation_prepared"
        assert len(item.root.agent_posts()) == 1
        restored = await item.registry.restore(item.root.reference)
        assert restored.mode == "mutation_ready" and restored.agent_id == "plan"
        assert len(item.root.agent_posts()) == 1
        assert (await actions(db))[-1].state == "completed"
    finally:
        await close(item)


async def test_restart_after_prepared_with_changed_native_stays_unverified(db):
    item = await topic(db)
    try:
        await confirmed(item)
        await _prepared(item)
        item.root.agents["plan"]["permissions"] = list(PLAN_RULES) + [
            {"action": "bash", "resource": "*", "effect": "allow"}
        ]
        restored = await item.registry.restore(item.root.reference)
        assert restored.reason == "activation_unverified"
        assert (await head(item)).token.phase == "activation_prepared"
        assert len(item.root.agent_posts()) == 1
    finally:
        await close(item)


async def test_lost_commit_response_joins_sql_and_never_repeats_the_setter(db):
    item = await topic(db)
    try:
        await confirmed(item)
        settle = item.registry.heads.settle

        async def lost(token, outcome, evidence_sha256, **kwargs):
            await settle(token, outcome, evidence_sha256, **kwargs)
            raise OSError("synthetic commit response lost")

        item.registry.heads.settle = lost
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "completed"
        item.registry.heads.settle = settle
        assert len(item.root.agent_posts()) == 1
        assert (await head(item)).token.phase == "stable"
    finally:
        await close(item)


async def test_generic_dispatcher_never_claims_or_recovers_an_agent_attempt(db):
    item = await topic(db)
    try:
        await confirmed(item)
        action = (await actions(db))[-1]
        assert await item.worker.advance(action.id) == "queued"
        assert not item.root.writes
        await item.worker.store.recover()
        async with db.sessions() as session:
            # Queued attempts revalidate their short confirmation deadline before sending.
            assert (await session.get(Action, action.id)).state == "queued"
        async with db.sessions.begin() as session:
            await session.execute(
                update(Action).where(Action.id == action.id).values(state="dispatching")
            )
        await item.worker.store.recover()
        async with db.sessions() as session:
            assert (await session.get(Action, action.id)).state == "dispatching"
    finally:
        await close(item)


async def test_queued_work_is_held_at_activation_not_retagged_and_notice_is_truthful(db):
    item = await topic(db)
    try:
        await confirmed(item)
        _reply, queued = await prompt(item, 300)
        action = (await actions(db))[-1]
        assert await item.coordinator.advance(action.id) == "completed"
        async with db.sessions() as session:
            held = await session.get(Action, queued.id)
        assert held.state == "held" and held.status_reason == CONFIGURATION_HELD
        assert not item.root.prompt_posts()
        outbox = Outbox(item.bindings, 77, fence=item.fence)
        publisher = AgentSettingPublisher(
            RoutedOutbox(outbox, realm_id="realm", message_limit=1000, topic_limit=60),
            ready=lambda ref, intent: item.root.cell.mutation_ready(ref),
        )
        assert await publisher.next_pending() == action.id
        batch = await publisher.publish(action.id)
        assert await publisher.next_pending() is None
        assert await publisher.publish(action.id) == batch
        async with db.sessions() as session:
            rows = list((await session.scalars(select(Delivery))).all())
        content = rows[0].payload["content"]
        assert "Default Agent is now **Plan**" in unescape(content)
        assert "1 waiting message" in content and "completed" not in content
    finally:
        await close(item)


async def test_ambiguous_and_rejected_notices_never_claim_success(db):
    item = await topic(db)
    item.root.post_mode[0] = "lost_ack"
    try:
        await confirmed(item)
        action = (await actions(db))[-1]
        await item.coordinator.advance(action.id)
        outbox = Outbox(item.bindings, 77, fence=item.fence)
        publisher = AgentSettingPublisher(
            RoutedOutbox(outbox, realm_id="realm", message_limit=1000, topic_limit=60),
            ready=lambda ref, intent: False,
        )
        assert await publisher.next_pending() == action.id
        await publisher.publish(action.id)
        async with db.sessions() as session:
            rows = list((await session.scalars(select(Delivery))).all())
        assert "won't be sent again" in unescape(rows[0].payload["content"])
    finally:
        await close(item)


async def test_completed_notice_waits_until_memory_agrees_with_committed_head(db):
    item = await topic(db)
    try:
        action = await switched(item)
        outbox = Outbox(item.bindings, 77, fence=item.fence)
        publisher = AgentSettingPublisher(
            RoutedOutbox(outbox, realm_id="realm", message_limit=1000, topic_limit=60),
            ready=lambda ref, intent: False,
        )
        assert await publisher.next_pending() is None
        publisher.ready = lambda ref, intent: True
        assert await publisher.next_pending() == action.id
    finally:
        await close(item)


async def test_second_realm_binding_shares_the_root_barrier(db):
    item = await topic(db)
    item.root.post_mode[0] = "lost_ack"
    try:
        await confirmed(item)
        await item.coordinator.advance((await actions(db))[-1].id)
        columns = {c.name: getattr(item.binding, c.name) for c in Binding.__table__.columns}
        other = Binding(
            **columns
            | {
                "id": str(uuid.uuid4()),
                "realm_id": "realm-b",
                "session_key": "b" * 64,
                "topic_key": "c" * 64,
            }
        )
        queued = Action(
            id=str(uuid.uuid4()),
            dedupe_key="other-realm",
            binding_id=other.id,
            binding_revision=other.revision,
            actor_id=7,
            payload={"operation": "prompt"},
            operation="prompt",
            operation_digest="d" * 64,
            state="queued",
            version=1,
            owner="bridge",
        )
        async with db.sessions.begin() as session:
            session.add_all((other, queued))
        async with db.sessions() as session:
            assert await configuration_barrier(session, reference(other)) == "quarantined"
        assert await item.worker.claim(queued, other, Permission.OPERATE) is False
        async with db.sessions() as session:
            assert (await session.get(Action, queued.id)).state == "queued"
    finally:
        await close(item)


async def test_head_is_never_minted_when_enrolled_policy_already_changed(db):
    item = await topic(db)
    try:
        item.root.external_switch("plan")
        await item.root.proofs.watch(item.root.reference)
        menu = await send(item.router, item.source, message("!agent", 200))
        assert "no longer match" in menu.text and await head(item) is None
    finally:
        await close(item)


async def test_unqualified_root_and_uncomposed_router_keep_original_behavior(db):
    item = await topic(db, qualified=False)
    try:
        menu = await send(item.router, item.source, message("!agent", 200))
        assert "isn't enabled" in menu.text or "isn&#x27;t enabled" in menu.text
        item.router.agents = None
        plain = await send(item.router, item.source, message("!oz agent", 201))
        assert "isn't available" in plain.text
        choose = await send(item.router, item.source, message("!1", 202))
        assert "expired" in choose.text or "no menu" in choose.text
        assert not item.root.writes
    finally:
        await close(item)


async def test_stored_intent_seals_sources_endpoints_and_no_definition_bodies(db):
    item = await topic(db)
    item.root.agents["plan"]["system"] = "PRIVATE SYSTEM PROMPT"
    try:
        item.root.settings.transitions = (item.root.transition("build", "plan"),)
        await confirmed(item)
        action = (await actions(db))[-1]
        intent = AgentSwitchIntent.model_validate(action.payload)
        assert intent.source["message_id"] == 202 and intent.preview_source["message_id"] == 201
        assert digest(action.payload) == action.operation_digest
        assert (
            intent.transition_certificate_sha256
            == item.root.settings.transitions[0].enrollment_sha256
        )
        assert "PRIVATE SYSTEM PROMPT" not in str(action.payload)
    finally:
        await close(item)


async def test_registry_facade_gates_mutations_keeps_interrupt_and_pins_approved_policy(db):
    item = await topic(db)
    registry = SessionRegistry(
        {
            item.root.reference: RegisteredSession(
                item.root.reference,
                item.root.transport.profile.sha256,
                item.root.client,
                item.root.client.models,
                _Results(),
                _pending,
            )
        }
    )
    try:
        ref = item.root.reference
        registry.attach_configuration(item.root.cell)
        with pytest.raises(ValueError, match="already_composed"):
            registry.attach_configuration(item.root.cell)
        assert registry.capabilities(ref)["prompt"].supported
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))
        saved = await head(item)
        item.registry.publish_snapshot(saved, reason="review_required")
        gated = registry.capabilities(ref)
        assert not gated["prompt"].supported and not gated["model.switch"].supported
        assert gated["interrupt"].supported
        assert (await registry.snapshot(ref)).reference == ref
        item.registry.publish_snapshot(saved, reason=None)
        assert registry.capabilities(ref)["prompt"].supported

        # A repeated identical restore during a Native write must not turn it ambiguous.
        submitted = item.root.client.submit

        async def restored_during_write(reference, payload, action_id):
            result = await submitted(reference, payload, action_id)
            item.registry.publish_snapshot(saved, reason=None)
            return result

        item.root.client.submit = restored_during_write
        admitted = await registry.submit(ref, prompt_payload(), "action_fixture")
        assert admitted.status == "admitted"

        async def changed_during_write(reference, payload, action_id):
            result = await submitted(reference, payload, action_id)
            item.root.cell.set(
                ConfigurationReadiness(
                    reference=ref,
                    root_key=saved.token.root_key,
                    revision=saved.token.revision + 9,
                    effective_sha256="f" * 64,
                    agent_id="plan",
                    policy_sha256="e" * 64,
                    mode="mutation_ready",
                )
            )
            return result

        item.root.client.submit = changed_during_write
        item.root.data["session.message.list"] = {"data": [], "cursor": {}}
        with pytest.raises(Conflict, match="original_session_configuration_changed"):
            await registry.submit(ref, prompt_payload(), "action_fixture")
    finally:
        await close(item)


class _Results:
    async def capture(self, correlation):
        raise AssertionError("no result capture in this case")

    def current(self, evidence):
        return False


async def _pending(_reference):
    return ()


async def test_failed_read_keeps_proven_readiness_but_never_grants_it_at_startup(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))
        proven = item.root.cell.readiness(item.root.reference)
        observe = item.root.settings.observe

        async def unavailable(_reference):
            raise TimeoutError

        item.root.settings.observe = unavailable
        kept = await item.registry.restore(item.root.reference)
        assert kept is proven and kept.mode == "mutation_ready"
        item.root.cell._state = MappingProxyType({})  # A restarted process knows nothing yet.
        fresh = await item.registry.restore(item.root.reference)
        assert fresh.mode == "read_only" and fresh.reason == "native_unverified"
        item.root.settings.observe = observe
        assert (await item.registry.restore(item.root.reference)).mode == "mutation_ready"
    finally:
        await close(item)


async def test_running_root_stays_ready_on_background_restore_and_cannot_switch(db):
    item = await topic(db)
    try:
        await send(item.router, item.source, message("!agent", 200))
        await send(item.router, item.source, message("!1", 201))
        data = item.root.data
        data["session.active"]["data"] = {item.root.reference.upstream_session_id: ACTIVE}
        data["session.get"]["data"]["tokens"]["output"] = 99
        restored = await item.registry.restore(item.root.reference)
        assert restored.mode == "mutation_ready" and not item.root.writes
    finally:
        await close(item)


async def test_lost_watch_waits_then_expires_visibly_without_any_post(db, monkeypatch):
    item = await topic(db)
    try:
        await preview(item)
        await send(item.router, item.source, message("!confirm", 202))
        action = (await actions(db))[-1]
        item.root.proofs.revoke_watch(item.root.reference)
        assert await item.coordinator.advance(action.id) == "queued"
        assert (await actions(db))[-1].state == "queued" and not item.root.writes
    finally:
        await close(item)


async def test_paused_queue_holds_confirmation_and_resume_cannot_revive_old_intent(db):
    item = await topic(db)
    try:
        await preview(item)
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(dispatch_paused=True))
        await send(item.router, item.source, message("!confirm", 202))
        action = (await actions(db))[-1]
        assert action.state == "held" and not item.root.writes
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(dispatch_paused=False))
            await session.execute(
                update(Action)
                .where(Action.id == action.id)
                .values(state="queued", version=Action.version + 1)
            )
        assert await item.coordinator.advance(action.id) == "rejected"
        assert not item.root.writes and (await head(item)).token.phase == "stable"
    finally:
        await close(item)


def _attestation(ref):
    return AgentSettingsAttestation(
        reference=ref,
        native_project_id="global",
        contract_sha256="1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce",
        semantics_sha256=AGENT_SETTING_SEMANTICS,
        switch_evidence_sha256="a" * 64,
        mixed_tail_evidence_sha256="b" * 64,
        policy_transition_evidence_sha256="c" * 64,
    )


async def test_runtime_composes_switching_only_with_explicit_agent_enrollment(db, tmp_path):
    from tests.integration.test_consumer_runtime import setup as runtime_setup
    from tests.support import REF

    attestation = _attestation(REF)
    client = SimpleNamespace(
        attestation=attestation, transitions=(), available=lambda reference: False
    )
    cell = AgentConfigurationCell({REF: attestation})
    pipeline, *_rest = await runtime_setup(
        db,
        agent_fields={
            "agent_settings": {REF: client},
            "agent_origins": {REF: ("1" * 64, "2" * 64)},
            "agent_policies": {REF: "3" * 64},
            "agent_configuration": cell,
        },
    )
    assert isinstance(pipeline.router.agents, AgentCommands)
    assert pipeline.agent_results is not None and pipeline.agent_coordinator is not None
    runtime = pipeline.runtime()
    assert "native-agent-settings" in [worker.name for worker in runtime.workers]
    assert "agent-configuration-restoration" in [item.name for item in runtime.resources]
    assert await pipeline.agent_coordinator.queued() == ()
    await pipeline.agent_registry.restore_all()
    assert cell.readiness(REF) is None  # An absent head stays unmanaged, not revision zero.
    worker = asyncio.create_task(pipeline.maintain_agent_settings())
    await asyncio.sleep(0.05)
    worker.cancel()
    with pytest.raises(asyncio.CancelledError):
        await worker


async def test_runtime_without_agent_enrollment_adds_nothing(db):
    from tests.integration.test_consumer_runtime import setup as runtime_setup

    pipeline, *_rest = await runtime_setup(db)
    assert pipeline.router.agents is None and pipeline.agent_coordinator is None
    runtime = pipeline.runtime()
    assert "native-agent-settings" not in [worker.name for worker in runtime.workers]
    assert "agent-configuration-restoration" not in [item.name for item in runtime.resources]


def test_tree_registered_root_cannot_enroll_agent_switching_yet():
    from jt_oz_bridge.services.runtime_enrollment import require_agent_switch_scope
    from tests.support import REF

    require_agent_switch_scope({REF: object()}, ())
    require_agent_switch_scope({}, (REF,))
    with pytest.raises(ValueError, match="tree_root_not_qualified"):
        require_agent_switch_scope({REF: object()}, (REF,))
