"""Real isolated SQL/Source/router pipeline with an explicit synthetic Native producer."""

import asyncio
import re
import time

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.worktrees import WorktreeObservation, WorktreePreflight, WorktreeTemplate
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.worktree_commands import WorktreeCommands
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_router import Source, message, send
from tests.support import REF, bound


class SyntheticWorktree:
    """No installed qualification and no real worktree/setup/HTTP mutation."""

    def __init__(self, contract):
        self.template = WorktreeTemplate(
            reference=REF,
            native_project_id="native-project",
            destination_parent=REF.canonical_directory + "/worktrees",
            contract_sha256=contract,
            native_policy_sha256="b" * 64,
            project_facts_sha256="c" * 64,
            strategy_evidence_sha256="d" * 64,
            setup_command="echo setup",
        )
        self.proofs, self.observations, self.posts, self.readbacks = [], [], [], []
        self.comparison = "e" * 64
        self.directory_identity = "8" * 64
        self.before = self.after = None
        self.fail_after = False

    async def prepare(self, intent):
        proof = WorktreePreflight(
            intent_sha256=digest(intent.model_dump(mode="json")),
            comparison_sha256=self.comparison,
            issued_at=time.time(),
            expires_at=time.time() + 5,
            dirty_workspace=True,
        )
        self.proofs.append(proof)
        return proof

    def current(self, intent, proof):
        return (
            any(p is proof for p in self.proofs)
            and proof.expires_at > time.time()
            and proof.comparison_sha256 == self.comparison
        )

    async def create(self, intent, proof, *, authorize):
        if self.before:
            await self.before(intent)
        try:
            await authorize()
        except (Conflict, AccessDenied):
            raise MutationNotSent("synthetic_pre_send_denial") from None
        assert self.current(intent, proof)
        self.posts.append(intent)
        if self.after:
            await self.after(intent)
        if self.fail_after:
            raise TimeoutError("synthetic_lost_response_after_native_create")
        return self.observe(intent, "completed")

    def observe(self, intent, status):
        observed = WorktreeObservation(
            intent_sha256=digest(intent.model_dump(mode="json")),
            directory=intent.directory,
            native_project_id=self.template.native_project_id,
            physical_sha256="f" * 64,
            directory_identity_sha256=self.directory_identity,
            inventory_sha256="9" * 64,
            observed_at=time.time(),
            status=status,
        )
        self.observations.append(observed)
        return observed

    async def reconcile(self, intent):
        assert any(i == intent for i in self.posts)
        self.readbacks.append(intent)
        return self.observe(intent, "registered_setup_unknown")

    def observation_current(self, intent, observed):
        return (
            any(o is observed for o in self.observations) and observed.observed_at + 5 > time.time()
        )


async def setup(db):
    bindings, binding, control, audience = await bound(db)
    fence = await DurableStore(db).acquire_lease("worktree-test")
    source = Source()
    producer = SyntheticWorktree(control.contract_hash)
    commands = WorktreeCommands(
        bindings,
        source,
        TokenService(db, fence=ConsumerFence("worktree-test", fence)),
        {REF: producer},
    )
    router = CommandRouter(
        bindings, source, CommandInbox(db, "worktree-test", fence), worktrees=commands
    )
    return bindings, binding, source, producer, commands, router, audience


async def preview(db):
    values = await setup(db)
    _, _, source, _, _, router, _ = values
    first = await send(router, source, message("!oz worktrees"))
    choice = re.search(r"!oz worktree create (\S+)`", first.text)[1]
    second = await send(router, source, message("!oz worktree create " + choice, 102))
    token = re.search(r"!oz worktree confirm (\S+)`", second.text)[1]
    assert "Workspace has changes: true" in second.text and "privileges" in second.text
    return (*values, token)


async def actions(db):
    async with db.sessions() as session:
        return list((await session.scalars(select(Action))).all())


async def test_worktree_one_attempt_preview_confirm_and_original_binding_unchanged(db):
    _, original, source, producer, _, router, _, token = await preview(db)
    before = (
        original.canonical_directory,
        original.session_id,
        original.revision,
        original.session_key,
    )
    confirm = message("!oz worktree confirm " + token, 103)
    reply = await send(router, source, confirm)
    assert "Worktree created" in reply.text and len(producer.posts) == 1
    assert await router.route(confirm) == reply
    assert len(producer.posts) == 1
    row = (await actions(db))[0]
    assert row.operation == "worktree.create" and row.state == "completed"
    assert row.owner == "opencode" and row.admission["attempt_reserved"]
    async with db.sessions() as session:
        current = await session.get(Binding, original.id)
        assert (
            current.canonical_directory,
            current.session_id,
            current.revision,
            current.session_key,
        ) == before
    assert (
        not row.native_result["changes_original_session"]
        and not row.native_result["grants_execution"]
    )


async def test_worktree_lost_response_and_status_never_repeat_post_or_claim_setup_success(db):
    _, _, source, producer, _, router, _, token = await preview(db)
    producer.fail_after = True
    reply = await send(router, source, message("!oz worktree confirm " + token, 103))
    row = (await actions(db))[0]
    assert row.state == "ambiguous" and "create it again" in reply.text and len(producer.posts) == 1
    await send(router, source, message("!oz worktree confirm " + token, 104))
    status = await send(router, source, message("!oz worktree status " + row.id, 105))
    assert "registered_setup_unknown" in status.text and "setup succeeded" in status.text
    assert len(producer.posts) == 1 and len(producer.readbacks) == 1
    assert (await actions(db))[0].state == "ambiguous"


@pytest.mark.parametrize("change", ["source", "audience", "grant", "binding", "native"])
async def test_worktree_before_send_changes_never_post(db, change):
    _, binding, source, producer, _, router, audience, token = await preview(db)

    async def before(intent):
        if change == "source":
            source.messages[103] = source.messages[103].model_copy(update={"revision": 1})
        elif change == "audience":
            audience.users = frozenset({7, 8, 999})
        elif change == "native":
            producer.comparison = "0" * 64
        else:
            async with db.sessions.begin() as session:
                if change == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                else:
                    await session.execute(
                        update(Binding).where(Binding.id == binding.id).values(revision=2)
                    )

    producer.before = before
    if change in {"audience", "grant", "binding"}:
        with pytest.raises((Conflict, AccessDenied)):
            await send(router, source, message("!oz worktree confirm " + token, 103))
    else:
        await send(router, source, message("!oz worktree confirm " + token, 103))
    assert producer.posts == []
    assert (await actions(db))[0].state == "failed"


async def test_worktree_explicit_cancel_racing_before_reservation_has_zero_post(db):
    _, binding, source, producer, commands, router, _, token = await preview(db)

    async def before(intent):
        row = (await actions(db))[0]
        assert row.state == "worktree_prepared"
        cancel = message("!oz worktree cancel " + row.id, 104)
        source.messages[104] = cancel
        text = await commands.route(binding, cancel, "en", "worktree", "cancel " + row.id)
        assert "Cancelled" in text

    producer.before = before
    await send(router, source, message("!oz worktree confirm " + token, 103))
    assert producer.posts == [] and (await actions(db))[0].state == "cancelled"


async def test_worktree_cancel_after_send_reservation_cannot_claim_cancellation(db):
    _, binding, source, producer, commands, router, _, token = await preview(db)

    async def after(intent):
        row = (await actions(db))[0]
        assert row.state == "worktree_sending"
        cancel = message("!oz worktree cancel " + row.id, 104)
        source.messages[104] = cancel
        with pytest.raises(Conflict, match="after_send_reservation"):
            await commands.route(binding, cancel, "en", "worktree", "cancel " + row.id)

    producer.after = after
    await send(router, source, message("!oz worktree confirm " + token, 103))
    assert len(producer.posts) == 1 and (await actions(db))[0].state == "completed"


@pytest.mark.parametrize("stage", ["before", "after"])
async def test_worktree_cancelled_task_is_ambiguous_and_never_reposts(db, stage):
    _, _, source, producer, _, router, _, token = await preview(db)

    async def cancel(intent):
        raise asyncio.CancelledError()

    setattr(producer, stage, cancel)
    with pytest.raises(asyncio.CancelledError):
        await send(router, source, message("!oz worktree confirm " + token, 103))
    assert (await actions(db))[0].state == "ambiguous"
    assert len(producer.posts) == (stage == "after")


async def test_worktree_preview_digest_change_and_wrong_actor_require_new_confirmation(db):
    _, _, source, producer, _, router, _, token = await preview(db)
    await send(router, source, message("!oz worktree confirm " + token, 103, author_id=8))
    assert await actions(db) == [] and producer.posts == []
    producer.comparison = "0" * 64
    await send(router, source, message("!oz worktree confirm " + token, 104))
    assert await actions(db) == [] and producer.posts == []


@pytest.mark.parametrize(
    "prior_state,restored_state", [("worktree_prepared", "held"), ("worktree_sending", "ambiguous")]
)
async def test_worktree_recovery_old_fence_is_deny_only_and_queue_resume_cannot_dispatch(
    db, prior_state, restored_state
):
    bindings, binding, source, producer, commands, router, _, token = await preview(db)
    producer.fail_after = True
    await send(router, source, message("!oz worktree confirm " + token, 103))
    async with db.sessions.begin() as session:
        row = await session.get(Action, (await actions(db))[0].id)
        row.state = prior_state
        payload = dict(row.payload)
        payload["consumer"] = {"holder": "old-consumer", "fencing": 1}
        row.payload, row.operation_digest = payload, digest(payload)
    assert await commands.recover() == 1
    row = (await actions(db))[0]
    assert row.state == restored_state
    async with db.sessions.begin() as session:
        current = await session.get(Binding, binding.id)
        current.dispatch_paused = True
    await router.queue.resume(binding.id, binding.realm_id, 7, binding.revision, 0)
    assert (await actions(db))[0].state == restored_state
    # Even a malformed restored queued state is excluded by the general dispatcher.
    async with db.sessions.begin() as session:
        (await session.get(Action, row.id)).state = "queued"
    dispatcher = Dispatcher(
        bindings, bindings.control, source, commands.fence.holder, commands.fence.fencing
    )
    assert await dispatcher.advance(row.id) == "queued"
    assert len(producer.posts) == 1


async def test_worktree_historical_control_is_held_without_any_producer_or_token_effect(db):
    _, _, source, producer, _, router, _ = await setup(db)
    result = await send(router, source, message("!oz worktrees"), recovered=True)
    assert result.state == "held" and producer.proofs == [] and await actions(db) == []


async def test_worktree_completed_status_rejects_replaced_directory_identity_without_new_post(db):
    _, _, source, producer, _, router, _, token = await preview(db)
    await send(router, source, message("!oz worktree confirm " + token, 103))
    row = (await actions(db))[0]
    producer.directory_identity = "0" * 64
    result = await send(router, source, message("!oz worktree status " + row.id, 104))
    assert "expired" in result.text
    assert len(producer.posts) == 1 and (await actions(db))[0].native_result == row.native_result


async def test_worktree_cancelling_preview_consumes_only_original_actor_token_and_never_posts(db):
    _, _, source, producer, _, router, _, token = await preview(db)
    result = await send(router, source, message("!oz worktree cancel " + token, 103))
    assert "Cancelled" in result.text
    await send(router, source, message("!oz worktree confirm " + token, 104))
    assert producer.posts == [] and await actions(db) == []
