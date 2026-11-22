"""Isolated system-admin decisions; never real Zulip Human or Native acceptance."""

import asyncio
import time

import httpx
import pytest
from sqlalchemy import func, select, text, update

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.admin import AdminAuth, LoginRejected
from jt_oz_bridge.services.admin_decisions import AdminDecisions, read_intent
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.storage.admin_models import AdminDecision
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken, PendingInteraction
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import (
    Action,
    AdminAccount,
    AdminSession,
    AuditEvent,
    Delivery,
    Grant,
    WorkerLease,
    uid,
)
from jt_oz_bridge.web.app import create_app
from tests.integration.test_dispatch import message
from tests.support import bound

PRIVATE = "SYNTHETIC_PRIVATE_PROMPT_OR_INTERACTION"


async def principal(db):
    auth = AdminAuth(db)
    initial = await auth.create("synthetic-admin")
    token, _, _ = await auth.login("synthetic-admin", initial, "setup")
    account = await auth.authenticate(token)
    await auth.reset_password(account, "synthetic-admin-decision-password")
    token, csrf, _ = await auth.login(
        "synthetic-admin", "synthetic-admin-decision-password", "test"
    )
    return auth, account.id, token, csrf


async def setup(db):
    bindings, binding, control, _ = await bound(db)
    auth, admin_id, token, _ = await principal(db)
    holder = uid()
    fencing = await DurableStore(db).acquire_lease(holder, ttl=600)
    async with db.sessions.begin() as session:
        for i, state in enumerate(("queued", "queued", "running")):
            session.add(
                Action(
                    id=uid(),
                    dedupe_key=f"admin-fixture-{i}",
                    binding_id=binding.id,
                    binding_revision=1,
                    actor_id=7,
                    operation_digest="a" * 64,
                    payload={"text": PRIVATE},
                    admission={"data": PRIVATE},
                    native_result={"data": PRIVATE},
                    operation="prompt",
                    state=state,
                )
            )
        session.add(
            PendingInteraction(
                id=uid(),
                identity_key="b" * 64,
                binding_id=binding.id,
                binding_revision=1,
                snapshot={"question": PRIVATE},
                snapshot_hash="c" * 64,
                expires_at=time.time() + 600,
                state="pending",
            )
        )
        session.add(
            Delivery(
                id=uid(),
                dedupe_key="admin-delivery",
                binding_id=binding.id,
                binding_revision=1,
                payload={"content": PRIVATE},
                payload_hash="d" * 64,
                state="held",
            )
        )
    return (
        AdminDecisions(db, Settings()),
        auth,
        admin_id,
        token,
        ConsumerFence(holder, fencing),
        bindings,
        binding,
        control,
    )


async def preview(values, operation="pause", client=None):
    service, _, admin_id, token, fence, _, binding, _ = values
    return await service.preview(
        token,
        admin_id,
        fence,
        client_action_id=client or uid(),
        operation=operation,
        binding_id=binding.id,
        binding_revision=1,
        queue_revision=0,
    )


async def finish(values, decision, *, cancel=False, **changes):
    service, _, admin_id, token, fence, *_ = values
    args = dict(
        decision_id=decision["decision_id"],
        confirmation_token=decision["confirmation_token"],
        version=1,
        cancel=cancel,
    )
    args.update(changes)
    return await service.finish(token, admin_id, fence, **args)


@pytest.mark.parametrize("operation", ("pause", "unbind"))
async def test_local_admin_preview_confirm_replay_and_original_work_preservation(
    db, monkeypatch, operation
):
    values = await setup(db)
    service, _, admin_id, _, _, _, binding, control = values
    calls = list(control.calls)
    async with db.engine.connect() as connection:
        original_payloads = (
            await connection.execute(
                text("SELECT id,payload,admission,native_result FROM actions ORDER BY id")
            )
        ).all()
    original_open = db.cipher.open

    def only_own_decision(ciphertext, scope, **kwargs):
        assert scope.get("table") == "admin_decisions", (
            "Administrative operation decrypted unrelated content"
        )
        return original_open(ciphertext, scope, **kwargs)

    monkeypatch.setattr(db.cipher, "open", only_own_decision)
    decision = await preview(values, operation)
    assert decision["principal_kind"] == "web_administrator"
    assert decision["preview"]["scope"]["reference"]["upstream_session_id"] == binding.session_id
    assert decision["preview"]["affected"]["actions"] == {"queued": 2, "running": 1}
    assert PRIVATE not in str(decision)
    async with db.sessions() as session:
        current = await session.get(Binding, binding.id)
        assert (
            current.state == "active"
            and not current.dispatch_paused
            and current.queue_revision == 0
        )
    first, duplicate = await asyncio.gather(finish(values, decision), finish(values, decision))
    assert first == duplicate and first["result"]["actions_held"] == 2
    assert (
        not first["result"]["native_session_deleted"] and first["result"]["upstream_requests"] == 0
    )
    assert control.calls == calls
    async with db.sessions() as session:
        current = await session.get(Binding, binding.id)
        assert (
            current.session_id == binding.session_id
            and current.dispatch_paused
            and current.queue_revision == 1
        )
        assert current.state == ("unbound" if operation == "unbind" else "active")
        assert current.revision == (2 if operation == "unbind" else 1)
        assert (current.session_key is None) == (operation == "unbind")
        assert sorted((await session.scalars(select(Action.state))).all()) == [
            "held",
            "held",
            "running",
        ]
        assert await session.scalar(select(func.count()).select_from(Grant)) == 6
        assert await session.scalar(select(func.count()).select_from(CommandReceipt)) == 0
        assert await session.scalar(select(func.count()).select_from(ControlToken)) == 0
        audit = (
            await session.execute(
                select(AuditEvent.actor, AuditEvent.event).where(
                    AuditEvent.event.in_(("admin_queue_paused", "admin_session_unbound"))
                )
            )
        ).all()
        assert audit == [
            (
                "admin:" + admin_id,
                "admin_session_unbound" if operation == "unbind" else "admin_queue_paused",
            )
        ]
        assert await session.scalar(select(PendingInteraction.state)) == "pending"
        assert await session.scalar(select(Delivery.state)) == "held"
    async with db.engine.connect() as connection:
        assert (
            await connection.execute(
                text("SELECT id,payload,admission,native_result FROM actions ORDER BY id")
            )
        ).all() == original_payloads
        blob = (await connection.execute(text("SELECT payload FROM admin_decisions"))).scalar_one()
        assert (
            isinstance(blob, bytes)
            and decision["confirmation_token"].encode() not in blob
            and PRIVATE.encode() not in blob
        )


async def test_preview_idempotency_and_cross_target_reuse_rejects(db):
    values = await setup(db)
    client = uid()
    a, b = await asyncio.gather(preview(values, client=client), preview(values, client=client))
    assert a == b
    with pytest.raises(Conflict, match="idempotency"):
        await preview(values, "unbind", client=client)
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AdminDecision)) == 1


@pytest.mark.parametrize(
    "drift",
    (
        "revision",
        "queue",
        "pause",
        "topic",
        "channel",
        "root",
        "backend",
        "directory",
        "owner",
        "audience",
        "audience_revision",
        "unbind",
        "action",
        "new_action",
        "interaction",
        "delivery",
        "lease",
        "login",
        "reset",
        "must_reset",
        "disabled",
        "expiry",
    ),
)
async def test_current_authority_scope_work_and_expiry_are_rechecked_atomically(db, drift):
    values = await setup(db)
    service, auth, admin_id, token, fence, _, binding, _ = values
    decision = await preview(values)
    async with db.sessions.begin() as session:
        current = await session.get(Binding, binding.id)
        if drift == "revision":
            current.revision += 1
        elif drift == "queue":
            current.queue_revision += 1
        elif drift == "pause":
            current.dispatch_paused = True
        elif drift == "topic":
            current.topic = "changed"
        elif drift == "channel":
            current.channel_id = 11
        elif drift == "root":
            current.session_id = "another-original-root"
        elif drift == "backend":
            current.backend_identity = "replacement"
        elif drift == "directory":
            current.canonical_directory = "/workspace/other"
        elif drift == "owner":
            current.owner_id = 8
        elif drift == "audience":
            current.audience_user_ids = [7]
        elif drift == "audience_revision":
            current.audience_revision = "changed"
        elif drift == "unbind":
            current.state = "unbound"
        elif drift == "action":
            await session.execute(update(Action).values(version=Action.version + 1))
        elif drift == "new_action":
            session.add(
                Action(
                    id=uid(),
                    dedupe_key="new-work",
                    binding_id=binding.id,
                    binding_revision=1,
                    actor_id=8,
                    payload={},
                    operation_digest="a" * 64,
                    state="queued",
                )
            )
        elif drift == "interaction":
            await session.execute(update(PendingInteraction).values(state="resolved", version=2))
        elif drift == "delivery":
            await session.execute(update(Delivery).values(version=2))
        elif drift == "lease":
            await session.execute(update(WorkerLease).values(expires_at=0))
        elif drift == "login":
            await session.execute(update(AdminSession).values(expires_at=0))
        elif drift == "must_reset":
            await session.execute(update(AdminAccount).values(must_reset=True))
        elif drift == "expiry":
            row = await session.get(AdminDecision, decision["decision_id"])
            intent = read_intent(row).model_copy(update={"expires_at": time.time() - 1})
            row.payload = intent.payload()
            row.payload_hash = digest(row.payload)
            row.expires_at = intent.expires_at
    if drift == "disabled":
        service.settings.admin.enabled = False
    if drift == "reset":
        await auth.reset_password(await auth.authenticate(token), "different-synthetic-password")
    with pytest.raises((Conflict, LoginRejected)):
        await finish(values, decision)
    async with db.sessions() as session:
        row = await session.get(AdminDecision, decision["decision_id"])
        assert row.state == "pending" and row.version == 1
        assert (
            await session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.event == "admin_queue_paused")
            )
            == 0
        )
        assert await session.scalar(
            select(func.count()).select_from(Action).where(Action.state == "queued")
        ) == (3 if drift == "new_action" else 2)


async def test_other_login_same_admin_and_logout_cannot_consume_original_preview(db):
    values = await setup(db)
    service, auth, admin_id, token, fence, *_ = values
    decision = await preview(values)
    other, _, _ = await auth.login("synthetic-admin", "synthetic-admin-decision-password", "other")
    with pytest.raises(Conflict, match="unavailable"):
        await service.finish(
            other,
            admin_id,
            fence,
            decision_id=decision["decision_id"],
            confirmation_token=decision["confirmation_token"],
            version=1,
        )
    await auth.logout(token)
    with pytest.raises(LoginRejected):
        await finish(values, decision)


@pytest.mark.parametrize(
    "change", ("token", "version", "evidence", "principal_kind", "target", "result")
)
async def test_confirmation_and_encrypted_receipt_cannot_be_repurposed(db, change):
    values = await setup(db)
    decision = await preview(values)
    options = {}
    if change == "token":
        options["confirmation_token"] = "unrelated-token"
    elif change == "version":
        options["version"] = 2
    else:
        async with db.sessions.begin() as session:
            row = await session.get(AdminDecision, decision["decision_id"])
            payload = dict(row.payload)
            if change == "evidence":
                row.payload_hash = "0" * 64
            elif change == "principal_kind":
                payload["principal_kind"] = "zulip_human"
            elif change == "target":
                payload["scope"] = {**payload["scope"], "owner_id": 99}
            elif change == "result":
                payload["result"] = {"forged": True}
            if change != "evidence":
                row.payload = payload
                row.payload_hash = digest(payload)
    # A changed owner in a consistently rewritten preview is rejected against current SQL scope.
    with pytest.raises(Conflict):
        await finish(values, decision, **options)
    async with db.sessions() as session:
        assert not (await session.get(Binding, values[6].id)).dispatch_paused


async def test_cancel_is_durable_idempotent_and_cannot_turn_into_confirmation(db):
    values = await setup(db)
    decision = await preview(values, "unbind")
    a = await finish(values, decision, cancel=True)
    b = await finish(values, decision, cancel=True)
    assert a == b and a["state"] == "cancelled" and a["result"]["actions_held"] == 0
    with pytest.raises(Conflict):
        await finish(values, decision)
    async with db.sessions() as session:
        row = await session.get(Binding, values[6].id)
        assert row.state == "active" and not row.dispatch_paused and row.queue_revision == 0


async def test_competing_previews_and_completed_retry_after_new_consumer_epoch(db):
    values = await setup(db)
    a = await preview(values)
    b = await preview(values, "unbind")
    done = await finish(values, a)
    with pytest.raises(Conflict):
        await finish(values, b)
    await DurableStore(db).release_lease(values[4].holder, values[4].fencing)
    holder = uid()
    number = await DurableStore(db).acquire_lease(holder, ttl=600)
    new_fence = ConsumerFence(holder, number)
    changed = (*values[:4], new_fence, *values[5:])
    assert await finish(changed, a) == done
    with pytest.raises(Conflict):
        await finish(changed, b)
    assert (await finish(changed, b, cancel=True))["state"] == "cancelled"


@pytest.mark.parametrize("change", ("pause", "unbind", "root"))
async def test_human_admission_rechecks_binding_after_the_consumer_fence(db, monkeypatch, change):
    bindings, binding, _, _ = await bound(db)
    original = bindings.get

    async def changed_after_read(*args, **kwargs):
        value = await original(*args, **kwargs)
        async with db.sessions.begin() as session:
            row = await session.get(Binding, binding.id)
            if change == "pause":
                row.dispatch_paused = True
                row.queue_revision += 1
            elif change == "unbind":
                row.state = "unbound"
                row.revision += 1
                row.dispatch_paused = True
            else:
                row.session_id = "replacement-without-revision"
        return value

    monkeypatch.setattr(bindings, "get", changed_after_read)
    queue = QueueService(bindings)
    if change == "pause":
        assert (await queue.receive(binding.id, message())).state == "held"
    else:
        with pytest.raises(Conflict, match="queue_admission"):
            await queue.receive(binding.id, message())
        async with db.sessions() as session:
            assert await session.scalar(select(Action.id)) is None


async def test_http_preview_confirm_csrf_unknown_fields_and_active_lease(db):
    _, binding, control, _ = await bound(db)
    app = create_app(Settings(), db)
    async with app.router.lifespan_context(app):
        auth, admin_id, token, csrf = await principal(db)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://bridge.invalid",
            cookies={"jtoz_session": token},
        ) as client:
            path = f"/api/v1/admin/bindings/{binding.id}/preview"
            body = {
                "client_action_id": uid(),
                "operation": "pause",
                "binding_revision": 1,
                "queue_revision": 0,
            }
            assert (await client.post(path, json=body)).status_code == 403
            headers = {"x-csrf-token": csrf}
            assert (
                await client.post(
                    path, json=body, headers={**headers, "origin": "https://evil.invalid"}
                )
            ).status_code == 403
            invalid = await client.post(
                path,
                json={**body, "actor_id": 7, "confirmation_token": "DO_NOT_ECHO"},
                headers=headers,
            )
            assert invalid.status_code == 422 and "DO_NOT_ECHO" not in invalid.text
            result = await client.post(path, json=body, headers=headers)
            assert result.status_code == 200
            data = result.json()
            confirm = f"/api/v1/admin/decisions/{data['decision_id']}/confirm"
            content = {"confirmation_token": data["confirmation_token"], "version": 1}
            assert (await client.get(confirm)).status_code == 405
            response = await client.post(confirm, json=content, headers=headers)
            assert response.status_code == 200 and response.json()["state"] == "confirmed"
            assert (
                await client.post(confirm, json=content, headers=headers)
            ).json() == response.json()
            assert all(call[0] == "snapshot" for call in control.calls)
            await auth.logout(token)
            assert (await client.post(confirm, json=content, headers=headers)).status_code == 403


async def test_binding_and_nonce_roll_back_together_if_receipt_flush_fails(db, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession

    values = await setup(db)
    decision = await preview(values, "unbind")
    original = AsyncSession.flush

    async def fail_receipt(session, *args, **kwargs):
        if any(
            isinstance(row, AuditEvent) and row.event == "admin_session_unbound"
            for row in session.new
        ):
            raise RuntimeError("synthetic_receipt_failure")
        return await original(session, *args, **kwargs)

    monkeypatch.setattr(AsyncSession, "flush", fail_receipt)
    with pytest.raises(RuntimeError, match="synthetic_receipt"):
        await finish(values, decision)
    async with db.sessions() as session:
        binding = await session.get(Binding, values[6].id)
        row = await session.get(AdminDecision, decision["decision_id"])
        assert (
            binding.state == "active"
            and not binding.dispatch_paused
            and binding.queue_revision == 0
        )
        assert row.state == "pending" and row.version == 1
        assert (
            await session.scalar(
                select(func.count()).select_from(Action).where(Action.state == "queued")
            )
            == 2
        )
    monkeypatch.setattr(AsyncSession, "flush", original)
    assert (await finish(values, decision))["state"] == "confirmed"


async def test_pending_preview_cap_preserves_retries_and_cancel_frees_capacity(db):
    values = await setup(db)
    first_client = uid()
    first = await preview(values, client=first_client)
    for _ in range(49):
        await preview(values)
    assert await preview(values, client=first_client) == first
    with pytest.raises(Conflict, match="preview_limit"):
        await preview(values)
    await finish(values, first, cancel=True)
    assert (await preview(values))["state"] == "pending"
    async with db.sessions() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(AdminDecision)
                .where(AdminDecision.state == "pending")
            )
            == 50
        )


async def test_oversized_work_scope_fails_before_a_preview_is_issued(db):
    values = await setup(db)
    async with db.sessions.begin() as session:
        for i in range(1001):
            session.add(
                Action(
                    id=uid(),
                    dedupe_key=f"overflow-{i}",
                    binding_id=values[6].id,
                    binding_revision=1,
                    actor_id=7,
                    payload={"text": PRIVATE},
                    operation_digest="a" * 64,
                    state="held",
                )
            )
    with pytest.raises(Conflict, match="too_many_active_records"):
        await preview(values)
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AdminDecision)) == 0
        assert not (await session.get(Binding, values[6].id)).dispatch_paused


async def test_administrative_metadata_never_reads_confirmation_tokens(db, monkeypatch):
    from jt_oz_bridge.web.catalog import AdminCatalog

    values = await setup(db)
    decision = await preview(values)

    def forbidden(*args, **kwargs):
        raise AssertionError("metadata read decrypted a pending decision")

    monkeypatch.setattr(db.cipher, "open", forbidden)
    page = await AdminCatalog(db, Settings()).page("bindings")
    assert decision["confirmation_token"] not in str(page.response()) and PRIVATE not in str(
        page.response()
    )


@pytest.mark.parametrize("expires", ("decision", "session", "lease"))
async def test_slow_scope_validation_cannot_consume_after_any_deadline(db, monkeypatch, expires):
    from sqlalchemy import literal

    values = await setup(db)
    decision = await preview(values)
    service = values[0]
    clock = {"now": time.time()}
    async with db.sessions.begin() as session:
        if expires == "decision":
            row = await session.get(AdminDecision, decision["decision_id"])
            intent = read_intent(row).model_copy(update={"expires_at": clock["now"] + 100})
            row.payload = intent.payload()
            row.payload_hash = digest(row.payload)
            row.expires_at = intent.expires_at
        elif expires == "session":
            await session.execute(update(AdminSession).values(expires_at=clock["now"] + 100))
        else:
            await session.execute(update(WorkerLease).values(expires_at=clock["now"] + 100))
    original = service._effects
    entered = []

    async def crosses_deadline(session, binding_id):
        rows = await original(session, binding_id)
        entered.append(True)
        clock["now"] += 200
        return rows

    # Model elapsed database time deterministically; application clocks, test
    # limits, original proof deadlines and garbage collection are unchanged.
    monkeypatch.setattr(service, "_clock", lambda: literal(clock["now"]))
    monkeypatch.setattr(service, "_effects", crosses_deadline)
    with pytest.raises(Conflict, match="expired_or_authority"):
        await finish(values, decision)
    assert entered == [True]
    async with db.sessions() as session:
        row = await session.get(AdminDecision, decision["decision_id"])
        binding = await session.get(Binding, values[6].id)
        assert row.state == "pending" and row.version == 1
        assert not binding.dispatch_paused and binding.queue_revision == 0
        assert (
            await session.scalar(
                select(func.count()).select_from(Action).where(Action.state == "queued")
            )
            == 2
        )


@pytest.mark.parametrize("expires", ("session", "lease"))
async def test_preview_issuance_rolls_back_if_authority_expires_during_validation(
    db, monkeypatch, expires
):
    from sqlalchemy import literal

    values = await setup(db)
    service = values[0]
    clock = {"now": time.time()}
    async with db.sessions.begin() as session:
        model = AdminSession if expires == "session" else WorkerLease
        await session.execute(update(model).values(expires_at=clock["now"] + 100))
    original = service._effects

    async def crosses_deadline(session, binding_id):
        rows = await original(session, binding_id)
        clock["now"] += 200
        return rows

    monkeypatch.setattr(service, "_clock", lambda: literal(clock["now"]))
    monkeypatch.setattr(service, "_effects", crosses_deadline)
    with pytest.raises(Conflict, match="authority_expired"):
        await preview(values)
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AdminDecision)) == 0
        assert (
            await session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.event == "admin_scope_previewed")
            )
            == 0
        )


async def test_database_execution_wait_does_not_reuse_a_precomputed_expiry_clock(db):
    from sqlalchemy import event

    values = await setup(db)
    decision = await preview(values)
    async with db.sessions.begin() as session:
        row = await session.get(AdminDecision, decision["decision_id"])
        expires = time.time() + 1.0
        intent = read_intent(row).model_copy(update={"expires_at": expires})
        row.payload = intent.payload()
        row.payload_hash = digest(row.payload)
        row.expires_at = expires
    waited = []

    def database_wait(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("UPDATE ADMIN_DECISIONS SET"):
            assert time.time() < expires
            # Synchronous SQL-driver/lock wait after bound values were encoded.
            # Only this isolated test connection is delayed, with no Native call.
            time.sleep(1.2)
            waited.append(True)

    event.listen(db.engine.sync_engine, "before_cursor_execute", database_wait)
    try:
        with pytest.raises(Conflict, match="expired_or_authority"):
            await finish(values, decision)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", database_wait)
    assert waited == [True]
    async with db.sessions() as session:
        assert (await session.get(AdminDecision, decision["decision_id"])).state == "pending"
        assert not (await session.get(Binding, values[6].id)).dispatch_paused
