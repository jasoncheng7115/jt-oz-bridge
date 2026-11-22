import asyncio

import pytest
from sqlalchemy import event, update
from sqlalchemy.orm import Session

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_confirmation import BindingConfirmation
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant, WorkerLease
from tests.integration.test_discovery import discovery
from tests.integration.test_router import Source, count, message
from tests.support import REF


@pytest.mark.parametrize("failure", [None, "view", "operate", "current", "flush"])
async def test_closed_confirmation_stages_reads_then_commits_token_and_binding_atomically(
    db, monkeypatch, failure
):
    """SQL boundary fixture only; the existing V2 tests own Native witness evidence."""
    service, _, preview, confirmed = await prepared(db)
    audience = await service.discovery.audience(confirmed)
    execution = service.bindings.control.backends["backend"].client
    snapshot = await execution.snapshot(REF)
    current = [True]

    def require_current():
        if not current[0]:
            raise Conflict("synthetic_original_witness_expired")

    async def native(selected):
        assert selected == REF
        return snapshot, require_current

    monkeypatch.setattr(service, "_observed_native_snapshot", native)
    prepared_confirmation = await service._prepare_confirmation_observed(
        confirmed, preview.token, audience
    )
    assert await count(db, Binding) == 0
    assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used
    if failure in {"view", "operate"}:
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant)
                .where(
                    Grant.user_id == (8 if failure == "view" else 7),
                    Grant.project_id == "project",
                    *(
                        []
                        if failure == "view"
                        else [
                            Grant.role.in_(
                                [
                                    role
                                    for role, permissions in ROLES.items()
                                    if Permission.OPERATE in permissions
                                ]
                            )
                        ]
                    ),
                )
                .values(active=False)
            )
    elif failure == "current":
        current[0] = False

    async def commit():
        async with db.sessions.begin() as session:
            binding = await service._commit_confirmation_observed(session, prepared_confirmation)
            if failure == "flush":
                raise RuntimeError("synthetic_after_binding_flush")
            return binding

    if failure is None:
        binding = await commit()
        assert binding.anchor_message_id == confirmed.message_id
        assert binding.session_id == REF.upstream_session_id
        assert binding.audience_user_ids == [7, 8] and binding.owner_id == 7
        assert await count(db, Binding) == 1
        with pytest.raises(Conflict):
            await commit()
    else:
        with pytest.raises((AccessDenied, Conflict, RuntimeError)):
            await commit()
        assert await count(db, Binding) == 0
        assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used
    assert not execution.submitted


async def prepared(db, locale="en"):
    catalog, _clients = await discovery(db)
    fencing = await DurableStore(db).acquire_lease("binding-test")
    tokens = TokenService(db, fence=ConsumerFence("binding-test", fencing))
    reader = Source()
    service = BindingConfirmation(catalog, tokens, reader)
    selected = message("!oz bind selection", 201)
    reader.messages[201] = selected
    preview = await service.prepare(selected, REF, locale)
    confirmed = message("!oz confirm " + preview.token, 202)
    reader.messages[202] = confirmed
    return service, reader, preview, confirmed


async def test_original_session_confirmation_and_binding_are_one_atomic_fenced_commit(db):
    service, reader, preview, confirmed = await prepared(db)
    assert "Connect this conversation" in preview.text and "original-session" in preview.text
    assert await count(db, Binding) == 0
    bound = await service.confirm(confirmed, preview.token)
    assert bound.session_id == REF.upstream_session_id and bound.anchor_message_id == 202
    assert bound.owner_id == 7 and bound.topic == "Original work"
    with pytest.raises(Conflict):
        await service.confirm(confirmed, preview.token)
    assert await count(db, Binding) == 1
    execution = service.bindings.control.backends["backend"].client
    assert not execution.submitted and all(call[0] == "snapshot" for call in execution.calls)


async def test_running_progress_cursor_and_state_changes_do_not_change_confirmed_target(db):
    service, reader, preview, confirmed = await prepared(db)
    execution = service.bindings.control.backends["backend"].client
    original = execution.snapshot

    async def progressed(ref):
        return (await original(ref)).model_copy(
            update={"state": ExecutionState.RUNNING, "cursor": "genuine-progress:999"}
        )

    execution.snapshot = progressed
    bound = await service.confirm(confirmed, preview.token)
    assert (
        bound.observed_cursor == "genuine-progress:999"
        and bound.session_id == REF.upstream_session_id
    )


@pytest.mark.parametrize("changed", ["title", "reference", "unreconciled"])
async def test_changed_title_or_original_execution_proof_invalidates_confirmation(db, changed):
    service, reader, preview, confirmed = await prepared(db)
    execution = service.bindings.control.backends["backend"].client
    original = execution.snapshot

    async def changed_snapshot(ref):
        values = (
            {"title": "different title"}
            if changed == "title"
            else {"reference": REF.model_copy(update={"upstream_session_id": "different"})}
            if changed == "reference"
            else {"reconciled": False}
        )
        return (await original(ref)).model_copy(update=values)

    execution.snapshot = changed_snapshot
    with pytest.raises(Conflict):
        await service.confirm(confirmed, preview.token)
    assert await count(db, Binding) == 0
    assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used


@pytest.mark.parametrize(
    "changes",
    [{"topic": "Other topic"}, {"channel_id": 11}, {"author_id": 8}, {"realm_id": "other"}],
)
async def test_binding_confirmation_never_moves_to_another_actor_or_target(db, changes):
    service, reader, preview, confirmed = await prepared(db)
    item = confirmed.model_copy(update=changes)
    reader.messages[202] = item
    with pytest.raises((AccessDenied, Conflict)):
        await service.confirm(item, preview.token)
    assert await count(db, Binding) == 0


async def test_edited_during_last_native_snapshot_cannot_bind_or_consume_confirmation(db):
    service, reader, preview, confirmed = await prepared(db)
    execution = service.bindings.control.backends["backend"].client
    original = execution.snapshot

    async def edited(ref):
        reader.messages[202] = confirmed.model_copy(update={"revision": 1, "text": "!oz stop"})
        return await original(ref)

    execution.snapshot = edited
    with pytest.raises(AccessDenied, match="source_changed"):
        await service.confirm(confirmed, preview.token)
    assert await count(db, Binding) == 0
    assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used


async def test_grant_revocation_at_final_source_read_is_rechecked_in_binding_transaction(db):
    service, reader, preview, confirmed = await prepared(db)
    original = reader.read
    execution = service.bindings.control.backends["backend"].client
    original_snapshot = execution.snapshot
    snapshot_seen = False
    grant_revoked = False

    async def snapshot(reference):
        nonlocal snapshot_seen
        result = await original_snapshot(reference)
        snapshot_seen = True
        return result

    async def revoked(realm, message_id):
        nonlocal grant_revoked
        # Revoke at the source check after the Native snapshot, not at an
        # incidental count of earlier reads in an implementation.
        if snapshot_seen and not grant_revoked:
            grant_revoked = True
            async with db.sessions.begin() as session:
                await session.execute(
                    update(Grant)
                    .where(Grant.user_id == 8, Grant.project_id == "project")
                    .values(active=False)
                )
        return await original(realm, message_id)

    execution.snapshot = snapshot
    reader.read = revoked
    with pytest.raises(AccessDenied, match="grants_changed"):
        await service.confirm(confirmed, preview.token)
    assert await count(db, Binding) == 0
    assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used


async def test_binding_storage_failure_rolls_back_token_and_can_be_retried_fresh(db):
    service, reader, preview, confirmed = await prepared(db)

    def failing_flush(session, context, instances):
        if any(isinstance(item, Binding) for item in session.new):
            raise RuntimeError("injected binding storage failure")

    event.listen(Session, "before_flush", failing_flush)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            await service.confirm(confirmed, preview.token)
    finally:
        event.remove(Session, "before_flush", failing_flush)
    assert await count(db, Binding) == 0
    assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used
    assert (await service.confirm(confirmed, preview.token)).session_id == REF.upstream_session_id


async def test_two_confirm_messages_have_one_binding_winner(db):
    service, reader, preview, confirmed = await prepared(db)
    other = confirmed.model_copy(update={"message_id": 203})
    reader.messages[203] = other
    results = await asyncio.gather(
        service.confirm(confirmed, preview.token),
        service.confirm(other, preview.token),
        return_exceptions=True,
    )
    assert sum(isinstance(result, Binding) for result in results) == 1
    assert await count(db, Binding) == 1


@pytest.mark.parametrize("changed", ["token", "lease", "audience"])
async def test_expired_token_lost_lease_or_changed_audience_cannot_commit(db, changed):
    service, reader, preview, confirmed = await prepared(db)
    if changed == "audience":
        service.bindings.audience.users = frozenset({7, 8, 999})
    else:
        async with db.sessions.begin() as session:
            if changed == "token":
                await session.execute(
                    update(ControlToken)
                    .where(ControlToken.kind == "binding-confirm")
                    .values(expires_at=0)
                )
            else:
                await session.execute(update(WorkerLease).values(expires_at=0))
    with pytest.raises((Conflict, AccessDenied)):
        await service.confirm(confirmed, preview.token)
    assert await count(db, Binding) == 0


async def test_complete_preview_is_localized_and_known_secrets_issue_no_binding_token(db):
    service, reader, preview, confirmed = await prepared(db, locale="zh-TW")
    assert "沒問題就回" in preview.text and "!ok" in preview.text and "要把這個對話" in preview.text
    execution = service.bindings.control.backends["backend"].client
    original = execution.snapshot

    async def private(ref):
        return (await original(ref)).model_copy(
            update={"title": "Authorization: Bearer PRIVATE_BINDING_MARKER"}
        )

    execution.snapshot = private
    item = message("!oz bind selection", 204)
    reader.messages[204] = item
    denied = await service.prepare(item, REF, "en")
    assert denied.token is None and "PRIVATE_BINDING_MARKER" not in denied.text
    assert await count(db, Binding) == 0


async def test_viewer_may_discover_but_cannot_get_binding_confirmation(db):
    service, reader, preview, confirmed = await prepared(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Grant)
            .where(Grant.user_id == 7, Grant.project_id == "project")
            .values(active=False)
        )
        session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    selected = message("!oz bind selection", 204)
    reader.messages[204] = selected
    assert (await service.discovery.sessions(selected, "project")).items
    with pytest.raises(AccessDenied):
        await service.prepare(selected, REF)
    assert await count(db, Binding) == 0


async def test_conflicting_binding_rolls_back_confirmation_then_fresh_human_can_retry_after_unbind(
    db,
):
    service, reader, preview, confirmed = await prepared(db)
    existing = await service.bindings.bind("realm", 7, 10, "Original work", REF)
    with pytest.raises(Conflict, match="already has"):
        await service.confirm(confirmed, preview.token)
    assert not (await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)).used
    assert await count(db, Binding) == 1
    await service.bindings.unbind(existing.id, "realm", 7, existing.revision)
    fresh = confirmed.model_copy(update={"message_id": 203})
    reader.messages[203] = fresh
    current = await service.confirm(fresh, preview.token)
    assert current.id != existing.id and current.anchor_message_id == 203


async def test_closed_preview_requires_owned_plan_before_any_native_read(db):
    service, _reader, _preview, confirmed = await prepared(db)
    source = confirmed.model_copy(update={"message_id": 203, "text": "!1"})
    audience = await service.discovery.audience(source)
    execution = service.bindings.control.backends["backend"].client
    execution.calls.clear()
    before = await count(db, ControlToken)
    with pytest.raises((AccessDenied, Conflict)):
        await service._prepare_observed(source, REF, audience)
    assert not execution.calls and await count(db, ControlToken) == before


@pytest.mark.parametrize("failure", [None, "late-view", "late-operate", "unreconciled"])
async def test_closed_preview_only_stages_data_and_rechecks_sql_after_native(db, failure):
    service, reader, _preview, confirmed = await prepared(db)
    source = confirmed.model_copy(update={"message_id": 203, "text": "!1"})
    audience = await service.discovery.audience(source)
    execution = service.bindings.control.backends["backend"].client
    original = execution.snapshot

    async def observed(ref):
        snapshot = await original(ref)
        if failure == "unreconciled":
            return snapshot.model_copy(update={"reconciled": False})
        if failure in {"late-view", "late-operate"}:
            async with db.sessions.begin() as session:
                query = update(Grant).where(
                    Grant.realm_id == "realm", Grant.project_id == REF.project_id
                )
                if failure == "late-view":
                    query = query.where(Grant.user_id == 8).values(active=False)
                else:
                    query = query.where(
                        Grant.user_id == 7,
                        Grant.role.in_(
                            [
                                role
                                for role, permissions in ROLES.items()
                                if Permission.OPERATE in permissions
                            ]
                        ),
                    ).values(active=False)
                await session.execute(query)
        return snapshot

    execution.snapshot = observed
    before = await count(db, ControlToken)
    with service.tokens.planning() as plan:
        if failure is None:
            result = await service._prepare_observed(source, REF, audience)
            assert "Connect this conversation" in result.text and result.token
            assert len(plan.issued) == 1 and plan.required_output_source == source
            assert plan.issued[0].kind == "binding-confirm"
            assert plan.issued[0].context["reference"] == REF.model_dump(mode="json")
            # This generic domain double has no original Native witness.
            # Staged preview data must never be mistaken for publication authority.
            with pytest.raises(Conflict, match="original_native_witness_required"):
                result.require_current()
        else:
            with pytest.raises((AccessDenied, Conflict)):
                await service._prepare_observed(source, REF, audience)
            assert not plan.issued and not plan.committed
    assert await count(db, ControlToken) == before
    assert await count(db, Binding) == 0 and not execution.submitted


@pytest.mark.parametrize("failure", [None, "expired", "owner", "watch", "assembly"])
async def test_closed_preview_retains_actual_v2_witness_without_renewing_it(
    db, monkeypatch, failure
):
    import time
    from types import SimpleNamespace

    from jt_oz_bridge.adapters.opencode import execution as native_module
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_leaf_resources import setup as native_setup

    service, _reader, _preview, _confirmed = await prepared(db)
    import httpx

    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from tests.contract.test_leaf_resources import REF as ref

    proofs, transport, _data, _calls = await native_setup()
    delegate = transport.client._transport
    methods = []

    def traced(request):
        methods.append(request.method)
        return delegate.handler(request)

    transport.client._transport = httpx.MockTransport(traced)
    execution = V2ExecutionClient(transport, proofs.projects, proofs=proofs)
    service.bindings.control = execution
    try:
        await proofs.watch(ref)
        snapshot, current = await service._observed_native_snapshot(ref)
        assert snapshot.reference == ref and snapshot.reconciled
        current()
        if failure == "expired":
            now = time.time()
            monkeypatch.setattr(native_module, "time", SimpleNamespace(time=lambda: now + 6))
        elif failure == "owner":
            proofs.feed.index.owner_epoch = "d" * 64
        elif failure == "watch":
            proofs.revoke_watch(ref)
        elif failure == "assembly":
            service.bindings.control = SimpleNamespace(snapshot=execution.snapshot)
        if failure is not None:
            with pytest.raises((ContractError, Conflict)):
                current()
        else:
            current()
        assert not any(call[0] in {"POST", "PATCH", "DELETE"} for call in _data.get("calls", []))
    finally:
        await finish(proofs, transport)


@pytest.mark.parametrize(
    "replacement",
    [
        "proofs",
        "transport",
        "http-client",
        "verifier",
        "attestation",
        "guard",
        "enrollment-map",
        "enrollment-value",
        "model-settings",
    ],
)
@pytest.mark.parametrize("when", ["after", "during"])
async def test_closed_native_witness_rejects_equivalent_inner_assembly_replacement(
    replacement, when
):
    """Real V2 GET proof, not a synthetic current callback or new Native owner."""
    from dataclasses import replace
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    import httpx

    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from jt_oz_bridge.adapters.opencode.transport import V2HTTPTransport
    from tests.contract.test_leaf_resources import REF as ref
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_native_project_policy import setup as native_setup

    proofs, transport, _data, guard, execution, _calls, writes = await native_setup()
    qualification = ModelSettingsAttestation(
        ref, transport.profile.sha256, MODEL_SETTING_SEMANTICS, "e" * 64
    )
    proofs.model_settings = qualification
    # A mapping's identity alone is insufficient: values must remain the exact
    # original enrollments too. Keep this alternate mapping private to fixture.
    if replacement == "enrollment-value":
        guard.enrollments = dict(guard.enrollments)
    await proofs.watch(ref)
    service = BindingConfirmation.__new__(BindingConfirmation)
    service.bindings = SimpleNamespace(control=execution)
    old_client = transport.client
    extras = []

    async def change():
        if replacement == "proofs":
            other = V2LeafResourceProofs(proofs.feed, proofs.projects, model_settings=qualification)
            await other.watch(ref)
            execution.proofs = other
        elif replacement == "transport":
            other = V2HTTPTransport(
                str(old_client.base_url).rstrip("/"),
                transport.profile,
                attestation=transport.attestation,
                verify_identity=transport.verify_identity,
                transport=httpx.MockTransport(old_client._transport.handler),
            )
            extras.append(other.client)
            execution.transport = other
        elif replacement == "http-client":
            other = httpx.AsyncClient(
                base_url=old_client.base_url,
                transport=httpx.MockTransport(old_client._transport.handler),
            )
            extras.append(other)
            transport.client = other
        elif replacement == "verifier":
            transport.verify_identity = AsyncMock(return_value=True)
        elif replacement == "attestation":
            transport.attestation = replace(transport.attestation)
        elif replacement == "guard":
            execution.scope_guard = V2ProjectPolicyGuard(proofs, guard.enrollments)
        elif replacement == "enrollment-map":
            guard.enrollments = dict(guard.enrollments)
        elif replacement == "enrollment-value":
            guard.enrollments[ref] = guard.enrollments[ref].model_copy()
        else:
            proofs.model_settings = replace(qualification)

    original = execution.qualified_snapshot
    if when == "during":

        async def changed_snapshot(selected):
            result = await original(selected)
            await change()
            return result

        execution.qualified_snapshot = changed_snapshot
    try:
        if when == "during":
            with pytest.raises(Conflict, match="original_native_assembly_changed"):
                await service._observed_native_snapshot(ref)
        else:
            _snapshot, current = await service._observed_native_snapshot(ref)
            current()
            await change()
            with pytest.raises(Conflict, match="original_native_assembly_changed"):
                current()
        assert not writes
    finally:
        execution.transport = transport
        execution.proofs = proofs
        transport.client = old_client
        for client in extras:
            await client.aclose()
        await finish(proofs, transport)


@pytest.mark.parametrize("locale,details", [("en", "Full details"), ("zh-TW", "完整資訊")])
async def test_binding_preview_shows_readable_target_and_keeps_complete_confirmation_context(
    db, locale, details
):
    from markdown_it import MarkdownIt

    from jt_oz_bridge.presentation.markdown import MobileMarkdown

    service, _reader, preview, _confirmed = await prepared(db, locale=locale)
    assert preview.token
    before_details, _ = preview.text.split("spoiler " + details, 1)
    for value in [
        REF.project_id,
        REF.canonical_directory,
        REF.upstream_session_id,
        "Original work",
    ]:
        assert value in before_details
    assert "!ok" in preview.text
    page = MobileMarkdown(locale=locale).render(preview.text, 10000).pages[0]
    fences = [t for t in MarkdownIt("commonmark").parse(page) if t.type == "fence"]
    assert any(t.info == "spoiler " + details and '"reference"' in t.content for t in fences)
    token = await service.tokens.inspect(preview.token, "binding-confirm", "realm", 7)
    assert token.context["reference"] == REF.model_dump(mode="json")
    assert token.context["channel_id"] == 10 and token.context["topic"] == "Original work"
    assert not token.used and await count(db, Binding) == 0
