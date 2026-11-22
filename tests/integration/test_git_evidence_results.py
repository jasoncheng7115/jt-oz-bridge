"""Real encrypted ownDB/dispatcher chain, synthetic Human/Native HTTP only."""

import json
import time

import pytest
from sqlalchemy import event, select, update

from jt_oz_bridge.domain.checks import ApprovedCheck
from jt_oz_bridge.domain.git_evidence import RootReviewedGitEvidencePin
from jt_oz_bridge.services.git_evidence import GitEvidenceResults
from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord
from jt_oz_bridge.storage.control_models import Binding, ControlToken, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration import test_check_commands as original
from tests.unit.test_git_evidence import document, pin


def view_request(message, action_id, source):
    request = message.model_copy(
        update={"message_id": 201, "text": "!oz git evidence " + action_id}
    )
    source.messages[201] = request
    source.calls.clear()
    return request


async def test_new_view_request_reads_original_source_without_rebuilding_it(db, monkeypatch):
    service, binding, original_source, action, values, _ = await setup(db, monkeypatch)
    request = view_request(original_source, action.id, values[2])
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", record)
    try:
        view = await service.read_for_request(binding, request, action.id)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", record)
    assert view.action_id == action.id and view.historical
    assert not view.current_index_verified and not view.mutation_confirmation_usable
    assert ("realm", 201) in values[2].calls and ("realm", 102) in values[2].calls
    assert values[2].messages[102] == original_source
    assert len(values[3].submitted) == 1
    assert all(s.lstrip().upper().startswith("SELECT") or s == "BEGIN" for s in statements)


@pytest.mark.parametrize(
    "change",
    [
        {"is_bot": True},
        {"deleted": True},
        {"revision": 1},
        {"channel_id": 11},
        {"topic": "other topic"},
        {"text": "!oz help"},
    ],
)
async def test_invalid_current_view_is_rejected_before_loading_old_action(db, monkeypatch, change):
    service, binding, message, action, values, _ = await setup(db, monkeypatch)
    request = view_request(message, action.id, values[2]).model_copy(update=change)
    values[2].messages[201] = request
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", record)
    try:
        with pytest.raises((ValueError, Conflict)):
            await service.read_for_request(binding, request, action.id)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", record)
    assert not any("FROM actions" in s for s in statements)
    assert ("realm", 102) not in values[2].calls
    assert len(values[3].submitted) == 1


async def test_view_filters_wrong_revision_before_decrypting_payload(db, monkeypatch):
    from sqlalchemy import text

    service, binding, message, action, values, _ = await setup(db, monkeypatch)
    request = view_request(message, action.id, values[2])
    async with db.engine.begin() as connection:
        await connection.execute(
            text("UPDATE actions SET binding_revision=2, payload=:bad WHERE id=:id"),
            {"bad": b"invalid-aead", "id": action.id},
        )
    with pytest.raises(Conflict, match="completed_original_journals_required"):
        await service.read_for_request(binding, request, action.id)
    assert ("realm", 102) not in values[2].calls and len(values[3].submitted) == 1


async def test_view_rechecks_current_request_after_original_chain_read(db, monkeypatch):
    service, binding, message, action, values, _ = await setup(db, monkeypatch)
    request = view_request(message, action.id, values[2])
    initial = service._read

    async def changed(*args):
        result = await initial(*args)
        values[2].messages[201] = request.model_copy(update={"deleted": True})
        return result

    monkeypatch.setattr(service, "_read", changed)
    with pytest.raises(Conflict, match="view_request_changed"):
        await service.read_for_request(binding, request, action.id)
    assert len(values[3].submitted) == 1


async def viewer_request(db, values, original_source, action_id):
    from sqlalchemy import delete

    async with db.sessions.begin() as session:
        await session.execute(delete(Grant).where(Grant.user_id == 8))
        session.add(Grant(realm_id="realm", user_id=8, project_id="project", role="viewer"))
    request = view_request(original_source, action_id, values[2]).model_copy(
        update={"author_id": 8}
    )
    values[2].messages[201] = request
    return request


async def test_current_viewer_does_not_need_original_check_actor_or_operate(db, monkeypatch):
    service, binding, message, action, values, _ = await setup(db, monkeypatch)
    request = await viewer_request(db, values, message, action.id)
    view = await service.read_for_request(binding, request, action.id)
    assert view.action_id == action.id and view.historical
    assert values[2].messages[102].author_id == 7 and request.author_id == 8
    assert not view.mutation_confirmation_usable and len(values[3].submitted) == 1


async def test_viewer_revoke_after_request_authentication_is_locked_before_return(db, monkeypatch):
    from sqlalchemy import delete

    from jt_oz_bridge.security.policy import AccessDenied

    service, binding, message, action, values, _ = await setup(db, monkeypatch)
    request = await viewer_request(db, values, message, action.id)
    initial = service._view_request_current
    calls = 0

    async def revoke(*args):
        nonlocal calls
        await initial(*args)
        calls += 1
        if calls == 3:
            async with db.sessions.begin() as session:
                await session.execute(delete(Grant).where(Grant.user_id == 8))

    monkeypatch.setattr(service, "_view_request_current", revoke)
    with pytest.raises(AccessDenied, match="audience_grants_changed"):
        await service.read_for_request(binding, request, action.id)
    assert len(values[3].submitted) == 1


async def setup(db, monkeypatch):
    # Original check choice -> Action -> owner dispatch journal -> one admitted
    # shell -> original result collector, rather than fabricate a result dict.
    p = pin()
    monkeypatch.setattr(original, "CHECK", p.check)
    values = await original.setup(db)
    execution = values[3]
    execution.checks = (p.check,)
    action = await original.queued(values)
    assert await values[5].advance(action.id) == "admitted"
    observed = execution.observations[action.id]
    execution.observations[action.id] = observed.model_copy(
        update={"output": json.dumps(document())}
    )
    assert await values[6].collect(action.id, "realm")
    p = RootReviewedGitEvidencePin.model_validate(
        p.model_dump(mode="python")
        | {
            "contract_sha256": execution.contract_for(execution.ref),
            "qualification_sha256": execution.qualification_for(execution.ref),
            "catalog_sha256": digest(execution.catalog(execution.ref).model_dump(mode="json")),
        }
    )
    service = GitEvidenceResults(
        values[4].bindings,
        values[2],
        {execution.ref: execution},
        fence=values[4].fence,
        pins={execution.ref: p},
    )
    return service, values[1], values[2].messages[102], action, values, p


async def test_reads_actual_chain_twice_without_native_or_sql_writes(db, monkeypatch):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    from unittest.mock import AsyncMock

    native_read = AsyncMock(side_effect=AssertionError("no new Native observation"))
    monkeypatch.setattr(values[3], "observe", native_read)
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", record)
    try:
        view = await service.read(binding, message, action.id)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", record)
    assert (
        view.historical
        and not view.current_index_verified
        and not view.mutation_confirmation_usable
    )
    assert view.evidence.index_tree_oid == "e" * 40 and len(values[3].submitted) == 1
    assert all(s.lstrip().upper().startswith("SELECT") or s == "BEGIN" for s in statements)
    assert values[2].calls[-2:] == [("realm", 102)] * 2
    wire = view.model_dump_json()
    assert "canonical_directory" not in wire and "command" not in wire and "output" not in wire
    assert await service.read(binding, message, action.id) == view
    native_read.assert_not_awaited()


async def test_missing_pin_disabled_does_not_even_read_source_or_native(db, monkeypatch):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    disabled = GitEvidenceResults(
        service.bindings, service.source, service.readers, fence=service.fence
    )
    assert not disabled.available(binding)
    with pytest.raises(Conflict):
        await disabled.read(binding, message, action.id)
    assert len(values[3].submitted) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "state",
        "payload",
        "result",
        "preflight",
        "command",
        "token",
        "ref",
        "truncated",
        "failed",
        "other_actor",
    ],
)
async def test_rejects_changed_real_journals_or_terminal_identity(db, monkeypatch, fault):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    async with db.sessions.begin() as session:
        saved = await session.get(Action, action.id)
        if fault == "state":
            saved.state = "ambiguous"
        elif fault == "payload":
            saved.payload = saved.payload | {"binding_revision": 9}
        elif fault == "result":
            saved.native_result = saved.native_result | {"channel_id": 99}
        elif fault == "preflight":
            (await session.get(CheckDispatchRecord, action.id)).payload_hash = "0" * 64
        elif fault == "command":
            values[3].checks = (
                ApprovedCheck(id=p.check.id, title=p.check.title, command="git status"),
            )
        elif fault == "token":
            (
                await session.scalar(
                    select(ControlToken).where(ControlToken.kind == "native-check-choice")
                )
            ).used = False
        elif fault == "ref":
            saved.payload = saved.payload | {"reference": binding.id}
        elif fault in {"truncated", "failed"}:
            result = saved.native_result.copy()
            observed = result["observation"].copy()
            observed["output_truncated" if fault == "truncated" else "exit_code"] = (
                True if fault == "truncated" else 1
            )
            result["observation"] = observed
            saved.native_result = result
        elif fault == "other_actor":
            saved.actor_id = 99
    with pytest.raises((ValueError, Conflict)):
        await service.read(binding, message, action.id)
    assert len(values[3].submitted) == 1


@pytest.mark.parametrize(
    "fault", ["source", "grant", "enrollment", "fence", "lease", "binding", "result", "preflight"]
)
async def test_late_changes_after_first_chain_read_are_rejected(db, monkeypatch, fault):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    initial = service._read
    calls = 0

    async def changed(*args):
        nonlocal calls
        value = await initial(*args)
        calls += 1
        if calls == 1:
            async with db.sessions.begin() as session:
                if fault == "source":
                    values[2].messages[102] = message.model_copy(update={"text": "!oz help"})
                elif fault == "grant":
                    await session.execute(update(Grant).values(active=False))
                elif fault == "enrollment":
                    await session.execute(update(EnrolledProject).values(enabled=False))
                elif fault == "fence":
                    await session.execute(update(WorkerLease).values(fencing=999))
                elif fault == "lease":
                    await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
                elif fault == "binding":
                    await session.execute(update(Binding).values(revision=2))
                elif fault == "result":
                    saved = await session.get(Action, action.id)
                    result = saved.native_result.copy()
                    observed = result["observation"].copy()
                    observed["output"] = json.dumps(document(index_tree_oid="f" * 40))
                    result["observation"] = observed
                    saved.native_result = result
                elif fault == "preflight":
                    saved = await session.get(CheckDispatchRecord, action.id)
                    saved.payload = saved.payload | {"owner_epoch": "f" * 64}
                    saved.payload_hash = digest(saved.payload)
        return value

    monkeypatch.setattr(service, "_read", changed)
    with pytest.raises((ValueError, Conflict)):
        await service.read(binding, message, action.id)
    assert len(values[3].submitted) == 1


async def test_ciphertext_tamper_not_admitted_as_caller_result(db, monkeypatch):
    from sqlalchemy import text

    service, binding, message, action, values, p = await setup(db, monkeypatch)
    async with db.engine.begin() as conn:
        await conn.execute(
            text("UPDATE actions SET native_result=:bad WHERE id=:id"),
            {"bad": b"invalid-aead", "id": action.id},
        )
    from jt_oz_bridge.storage.cipher_types import PayloadUnavailable

    with pytest.raises(PayloadUnavailable):
        await service.read(binding, message, action.id)
    assert len(values[3].submitted) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"is_bot": True},
        {"deleted": True},
        {"revision": 1},
        {"author_id": 8},
        {"channel_id": 11},
        {"topic": "original work"},
    ],
)
async def test_fresh_source_cannot_rebind_original_check_actor_or_topic(db, monkeypatch, change):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    altered = message.model_copy(update=change)
    values[2].messages[102] = altered
    with pytest.raises(ValueError):
        await service.read(binding, altered, action.id)
    assert len(values[3].submitted) == 1


async def test_historical_preflight_does_not_renew_or_claim_native_freshness(db, monkeypatch):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    async with db.sessions.begin() as session:
        saved = await session.get(CheckDispatchRecord, action.id)
        saved.payload = saved.payload | {"issued_at": 100, "expires_at": 105}
        saved.payload_hash = digest(saved.payload)
    view = await service.read(binding, message, action.id)
    assert view.historical and not view.current_index_verified
    assert not view.mutation_confirmation_usable and len(values[3].submitted) == 1


async def test_invalid_output_never_exposes_stdout_in_view_or_error(db, monkeypatch):
    service, binding, message, action, values, p = await setup(db, monkeypatch)
    secret = "https://user:synthetic-password@private-host.invalid/secret"
    async with db.sessions.begin() as session:
        saved = await session.get(Action, action.id)
        result = saved.native_result.copy()
        observed = result["observation"].copy()
        observed["output"] = secret
        result["observation"] = observed
        saved.native_result = result
    with pytest.raises(ValueError) as error:
        await service.read(binding, message, action.id)
    assert secret not in str(error.value) and "synthetic-password" not in str(error.value)


async def test_late_action_scope_change_is_filtered_before_each_payload_decryption(db, monkeypatch):
    from sqlalchemy import text

    service, binding, message, action, values, _ = await setup(db, monkeypatch)
    request = view_request(message, action.id, values[2])
    initial = service._view_request_current
    calls = 0

    async def replaced(*args):
        nonlocal calls
        await initial(*args)
        calls += 1
        if calls == 2:
            async with db.engine.begin() as connection:
                await connection.execute(
                    text("UPDATE actions SET binding_revision=2, payload=:bad WHERE id=:id"),
                    {"bad": b"invalid-aead", "id": action.id},
                )

    monkeypatch.setattr(service, "_view_request_current", replaced)
    with pytest.raises(Conflict, match="completed_original_journals_required"):
        await service.read_for_request(binding, request, action.id)
    assert len(values[3].submitted) == 1
