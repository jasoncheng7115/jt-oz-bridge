"""Synthetic qualified reader + own encrypted DB; no real Human or Native writes."""

import copy
import time

import pytest
from sqlalchemy import event, update

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    NativeResourceTurn,
    ProjectedTurn,
    ResourceText,
)
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.execution_results import read_result
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.resource_execution_results import (
    ResourceResultCollector,
    resource_result,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message
from tests.support import bound


class Reader:
    def __init__(self):
        self.evidence = None
        self.calls = 0
        self.mode = "succeeded"
        self.hook = None
        self.alive = True

    async def capture(self, correlation):
        self.calls += 1
        now = time.time()
        outcome = self.mode if self.mode in {"succeeded", "failed", "interrupted"} else "succeeded"
        self.evidence = NativeResourceTurn(
            correlation=correlation,
            contract_sha256=INSTALLED_SCHEMA,
            semantics_sha256=RESOURCE_SEMANTICS,
            installed_evidence_sha256="a" * 64,
            connection_epoch="synthetic-only-resource-epoch",
            owner_epoch="b" * 64,
            ownership_evidence_sha256="c" * 64,
            session_info_sha256="d" * 64,
            resource_fence="e" * 64,
            observed_at=now,
            expires_at=now + 5,
            turn=ProjectedTurn(
                user_id=correlation.upstream_id,
                user_projection_sha256="f" * 64,
                terminal_id="msg_synthetic_idle",
                terminal_projection_sha256="a" * 64,
                terminal_created=1,
                outcome=outcome,
                text=(
                    ResourceText(
                        assistant_id="msg_synthetic_final",
                        content_index=0,
                        text="PRIVATE_NATIVE_FINAL_RESULT",
                    ),
                ),
                tools=(),
                ordered_message_ids=(
                    correlation.upstream_id,
                    "msg_synthetic_final",
                    "msg_synthetic_idle",
                ),
                selected_projection_sha256="b" * 64,
            ),
        )
        if self.hook:
            await self.hook()
        if self.mode == "copy":
            return self.evidence.model_copy()
        if self.mode == "foreign":
            self.evidence = self.evidence.model_copy(
                update={
                    "correlation": correlation.model_copy(update={"action_id": "another_action"})
                }
            )
        return self.evidence

    def current(self, value):
        return self.alive and value is self.evidence and time.time() < value.expires_at


async def setup(db, *, locale="en"):
    execution, source = SyntheticExecution(), Source()
    execution.contract_hash = INSTALLED_SCHEMA
    bindings, binding, _control, audience = await bound(db, control=execution)
    fencing = await DurableStore(db).acquire_lease("resources", ttl=120)
    inbox = CommandInbox(db, "resources", fencing)
    worker = Dispatcher(bindings, execution, source, "resources", fencing)
    item = message("Original exact prompt", 101)
    source.messages[item.message_id] = item
    queued = await QueueService(bindings).receive(binding.id, item, reply_locale=locale)
    assert await worker.advance(queued.action_id) == "admitted"
    reader = Reader()
    return (
        ResourceResultCollector(bindings, reader, inbox.fence),
        binding,
        queued.action_id,
        reader,
        execution,
        audience,
    )


async def action(db, identity):
    async with db.sessions() as session:
        return await session.get(Action, identity)


@pytest.mark.parametrize(
    "outcome,state",
    [("succeeded", "completed"), ("failed", "failed"), ("interrupted", "cancelled")],
)
async def test_admission_remains_separate_until_a_live_correlated_resource_terminal_is_stored(
    db, outcome, state
):
    collector, binding, identity, reader, execution, _audience = await setup(db)
    before = await action(db, identity)
    assert before.state == "admitted" and not before.native_result
    reader.mode = outcome
    result = await collector.collect(identity, "realm")
    assert result.outcome == state and result.format == "native-resource-execution-v1"
    saved = await action(db, identity)
    assert saved.state == state and saved.admission == before.admission
    assert (
        resource_result(saved) == result
        and await read_result(collector.bindings, identity, "realm", 7) == result
    )
    assert result.evidence.turn.text[0].text == "PRIVATE_NATIVE_FINAL_RESULT"
    assert result.reference == binding_to_ref(binding) and len(execution.submitted) == 1
    reader.alive = False
    assert await collector.collect(identity, "realm") == result and reader.calls == 1


def binding_to_ref(binding):
    from jt_oz_bridge.services.bindings import reference

    return reference(binding)


@pytest.mark.parametrize("mode", ["copy", "foreign", "expired"])
async def test_rehydrated_foreign_or_expired_snapshot_is_not_live_capture_authority(db, mode):
    collector, _binding, identity, reader, _execution, _audience = await setup(db)
    reader.mode = mode
    if mode == "expired":
        reader.alive = False
    with pytest.raises(Conflict):
        await collector.collect(identity, "realm")
    saved = await action(db, identity)
    assert saved.state == "admitted" and not saved.native_result


async def test_witness_revoked_at_final_database_boundary_rolls_back_completion(db):
    collector, _binding, identity, reader, _execution, _audience = await setup(db)
    original = collector.bindings.get
    count = 0

    async def revoke(*args, **kwargs):
        nonlocal count
        result = await original(*args, **kwargs)
        count += 1
        if count == 2:
            reader.alive = False
        return result

    collector.bindings.get = revoke
    with pytest.raises(Conflict, match="witness"):
        await collector.collect(identity, "realm")
    assert not (await action(db, identity)).native_result


@pytest.mark.parametrize("change", ["revision", "view", "audience", "lease"])
async def test_scope_and_lease_changes_during_capture_prevent_result_commit(db, change):
    collector, binding, identity, reader, _execution, audience = await setup(db)

    async def changed():
        if change == "audience":
            audience.users = frozenset({7, 8, 999})
            return
        async with db.sessions.begin() as session:
            if change == "revision":
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(revision=2)
                )
            elif change == "view":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            else:
                await session.execute(update(WorkerLease).values(expires_at=0))

    reader.hook = changed
    with pytest.raises(ValueError):
        await collector.collect(identity, "realm")
    assert not (await action(db, identity)).native_result


async def test_write_failure_cannot_leave_completed_state_without_the_sealed_result(db):
    collector, _binding, identity, reader, execution, _audience = await setup(db)

    def fail(mapper, connection, target):
        if target.native_result:
            raise OSError("synthetic result commit failure")

    event.listen(Action, "before_update", fail)
    try:
        with pytest.raises(OSError):
            await collector.collect(identity, "realm")
    finally:
        event.remove(Action, "before_update", fail)
    saved = await action(db, identity)
    assert saved.state == "admitted" and not saved.native_result
    await collector.collect(identity, "realm")
    assert (await action(db, identity)).state == "completed" and len(execution.submitted) == 1


@pytest.mark.parametrize(
    "change", ["text", "native_id", "admission", "evidence_hash", "outcome", "topic"]
)
async def test_stored_result_crosschecks_original_action_admission_scope_and_resource_seal(
    db, change
):
    collector, _binding, identity, _reader, _execution, _audience = await setup(db)
    await collector.collect(identity, "realm")
    async with db.sessions.begin() as session:
        saved = await session.get(Action, identity)
        payload = copy.deepcopy(saved.native_result)
        if change == "text":
            payload["evidence"]["correlation"]["text"] = "replaced text"
        elif change == "native_id":
            payload["evidence"]["turn"]["user_id"] = "another_native_input"
        elif change == "admission":
            payload["admission_sha256"] = "c" * 64
        elif change == "evidence_hash":
            payload["evidence_sha256"] = "c" * 64
        elif change == "outcome":
            payload["outcome"] = "failed"
        else:
            payload["topic"] = "a different private topic"
        saved.native_result = payload
    with pytest.raises(ValueError):
        await read_result(collector.bindings, identity, "realm", 7)


def add_synthetic_file_admission(item):
    """Detached local fixture only; never produce operational Human/binding rows."""
    import hashlib
    import uuid

    from jt_oz_bridge.adapters.opencode.attachments import ATTACHMENT_SEMANTICS
    from jt_oz_bridge.domain.attachments import PromptAttachmentManifest, PromptAttachmentReceipt
    from jt_oz_bridge.storage.durable import digest

    receipt = PromptAttachmentReceipt(
        artifact_id=str(uuid.uuid4()),
        source_upload="/user_uploads/2/fixture/file.txt",
        source_message_id=item.payload["source"]["message_id"],
        source_sha256=digest(item.payload["source"]),
        filename="file.txt",
        mime_type="text/plain",
        size=4,
        sha256=hashlib.sha256(b"body").hexdigest(),
    )
    manifest = PromptAttachmentManifest(files=(receipt,))
    item.payload = {**item.payload, "attachments": manifest.model_dump(mode="json")}
    item.operation_digest = digest(item.payload)
    item.admission = copy.deepcopy(item.admission)
    item.admission["operation_digest"] = item.operation_digest
    item.admission["admission"]["details"].update(
        attachments=[
            {
                "source": receipt.model_dump(
                    mode="json", include={"artifact_id", "filename", "mime_type", "size", "sha256"}
                ),
                "native": receipt.model_dump(
                    mode="json", include={"filename", "mime_type", "size", "sha256"}
                ),
                "normalization": "none",
                "mime_detected_from_bytes": True,
            }
        ],
        attachment_semantics_sha256=ATTACHMENT_SEMANTICS,
        model_visibility="unverified",
    )
    return receipt


@pytest.mark.parametrize(
    "change", [None, "source", "native", "missing", "semantics", "unexpected", "source_message"]
)
async def test_file_result_correlation_binds_original_manifest_and_native_admission(db, change):
    from jt_oz_bridge.services.resource_execution_results import correlation
    from jt_oz_bridge.storage.durable import digest

    collector, binding, identity, reader, execution, _audience = await setup(db)
    item = await action(db, identity)
    file = add_synthetic_file_admission(item)
    details = item.admission["admission"]["details"]
    if change == "source":
        details["attachments"][0]["source"]["artifact_id"] = "00000000-0000-0000-0000-000000000000"
    elif change == "native":
        details["attachments"][0]["native"]["sha256"] = "0" * 64
    elif change == "missing":
        details.pop("attachments")
    elif change == "semantics":
        details["attachment_semantics_sha256"] = "0" * 64
    elif change == "unexpected":
        item.payload.pop("attachments")
        item.operation_digest = digest(item.payload)
        item.admission["operation_digest"] = item.operation_digest
    elif change == "source_message":
        item.payload["attachments"]["files"][0]["source_message_id"] += 1
        item.operation_digest = digest(item.payload)
        item.admission["operation_digest"] = item.operation_digest
    if change:
        with pytest.raises((Conflict, ValueError)):
            correlation(item)
    else:
        value = correlation(item)
        assert len(value.attachments) == 1 and value.attachments[0].sha256 == file.sha256
        assert "body" not in value.model_dump_json()


async def test_attachment_result_evidence_without_independent_file_qualification_rolls_back(db):
    from jt_oz_bridge.storage.resource_models import ResourceResultRecord

    collector, binding, identity, reader, execution, _audience = await setup(db)
    async with db.sessions.begin() as session:
        item = await session.get(Action, identity)
        add_synthetic_file_admission(item)
    # Reader has a synthetic live object witness but no separate file evidence.
    with pytest.raises(Conflict, match="identity_or_evidence_changed"):
        await collector.collect(identity, "realm")
    item = await action(db, identity)
    assert item.state == "admitted" and not item.native_result
    async with db.sessions() as session:
        assert await session.get(ResourceResultRecord, identity) is None


async def test_qualified_attachment_result_is_durable_without_altering_old_text_result_hashes(db):
    from jt_oz_bridge.adapters.opencode.attachments import ATTACHMENT_SEMANTICS

    collector, binding, identity, reader, execution, _audience = await setup(db)
    async with db.sessions.begin() as session:
        item = await session.get(Action, identity)
        add_synthetic_file_admission(item)
    original = reader.capture

    async def capture(c):
        evidence = await original(c)
        reader.evidence = evidence.model_copy(
            update={
                "attachment_semantics_sha256": ATTACHMENT_SEMANTICS,
                "attachment_evidence_sha256": "d" * 64,
            }
        )
        return reader.evidence

    reader.capture = capture
    result = await collector.collect(identity, "realm")
    assert result.evidence.attachment_evidence_sha256 == "d" * 64
    reader.alive = False
    assert await collector.collect(identity, "realm") == result and reader.calls == 1
    item = await action(db, identity)
    item.native_result = copy.deepcopy(item.native_result)
    item.native_result["evidence"]["attachment_evidence_sha256"] = None
    with pytest.raises(Conflict):
        resource_result(item)


@pytest.mark.parametrize("delivery", ["steer", "queue"])
async def test_a_later_steer_lets_the_head_accept_a_following_busy_period(db, delivery):
    collector, binding, identity, reader, execution, _audience = await setup(db)
    seen = []
    plain = reader.capture

    async def capture(correlation, **options):
        seen.append(options)
        return await plain(correlation)

    reader.capture = capture
    head = await action(db, identity)
    payload = {"operation": "prompt", "text": "later"}
    later = Action(
        id="later-steer-action",
        dedupe_key="later-steer",
        binding_id=binding.id,
        binding_revision=binding.revision,
        actor_id=head.actor_id,
        operation="prompt",
        operation_digest=digest(payload),
        payload=payload,
        state="admitted",
        upstream_id="msg_steered",
        owner="opencode",
        admission={
            **head.admission,
            "action_id": "later-steer-action",
            "operation_digest": digest(payload),
            "admission": {
                **head.admission["admission"],
                "upstream_id": "msg_steered",
                "details": {"operation": "prompt", "delivery": delivery, "turn_completed": False},
            },
        },
        created_at=head.created_at + 1,
    )
    async with db.sessions.begin() as session:
        session.add(later)
    result = await collector.collect(identity, "realm")
    assert result.outcome == "completed"
    assert seen == ([{"allow_later_steer": True}] if delivery == "steer" else [{}])
