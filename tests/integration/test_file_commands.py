"""Owned command -> synthetic original Native read -> encrypted return journal."""

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.integration.test_file_returns import all_rows, setup
from tests.integration.test_router import message
from tests.support import REF


@asynccontextmanager
async def commands(db, tmp_path, **options):
    async with setup(db, tmp_path, initial_artifact=False, **options) as v:
        v.reads, v.hook = 0, None
        v.read_evidence = []

        async def read(ref, path, *, maximum_bytes):
            assert ref == REF and path == v.file.evidence.relative_path
            v.reads += 1
            if len(v.file.content) > maximum_bytes:
                raise ContractError("synthetic_native_limit")
            now = time.time()
            v.file = replace(
                v.file,
                evidence=v.file.evidence.model_copy(
                    update={"observed_at": now, "expires_at": now + 5}
                ),
            )
            v.witness.file = v.file
            if v.hook is not None:
                await v.hook()
            v.read_evidence.append(v.file.evidence)
            return v.file

        v.witness.read = read
        v.commands = FileCommands(v.service, {REF: v.witness})
        v.inbox = CommandInbox(db, v.store.fence.holder, v.store.fence.fencing)
        v.router = CommandRouter(v.store.bindings, v.source, v.inbox, files=v.commands)
        yield v


async def claim(v):
    return await v.inbox.claim(
        v.human, "file", binding_id=v.binding.id, binding_revision=v.binding.revision
    )


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize(
    "body",
    [b"", b"original\r\n\x00bytes", b"x" * MAX_ATTACHMENT_BYTES],
    ids=("empty", "binary", "20MiB"),
)
async def test_capture_exact_bytes_then_original_topic_journal_without_native_mutation(
    db, tmp_path, locale, body
):
    async with commands(db, tmp_path, body=body) as v:
        c = await claim(v)
        reply = await v.commands.route(v.binding, v.human, locale, c)
        row = (await all_rows(db, FileTransfer))[0]
        assert row.id not in reply and 1 <= v.reads <= 2 and v.remote.posts == 0
        # Storage/scanning may legitimately exhaust the original five seconds.
        # Only one exact-byte reproof is allowed; no timing-dependent read count.
        assert len(v.read_evidence) == v.reads
        if v.reads == 2:
            first, fresh = v.read_evidence
            assert first.expires_at <= fresh.observed_at
            assert first.model_dump(exclude={"observed_at", "expires_at"}) == fresh.model_dump(
                exclude={"observed_at", "expires_at"}
            )
        plan = (await v.service.load(row.id))[1]
        assert plan.native == v.read_evidence[-1]
        assert plan.native.expires_at - plan.native.observed_at == 5
        artifacts = await all_rows(db, Artifact)
        assert len(artifacts) == 1 and artifacts[0].source_message_id == v.human.message_id
        assert (await v.store.read(artifacts[0].id, "realm", 7)).content == body
        for state in ("uploaded", "verified", "queued"):
            assert await v.service.advance(row.id) == state
        assert v.remote.posts == 1 and not await all_rows(db, Action)
        assert (await v.service.load(row.id))[1].source == v.human


async def test_router_replay_never_rereads_a_newer_native_file(db, tmp_path):
    async with commands(db, tmp_path) as v:
        first = await v.router.route(v.human)
        v.witness.read = AsyncMock(side_effect=AssertionError("must not re-capture"))
        assert await v.router.route(v.human) == first
        assert v.reads == 1 and len(await all_rows(db, FileTransfer)) == 1
        assert len(await all_rows(db, Artifact)) == 1 and not await all_rows(db, Action)


async def test_same_owned_attempt_reentry_uses_prepared_record_without_native_read(db, tmp_path):
    async with commands(db, tmp_path) as v:
        c = await claim(v)
        first = await v.commands.capture(v.binding, v.human, c, locale="en")
        v.witness.read = AsyncMock(side_effect=AssertionError("must use known transfer"))
        assert await v.commands.capture(v.binding, v.human, c, locale="zh-TW") == first
        assert (await v.service.load(first))[1].locale == "en"
        assert len(await all_rows(db, Artifact)) == 1


async def test_concurrent_same_command_capture_reads_and_stores_only_once(db, tmp_path):
    async with commands(db, tmp_path) as v:
        c = await claim(v)
        first, second = await asyncio.gather(
            *(v.commands.capture(v.binding, v.human, c, locale="en") for _ in range(2))
        )
        assert first == second and v.reads == 1
        assert len(await all_rows(db, Artifact)) == len(await all_rows(db, FileTransfer)) == 1


@pytest.mark.parametrize(
    "kind", ["source", "claim", "binding", "viewer", "operator", "fence", "file-capability"]
)
async def test_failures_before_capture_make_no_native_request_or_artifact(db, tmp_path, kind):
    async with commands(db, tmp_path) as v:
        c = await claim(v)
        if kind == "source":
            v.source.messages[v.human.message_id] = v.human.model_copy(update={"deleted": True})
        elif kind == "file-capability":
            v.client.attestation = replace(
                v.client.attestation, verified_file_operations=frozenset()
            )
        else:
            async with db.sessions.begin() as session:
                if kind == "claim":
                    await session.execute(update(CommandReceipt).values(state="ambiguous"))
                elif kind == "binding":
                    await session.execute(update(Binding).values(revision=2))
                elif kind in {"viewer", "operator"}:
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == (8 if kind == "viewer" else 7))
                        .values(active=False)
                    )
                else:
                    await session.execute(update(WorkerLease).values(fencing=99))
        with pytest.raises(ValueError):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert v.reads == 0 and not await all_rows(db, Artifact)
        assert not await all_rows(db, FileTransfer) and v.remote.posts == 0


@pytest.mark.parametrize(
    "kind",
    [
        "edited",
        "deleted",
        "operator",
        "claim",
        "expiry",
        "checksum",
        "reference",
        "path",
        "contract",
        "filename",
    ],
)
async def test_changes_during_original_native_read_never_become_uploadable(db, tmp_path, kind):
    async with commands(db, tmp_path) as v:
        c = await claim(v)

        async def change():
            if kind in {"edited", "deleted"}:
                v.source.messages[v.human.message_id] = v.human.model_copy(
                    update={"revision": 1} if kind == "edited" else {"deleted": True}
                )
            elif kind in {"operator", "claim"}:
                async with db.sessions.begin() as session:
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                        if kind == "operator"
                        else update(CommandReceipt).values(state="ambiguous")
                    )
            elif kind == "expiry":
                v.witness.active = False
            elif kind == "checksum":
                v.file = replace(v.file, content=b"different")
                v.witness.file = v.file
            else:
                field, value = {
                    "reference": ("reference", REF.model_copy(update={"project_id": "different"})),
                    "path": ("relative_path", "different.html"),
                    "contract": ("contract_sha256", "f" * 64),
                    "filename": (
                        "projection",
                        v.file.evidence.projection.model_copy(
                            update={"filename": "different.html"}
                        ),
                    ),
                }[kind]
                v.file = replace(v.file, evidence=v.file.evidence.model_copy(update={field: value}))
                v.witness.file = v.file

        v.hook = change
        with pytest.raises(ValueError):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert v.reads == 1 and not await all_rows(db, Artifact)
        assert not await all_rows(db, FileTransfer) and v.remote.posts == 0


async def test_recovery_reuses_exact_committed_artifact_after_failed_prepare(
    db, tmp_path, monkeypatch
):
    async with commands(db, tmp_path) as v:
        c = await claim(v)
        original = v.service.prepare
        monkeypatch.setattr(v.service, "prepare", AsyncMock(side_effect=Conflict("before_prepare")))
        with pytest.raises(Conflict):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        first = (await all_rows(db, Artifact))[0]
        assert not await all_rows(db, FileTransfer)
        monkeypatch.setattr(v.service, "prepare", original)
        identity = await v.commands.capture(v.binding, v.human, c, locale="en")
        assert (await v.service.load(identity))[0].artifact_id == first.id
        assert len(await all_rows(db, Artifact)) == 1 and v.reads == 2


async def test_router_crash_after_prepare_does_not_repeat_capture_but_preserves_journal(
    db, tmp_path, monkeypatch
):
    async with commands(db, tmp_path) as v:
        monkeypatch.setattr(
            v.inbox, "finish", AsyncMock(side_effect=RuntimeError("lost reply commit"))
        )
        with pytest.raises(RuntimeError):
            await v.router.route(v.human)
        assert (await all_rows(db, CommandReceipt))[0].state == "ambiguous"
        assert (await v.router.route(v.human)).state == "ambiguous" and v.reads == 1
        row = (await all_rows(db, FileTransfer))[0]
        assert await v.service.advance(row.id) == "uploaded" and v.remote.posts == 1


async def test_help_describes_actual_relative_path_extension_and_default_remains_unavailable(
    db, tmp_path
):
    async with commands(db, tmp_path) as v:
        help_message = message("!oz help file", 102)
        v.source.messages[102] = help_message
        assert "relative-path" in (await v.router.route(help_message)).text
        bare = CommandRouter(v.store.bindings, v.source, v.inbox)
        v.source.messages[103] = message("!oz file example.txt", 103)
        assert "available yet" in (await bare.route(v.source.messages[103])).text
        assert v.reads == 0


@pytest.mark.parametrize("path", [".env", "../escape", "/etc/shadow", ".ssh/id_ed25519"])
async def test_sensitive_paths_are_rejected_before_any_native_read(db, tmp_path, path):
    async with commands(db, tmp_path) as v:
        v.human = message("!oz file " + path)
        v.source.messages[v.human.message_id] = v.human
        assert (await v.router.route(v.human)).text in {
            Translator().render("permission.denied", "en"),
            Translator().render("router.stale", "en"),
            Translator().render("router.usage", "en"),
        }
        assert v.reads == 0 and not await all_rows(db, Artifact)


async def test_router_rejects_a_file_handler_with_another_source_reader(db, tmp_path):
    async with commands(db, tmp_path) as v:
        with pytest.raises(ValueError, match="scope_mismatch"):
            CommandRouter(v.store.bindings, object(), v.inbox, files=v.commands)
        with pytest.raises(ValueError, match="original_journal_readers"):
            FileCommands(v.service, {})


async def test_original_scan_memo_only_avoids_duplicate_capture_scan_then_upload_rescans(
    db, tmp_path, monkeypatch
):
    import jt_oz_bridge.services.file_returns as module

    async with commands(db, tmp_path) as v:
        scan = Mock(wraps=module.check_content)
        monkeypatch.setattr(module, "check_content", scan)
        c = await claim(v)
        identity = await v.commands.capture(v.binding, v.human, c, locale="en")
        assert scan.call_count == 1
        assert await v.service.advance(identity) == "uploaded"
        assert scan.call_count > 1
        with pytest.raises(Conflict, match="original_native_scan_witness"):
            v.service.scan_native(replace(v.file))


async def test_literal_credential_content_is_rejected_before_encrypted_artifact_creation(
    db, tmp_path
):
    async with commands(
        db, tmp_path, body=b'password="actual-private-value"', path="report.txt"
    ) as v:
        c = await claim(v)
        with pytest.raises(ValueError):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert v.reads == 1 and not await all_rows(db, Artifact)
        assert not await all_rows(db, FileTransfer)


async def test_lost_original_witness_during_artifact_commit_never_prepares_upload(
    db, tmp_path, monkeypatch
):
    async with commands(db, tmp_path) as v:
        create = v.store.create

        async def lose_after_commit(*args, **kwargs):
            identity = await create(*args, **kwargs)
            v.witness.active = False
            return identity

        monkeypatch.setattr(v.store, "create", lose_after_commit)
        c = await claim(v)
        with pytest.raises(Conflict):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert len(await all_rows(db, Artifact)) == 1
        assert not await all_rows(db, FileTransfer) and v.remote.posts == 0


@pytest.mark.parametrize(
    "body", [b"small exact bytes", b"x" * MAX_ATTACHMENT_BYTES], ids=["small", "20MiB"]
)
@pytest.mark.parametrize("slow_stage", ["scan", "storage"])
async def test_slow_capture_reproves_same_bytes_without_extending_native_expiry(
    db, tmp_path, monkeypatch, slow_stage, body
):
    from jt_oz_bridge.services import file_returns

    async with commands(db, tmp_path, body=body) as v:
        clock = [time.time()]
        monkeypatch.setattr(time, "time", lambda: clock[0])
        inspected = []
        original_scan = file_returns.check_content

        def scan(data, filename=""):
            inspected.append(data)
            original_scan(data, filename)
            if slow_stage == "scan":
                clock[0] += 6

        monkeypatch.setattr(file_returns, "check_content", scan)
        original_create = v.store.create

        async def store(*args, **kwargs):
            result = await original_create(*args, **kwargs)
            if slow_stage == "storage":
                clock[0] += 6
            return result

        monkeypatch.setattr(v.store, "create", store)
        c = await claim(v)
        identity = await v.commands.capture(v.binding, v.human, c, locale="zh-TW")
        saved, plan = await v.service.load(identity)
        assert saved.state == "prepared" and v.reads == 2 and v.remote.posts == 0
        assert len(inspected) == 1
        assert plan.native.expires_at - plan.native.observed_at == 5
        assert plan.native.observed_at == clock[0]
        assert (await v.store.read(saved.artifact_id, "realm", 7)).content == v.file.content


@pytest.mark.parametrize(
    "change",
    ["content", "reference", "etag", "owner", "policy", "expired", "reader", "source", "grant"],
)
async def test_expired_capture_refresh_cannot_substitute_changed_bytes_scope_or_source(
    db, tmp_path, monkeypatch, change
):
    from jt_oz_bridge.services import file_returns

    async with commands(db, tmp_path) as v:
        clock = [time.time()]
        monkeypatch.setattr(time, "time", lambda: clock[0])
        original_scan = file_returns.check_content

        def scan(data, filename=""):
            original_scan(data, filename)
            clock[0] += 6

        monkeypatch.setattr(file_returns, "check_content", scan)

        async def changed_read():
            if v.reads != 2:
                return
            if change == "content":
                v.file = replace(v.file, content=b"different newer file")
            elif change == "reader":
                v.service.readers = {}
            elif change == "source":
                v.source.messages[v.human.message_id] = v.human.model_copy(update={"revision": 1})
            elif change == "grant":
                async with db.sessions.begin() as session:
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
            else:
                key, value = {
                    "reference": ("reference", REF.model_copy(update={"project_id": "other"})),
                    "etag": ("etag", "different-file-version"),
                    "owner": ("owner_epoch", "other-owner"),
                    "policy": ("native_policy_sha256", "f" * 64),
                    "expired": ("expires_at", clock[0] - 1),
                }[change]
                v.file = replace(v.file, evidence=v.file.evidence.model_copy(update={key: value}))
            v.witness.file = v.file

        v.hook = changed_read
        c = await claim(v)
        with pytest.raises(ValueError):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert v.reads == 2 and not await all_rows(db, FileTransfer)
        assert v.remote.posts == 0 and len(await all_rows(db, Artifact)) == 1


async def test_scan_fact_does_not_make_an_expired_native_object_authoritative(
    db, tmp_path, monkeypatch
):
    async with commands(db, tmp_path) as v:
        clock = [time.time()]
        monkeypatch.setattr(time, "time", lambda: clock[0])
        v.service.scan_native(v.file)
        clock[0] += 6
        # Inspection facts cannot bypass prepare's current original-object check.
        with pytest.raises(ValueError, match="native_witness"):
            await v.service.prepare("not-an-artifact", v.human, v.file)
        with pytest.raises(ValueError, match="inspected_original"):
            v.service.rebind_scan(replace(v.file), v.file)
        assert v.remote.posts == 0 and not await all_rows(db, FileTransfer)


async def test_reader_invalidation_before_expiry_does_not_trigger_a_new_capture(
    db, tmp_path, monkeypatch
):
    async with commands(db, tmp_path) as v:
        create = v.store.create

        async def invalidated(*args, **kwargs):
            identity = await create(*args, **kwargs)
            v.witness.active = False
            return identity

        monkeypatch.setattr(v.store, "create", invalidated)
        c = await claim(v)
        with pytest.raises(ValueError, match="reader_invalidated"):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert v.reads == 1 and not await all_rows(db, FileTransfer) and v.remote.posts == 0


async def test_unchanged_file_can_be_reproved_after_resource_fence_advances(
    db, tmp_path, monkeypatch
):
    from jt_oz_bridge.services import file_returns

    async with commands(db, tmp_path) as v:
        clock = [time.time()]
        monkeypatch.setattr(time, "time", lambda: clock[0])
        check = file_returns.check_content

        def scan(data, filename=""):
            check(data, filename)
            clock[0] += 6

        monkeypatch.setattr(file_returns, "check_content", scan)

        async def changed_fence():
            if v.reads == 2:
                v.file = replace(
                    v.file,
                    evidence=v.file.evidence.model_copy(
                        update={"resource_fence": "new-resource-fence"}
                    ),
                )
                v.witness.file = v.file

        v.hook = changed_fence
        c = await claim(v)
        identity = await v.commands.capture(v.binding, v.human, c, locale="en")
        row, plan = await v.service.load(identity)
        assert row.state == "prepared" and plan.native.resource_fence == "new-resource-fence"
        assert v.reads == 2 and v.remote.posts == 0
