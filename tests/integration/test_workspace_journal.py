"""Real own DB/encryption/files; synthetic source and no Native/chat mutations."""

import asyncio
import os
import time
from dataclasses import asdict

import pytest
from sqlalchemy import select, text

from jt_oz_bridge.domain.attachments import WorkspaceAttachmentManifest
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.workspace_journal import RegisteredPartial, WorkspaceJournal, plan_of
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from jt_oz_bridge.storage.workspace_files import (
    WorkspaceFiles,
    WorkspaceNamespace,
    WorkspacePartial,
)
from jt_oz_bridge.storage.workspace_models import WorkspaceBudget, WorkspacePublication
from tests.integration.test_prompt_attachments import close
from tests.integration.test_workspace_attachment_imports import workspace


async def setup(db, tmp_path, *, count=2, size=22, **limits):
    parts, incoming = await workspace(db, tmp_path, count=count, size=size)
    staged = await incoming.stage(parts[5])
    manifest = WorkspaceAttachmentManifest.model_validate(staged.payload["workspace_attachments"])
    source = parts[4].messages[parts[3].message_id]
    async with db.sessions.begin() as session:
        (await session.get(Action, parts[5])).state = "dispatching"
    path = tmp_path / "ordinary-workspace"
    path.mkdir(mode=0o2750)
    path.chmod(0o2750)
    stat = path.stat()
    files = WorkspaceFiles(
        WorkspaceNamespace(path, stat.st_dev, stat.st_ino, os.geteuid(), stat.st_gid),
        reserve_free_bytes=0,
    )
    return parts, WorkspaceJournal(parts[0], files, **limits), source, manifest


async def finish(parts, journal):
    journal.files.close()
    await close(parts)


async def rows(db):
    async with db.sessions() as session:
        return tuple(
            (
                await session.scalars(
                    select(WorkspacePublication).order_by(WorkspacePublication.artifact_id)
                )
            ).all()
        )


async def terminal_and_expire(db, action_id, *, state="completed"):
    async with db.sessions.begin() as session:
        (await session.get(Action, action_id)).state = state
        for row in (await session.scalars(select(WorkspacePublication))).all():
            row.expires_at = time.time() - 1


async def test_fenced_workspace_batch_preserves_bytes_encrypts_metadata_and_reuses_ready_files(
    db, tmp_path
):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        first = await journal.stage(parts[5], source, manifest)
        repeated = await WorkspaceJournal(parts[0], journal.files).stage(parts[5], source, manifest)
        assert first == repeated and len(first) == 2
        assert all(journal.files.current(f) for f in first)
        assert all(
            (journal.files.namespace.path / f.storage_name).read_bytes() == bytes(22) for f in first
        )
        saved = await rows(db)
        assert {r.state for r in saved} == {"ready"}
        assert all(plan_of(r).file is not None for r in saved)
        async with db.engine.connect() as connection:
            encrypted = (
                await connection.execute(
                    text("SELECT typeof(payload),payload FROM workspace_publications")
                )
            ).all()
        assert all(
            kind == "blob" and b"original-workspace-publication-v1" not in payload
            for kind, payload in encrypted
        )
        async with db.sessions() as session:
            budget = await session.get(WorkspaceBudget, "global")
            assert budget.reserved_bytes == 44 and budget.object_count == 2
        assert len(parts[-1]) == 4  # importer only; workspace journal performs no HTTP
    finally:
        await finish(parts, journal)


@pytest.mark.parametrize("limits", [{"quota_bytes": 43}, {"maximum_objects": 1}])
async def test_entire_batch_quota_is_reserved_atomically_before_any_plaintext_write(
    db, tmp_path, limits
):
    parts, journal, source, manifest = await setup(db, tmp_path, **limits)
    try:
        with pytest.raises(Conflict, match="quota"):
            await journal.stage(parts[5], source, manifest)
        assert not await rows(db) and not tuple(journal.files.namespace.path.iterdir())
        async with db.sessions() as session:
            assert await session.get(WorkspaceBudget, "global") is None
    finally:
        await finish(parts, journal)


@pytest.mark.parametrize("kind", ["partial", "linked-ready", "ready-before-cas"])
async def test_registered_power_loss_boundaries_recover_exact_files_without_double_quota(
    db, tmp_path, kind
):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        identities = await journal.reserve(parts[5], source, manifest)
        row, plan = await journal.load(identities[0])
        name = plan.action_id + "_" + plan.artifact_id
        part = journal.files.namespace.path / ("." + name + ".part")
        part.write_bytes(bytes(11) if kind == "partial" else bytes(22))
        part.chmod(0o600)
        stat = part.stat()
        partial = WorkspacePartial(plan.action_id, plan.artifact_id, stat.st_dev, stat.st_ino)
        await journal.checkpoint(
            row, plan.model_copy(update={"partial": RegisteredPartial(**asdict(partial))})
        )
        if kind != "partial":
            part.chmod(0o640)
            os.link(part, journal.files.namespace.path / name)
            if kind == "ready-before-cas":
                part.unlink()
        result = await WorkspaceJournal(parts[0], journal.files).stage(parts[5], source, manifest)
        assert len(result) == 2 and all(journal.files.current(f) for f in result)
        assert not part.exists()
        async with db.sessions() as session:
            assert (await session.get(WorkspaceBudget, "global")).object_count == 2
    finally:
        await finish(parts, journal)


async def test_unknown_partial_is_not_deleted_or_overwritten_during_recovery(db, tmp_path):
    parts, journal, source, manifest = await setup(db, tmp_path)
    partial = journal.files.namespace.path / (
        "." + parts[5] + "_" + manifest.files[0].artifact_id + ".part"
    )
    partial.write_bytes(b"UNKNOWN-OWNER-DATA")
    try:
        with pytest.raises(FileExistsError):
            await journal.stage(parts[5], source, manifest)
        assert partial.read_bytes() == b"UNKNOWN-OWNER-DATA"
        assert all(r.state == "reserved" for r in await rows(db))
    finally:
        await finish(parts, journal)


@pytest.mark.parametrize("kind", ["source", "grant", "action", "artifact", "lease"])
async def test_changed_scope_is_rejected_before_plaintext_publication(db, tmp_path, kind):
    parts, journal, source, manifest = await setup(db, tmp_path)
    if kind == "source":
        source = source.model_copy(update={"revision": source.revision + 1})
    async with db.sessions.begin() as session:
        if kind == "grant":
            for grant in (await session.scalars(select(Grant))).all():
                grant.active = False
        if kind == "action":
            (await session.get(Action, parts[5])).state = "admitted"
        if kind == "artifact":
            from jt_oz_bridge.storage.artifact_models import Artifact

            (
                await session.get(Artifact, manifest.files[0].artifact_id)
            ).action_id = "foreign-action"
        if kind == "lease":
            (await session.get(WorkerLease, "consumer")).expires_at = 0
    try:
        with pytest.raises((ValueError, AccessDenied)):
            await journal.stage(parts[5], source, manifest)
        assert not tuple(journal.files.namespace.path.iterdir())
    finally:
        await finish(parts, journal)


async def test_crash_after_ready_file_before_sql_checkpoint_recovers_recorded_inode(db, tmp_path):
    parts, journal, source, manifest = await setup(db, tmp_path)
    original = journal.checkpoint

    async def crash(row, plan, *, ready=False):
        if ready:
            raise RuntimeError("isolated crash after fsync before ready CAS")
        await original(row, plan, ready=ready)

    journal.checkpoint = crash
    try:
        with pytest.raises(RuntimeError):
            await journal.stage(parts[5], source, manifest)
        saved = await rows(db)
        assert all(r.state == "reserved" for r in saved)
        assert len(tuple(journal.files.namespace.path.iterdir())) == 1
        result = await WorkspaceJournal(parts[0], journal.files).stage(parts[5], source, manifest)
        assert len(result) == 2
        async with db.sessions() as session:
            assert (await session.get(WorkspaceBudget, "global")).reserved_bytes == 44
    finally:
        await finish(parts, journal)


@pytest.mark.parametrize("state", ["queued", "held", "dispatching", "admitted", "ambiguous"])
async def test_expiry_does_not_delete_files_owned_by_unresolved_actions(db, tmp_path, state):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        result = await journal.stage(parts[5], source, manifest)
        await terminal_and_expire(db, parts[5], state=state)
        assert await journal.prune_expired() == 0
        assert all(journal.files.current(f) for f in result)
    finally:
        await finish(parts, journal)


async def test_expired_terminal_files_are_deleted_by_identity_and_quota_released_once(db, tmp_path):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        await journal.stage(parts[5], source, manifest)
        await terminal_and_expire(db, parts[5])
        assert await journal.prune_expired() == 2 and await journal.prune_expired() == 0
        assert not tuple(journal.files.namespace.path.iterdir())
        assert {r.state for r in await rows(db)} == {"deleted"}
        async with db.sessions() as session:
            budget = await session.get(WorkspaceBudget, "global")
            assert budget.reserved_bytes == 0 and budget.object_count == 0
    finally:
        await finish(parts, journal)


@pytest.mark.parametrize("kind", ["bytes", "symlink", "hardlink", "namespace"])
async def test_cleanup_keeps_changed_files_and_quota_for_review(db, tmp_path, kind):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        result = await journal.stage(parts[5], source, manifest)
        target = journal.files.namespace.path / result[0].storage_name
        outside = tmp_path / "unrelated"
        outside.write_bytes(b"KEEP")
        if kind == "bytes":
            target.write_bytes(b"CHANGED")
        if kind == "symlink":
            target.unlink()
            target.symlink_to(outside)
        if kind == "hardlink":
            os.link(target, tmp_path / "extra-link")
        if kind == "namespace":
            journal.files.namespace.path.rename(tmp_path / "old-namespace")
            journal.files.namespace.path.mkdir(mode=0o2750)
            journal.files.namespace.path.chmod(0o2750)
        await terminal_and_expire(db, parts[5])
        removed = await journal.prune_expired()
        assert removed == (0 if kind == "namespace" else 1)
        assert outside.read_bytes() == b"KEEP"
        assert any(r.state == "quarantined" for r in await rows(db))
        async with db.sessions() as session:
            assert (await session.get(WorkspaceBudget, "global")).object_count == (2 - removed)
    finally:
        await finish(parts, journal)


async def test_cleanup_crash_after_unlink_releases_reservation_on_successor_fence(db, tmp_path):
    parts, journal, source, manifest = await setup(db, tmp_path)
    original = journal.files.remove

    async def crash(saved):
        await original(saved)
        raise asyncio.CancelledError

    try:
        await journal.stage(parts[5], source, manifest)
        await terminal_and_expire(db, parts[5])
        journal.files.remove = crash
        with pytest.raises(asyncio.CancelledError):
            await journal.prune_expired()
        assert any(r.state == "deleting" for r in await rows(db))
        async with db.sessions.begin() as session:
            (await session.get(WorkerLease, "consumer")).expires_at = 0
        value = await DurableStore(db).acquire_lease("successor-workspace")
        assert value is not None
        parts[0].fence = ConsumerFence("successor-workspace", value)
        journal.files.remove = original
        successor = WorkspaceJournal(parts[0], journal.files)
        with pytest.raises(Conflict, match="lease"):
            await journal.prune_expired()
        assert await successor.prune_expired() == 2
    finally:
        await finish(parts, journal)


async def test_pin_requires_manager_current_revision_and_blocks_expiry(db, tmp_path):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        await journal.stage(parts[5], source, manifest)
        saved = (await rows(db))[0]
        # The base fixture grants both users admin; revoke only user 7's
        # administrator role to make the negative manage check substantive.
        async with db.sessions.begin() as session:
            grants = (
                await session.scalars(
                    select(Grant).where(Grant.user_id == 7, Grant.role == "administrator")
                )
            ).all()
            for grant in grants:
                grant.active = False
                grant.revision += 1
        with pytest.raises(AccessDenied):
            await journal.pin(saved.id, source.realm_id, 7, saved.version, True)
        await journal.pin(saved.id, source.realm_id, 8, saved.version, True)
        with pytest.raises(Conflict):
            await journal.pin(saved.id, source.realm_id, 8, saved.version, False)
        await terminal_and_expire(db, parts[5])
        assert await journal.prune_expired() == 1
        current, plan = await journal.load(saved.id)
        assert current.pinned and current.state == "ready"
        await journal.pin(saved.id, source.realm_id, 8, current.version, False)
        assert await journal.prune_expired() == 1
    finally:
        await finish(parts, journal)


async def test_ten_20mib_encrypted_sources_publish_with_exact_plaintext_batch_quota(db, tmp_path):
    from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES

    parts, journal, source, manifest = await setup(
        db,
        tmp_path,
        count=10,
        size=MAX_ATTACHMENT_BYTES,
        quota_bytes=10 * MAX_ATTACHMENT_BYTES,
        maximum_objects=10,
    )
    try:
        result = await journal.stage(parts[5], source, manifest)
        assert len(result) == 10 and all(journal.files.current(file) for file in result)
        assert sum(file.original.size for file in result) == 200 * 1024**2
        repeated = await journal.stage(parts[5], source, manifest)
        assert repeated == result
        async with db.sessions() as session:
            budget = await session.get(WorkspaceBudget, "global")
            assert budget.reserved_bytes == 200 * 1024**2 and budget.object_count == 10
        assert {row.state for row in await rows(db)} == {"ready"}
    finally:
        await finish(parts, journal)


async def test_recovery_rechecks_encrypted_source_even_when_plaintext_is_already_ready(
    db, tmp_path
):
    parts, journal, source, manifest = await setup(db, tmp_path)
    try:
        result = await journal.stage(parts[5], source, manifest)
        artifact = tmp_path / "private-artifacts" / (manifest.files[0].artifact_id + ".bin")
        artifact.write_bytes(b"CORRUPTED")
        with pytest.raises(ValueError):
            await journal.stage(parts[5], source, manifest)
        assert all(journal.files.current(file) for file in result)
    finally:
        await finish(parts, journal)


async def test_empty_files_consume_objects_and_release_zero_bytes_without_underflow(db, tmp_path):
    parts, journal, source, manifest = await setup(
        db, tmp_path, size=0, quota_bytes=1, maximum_objects=2
    )
    try:
        result = await journal.stage(parts[5], source, manifest)
        assert len(result) == 2 and all(
            file.original.size == 0 and journal.files.current(file) for file in result
        )
        async with db.sessions() as session:
            budget = await session.get(WorkspaceBudget, "global")
            assert budget.reserved_bytes == 0 and budget.object_count == 2
        await terminal_and_expire(db, parts[5])
        assert await journal.prune_expired() == 2 and await journal.prune_expired() == 0
        async with db.sessions() as session:
            budget = await session.get(WorkspaceBudget, "global")
            assert budget.reserved_bytes == 0 and budget.object_count == 0
    finally:
        await finish(parts, journal)


async def test_parallel_claims_cannot_overbook_the_shared_plaintext_budget(db, tmp_path):
    from jt_oz_bridge.services.attachment_imports import AttachmentImportJournal
    from jt_oz_bridge.services.queue import QueueService

    parts, journal, source, manifest = await setup(db, tmp_path, quota_bytes=44, maximum_objects=2)
    second = source.model_copy(update={"message_id": source.message_id + 1})
    parts[4].messages[second.message_id] = second
    queued = await QueueService(parts[0].bindings).receive(parts[1].id, second)
    imported = await AttachmentImportJournal(parts[8], journal.fence, transport="workspace").stage(
        queued.action_id
    )
    other_manifest = WorkspaceAttachmentManifest.model_validate(
        imported.payload["workspace_attachments"]
    )
    async with db.sessions.begin() as session:
        (await session.get(Action, queued.action_id)).state = "dispatching"
    try:
        other = WorkspaceJournal(parts[0], journal.files, quota_bytes=44, maximum_objects=2)
        result = await asyncio.gather(
            journal.stage(parts[5], source, manifest),
            other.stage(queued.action_id, second, other_manifest),
            return_exceptions=True,
        )
        assert sum(isinstance(value, tuple) for value in result) == 1
        assert sum(isinstance(value, Conflict) for value in result) == 1
        assert len(await rows(db)) == 2 and len(tuple(journal.files.namespace.path.iterdir())) == 2
        async with db.sessions() as session:
            budget = await session.get(WorkspaceBudget, "global")
            assert budget.reserved_bytes == 44 and budget.object_count == 2
    finally:
        await finish(parts, journal)
