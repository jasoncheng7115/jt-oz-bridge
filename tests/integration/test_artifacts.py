import asyncio
import hashlib
import os
import time

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.orm import Session

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.artifacts import ArtifactService, ArtifactUnavailable, FileDescriptor
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.artifact_models import Artifact, ArtifactBudget
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Action, Grant
from tests.support import bound


async def chunks(value):
    for offset in range(0, len(value), 3):
        yield value[offset : offset + 3]


async def service(db, tmp_path, **limits):
    bindings, binding, _, audience = await bound(db)
    files = LocalArtifactFiles(tmp_path / "private-artifacts")
    cipher = EnvelopeCipher({"v1": os.urandom(32)}, "v1")
    store = ArtifactService(
        bindings, files, cipher, maximum_file_bytes=1024, reserve_free_bytes=0, **limits
    )
    return store, binding, audience


async def test_artifact_preserves_bytes_filename_mime_hash_and_encrypts_disk_and_metadata(
    db, tmp_path
):
    store, binding, _ = await service(db, tmp_path)
    content = b"PRIVATE-MARKER original exact output\r\n" * 5
    descriptor = FileDescriptor(filename="PRIVATE-MARKER-原始.txt", mime_type="text/plain")
    try:
        identity = await store.create(
            binding.id,
            "realm",
            7,
            descriptor,
            chunks(content),
            expected_size=len(content),
            expected_sha256=hashlib.sha256(content).hexdigest(),
        )
        restored = await store.read(identity, "realm", 8)
        assert restored.descriptor == descriptor and restored.content == content
        assert restored.sha256 == hashlib.sha256(content).hexdigest()
        blobs = list((tmp_path / "private-artifacts").iterdir())
        assert len(blobs) == 1 and blobs[0].suffix == ".bin"
        assert b"PRIVATE-MARKER" not in blobs[0].read_bytes()
        assert blobs[0].stat().st_mode & 0o077 == 0
        async with db.sessions() as session:
            saved = await session.get(Artifact, identity)
            budget = await session.get(ArtifactBudget, "global")
            assert saved.state == "ready" and saved.size_bytes == len(content)
            assert budget.object_count == 1 and budget.reserved_bytes == blobs[0].stat().st_size
        database_file = tmp_path / "test.db"
        assert b"PRIVATE-MARKER" not in database_file.read_bytes()
    finally:
        store.files.close()


@pytest.mark.parametrize("kind", ["wrong-size", "wrong-hash", "too-big", "stream-error"])
async def test_failed_import_does_not_publish_partial_plaintext_or_leak_quota(db, tmp_path, kind):
    store, binding, _ = await service(db, tmp_path)
    options = {}
    value = b"small content"
    if kind == "wrong-size":
        options["expected_size"] = 1
    if kind == "wrong-hash":
        options["expected_sha256"] = "0" * 64
    if kind == "too-big":
        value = b"x" * 1025

    async def source():
        yield value
        if kind == "stream-error":
            raise RuntimeError("PRIVATE-MARKER")

    try:
        with pytest.raises(ArtifactUnavailable) as error:
            await store.create(
                binding.id,
                "realm",
                7,
                FileDescriptor(filename="file.txt", mime_type="text/plain"),
                source(),
                **options,
            )
        assert "PRIVATE-MARKER" not in str(error.value)
        assert not list((tmp_path / "private-artifacts").iterdir())
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).reserved_bytes == 0
            assert (await session.get(ArtifactBudget, "global")).object_count == 0
            assert (await session.scalars(select(Artifact))).one().state == "failed"
    finally:
        store.files.close()


async def test_active_upload_reservation_prevents_concurrent_quota_oversubscription(db, tmp_path):
    store, binding, _ = await service(db, tmp_path, quota_bytes=6000)
    entered = asyncio.Event()

    async def waiting():
        entered.set()
        await asyncio.Event().wait()
        yield b"unreachable"

    first = asyncio.create_task(
        store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="one", mime_type="text/plain"),
            waiting(),
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        with pytest.raises(ArtifactUnavailable, match="quota"):
            await store.create(
                binding.id,
                "realm",
                7,
                FileDescriptor(filename="two", mime_type="text/plain"),
                chunks(b"small"),
            )
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        async with db.sessions() as session:
            budget = await session.get(ArtifactBudget, "global")
            assert budget.object_count == 0 and budget.reserved_bytes == 0
    finally:
        if not first.done():
            first.cancel()
        store.files.close()


async def test_revoked_viewer_changed_binding_or_broader_audience_cannot_read(db, tmp_path):
    store, binding, audience = await service(db, tmp_path)
    try:
        identity = await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="full.txt", mime_type="text/plain"),
            chunks(b"private"),
        )
        with pytest.raises(AccessDenied):
            await store.read(identity, "another-realm", 8)
        audience.users = frozenset({7, 8, 99})
        with pytest.raises((AccessDenied, ValueError)):
            await store.read(identity, "realm", 8)
        audience.users = frozenset({7, 8})
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        with pytest.raises(AccessDenied):
            await store.read(identity, "realm", 8)
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 8).values(active=True))
            await session.execute(update(Binding).values(revision=2))
        with pytest.raises(AccessDenied):
            await store.read(identity, "realm", 8)
    finally:
        store.files.close()


async def test_ciphertext_or_descriptor_metadata_tamper_quarantines_instead_of_serving(
    db, tmp_path
):
    store, binding, _ = await service(db, tmp_path)
    try:
        identity = await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="full.txt", mime_type="text/plain"),
            chunks(b"private"),
        )
        path = tmp_path / "private-artifacts" / (identity + ".bin")
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with pytest.raises(ArtifactUnavailable):
            await store.read(identity, "realm", 7)
        async with db.sessions() as session:
            assert (await session.get(Artifact, identity)).state == "quarantined"
            assert (await session.get(ArtifactBudget, "global")).object_count == 1
    finally:
        store.files.close()


@pytest.mark.parametrize(
    "filename",
    ["../escape", "/etc/passwd", "a\\b", "..", ".", "header\r\ninjection", "null\x00byte"],
)
def test_untrusted_filenames_cannot_become_filesystem_or_header_paths(filename):
    with pytest.raises(ValueError):
        FileDescriptor(filename=filename, mime_type="text/plain")


def test_metadata_validation_exception_does_not_echo_private_filename():
    with pytest.raises(ValueError) as error:
        FileDescriptor(filename="/PRIVATE-MARKER", mime_type="text/plain")
    assert "PRIVATE-MARKER" not in str(error.value)


async def test_expiration_cleanup_requires_fencing_and_releases_bytes_exactly_once(db, tmp_path):
    store, binding, _ = await service(db, tmp_path)
    try:
        identity = await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="file", mime_type="text/plain"),
            chunks(b"temporary"),
        )
        async with db.sessions.begin() as session:
            await session.execute(update(Artifact).values(expires_at=time.time() - 1))
        with pytest.raises(ArtifactUnavailable, match="expired"):
            await store.read(identity, "realm", 7)
        assert await store.prune_expired("unknown", 1) == 0
        fence = await DurableStore(db).acquire_lease("retention-test")
        assert await store.prune_expired("retention-test", fence) == 1
        assert await store.prune_expired("retention-test", fence) == 0
        async with db.sessions() as session:
            assert (await session.get(Artifact, identity)).state == "deleted"
            budget = await session.get(ArtifactBudget, "global")
            assert budget.reserved_bytes == 0 and budget.object_count == 0
        assert not list((tmp_path / "private-artifacts").iterdir())
    finally:
        store.files.close()


async def test_pins_and_unresolved_action_evidence_survive_normal_ttl(db, tmp_path):
    store, binding, _ = await service(db, tmp_path)
    try:
        async with db.sessions.begin() as session:
            action = Action(
                dedupe_key="artifact-action",
                binding_id=binding.id,
                binding_revision=1,
                actor_id=7,
                payload={},
                operation_digest="a" * 64,
                state="ambiguous",
            )
            session.add(action)
            await session.flush()
        pinned = await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="pinned", mime_type="text/plain"),
            chunks(b"pinned"),
        )
        pending = await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="pending", mime_type="text/plain"),
            chunks(b"pending"),
            action_id=action.id,
        )
        async with db.sessions() as session:
            version = (await session.get(Artifact, pinned)).version
        await store.pin(pinned, "realm", 7, version, True)
        async with db.sessions.begin() as session:
            await session.execute(update(Artifact).values(expires_at=time.time() - 1))
        fence = await DurableStore(db).acquire_lease("retention-test")
        assert await store.prune_expired("retention-test", fence) == 0
        assert (await store.read(pinned, "realm", 7)).content == b"pinned"
        assert (await store.read(pending, "realm", 7)).content == b"pending"
        async with db.sessions.begin() as session:
            await session.execute(
                update(Action).where(Action.id == action.id).values(state="completed")
            )
        assert await store.prune_expired("retention-test", fence) == 1
        assert (await store.read(pinned, "realm", 7)).content == b"pinned"
    finally:
        store.files.close()


async def test_incomplete_import_is_quarantined_on_fenced_startup_and_not_ttl_pruned(db, tmp_path):
    store, binding, _ = await service(db, tmp_path)
    entered = asyncio.Event()

    async def source():
        entered.set()
        await asyncio.Event().wait()
        yield b"never complete"

    task = asyncio.create_task(
        store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="partial", mime_type="text/plain"),
            source(),
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        fence = await DurableStore(db).acquire_lease("startup-test")
        assert await store.recover_incomplete("startup-test", fence, before=0) == 0
        assert await store.recover_incomplete("startup-test", fence, before=time.time() + 1) == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with db.sessions.begin() as session:
            await session.execute(update(Artifact).values(expires_at=time.time() - 1))
        assert await store.prune_expired("startup-test", fence) == 0
        async with db.sessions() as session:
            assert (await session.scalars(select(Artifact))).one().state == "quarantined"
            assert (await session.get(ArtifactBudget, "global")).reserved_bytes > 0
    finally:
        if not task.done():
            task.cancel()
        store.files.close()


async def test_failed_final_commit_after_encrypted_file_write_never_marks_it_ready(db, tmp_path):
    store, binding, _ = await service(db, tmp_path)
    original = store.files.write

    def fail(_):
        raise RuntimeError("PRIVATE-MARKER injected commit failure")

    def write(identity, data):
        original(identity, data)
        event.listen(Session, "before_commit", fail, once=True)

    store.files.write = write
    try:
        with pytest.raises(ArtifactUnavailable) as error:
            await store.create(
                binding.id,
                "realm",
                7,
                FileDescriptor(filename="full", mime_type="text/plain"),
                chunks(b"private"),
            )
        assert "PRIVATE-MARKER" not in str(error.value)
        async with db.sessions() as session:
            assert (await session.scalars(select(Artifact))).one().state == "failed"
            assert (await session.get(ArtifactBudget, "global")).reserved_bytes == 0
        assert not list((tmp_path / "private-artifacts").iterdir())
    finally:
        if event.contains(Session, "before_commit", fail):
            event.remove(Session, "before_commit", fail)
        store.files.close()


async def test_revocation_during_inbound_stream_aborts_before_publication(db, tmp_path):
    store, binding, _ = await service(db, tmp_path)

    async def source():
        yield b"private"
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))

    try:
        with pytest.raises(AccessDenied):
            await store.create(
                binding.id,
                "realm",
                7,
                FileDescriptor(filename="full", mime_type="text/plain"),
                source(),
            )
        assert not list((tmp_path / "private-artifacts").iterdir())
        async with db.sessions() as session:
            assert (await session.get(ArtifactBudget, "global")).object_count == 0
    finally:
        store.files.close()
