"""Real descriptor-relative ordinary files; no Native/Human/runtime qualification."""

import asyncio
import hashlib
import threading
import tracemalloc
from dataclasses import replace
from uuid import uuid4

import pytest

from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.storage.workspace_files import (
    CHUNK,
    WorkspaceFileError,
    WorkspaceFiles,
    WorkspaceInput,
    WorkspaceNamespace,
)


def uid():
    return str(uuid4())


@pytest.fixture
def store(tmp_path):
    root = tmp_path.resolve() / "namespace"
    root.mkdir()
    root.chmod(0o2750)
    s = root.stat()
    value = WorkspaceFiles(
        WorkspaceNamespace(root, s.st_dev, s.st_ino, s.st_uid, s.st_gid), reserve_free_bytes=0
    )
    yield value
    value.close()


def entry(data=b"original\x00\xffbytes", *, name="AGENTS.md", identity=None):
    async def chunks():
        for n in range(0, len(data), CHUNK):
            yield data[n : n + CHUNK]

    return WorkspaceInput(
        identity or uid(),
        NativeAttachmentProjection(
            filename=name,
            mime_type="application/octet-stream",
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        ),
        chunks(),
    )


@pytest.mark.parametrize("data", [b"", b"binary\x00\xff", "繁體中文\r\n".encode()])
async def test_exact_bytes_original_name_only_metadata_and_native_group_read_mode(store, data):
    action, source = uid(), entry(data)
    (saved,) = await store.stage(action, (source,))
    path = store.namespace.path / saved.storage_name
    assert path.read_bytes() == data and saved.original.filename == "AGENTS.md"
    assert path.name == action + "_" + source.artifact_id
    assert path.stat().st_mode & 0o777 == 0o640
    assert path.stat().st_gid == store.namespace.reader_gid
    assert not (store.namespace.path / "AGENTS.md").exists()
    assert store.current(saved)


async def test_ten_files_each_twenty_mib_stream_without_collecting_two_hundred_mib(store):
    chunk = b"x" * CHUNK
    checksum = hashlib.sha256()
    for _ in range(MAX_ATTACHMENT_BYTES // CHUNK):
        checksum.update(chunk)

    async def chunks():
        for _ in range(MAX_ATTACHMENT_BYTES // CHUNK):
            yield chunk

    files = tuple(
        WorkspaceInput(
            uid(),
            NativeAttachmentProjection(
                filename=f"file-{n}.bin",
                mime_type="application/octet-stream",
                size=MAX_ATTACHMENT_BYTES,
                sha256=checksum.hexdigest(),
            ),
            chunks(),
        )
        for n in range(10)
    )
    tracemalloc.start()
    try:
        saved = await store.stage(uid(), files)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(saved) == 10 and sum(s.original.size for s in saved) == 200 * 1024**2
    assert peak < 10 * 1024**2
    assert all(store.current(s) for s in saved)


async def test_idempotent_reentry_rechecks_file_bytes_without_overwriting_or_reading_new_stream(
    store,
):
    action, source = uid(), entry()
    saved = await store.stage(action, (source,))

    async def forbidden():
        raise AssertionError("completed original bytes must be reused")
        yield b""

    assert await store.stage(action, (replace(source, chunks=forbidden()),)) == saved
    path = store.namespace.path / saved[0].storage_name
    path.write_bytes(b"changed")
    with pytest.raises(WorkspaceFileError):
        await store.stage(action, (replace(source, chunks=forbidden()),))
    assert path.read_bytes() == b"changed" and not store.current(saved[0])


@pytest.mark.parametrize(
    "change", ["overrun", "short", "checksum", "nonbytes", "huge-chunk", "empty-chunk"]
)
async def test_bad_stream_never_publishes_ready_file_and_cleans_only_own_partial(store, change):
    source = entry(b"xx")

    async def chunks():
        if change == "overrun":
            yield b"xxx"
        elif change == "short":
            yield b"x"
        elif change == "checksum":
            yield b"zz"
        elif change == "nonbytes":
            yield bytearray(b"xx")
        elif change == "huge-chunk":
            yield b"x" * (CHUNK + 1)
        else:
            yield b""

    with pytest.raises((WorkspaceFileError, ValueError)):
        await store.stage(uid(), (replace(source, chunks=chunks()),))
    assert not list(store.namespace.path.iterdir())


@pytest.mark.parametrize("change", ["eleven", "duplicate", "oversize", "noncanonical"])
async def test_invalid_batch_is_rejected_before_any_directory_write(store, change):
    one = entry()
    if change == "eleven":
        items = tuple(entry() for _ in range(11))
    elif change == "duplicate":
        items = (one, one)
    elif change == "oversize":
        items = (
            replace(
                one, projection=one.projection.model_copy(update={"size": MAX_ATTACHMENT_BYTES + 1})
            ),
        )
    else:
        items = (replace(one, artifact_id="../untrusted"),)
    with pytest.raises(ValueError):
        await store.stage(uid(), items)
    assert not list(store.namespace.path.iterdir())


async def test_root_replacement_during_stream_cannot_write_into_replacement(store):
    original = store.namespace.path
    moved = original.with_name("old")
    source = entry(b"x")

    async def chunks():
        original.rename(moved)
        original.mkdir()
        original.chmod(0o2750)
        yield b"x"

    with pytest.raises(WorkspaceFileError):
        await store.stage(uid(), (replace(source, chunks=chunks()),))
    assert not list(original.iterdir()) and not list(moved.iterdir())


async def test_existing_symlink_cannot_overwrite_outside_file(store, tmp_path):
    action, source = uid(), entry()
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    (store.namespace.path / (action + "_" + source.artifact_id)).symlink_to(outside)
    with pytest.raises(OSError):
        await store.stage(action, (source,))
    assert outside.read_bytes() == b"untouched"


async def test_cancellation_joins_inflight_thread_before_fd_cleanup_or_close(store, monkeypatch):
    entered, finish = threading.Event(), threading.Event()
    original = store.write_chunk

    def slow(fd, data):
        entered.set()
        assert finish.wait(5)
        original(fd, data)

    monkeypatch.setattr(store, "write_chunk", slow)
    task = asyncio.create_task(store.stage(uid(), (entry(b"x"),)))
    assert await asyncio.to_thread(entered.wait, 3)
    task.cancel()
    await asyncio.sleep(0.01)
    task.cancel()
    await asyncio.sleep(0.01)
    try:
        assert not task.done()
        with pytest.raises(WorkspaceFileError, match="finish_before_close"):
            store.close()
    finally:
        finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not list(store.namespace.path.iterdir())


async def test_unknown_partial_requires_review_and_is_not_removed(store):
    action, source = uid(), entry()
    path = store.namespace.path / ("." + action + "_" + source.artifact_id + ".part")
    path.write_bytes(b"prior crash evidence")
    with pytest.raises(FileExistsError):
        await store.stage(action, (source,))
    assert path.read_bytes() == b"prior crash evidence"


async def test_reserve_failure_does_not_create_partial(store, monkeypatch):
    def no_space(_):
        raise WorkspaceFileError("workspace_free_space_reserve")

    monkeypatch.setattr(store, "space", no_space)
    with pytest.raises(WorkspaceFileError):
        await store.stage(uid(), (entry(),))
    assert not list(store.namespace.path.iterdir())


def test_namespace_pin_and_symlink_ancestry_are_required(tmp_path):
    root = tmp_path.resolve() / "actual"
    root.mkdir()
    root.chmod(0o2750)
    s = root.stat()
    alias = root.with_name("alias")
    alias.symlink_to(root, target_is_directory=True)
    for path, inode in ((alias, s.st_ino), (root, s.st_ino + 1)):
        with pytest.raises(WorkspaceFileError):
            WorkspaceFiles(
                WorkspaceNamespace(path, s.st_dev, inode, s.st_uid, s.st_gid), reserve_free_bytes=0
            )


async def test_partial_path_swap_is_not_followed_or_deleted_as_our_file(store, tmp_path):
    action, source = uid(), entry(b"x")
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    part = store.namespace.path / ("." + action + "_" + source.artifact_id + ".part")

    async def chunks():
        part.unlink()
        part.symlink_to(outside)
        yield b"x"

    with pytest.raises(WorkspaceFileError):
        await store.stage(action, (replace(source, chunks=chunks()),))
    assert outside.read_bytes() == b"untouched" and part.is_symlink()
    assert not (store.namespace.path / (action + "_" + source.artifact_id)).exists()


async def test_completed_earlier_file_survives_later_stream_failure_for_exact_recovery(store):
    action, first = uid(), entry(b"one")
    second = entry(b"two")

    async def fail():
        yield b"bad"

    with pytest.raises(WorkspaceFileError):
        await store.stage(action, (first, replace(second, chunks=fail())))
    first_path = store.namespace.path / (action + "_" + first.artifact_id)
    assert first_path.read_bytes() == b"one"
    recovered = await store.stage(action, (replace(first, chunks=fail()), second))
    assert len(recovered) == 2 and all(store.current(f) for f in recovered)


async def test_existing_hardlink_is_not_accepted_as_a_staged_file(store, tmp_path):
    from jt_oz_bridge.storage import workspace_files as module

    action, source = uid(), entry()
    outside = tmp_path / "outside"
    outside.write_bytes(b"original\x00\xffbytes")
    outside.chmod(0o640)
    path = store.namespace.path / (action + "_" + source.artifact_id)
    module.os.link(outside, path)
    with pytest.raises(WorkspaceFileError):
        await store.stage(action, (source,))
    assert outside.read_bytes() == b"original\x00\xffbytes" and outside.stat().st_nlink == 2


async def test_publication_race_never_overwrites_or_removes_an_existing_destination(
    store, monkeypatch
):
    from jt_oz_bridge.storage import workspace_files as module

    action, source = uid(), entry()
    path = store.namespace.path / (action + "_" + source.artifact_id)
    original = module.os.link

    def race(*args, **kwargs):
        path.write_bytes(b"another existing file")
        return original(*args, **kwargs)

    monkeypatch.setattr(module.os, "link", race)
    with pytest.raises(FileExistsError):
        await store.stage(action, (source,))
    assert path.read_bytes() == b"another existing file"
    assert {p.name for p in store.namespace.path.iterdir()} == {path.name}
