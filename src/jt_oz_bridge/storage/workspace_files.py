"""Explicitly pinned ordinary workspace files; not an authorization provider.

The runtime must separately qualify the original Native host/path and authorize
source/action/binding, reserve quota, journal progress and manage retention.
Original upload names never become filesystem paths. No worker is enabled here.
"""

import asyncio
import hashlib
import os
import stat
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    NativeAttachmentProjection,
)
from jt_oz_bridge.storage.artifact_files import artifact_name

CHUNK = 65536


class WorkspaceFileError(ValueError):
    pass


@dataclass(frozen=True)
class WorkspaceNamespace:
    path: Path
    device: int
    inode: int
    owner_uid: int
    reader_gid: int


@dataclass(frozen=True)
class WorkspaceInput:
    artifact_id: str
    projection: NativeAttachmentProjection
    chunks: AsyncIterator[bytes]


@dataclass(frozen=True)
class WorkspacePartial:
    action_id: str
    artifact_id: str
    device: int
    inode: int


@dataclass(frozen=True)
class WorkspaceFile:
    action_id: str
    artifact_id: str
    storage_name: str
    original: NativeAttachmentProjection
    # This metadata is not a Human/Native authority certificate.
    identity: tuple[int, int, int, int, int]


def open_directory(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise WorkspaceFileError("workspace_absolute_canonical_namespace_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


async def joined_io[T](operation: Callable[[], T]) -> T:
    """Never close/reuse an FD while its cancelled caller's thread still writes."""
    task = asyncio.create_task(asyncio.to_thread(operation))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if task.done() and not task.cancelled():
            try:
                task.result()
            except Exception:
                pass
        raise


class WorkspaceFiles:
    def __init__(self, namespace: WorkspaceNamespace, *, reserve_free_bytes: int) -> None:
        if (
            type(reserve_free_bytes) is not int
            or reserve_free_bytes < 0
            or any(
                type(n) is not int or n < 0
                for n in (
                    namespace.device,
                    namespace.inode,
                    namespace.owner_uid,
                    namespace.reader_gid,
                )
            )
            or namespace.owner_uid != os.geteuid()
        ):
            raise WorkspaceFileError("workspace_explicit_owner_and_reserve_required")
        self.namespace, self.reserve = namespace, reserve_free_bytes
        self._fd = -1
        self._lock = asyncio.Lock()
        try:
            self._fd = open_directory(namespace.path)
            self.check()
        except (OSError, WorkspaceFileError):
            self.close()
            raise WorkspaceFileError("workspace_namespace_pin_rejected") from None

    def check(self) -> None:
        if self._fd < 0:
            raise WorkspaceFileError("workspace_namespace_closed")
        s = os.fstat(self._fd)
        pin = self.namespace
        if (s.st_dev, s.st_ino, s.st_uid, s.st_gid) != (
            pin.device,
            pin.inode,
            pin.owner_uid,
            pin.reader_gid,
        ) or stat.S_IMODE(s.st_mode) != 0o2750:
            raise WorkspaceFileError("workspace_namespace_identity_or_mode_changed")
        fd = open_directory(pin.path)
        try:
            now = os.fstat(fd)
            if (now.st_dev, now.st_ino) != (s.st_dev, s.st_ino):
                raise WorkspaceFileError("workspace_namespace_name_changed")
        finally:
            os.close(fd)

    def close(self) -> None:
        if self._lock.locked():
            raise WorkspaceFileError("workspace_stage_must_finish_before_close")
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def space(self, remaining: int) -> None:
        s = os.fstatvfs(self._fd)
        if s.f_bavail * s.f_frsize < self.reserve + remaining:
            raise WorkspaceFileError("workspace_free_space_reserve")

    @staticmethod
    def identity(s: os.stat_result) -> tuple[int, int, int, int, int]:
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns

    def file(self, action_id: str, entry: WorkspaceInput) -> WorkspaceFile:
        name = artifact_name(action_id) + "_" + artifact_name(entry.artifact_id)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd)
        try:
            s = os.fstat(fd)
            if (
                not stat.S_ISREG(s.st_mode)
                or (s.st_uid, s.st_gid) != (self.namespace.owner_uid, self.namespace.reader_gid)
                or stat.S_IMODE(s.st_mode) != 0o640
                or s.st_nlink != 1
                or s.st_size != entry.projection.size
            ):
                raise WorkspaceFileError("workspace_file_properties_changed")
            checksum = hashlib.sha256()
            total = 0
            while chunk := os.read(fd, CHUNK):
                total += len(chunk)
                if total > entry.projection.size:
                    raise WorkspaceFileError("workspace_file_size_changed")
                checksum.update(chunk)
            if (
                total != entry.projection.size
                or checksum.hexdigest() != entry.projection.sha256
                or self.identity(os.fstat(fd)) != self.identity(s)
            ):
                raise WorkspaceFileError("workspace_file_bytes_changed")
            return WorkspaceFile(
                action_id, entry.artifact_id, name, entry.projection, self.identity(s)
            )
        finally:
            os.close(fd)

    def current(self, saved: WorkspaceFile) -> bool:
        try:
            self.check()
            entry = WorkspaceInput(saved.artifact_id, saved.original, empty())
            now = self.file(saved.action_id, entry)
            return now == saved
        except (OSError, ValueError):
            return False

    def unchanged(self, saved: WorkspaceFile) -> bool:
        """Cheap identity check after trusted byte verification, not authority."""
        try:
            self.check()
            name = artifact_name(saved.action_id) + "_" + artifact_name(saved.artifact_id)
            if name != saved.storage_name:
                return False
            now = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            return bool(
                stat.S_ISREG(now.st_mode)
                and self.identity(now) == saved.identity
                and (now.st_uid, now.st_gid)
                == (self.namespace.owner_uid, self.namespace.reader_gid)
                and stat.S_IMODE(now.st_mode) == 0o640
                and now.st_nlink == 1
            )
        except (OSError, ValueError):
            return False

    async def remove(self, saved: WorkspaceFile) -> None:
        """Delete only this published identity; a changed/missing file is retained."""
        async with self._lock:
            await joined_io(partial(self._remove, saved))

    def _remove(self, saved: WorkspaceFile) -> None:
        if not self.current(saved) or not self.unchanged(saved):
            raise WorkspaceFileError("workspace_cleanup_identity_or_bytes_changed")
        os.unlink(saved.storage_name, dir_fd=self._fd)
        os.fsync(self._fd)

    def absent(self, saved: WorkspaceFile) -> bool:
        """Recovery only: both exact names absent in the still-pinned namespace."""
        self.check()
        name = artifact_name(saved.action_id) + "_" + artifact_name(saved.artifact_id)
        if saved.storage_name != name:
            return False
        for candidate in (name, "." + name + ".part"):
            try:
                os.stat(candidate, dir_fd=self._fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            return False
        return True

    async def recover_partial(self, saved: WorkspacePartial, maximum_bytes: int) -> None:
        async with self._lock:
            await joined_io(partial(self._recover_partial, saved, maximum_bytes))

    def _recover_partial(self, saved: WorkspacePartial, maximum_bytes: int) -> None:
        self.check()
        if type(maximum_bytes) is not int or not 0 <= maximum_bytes <= MAX_ATTACHMENT_BYTES:
            raise WorkspaceFileError("workspace_partial_recovery_bound_required")
        name = artifact_name(saved.action_id) + "_" + artifact_name(saved.artifact_id)
        part = "." + name + ".part"
        try:
            now = os.stat(part, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(now.st_mode)
            or (now.st_dev, now.st_ino) != (saved.device, saved.inode)
            or (now.st_uid, now.st_gid) != (self.namespace.owner_uid, self.namespace.reader_gid)
            or stat.S_IMODE(now.st_mode) not in {0o600, 0o640}
            or now.st_size > maximum_bytes
            or now.st_nlink not in {1, 2}
        ):
            raise WorkspaceFileError("workspace_registered_partial_identity_changed")
        if now.st_nlink == 2:
            ready = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            if (ready.st_dev, ready.st_ino) != (now.st_dev, now.st_ino):
                raise WorkspaceFileError("workspace_partial_publication_link_changed")
        os.unlink(part, dir_fd=self._fd)
        os.fsync(self._fd)

    def write_chunk(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise WorkspaceFileError("workspace_write_not_advancing")
            view = view[written:]

    async def stage(
        self,
        action_id: str,
        entries: tuple[WorkspaceInput, ...],
        *,
        on_partial: Callable[[WorkspacePartial], Awaitable[None]] | None = None,
    ) -> tuple[WorkspaceFile, ...]:
        artifact_name(action_id)
        if (
            type(entries) is not tuple
            or not 1 <= len(entries) <= MAX_ATTACHMENTS
            or len({e.artifact_id for e in entries}) != len(entries)
        ):
            raise WorkspaceFileError("workspace_unique_bounded_batch_required")
        for entry in entries:
            artifact_name(entry.artifact_id)
            NativeAttachmentProjection.model_validate(entry.projection.model_dump(mode="json"))
        if sum(e.projection.size for e in entries) > MAX_ATTACHMENTS * MAX_ATTACHMENT_BYTES:
            raise WorkspaceFileError("workspace_batch_capacity")
        async with self._lock:
            saved = []
            for entry in entries:
                self.check()
                try:
                    prior = await joined_io(partial(self.file, action_id, entry))
                except FileNotFoundError:
                    prior = None
                if prior is not None:
                    saved.append(prior)
                    continue
                name = action_id + "_" + entry.artifact_id
                part = "." + name + ".part"
                self.space(entry.projection.size)
                fd = os.open(
                    part,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self._fd,
                )
                original = os.fstat(fd)
                total, checksum = 0, hashlib.sha256()
                try:
                    if on_partial is not None:
                        await on_partial(
                            WorkspacePartial(
                                action_id, entry.artifact_id, original.st_dev, original.st_ino
                            )
                        )
                    async for data in entry.chunks:
                        if type(data) is not bytes or not 0 < len(data) <= CHUNK:
                            raise WorkspaceFileError("workspace_bounded_byte_chunks_required")
                        if total + len(data) > entry.projection.size:
                            raise WorkspaceFileError("workspace_stream_exceeds_declared_size")
                        self.check()
                        self.space(entry.projection.size - total)
                        await joined_io(partial(self.write_chunk, fd, data))
                        checksum.update(data)
                        total += len(data)
                    if (
                        total != entry.projection.size
                        or checksum.hexdigest() != entry.projection.sha256
                    ):
                        raise WorkspaceFileError("workspace_stream_size_or_checksum_changed")
                    await joined_io(partial(os.fsync, fd))
                    self.check()
                    now = os.stat(part, dir_fd=self._fd, follow_symlinks=False)
                    if (now.st_dev, now.st_ino) != (
                        original.st_dev,
                        original.st_ino,
                    ) or now.st_nlink != 1:
                        raise WorkspaceFileError("workspace_partial_identity_changed")
                    os.fchmod(fd, 0o640)
                    os.link(
                        part, name, src_dir_fd=self._fd, dst_dir_fd=self._fd, follow_symlinks=False
                    )
                    os.unlink(part, dir_fd=self._fd)
                    await joined_io(partial(os.fsync, self._fd))
                finally:
                    os.close(fd)
                    try:
                        now = os.stat(part, dir_fd=self._fd, follow_symlinks=False)
                        if (now.st_dev, now.st_ino) == (original.st_dev, original.st_ino):
                            os.unlink(part, dir_fd=self._fd)
                    except FileNotFoundError:
                        pass
                saved.append(await joined_io(partial(self.file, action_id, entry)))
            self.check()
            return tuple(saved)


async def empty() -> AsyncIterator[bytes]:
    if False:
        yield b""
