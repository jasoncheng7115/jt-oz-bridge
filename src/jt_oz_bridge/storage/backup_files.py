"""Descriptor-relative, owner-only backup files; no archives or caller filenames."""

import hashlib
import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TypedDict


class BackupFileError(ValueError):
    pass


class FileRecord(TypedDict):
    size: int
    sha256: str


def component(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise BackupFileError("backup_path_component_rejected")
    return value


def directory_fd(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise BackupFileError("absolute_backup_path_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            following = os.open(
                component(part), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def beneath(directory: "PrivateDirectory", destination_parent: Path) -> bool:
    """Compare directory identities too, including case-insensitive path aliases."""
    fd = directory_fd(destination_parent)
    try:
        while True:
            current = os.fstat(fd)
            identity = current.st_dev, current.st_ino
            if identity == directory.identity:
                return True
            parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            above = os.fstat(parent)
            os.close(fd)
            fd = parent
            if (above.st_dev, above.st_ino) == identity:
                return False
    finally:
        os.close(fd)


class PrivateDirectory:
    def __init__(self, path: Path, *, create: bool = False) -> None:
        self.path = path
        if create:
            parent = directory_fd(path.parent)
            try:
                os.mkdir(component(path.name), mode=0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        self.fd = directory_fd(path)
        info = os.fstat(self.fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            self.close()
            raise BackupFileError("backup_directory_must_be_private_and_owned")
        self.identity = info.st_dev, info.st_ino

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def verify(self) -> None:
        fd = directory_fd(self.path)
        try:
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) != self.identity:
                raise BackupFileError("backup_directory_changed")
        finally:
            os.close(fd)

    def names(self) -> set[str]:
        return set(os.listdir(self.fd))

    def open_file(self, name: str) -> int:
        fd = os.open(component(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            os.close(fd)
            raise BackupFileError("backup_regular_private_file_required")
        return fd

    def chunks(self, name: str, maximum: int, *, deadline: float | None = None) -> Iterator[bytes]:
        fd = self.open_file(name)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if before.st_size > maximum:
                raise BackupFileError("backup_file_limit_reached")
            count = 0
            while value := source.read(1024 * 1024):
                if deadline is not None and time.monotonic() >= deadline:
                    raise BackupFileError("backup_file_deadline_reached")
                count += len(value)
                if count > maximum:
                    raise BackupFileError("backup_file_limit_reached")
                yield value
            after = os.fstat(source.fileno())
            if count != before.st_size or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise BackupFileError("backup_file_changed_during_read")

    def read(self, name: str, maximum: int, *, deadline: float | None = None) -> bytes:
        return b"".join(self.chunks(name, maximum, deadline=deadline))

    def write(self, name: str, value: bytes) -> FileRecord:
        return self.copy(name, iter((value,)), len(value))

    def copy(self, name: str, chunks: Iterator[bytes], maximum: int) -> FileRecord:
        fd = os.open(
            component(name),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        checksum, count = hashlib.sha256(), 0
        with os.fdopen(fd, "wb") as output:
            for value in chunks:
                count += len(value)
                if count > maximum:
                    raise BackupFileError("backup_file_limit_reached")
                output.write(value)
                checksum.update(value)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(self.fd)
        return {"size": count, "sha256": checksum.hexdigest()}

    def record(self, name: str, maximum: int, *, deadline: float | None = None) -> FileRecord:
        checksum, count = hashlib.sha256(), 0
        for value in self.chunks(name, maximum, deadline=deadline):
            count += len(value)
            checksum.update(value)
        return {"size": count, "sha256": checksum.hexdigest()}

    def free_bytes(self) -> int:
        info = os.fstatvfs(self.fd)
        return info.f_bavail * info.f_frsize
