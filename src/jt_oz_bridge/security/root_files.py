"""Bounded immutable reads below a root-managed, non-writable ancestry."""

import hashlib
import os
import stat
from pathlib import Path


def root_bytes(path: Path, *, maximum: int = 8 * 1024 * 1024) -> bytes:
    if not path.is_absolute() or ".." in path.parts or not 1 <= maximum <= 16 * 1024 * 1024:
        raise ValueError("absolute_bounded_root_file_required")
    parents = []
    for directory in reversed(path.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("root_managed_file_ancestry_required")
        parents.append((directory, info.st_dev, info.st_ino, info.st_mode))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("root_managed_regular_file_required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise ValueError("root_managed_file_too_large")
        named = path.lstat()
        if (named.st_dev, named.st_ino, named.st_mode, named.st_uid) != (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
        ):
            raise ValueError("root_managed_file_changed")
        for directory, device, inode, mode in parents:
            current = directory.lstat()
            if (current.st_dev, current.st_ino, current.st_mode) != (device, inode, mode):
                raise ValueError("root_managed_file_parent_changed")
        return content
    finally:
        os.close(fd)


def pinned_root_bytes(path: Path, sha256: str) -> bytes:
    content = root_bytes(path)
    if hashlib.sha256(content).hexdigest() != sha256:
        raise ValueError("root_managed_file_digest_changed")
    return content
