"""Private descriptor-relative artifact files; filenames are never caller paths."""

import os
import stat
import uuid
from pathlib import Path


class ArtifactFileError(ValueError):
    pass


def artifact_name(identity: str) -> str:
    try:
        if str(uuid.UUID(identity)) != identity:
            raise ValueError("non-canonical identity")
        return identity
    except (ValueError, AttributeError):
        raise ArtifactFileError("invalid_artifact_identity") from None


class LocalArtifactFiles:
    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ArtifactFileError("artifact_root_must_be_absolute")
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self._fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                os.close(self._fd)
                raise ArtifactFileError("artifact_root_must_be_private_and_owned")
        except OSError:
            raise ArtifactFileError("artifact_root_unavailable") from None

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def free_bytes(self) -> int:
        info = os.fstatvfs(self._fd)
        return info.f_bavail * info.f_frsize

    def write(self, identity: str, encrypted: bytes) -> None:
        name = artifact_name(identity)
        created = linked = False
        try:
            fd = os.open(
                name + ".part",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._fd,
            )
            created = True
            with os.fdopen(fd, "wb") as target:
                target.write(encrypted)
                target.flush()
                os.fsync(target.fileno())
            # link is atomic and refuses an existing destination; rename can overwrite.
            os.link(
                name + ".part",
                name + ".bin",
                src_dir_fd=self._fd,
                dst_dir_fd=self._fd,
                follow_symlinks=False,
            )
            linked = True
            os.unlink(name + ".part", dir_fd=self._fd)
            created = False
            os.fsync(self._fd)
        except OSError:
            if created:
                try:
                    self._unlink(name + ".part")
                except OSError:
                    pass
            if linked:
                try:
                    self._unlink(name + ".bin")
                except OSError:
                    pass
            raise ArtifactFileError("artifact_write_failed") from None

    def read(self, identity: str, maximum: int) -> bytes:
        name = artifact_name(identity)
        try:
            fd = os.open(
                name + ".bin", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd
            )
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_nlink != 1
                    or info.st_size > maximum
                ):
                    raise ArtifactFileError("artifact_file_properties_rejected")
                value = source.read(maximum + 1)
                if len(value) > maximum or len(value) != info.st_size:
                    raise ArtifactFileError("artifact_file_size_changed")
                return value
        except OSError:
            raise ArtifactFileError("artifact_read_failed") from None

    def _unlink(self, name: str) -> None:
        try:
            os.unlink(name, dir_fd=self._fd)
        except FileNotFoundError:
            pass

    def remove(self, identity: str) -> None:
        name = artifact_name(identity)
        try:
            self._unlink(name + ".bin")
            self._unlink(name + ".part")
            os.fsync(self._fd)
        except OSError:
            raise ArtifactFileError("artifact_remove_failed") from None
