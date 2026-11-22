"""Bounded private diagnostic snapshots; no transport, database or mutation proof."""

import ctypes
import hashlib
import math
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from jt_oz_bridge.domain.runtime_readiness import (
    MAX_ROOTS,
    ConsumerLeaseObservation,
    RuntimeModeSnapshot,
)
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.backup_files import BackupFileError, PrivateDirectory

FILENAME = "runtime-mode-snapshot.json"
BUFFER = ".runtime-mode-buffer.json"
MAX_BYTES = 512 * 1024
MAX_AGE = 5.0


class RuntimeStatusError(ValueError):
    """Fixed error codes only; callers render unavailable, never infer authority."""


@dataclass(frozen=True)
class _Stamp:
    dev: int
    ino: int
    size: int
    mtime: int
    ctime: int
    uid: int
    mode: int
    links: int

    @classmethod
    def of(cls, info: os.stat_result) -> "_Stamp":
        return cls(
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            info.st_uid,
            info.st_mode,
            info.st_nlink,
        )

    @property
    def identity(self) -> tuple[int, int]:
        return self.dev, self.ino


def _atomic_rename(fd: int, source: str, target: str, *, exchange: bool) -> None:
    """No overwrite on initial publication; exchange retains a raced replacement.

    Linux UAPI fs.h: NOREPLACE=1, EXCHANGE=2. Darwin sys/stdio.h: EXCL=4, SWAP=2.
    Unsupported platforms/filesystems fail closed, with no ordinary-rename fallback.
    """
    library = ctypes.CDLL(None, use_errno=True)
    try:
        if sys.platform == "darwin":
            rename = library.renameatx_np
            flags = 2 if exchange else 4
        elif sys.platform == "linux":
            rename = library.renameat2
            flags = 2 if exchange else 1
        else:
            raise RuntimeStatusError("runtime_status_atomic_rename_unavailable")
    except AttributeError:
        raise RuntimeStatusError("runtime_status_atomic_rename_unavailable") from None
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(fd, os.fsencode(source), fd, os.fsencode(target), flags) != 0:
        raise RuntimeStatusError("runtime_status_atomic_rename_failed")


def _now(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) is not float or not math.isfinite(value) or value < 0:
        raise RuntimeStatusError("runtime_status_clock_invalid")
    return value


def _fresh(snapshot: RuntimeModeSnapshot, now: float) -> None:
    if not snapshot.generated_at <= now < snapshot.generated_at + MAX_AGE:
        raise RuntimeStatusError("runtime_status_snapshot_not_current")


def _parse(raw: bytes) -> RuntimeModeSnapshot:
    try:
        return RuntimeModeSnapshot.model_validate(strict_loads(raw))
    except (ValueError, TypeError, RecursionError):
        raise RuntimeStatusError("runtime_status_invalid_snapshot") from None


class _PrivateStatus:
    def __init__(self, directory: Path, clock: Callable[[], float]) -> None:
        self.clock = clock
        try:
            self.directory = PrivateDirectory(directory)
        except (OSError, BackupFileError):
            raise RuntimeStatusError("runtime_status_private_directory_required") from None
        try:
            self._verify_directory()
        except (OSError, BackupFileError, RuntimeStatusError):
            self.directory.close()
            raise RuntimeStatusError("runtime_status_private_directory_required") from None

    def close(self) -> None:
        self.directory.close()

    def _verify_directory(self) -> None:
        self.directory.verify()
        info = os.fstat(self.directory.fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeStatusError("runtime_status_private_directory_required")

    def _identity(self, name: str) -> tuple[int, int] | None:
        try:
            info = os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
            return info.st_dev, info.st_ino
        except FileNotFoundError:
            return None

    def _raw(self, name: str) -> tuple[bytes, _Stamp]:
        self._verify_directory()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory.fd)
        try:
            before = _Stamp.of(os.fstat(fd))
            if (
                not stat.S_ISREG(before.mode)
                or before.uid != os.geteuid()
                or stat.S_IMODE(before.mode) != 0o600
                or before.links != 1
            ):
                raise RuntimeStatusError("runtime_status_private_regular_file_required")
            if before.size > MAX_BYTES:
                raise RuntimeStatusError("runtime_status_capacity")
            chunks, total = [], 0
            while part := os.read(fd, min(65536, MAX_BYTES + 1 - total)):
                total += len(part)
                if total > MAX_BYTES:
                    raise RuntimeStatusError("runtime_status_capacity")
                chunks.append(part)
            after = _Stamp.of(os.fstat(fd))
            entry = _Stamp.of(os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False))
            self._verify_directory()
            if before != after or after != entry or total != before.size:
                raise RuntimeStatusError("runtime_status_file_changed")
            return b"".join(chunks), after
        finally:
            os.close(fd)


class RuntimeStatusReader(_PrivateStatus):
    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.time) -> None:
        super().__init__(directory, clock)

    def read(self, lease: ConsumerLeaseObservation, *, bridge_healthy: bool) -> RuntimeModeSnapshot:
        try:
            if type(lease) is not ConsumerLeaseObservation:
                raise RuntimeStatusError("runtime_status_lease_invalid")
            checked = ConsumerLeaseObservation.model_validate(lease.model_dump(mode="json"))
            if type(bridge_healthy) is not bool or not bridge_healthy:
                raise RuntimeStatusError("runtime_status_bridge_unavailable")

            def current() -> float:
                now = _now(self.clock)
                if (
                    not checked.observed_at
                    <= now
                    < min(checked.observed_at + MAX_AGE, checked.expires_at)
                ):
                    raise RuntimeStatusError("runtime_status_lease_not_current")
                return now

            current()
            raw, stamp = self._raw(FILENAME)
            snapshot = _parse(raw)
            if snapshot.lease_fingerprint != checked.lease_fingerprint:
                raise RuntimeStatusError("runtime_status_lease_changed")
            _fresh(snapshot, current())
            self._verify_directory()
            if (
                _Stamp.of(os.stat(FILENAME, dir_fd=self.directory.fd, follow_symlinks=False))
                != stamp
            ):
                raise RuntimeStatusError("runtime_status_file_changed")
            _fresh(snapshot, current())
            return snapshot
        except RuntimeStatusError:
            raise
        except (OSError, BackupFileError, ValueError, TypeError):
            raise RuntimeStatusError("runtime_status_unavailable") from None


class RuntimeStatusWriter(_PrivateStatus):
    def __init__(
        self, directory: Path, lease_fingerprint: str, *, clock: Callable[[], float] = time.time
    ) -> None:
        if (
            not isinstance(lease_fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", lease_fingerprint) is None
        ):
            raise RuntimeStatusError("runtime_status_lease_invalid")
        super().__init__(directory, clock)
        self.lease_fingerprint = lease_fingerprint
        self._target: _Stamp | None = None
        self._target_digest: str | None = None
        self._buffer: _Stamp | None = None
        self._buffer_digest: str | None = None
        self._poisoned = False
        self._lock = threading.Lock()
        try:
            # Across restart only complete, bounded, private, self-consistent diagnostic
            # records are adopted. This is managed data recognition, not authenticity.
            for name in (FILENAME, BUFFER):
                if self._identity(name) is not None:
                    raw, stamp = self._raw(name)
                    _parse(raw)
                    digest = hashlib.sha256(raw).hexdigest()
                    if name == FILENAME:
                        self._target, self._target_digest = stamp, digest
                    else:
                        self._buffer, self._buffer_digest = stamp, digest
        except (OSError, BackupFileError, RuntimeStatusError):
            self.close()
            raise RuntimeStatusError("runtime_status_existing_file_untrusted") from None

    def _expected(self, name: str, stamp: _Stamp | None, digest: str | None) -> None:
        if stamp is None:
            if self._identity(name) is not None:
                raise RuntimeStatusError("runtime_status_file_changed")
        else:
            raw, current = self._raw(name)
            if current != stamp or hashlib.sha256(raw).hexdigest() != digest:
                raise RuntimeStatusError("runtime_status_file_changed")

    def publish(self, snapshot: RuntimeModeSnapshot) -> None:
        """Publish with at most two fixed slots and no pathname unlink cleanup.

        Partial/unknown buffers are preserved and invalidate this writer; a new writer
        refuses incomplete buffers until operator review. This does not sandbox a
        malicious same-UID process or privileged Native's in-place filesystem writes.
        """
        with self._lock:
            if self._poisoned:
                raise RuntimeStatusError("runtime_status_writer_invalidated")
            try:
                if (
                    type(snapshot) is not RuntimeModeSnapshot
                    or type(snapshot.roots) is not tuple
                    or len(snapshot.roots) > MAX_ROOTS
                ):
                    raise RuntimeStatusError("runtime_status_invalid_snapshot")
                checked = RuntimeModeSnapshot.model_validate(snapshot.model_dump(mode="json"))
                if checked.lease_fingerprint != self.lease_fingerprint:
                    raise RuntimeStatusError("runtime_status_lease_changed")
                _fresh(checked, _now(self.clock))
                raw = (checked.model_dump_json() + "\n").encode()
                if len(raw) > MAX_BYTES:
                    raise RuntimeStatusError("runtime_status_capacity")
                self._verify_directory()
                self._expected(FILENAME, self._target, self._target_digest)
                self._expected(BUFFER, self._buffer, self._buffer_digest)
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
                if self._buffer is None:
                    flags |= os.O_CREAT | os.O_EXCL
                fd = os.open(BUFFER, flags, 0o600, dir_fd=self.directory.fd)
                try:
                    opened = _Stamp.of(os.fstat(fd))
                    if self._buffer is not None and opened != self._buffer:
                        raise RuntimeStatusError("runtime_status_file_changed")
                    if (
                        not stat.S_ISREG(opened.mode)
                        or opened.uid != os.geteuid()
                        or stat.S_IMODE(opened.mode) != 0o600
                        or opened.links != 1
                        or self._identity(BUFFER) != opened.identity
                    ):
                        raise RuntimeStatusError("runtime_status_private_regular_file_required")
                    # No O_TRUNC: verify the actual non-followed descriptor and its
                    # known slot identity before changing this managed inode.
                    os.ftruncate(fd, 0)
                    position = 0
                    while position < len(raw):
                        count = os.write(fd, raw[position : position + 65536])
                        if count <= 0:
                            raise RuntimeStatusError("runtime_status_write_incomplete")
                        position += count
                        _fresh(checked, _now(self.clock))
                    os.fsync(fd)
                    written = _Stamp.of(os.fstat(fd))
                finally:
                    os.close(fd)
                candidate, stamp = self._raw(BUFFER)
                if stamp != written or candidate != raw:
                    raise RuntimeStatusError("runtime_status_file_changed")
                self._verify_directory()
                _fresh(checked, _now(self.clock))
                self._expected(FILENAME, self._target, self._target_digest)
                _atomic_rename(
                    self.directory.fd, BUFFER, FILENAME, exchange=self._target is not None
                )
                if self._target is not None:
                    previous, stamp = self._raw(BUFFER)
                    if (
                        stamp.identity != self._target.identity
                        or hashlib.sha256(previous).hexdigest() != self._target_digest
                    ):
                        raise RuntimeStatusError("runtime_status_file_changed")
                    self._buffer, self._buffer_digest = stamp, hashlib.sha256(previous).hexdigest()
                else:
                    self._buffer = self._buffer_digest = None
                os.fsync(self.directory.fd)
                published, stamp = self._raw(FILENAME)
                if stamp.identity != written.identity or published != raw:
                    raise RuntimeStatusError("runtime_status_file_changed")
                _fresh(checked, _now(self.clock))
                self._target, self._target_digest = stamp, hashlib.sha256(published).hexdigest()
            except (OSError, BackupFileError, ValueError, TypeError) as error:
                self._poisoned = True
                # No unlink or rollback: even a raced replacement is retained in one
                # of the two fixed slots. Reader independently rejects malformed/stale.
                if isinstance(error, RuntimeStatusError):
                    raise
                raise RuntimeStatusError("runtime_status_publication_failed") from None
