"""Linux-only local owner proof via a root-created, fixed-operation Unix socket.

The server-side helper checks unit, executable, original dataset file metadata,
registration and authenticated native info. This evidence alone is not a session
snapshot or stream-continuity certificate; those remain separate requirements.
"""

import asyncio
import os
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.durable import digest


class HostOwnerError(ValueError):
    pass


def absolute(value: str) -> str:
    if not Path(value).is_absolute() or ".." in Path(value).parts or "\x00" in value:
        raise ValueError("absolute_enrolled_path_required")
    return value


def loopback_url(value: str) -> str:
    u = urlsplit(value)
    if (
        u.scheme != "http"
        or u.hostname != "127.0.0.1"
        or u.port is None
        or u.username is not None
        or u.password is not None
        or u.path
        or u.query
        or u.fragment
        or value != f"http://127.0.0.1:{u.port}"
    ):
        raise ValueError("fixed_loopback_api_required")
    return value


class HostOwnerEnrollment(ControlModel):
    backend_id: str = Field(min_length=1, max_length=255)
    backend_identity: str = Field(min_length=1, max_length=255)
    unit: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9@_.-]*\.service$")
    unit_path: str = Field(min_length=1, max_length=4096)
    unit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_uid: StrictInt = Field(gt=0)
    client_uid: StrictInt = Field(gt=0)
    version: str = Field(min_length=1, max_length=255)
    url: str
    executable_path: str = Field(min_length=1, max_length=4096)
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_path: str = Field(min_length=1, max_length=4096)
    dataset_device: StrictInt = Field(ge=0)
    dataset_inode: StrictInt = Field(gt=0)
    registration_path: str = Field(min_length=1, max_length=4096)

    @field_validator("unit_path", "executable_path", "dataset_path", "registration_path")
    @classmethod
    def enrolled_absolute_path(cls, value: str) -> str:
        return absolute(value)

    @field_validator("url")
    @classmethod
    def private_api(cls, value: str) -> str:
        return loopback_url(value)


class HostOwnerEvidence(ControlModel):
    format: Literal["linux-opencode-owner-v2"]
    backend_id: str = Field(min_length=1, max_length=255)
    backend_identity: str = Field(min_length=1, max_length=255)
    unit: str = Field(min_length=1, max_length=255)
    unit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_uid: StrictInt = Field(gt=0)
    pid: StrictInt = Field(gt=1, le=2**31 - 1)
    process_start_ticks: StrictInt = Field(gt=0)
    boot_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_device: StrictInt = Field(ge=0)
    dataset_inode: StrictInt = Field(gt=0)
    dataset_open_in_owner: StrictBool
    registration_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    version: str = Field(min_length=1, max_length=255)
    url: str
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def authentic_digest(self) -> Self:
        if not self.dataset_open_in_owner or self.owner_epoch != digest(
            self.model_dump(exclude={"owner_epoch", "observed_at"})
        ):
            raise ValueError("host_owner_epoch_not_coherent")
        return self


def validate_evidence(
    value: Any, enrolled: HostOwnerEnrollment, *, now: float | None = None
) -> HostOwnerEvidence:
    try:
        current = HostOwnerEvidence.model_validate(value)
        for key in (
            "backend_id",
            "backend_identity",
            "unit",
            "unit_sha256",
            "native_uid",
            "version",
            "url",
            "executable_sha256",
            "dataset_device",
            "dataset_inode",
        ):
            if getattr(current, key) != getattr(enrolled, key):
                raise ValueError("enrolled_owner_changed")
        age = (time.time() if now is None else now) - current.observed_at
        if not -1 <= age <= 5:
            raise ValueError("owner_evidence_not_fresh")
        return current
    except (ValueError, TypeError, RecursionError):
        raise HostOwnerError("host_owner_evidence_invalid_or_stale") from None


def root_enrollment(path: Path) -> HostOwnerEnrollment:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise HostOwnerError("root_managed_owner_enrollment_required")
        b = os.read(fd, 65537)
        if len(b) > 65536:
            raise HostOwnerError("owner_enrollment_too_large")
        return HostOwnerEnrollment.model_validate(strict_loads(b))
    finally:
        os.close(fd)


class LinuxHostOwnerProbe:
    def __init__(self, enrollment: HostOwnerEnrollment, socket_path: Path) -> None:
        absolute(str(socket_path))
        self.enrollment, self.socket_path = enrollment, socket_path

    def socket_state(self) -> tuple[int, int, int, int, int]:
        for directory in reversed(self.socket_path.parents):
            s = directory.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
                raise HostOwnerError("root_managed_socket_parent_required")
        s = self.socket_path.lstat()
        if not stat.S_ISSOCK(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) != 0o660:
            raise HostOwnerError("root_managed_restricted_socket_required")
        return s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode

    async def _read(self) -> HostOwnerEvidence:
        if sys.platform != "linux" or os.geteuid() not in {0, self.enrollment.client_uid}:
            raise HostOwnerError("enrolled_linux_client_required")
        before = self.socket_state()
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path), limit=16384)
        try:
            peer = writer.get_extra_info("socket")
            _, uid, _ = struct.unpack(
                "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            # systemd creates the root-owned path/listening FD. asyncio may call
            # listen again after the FD is handed to the enrolled native UID.
            if uid not in {0, self.enrollment.native_uid} or self.socket_state() != before:
                raise HostOwnerError("socket_activation_enrolled_peer_required")
            writer.write(b"STATUS\n")
            await writer.drain()
            line = await reader.readline()
            if not line.endswith(b"\n") or len(line) > 16384:
                raise HostOwnerError("bounded_owner_response_required")
            value = strict_loads(line)
            if (
                not isinstance(value, dict)
                or set(value) != {"ok", "evidence"}
                or value["ok"] is not True
                or self.socket_state() != before
            ):
                raise HostOwnerError("owner_probe_unavailable")
            return validate_evidence(value["evidence"], self.enrollment)
        finally:
            writer.close()
            await writer.wait_closed()

    async def read(self) -> HostOwnerEvidence:
        try:
            return await asyncio.wait_for(self._read(), timeout=15)
        except (
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            struct.error,
            TimeoutError,
            RecursionError,
        ):
            raise HostOwnerError("host_owner_probe_failed") from None
