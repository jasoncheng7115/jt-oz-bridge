"""Linux local metadata-only socket: fixed roots, original objects, five seconds."""

import asyncio
import json
import os
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from weakref import ReferenceType
from weakref import ref as weakref

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.directory_scope import (
    DirectoryScopeSnapshot,
    directory_path,
    directory_project_key,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads

REQUEST_LIMIT = 256 * 1024
RESPONSE_LIMIT = 2 * 1024 * 1024


class DirectoryScopeRoot(ControlModel):
    project_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory: str
    device: StrictInt = Field(ge=0)
    inode: StrictInt = Field(gt=0)
    uid: StrictInt = Field(ge=0)
    gid: StrictInt = Field(ge=0)
    mode: StrictInt = Field(ge=0, le=0o7777)

    @field_validator("directory")
    @classmethod
    def absolute(cls, value: str) -> str:
        p = Path(value)
        if (
            not p.is_absolute()
            or value != str(p)
            or ".." in p.parts
            or value == "/"
            or value.startswith("//")
            or len(value.encode("utf-8")) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("directory_scope_canonical_root_required")
        return value


class DirectoryScopeEnrollment(ControlModel):
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    server_uid: StrictInt = Field(ge=0)
    client_uid: StrictInt = Field(ge=0)
    roots: tuple[DirectoryScopeRoot, ...] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def unique(self) -> "DirectoryScopeEnrollment":
        if len({r.project_key for r in self.roots}) != len(self.roots):
            raise ValueError("directory_scope_unique_root_required")
        return self


@dataclass(frozen=True)
class _Observation:
    original: ReferenceType[DirectoryScopeSnapshot]
    socket_state: tuple[int, ...]
    deadline: float


class LinuxDirectoryScopeGuard:
    def __init__(self, enrollment: DirectoryScopeEnrollment, socket_path: Path) -> None:
        if not socket_path.is_absolute() or ".." in socket_path.parts:
            raise ValueError("directory_scope_absolute_socket_required")
        self.enrollment, self.socket_path = enrollment, socket_path
        self.roots = MappingProxyType({r.project_key: r for r in enrollment.roots})
        self._observed: dict[int, _Observation] = {}
        self._server_epoch: str | None = None

    def qualified(self, reference: SessionRef) -> bool:
        root = self.roots.get(directory_project_key(reference))
        return (
            sys.platform == "linux"
            and os.geteuid() in {0, self.enrollment.client_uid}
            and root is not None
            and root.directory == reference.canonical_directory
        )

    def socket_state(self) -> tuple[int, ...]:
        for directory in reversed(self.socket_path.parents):
            s = directory.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
                raise ValueError("directory_scope_root_managed_socket_parent_required")
        s = self.socket_path.lstat()
        if not stat.S_ISSOCK(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) != 0o660:
            raise ValueError("directory_scope_restricted_socket_required")
        return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)

    async def _read(self, reference: SessionRef, paths: tuple[str, ...]) -> DirectoryScopeSnapshot:
        if (
            sys.platform != "linux"
            or os.geteuid() not in {0, self.enrollment.client_uid}
            or not self.qualified(reference)
        ):
            raise ValueError("directory_scope_enrolled_linux_client_required")
        paths = tuple(sorted(set(paths)))
        if not 1 <= len(paths) <= 1024:
            raise ValueError("directory_scope_path_capacity")
        for path in paths:
            directory_path(path)
        key = directory_project_key(reference)
        wire = (
            json.dumps(
                {"operation": "directory-scope-v1", "project_key": key, "directories": paths},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
            + b"\n"
        )
        if len(wire) > REQUEST_LIMIT:
            raise ValueError("directory_scope_request_capacity")
        before = self.socket_state()
        reader, writer = await asyncio.open_unix_connection(
            str(self.socket_path), limit=RESPONSE_LIMIT
        )
        try:
            peer = writer.get_extra_info("socket")
            _, uid, _ = struct.unpack(
                "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid not in {0, self.enrollment.server_uid} or self.socket_state() != before:
                raise ValueError("directory_scope_enrolled_socket_peer_required")
            writer.write(wire)
            await writer.drain()
            line = await reader.readline()
            if not line.endswith(b"\n") or len(line) > RESPONSE_LIMIT:
                raise ValueError("directory_scope_response_capacity")
            value = strict_loads(line)
            if (
                not isinstance(value, dict)
                or set(value) != {"ok", "snapshot"}
                or value["ok"] is not True
            ):
                raise ValueError("directory_scope_observation_unavailable")
            snap = DirectoryScopeSnapshot.model_validate(value["snapshot"])
            root = self.roots[key]
            identity = snap.records[0]
            if (
                (snap.project_key, snap.directories, snap.config_sha256, snap.implementation_sha256)
                != (
                    key,
                    paths,
                    self.enrollment.config_sha256,
                    self.enrollment.implementation_sha256,
                )
                or (identity.device, identity.inode, identity.uid, identity.gid, identity.mode)
                != (root.device, root.inode, root.uid, root.gid, root.mode)
                or not 0 <= time.time() - snap.observed_at < 5
                or self.socket_state() != before
            ):
                raise ValueError("directory_scope_original_root_or_response_changed")
            if self._server_epoch is not None and self._server_epoch != snap.server_epoch:
                self._observed.clear()
            self._server_epoch = snap.server_epoch
            now = time.monotonic()
            self._observed = {
                k: v
                for k, v in self._observed.items()
                if v.original() is not None and v.deadline > now
            }
            if len(self._observed) >= 32:
                raise ValueError("directory_scope_observation_capacity")
            self._observed[id(snap)] = _Observation(
                weakref(snap), before, now + min(5, max(0, snap.observed_at + 5 - time.time()))
            )
            return snap
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass  # Do not mask an original cancellation/protocol failure.

    async def observe(
        self, reference: SessionRef, directories: tuple[str, ...]
    ) -> DirectoryScopeSnapshot:
        try:
            return await asyncio.wait_for(self._read(reference, directories), timeout=5)
        except (
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            struct.error,
            TimeoutError,
            RecursionError,
        ):
            raise ValueError("directory_scope_probe_failed") from None

    def current(self, reference: SessionRef, snapshot: DirectoryScopeSnapshot) -> bool:
        item = self._observed.get(id(snapshot))
        try:
            return bool(
                item is not None
                and item.original() is snapshot
                and self.qualified(reference)
                and snapshot.project_key == directory_project_key(reference)
                and snapshot.server_epoch == self._server_epoch
                and item.deadline > time.monotonic()
                and self.socket_state() == item.socket_state
            )
        except (OSError, ValueError):
            return False
