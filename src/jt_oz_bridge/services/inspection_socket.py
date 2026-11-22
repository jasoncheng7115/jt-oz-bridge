"""Bounded Linux peer-authenticated AF_UNIX observation, never a command RPC."""

import asyncio
import contextlib
import json
import os
import socket
import stat
import struct
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from jt_oz_bridge.domain.inspection import (
    InspectionClock,
    InspectionIssue,
    InspectionIssueCode,
    InspectionProtocolQuery,
    InspectionProtocolResponse,
    InspectionQuery,
    InspectionQueryV2,
    InspectionResponse,
    InspectionResponseV2,
    fresh_inspection_response,
)
from jt_oz_bridge.security.json_data import strict_loads

MAX_REQUEST = 16384
MAX_RESPONSE = 4 * 1024 * 1024
DEFAULT_SOCKET = Path("/run/jt-oz-observer/observer.sock")
PeerUID = Callable[[Any], int]


def peer_uid(connection: Any) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("linux_peer_credentials_required")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise ValueError("invalid_peer_credentials")
    return int(uid)


def trusted_parents(path: Path, service_uid: int) -> None:
    if not path.is_absolute() or ".." in path.parts or len(str(path).encode()) > 103:
        raise ValueError("fixed_absolute_unix_socket_path_required")
    for parent in path.parents:
        value = parent.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, service_uid}:
            raise ValueError("trusted_observer_socket_parent_required")
        if value.st_mode & 0o022 and not (value.st_uid == 0 and value.st_mode & stat.S_ISVTX):
            raise ValueError("observer_socket_parent_writable_by_other_principal")


def error(code: InspectionIssueCode, *, runtime_modes: bool = False) -> InspectionProtocolResponse:
    response_type = InspectionResponseV2 if runtime_modes else InspectionResponse
    return response_type(
        status="error", observed_at=time.time(), issues=(InspectionIssue(code=code),)
    )


class InspectionSocketServer:
    def __init__(
        self,
        path: Path,
        gid: int,
        allowed_uids: frozenset[int],
        handler: Callable[[InspectionProtocolQuery], Awaitable[InspectionProtocolResponse]],
        *,
        peer_reader: PeerUID = peer_uid,
    ) -> None:
        if (
            not allowed_uids
            or any(type(uid) is not int or uid < 0 for uid in allowed_uids)
            or len(allowed_uids) > 32
        ):
            raise ValueError("explicit_local_peer_uid_scope_required")
        self.path, self.gid, self.allowed, self.handler = path, gid, allowed_uids, handler
        self.peer_reader = peer_reader
        self.server: asyncio.AbstractServer | None = None
        self.identity: tuple[int, int] | None = None
        self.tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        if self.server is not None:
            raise ValueError("observer_socket_already_started")
        trusted_parents(self.path, os.geteuid())
        if self.path.exists() or self.path.is_symlink():
            value = self.path.lstat()
            if (
                not stat.S_ISSOCK(value.st_mode)
                or value.st_uid != os.geteuid()
                or value.st_mode & 0o007
            ):
                raise ValueError("existing_observer_socket_not_owned_or_not_socket")
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(str(self.path)), 0.5
                )
            except (ConnectionRefusedError, FileNotFoundError):
                now = self.path.lstat()
                if (now.st_dev, now.st_ino) != (value.st_dev, value.st_ino):
                    raise ValueError("stale_socket_replaced") from None
                self.path.unlink()
            else:
                writer.close()
                await writer.wait_closed()
                raise ValueError("observer_socket_already_listening")
        self.server = await asyncio.start_unix_server(
            self.accept,
            path=str(self.path),
            limit=MAX_REQUEST + 1,
            backlog=16,
            cleanup_socket=False,
        )
        value = self.path.lstat()
        self.identity = (value.st_dev, value.st_ino)
        try:
            os.chown(self.path, -1, self.gid)
            self.path.chmod(0o660)
        except BaseException:
            await self.close()
            raise

    def accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self.tasks) >= 4:
            writer.close()
            return
        task = asyncio.create_task(
            self.connection(reader, writer), name="jtoz:local-observer-query"
        )
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        runtime_modes = False
        started = InspectionClock.capture(time.time, time.monotonic)
        try:
            if self.peer_reader(writer.get_extra_info("socket")) not in self.allowed:
                response = error("unauthorized")
            else:
                raw = await asyncio.wait_for(reader.readuntil(b"\n"), 2)
                if len(raw) > MAX_REQUEST:
                    raise ValueError("request_capacity")
                value = strict_loads(raw)
                runtime_modes = (
                    isinstance(value, dict) and value.get("version") == "jt-oz-inspector-v2"
                )
                query_type = InspectionQueryV2 if runtime_modes else InspectionQuery
                query = query_type.model_validate(value)
                try:
                    response = await asyncio.wait_for(self.handler(query), 30)
                except TimeoutError:
                    response = error("deadline", runtime_modes=runtime_modes)
                response_type = InspectionResponseV2 if runtime_modes else InspectionResponse
                response = response_type.model_validate(response.model_dump(mode="json"))
            response = fresh_inspection_response(
                response, started, InspectionClock.capture(time.time, time.monotonic)
            )
            data = (
                json.dumps(
                    response.model_dump(mode="json"),
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            # Bounded serialization is synchronous but can still outlive a fact.
            closing = fresh_inspection_response(
                response, started, InspectionClock.capture(time.time, time.monotonic)
            )
            if closing != response:
                data = (
                    json.dumps(
                        closing.model_dump(mode="json"),
                        ensure_ascii=False,
                        allow_nan=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
            if len(data) > MAX_RESPONSE:
                data = (
                    error("capacity", runtime_modes=runtime_modes).model_dump_json() + "\n"
                ).encode()
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 3)
        except asyncio.CancelledError:
            raise
        except Exception:
            with contextlib.suppress(Exception):
                writer.write(
                    (
                        error("invalid_request", runtime_modes=runtime_modes).model_dump_json()
                        + "\n"
                    ).encode()
                )
                await asyncio.wait_for(writer.drain(), 1)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        for task in tuple(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        if self.identity is not None:
            with contextlib.suppress(FileNotFoundError):
                value = self.path.lstat()
                if stat.S_ISSOCK(value.st_mode) and (value.st_dev, value.st_ino) == self.identity:
                    self.path.unlink()
            self.identity = None


async def inspect_query(
    path: Path,
    query: InspectionProtocolQuery,
    *,
    expected_uid: int,
    peer_reader: PeerUID = peer_uid,
) -> InspectionProtocolResponse:
    writer = None
    runtime_modes = isinstance(query, InspectionQueryV2)
    started = InspectionClock.capture(time.time, time.monotonic)
    try:
        await asyncio.to_thread(trusted_parents, path, expected_uid)
        value = await asyncio.to_thread(path.lstat)
        if (
            not stat.S_ISSOCK(value.st_mode)
            or value.st_uid not in {0, expected_uid}
            or value.st_mode & 0o007
        ):
            raise ValueError("untrusted_local_observer_socket")
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(str(path), limit=MAX_RESPONSE + 1), 2
        )
        if peer_reader(writer.get_extra_info("socket")) not in {0, expected_uid}:
            raise ValueError("untrusted_observer_peer")
        writer.write((query.model_dump_json() + "\n").encode())
        await asyncio.wait_for(writer.drain(), 2)
        raw = await asyncio.wait_for(reader.readuntil(b"\n"), 35)
        if len(raw) > MAX_RESPONSE:
            result: InspectionProtocolResponse = error(
                "invalid_response", runtime_modes=runtime_modes
            )
        else:
            response_type = InspectionResponseV2 if runtime_modes else InspectionResponse
            try:
                result = response_type.model_validate(strict_loads(raw))
            except (ValueError, TypeError):
                result = error("invalid_response", runtime_modes=runtime_modes)
    except asyncio.CancelledError:
        raise
    except Exception:
        result = error("observer_unavailable", runtime_modes=runtime_modes)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    return fresh_inspection_response(
        result, started, InspectionClock.capture(time.time, time.monotonic)
    )
