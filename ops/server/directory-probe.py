#!/usr/bin/python3
"""Socket-activated metadata-only walks under root-enrolled physical projects.

No arbitrary root, shell, file-content read, directory enumeration or database
operation is accepted. Run as the Native UID in a separate read-only service;
this does not change the OpenCode service or its filesystem/sudo privileges.
"""

import argparse
import asyncio
import hashlib
import json
import os
import socket
import stat
import struct
import time
import uuid
from pathlib import Path

REQUEST_LIMIT = 256 * 1024
RESPONSE_LIMIT = 2 * 1024 * 1024


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def canonical(data):
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def read_config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size > 65536
        ):
            raise ValueError("root_managed_configuration_required")
        raw = os.read(fd, 65537)
        if len(raw) > 65536:
            raise ValueError("configuration_capacity")
        return strict_json(raw), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)


def relative(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
        raise ValueError("bounded_relative_directory_required")
    if value and (
        value.startswith("/")
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or len(value.split("/")) > 64
        or any(not p or p in {".", ".."} or len(p.encode("utf-8")) > 255 for p in value.split("/"))
    ):
        raise ValueError("canonical_relative_directory_required")
    return value


def open_root(path):
    path = Path(path)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) == "/"
        or str(path).startswith("//")
        or len(str(path).encode("utf-8")) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in str(path))
    ):
        raise ValueError("canonical_project_root_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
            )
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def record(path, fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("directory_required")
    return {
        "path": path,
        **identity(info),
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


class DirectoryProbe:
    def __init__(self, config, config_sha256, implementation_sha256):
        if (
            not isinstance(config, dict)
            or set(config) != {"format", "client_uid", "native_uid", "roots"}
            or config["format"] != "directory-scope-server-v1"
        ):
            raise ValueError("fixed_configuration_required")
        if (
            any(type(config[k]) is not int or config[k] < 0 for k in ("client_uid", "native_uid"))
            or os.geteuid() != config["native_uid"]
        ):
            raise ValueError("enrolled_native_uid_required")
        roots = config["roots"]
        if not isinstance(roots, list) or not 1 <= len(roots) <= 20:
            raise ValueError("explicit_roots_required")
        self.roots = {}
        for root in roots:
            if not isinstance(root, dict) or set(root) != {
                "project_key",
                "directory",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
            }:
                raise ValueError("fixed_root_identity_required")
            key = root["project_key"]
            if (
                not isinstance(key, str)
                or len(key) != 64
                or any(c not in "0123456789abcdef" for c in key)
                or key in self.roots
            ):
                raise ValueError("unique_project_key_required")
            if (
                not isinstance(root["directory"], str)
                or str(Path(root["directory"])) != root["directory"]
            ):
                raise ValueError("canonical_root_required")
            if any(
                type(root[k]) is not int or root[k] < 0
                for k in ("device", "inode", "uid", "gid", "mode")
            ):
                raise ValueError("strict_root_metadata_required")
            self.roots[key] = root
        self.client_uid = config["client_uid"]
        self.config_sha256, self.implementation_sha256 = config_sha256, implementation_sha256
        self.epoch = uuid.uuid4().hex

    def observe(self, request):
        started = time.time()
        if (
            not isinstance(request, dict)
            or set(request) != {"operation", "project_key", "directories"}
            or request["operation"] != "directory-scope-v1"
        ):
            raise ValueError("fixed_operation_required")
        root = self.roots.get(request["project_key"])
        paths = request["directories"]
        if root is None or not isinstance(paths, list) or not 1 <= len(paths) <= 1024:
            raise ValueError("enrolled_project_and_bounded_paths_required")
        for path in paths:
            relative(path)
        if paths != sorted(set(paths)):
            raise ValueError("unique_sorted_paths_required")
        fds = {}
        try:
            fds[""] = open_root(root["directory"])
            if identity(os.fstat(fds[""])) != {
                k: root[k] for k in ("device", "inode", "uid", "gid", "mode")
            }:
                raise ValueError("original_project_identity_changed")
            for path in paths:
                parts = path.split("/") if path else []
                for count in range(1, len(parts) + 1):
                    key = "/".join(parts[:count])
                    if key in fds:
                        continue
                    if len(fds) >= 8192:
                        raise ValueError("directory_node_capacity")
                    parent = "/".join(parts[: count - 1])
                    fds[key] = os.open(
                        parts[count - 1],
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=fds[parent],
                    )
            records = [record(path, fds[path]) for path in sorted(fds)]
            # Detect an ancestor/name replacement while walking, including a
            # directory renamed away while its original descriptor stays open.
            check = open_root(root["directory"])
            try:
                if record("", check) != records[0]:
                    raise ValueError("project_changed_during_observation")
            finally:
                os.close(check)
            for row in records[1:]:
                parent, _, name = row["path"].rpartition("/")
                info = os.stat(name, dir_fd=fds[parent], follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or {
                    **identity(info),
                    "mtime_ns": info.st_mtime_ns,
                    "ctime_ns": info.st_ctime_ns,
                } != {k: v for k, v in row.items() if k != "path"}:
                    raise ValueError("directory_changed_during_observation")
            if not 0 <= time.time() - started < 5:
                raise ValueError("directory_observation_expired")
            return {
                "project_key": request["project_key"],
                "config_sha256": self.config_sha256,
                "implementation_sha256": self.implementation_sha256,
                "server_epoch": self.epoch,
                "observed_at": started,
                "directories": paths,
                "records": records,
            }
        finally:
            for fd in fds.values():
                os.close(fd)


async def serve(probe, inherited_socket):
    slots = asyncio.Semaphore(4)

    async def handle(reader, writer):
        try:
            peer = writer.get_extra_info("socket")
            _, uid, _ = struct.unpack(
                "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid not in {0, probe.client_uid}:
                raise ValueError("enrolled_client_required")
            async with asyncio.timeout(5), slots:
                line = await reader.readline()
                if not line.endswith(b"\n") or len(line) > REQUEST_LIMIT:
                    raise ValueError("bounded_request_required")
                snapshot = probe.observe(strict_json(line))
                response = canonical({"ok": True, "snapshot": snapshot}) + b"\n"
                if len(response) > RESPONSE_LIMIT:
                    raise ValueError("bounded_response_required")
                writer.write(response)
                await writer.drain()
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            RecursionError,
            TimeoutError,
            struct.error,
        ):
            writer.write(b'{"ok":false,"snapshot":null}\n')
            try:
                await writer.drain()
            except (OSError, ConnectionError):
                pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(handle, sock=inherited_socket, limit=REQUEST_LIMIT)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config, config_sha256 = read_config(args.config)
    implementation_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise ValueError("systemd_socket_activation_required")
    inherited = socket.socket(fileno=3)
    if inherited.family != socket.AF_UNIX or inherited.type != socket.SOCK_STREAM:
        raise ValueError("local_stream_socket_required")
    asyncio.run(serve(DirectoryProbe(config, config_sha256, implementation_sha256), inherited))


if __name__ == "__main__":
    main()
