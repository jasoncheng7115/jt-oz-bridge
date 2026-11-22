#!/usr/bin/python3
"""Read-only, socket-activated proof of the one root-enrolled native backend.

This helper never opens native database contents or accepts a command/path from a
client. Credentials read from native registration are used only for loopback info.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
import time
import urllib.error
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_opener():
    # The enrolled endpoint is fixed HTTP loopback. build_opener() also creates
    # an unused HTTPS trust store and cyclic handler graph on every status call.
    # Keep one HTTP-only director; requests, credentials and responses stay fresh.
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.UnknownHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        NoRedirect(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def read_file(path, uid, *, private=False, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid != uid
            or s.st_mode & (0o077 if private else 0o022)
            or s.st_size > limit
        ):
            raise ValueError("file_not_trusted")
        b = os.read(fd, limit + 1)
        if len(b) > limit:
            raise ValueError("file_too_large")
        return b
    finally:
        os.close(fd)


class OwnerProbe:
    def __init__(self, config):
        self.c = config
        self.cache = None
        self.opener = http_opener()

    def unit(self):
        r = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                self.c["unit"],
                "--property=MainPID,ActiveState,SubState,FragmentPath",
                "--no-pager",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        d = dict(line.split("=", 1) for line in r.stdout.splitlines())
        pid = int(d["MainPID"])
        if (
            pid <= 1
            or d["ActiveState"] != "active"
            or d["SubState"] != "running"
            or d["FragmentPath"] != self.c["unit_path"]
        ):
            raise ValueError("native_unit_not_running")
        if hashlib.sha256(read_file(self.c["unit_path"], 0)).hexdigest() != self.c["unit_sha256"]:
            raise ValueError("native_unit_changed")
        return pid

    def process(self, pid):
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read(8192)
        start = int(raw.rsplit(b")", 1)[1].split()[19])
        with open(f"/proc/{pid}/status") as f:
            uids = next(line.split()[1:] for line in f if line.startswith("Uid:"))
        if [int(x) for x in uids] != [self.c["native_uid"]] * 4:
            raise ValueError("native_process_uid_changed")
        if os.readlink(f"/proc/{pid}/exe") != self.c["executable_path"]:
            raise ValueError("native_executable_changed")
        return start

    def executable(self, pid, start):
        # /proc/PID/exe is a kernel-produced link, intentionally opened as such.
        with open(f"/proc/{pid}/exe", "rb") as f:
            s = os.fstat(f.fileno())
            if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
                raise ValueError("native_executable_not_root_managed")
            key = (pid, start, s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if self.cache is None or self.cache[0] != key:
                value = hashlib.file_digest(f, "sha256").hexdigest()
                if value != self.c["executable_sha256"]:
                    raise ValueError("native_binary_not_enrolled")
                self.cache = (key, value)
            return self.cache[1]

    def dataset(self):
        # Metadata only: no SQLite connection, file read, table query or copy.
        s = os.stat(self.c["dataset_path"], follow_symlinks=False)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid != self.c["native_uid"]
            or s.st_mode & 0o077
            or (s.st_dev, s.st_ino) != (self.c["dataset_device"], self.c["dataset_inode"])
        ):
            raise ValueError("original_dataset_identity_changed")
        return s.st_dev, s.st_ino

    def registration(self, pid):
        d = json.loads(read_file(self.c["registration_path"], self.c["native_uid"], private=True))
        if (
            type(d.get("pid")) is not int
            or d["pid"] != pid
            or d.get("version") != self.c["version"]
            or d.get("url") != self.c["url"]
            or not isinstance(d.get("password"), str)
            or not d["password"]
            or str(uuid.UUID(d["id"])) != d["id"]
        ):
            raise ValueError("native_registration_changed")
        return d

    def open_dataset(self, pid, identity):
        # Kernel descriptor metadata proves the enrolled process actually holds
        # this dataset, rather than merely coexisting with an unused old file.
        directory = f"/proc/{pid}/fd"
        names = os.listdir(directory)
        if len(names) > 8192:
            raise ValueError("native_descriptor_inventory_too_large")
        for name in names:
            if not name.isascii() or not name.isdigit():
                continue
            path = directory + "/" + name
            try:
                if os.readlink(path) != self.c["dataset_path"]:
                    continue
                s = os.stat(path)
                if stat.S_ISREG(s.st_mode) and (s.st_dev, s.st_ino) == identity:
                    return True
            except OSError:
                continue
        raise ValueError("original_dataset_not_open_in_owner")

    def status(self):
        c = self.c
        pid = self.unit()
        start = self.process(pid)
        executable = self.executable(pid, start)
        device, inode = self.dataset()
        self.open_dataset(pid, (device, inode))
        registration = self.registration(pid)
        auth = base64.b64encode(("opencode:" + registration["password"]).encode()).decode()
        request = urllib.request.Request(
            c["url"] + "/api/info", headers={"Authorization": "Basic " + auth}
        )
        try:
            response = self.opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            error.close()
            raise ValueError("native_info_rejected") from None
        with response:
            if response.status != 200:
                raise ValueError("native_info_rejected")
            b = response.read(65537)
            if len(b) > 65536:
                raise ValueError("native_info_too_large")
            info = json.loads(b)
        if (
            type(info.get("pid")) is not int
            or info["pid"] != pid
            or info.get("version") != c["version"]
            or info.get("urls") != [c["url"]]
        ):
            raise ValueError("authenticated_native_info_does_not_match_owner")
        if (
            self.unit() != pid
            or self.process(pid) != start
            or self.dataset() != (device, inode)
            or self.open_dataset(pid, (device, inode)) is not True
            or self.registration(pid) != registration
        ):
            raise ValueError("native_owner_changed_during_probe")
        with open("/proc/sys/kernel/random/boot_id") as f:
            boot_id = f.read(100).strip()
        core = {
            "format": "linux-opencode-owner-v2",
            "backend_id": c["backend_id"],
            "backend_identity": c["backend_identity"],
            "unit": c["unit"],
            "unit_sha256": c["unit_sha256"],
            "native_uid": c["native_uid"],
            "pid": pid,
            "process_start_ticks": start,
            "boot_id": boot_id,
            "executable_sha256": executable,
            "dataset_device": device,
            "dataset_inode": inode,
            "dataset_open_in_owner": True,
            "registration_id": registration["id"],
            "version": c["version"],
            "url": c["url"],
        }
        return {
            **core,
            "owner_epoch": hashlib.sha256(canonical(core)).hexdigest(),
            "observed_at": time.time(),
        }


async def serve(config):
    if int(os.environ.get("LISTEN_PID", "0")) != os.getpid() or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("one_systemd_socket_required")
    probe = OwnerProbe(config)
    gate = asyncio.Lock()

    async def client(reader, writer):
        try:
            raw_socket = writer.get_extra_info("socket")
            _, uid, _ = struct.unpack(
                "3i", raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid not in {0, config["client_uid"]}:
                raise ValueError("peer_not_allowed")
            line = await asyncio.wait_for(reader.readline(), timeout=2)
            if line != b"STATUS\n":
                raise ValueError("fixed_status_request_required")
            async with gate:
                value = await asyncio.wait_for(asyncio.to_thread(probe.status), timeout=10)
            response = {"ok": True, "evidence": value}
        except Exception:
            # Never echo request data, paths, native credentials or exception details.
            response = {"ok": False, "error": "native_owner_unavailable"}
        try:
            writer.write(canonical(response) + b"\n")
            await asyncio.wait_for(writer.drain(), timeout=2)
        except (OSError, TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, TimeoutError):
                pass

    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX:
        raise RuntimeError("unix_socket_required")
    server = await asyncio.start_unix_server(client, sock=listener, limit=64)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(read_file(args.config, 0))
    asyncio.run(serve(config))
