"""Real local metadata walks and synthetic Unix framing; no Native database I/O."""

import asyncio
import importlib.util
import json
import os
import stat
import struct
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode import directory_scope as client_module
from jt_oz_bridge.adapters.opencode.directory_scope import (
    DirectoryScopeEnrollment,
    LinuxDirectoryScopeGuard,
)
from jt_oz_bridge.domain.directory_scope import DirectoryScopeSnapshot, directory_project_key
from tests.support import REF

spec = importlib.util.spec_from_file_location("directory_probe", "ops/server/directory-probe.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def setup(tmp_path):
    root = tmp_path.resolve() / "project"
    root.mkdir(mode=0o700)
    (root / "nested").mkdir(mode=0o700)
    (root / "nested" / "資料").mkdir(mode=0o700)
    ref = REF.model_copy(update={"canonical_directory": str(root)})
    identity = helper.identity(root.stat())
    config = {
        "format": "directory-scope-server-v1",
        "native_uid": os.geteuid(),
        "client_uid": 1001,
        "roots": [{"project_key": directory_project_key(ref), "directory": str(root), **identity}],
    }
    probe = helper.DirectoryProbe(config, "a" * 64, "b" * 64)
    request = {
        "operation": "directory-scope-v1",
        "project_key": directory_project_key(ref),
        "directories": ["", "nested/資料"],
    }
    return root, ref, config, probe, request


def test_root_and_all_ancestor_identities_are_metadata_only(tmp_path, monkeypatch):
    root, ref, cfg, probe, request = setup(tmp_path)
    original = helper.os.open
    flags = []

    def observed(path, mode, *args, **kwargs):
        flags.append(mode)
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(helper.os, "open", observed)
    value = DirectoryScopeSnapshot.model_validate(probe.observe(request))
    assert [row.path for row in value.records] == ["", "nested", "nested/資料"]
    assert value.records[0].inode == root.stat().st_ino
    assert all(flag & os.O_DIRECTORY for flag in flags)
    assert "content" not in value.model_dump_json() and "session_id" not in value.model_dump_json()
    first = value.fingerprint
    second = DirectoryScopeSnapshot.model_validate(probe.observe(request))
    assert first == second.fingerprint


@pytest.mark.parametrize(
    "kind", ["inside-link", "outside-link", "root-link", "root-replaced", "file", "fifo"]
)
def test_links_replacements_and_non_directories_never_become_directory_scope(tmp_path, kind):
    root, ref, cfg, probe, request = setup(tmp_path)
    if kind in {"inside-link", "outside-link"}:
        target = root / "nested" if kind == "inside-link" else tmp_path / "outside"
        if kind == "outside-link":
            target.mkdir()
        (root / "link").symlink_to(target, target_is_directory=True)
        request["directories"] = ["link"]
    elif kind in {"root-link", "root-replaced"}:
        saved = tmp_path / "saved"
        root.rename(saved)
        if kind == "root-link":
            root.symlink_to(saved, target_is_directory=True)
        else:
            root.mkdir(mode=0o700)
    else:
        path = root / "not-dir"
        if kind == "file":
            path.write_bytes(b"never read this content")
        else:
            os.mkfifo(path)
        request["directories"] = ["not-dir"]
    with pytest.raises((OSError, ValueError)):
        probe.observe(request)


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "/etc",
        "nested//資料",
        "nested/../資料",
        "nested\\資料",
        "nested/",
        "a\n",
        "a" * 256,
        "/".join(["x"] * 65),
    ],
)
def test_invalid_directories_fail_before_any_filesystem_open(tmp_path, monkeypatch, path):
    root, ref, cfg, probe, request = setup(tmp_path)
    request["directories"] = [path]
    monkeypatch.setattr(
        helper.os, "open", lambda *a, **k: pytest.fail("invalid request reached filesystem")
    )
    with pytest.raises(ValueError):
        probe.observe(request)


@pytest.mark.parametrize(
    "change", ["operation", "project", "duplicate", "extra", "empty", "capacity"]
)
def test_fixed_operation_whitelist_and_collection_bounds(tmp_path, change, monkeypatch):
    root, ref, cfg, probe, request = setup(tmp_path)
    if change == "operation":
        request["operation"] = "read-file"
    elif change == "project":
        request["project_key"] = "c" * 64
    elif change == "duplicate":
        request["directories"] = ["nested", "nested"]
    elif change == "extra":
        request["path"] = "/etc"
    elif change == "empty":
        request["directories"] = []
    else:
        request["directories"] = ["x"] * 1025
    monkeypatch.setattr(
        helper.os, "open", lambda *a, **k: pytest.fail("invalid request reached filesystem")
    )
    with pytest.raises(ValueError):
        probe.observe(request)


@pytest.mark.parametrize("failure", ["ancestor-replacement", "age"])
def test_walk_cannot_publish_a_mixed_or_expired_metadata_snapshot(tmp_path, monkeypatch, failure):
    root, ref, cfg, probe, request = setup(tmp_path)
    if failure == "age":
        clock = iter([100.0, 106.0])
        monkeypatch.setattr(helper.time, "time", lambda: next(clock))
    else:
        original = helper.os.stat

        def replaced(path, *args, **kwargs):
            if path == "nested":
                (root / "nested").rename(root / "old")
                (root / "nested").mkdir()
            return original(path, *args, **kwargs)

        monkeypatch.setattr(helper.os, "stat", replaced)
    with pytest.raises(ValueError):
        probe.observe(request)


def test_configuration_reader_refuses_non_root_files_before_reading_bytes(tmp_path, monkeypatch):
    path = tmp_path / "opencode.db"
    path.write_bytes(b"not actual database bytes")
    monkeypatch.setattr(helper.os, "read", lambda *a: pytest.fail("untrusted data read"))
    with pytest.raises(ValueError):
        helper.read_config(path)


def test_json_duplicate_and_nonfinite_values_fail():
    for value in (b'{"directories":[],"directories":[]}', b'{"x":NaN}', b'{"x":Infinity}'):
        with pytest.raises(ValueError):
            helper.strict_json(value)


class Writer:
    def __init__(self, uid=1000):
        self.uid, self.closed, self.wire = uid, False, b""

    def get_extra_info(self, _):
        return SimpleNamespace(getsockopt=lambda *a: struct.pack("3i", 55, self.uid, 1000))

    def write(self, value):
        self.wire += value

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def wire_setup(tmp_path, monkeypatch):
    root, ref, cfg, server, request = setup(tmp_path)
    snapshot = server.observe(request)
    enrollment = DirectoryScopeEnrollment(
        config_sha256="a" * 64,
        implementation_sha256="b" * 64,
        server_uid=1000,
        client_uid=1001,
        roots=cfg["roots"],
    )
    guard = LinuxDirectoryScopeGuard(enrollment, Path("/run/jt-directory/scope.sock"))
    writer = Writer()
    reader = SimpleNamespace(
        readline=AsyncMock(
            return_value=json.dumps({"ok": True, "snapshot": snapshot}).encode() + b"\n"
        )
    )
    monkeypatch.setattr(client_module.sys, "platform", "linux")
    monkeypatch.setattr(client_module.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(client_module.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(guard, "socket_state", lambda: (1, 2, 0, 1001, stat.S_IFSOCK | 0o660))
    monkeypatch.setattr(
        client_module.asyncio, "open_unix_connection", AsyncMock(return_value=(reader, writer))
    )
    return guard, ref, snapshot, reader, writer


async def test_bounded_fixed_socket_exchange_does_not_grant_dto_copy_authority(
    tmp_path, monkeypatch
):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    value = await guard.observe(ref, ("nested/資料", ""))
    assert (
        guard.current(ref, value) and not guard.current(ref, value.model_copy()) and writer.closed
    )
    assert json.loads(writer.wire) == {
        "operation": "directory-scope-v1",
        "project_key": directory_project_key(ref),
        "directories": ["", "nested/資料"],
    }
    assert not guard.current(ref.model_copy(update={"canonical_directory": "/other"}), value)


@pytest.mark.parametrize(
    "failure",
    [
        "peer",
        "root",
        "config",
        "implementation",
        "epoch",
        "time",
        "negative",
        "duplicate",
        "truncated",
        "capacity",
        "extra",
        "dirs",
        "root-missing",
    ],
)
async def test_wrong_peer_or_scope_and_malformed_replies_fail_closed(
    tmp_path, monkeypatch, failure
):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    wire = None
    if failure == "peer":
        writer.uid = 77
    elif failure == "root":
        snapshot["records"][0]["inode"] += 1
    elif failure in {"config", "implementation"}:
        snapshot[failure + "_sha256"] = "e" * 64
    elif failure == "epoch":
        snapshot["server_epoch"] = "wrong"
    elif failure == "time":
        snapshot["observed_at"] = time.time() - 6
    elif failure == "dirs":
        snapshot["directories"] = ["nested"]
    elif failure == "root-missing":
        snapshot["records"] = snapshot["records"][1:]
    elif failure == "extra":
        snapshot["content"] = "not metadata"
    elif failure == "negative":
        wire = b'{"ok":false,"snapshot":null}\n'
    elif failure == "duplicate":
        wire = b'{"ok":true,"ok":false,"snapshot":null}\n'
    elif failure == "truncated":
        wire = b"{}"
    else:
        wire = b"x" * (client_module.RESPONSE_LIMIT + 1) + b"\n"
    reader.readline = AsyncMock(
        return_value=wire
        if wire is not None
        else json.dumps({"ok": True, "snapshot": snapshot}).encode() + b"\n"
    )
    with pytest.raises(ValueError, match="directory_scope_probe_failed"):
        await guard.observe(ref, ("", "nested/資料"))
    assert writer.closed
    assert reader.readline.await_count == (0 if failure == "peer" else 1)


async def test_metadata_observation_expires_after_five_seconds(tmp_path, monkeypatch):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    value = await guard.observe(ref, ("", "nested/資料"))
    now = time.monotonic()
    monkeypatch.setattr(client_module.time, "monotonic", lambda: now + 6)
    assert not guard.current(ref, value)


async def test_cancellation_propagates_and_closes_socket(tmp_path, monkeypatch):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    waiting = asyncio.Event()

    async def block():
        waiting.set()
        await asyncio.Event().wait()

    reader.readline = block
    task = asyncio.create_task(guard.observe(ref, ("", "nested/資料")))
    reached = asyncio.create_task(waiting.wait())
    done, _ = await asyncio.wait({task, reached}, timeout=2, return_when=asyncio.FIRST_COMPLETED)
    if task in done:
        await task
    assert reached in done
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer.closed


@pytest.mark.parametrize("bad", ["parent", "owner", "mode", "not-socket"])
def test_socket_root_ownership_directory_chain_and_mode_are_required(tmp_path, monkeypatch, bad):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    monkeypatch.undo()

    def status(path):
        if str(path) == str(guard.socket_path):
            return SimpleNamespace(
                st_mode=(stat.S_IFREG if bad == "not-socket" else stat.S_IFSOCK)
                | (0o666 if bad == "mode" else 0o660),
                st_uid=7 if bad == "owner" else 0,
                st_gid=1001,
                st_dev=1,
                st_ino=2,
            )
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | (0o777 if bad == "parent" else 0o755), st_uid=0
        )

    monkeypatch.setattr(Path, "lstat", status)
    with pytest.raises(ValueError):
        guard.socket_state()


async def test_socket_replacement_during_response_invalidates_observation(tmp_path, monkeypatch):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    state = [1, 2, 0, 1001, stat.S_IFSOCK | 0o660]
    monkeypatch.setattr(guard, "socket_state", lambda: tuple(state))

    async def changed():
        state[1] += 1
        return json.dumps({"ok": True, "snapshot": snapshot}).encode() + b"\n"

    reader.readline = changed
    with pytest.raises(ValueError, match="directory_scope_probe_failed"):
        await guard.observe(ref, ("", "nested/資料"))
    assert writer.closed


async def test_socket_replacement_invalidates_an_already_observed_object(tmp_path, monkeypatch):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    value = await guard.observe(ref, ("", "nested/資料"))
    assert guard.current(ref, value)
    monkeypatch.setattr(guard, "socket_state", lambda: (1, 3, 0, 1001, stat.S_IFSOCK | 0o660))
    assert not guard.current(ref, value)


@pytest.mark.parametrize("failure", [False, True])
def test_all_open_directory_descriptors_close_on_success_and_failure(
    tmp_path, monkeypatch, failure
):
    root, ref, cfg, probe, request = setup(tmp_path)
    if failure:
        (root / "nested" / "escape").symlink_to(tmp_path, target_is_directory=True)
        request["directories"] = ["nested/escape"]
    opened, closed = [], []
    real_open, real_close = helper.os.open, helper.os.close

    def track_open(*args, **kwargs):
        value = real_open(*args, **kwargs)
        opened.append(value)
        return value

    def track_close(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(helper.os, "open", track_open)
    monkeypatch.setattr(helper.os, "close", track_close)
    if failure:
        with pytest.raises(OSError):
            probe.observe(request)
    else:
        probe.observe(request)
    assert sorted(opened) == sorted(closed)


async def test_socket_close_error_does_not_replace_original_cancellation(tmp_path, monkeypatch):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    waiting = asyncio.Event()

    async def block():
        waiting.set()
        await asyncio.Event().wait()

    async def close_error():
        raise ConnectionResetError("synthetic only")

    reader.readline = block
    writer.wait_closed = close_error
    task = asyncio.create_task(guard.observe(ref, ("", "nested/資料")))
    reached = asyncio.create_task(waiting.wait())
    done, _ = await asyncio.wait({task, reached}, timeout=2, return_when=asyncio.FIRST_COMPLETED)
    if task in done:
        await task
    assert reached in done
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer.closed


async def test_new_service_epoch_invalidates_prior_original_observations(tmp_path, monkeypatch):
    guard, ref, snapshot, reader, writer = wire_setup(tmp_path, monkeypatch)
    first = await guard.observe(ref, ("", "nested/資料"))
    assert guard.current(ref, first)
    snapshot["server_epoch"] = "e" * 32
    reader.readline = AsyncMock(
        return_value=json.dumps({"ok": True, "snapshot": snapshot}).encode() + b"\n"
    )
    second = await guard.observe(ref, ("", "nested/資料"))
    assert guard.current(ref, second) and not guard.current(ref, first)
