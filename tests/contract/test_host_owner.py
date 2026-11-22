import asyncio
import copy
import importlib.util
import io
import json
import os
import stat
import struct
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode import host_owner
from jt_oz_bridge.adapters.opencode.host_owner import (
    HostOwnerEnrollment,
    HostOwnerError,
    LinuxHostOwnerProbe,
    validate_evidence,
)
from jt_oz_bridge.storage.durable import digest

spec = importlib.util.spec_from_file_location("owner_probe_helper", "ops/server/owner-probe.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

CONFIG = {
    "backend_id": "server-test",
    "backend_identity": "fixture-identity",
    "unit": "opencode.service",
    "unit_path": "/etc/systemd/system/opencode.service",
    "unit_sha256": "a" * 64,
    "native_uid": 1000,
    "client_uid": 1001,
    "version": "2.0.32",
    "url": "http://127.0.0.1:4096",
    "executable_path": "/opt/opencode/2.0.32/opencode",
    "executable_sha256": "b" * 64,
    "dataset_path": "/home/opencode/.local/share/opencode/opencode.db",
    "dataset_device": 1,
    "dataset_inode": 2,
    "registration_path": "/home/opencode/.local/state/opencode/service.json",
}
ENROLLED = HostOwnerEnrollment(**CONFIG)


def evidence(**changes):
    fields = {
        "format": "linux-opencode-owner-v2",
        "dataset_open_in_owner": True,
        **{
            k: CONFIG[k]
            for k in [
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
            ]
        },
        "pid": 123,
        "process_start_ticks": 100,
        "boot_id": "00000000-0000-4000-8000-000000000001",
        "registration_id": "00000000-0000-4000-8000-000000000002",
    }
    fields.update(changes)
    return {**fields, "owner_epoch": digest(fields), "observed_at": 100.0}


def test_epoch_and_all_pins_validate_but_do_not_claim_session_or_stream_proof():
    a = validate_evidence(evidence(), ENROLLED, now=100)
    b = validate_evidence(evidence(pid=124, process_start_ticks=110), ENROLLED, now=100)
    assert a.owner_epoch != b.owner_epoch
    assert "session_id" not in type(a).model_fields and "password" not in type(a).model_fields


@pytest.mark.parametrize(
    "key,value",
    [
        ("backend_id", "other"),
        ("backend_identity", "other"),
        ("unit", "other.service"),
        ("unit_sha256", "c" * 64),
        ("native_uid", 1002),
        ("version", "other"),
        ("url", "http://127.0.0.1:9999"),
        ("executable_sha256", "d" * 64),
        ("dataset_device", 2),
        ("dataset_inode", 3),
    ],
)
def test_even_self_consistent_changed_owner_pins_are_not_the_enrolled_backend(key, value):
    with pytest.raises(HostOwnerError):
        validate_evidence(evidence(**{key: value}), ENROLLED, now=100)


@pytest.mark.parametrize(
    "key,value",
    [
        ("pid", True),
        ("pid", "123"),
        ("process_start_ticks", 0),
        ("dataset_inode", "2"),
        ("native_uid", False),
        ("registration_id", "invalid"),
        ("boot_id", "invalid"),
        ("format", "untrusted-v1"),
    ],
)
def test_coerced_or_malformed_host_fields_are_not_trusted(key, value):
    with pytest.raises(HostOwnerError):
        validate_evidence(evidence(**{key: value}), ENROLLED, now=100)


@pytest.mark.parametrize("now", [98.9, 105.1, float("nan"), float("inf")])
def test_old_future_or_nonfinite_observation_refuses(now):
    with pytest.raises(HostOwnerError):
        validate_evidence(evidence(), ENROLLED, now=now)


def test_epoch_tampering_and_extra_secret_fields_refuse_without_echoing_values():
    for changed in [{"owner_epoch": "c" * 64}, {"password": "PRIVATE_TEST_CREDENTIAL"}]:
        raw = {**evidence(), **changed}
        with pytest.raises(HostOwnerError) as caught:
            validate_evidence(raw, ENROLLED, now=100)
        assert "PRIVATE_TEST_CREDENTIAL" not in str(caught.value)


@pytest.mark.parametrize(
    "change",
    [
        {"native_uid": 0},
        {"client_uid": 0},
        {"url": "http://10.0.0.19:4096"},
        {"url": "http://user:secret@127.0.0.1:4096"},
        {"url": "http://127.0.0.1:4096/path"},
        {"unit": "--unapproved.service"},
        {"dataset_path": "../other"},
        {"registration_path": "/a/../b"},
    ],
)
def test_owner_enrollment_rejects_root_runtime_broad_endpoints_and_ambiguous_paths(change):
    with pytest.raises(ValueError):
        HostOwnerEnrollment(**{**CONFIG, **change})


def test_private_helper_file_read_refuses_symlinks_other_owners_and_world_readable_secrets(
    tmp_path,
):
    p = tmp_path / "registration"
    p.write_text("PRIVATE_TEST_CREDENTIAL")
    p.chmod(0o600)
    assert helper.read_file(p, os.getuid(), private=True) == b"PRIVATE_TEST_CREDENTIAL"
    p.chmod(0o644)
    with pytest.raises(ValueError):
        helper.read_file(p, os.getuid(), private=True)
    p.chmod(0o600)
    with pytest.raises(ValueError):
        helper.read_file(p, os.getuid() + 1, private=True)
    link = tmp_path / "link"
    link.symlink_to(p)
    with pytest.raises(OSError):
        helper.read_file(link, os.getuid(), private=True)


@pytest.mark.parametrize(
    "change",
    [
        {"st_uid": 1002},
        {"st_mode": stat.S_IFREG | 0o644},
        {"st_mode": stat.S_IFLNK | 0o600},
        {"st_dev": 2},
        {"st_ino": 3},
    ],
)
def test_dataset_identity_check_uses_only_metadata_and_refuses_replacement(monkeypatch, change):
    values = {"st_mode": stat.S_IFREG | 0o600, "st_uid": 1000, "st_dev": 1, "st_ino": 2}
    values.update(change)
    calls = []

    def meta(path, *, follow_symlinks):
        calls.append((path, follow_symlinks))
        return SimpleNamespace(**values)

    monkeypatch.setattr(helper.os, "stat", meta)
    monkeypatch.setattr(
        "builtins.open", lambda *a, **k: pytest.fail("dataset contents must not be read")
    )
    with pytest.raises(ValueError):
        helper.OwnerProbe(CONFIG).dataset()
    assert calls == [(CONFIG["dataset_path"], False)]


@pytest.mark.parametrize(
    "change", ["unit", "process", "dataset", "open_dataset", "registration", "info"]
)
def test_cross_probe_change_never_returns_mixed_owner_evidence(monkeypatch, change):
    probe = helper.OwnerProbe(CONFIG)
    probe.unit = lambda: 123
    probe.process = lambda pid: 100
    probe.executable = lambda pid, start: CONFIG["executable_sha256"]
    probe.dataset = lambda: (1, 2)
    probe.open_dataset = lambda pid, identity: True
    registration = {
        "id": "00000000-0000-4000-8000-000000000002",
        "password": "PRIVATE_TEST_CREDENTIAL",
    }
    probe.registration = lambda pid: copy.deepcopy(registration)
    info = {"pid": 123, "version": "2.0.32", "urls": [CONFIG["url"]]}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            if change == "unit":
                probe.unit = lambda: 124
            elif change == "process":
                probe.process = lambda pid: 101
            elif change == "dataset":
                probe.dataset = lambda: (1, 3)
            elif change == "open_dataset":
                probe.open_dataset = lambda pid, identity: False
            elif change == "registration":
                probe.registration = lambda pid: {**registration, "id": "different"}
            elif change == "info":
                info["pid"] = 124
            return json.dumps(info).encode()

    def request(req, timeout):
        assert req.full_url == CONFIG["url"] + "/api/info"
        assert req.get_header("Authorization").startswith("Basic ")
        return Response()

    probe.opener = SimpleNamespace(open=request)
    with pytest.raises(ValueError):
        probe.status()


@pytest.fixture
def info_endpoint():
    class Info(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(self.server.status)
            if self.server.location is not None:
                self.send_header("Location", self.server.location)
            body = self.server.body
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Info)
    server.url = f"http://127.0.0.1:{server.server_port}"
    server.status, server.location, server.seen = 200, None, []
    server.body = json.dumps(
        {"pid": 123, "version": CONFIG["version"], "urls": [server.url]}
    ).encode()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def isolated_probe(monkeypatch, endpoint):
    """Real HTTP, with synthetic physical owner evidence and no Native DB I/O."""
    probe = helper.OwnerProbe({**CONFIG, "url": endpoint.url})
    probe.unit = lambda: 123
    probe.process = lambda pid: 100
    probe.executable = lambda pid, start: CONFIG["executable_sha256"]
    probe.dataset = lambda: (1, 2)
    probe.open_dataset = lambda pid, identity: True
    probe.registration = lambda pid: {
        "id": "00000000-0000-4000-8000-000000000002",
        "password": "SYNTHETIC_FIRST_PASSWORD",
    }

    def boot_id(path, *args, **kwargs):
        assert path == "/proc/sys/kernel/random/boot_id"
        return io.StringIO("00000000-0000-4000-8000-000000000001\n")

    monkeypatch.setattr("builtins.open", boot_id)
    return probe


def test_repeated_real_http_keeps_fresh_credentials_and_evidence_without_tls_or_proxy(
    monkeypatch, info_endpoint
):
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")

    def no_tls(*args, **kwargs):
        pytest.fail("fixed HTTP owner probe must work without TLS context/trust-store setup")

    monkeypatch.setattr(helper.urllib.request, "HTTPSHandler", no_tls)
    probe = isolated_probe(monkeypatch, info_endpoint)
    observed = iter([100.0, 101.0, 102.0])
    monkeypatch.setattr(helper, "time", SimpleNamespace(time=lambda: next(observed)))
    first = probe.status()
    original = probe.registration(123)
    probe.registration = lambda pid: {**original, "password": "SYNTHETIC_SECOND_PASSWORD"}
    second = probe.status()
    info_endpoint.body = b'{"pid":124,"version":"2.0.32","urls":[]}'
    with pytest.raises(ValueError, match="authenticated_native_info"):
        probe.status()
    assert first["owner_epoch"] == second["owner_epoch"]
    assert (first["observed_at"], second["observed_at"]) == (100.0, 101.0)
    assert info_endpoint.seen == [
        ("/api/info", "Basic b3BlbmNvZGU6U1lOVEhFVElDX0ZJUlNUX1BBU1NXT1JE"),
        ("/api/info", "Basic b3BlbmNvZGU6U1lOVEhFVElDX1NFQ09ORF9QQVNTV09SRA=="),
        ("/api/info", "Basic b3BlbmNvZGU6U1lOVEhFVElDX1NFQ09ORF9QQVNTV09SRA=="),
    ]
    assert "PASSWORD" not in json.dumps([first, second])


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", ["/another", "http://127.0.0.1:1/stolen"])
def test_owner_http_redirect_is_rejected_without_forwarding_credentials(
    monkeypatch, info_endpoint, code, location
):
    probe = isolated_probe(monkeypatch, info_endpoint)
    info_endpoint.status, info_endpoint.location = code, location
    with pytest.raises(ValueError, match="native_info_rejected"):
        probe.status()
    assert len(info_endpoint.seen) == 1 and info_endpoint.seen[0][0] == "/api/info"


@pytest.mark.parametrize("code", [400, 401, 403, 500, 503])
def test_http_errors_never_become_owner_evidence(monkeypatch, info_endpoint, code):
    probe = isolated_probe(monkeypatch, info_endpoint)
    info_endpoint.status = code
    with pytest.raises(ValueError, match="native_info_rejected"):
        probe.status()
    assert len(info_endpoint.seen) == 1


def test_http_error_response_is_closed_even_before_response_context_enters(
    monkeypatch, info_endpoint
):
    probe = isolated_probe(monkeypatch, info_endpoint)
    body = io.BytesIO(b"PRIVATE_SYNTHETIC_ERROR")

    def reject(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 503, "unavailable", {}, body)

    probe.opener = SimpleNamespace(open=reject)
    with pytest.raises(ValueError, match="^native_info_rejected$") as caught:
        probe.status()
    assert body.closed and "PRIVATE_SYNTHETIC_ERROR" not in str(caught.value)


@pytest.mark.parametrize("body", [b"not-json", b"x" * 65537])
def test_reused_http_client_still_rejects_invalid_or_oversized_info(
    monkeypatch, info_endpoint, body
):
    probe = isolated_probe(monkeypatch, info_endpoint)
    info_endpoint.body = body
    with pytest.raises(ValueError):
        probe.status()


@pytest.mark.parametrize("scheme", ["file", "data", "ftp", "https"])
def test_owner_transport_does_not_gain_unused_protocol_handlers(tmp_path, scheme):
    marker = tmp_path / "not-an-owner"
    marker.write_text("PRIVATE_SYNTHETIC_FILE")
    urls = {
        "file": marker.as_uri(),
        "data": "data:text/plain,PRIVATE_SYNTHETIC_FILE",
        "ftp": "ftp://127.0.0.1:1/never",
        "https": "https://127.0.0.1:1/never",
    }
    with pytest.raises(urllib.error.URLError, match="unknown url type"):
        helper.http_opener().open(urllib.request.Request(urls[scheme]), timeout=0.1)


class Writer:
    def __init__(self, uid=0):
        self.uid, self.closed, self.sent = uid, False, b""

    def get_extra_info(self, name):
        return SimpleNamespace(getsockopt=lambda *args: struct.pack("3i", 1, self.uid, 0))

    def write(self, b):
        self.sent += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.fixture
def fake_socket(monkeypatch):
    monkeypatch.setattr(host_owner.sys, "platform", "linux")
    monkeypatch.setattr(host_owner.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(host_owner.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(host_owner.time, "time", lambda: 100.0)
    probe = LinuxHostOwnerProbe(ENROLLED, Path("/run/jt-opencode-owner/status.sock"))
    monkeypatch.setattr(probe, "socket_state", lambda: (1, 2, 0, 1001, stat.S_IFSOCK | 0o660))
    writer = Writer()
    reader = SimpleNamespace(
        readline=AsyncMock(
            return_value=json.dumps({"ok": True, "evidence": evidence()}).encode() + b"\n"
        )
    )
    monkeypatch.setattr(
        host_owner.asyncio, "open_unix_connection", AsyncMock(return_value=(reader, writer))
    )
    return probe, reader, writer


@pytest.mark.parametrize("uid", [0, 1000])
async def test_fixed_unix_request_and_enrolled_socket_activation_peer_are_verified(
    fake_socket, uid
):
    probe, reader, writer = fake_socket
    writer.uid = uid
    got = await probe.read()
    assert got.pid == 123 and writer.sent == b"STATUS\n" and writer.closed


@pytest.mark.parametrize("uid", [1001, 1002, 65534])
async def test_nonenrolled_listening_peer_does_not_become_a_host_certificate(fake_socket, uid):
    probe, reader, writer = fake_socket
    writer.uid = uid
    with pytest.raises(HostOwnerError):
        await probe.read()
    assert not writer.sent and writer.closed


@pytest.mark.parametrize(
    "reply",
    [
        b'{"ok":false,"error":"PRIVATE_TEST_CREDENTIAL"}\n',
        b'{"ok":true,"ok":false}\n',
        b'{"ok":NaN}\n',
        b"{}",
        b"x" * 16385 + b"\n",
    ],
)
async def test_negative_duplicate_nonfinite_truncated_or_oversized_reply_is_generic(
    fake_socket, reply
):
    probe, reader, writer = fake_socket
    reader.readline.return_value = reply
    with pytest.raises(HostOwnerError) as caught:
        await probe.read()
    assert "PRIVATE_TEST_CREDENTIAL" not in str(caught.value) and writer.closed


async def test_socket_replacement_during_exchange_refuses(fake_socket, monkeypatch):
    probe, reader, writer = fake_socket
    calls = 0

    def state():
        nonlocal calls
        calls += 1
        return 1, 2 if calls == 1 else 3, 0, 1001, stat.S_IFSOCK | 0o660

    monkeypatch.setattr(probe, "socket_state", state)
    with pytest.raises(HostOwnerError):
        await probe.read()
    assert writer.closed and not writer.sent


async def test_cancellation_closes_the_readonly_socket_and_propagates(fake_socket):
    probe, reader, writer = fake_socket
    waiting = asyncio.Event()

    async def block():
        waiting.set()
        await asyncio.Event().wait()

    reader.readline.side_effect = block
    task = asyncio.create_task(probe.read())
    await asyncio.wait_for(waiting.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer.closed


def test_root_managed_binary_hash_cache_invalidates_on_file_identity_change(monkeypatch):
    content = [b"approved-executable"]
    metadata = {
        "st_mode": stat.S_IFREG | 0o755,
        "st_uid": 0,
        "st_dev": 1,
        "st_ino": 2,
        "st_size": 19,
        "st_mtime_ns": 1,
        "st_ctime_ns": 1,
    }

    class Binary(io.BytesIO):
        def fileno(self):
            return 42

    monkeypatch.setattr("builtins.open", lambda *a, **k: Binary(content[0]))
    monkeypatch.setattr(helper.os, "fstat", lambda fd: SimpleNamespace(**metadata))
    c = {**CONFIG, "executable_sha256": helper.hashlib.sha256(content[0]).hexdigest()}
    probe = helper.OwnerProbe(c)
    assert probe.executable(123, 100) == c["executable_sha256"]
    content[0] = b"different-executable"
    metadata["st_ctime_ns"] += 1
    with pytest.raises(ValueError):
        probe.executable(123, 100)


@pytest.mark.parametrize(
    "bad",
    ["parent_owner", "parent_writable", "parent_symlink", "socket_owner", "socket_world_readable"],
)
def test_socket_root_ownership_directory_chain_and_restricted_mode_are_required(monkeypatch, bad):
    probe = LinuxHostOwnerProbe(ENROLLED, Path("/run/jt-opencode-owner/status.sock"))

    def meta(path):
        target = path == probe.socket_path
        values = {
            "st_mode": stat.S_IFSOCK | 0o660 if target else stat.S_IFDIR | 0o755,
            "st_uid": 0,
            "st_gid": 1001,
            "st_dev": 1,
            "st_ino": 2,
        }
        if str(path) == "/run/jt-opencode-owner":
            if bad == "parent_owner":
                values["st_uid"] = 1000
            elif bad == "parent_writable":
                values["st_mode"] = stat.S_IFDIR | 0o775
            elif bad == "parent_symlink":
                values["st_mode"] = stat.S_IFLNK | 0o755
        if target and bad == "socket_owner":
            values["st_uid"] = 1000
        if target and bad == "socket_world_readable":
            values["st_mode"] = stat.S_IFSOCK | 0o666
        return SimpleNamespace(**values)

    monkeypatch.setattr(Path, "lstat", meta)
    with pytest.raises(HostOwnerError):
        probe.socket_state()


@pytest.mark.parametrize("value", [False, 1, "true"])
def test_dataset_in_use_requires_positive_strict_kernel_metadata_evidence(value):
    with pytest.raises(HostOwnerError):
        validate_evidence(evidence(dataset_open_in_owner=value), ENROLLED, now=100)


@pytest.mark.parametrize(
    "case", ["match", "closed", "different_inode", "different_target", "not_regular", "over_limit"]
)
def test_open_descriptor_proof_does_not_open_dataset_contents(monkeypatch, case):
    seen = []

    def names(path):
        assert path == "/proc/123/fd"
        return [str(i) for i in range(8193)] if case == "over_limit" else ["22", "../untrusted"]

    def target(path):
        seen.append(path)
        assert path == "/proc/123/fd/22"
        if case == "closed":
            raise FileNotFoundError
        return "/another/dataset" if case == "different_target" else CONFIG["dataset_path"]

    def meta(path):
        assert path == "/proc/123/fd/22"
        return SimpleNamespace(
            st_mode=stat.S_IFSOCK if case == "not_regular" else stat.S_IFREG | 0o600,
            st_dev=1,
            st_ino=3 if case == "different_inode" else 2,
        )

    monkeypatch.setattr(helper, "os", SimpleNamespace(listdir=names, readlink=target, stat=meta))
    monkeypatch.setattr(
        "builtins.open", lambda *a, **k: pytest.fail("native dataset contents must not be opened")
    )
    if case == "match":
        assert helper.OwnerProbe(CONFIG).open_dataset(123, (1, 2)) is True
    else:
        with pytest.raises(ValueError):
            helper.OwnerProbe(CONFIG).open_dataset(123, (1, 2))
