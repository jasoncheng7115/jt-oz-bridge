"""Own temporary credentials and synthetic SSH replies; never live Human rows."""

import asyncio
import gc
import hashlib
import json
import time
import weakref
from dataclasses import dataclass

import pytest

from jt_oz_bridge.adapters.zulip.uploads import upload_reference
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services import upload_associations as m
from jt_oz_bridge.services.prompt_attachments import associated_uploads
from jt_oz_bridge.storage.durable import digest


@dataclass
class Pin:
    raw: bytes
    sha256: str

    def read(self):
        return self.raw


def setup(tmp_path, monkeypatch, change=None):
    key = tmp_path / "key"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY\n")
    key.chmod(0o400)
    hosts = tmp_path / "hosts"
    hosts.write_text("metadata.invalid ssh-ed25519 SYNTHETIC-NOT-A-REAL-KEY\n")
    config = m.SSHAssociationConfig(
        realm_id="realm",
        realm_url="https://chat.example",
        channel_ids=frozenset({10}),
        host="metadata.invalid",
        user="root",
        key_file=key,
        key_sha256=hashlib.sha256(key.read_text().rstrip("\r\n").encode()).hexdigest(),
        known_hosts_file=hosts,
        known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
        helper_sha256="a" * 64,
        remote_policy_sha256="b" * 64,
        installed_evidence_sha256="c" * 64,
    )
    raw = config.model_dump_json().encode()
    pin = Pin(raw, hashlib.sha256(raw).hexdigest())

    def known(path, sha):
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise AccessDenied("fixture root pin changed")
        return data

    monkeypatch.setattr(m, "pinned_root_bytes", known)
    seen = []

    async def exchange(cfg, data):
        seen.append((cfg, json.loads(data)))
        request = seen[-1][1]
        reply = {
            "format": m.FORMAT,
            "nonce": request["nonce"],
            "allowed": True,
            "source_sha256": digest(request["source"]),
            "upload_paths": request["upload_paths"],
            "files": [
                {
                    "upload_path": p,
                    "filename": "原始 [file].txt",
                    "mime_type": "text/plain",
                    "size": 23,
                }
                for p in request["upload_paths"]
            ],
            "observation_sha256": "d" * 64,
            "helper_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
            "observed_at": time.time(),
            "mode": "human-source",
            "transaction_read_only": True,
        }
        if change:
            reply = change(reply, request, pin)
        return reply if isinstance(reply, bytes) else json.dumps(reply).encode()

    monkeypatch.setattr(m, "ssh_exchange", exchange)
    source = HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic="Docs",
        message_id=100,
        revision=0,
        author_id=7,
        text="[original](/user_uploads/2/random/file.txt)",
    )
    upload = upload_reference("/user_uploads/2/random/file.txt", config.realm_url)
    return m.SSHUploadAssociations(pin), source, (upload,), seen, pin, config


async def test_exact_source_nonce_paths_metadata_and_root_pins_issue_only_weak_short_lived_witness(
    tmp_path, monkeypatch
):
    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch)
    witness = await associated_uploads(reader, source, uploads)
    assert reader.current(witness) and len(seen) == 1
    assert (
        witness.files[0].filename == "原始 [file].txt"
        and witness.files[0].filename != uploads[0].filename
    )
    assert witness.source_sha256 == digest(source.model_dump(mode="json"))
    assert not reader.current(witness.model_copy())
    assert source.text not in witness.model_dump_json()
    ref = weakref.ref(witness)
    del witness
    gc.collect()
    assert ref() is None


@pytest.mark.parametrize(
    "kind",
    [
        "nonce",
        "source",
        "paths",
        "file-path",
        "helper",
        "policy",
        "mode",
        "allowed",
        "extra",
        "old",
        "future",
        "unsafe-name",
        "duplicate-json",
        "read-write-transaction",
    ],
)
async def test_cross_source_or_forged_remote_reply_never_mints_authority(
    tmp_path, monkeypatch, kind
):
    def change(reply, request, pin):
        if kind == "nonce":
            reply["nonce"] = "0" * 32
        elif kind == "source":
            reply["source_sha256"] = "0" * 64
        elif kind == "paths":
            reply["upload_paths"] = ["/user_uploads/2/private/other.txt"]
        elif kind == "file-path":
            reply["files"][0]["upload_path"] = "/user_uploads/2/private/other.txt"
        elif kind == "helper":
            reply["helper_sha256"] = "0" * 64
        elif kind == "policy":
            reply["policy_sha256"] = "0" * 64
        elif kind == "mode":
            reply["mode"] = "operator-bot-only"
        elif kind == "allowed":
            reply["allowed"] = 1
        elif kind == "extra":
            reply["sql"] = "select private"
        elif kind == "old":
            reply["observed_at"] = time.time() - 10
        elif kind == "future":
            reply["observed_at"] = time.time() + 10
        elif kind == "unsafe-name":
            reply["files"][0]["filename"] = "../secret"
        elif kind == "duplicate-json":
            return b'{"allowed":true,"allowed":false}'
        elif kind == "read-write-transaction":
            reply["transaction_read_only"] = False
        return reply

    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch, change)
    with pytest.raises(ValueError):
        await reader.authorize(source, uploads)
    assert len(seen) == 1 and not reader._witnesses


@pytest.mark.parametrize(
    "kind",
    ["bot", "deleted", "realm", "channel", "empty", "duplicate", "key-mode", "bad-key", "root-pin"],
)
async def test_untrusted_source_or_credential_stops_before_ssh(tmp_path, monkeypatch, kind):
    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch)
    if kind in {"bot", "deleted", "realm", "channel"}:
        update = {
            "bot": {"is_bot": True},
            "deleted": {"deleted": True},
            "realm": {"realm_id": "other"},
            "channel": {"channel_id": 99},
        }[kind]
        source = source.model_copy(update=update)
    elif kind == "empty":
        uploads = ()
    elif kind == "duplicate":
        uploads = uploads + uploads
    elif kind == "key-mode":
        cfg.key_file.chmod(0o644)
    elif kind == "bad-key":
        cfg.key_file.chmod(0o600)
        cfg.key_file.write_text("wrong secret, not an SSH key")
        cfg.key_file.chmod(0o400)
    elif kind == "root-pin":
        pin.raw = b"{}"
    with pytest.raises(ValueError):
        await reader.authorize(source, uploads)
    assert not seen


async def test_root_known_host_changes_and_expiry_revoke_existing_witness(tmp_path, monkeypatch):
    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch)
    witness = await reader.authorize(source, uploads)
    assert reader.current(witness)
    with monkeypatch.context() as scoped:
        scoped.setattr(m.time, "monotonic", lambda: witness.expires_at + 0.1)
        assert not reader.current(witness)
    cfg.known_hosts_file.write_text("changed host key")
    assert not reader.current(witness)


@pytest.mark.parametrize("kind", ["content", "mode", "owner", "missing", "symlink"])
async def test_key_replacement_or_permission_change_revokes_witness_and_prevents_another_ssh(
    tmp_path, monkeypatch, kind
):
    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch)
    witness = await reader.authorize(source, uploads)
    assert reader.current(witness)
    if kind == "mode":
        cfg.key_file.chmod(0o600)
    elif kind == "owner":
        uid = m.os.geteuid()
        monkeypatch.setattr(m.os, "geteuid", lambda: uid + 1)
    elif kind == "missing":
        cfg.key_file.unlink()
    elif kind == "symlink":
        other = tmp_path / "other-key"
        cfg.key_file.rename(other)
        cfg.key_file.symlink_to(other)
    else:
        cfg.key_file.chmod(0o600)
        cfg.key_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nDIFFERENT-SYNTHETIC-KEY\n")
        cfg.key_file.chmod(0o400)
    assert not reader.current(witness)
    with pytest.raises((ValueError, OSError)):
        await reader.authorize(source, uploads)
    assert len(seen) == 1


async def test_key_changed_during_exchange_cannot_publish_an_original_witness(
    tmp_path, monkeypatch
):
    def change(reply, request, pin):
        key = tmp_path / "key"
        key.chmod(0o600)
        key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nREPLACED-DURING-EXCHANGE\n")
        key.chmod(0o400)
        return reply

    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch, change)
    with pytest.raises(ValueError):
        await reader.authorize(source, uploads)
    assert len(seen) == 1 and not reader._witnesses


class Input:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True


class Process:
    def __init__(self, stdout=b"{}", stderr=b"", code=0, hang=False):
        self.stdin = Input()
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.returncode = None
        self.code = code
        self.hang = hang
        self.killed = False
        self.event = asyncio.Event()
        if not hang:
            self.stdout.feed_data(stdout)
            self.stdout.feed_eof()
            self.stderr.feed_data(stderr)
            self.stderr.feed_eof()

    async def wait(self):
        if self.hang:
            await self.event.wait()
        self.returncode = self.code
        return self.code

    def kill(self):
        self.killed = True
        self.code = -9
        self.event.set()


@pytest.mark.parametrize("kind", ["success", "stdout-limit", "stderr-limit", "exit", "timeout"])
async def test_fixed_ssh_argv_stdin_caps_timeout_and_cleanup(tmp_path, monkeypatch, kind):
    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch)
    process = Process(
        stdout=b"x" * (m.RESPONSE_LIMIT + 1) if kind == "stdout-limit" else b"{}",
        stderr=b"PRIVATE-ERROR" * 400 if kind == "stderr-limit" else b"",
        code=255 if kind == "exit" else 0,
        hang=kind == "timeout",
    )
    observed = []

    async def create(*argv, **kwargs):
        observed.append((argv, kwargs))
        return process

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", create)
    # setup() mocked the high-level exchange; restore the actual primitive.
    exchange = REAL_EXCHANGE
    if kind == "timeout":
        cfg = cfg.model_copy(update={"timeout_seconds": 0.02})
    body = b'{"source":"data; never a remote shell command"}'
    if kind == "success":
        assert await exchange(cfg, body) == b"{}"
    else:
        with pytest.raises(ValueError):
            await exchange(cfg, body)
    argv, kwargs = observed[0]
    assert argv[0] == "/usr/bin/ssh" and argv[-2] == "root@metadata.invalid"
    assert argv[-1] == m.REMOTE_HELPER
    assert "-F" in argv and "/dev/null" in argv and "ProxyCommand=none" in argv
    assert body.decode() not in argv and process.stdin.data == body and process.stdin.closed
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"}
    assert process.returncode is not None
    if kind == "timeout":
        assert process.killed


REAL_EXCHANGE = m.ssh_exchange


async def test_actual_pipe_fits_ten_maximum_unicode_filename_metadata(tmp_path, monkeypatch):
    from urllib.parse import quote

    reader, source, uploads, seen, pin, cfg = setup(tmp_path, monkeypatch)
    name = "\U00010400" * 255
    paths = ["/user_uploads/2/random-" + str(i) + "/" + quote(name, safe="-._~") for i in range(10)]
    reply = {
        "format": m.FORMAT,
        "nonce": "a" * 32,
        "allowed": True,
        "source_sha256": "a" * 64,
        "upload_paths": paths,
        "files": [
            {"upload_path": path, "filename": name, "mime_type": "text/plain", "size": 1}
            for path in paths
        ],
        "observation_sha256": "b" * 64,
        "helper_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "observed_at": time.time(),
        "mode": "human-source",
        "transaction_read_only": True,
    }
    encoded = json.dumps(reply, ensure_ascii=False).encode()
    assert 65536 < len(encoded) <= m.RESPONSE_LIMIT
    process = Process(stdout=encoded)

    async def create(*args, **kwargs):
        return process

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", create)
    received = await REAL_EXCHANGE(cfg, b"{}")
    assert (
        received == encoded
        and len(m.AssociationReply.model_validate(json.loads(received)).files) == 10
    )
