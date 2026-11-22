"""Root-configured fixed SSH transport for read-only Zulip attachment claims.

The SSH key must have a server-side forced command. No remote command, SQL or
shell argument is accepted from a Human, model, upload URL or request payload.
"""

import asyncio
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4
from weakref import WeakValueDictionary

from pydantic import Field, StrictInt, field_validator

from jt_oz_bridge.adapters.zulip.uploads import UploadReference, upload_reference
from jt_oz_bridge.config import validate_endpoint
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.root_files import pinned_root_bytes
from jt_oz_bridge.security.secrets import resolve_secret
from jt_oz_bridge.services.prompt_attachments import SourceUploadAssociation, SourceUploadDescriptor
from jt_oz_bridge.storage.durable import digest

FORMAT: Literal["jt-oz-upload-association-v1"] = "jt-oz-upload-association-v1"
REMOTE_HELPER = "/usr/local/libexec/jt-oz-upload-association"
RESPONSE_LIMIT = 128 * 1024


class AssociationPin(Protocol):
    @property
    def sha256(self) -> str: ...
    def read(self) -> bytes: ...


class SSHAssociationConfig(ControlModel):
    format: Literal["jt-oz-upload-association-v1"] = FORMAT
    realm_id: str = Field(min_length=1, max_length=255)
    realm_url: str
    channel_ids: frozenset[StrictInt] = Field(min_length=1, max_length=100)
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    port: StrictInt = Field(default=22, gt=0, lt=65536)
    key_file: Path
    key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    known_hosts_file: Path
    known_hosts_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    helper_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    remote_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    timeout_seconds: float = Field(default=5, gt=0, le=8, allow_inf_nan=False)

    @field_validator("realm_url")
    @classmethod
    def fixed_origin(cls, value: str) -> str:
        from urllib.parse import urlsplit

        validate_endpoint(value, False)
        if urlsplit(value).path not in {"", "/"} or value.endswith("/"):
            raise ValueError("canonical_realm_origin_required")
        return value

    @field_validator("key_file", "known_hosts_file")
    @classmethod
    def trusted_path(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts or re.search(r'[\s\\"\x00]', str(value)):
            raise ValueError("fixed_unambiguous_ssh_path_required")
        return value

    @field_validator("channel_ids")
    @classmethod
    def positive_channels(cls, value: frozenset[int]) -> frozenset[int]:
        if any(not 0 < x < 10**18 for x in value):
            raise ValueError("positive_channel_ids_required")
        return value


class AssociationReply(ControlModel):
    format: Literal["jt-oz-upload-association-v1"]
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    allowed: Literal[True]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    upload_paths: tuple[str, ...] = Field(min_length=1, max_length=10)
    files: tuple[SourceUploadDescriptor, ...] = Field(min_length=1, max_length=10)
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    helper_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    mode: Literal["human-source"]
    transaction_read_only: Literal[True]


async def _bounded(stream: asyncio.StreamReader, limit: int) -> bytes:
    result = bytearray()
    while True:
        part = await stream.read(8192)
        if not part:
            return bytes(result)
        if len(result) + len(part) > limit:
            raise AccessDenied("attachment_metadata_response_limit")
        result.extend(part)


async def ssh_exchange(config: SSHAssociationConfig, payload: bytes) -> bytes:
    """One fixed binary/argv, EOF-delimited JSON, bounded pipes and lifetime."""
    argv = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-T",
        "-p",
        str(config.port),
        "-i",
        str(config.key_file),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(config.known_hosts_file),
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=3",
        "-o",
        "LogLevel=ERROR",
        config.user + "@" + config.host,
        REMOTE_HELPER,
    ]
    process = None
    tasks: list[asyncio.Task[Any]] = []
    try:
        async with asyncio.timeout(config.timeout_seconds):
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"},
                start_new_session=True,
            )
            assert (
                process.stdin is not None
                and process.stdout is not None
                and process.stderr is not None
            )
            process.stdin.write(payload)
            await process.stdin.drain()
            process.stdin.close()
            tasks = [
                asyncio.create_task(_bounded(process.stdout, RESPONSE_LIMIT)),
                asyncio.create_task(_bounded(process.stderr, 4096)),
                asyncio.create_task(process.wait()),
            ]
            output, _error, status = await asyncio.gather(*tasks)
            if status != 0 or not isinstance(output, bytes):
                raise AccessDenied("attachment_metadata_remote_rejected")
            return output
    except (OSError, TimeoutError, BrokenPipeError, ConnectionError):
        raise AccessDenied("attachment_metadata_transport_unavailable") from None
    finally:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class SSHUploadAssociations:
    def __init__(self, pin: AssociationPin) -> None:
        self.pin = pin
        self._witnesses: WeakValueDictionary[int, SourceUploadAssociation] = WeakValueDictionary()
        self._config: SSHAssociationConfig | None = None
        self._slots = asyncio.Semaphore(4)

    def configuration(self) -> SSHAssociationConfig:
        raw = self.pin.read()
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != self.pin.sha256:
            raise AccessDenied("attachment_metadata_enrollment_changed")
        config = SSHAssociationConfig.model_validate(strict_loads(raw))
        pinned_root_bytes(config.known_hosts_file, config.known_hosts_sha256)
        info = config.key_file.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o400
        ):
            raise AccessDenied("attachment_metadata_service_key_permissions_changed")
        key = resolve_secret("file:" + str(config.key_file)).get_secret_value()
        if (
            not key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            or hashlib.sha256(key.encode()).hexdigest() != config.key_sha256
        ):
            raise AccessDenied("attachment_metadata_service_key_changed")
        return config

    async def authorize(
        self, source: HumanMessage, uploads: tuple[UploadReference, ...]
    ) -> SourceUploadAssociation:
        source = HumanMessage.model_validate(source.model_dump(mode="json"))
        config = self.configuration()
        if (
            source.is_bot
            or source.deleted
            or source.realm_id != config.realm_id
            or source.channel_id not in config.channel_ids
            or not 1 <= len(uploads) <= 10
        ):
            raise AccessDenied("attachment_metadata_source_scope_denied")
        paths = tuple("/user_uploads/" + upload.path_id for upload in uploads)
        if len(set(paths)) != len(paths) or any(
            upload_reference(path, config.realm_url) != upload
            for path, upload in zip(paths, uploads, strict=True)
        ):
            raise AccessDenied("attachment_metadata_upload_scope_denied")
        nonce = uuid4().hex
        payload = {
            "format": FORMAT,
            "nonce": nonce,
            "source": source.model_dump(mode="json"),
            "upload_paths": list(paths),
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        if len(encoded) > 4 * 1024**2:
            raise AccessDenied("attachment_metadata_request_limit")
        async with self._slots:
            start = time.monotonic()
            wall = time.time()
            raw = await ssh_exchange(config, encoded)
        value = strict_loads(raw)
        if (
            not isinstance(value, dict)
            or value.get("allowed") is not True
            or value.get("transaction_read_only") is not True
        ):
            raise AccessDenied("attachment_original_message_file_not_authorized")
        reply = AssociationReply.model_validate(value)
        now = time.monotonic()
        if (
            self.configuration() != config
            or now >= start + 5
            or reply.nonce != nonce
            or reply.source_sha256 != digest(source.model_dump(mode="json"))
            or reply.upload_paths != paths
            or tuple(file.upload_path for file in reply.files) != paths
            or reply.helper_sha256 != config.helper_sha256
            or reply.policy_sha256 != config.remote_policy_sha256
            or not wall - 2 <= reply.observed_at <= time.time() + 2
        ):
            raise AccessDenied("attachment_metadata_response_scope_or_boundary_changed")
        witness = SourceUploadAssociation(
            source_sha256=reply.source_sha256,
            upload_paths=paths,
            files=reply.files,
            observation_sha256=reply.observation_sha256,
            observed_at=start,
            expires_at=start + 5,
        )
        if len(self._witnesses) >= 32:
            raise AccessDenied("attachment_metadata_witness_capacity")
        self._config = config
        self._witnesses[id(witness)] = witness
        return witness

    def current(self, witness: SourceUploadAssociation) -> bool:
        try:
            now = time.monotonic()
            return bool(
                self._witnesses.get(id(witness)) is witness
                and self.configuration() == self._config
                and witness.observed_at <= now < witness.expires_at
            )
        except (ValueError, OSError, TypeError):
            return False
