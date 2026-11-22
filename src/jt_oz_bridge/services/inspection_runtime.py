"""Explicit Linux local-observer sidecar, with no consumer lease or Native writes."""

import asyncio
import hashlib
import os
import signal
from pathlib import Path
from typing import Any, Literal, Self

import httpx
from pydantic import Field, field_validator, model_validator
from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment, LinuxHostOwnerProbe
from jt_oz_bridge.adapters.opencode.inspection import INSPECTION_READS, V2SessionInspection
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.config import Settings
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.inspection import InspectionProtocolQuery, InspectionProtocolResponse
from jt_oz_bridge.domain.runtime_readiness import ConsumerLeaseObservation, RuntimeModeSnapshot
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.root_files import root_bytes
from jt_oz_bridge.security.secrets import resolve_secret
from jt_oz_bridge.services.inspection_socket import InspectionSocketServer
from jt_oz_bridge.services.local_inspection import InspectionRuntimeScope, LocalSessionInspector
from jt_oz_bridge.services.runtime_enrollment import RootFile, read_enrollment
from jt_oz_bridge.services.runtime_status import RuntimeStatusReader
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database
from jt_oz_bridge.storage.sessions import SessionFactory

INSPECTION_SEMANTICS = hashlib.sha256(
    b"jt-oz-bridge:OpenCode2.0.32:backend-catalog-and-repeated-resource-observation-only:v1"
).hexdigest()


class InspectionQualification(ControlModel):
    format: Literal["native-local-inspection-read-observation-v1"]
    passed: Literal[True]
    backend_id: str = Field(min_length=1, max_length=255)
    backend_identity: str = Field(min_length=1, max_length=255)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    upstream_version: Literal["2.0.32"]
    read_scope: Literal["backend-catalog-and-observed-session-state"]
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_operations: frozenset[str]
    observed_owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator_review: Literal["read-only-local-observation-scope-reviewed-no-execution-promotion"]

    @model_validator(mode="after")
    def qualified(self) -> Self:
        if (
            self.contract_sha256 != INSTALLED_SCHEMA
            or self.semantics_sha256 != INSPECTION_SEMANTICS
            or self.verified_operations != INSPECTION_READS
        ):
            raise ValueError("exact_observer_semantics_and_read_only_operations_required")
        return self


class LocalObserverPolicy(ControlModel):
    format: Literal["local-session-observer-v1"]
    socket: Path
    allowed_uids: frozenset[int] = Field(min_length=1, max_length=32)
    runtime_enrollment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    backend_evidence: dict[str, RootFile] = Field(min_length=1, max_length=20)
    operator_review: Literal["local-linux-peer-scope-reviewed-no-public-listener"]

    @field_validator("socket")
    @classmethod
    def socket_location(cls, value: Path) -> Path:
        if (
            not value.is_absolute()
            or ".." in value.parts
            or value.parent != Path("/run/jt-oz-observer")
        ):
            raise ValueError("root_managed_runtime_socket_directory_required")
        return value

    @field_validator("allowed_uids", mode="before")
    @classmethod
    def real_unix_uids(cls, value: object) -> object:
        if not isinstance(value, (list, tuple, set, frozenset)) or any(
            type(uid) is not int or uid < 0 for uid in value
        ):
            raise ValueError("explicit_unix_peer_uids_required")
        return value


class ReadOnlyInspectionDatabase(Database):
    """Metadata-only SQL connection; never resolves an application payload key."""

    def __init__(self, url: str) -> None:
        parsed = make_url(url)
        if parsed.drivername == "sqlite+aiosqlite":
            path = Path(parsed.database or "")
            if not path.is_absolute() or path.is_symlink() or not path.is_file():
                raise ValueError("existing_regular_bridge_database_required")
            parsed = parsed.set(database="file:" + str(path), query={"mode": "ro", "uri": "true"})
        elif parsed.drivername != "postgresql+asyncpg":
            raise ValueError("supported_read_only_bridge_database_required")
        self.engine = create_async_engine(parsed, echo=False, hide_parameters=True)
        self.cipher = None
        if parsed.drivername == "sqlite+aiosqlite":

            @event.listens_for(self.engine.sync_engine, "connect")
            def query_only(connection: Any, record: object) -> None:
                connection.execute("PRAGMA query_only=ON")
        else:
            self.engine = self.engine.execution_options(postgresql_readonly=True)
        self.sessions = SessionFactory(self.engine)

    async def schema_ready(self) -> bool:
        async with self.engine.connect() as connection:
            revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
            flags = await connection.scalar(
                text("SELECT count(*) FROM maintenance_flags WHERE pending=true")
            )
        return bool(revision == CURRENT_REVISION and flags == 0)

    async def close(self) -> None:
        await self.engine.dispose()


async def grant_peer_access(path: Path, uids: frozenset[int], permissions: str) -> None:
    # POSIX ACLs allow an already-running Native process to use the socket
    # without changing its groups or requiring another Native restart.
    if permissions not in {"r-x", "rw-"}:
        raise ValueError("fixed_observer_acl_required")
    for uid in sorted(uids - {0, os.geteuid()}):
        process = await asyncio.create_subprocess_exec(
            "/usr/bin/setfacl",
            "-m",
            f"u:{uid}:{permissions}",
            "--",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        if await process.wait() != 0:
            raise ValueError("observer_peer_acl_failed")


async def serve_observer(settings: Settings, policy_path: Path) -> None:
    if os.geteuid() == 0:
        raise ValueError("observer_requires_dedicated_non_root_service_account")
    raw = root_bytes(policy_path)
    policy = LocalObserverPolicy.model_validate(strict_loads(raw))
    policy_sha = hashlib.sha256(raw).hexdigest()
    enrolled, enrollment_sha = read_enrollment(settings)
    ids = {row.reference.backend_id for row in enrolled.backends}
    if policy.runtime_enrollment_sha256 != enrollment_sha or set(policy.backend_evidence) != ids:
        raise ValueError("observer_policy_and_runtime_enrollment_differ")
    url = settings.database.url
    if settings.database.url_ref:
        url = resolve_secret(settings.database.url_ref).get_secret_value()
    db = ReadOnlyInspectionDatabase(
        url or f"sqlite+aiosqlite:///{settings.app.state_dir / 'bridge.db'}"
    )
    transports: list[V2HTTPTransport] = []
    health = httpx.AsyncClient(trust_env=False, timeout=2, follow_redirects=False)
    server: InspectionSocketServer | None = None
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    signals: list[signal.Signals] = []
    try:
        if not await db.schema_ready():
            raise ValueError("observer_bridge_schema_or_maintenance_not_ready")
        backends = {}
        for row in enrolled.backends:
            ref = row.reference
            if ref.backend_id in backends:
                continue
            evidence = InspectionQualification.model_validate(
                strict_loads(policy.backend_evidence[ref.backend_id].read())
            )
            if (
                evidence.backend_id != ref.backend_id
                or evidence.backend_identity != ref.backend_identity
            ):
                raise ValueError("observer_backend_evidence_identity_changed")
            owner_config = HostOwnerEnrollment.model_validate(strict_loads(row.owner.read()))
            owner = LinuxHostOwnerProbe(owner_config, row.owner_socket)
            configured = next(
                item for item in settings.opencode_backends if item.id == ref.backend_id
            )
            transport = V2HTTPTransport(
                configured.base_url,
                OpenAPIProfile(row.schema_file.read()),
                auth=httpx.BasicAuth(
                    "opencode", resolve_secret(configured.credential_ref).get_secret_value()
                ),
                attestation=ContractAttestation(
                    INSTALLED_SCHEMA, ref.backend_identity, "2.0.32", INSPECTION_READS
                ),
            )
            transports.append(transport)

            async def identity(probe: LinuxHostOwnerProbe = owner) -> bool:
                await probe.read()
                return True

            transport.verify_identity = identity
            backend = V2SessionInspection(transport, owner, ref.backend_id, ref.backend_identity)
            await backend.original_owner()
            backends[ref.backend_id] = backend
        if settings.app.bind_host not in {"127.0.0.1", "0.0.0.0", "::", "::1"}:
            raise ValueError("observer_requires_local_bridge_readiness")
        host = "[::1]" if ":" in settings.app.bind_host else "127.0.0.1"

        async def ready() -> bool:
            response = await health.get(f"http://{host}:{settings.app.bind_port}/readyz")
            response.raise_for_status()
            value = strict_loads(response.content)
            return value.get("ready") is True and value.get("agent_consumers") is True

        projects = {
            r.reference.project_id: (
                r.reference.backend_id,
                r.native_project_id,
                r.reference.canonical_directory,
            )
            for r in enrolled.backends
        }
        references = frozenset(
            (
                r.reference.backend_id,
                r.reference.backend_identity,
                r.reference.upstream_session_id,
                r.reference.canonical_directory,
            )
            for r in enrolled.backends
        )

        async def runtime_snapshot(
            lease: ConsumerLeaseObservation, healthy: bool
        ) -> RuntimeModeSnapshot:
            def read() -> RuntimeModeSnapshot:
                reader = RuntimeStatusReader(settings.app.state_dir / "runtime-modes")
                try:
                    return reader.read(lease, bridge_healthy=healthy)
                finally:
                    reader.close()

            return await asyncio.to_thread(read)

        observer = LocalSessionInspector(
            db,
            backends,
            projects,
            references,
            {enrolled.realm.realm_id: enrolled.realm.url},
            ready,
            runtime_references=frozenset(r.reference for r in enrolled.backends),
            runtime_scopes={
                p.id: InspectionRuntimeScope(
                    p.backend_id, p.workspace_root, p.realm_id, frozenset(realm.allowed_channel_ids)
                )
                for p in settings.projects
                if p.enabled
                for realm in settings.zulip_realms
                if realm.enabled and realm.id == p.realm_id
            },
            runtime_snapshot=runtime_snapshot,
        )

        async def handler(query: InspectionProtocolQuery) -> InspectionProtocolResponse:
            if (
                hashlib.sha256(root_bytes(policy_path)).hexdigest() != policy_sha
                or read_enrollment(settings)[1] != enrollment_sha
            ):
                raise ValueError("observer_operator_policy_changed_restart_required")
            return await observer.query(query)

        await grant_peer_access(policy.socket.parent, policy.allowed_uids, "r-x")
        server = InspectionSocketServer(policy.socket, os.getegid(), policy.allowed_uids, handler)
        await server.start()
        await grant_peer_access(policy.socket, policy.allowed_uids, "rw-")
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
            signals.append(sig)
        await stop.wait()
    finally:
        for sig in signals:
            loop.remove_signal_handler(sig)
        if server is not None:
            await server.close()
        for transport in reversed(transports):
            await transport.close()
        await health.aclose()
        await db.close()
