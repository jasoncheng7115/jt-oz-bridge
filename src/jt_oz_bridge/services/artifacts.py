"""Authorized encrypted artifacts, bounded ingestion and durable quota reservations."""

import asyncio
import hashlib
import json
import re
import time
from collections.abc import AsyncIterable
from dataclasses import dataclass
from typing import Literal

from pydantic import Field, field_validator
from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import Exists

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles, artifact_name
from jt_oz_bridge.storage.artifact_models import Artifact, ArtifactBudget
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob, GeneratedOutputRecord
from jt_oz_bridge.storage.guards import enrollment
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, Grant, WorkerLease, uid
from jt_oz_bridge.storage.statements import insert

METADATA_LIMIT = 4096
TERMINAL_ACTIONS = ("completed", "failed", "cancelled", "rejected")


class ArtifactUnavailable(ValueError):
    pass


class FileDescriptor(ControlModel):
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(pattern=r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$", max_length=255)

    @field_validator("filename")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if (
            value in {".", ".."}
            or any(char in value for char in "/\\")
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("unsafe artifact filename")
        return value


@dataclass(frozen=True)
class ArtifactContent:
    id: str
    descriptor: FileDescriptor
    content: bytes
    sha256: str


class ArtifactService:
    def __init__(
        self,
        bindings: BindingService,
        files: LocalArtifactFiles,
        cipher: EnvelopeCipher,
        *,
        maximum_file_bytes: int = 20 * 1024**2,
        quota_bytes: int = 2 * 1024**3,
        reserve_free_bytes: int = 1024**3,
        maximum_objects: int = 10000,
        maximum_concurrent_imports: int = 2,
        fence: ConsumerFence | None = None,
    ) -> None:
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (
                    maximum_file_bytes,
                    quota_bytes,
                    reserve_free_bytes,
                    maximum_objects,
                    maximum_concurrent_imports,
                )
            )
            or not 0 < maximum_file_bytes <= 128 * 1024**2
            or not 0 < quota_bytes < 2**63
            or reserve_free_bytes < 0
            or maximum_objects < 1
            or not 1 <= maximum_concurrent_imports <= 16
        ):
            raise ValueError("invalid artifact limits")
        self.bindings, self.db, self.files, self.cipher = bindings, bindings.db, files, cipher
        self.fence = fence
        self.maximum, self.quota, self.free_reserve, self.object_limit = (
            maximum_file_bytes,
            quota_bytes,
            reserve_free_bytes,
            maximum_objects,
        )
        self._streams = asyncio.Semaphore(maximum_concurrent_imports)

    @staticmethod
    def scope(saved: Artifact) -> dict[str, str | int]:
        return {
            "purpose": "artifact",
            "object_id": saved.id,
            "realm_id": saved.realm_id,
            "project_id": saved.project_id,
            "binding_id": saved.binding_id,
            "binding_revision": saved.binding_revision,
            "kind": saved.kind,
            "key_id": saved.key_id,
        }

    @staticmethod
    def human(binding: Binding, actor_id: int, permission: Permission) -> Exists:
        return (
            select(Grant.id)
            .where(
                Grant.realm_id == binding.realm_id,
                Grant.project_id == binding.project_id,
                Grant.user_id == actor_id,
                Grant.active.is_(True),
                Grant.role.in_(
                    [role for role, permissions in ROLES.items() if permission in permissions]
                ),
            )
            .exists()
        )

    @staticmethod
    def binding_current(binding: Binding) -> Exists:
        return (
            select(Binding.id)
            .where(
                Binding.id == binding.id,
                Binding.state == "active",
                Binding.revision == binding.revision,
                Binding.project_id == binding.project_id,
                Binding.realm_id == binding.realm_id,
            )
            .exists()
        )

    async def _reserve(
        self,
        binding: Binding,
        actor_id: int,
        kind: str,
        reservation: int,
        ttl: int,
        source_message_id: int | None,
        action_id: str | None,
        identity: str | None,
    ) -> Artifact:
        if self.files.free_bytes() < reservation + self.free_reserve:
            raise ArtifactUnavailable("artifact_disk_reserve_reached")
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            if action_id:
                action = await session.get(Action, action_id)
                if (
                    not action
                    or action.binding_id != binding.id
                    or action.binding_revision != binding.revision
                ):
                    raise AccessDenied("artifact action scope mismatch")
            await session.execute(
                insert(self.db, ArtifactBudget)
                .values(id="global")
                .on_conflict_do_nothing(index_elements=["id"])
            )
            reserved = await session.execute(
                update(ArtifactBudget)
                .where(
                    ArtifactBudget.id == "global",
                    ArtifactBudget.reserved_bytes + reservation <= self.quota,
                    ArtifactBudget.object_count < self.object_limit,
                    self.binding_current(binding),
                    self.human(binding, actor_id, Permission.OPERATE),
                    *enrollment(binding, self.bindings.control.contract_for(reference(binding))),
                )
                .values(
                    reserved_bytes=ArtifactBudget.reserved_bytes + reservation,
                    object_count=ArtifactBudget.object_count + 1,
                )
            )
            if reserved.rowcount != 1:  # type: ignore[attr-defined]
                raise ArtifactUnavailable("artifact_quota_or_scope_unavailable")
            saved = Artifact(
                id=identity or uid(),
                binding_id=binding.id,
                binding_revision=binding.revision,
                realm_id=binding.realm_id,
                project_id=binding.project_id,
                actor_id=actor_id,
                source_message_id=source_message_id,
                kind=kind,
                reserved_bytes=reservation,
                key_id=self.cipher.active_key_id,
                action_id=action_id,
                expires_at=time.time() + ttl,
            )
            session.add(saved)
            await session.flush()
        return saved

    async def _abort(self, saved: Artifact) -> None:
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            result = await session.execute(
                update(Artifact)
                .where(Artifact.id == saved.id, Artifact.state == "staging")
                .values(state="failed_cleanup", version=Artifact.version + 1)
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                return
        self.files.remove(saved.id)
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            result = await session.execute(
                update(Artifact)
                .where(Artifact.id == saved.id, Artifact.state == "failed_cleanup")
                .values(state="failed", reserved_bytes=0, version=Artifact.version + 1)
            )
            if result.rowcount == 1:  # type: ignore[attr-defined]
                budget = await session.execute(
                    update(ArtifactBudget)
                    .where(
                        ArtifactBudget.id == "global",
                        ArtifactBudget.reserved_bytes >= saved.reserved_bytes,
                        ArtifactBudget.object_count >= 1,
                    )
                    .values(
                        reserved_bytes=ArtifactBudget.reserved_bytes - saved.reserved_bytes,
                        object_count=ArtifactBudget.object_count - 1,
                    )
                )
                if budget.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("artifact quota metadata inconsistent")

    async def create(
        self,
        binding_id: str,
        realm: str,
        actor_id: int,
        descriptor: FileDescriptor,
        chunks: AsyncIterable[bytes],
        *,
        kind: Literal["attachment", "output", "tool_output", "export"] = "attachment",
        expected_size: int | None = None,
        expected_sha256: str | None = None,
        ttl_seconds: int = 7 * 86400,
        source_message_id: int | None = None,
        action_id: str | None = None,
        identity: str | None = None,
    ) -> str:
        if identity is not None:
            artifact_name(identity)
        binding = await self.bindings.get(binding_id, realm, actor_id, Permission.OPERATE)
        if (
            kind not in {"attachment", "output", "tool_output", "export"}
            or isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or (
                expected_sha256 is not None
                and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            )
        ):
            raise ArtifactUnavailable("invalid_artifact_metadata")
        if (
            expected_size is not None
            and (
                isinstance(expected_size, bool)
                or not isinstance(expected_size, int)
                or not 0 <= expected_size <= self.maximum
            )
        ) or not 0 < ttl_seconds < 2**31:
            raise ArtifactUnavailable("invalid_artifact_size_or_lifetime")
        if source_message_id is not None and (
            isinstance(source_message_id, bool)
            or not isinstance(source_message_id, int)
            or source_message_id <= 0
        ):
            raise ArtifactUnavailable("invalid_artifact_source")
        metadata = descriptor.model_dump_json().encode()
        if len(metadata) > METADATA_LIMIT:
            raise ArtifactUnavailable("artifact_metadata_too_large")
        reservation = (
            (self.maximum if expected_size is None else expected_size)
            + METADATA_LIMIT
            + 4
            + self.cipher.overhead(self.cipher.active_key_id)
        )
        await self._streams.acquire()
        try:
            saved = await self._reserve(
                binding,
                actor_id,
                kind,
                reservation,
                ttl_seconds,
                source_message_id,
                action_id,
                identity,
            )
        except BaseException:
            self._streams.release()
            raise
        try:
            data = bytearray()
            checksum = hashlib.sha256()
            async for chunk in chunks:
                maximum = self.maximum if expected_size is None else expected_size
                if not isinstance(chunk, bytes) or len(data) + len(chunk) > maximum:
                    raise ArtifactUnavailable("artifact_stream_size_or_type_rejected")
                data.extend(chunk)
                checksum.update(chunk)
            actual_hash = checksum.hexdigest()
            if (expected_size is not None and len(data) != expected_size) or (
                expected_sha256 is not None and actual_hash != expected_sha256
            ):
                raise ArtifactUnavailable("artifact_integrity_mismatch")
            current = await self.bindings.get(binding_id, realm, actor_id, Permission.OPERATE)
            if current.revision != saved.binding_revision:
                raise Conflict("artifact binding revision changed")
            plaintext = len(metadata).to_bytes(4, "big") + metadata + bytes(data)
            encrypted = self.cipher.seal(plaintext, self.scope(saved))
            if (
                len(encrypted) > saved.reserved_bytes
                or self.files.free_bytes() < len(encrypted) + self.free_reserve
            ):
                raise ArtifactUnavailable("artifact_storage_reserve_exceeded")
            self.files.write(saved.id, encrypted)
            async with self.db.sessions.begin() as session:
                if self.fence is not None:
                    await self.fence.lock(session)
                accepted = await session.execute(
                    update(Artifact)
                    .where(
                        Artifact.id == saved.id,
                        Artifact.state == "staging",
                        Artifact.version == saved.version,
                        self.binding_current(current),
                        self.human(current, actor_id, Permission.OPERATE),
                        *enrollment(
                            current, self.bindings.control.contract_for(reference(current))
                        ),
                    )
                    .values(
                        state="ready",
                        size_bytes=len(data),
                        checksum=actual_hash,
                        reserved_bytes=len(encrypted),
                        version=Artifact.version + 1,
                    )
                )
                if accepted.rowcount != 1:  # type: ignore[attr-defined]
                    raise AccessDenied("artifact scope changed before commit")
                await session.execute(
                    update(ArtifactBudget)
                    .where(ArtifactBudget.id == "global")
                    .values(
                        reserved_bytes=ArtifactBudget.reserved_bytes
                        - (saved.reserved_bytes - len(encrypted))
                    )
                )
                session.add(
                    AuditEvent(
                        actor=f"{realm}:{actor_id}", event="artifact_stored", object_id=saved.id
                    )
                )
            return saved.id
        except asyncio.CancelledError:
            await asyncio.shield(self._abort(saved))
            raise
        except Exception as error:
            try:
                await self._abort(saved)
            except Exception:
                pass  # Durable reservation/evidence remains for controlled recovery.
            if isinstance(error, AccessDenied):
                raise
            raise ArtifactUnavailable("artifact_import_failed") from None
        finally:
            self._streams.release()

    async def read(self, identity: str, realm: str, actor_id: int) -> ArtifactContent:
        artifact_name(identity)
        async with self.db.sessions() as session:
            saved = await session.get(Artifact, identity)
        if not saved or saved.realm_id != realm or saved.state != "ready":
            raise AccessDenied("artifact unavailable")
        binding = await self.bindings.get(saved.binding_id, realm, actor_id, Permission.VIEW)
        if binding.revision != saved.binding_revision or binding.project_id != saved.project_id:
            raise AccessDenied("artifact scope changed")
        if saved.expires_at <= time.time() and not await self.protected(saved):
            raise ArtifactUnavailable("artifact_expired")
        try:
            encrypted = self.files.read(identity, self.maximum + METADATA_LIMIT + 128)
            plaintext = self.cipher.open(
                encrypted, self.scope(saved), max_plaintext_bytes=self.maximum + METADATA_LIMIT + 4
            )
            length = int.from_bytes(plaintext[:4], "big")
            if not 0 < length <= METADATA_LIMIT or len(plaintext) < length + 4:
                raise ValueError("invalid descriptor")
            descriptor = FileDescriptor.model_validate(json.loads(plaintext[4 : 4 + length]))
            content = plaintext[4 + length :]
            checksum = hashlib.sha256(content).hexdigest()
            if len(content) != saved.size_bytes or checksum != saved.checksum:
                raise ValueError("artifact integrity failed")
        except (ValueError, TypeError, RecursionError):
            async with self.db.sessions.begin() as session:
                if self.fence is not None:
                    await self.fence.lock(session)
                await session.execute(
                    update(Artifact)
                    .where(
                        Artifact.id == identity,
                        Artifact.state == "ready",
                        Artifact.version == saved.version,
                    )
                    .values(state="quarantined", version=Artifact.version + 1)
                )
                session.add(
                    AuditEvent(
                        actor="worker", event="artifact_integrity_failed", object_id=identity
                    )
                )
            raise ArtifactUnavailable("artifact_unavailable_or_invalid") from None
        current = await self.bindings.get(saved.binding_id, realm, actor_id, Permission.VIEW)
        async with self.db.sessions() as session:
            latest = await session.get(Artifact, identity)
        if (
            current.revision != saved.binding_revision
            or not latest
            or latest.state != "ready"
            or latest.version != saved.version
        ):
            raise AccessDenied("artifact access changed during read")
        if latest.expires_at <= time.time() and not await self.protected(latest):
            raise ArtifactUnavailable("artifact_expired")
        return ArtifactContent(identity, descriptor, content, checksum)

    async def protected(self, saved: Artifact) -> bool:
        async with self.db.sessions() as session:
            return await self.protected_in_session(session, saved)

    async def protected_in_session(self, session: AsyncSession, saved: Artifact) -> bool:
        if saved.pinned:
            return True
        capturing = await session.scalar(
            select(GeneratedOutputRecord.id)
            .where(
                GeneratedOutputRecord.reserved_artifact_id == saved.id,
                GeneratedOutputRecord.transfer_id.is_(None),
                ~select(GeneratedCaptureJob.action_id)
                .where(
                    GeneratedCaptureJob.action_id == GeneratedOutputRecord.action_id,
                    GeneratedCaptureJob.state == "skipped",
                )
                .exists(),
            )
            .limit(1)
        )
        if capturing is not None:
            return True
        pending_file = await session.scalar(
            select(FileTransfer.id)
            .where(
                FileTransfer.artifact_id == saved.id,
                or_(
                    FileTransfer.state.not_in(("queued", "rejected")),
                    and_(
                        FileTransfer.state == "queued",
                        or_(
                            ~select(Delivery.id)
                            .where(Delivery.batch_id == FileTransfer.batch_id)
                            .exists(),
                            select(Delivery.id)
                            .where(
                                Delivery.batch_id == FileTransfer.batch_id,
                                Delivery.state.not_in(("delivered", "rejected", "cancelled")),
                            )
                            .exists(),
                        ),
                    ),
                ),
            )
            .limit(1)
        )
        if pending_file is not None:
            return True
        if saved.action_id:
            state = await session.scalar(select(Action.state).where(Action.id == saved.action_id))
            return state is None or state not in TERMINAL_ACTIONS
        return False

    @staticmethod
    def lease(holder: str, fencing: int) -> Exists:
        return (
            select(WorkerLease.role)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == holder,
                WorkerLease.fencing == fencing,
                WorkerLease.expires_at > time.time(),
            )
            .exists()
        )

    async def recover_incomplete(self, holder: str, fencing: int, *, before: float) -> int:
        """Startup/maintenance only, before accepting new uploads. Retain evidence."""
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            result = await session.execute(
                update(Artifact)
                .where(
                    Artifact.state.in_(["staging", "failed_cleanup"]),
                    Artifact.created_at < before,
                    self.lease(holder, fencing),
                )
                .values(state="quarantined", version=Artifact.version + 1)
            )
            return result.rowcount  # type: ignore[attr-defined,no-any-return]

    async def pin(
        self, identity: str, realm: str, actor_id: int, version: int, pinned: bool
    ) -> None:
        artifact_name(identity)
        async with self.db.sessions() as session:
            saved = await session.get(Artifact, identity)
        if not saved or saved.realm_id != realm:
            raise AccessDenied("artifact unavailable")
        binding = await self.bindings.get(saved.binding_id, realm, actor_id, Permission.MANAGE)
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            result = await session.execute(
                update(Artifact)
                .where(
                    Artifact.id == identity,
                    Artifact.version == version,
                    Artifact.state.in_(["ready", "quarantined"]),
                    self.binding_current(binding),
                    self.human(binding, actor_id, Permission.MANAGE),
                    *enrollment(binding, self.bindings.control.contract_for(reference(binding))),
                )
                .values(pinned=pinned, version=Artifact.version + 1)
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("artifact pin revision changed")
            session.add(
                AuditEvent(
                    actor=f"{realm}:{actor_id}", event="artifact_pin_changed", object_id=identity
                )
            )

    async def prune_expired(self, holder: str, fencing: int, *, limit: int = 100) -> int:
        if not 1 <= limit <= 1000:
            raise ValueError("invalid artifact retention batch")
        eligible = or_(
            Artifact.action_id.is_(None),
            select(Action.id)
            .where(Action.id == Artifact.action_id, Action.state.in_(TERMINAL_ACTIONS))
            .exists(),
        )
        async with self.db.sessions() as session:
            candidates = (
                await session.scalars(
                    select(Artifact)
                    .where(
                        Artifact.state.in_(["ready", "deleting"]),
                        Artifact.expires_at <= time.time(),
                        Artifact.pinned.is_(False),
                        eligible,
                    )
                    .order_by(Artifact.expires_at)
                    .limit(limit)
                )
            ).all()
        removed = 0
        for saved in candidates:
            async with self.db.sessions.begin() as session:
                if self.fence is not None:
                    await self.fence.lock(session)
                current = await session.get(Artifact, saved.id, with_for_update=True)
                if (
                    current is None
                    or current.version != saved.version
                    or await self.protected_in_session(session, current)
                ):
                    continue
                claimed = await session.execute(
                    update(Artifact)
                    .where(
                        Artifact.id == saved.id,
                        Artifact.version == saved.version,
                        Artifact.state.in_(["ready", "deleting"]),
                        Artifact.expires_at <= time.time(),
                        Artifact.pinned.is_(False),
                        eligible,
                        self.lease(holder, fencing),
                    )
                    .values(state="deleting", version=Artifact.version + 1)
                )
                if claimed.rowcount != 1:  # type: ignore[attr-defined]
                    continue
            try:
                self.files.remove(saved.id)
            except ValueError:
                continue  # Keep deleting/reservation for a later fenced recovery attempt.
            async with self.db.sessions.begin() as session:
                if self.fence is not None:
                    await self.fence.lock(session)
                released = await session.execute(
                    update(Artifact)
                    .where(
                        Artifact.id == saved.id,
                        Artifact.state == "deleting",
                        Artifact.version == saved.version + 1,
                        self.lease(holder, fencing),
                    )
                    .values(state="deleted", reserved_bytes=0, version=Artifact.version + 1)
                )
                if released.rowcount != 1:  # type: ignore[attr-defined]
                    continue
                budget = await session.execute(
                    update(ArtifactBudget)
                    .where(
                        ArtifactBudget.id == "global",
                        ArtifactBudget.reserved_bytes >= saved.reserved_bytes,
                        ArtifactBudget.object_count >= 1,
                    )
                    .values(
                        reserved_bytes=ArtifactBudget.reserved_bytes - saved.reserved_bytes,
                        object_count=ArtifactBudget.object_count - 1,
                    )
                )
                if budget.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("artifact quota metadata inconsistent")
                session.add(
                    AuditEvent(actor="worker", event="artifact_expired_removed", object_id=saved.id)
                )
                removed += 1
        return removed
