"""Fenced ordinary-file quota, per-file recovery and identity-only retention.

The caller must freshly authorize the original chat source and Native host/path.
This journal checks the claimed frozen action and encrypted artifact ownership;
its receipts never qualify a Native session or authorize a prompt themselves.
"""

import asyncio
import time
from collections.abc import AsyncGenerator
from dataclasses import asdict
from functools import partial
from weakref import WeakValueDictionary

from pydantic import Field, StrictInt
from sqlalchemy import select, update

from jt_oz_bridge.domain.attachments import NativeAttachmentProjection, WorkspaceAttachmentManifest
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.artifacts import TERMINAL_ACTIONS, ArtifactService
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.guards import enrollment
from jt_oz_bridge.storage.models import Action, AuditEvent, uid
from jt_oz_bridge.storage.statements import insert
from jt_oz_bridge.storage.workspace_files import (
    CHUNK,
    WorkspaceFile,
    WorkspaceFiles,
    WorkspaceInput,
    WorkspacePartial,
    empty,
    joined_io,
)
from jt_oz_bridge.storage.workspace_models import WorkspaceBudget, WorkspacePublication


class PublishedWorkspaceFile(ControlModel):
    action_id: str
    artifact_id: str
    storage_name: str
    original: NativeAttachmentProjection
    identity: tuple[StrictInt, StrictInt, StrictInt, StrictInt, StrictInt]

    def storage(self) -> WorkspaceFile:
        return WorkspaceFile(
            self.action_id, self.artifact_id, self.storage_name, self.original, self.identity
        )


class RegisteredPartial(ControlModel):
    action_id: str
    artifact_id: str
    device: StrictInt = Field(ge=0)
    inode: StrictInt = Field(ge=0)

    def storage(self) -> WorkspacePartial:
        return WorkspacePartial(self.action_id, self.artifact_id, self.device, self.inode)


class WorkspacePlan(ControlModel):
    format: str = "original-workspace-publication-v1"
    namespace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: SessionRef
    action_id: str
    artifact_id: str
    binding_id: str
    binding_revision: StrictInt = Field(gt=0)
    realm_id: str
    actor_id: StrictInt = Field(gt=0)
    source_message_id: StrictInt = Field(gt=0)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    original: NativeAttachmentProjection
    partial: RegisteredPartial | None = None
    file: PublishedWorkspaceFile | None = None


def plan_of(row: WorkspacePublication) -> WorkspacePlan:
    plan = WorkspacePlan.model_validate(row.payload)
    if (
        plan.format != "original-workspace-publication-v1"
        or digest(row.payload) != row.payload_hash
        or (row.namespace_sha256, row.action_id, row.artifact_id, row.reserved_bytes)
        != (plan.namespace_sha256, plan.action_id, plan.artifact_id, plan.original.size)
        or row.state not in {"reserved", "ready", "deleting", "deleted", "quarantined"}
        or row.state == "ready"
        and plan.file is None
        or any(
            (entry.action_id, entry.artifact_id) != (plan.action_id, plan.artifact_id)
            for entry in (plan.partial, plan.file)
            if entry is not None
        )
        or plan.file is not None
        and plan.file.original != plan.original
    ):
        raise Conflict("workspace_publication_payload_or_identity_changed")
    return plan


class WorkspaceJournal:
    def __init__(
        self,
        artifacts: ArtifactService,
        files: WorkspaceFiles,
        *,
        quota_bytes: int = 2 * 1024**3,
        maximum_objects: int = 10000,
        ttl_seconds: int = 7 * 86400,
    ) -> None:
        if (
            artifacts.fence is None
            or any(
                type(n) is not int or n <= 0 for n in (quota_bytes, maximum_objects, ttl_seconds)
            )
            or quota_bytes >= 2**63
            or ttl_seconds >= 2**31
        ):
            raise ValueError("workspace_fence_and_bounded_retention_required")
        self.artifacts, self.files, self.db, self.fence = (
            artifacts,
            files,
            artifacts.db,
            artifacts.fence,
        )
        self.quota, self.maximum_objects, self.ttl = quota_bytes, maximum_objects, ttl_seconds
        namespace = asdict(files.namespace)
        namespace["path"] = str(files.namespace.path)
        self.namespace_sha256 = digest(namespace)
        self._locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()

    @staticmethod
    def claimed(
        action: Action, source: HumanMessage, manifest: WorkspaceAttachmentManifest
    ) -> None:
        manifest.checked(source)
        if (
            action.operation != "prompt"
            or action.state != "dispatching"
            or action.actor_id != source.author_id
            or action.payload.get("operation") != "prompt"
            or action.payload.get("source") != source.model_dump(mode="json")
            or action.payload.get("workspace_attachments") != manifest.model_dump(mode="json")
            or "attachments" in action.payload
            or "_workspace_attachment_import" in action.payload
            or digest(action.payload) != action.operation_digest
        ):
            raise Conflict("workspace_original_claimed_action_required")

    async def reserve(
        self, action_id: str, source: HumanMessage, manifest: WorkspaceAttachmentManifest
    ) -> tuple[str, ...]:
        self.files.check()
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None:
            raise Conflict("workspace_action_unavailable")
        self.claimed(action, source, manifest)
        binding = await self.artifacts.bindings.get(
            action.binding_id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (
            binding.revision != action.binding_revision
            or (binding.channel_id, binding.topic) != (source.channel_id, source.topic)
            or action.payload.get("reference") != reference(binding).model_dump(mode="json")
        ):
            raise Conflict("workspace_action_binding_or_reference_changed")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            current = await session.get(Action, action_id, with_for_update=True)
            if current is None or (current.version, current.operation_digest) != (
                action.version,
                action.operation_digest,
            ):
                raise Conflict("workspace_action_changed_before_reservation")
            self.claimed(current, source, manifest)
            pending = []
            added_bytes = added_objects = 0
            for file in manifest.files:
                artifact = await session.get(Artifact, file.artifact_id)
                if artifact is None or (
                    artifact.state,
                    artifact.kind,
                    artifact.action_id,
                    artifact.binding_id,
                    artifact.binding_revision,
                    artifact.realm_id,
                    artifact.actor_id,
                    artifact.source_message_id,
                    artifact.size_bytes,
                    artifact.checksum,
                ) != (
                    "ready",
                    "attachment",
                    action.id,
                    binding.id,
                    binding.revision,
                    source.realm_id,
                    source.author_id,
                    source.message_id,
                    file.size,
                    file.sha256,
                ):
                    raise Conflict("workspace_encrypted_artifact_provenance_changed")
                wanted = WorkspacePlan(
                    namespace_sha256=self.namespace_sha256,
                    reference=reference(binding),
                    action_id=action.id,
                    artifact_id=file.artifact_id,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    realm_id=source.realm_id,
                    actor_id=source.author_id,
                    source_message_id=source.message_id,
                    source_sha256=file.source_sha256,
                    operation_digest=action.operation_digest,
                    original=NativeAttachmentProjection(
                        **file.model_dump(include={"filename", "mime_type", "size", "sha256"})
                    ),
                )
                existing = await session.scalar(
                    select(WorkspacePublication)
                    .where(
                        WorkspacePublication.namespace_sha256 == self.namespace_sha256,
                        WorkspacePublication.action_id == action.id,
                        WorkspacePublication.artifact_id == file.artifact_id,
                    )
                    .with_for_update()
                )
                if existing is not None:
                    previous = plan_of(existing)
                    # A fresh claim may reauthorize identical stored bytes after
                    # a pre-admission source edit; never reuse its old authority.
                    if existing.state not in {"reserved", "ready"} or previous.model_dump(
                        exclude={"source_sha256", "operation_digest", "partial", "file"}
                    ) != wanted.model_dump(
                        exclude={"source_sha256", "operation_digest", "partial", "file"}
                    ):
                        raise Conflict("workspace_existing_publication_scope_changed")
                    wanted = wanted.model_copy(
                        update={"partial": previous.partial, "file": previous.file}
                    )
                    identity = existing.id
                else:
                    identity = uid()
                    added_bytes += file.size
                    added_objects += 1
                pending.append((identity, existing, wanted))
            await session.execute(
                insert(self.db, WorkspaceBudget)
                .values(id="global")
                .on_conflict_do_nothing(index_elements=["id"])
            )
            authorized = (
                select(Action.id)
                .where(
                    Action.id == action.id,
                    Action.state == "dispatching",
                    Action.version == action.version,
                    Action.operation_digest == action.operation_digest,
                )
                .exists()
            )
            budget = await session.execute(
                update(WorkspaceBudget)
                .where(
                    WorkspaceBudget.id == "global",
                    WorkspaceBudget.reserved_bytes + added_bytes <= self.quota,
                    WorkspaceBudget.object_count + added_objects <= self.maximum_objects,
                    self.artifacts.binding_current(binding),
                    self.artifacts.human(binding, source.author_id, Permission.OPERATE),
                    authorized,
                    *enrollment(
                        binding, self.artifacts.bindings.control.contract_for(reference(binding))
                    ),
                )
                .values(
                    reserved_bytes=WorkspaceBudget.reserved_bytes + added_bytes,
                    object_count=WorkspaceBudget.object_count + added_objects,
                )
            )
            if budget.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("workspace_quota_or_current_scope_unavailable")
            for identity, existing, plan in pending:
                payload = plan.model_dump(mode="json")
                if existing is None:
                    session.add(
                        WorkspacePublication(
                            id=identity,
                            namespace_sha256=self.namespace_sha256,
                            action_id=action.id,
                            artifact_id=plan.artifact_id,
                            state="reserved",
                            reserved_bytes=plan.original.size,
                            expires_at=time.time() + self.ttl,
                            payload=payload,
                            payload_hash=digest(payload),
                        )
                    )
                else:
                    existing.payload = payload
                    existing.payload_hash = digest(payload)
                    existing.version += 1
                    existing.expires_at = time.time() + self.ttl
            session.add(
                AuditEvent(actor="worker", event="workspace_bytes_reserved", object_id=action.id)
            )
        return tuple(identity for identity, _, _ in pending)

    async def load(self, identity: str) -> tuple[WorkspacePublication, WorkspacePlan]:
        async with self.db.sessions() as session:
            row = await session.get(WorkspacePublication, identity)
        if row is None or row.namespace_sha256 != self.namespace_sha256:
            raise Conflict("workspace_publication_unavailable")
        return row, plan_of(row)

    async def checkpoint(
        self, expected: WorkspacePublication, plan: WorkspacePlan, *, ready: bool = False
    ) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            row = await session.get(WorkspacePublication, expected.id, with_for_update=True)
            action = await session.get(Action, plan.action_id)
            if (
                row is None
                or row.version != expected.version
                or row.state not in {"reserved", "ready"}
                or action is None
                or action.state != "dispatching"
                or action.operation_digest != plan.operation_digest
            ):
                raise Conflict("workspace_progress_claim_or_fence_changed")
            binding = await session.get(Binding, plan.binding_id)
            if (
                binding is None
                or binding.revision != plan.binding_revision
                or reference(binding) != plan.reference
                or (action.binding_id, action.binding_revision, action.actor_id)
                != (plan.binding_id, plan.binding_revision, plan.actor_id)
                or await session.scalar(
                    select(Action.id).where(
                        Action.id == action.id,
                        self.artifacts.binding_current(binding),
                        self.artifacts.human(binding, plan.actor_id, Permission.OPERATE),
                        *enrollment(
                            binding, self.artifacts.bindings.control.contract_for(plan.reference)
                        ),
                    )
                )
                is None
            ):
                raise Conflict("workspace_progress_authorization_changed")
            row.payload = plan.model_dump(mode="json")
            row.payload_hash = digest(row.payload)
            row.version += 1
            if ready:
                row.state = "ready"

    async def stage(
        self, action_id: str, source: HumanMessage, manifest: WorkspaceAttachmentManifest
    ) -> tuple[WorkspaceFile, ...]:
        lock = self._locks.setdefault(action_id, asyncio.Lock())
        async with lock:
            ids = await self.reserve(action_id, source, manifest)
            result = []
            for identity in ids:
                row, plan = await self.load(identity)
                if plan.partial is not None:
                    await self.files.recover_partial(plan.partial.storage(), plan.original.size)

                content = await self.artifacts.read(plan.artifact_id, plan.realm_id, plan.actor_id)
                if (
                    content.descriptor.filename,
                    content.descriptor.mime_type,
                    len(content.content),
                    content.sha256,
                ) != (
                    plan.original.filename,
                    plan.original.mime_type,
                    plan.original.size,
                    plan.original.sha256,
                ):
                    raise Conflict("workspace_original_encrypted_bytes_changed")

                async def partial_created(
                    saved: WorkspacePartial, identity: str = identity
                ) -> None:
                    current, p = await self.load(identity)
                    await self.checkpoint(
                        current,
                        p.model_copy(update={"partial": RegisteredPartial(**asdict(saved))}),
                    )

                stream = artifact_chunks(content.content)
                entry = WorkspaceInput(plan.artifact_id, plan.original, stream)
                try:
                    staged = (
                        await self.files.stage(action_id, (entry,), on_partial=partial_created)
                    )[0]
                finally:
                    await stream.aclose()
                del content
                current, latest = await self.load(identity)
                ready = PublishedWorkspaceFile(
                    **{**asdict(staged), "original": staged.original.model_dump(mode="json")}
                )
                await self.checkpoint(
                    current, latest.model_copy(update={"file": ready}), ready=True
                )
                result.append(staged)
            return tuple(result)

    async def pin(
        self, identity: str, realm_id: str, actor_id: int, version: int, pinned: bool
    ) -> None:
        if type(pinned) is not bool or type(version) is not int or version < 1:
            raise ValueError("workspace_explicit_pin_revision_required")
        row, plan = await self.load(identity)
        if plan.realm_id != realm_id:
            raise Conflict("workspace_publication_unavailable")
        binding = await self.artifacts.bindings.get(
            plan.binding_id, realm_id, actor_id, Permission.MANAGE
        )
        if binding.revision != plan.binding_revision or reference(binding) != plan.reference:
            raise Conflict("workspace_pin_scope_changed")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            changed = await session.execute(
                update(WorkspacePublication)
                .where(
                    WorkspacePublication.id == identity,
                    WorkspacePublication.version == version,
                    WorkspacePublication.state.in_(("reserved", "ready", "quarantined")),
                    self.artifacts.binding_current(binding),
                    self.artifacts.human(binding, actor_id, Permission.MANAGE),
                    *enrollment(
                        binding, self.artifacts.bindings.control.contract_for(plan.reference)
                    ),
                )
                .values(pinned=pinned, version=WorkspacePublication.version + 1)
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("workspace_pin_revision_or_state_changed")
            session.add(
                AuditEvent(
                    actor=f"{realm_id}:{actor_id}",
                    event="workspace_pin_changed",
                    object_id=identity,
                )
            )

    async def prune_expired(self, *, limit: int = 100) -> int:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("workspace_retention_batch_bound_required")
        async with self.db.sessions() as session:
            ids = tuple(
                await session.scalars(
                    select(WorkspacePublication.id)
                    .where(
                        WorkspacePublication.namespace_sha256 == self.namespace_sha256,
                        WorkspacePublication.expires_at <= time.time(),
                        WorkspacePublication.pinned.is_(False),
                        WorkspacePublication.state.in_(("reserved", "ready", "deleting")),
                        select(Action.id)
                        .where(
                            Action.id == WorkspacePublication.action_id,
                            Action.state.in_(TERMINAL_ACTIONS),
                        )
                        .exists(),
                    )
                    .order_by(WorkspacePublication.expires_at)
                    .limit(limit)
                )
            )
        removed = 0
        for identity in ids:
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                row = await session.get(WorkspacePublication, identity, with_for_update=True)
                if (
                    row is None
                    or row.pinned
                    or row.expires_at > time.time()
                    or row.state not in {"reserved", "ready", "deleting"}
                ):
                    continue
                action = await session.get(Action, row.action_id, with_for_update=True)
                if action is None or action.state not in TERMINAL_ACTIONS:
                    continue
                plan = plan_of(row)
                row.state = "deleting"
                row.version += 1
            try:
                if plan.partial is not None:
                    await self.files.recover_partial(plan.partial.storage(), plan.original.size)
                if plan.file is not None:
                    file = plan.file.storage()
                elif plan.partial is not None:
                    try:
                        file = await joined_io(
                            partial(
                                self.files.file,
                                plan.action_id,
                                WorkspaceInput(plan.artifact_id, plan.original, empty()),
                            )
                        )
                    except FileNotFoundError:
                        file = None
                    if file is not None and file.identity[:2] != (
                        plan.partial.device,
                        plan.partial.inode,
                    ):
                        raise Conflict("workspace_unrecorded_ready_identity_changed")
                else:
                    # Even a zero-write attempt owns only its expected names.
                    file = None
                absent = WorkspaceFile(
                    plan.action_id,
                    plan.artifact_id,
                    plan.action_id + "_" + plan.artifact_id,
                    plan.original,
                    (0, 0, 0, 0, 0),
                )
                if file is not None and not self.files.absent(file):
                    await self.files.remove(file)
                if not self.files.absent(absent):
                    raise Conflict("workspace_unknown_publication_cannot_be_removed")
            except (OSError, ValueError):
                async with self.db.sessions.begin() as session:
                    await self.fence.lock(session)
                    saved = await session.get(WorkspacePublication, identity, with_for_update=True)
                    if saved is not None and saved.state == "deleting":
                        saved.state = "quarantined"
                        saved.version += 1
                continue
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                saved = await session.get(WorkspacePublication, identity, with_for_update=True)
                if saved is None or saved.state != "deleting":
                    raise Conflict("workspace_cleanup_state_changed")
                released = await session.execute(
                    update(WorkspaceBudget)
                    .where(
                        WorkspaceBudget.id == "global",
                        WorkspaceBudget.reserved_bytes >= saved.reserved_bytes,
                        WorkspaceBudget.object_count > 0,
                    )
                    .values(
                        reserved_bytes=WorkspaceBudget.reserved_bytes - saved.reserved_bytes,
                        object_count=WorkspaceBudget.object_count - 1,
                    )
                )
                if released.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("workspace_quota_release_invariant")
                saved.state = "deleted"
                saved.version += 1
                removed += 1
                session.add(
                    AuditEvent(
                        actor="worker", event="workspace_expired_removed", object_id=identity
                    )
                )
        return removed


async def artifact_chunks(content: bytes) -> AsyncGenerator[bytes]:
    for offset in range(0, len(content), CHUNK):
        yield content[offset : offset + CHUNK]
