"""Batch proof for a pinned shared ordinary workspace, not prompt authority.

Every Native read is current when observed. Older per-file witnesses are not
revived: a new aggregate object requires a fresh final original owner/policy
proof and unchanged pinned physical files. No file bodies are retained here.
"""

import time
from dataclasses import asdict, dataclass
from functools import partial
from pathlib import Path
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.files import BinaryReadAttestation, V2NativeFileReader
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENTS
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.workspace_files import WorkspaceFile, WorkspaceFiles, joined_io


@dataclass(frozen=True, slots=True, weakref_slot=True)
class NativeWorkspaceBatch:
    reference: SessionRef
    files: tuple[WorkspaceFile, ...]
    evidence_sha256: str


@dataclass(frozen=True)
class _BatchContext:
    original: ReferenceType[NativeWorkspaceBatch]
    proof: OriginalExecutionProof
    attestation: BinaryReadAttestation
    namespace_sha256: str
    deadline: float


def file_metadata(file: WorkspaceFile) -> dict[str, object]:
    return {
        "action_id": file.action_id,
        "artifact_id": file.artifact_id,
        "storage_name": file.storage_name,
        "identity": file.identity,
        "original": file.original.model_dump(mode="json"),
    }


class V2SharedWorkspaceHost:
    def __init__(self, reader: V2NativeFileReader, files: WorkspaceFiles) -> None:
        self.reader, self.files = reader, files
        self._issued: dict[int, _BatchContext] = {}
        namespace = asdict(files.namespace)
        namespace["path"] = str(files.namespace.path)
        self.namespace_sha256 = digest(namespace)

    def qualified(self, reference: SessionRef, schema_sha256: str) -> bool:
        try:
            attestation = self.reader.require(reference)
            self.files.check()
            return bool(
                attestation.contract_sha256 == schema_sha256
                and self.files.namespace.path.parent == Path(reference.canonical_directory)
                and self.files.namespace.path.name.startswith(".jt-oz-incoming-")
            )
        except (OSError, ValueError):
            return False

    async def prove(
        self, reference: SessionRef, files: tuple[WorkspaceFile, ...]
    ) -> NativeWorkspaceBatch:
        selected = self.reader.require(reference)
        if (
            not self.qualified(reference, selected.contract_sha256)
            or type(files) is not tuple
            or not 1 <= len(files) <= MAX_ATTACHMENTS
            or len({f.artifact_id for f in files}) != len(files)
            or len({f.action_id for f in files}) != 1
        ):
            raise ValueError("workspace_original_shared_namespace_required")
        owner_before = await self.reader.proofs.feed.current_owner()
        _, before = await self.reader.client.qualified_snapshot(reference)
        policy_before = await self.reader.guard.bundle(reference)
        self.reader.client.current(reference, before)
        if policy_before != (selected.native_policy_sha256, before.session_info_sha256):
            raise ValueError("workspace_original_policy_changed_before_batch")
        history = []
        for file in files:
            if not await joined_io(partial(self.files.current, file)):
                raise ValueError("workspace_published_original_file_changed")
            path = self.files.namespace.path.name + "/" + file.storage_name
            captured = await self.reader.read(reference, path, maximum_bytes=file.original.size)
            if (
                not self.reader.current(captured)
                or captured.evidence.relative_path != path
                or (captured.evidence.projection.size, captured.evidence.projection.sha256)
                != (file.original.size, file.original.sha256)
                or not await joined_io(partial(self.files.current, file))
            ):
                raise ValueError("workspace_native_does_not_see_original_staged_bytes")
            history.append(captured.evidence.model_dump(mode="json"))
            del captured
        _, after = await self.reader.client.qualified_snapshot(reference)
        policy_after = await self.reader.guard.bundle(reference)
        owner_after = await self.reader.proofs.feed.current_owner()
        self.reader.client.current(reference, after)
        if (
            self.reader.require(reference) is not selected
            or policy_after != (selected.native_policy_sha256, after.session_info_sha256)
            or owner_before.owner_epoch != owner_after.owner_epoch
            or before.connection_epoch != after.connection_epoch
            or before.resource_fence != after.resource_fence
            or after.resource_fence is None
            or any(
                proof["owner_epoch"] != owner_after.owner_epoch
                or proof["connection_epoch"] != after.connection_epoch
                or proof["resource_fence"] != after.resource_fence
                or proof["native_policy_sha256"] != selected.native_policy_sha256
                for proof in history
            )
            or not all(self.files.unchanged(file) for file in files)
        ):
            raise ValueError("workspace_batch_owner_policy_or_files_changed")
        now = time.monotonic()
        self._issued = {
            k: v for k, v in self._issued.items() if v.deadline > now and v.original() is not None
        }
        if len(self._issued) >= 32:
            raise ValueError("workspace_batch_proof_capacity")
        evidence = digest(
            {
                "format": "original-shared-workspace-batch-v1",
                "reference": reference.model_dump(mode="json"),
                "namespace_sha256": self.namespace_sha256,
                "files": [file_metadata(f) for f in files],
                "original_reads": history,
                "final_original_proof": after.model_dump(mode="json"),
                "policy": selected.native_policy_sha256,
            }
        )
        result = NativeWorkspaceBatch(reference, files, evidence)
        self._issued[id(result)] = _BatchContext(
            weakref(result),
            after,
            selected,
            self.namespace_sha256,
            now + min(5, max(0, after.expires_at - time.time())),
        )
        if not self.current(result):
            raise ValueError("workspace_batch_current_proof_required")
        return result

    def current(self, witness: NativeWorkspaceBatch) -> bool:
        try:
            context = self._issued.get(id(witness))
            if (
                context is None
                or context.original() is not witness
                or context.deadline <= time.monotonic()
                or context.namespace_sha256 != self.namespace_sha256
                or self.reader.require(witness.reference) is not context.attestation
                or not self.qualified(witness.reference, context.attestation.contract_sha256)
            ):
                return False
            self.reader.client.current(witness.reference, context.proof)
            return all(self.files.unchanged(file) for file in witness.files)
        except (ValueError, OSError, TypeError):
            return False
