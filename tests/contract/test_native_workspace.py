"""Pinned real files, synthetic original-owner/Native byte API; no live acceptance."""

import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.files import (
    FILE_FEATURES,
    FILE_SEMANTICS,
    BinaryReadAttestation,
    NativeFileEvidence,
    NativeReadFile,
)
from jt_oz_bridge.adapters.opencode.native_workspace import V2SharedWorkspaceHost
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.storage.workspace_files import WorkspaceFiles, WorkspaceNamespace
from tests.support import REF
from tests.unit.test_workspace_files import entry, uid


class SyntheticNativeReader:
    def __init__(self, ref, files):
        self.ref, self.files = ref, files
        self.attestation = BinaryReadAttestation(
            ref, "a" * 64, FILE_SEMANTICS, "b" * 64, "c" * 64, FILE_FEATURES
        )
        self.proofs = SimpleNamespace(feed=SimpleNamespace(current_owner=self.owner))
        self.client = SimpleNamespace(
            qualified_snapshot=self.snapshot, current=self.current_execution
        )
        self.guard = SimpleNamespace(bundle=self.bundle)
        self.owner_epoch = "original-owner"
        self.connection = "original-connection"
        self.fence = "e" * 64
        self.policy = "c" * 64
        self.original_proofs = []
        self.reads = []
        self.hook = None
        self.offset = 0
        self.slow = False

    def require(self, ref):
        if ref != self.ref or self.attestation is None:
            raise ValueError("synthetic_wrong_original_ref")
        return self.attestation

    async def owner(self):
        return SimpleNamespace(owner_epoch=self.owner_epoch)

    async def bundle(self, ref):
        return self.policy, "d" * 64

    async def snapshot(self, ref):
        now = time.time()
        p = OriginalExecutionProof(
            reference=ref,
            contract_sha256="a" * 64,
            session_info_sha256="d" * 64,
            ownership_evidence_sha256="f" * 64,
            connection_epoch=self.connection,
            issued_at=now,
            expires_at=now + 5,
            state=ExecutionState.IDLE,
            cursor="synthetic",
            descendants=(),
            resource_fence=self.fence,
        )
        self.original_proofs.append(p)
        return None, p

    def current_execution(self, ref, proof):
        if (
            ref != self.ref
            or not any(proof is p for p in self.original_proofs)
            or proof.connection_epoch != self.connection
            or proof.resource_fence != self.fence
            or not proof.issued_at <= time.time() < proof.expires_at
        ):
            raise ValueError("synthetic_current_original_execution_required")

    async def read(self, ref, path, *, maximum_bytes):
        file = next(f for f in self.files if path.endswith("/" + f.storage_name))
        data = (self.directory / path).read_bytes()
        assert len(data) <= maximum_bytes and ref == self.ref
        if self.slow:
            self.offset += 1
        now = time.time()
        captured = NativeReadFile(
            NativeFileEvidence(
                reference=ref,
                relative_path=path,
                projection=file.original,
                etag='"exact"',
                contract_sha256="a" * 64,
                semantics_sha256=FILE_SEMANTICS,
                installed_evidence_sha256="b" * 64,
                native_policy_sha256=self.policy,
                owner_epoch=self.owner_epoch,
                connection_epoch=self.connection,
                resource_fence=self.fence,
                observed_at=now,
                expires_at=now + 5,
            ),
            data,
        )
        self.reads.append(captured.evidence)
        self.last = captured
        if self.hook and len(self.reads) == len(self.files):
            self.hook()
        return captured

    def current(self, captured):
        return captured is self.last and time.time() < captured.evidence.expires_at


async def setup(tmp_path, count=2):
    root = tmp_path.resolve() / ".jt-oz-incoming-fixture"
    root.mkdir(mode=0o2750)
    root.chmod(0o2750)
    s = root.stat()
    store = WorkspaceFiles(
        WorkspaceNamespace(root, s.st_dev, s.st_ino, s.st_uid, s.st_gid), reserve_free_bytes=0
    )
    files = await store.stage(
        uid(), tuple(entry(b"ordinary\x00\xff" + bytes([i])) for i in range(count))
    )
    ref = REF.model_copy(update={"canonical_directory": str(root.parent)})
    reader = SyntheticNativeReader(ref, files)
    reader.directory = root.parent
    return store, reader, V2SharedWorkspaceHost(reader, store), ref, files


async def test_shared_files_are_proved_by_individual_current_reads_and_new_final_batch_proof(
    tmp_path, monkeypatch
):
    store, reader, host, ref, files = await setup(tmp_path, 10)
    original = time.time
    baseline = original()
    reader.slow = True
    monkeypatch.setattr(
        "jt_oz_bridge.adapters.opencode.native_workspace.time.time",
        lambda: baseline + reader.offset,
    )
    try:
        result = await host.prove(ref, files)
        assert len(reader.reads) == reader.offset == 10
        assert reader.reads[0].expires_at < time.time()  # old proof is expired, never resurrected
        assert host.current(result) and len(reader.original_proofs) == 2
        assert not host.current(replace(result))
        assert all(not isinstance(v, bytes) for v in result.files)
        reader.offset += 6
        assert not host.current(result)  # final original 5-second proof still expires
    finally:
        store.close()


@pytest.mark.parametrize(
    "change", ["bytes", "owner", "connection", "fence", "policy", "attestation", "namespace"]
)
async def test_change_during_batch_never_becomes_a_shared_workspace_certificate(tmp_path, change):
    store, reader, host, ref, files = await setup(tmp_path)

    def mutate():
        if change == "bytes":
            (store.namespace.path / files[0].storage_name).write_bytes(b"changed")
        elif change == "owner":
            reader.owner_epoch = "changed"
        elif change == "connection":
            reader.connection = "changed"
        elif change == "fence":
            reader.fence = "f" * 64
        elif change == "policy":
            reader.policy = "f" * 64
        elif change == "attestation":
            reader.attestation = replace(reader.attestation, installed_evidence_sha256="f" * 64)
        else:
            store.namespace.path.rename(store.namespace.path.with_name("moved"))

    reader.hook = mutate
    try:
        with pytest.raises((ValueError, OSError)):
            await host.prove(ref, files)
        assert not host._issued
    finally:
        store.close()


@pytest.mark.parametrize("change", ["wrong-ref", "schema", "outside", "closed"])
async def test_explicit_shared_original_directory_and_namespace_are_required(tmp_path, change):
    store, reader, host, ref, files = await setup(tmp_path)
    schema = "a" * 64
    if change == "wrong-ref":
        ref = ref.model_copy(update={"upstream_session_id": "other"})
    elif change == "schema":
        schema = "b" * 64
    elif change == "outside":
        ref = ref.model_copy(update={"canonical_directory": "/another/project"})
    else:
        store.close()
    try:
        assert not host.qualified(ref, schema)
    finally:
        store.close()


async def test_namespace_file_replacement_revokes_issued_original_object(tmp_path):
    store, reader, host, ref, files = await setup(tmp_path)
    try:
        witness = await host.prove(ref, files)
        path = store.namespace.path / files[0].storage_name
        path.unlink()
        path.write_bytes(b"ordinary\x00\xff" + bytes([0]))
        path.chmod(0o640)
        assert not host.current(witness)
    finally:
        store.close()
